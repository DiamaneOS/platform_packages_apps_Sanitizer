/*
 * Copyright (C) 2026 DiamaneOS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// DNG through its embedded preview: piex (external/piex, the preview extractor Skia uses for raw files on Android)
// finds the largest preview the camera stored, which is decoded as a JPEG (or taken as plain RGB). The raw sensor data
// itself is not developed: that would take the DNG SDK's whole pipeline into the VM. A DNG without a usable preview,
// and every other TIFF-based file, answers UNSUPPORTED. piex allocates through operator new, which comes from the
// arena (arena.cpp).

#include <string.h>

#include "image.h"
#include "src/piex.h"

namespace decoder {
namespace {

class Stream : public piex::StreamInterface {
  public:
    Stream(const uint8_t* data, size_t size) : mData(data), mSize(size) {}
    piex::Error GetData(const size_t offset, const size_t length, uint8_t* data) override {
        if (offset > mSize || length > mSize - offset) return piex::kFail;
        memcpy(data, mData + offset, length);
        return piex::kOk;
    }

  private:
    const uint8_t* mData;
    size_t mSize;
};

bool usable(const piex::Image& img, size_t size) {
    if (img.length == 0 || img.offset > size || img.length > size - img.offset) return false;
    if (img.format == piex::Image::kJpegCompressed) return true;
    return img.format == piex::Image::kUncompressedRgb && img.width != 0 && img.height != 0 &&
           static_cast<uint64_t>(img.width) * img.height * 3 == img.length;
}

bool emit_rgb(const uint8_t* p, uint32_t w, uint32_t h, uint32_t maxW, uint32_t maxH, Sink* sink) {
    uint8_t* row = static_cast<uint8_t*>(arena_alloc(static_cast<size_t>(w) * 4));
    Scaler scaler = {};
    if (row == nullptr || !start_output(&scaler, w, h, maxW, maxH, sink)) return false;
    for (uint32_t y = 0; y < h; y++) {
        const uint8_t* s = p + static_cast<size_t>(y) * w * 3;
        for (uint32_t x = 0; x < w; x++) {
            row[x * 4] = s[x * 3];
            row[x * 4 + 1] = s[x * 3 + 1];
            row[x * 4 + 2] = s[x * 3 + 2];
            row[x * 4 + 3] = 255;
        }
        if (!scaler_push(&scaler, row)) return false;
    }
    bool done = scaler_done(&scaler);
    scaler_free(&scaler);
    arena_free(row);
    return done && sink_flush(sink);
}

}  // namespace

bool decode_dng(const uint8_t* data, size_t size, uint32_t maxW, uint32_t maxH, Sink* sink, bool headerOnly,
                uint32_t* outW, uint32_t* outH) {
    Stream stream(data, size);
    piex::PreviewImageData preview;
    piex::image_type_recognition::RawImageTypes type = piex::image_type_recognition::kNonRawImage;
    piex::Error err = piex::GetPreviewImageData(&stream, &preview, &type);
    if (type != piex::image_type_recognition::kDngImage) {
        gOutcome.unsupported = true;  // a plain TIFF or another raw format
        return false;
    }
    if (err != piex::kOk) return false;
    const piex::Image* img = usable(preview.preview, size)     ? &preview.preview
                             : usable(preview.thumbnail, size) ? &preview.thumbnail
                                                               : nullptr;
    if (img == nullptr) {
        gOutcome.unsupported = true;  // no preview to show: the raw data itself is not developed
        return false;
    }
    const uint8_t* p = data + img->offset;
    if (headerOnly) {
        uint32_t w = preview.full_width, h = preview.full_height;
        if (w == 0 || h == 0 || w > kMaxDimension || h > kMaxDimension) {
            if (img->format != piex::Image::kJpegCompressed) {
                w = img->width;
                h = img->height;
            } else if (!decode_jpeg(p, img->length, 0, 0, sink, true, &w, &h)) {
                return false;
            }
        }
        *outW = w;
        *outH = h;
        return true;
    }
    if (img->format == piex::Image::kJpegCompressed) return decode_jpeg(p, img->length, maxW, maxH, sink, false, outW, outH);
    return emit_rgb(p, img->width, img->height, maxW, maxH, sink);
}

}  // namespace decoder
