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

// WebP through the tree's libwebp (external/webp, libwebp-decode with its demuxer): lossy, lossless, alpha, and the
// first frame of an animation. libwebp allocates with malloc, which comes from the arena (arena.cpp). It starts no
// threads unless asked (use_threads stays 0). Its function tables are set up once per process, in the broker's
// warm-up, where it also checks the CPU (on arm64 only at compile time).
//
// A still image is scaled by libwebp itself, straight into an output of the thumbnail's size, so only the decoder's
// own buffers depend on the image's size. Those are checked against the arena before anything is allocated.

#include <string.h>

#include <algorithm>
#include <utility>

#include <webp/decode.h>
#include <webp/demux.h>

#include "image.h"
#include "warmup_formats.h"

namespace decoder {
namespace {

// WebP's own limit is 16383 per side. These bound the work per file: a canvas or a still image, and an animation's
// first frame, which is decoded at full size.
constexpr uint64_t kWebpMaxPixels = 64u << 20;
constexpr uint64_t kWebpFrameMaxPixels = 12u << 20;
constexpr size_t kSlack = 2u << 20;  // the decoders' own state, the scaler and the stripe buffer

// What libwebp itself holds for a still image of w x h: a lossless image keeps every pixel as 32 bits while it
// decodes, a lossy one keeps its alpha plane whole and a few rows of macroblocks.
uint64_t decoder_bytes(uint32_t w, uint32_t h, int format, bool alpha) {
    uint64_t px = static_cast<uint64_t>(w) * h;
    uint64_t rows = static_cast<uint64_t>(w) * 64 * 4;
    return (format == 2 ? px * 4 : 0) + (alpha ? px : 0) + rows;
}

bool fits(uint64_t bytes) {
    return bytes + kSlack <= arena_left();
}

// Decodes data into rgba (premultiplied, external memory), scaled to ow x oh when that differs from w x h.
bool decode_into(const uint8_t* data, size_t size, uint32_t w, uint32_t h, uint32_t ow, uint32_t oh, uint8_t* rgba) {
    WebPDecoderConfig config;
    if (!WebPInitDecoderConfig(&config)) return false;
    config.options.use_threads = 0;
    if (ow != w || oh != h) {
        config.options.use_scaling = 1;
        config.options.scaled_width = static_cast<int>(ow);
        config.options.scaled_height = static_cast<int>(oh);
    }
    config.output.colorspace = MODE_rgbA;
    config.output.is_external_memory = 1;
    config.output.u.RGBA.rgba = rgba;
    config.output.u.RGBA.stride = static_cast<int>(ow * 4);
    config.output.u.RGBA.size = static_cast<size_t>(ow) * oh * 4;
    VP8StatusCode st = WebPDecode(data, size, &config);
    WebPFreeDecBuffer(&config.output);
    return st == VP8_STATUS_OK && config.output.width == static_cast<int>(ow) &&
           config.output.height == static_cast<int>(oh);
}

bool decode_still(const uint8_t* data, size_t size, const WebPBitstreamFeatures& f, uint32_t maxW, uint32_t maxH,
                  Sink* sink) {
    uint32_t w = static_cast<uint32_t>(f.width), h = static_cast<uint32_t>(f.height), ow, oh;
    fit_box(w, h, maxW, maxH, &ow, &oh);
    uint64_t out = static_cast<uint64_t>(ow) * oh * 4;
    if (!fits(out + decoder_bytes(w, h, f.format, f.has_alpha != 0))) return false;
    uint8_t* rgba = static_cast<uint8_t*>(arena_alloc(out));
    if (rgba == nullptr || !decode_into(data, size, w, h, ow, oh, rgba)) return false;
    Scaler scaler = {};
    if (!start_output(&scaler, ow, oh, ow, oh, sink)) return false;
    scaler.premultiplied = true;
    for (uint32_t y = 0; y < oh; y++) {
        if (!scaler_push(&scaler, rgba + static_cast<size_t>(ow) * 4 * y)) return false;
    }
    bool done = scaler_done(&scaler);
    scaler_free(&scaler);
    arena_free(rgba);
    return done && sink_flush(sink);
}

// The first frame of an animation, over a transparent canvas: the frame at its offset, decoded at full size, the rest
// of the canvas transparent. Blending and disposal only matter from the second frame on.
bool decode_first_frame(const uint8_t* data, size_t size, uint32_t maxW, uint32_t maxH, Sink* sink) {
    WebPData wd = {data, size};
    WebPDemuxer* dmx = WebPDemux(&wd);
    if (dmx == nullptr) return false;
    struct Closer {
        WebPDemuxer* d;
        WebPIterator it;
        bool have;
        ~Closer() {
            if (have) WebPDemuxReleaseIterator(&it);
            WebPDemuxDelete(d);
        }
    } c = {dmx, {}, false};
    uint32_t cw = WebPDemuxGetI(dmx, WEBP_FF_CANVAS_WIDTH), ch = WebPDemuxGetI(dmx, WEBP_FF_CANVAS_HEIGHT);
    if (cw == 0 || ch == 0 || static_cast<uint64_t>(cw) * ch > kWebpMaxPixels) return false;
    if (!WebPDemuxGetFrame(dmx, 1, &c.it)) return false;
    c.have = true;
    const WebPIterator& it = c.it;
    if (it.width <= 0 || it.height <= 0 || it.x_offset < 0 || it.y_offset < 0 ||
        static_cast<uint64_t>(it.x_offset) + static_cast<uint64_t>(it.width) > cw ||
        static_cast<uint64_t>(it.y_offset) + static_cast<uint64_t>(it.height) > ch) {
        return false;
    }
    uint32_t fw = static_cast<uint32_t>(it.width), fh = static_cast<uint32_t>(it.height);
    WebPBitstreamFeatures f;
    if (WebPGetFeatures(it.fragment.bytes, it.fragment.size, &f) != VP8_STATUS_OK ||
        static_cast<uint32_t>(f.width) != fw || static_cast<uint32_t>(f.height) != fh) {
        return false;
    }
    uint64_t frame = static_cast<uint64_t>(fw) * fh * 4;
    if (static_cast<uint64_t>(fw) * fh > kWebpFrameMaxPixels ||
        !fits(frame + static_cast<uint64_t>(cw) * 4 + decoder_bytes(fw, fh, f.format, f.has_alpha != 0))) {
        return false;
    }
    uint8_t* rgba = static_cast<uint8_t*>(arena_alloc(frame));
    uint8_t* row = static_cast<uint8_t*>(arena_alloc(static_cast<size_t>(cw) * 4));
    if (rgba == nullptr || row == nullptr ||
        !decode_into(it.fragment.bytes, it.fragment.size, fw, fh, fw, fh, rgba)) {
        return false;
    }
    Scaler scaler = {};
    if (!start_output(&scaler, cw, ch, maxW, maxH, sink)) return false;
    scaler.premultiplied = true;
    uint32_t fx = static_cast<uint32_t>(it.x_offset), fy = static_cast<uint32_t>(it.y_offset);
    for (uint32_t y = 0; y < ch; y++) {
        memset(row, 0, static_cast<size_t>(cw) * 4);
        if (y >= fy && y < fy + fh) {
            memcpy(row + static_cast<size_t>(fx) * 4, rgba + static_cast<size_t>(y - fy) * fw * 4,
                   static_cast<size_t>(fw) * 4);
        }
        if (!scaler_push(&scaler, row)) return false;
    }
    bool done = scaler_done(&scaler);
    scaler_free(&scaler);
    arena_free(row);
    arena_free(rgba);
    return done && sink_flush(sink);
}

}  // namespace

bool decode_webp(const uint8_t* data, size_t size, uint32_t maxW, uint32_t maxH, Sink* sink, bool headerOnly,
                 uint32_t* outW, uint32_t* outH) {
    WebPBitstreamFeatures f;
    if (WebPGetFeatures(data, size, &f) != VP8_STATUS_OK) return false;
    if (f.width <= 0 || f.height <= 0 || static_cast<uint64_t>(f.width) * static_cast<uint64_t>(f.height) >
                                                 kWebpMaxPixels) {
        return false;
    }
    if (headerOnly) {
        *outW = static_cast<uint32_t>(f.width);
        *outH = static_cast<uint32_t>(f.height);
        gOutcome.animated = f.has_animation != 0;
        return true;
    }
    return f.has_animation ? decode_first_frame(data, size, maxW, maxH, sink)
                           : decode_still(data, size, f, maxW, maxH, sink);
}

void warm_up_webp() {
    uint8_t out[16 * 16 * 4];
    for (const auto& img : {std::make_pair(kWarmupWebpLossy, sizeof(kWarmupWebpLossy)),
                            std::make_pair(kWarmupWebpLossless, sizeof(kWarmupWebpLossless))}) {
        decode_into(img.first, img.second, 16, 16, 16, 16, out);
        decode_into(img.first, img.second, 16, 16, 5, 3, out);
    }
}

}  // namespace decoder
