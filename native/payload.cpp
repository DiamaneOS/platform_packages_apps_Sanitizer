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

// The file sanitizer's payload, running inside a protected VM. It decodes untrusted images and returns plain
// pixels. A decoder exploit stays inside the VM: it can only return wrong pixels.

#include <aidl/de/diamaneos/sanitizer/BnSanitizer.h>
#include <android/log.h>
#include <vm_payload.h>

#include <algorithm>
#include <csetjmp>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <vector>

#include <jpeglib.h>
#include <png.h>

using aidl::de::diamaneos::sanitizer::BnSanitizer;
using ndk::ScopedAStatus;

namespace {

constexpr const char* kTag = "DiamaneOSSanitizer";
constexpr uint32_t kMaxSide = 16384;

struct Raster {
    uint32_t width = 0;
    uint32_t height = 0;
    std::vector<uint8_t> rgba;  // straight alpha until finish()
};

bool size_ok(uint64_t w, uint64_t h) {
    return w > 0 && h > 0 && w <= kMaxSide && h <= kMaxSide &&
           w * h <= static_cast<uint64_t>(BnSanitizer::MAX_PIXELS);
}

// PNG through libpng's simplified API.
bool decode_png(const std::vector<uint8_t>& in, Raster* out) {
    png_image image;
    memset(&image, 0, sizeof(image));
    image.version = PNG_IMAGE_VERSION;
    if (!png_image_begin_read_from_memory(&image, in.data(), in.size())) return false;
    image.format = PNG_FORMAT_RGBA;
    if (!size_ok(image.width, image.height)) {
        png_image_free(&image);
        return false;
    }
    out->width = image.width;
    out->height = image.height;
    out->rgba.resize(PNG_IMAGE_SIZE(image));
    if (!png_image_finish_read(&image, nullptr, out->rgba.data(), 0, nullptr)) {
        png_image_free(&image);
        return false;
    }
    return true;
}

struct JpegError {
    jpeg_error_mgr mgr;
    jmp_buf jump;
};

void jpeg_fail(j_common_ptr cinfo) {
    longjmp(reinterpret_cast<JpegError*>(cinfo->err)->jump, 1);
}

void jpeg_quiet(j_common_ptr, int) {}

// JPEG through libjpeg-turbo, scaled down while decoding when it is larger than MAX_PIXELS.
bool decode_jpeg(const std::vector<uint8_t>& in, Raster* out) {
    jpeg_decompress_struct cinfo;
    JpegError err;
    cinfo.err = jpeg_std_error(&err.mgr);
    err.mgr.error_exit = jpeg_fail;
    err.mgr.emit_message = jpeg_quiet;
    if (setjmp(err.jump)) {
        jpeg_destroy_decompress(&cinfo);
        return false;
    }
    jpeg_create_decompress(&cinfo);
    jpeg_mem_src(&cinfo, in.data(), in.size());
    if (jpeg_read_header(&cinfo, TRUE) != JPEG_HEADER_OK) {
        jpeg_destroy_decompress(&cinfo);
        return false;
    }
    cinfo.out_color_space = JCS_EXT_RGBA;
    cinfo.scale_num = 1;
    cinfo.scale_denom = 1;
    jpeg_calc_output_dimensions(&cinfo);
    while (!size_ok(cinfo.output_width, cinfo.output_height) && cinfo.scale_denom < 8) {
        cinfo.scale_denom *= 2;
        jpeg_calc_output_dimensions(&cinfo);
    }
    if (!size_ok(cinfo.output_width, cinfo.output_height)) {
        jpeg_destroy_decompress(&cinfo);
        return false;
    }
    jpeg_start_decompress(&cinfo);
    out->width = cinfo.output_width;
    out->height = cinfo.output_height;
    out->rgba.resize(static_cast<size_t>(out->width) * out->height * 4);
    while (cinfo.output_scanline < cinfo.output_height) {
        JSAMPROW row = out->rgba.data() + static_cast<size_t>(cinfo.output_scanline) * out->width * 4;
        if (jpeg_read_scanlines(&cinfo, &row, 1) != 1) {
            jpeg_destroy_decompress(&cinfo);
            return false;
        }
    }
    jpeg_finish_decompress(&cinfo);
    jpeg_destroy_decompress(&cinfo);
    return true;
}

// "DSR1", width, height, premultiplied RGBA.
void finish(Raster& r, std::vector<uint8_t>* out) {
    out->resize(12 + r.rgba.size());
    uint8_t* o = out->data();
    memcpy(o, "DSR1", 4);
    for (int i = 0; i < 4; i++) {
        o[4 + i] = static_cast<uint8_t>(r.width >> (8 * i));
        o[8 + i] = static_cast<uint8_t>(r.height >> (8 * i));
    }
    uint8_t* p = r.rgba.data();
    for (size_t i = 0; i < r.rgba.size(); i += 4) {
        uint32_t a = p[i + 3];
        if (a != 255) {
            p[i] = static_cast<uint8_t>((p[i] * a + 127) / 255);
            p[i + 1] = static_cast<uint8_t>((p[i + 1] * a + 127) / 255);
            p[i + 2] = static_cast<uint8_t>((p[i + 2] * a + 127) / 255);
        }
    }
    memcpy(o + 12, p, r.rgba.size());
}

class Sanitizer : public BnSanitizer {
public:
    ScopedAStatus addInput(const std::vector<uint8_t>& piece) override {
        std::lock_guard<std::mutex> lock(mLock);
        if (piece.size() > static_cast<size_t>(CHUNK) ||
            mInput.size() + piece.size() > static_cast<size_t>(MAX_INPUT_BYTES)) {
            mInput.clear();
            return ScopedAStatus::fromServiceSpecificErrorWithMessage(1, "size");
        }
        mInput.insert(mInput.end(), piece.begin(), piece.end());
        return ScopedAStatus::ok();
    }

    ScopedAStatus decode(int64_t* length) override {
        std::lock_guard<std::mutex> lock(mLock);
        std::vector<uint8_t> file;
        file.swap(mInput);
        mResult.clear();
        if (file.size() < 8) return ScopedAStatus::fromServiceSpecificErrorWithMessage(1, "size");
        Raster r;
        const uint8_t* b = file.data();
        bool ok = false;
        if (memcmp(b, "\x89PNG\r\n\x1a\n", 8) == 0) {
            ok = decode_png(file, &r);
        } else if (b[0] == 0xff && b[1] == 0xd8 && b[2] == 0xff) {
            ok = decode_jpeg(file, &r);
        } else {
            return ScopedAStatus::fromServiceSpecificErrorWithMessage(2, "format");
        }
        if (!ok) return ScopedAStatus::fromServiceSpecificErrorWithMessage(3, "decode");
        finish(r, &mResult);
        *length = static_cast<int64_t>(mResult.size());
        __android_log_print(ANDROID_LOG_INFO, kTag, "decoded %ux%u", r.width, r.height);
        return ScopedAStatus::ok();
    }

    ScopedAStatus readResult(int64_t offset, std::vector<uint8_t>* out) override {
        std::lock_guard<std::mutex> lock(mLock);
        if (offset < 0 || static_cast<uint64_t>(offset) > mResult.size()) {
            return ScopedAStatus::fromServiceSpecificErrorWithMessage(1, "offset");
        }
        size_t n = std::min(static_cast<size_t>(CHUNK), mResult.size() - static_cast<size_t>(offset));
        out->assign(mResult.begin() + offset, mResult.begin() + offset + n);
        return ScopedAStatus::ok();
    }

private:
    std::mutex mLock;
    std::vector<uint8_t> mInput;
    std::vector<uint8_t> mResult;
};

}  // namespace

extern "C" int AVmPayload_main() {
    auto service = ndk::SharedRefBase::make<Sanitizer>();
    AVmPayload_runVsockRpcServer(
            service->asBinder().get(), Sanitizer::PORT,
            [](void*) { AVmPayload_notifyPayloadReady(); }, nullptr);
}
