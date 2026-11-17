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

// GIF, BMP and WBMP through Wuffs, the memory-safe decoders Skia uses for GIF on Android. Wuffs is one C file,
// meant to be compiled into its user with the modules it needs: the tree's external/wuffs-mirror-release-c, unchanged,
// included here with GIF, LZW, BMP and WBMP and every function static, so nothing of the tree's own Wuffs library
// (which has only GIF) is linked. Wuffs never allocates, starts no threads and makes no system calls: the decoder
// state and every buffer come from the arena here.

#include <string.h>

#include <algorithm>

#include "image.h"

#define WUFFS_IMPLEMENTATION
#define WUFFS_CONFIG__STATIC_FUNCTIONS
#define WUFFS_CONFIG__MODULES
#define WUFFS_CONFIG__MODULE__BASE
#define WUFFS_CONFIG__MODULE__GIF
#define WUFFS_CONFIG__MODULE__LZW
#define WUFFS_CONFIG__MODULE__BMP
#define WUFFS_CONFIG__MODULE__WBMP
// The modules left out are still declared: their functions are static and never defined, which this warning reports at
// the end of the file, outside any push and pop.
#pragma clang diagnostic ignored "-Wundefined-internal"
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
#pragma clang diagnostic ignored "-Wunused-parameter"
#pragma clang diagnostic ignored "-Wunused-variable"
#pragma clang diagnostic ignored "-Wmissing-field-initializers"
#pragma clang diagnostic ignored "-Wimplicit-fallthrough"
#include "wuffs-v0.3.c"
#pragma clang diagnostic pop

namespace decoder {
namespace {

// Limits on top of the shared ones. A GIF canvas is held as one byte per pixel (palette indices), a BMP as four, a
// WBMP as one, so these keep each within the arena with room for the scaler.
constexpr uint64_t kGifMaxPixels = 32u << 20;
constexpr uint64_t kBmpMaxPixels = 12u << 20;
constexpr uint64_t kWbmpMaxPixels = 32u << 20;

bool ok(const wuffs_base__status& s) {
    return s.repr == nullptr;
}

template <typename T>
struct Freer {
    T* p;
    ~Freer() { arena_free(p); }
};

// The rows of a full-size buffer, through the scaler. palette: indexed pixels (GIF), BGRA entries. gray: one byte
// per pixel (WBMP). Else RGBA. Pixels outside [x0, x1) x [y0, y1) are transparent (a GIF frame smaller than its
// canvas).
struct Rows {
    const uint8_t* pixels;
    size_t stride;
    uint32_t w, h;
    const uint8_t* palette;
    bool gray;
    uint32_t x0, y0, x1, y1;
};

bool emit(const Rows& r, uint32_t maxW, uint32_t maxH, Sink* sink) {
    Scaler scaler = {};
    uint8_t* row = static_cast<uint8_t*>(arena_alloc(static_cast<size_t>(r.w) * 4));
    if (row == nullptr || !start_output(&scaler, r.w, r.h, maxW, maxH, sink)) return false;
    for (uint32_t y = 0; y < r.h; y++) {
        const uint8_t* src = r.pixels + r.stride * y;
        if (r.palette != nullptr) {
            memset(row, 0, static_cast<size_t>(r.w) * 4);
            if (y >= r.y0 && y < r.y1) {
                for (uint32_t x = r.x0; x < r.x1; x++) {
                    const uint8_t* e = r.palette + 4 * src[x];
                    uint8_t* d = row + static_cast<size_t>(x) * 4;
                    d[0] = e[2];
                    d[1] = e[1];
                    d[2] = e[0];
                    d[3] = e[3];
                }
            }
        } else if (r.gray) {
            for (uint32_t x = 0; x < r.w; x++) {
                uint8_t* d = row + static_cast<size_t>(x) * 4;
                d[0] = d[1] = d[2] = src[x];
                d[3] = 255;
            }
        } else {
            memcpy(row, src, static_cast<size_t>(r.w) * 4);
        }
        if (!scaler_push(&scaler, row)) return false;
    }
    bool done = scaler_done(&scaler);
    scaler_free(&scaler);
    arena_free(row);
    return done && sink_flush(sink);
}

// A frame that ran out of input ends where the data ends: the rows not reached stay empty, as Android shows a cut-off
// image. Any other error refuses the file.
bool frame_done(const wuffs_base__status& s) {
    return ok(s) || s.repr == wuffs_base__suspension__short_read;
}

}  // namespace

bool decode_gif(const uint8_t* data, size_t size, uint32_t maxW, uint32_t maxH, Sink* sink, bool headerOnly,
                uint32_t* outW, uint32_t* outH) {
    Freer<wuffs_gif__decoder> dec = {wuffs_gif__decoder__alloc()};
    if (dec.p == nullptr) return false;
    wuffs_base__io_buffer src = wuffs_base__ptr_u8__reader(const_cast<uint8_t*>(data), size, true);
    wuffs_base__image_config ic = {};
    if (!ok(wuffs_gif__decoder__decode_image_config(dec.p, &ic, &src))) return false;
    uint32_t w = wuffs_base__pixel_config__width(&ic.pixcfg), h = wuffs_base__pixel_config__height(&ic.pixcfg);
    if (w == 0 || h == 0 || w > kMaxDimension || h > kMaxDimension) return false;
    if (static_cast<uint64_t>(w) * h > kGifMaxPixels) return false;
    if (headerOnly) {
        // Animated: a second frame follows the first. Reading its frame header skips the first frame's data without
        // decoding it. A probe of the file's start may end before it: then the answer is a single frame.
        wuffs_base__frame_config fc = {};
        if (ok(wuffs_gif__decoder__decode_frame_config(dec.p, &fc, &src))) {
            gOutcome.animated = ok(wuffs_gif__decoder__decode_frame_config(dec.p, &fc, &src));
        }
        *outW = w;
        *outH = h;
        return true;
    }
    wuffs_base__pixel_config__set(&ic.pixcfg, WUFFS_BASE__PIXEL_FORMAT__INDEXED__BGRA_NONPREMUL,
                                  WUFFS_BASE__PIXEL_SUBSAMPLING__NONE, w, h);
    // An indexed buffer starts with its 1024-byte palette, then one byte per pixel.
    size_t bytes = WUFFS_BASE__PIXEL_FORMAT__INDEXED__PALETTE_BYTE_LENGTH + static_cast<size_t>(w) * h;
    Freer<uint8_t> pixels = {static_cast<uint8_t*>(arena_calloc(bytes, 1))};
    if (pixels.p == nullptr) return false;
    wuffs_base__pixel_buffer pb = {};
    if (!ok(wuffs_base__pixel_buffer__set_from_slice(&pb, &ic.pixcfg, wuffs_base__make_slice_u8(pixels.p, bytes)))) {
        return false;
    }
    wuffs_base__frame_config fc = {};
    if (!ok(wuffs_gif__decoder__decode_frame_config(dec.p, &fc, &src))) return false;
    wuffs_base__range_ii_u64 wb = wuffs_gif__decoder__workbuf_len(dec.p);
    if (wb.max_incl > (16u << 20)) return false;
    Freer<uint8_t> work = {static_cast<uint8_t*>(arena_alloc(std::max<size_t>(wb.max_incl, 1)))};
    if (work.p == nullptr) return false;
    // The first frame alone, over a transparent canvas (the background colour is not used, as on Android).
    wuffs_base__status st = wuffs_gif__decoder__decode_frame(dec.p, &pb, &src, WUFFS_BASE__PIXEL_BLEND__SRC,
                                                            wuffs_base__make_slice_u8(work.p, wb.max_incl), nullptr);
    if (!frame_done(st)) return false;
    wuffs_base__rect_ie_u32 r = wuffs_base__frame_config__bounds(&fc);
    wuffs_base__slice_u8 pal = wuffs_base__pixel_buffer__palette(&pb);
    if (pal.len != 1024) return false;
    Rows rows = {pixels.p + WUFFS_BASE__PIXEL_FORMAT__INDEXED__PALETTE_BYTE_LENGTH, w, w, h, pal.ptr, false, std::min(r.min_incl_x, w), std::min(r.min_incl_y, h),
                 std::min(r.max_excl_x, w), std::min(r.max_excl_y, h)};
    return emit(rows, maxW, maxH, sink);
}

bool decode_bmp(const uint8_t* data, size_t size, uint32_t maxW, uint32_t maxH, Sink* sink, bool headerOnly,
                uint32_t* outW, uint32_t* outH) {
    Freer<wuffs_bmp__decoder> dec = {wuffs_bmp__decoder__alloc()};
    if (dec.p == nullptr) return false;
    wuffs_base__io_buffer src = wuffs_base__ptr_u8__reader(const_cast<uint8_t*>(data), size, true);
    wuffs_base__image_config ic = {};
    wuffs_base__status st = wuffs_bmp__decoder__decode_image_config(dec.p, &ic, &src);
    if (st.repr == wuffs_base__note__i_o_redirect) gOutcome.unsupported = true;  // an embedded PNG or JPEG
    if (!ok(st)) return false;
    uint32_t w = wuffs_base__pixel_config__width(&ic.pixcfg), h = wuffs_base__pixel_config__height(&ic.pixcfg);
    if (w == 0 || h == 0 || w > kMaxDimension || h > kMaxDimension) return false;
    if (static_cast<uint64_t>(w) * h > kBmpMaxPixels) return false;
    if (headerOnly) {
        *outW = w;
        *outH = h;
        return true;
    }
    wuffs_base__pixel_config__set(&ic.pixcfg, WUFFS_BASE__PIXEL_FORMAT__RGBA_NONPREMUL,
                                  WUFFS_BASE__PIXEL_SUBSAMPLING__NONE, w, h);
    size_t bytes = static_cast<size_t>(w) * h * 4;
    Freer<uint8_t> pixels = {static_cast<uint8_t*>(arena_calloc(bytes, 1))};
    if (pixels.p == nullptr) return false;
    wuffs_base__pixel_buffer pb = {};
    if (!ok(wuffs_base__pixel_buffer__set_from_slice(&pb, &ic.pixcfg, wuffs_base__make_slice_u8(pixels.p, bytes)))) {
        return false;
    }
    wuffs_base__range_ii_u64 wb = wuffs_bmp__decoder__workbuf_len(dec.p);
    if (wb.max_incl > (16u << 20)) return false;
    Freer<uint8_t> work = {static_cast<uint8_t*>(arena_alloc(std::max<size_t>(wb.max_incl, 1)))};
    if (work.p == nullptr) return false;
    st = wuffs_bmp__decoder__decode_frame(dec.p, &pb, &src, WUFFS_BASE__PIXEL_BLEND__SRC,
                                          wuffs_base__make_slice_u8(work.p, wb.max_incl), nullptr);
    if (!frame_done(st)) return false;
    Rows rows = {pixels.p, static_cast<size_t>(w) * 4, w, h, nullptr, false, 0, 0, w, h};
    return emit(rows, maxW, maxH, sink);
}

bool decode_wbmp(const uint8_t* data, size_t size, uint32_t maxW, uint32_t maxH, Sink* sink, bool headerOnly,
                 uint32_t* outW, uint32_t* outH) {
    Freer<wuffs_wbmp__decoder> dec = {wuffs_wbmp__decoder__alloc()};
    if (dec.p == nullptr) return false;
    wuffs_base__io_buffer src = wuffs_base__ptr_u8__reader(const_cast<uint8_t*>(data), size, true);
    wuffs_base__image_config ic = {};
    if (!ok(wuffs_wbmp__decoder__decode_image_config(dec.p, &ic, &src))) return false;
    uint32_t w = wuffs_base__pixel_config__width(&ic.pixcfg), h = wuffs_base__pixel_config__height(&ic.pixcfg);
    if (w == 0 || h == 0 || w > kMaxDimension || h > kMaxDimension) return false;
    if (static_cast<uint64_t>(w) * h > kWbmpMaxPixels) return false;
    if (headerOnly) {
        *outW = w;
        *outH = h;
        return true;
    }
    wuffs_base__pixel_config__set(&ic.pixcfg, WUFFS_BASE__PIXEL_FORMAT__Y, WUFFS_BASE__PIXEL_SUBSAMPLING__NONE, w, h);
    size_t bytes = static_cast<size_t>(w) * h;
    Freer<uint8_t> pixels = {static_cast<uint8_t*>(arena_calloc(bytes, 1))};
    if (pixels.p == nullptr) return false;
    wuffs_base__pixel_buffer pb = {};
    if (!ok(wuffs_base__pixel_buffer__set_from_slice(&pb, &ic.pixcfg, wuffs_base__make_slice_u8(pixels.p, bytes)))) {
        return false;
    }
    wuffs_base__status st = wuffs_wbmp__decoder__decode_frame(dec.p, &pb, &src, WUFFS_BASE__PIXEL_BLEND__SRC,
                                                             wuffs_base__make_slice_u8(nullptr, 0), nullptr);
    if (!frame_done(st)) return false;
    Rows rows = {pixels.p, w, w, h, nullptr, true, 0, 0, w, h};
    return emit(rows, maxW, maxH, sink);
}

}  // namespace decoder
