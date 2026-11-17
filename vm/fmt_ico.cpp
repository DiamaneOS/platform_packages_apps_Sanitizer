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

// ICO and CUR: a directory of images, each a PNG (decoded by the PNG decoder) or a bare DIB, a BMP without its file
// header, twice as high as the icon because an AND mask follows the colours. No library in the tree reads the DIB
// form outside Skia, so this small reader does, for the only form icons use: uncompressed 1, 4, 8, 24 and 32 bits per
// pixel. It reads row by row straight from the file, with every offset checked, and allocates one row.
//
// Like Android, the largest image of the directory is shown (by its real size, not the directory's claim).

#include <string.h>

#include "image.h"

namespace decoder {
namespace {

constexpr uint32_t kMaxEntries = 256;
constexpr uint32_t kDibMaxSide = 4096;

uint16_t le16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0] | p[1] << 8);
}
uint32_t le32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0] | p[1] << 8 | p[2] << 16) | static_cast<uint32_t>(p[3]) << 24;
}
uint32_t be32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) << 24 | static_cast<uint32_t>(p[1] << 16 | p[2] << 8 | p[3]);
}

struct Entry {
    const uint8_t* p;
    size_t n;
    bool png;
    uint32_t w, h, bpp;
};

// The entry's real size from its own header. False for an entry that is neither a PNG nor a DIB this reader takes.
bool inspect(Entry* e) {
    if (e->n >= 24 && memcmp(e->p, "\x89PNG\r\n\x1a\n", 8) == 0 && memcmp(e->p + 12, "IHDR", 4) == 0) {
        e->png = true;
        e->w = be32(e->p + 16);
        e->h = be32(e->p + 20);
        e->bpp = 32;
        return e->w != 0 && e->h != 0 && e->w <= kMaxDimension && e->h <= kMaxDimension;
    }
    if (e->n < 40) return false;
    uint32_t hdr = le32(e->p);
    int32_t w = static_cast<int32_t>(le32(e->p + 4)), h2 = static_cast<int32_t>(le32(e->p + 8));
    uint16_t planes = le16(e->p + 12), bpp = le16(e->p + 14);
    uint32_t compression = le32(e->p + 16);
    if (hdr < 40 || hdr > e->n || planes != 1 || compression != 0) return false;
    if (bpp != 1 && bpp != 4 && bpp != 8 && bpp != 24 && bpp != 32) return false;
    if (w <= 0 || h2 <= 0 || (h2 & 1) != 0) return false;
    e->png = false;
    e->w = static_cast<uint32_t>(w);
    e->h = static_cast<uint32_t>(h2) / 2;
    e->bpp = bpp;
    return e->w <= kDibMaxSide && e->h <= kDibMaxSide;
}

bool pick(const uint8_t* data, size_t size, Entry* best) {
    if (size < 6) return false;
    uint32_t count = le16(data + 4);
    if (count == 0 || count > kMaxEntries || 6 + static_cast<uint64_t>(count) * 16 > size) return false;
    bool found = false;
    for (uint32_t i = 0; i < count; i++) {
        const uint8_t* d = data + 6 + i * 16;
        uint64_t len = le32(d + 8), at = le32(d + 12);
        if (len == 0 || at + len > size) continue;
        Entry e = {data + at, static_cast<size_t>(len), false, 0, 0, 0};
        if (!inspect(&e)) continue;
        uint64_t area = static_cast<uint64_t>(e.w) * e.h, bestArea = static_cast<uint64_t>(best->w) * best->h;
        if (!found || area > bestArea || (area == bestArea && e.bpp > best->bpp)) {
            *best = e;
            found = true;
        }
    }
    return found;
}

bool decode_dib(const Entry& e, uint32_t maxW, uint32_t maxH, Sink* sink) {
    const uint8_t* p = e.p;
    uint32_t hdr = le32(p), w = e.w, h = e.h, bpp = e.bpp;
    uint32_t colors = 0;
    if (bpp <= 8) {
        colors = le32(p + 32);
        if (colors == 0 || colors > (1u << bpp)) colors = 1u << bpp;
    }
    uint64_t palAt = hdr, xorAt = palAt + static_cast<uint64_t>(colors) * 4;
    uint64_t xorStride = (static_cast<uint64_t>(w) * bpp + 31) / 32 * 4, andStride = (static_cast<uint64_t>(w) + 31) / 32 * 4;
    uint64_t andAt = xorAt + xorStride * h;
    if (andAt > e.n) return false;
    bool haveMask = andAt + andStride * h <= e.n;
    // A 32-bit icon carries alpha, unless every alpha byte is 0 (old icons): then the mask decides, as on Android.
    bool useAlpha = false;
    if (bpp == 32) {
        for (uint32_t y = 0; y < h && !useAlpha; y++) {
            const uint8_t* r = p + xorAt + xorStride * y;
            for (uint32_t x = 0; x < w; x++) {
                if (r[x * 4 + 3] != 0) {
                    useAlpha = true;
                    break;
                }
            }
        }
    }
    uint8_t* row = static_cast<uint8_t*>(arena_alloc(static_cast<size_t>(w) * 4));
    Scaler scaler = {};
    if (row == nullptr || !start_output(&scaler, w, h, maxW, maxH, sink)) return false;
    const uint8_t* pal = p + palAt;
    for (uint32_t y = 0; y < h; y++) {
        uint32_t sy = h - 1 - y;  // stored bottom-up
        const uint8_t* src = p + xorAt + xorStride * sy;
        const uint8_t* mask = haveMask ? p + andAt + andStride * sy : nullptr;
        for (uint32_t x = 0; x < w; x++) {
            uint8_t* d = row + static_cast<size_t>(x) * 4;
            uint8_t b, g, r, a = 255;
            if (bpp <= 8) {
                uint32_t bit = x * bpp;
                uint32_t idx = (src[bit / 8] >> (8 - bpp - bit % 8)) & ((1u << bpp) - 1);
                if (idx >= colors) idx = 0;
                b = pal[idx * 4];
                g = pal[idx * 4 + 1];
                r = pal[idx * 4 + 2];
            } else {
                const uint8_t* s = src + static_cast<size_t>(x) * (bpp / 8);
                b = s[0];
                g = s[1];
                r = s[2];
                if (useAlpha) a = s[3];
            }
            if (!useAlpha && mask != nullptr && (mask[x / 8] >> (7 - x % 8) & 1) != 0) a = 0;
            d[0] = r;
            d[1] = g;
            d[2] = b;
            d[3] = a;
        }
        if (!scaler_push(&scaler, row)) return false;
    }
    bool done = scaler_done(&scaler);
    scaler_free(&scaler);
    arena_free(row);
    return done && sink_flush(sink);
}

}  // namespace

bool decode_ico(const uint8_t* data, size_t size, uint32_t maxW, uint32_t maxH, Sink* sink, bool headerOnly,
                uint32_t* outW, uint32_t* outH) {
    Entry e = {};
    if (!pick(data, size, &e)) return false;
    if (e.png) return decode_png(e.p, e.n, maxW, maxH, sink, headerOnly, outW, outH);
    if (headerOnly) {
        *outW = e.w;
        *outH = e.h;
        return true;
    }
    return decode_dib(e, maxW, maxH, sink);
}

}  // namespace decoder
