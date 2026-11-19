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

// Ultra HDR: a JPEG whose second image (listed in its MPF directory) is a gain map, a JPEG whose XMP carries the
// hdrgm parameters. Android's decode attaches it to the Bitmap (android.graphics.Gainmap), so an HDR screen shows the
// photo brighter than SDR. Here it is found and checked, and the worker decodes it after the base image at the same
// scale (decoder_vm.cpp). Anything that does not fit these rules leaves the photo as SDR, as before: never an error.

#include <math.h>
#include <stdlib.h>
#include <string.h>

#include "image.h"

namespace decoder {
namespace {

uint16_t be16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0] << 8 | p[1]);
}

uint32_t rd32(const uint8_t* p, bool le) {
    return le ? (uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24)
              : (uint32_t(p[0]) << 24 | uint32_t(p[1]) << 16 | uint32_t(p[2]) << 8 | uint32_t(p[3]));
}

uint16_t rd16(const uint8_t* p, bool le) {
    return le ? static_cast<uint16_t>(p[0] | p[1] << 8) : be16(p);
}

// Calls fn(marker, payload, length) for each marker segment before the image data. False when the JPEG's structure
// breaks before that.
template <typename Fn>
bool walk_markers(const uint8_t* d, size_t n, Fn fn) {
    if (n < 4 || d[0] != 0xff || d[1] != 0xd8) return false;
    size_t at = 2;
    while (at + 4 <= n) {
        if (d[at] != 0xff) return false;
        uint8_t m = d[at + 1];
        if (m == 0xff) {
            at++;
            continue;
        }
        if (m == 0xd9 || m == 0xda) return true;  // end of image, start of scan
        size_t len = be16(d + at + 2);
        if (len < 2 || at + 2 + len > n) return false;
        if (!fn(m, d + at + 4, len - 2, at + 4)) return true;
        at += 2 + len;
    }
    return false;
}

// The gain map's place: the second entry of the MPF directory (APP2 "MPF\0"), offsets from the MPF header.
bool mpf_second(const uint8_t* file, size_t size, size_t* off, size_t* len) {
    bool found = false;
    walk_markers(file, size, [&](uint8_t m, const uint8_t* p, size_t n, size_t pos) {
        if (m != 0xe2 || n < 8 + 8 || memcmp(p, "MPF\0", 4) != 0) return true;
        const uint8_t* t = p + 4;  // the TIFF-style header
        size_t tn = n - 4;
        bool le = memcmp(t, "II*\0", 4) == 0;
        if (!le && memcmp(t, "MM\0*", 4) != 0) return false;
        uint32_t ifd = rd32(t + 4, le);
        if (ifd < 8 || static_cast<uint64_t>(ifd) + 2 > tn) return false;
        uint16_t count = rd16(t + ifd, le);
        if (count > 64 || static_cast<uint64_t>(ifd) + 2 + count * 12u > tn) return false;
        for (uint16_t i = 0; i < count; i++) {
            const uint8_t* e = t + ifd + 2 + i * 12u;
            if (rd16(e, le) != 0xb002) continue;  // MP Entry: 16 bytes per image
            uint32_t bytes = rd32(e + 4, le), at = rd32(e + 8, le);
            if (bytes < 32 || bytes > 16 * 16 || static_cast<uint64_t>(at) + bytes > tn) return false;
            const uint8_t* second = t + at + 16;
            uint32_t sLen = rd32(second + 4, le), sOff = rd32(second + 8, le);
            size_t base = pos + 4;  // the file offset of the TIFF header
            if (sOff == 0 || static_cast<uint64_t>(base) + sOff + sLen > size || sLen < 4) return false;
            *off = base + sOff;
            *len = sLen;
            found = true;
            return false;
        }
        return false;
    });
    return found;
}

// One hdrgm value or three (an rdf:Seq), as an attribute (hdrgm:Key="v") or an element (<hdrgm:Key>v</...>).
// Returns how many were read: 0 when absent or unreadable.
int xmp_values(const char* x, size_t n, const char* key, float out[3]) {
    char name[48];
    size_t kl = strlen(key);
    if (kl + 7 > sizeof(name)) return 0;
    memcpy(name, "hdrgm:", 6);
    memcpy(name + 6, key, kl + 1);
    size_t nl = kl + 6;
    for (size_t i = 0; i + nl + 2 < n; i++) {
        if (memcmp(x + i, name, nl) != 0) continue;
        if (i > 0 && x[i - 1] != ' ' && x[i - 1] != '<' && x[i - 1] != '\n' && x[i - 1] != '\t' && x[i - 1] != '\r') {
            continue;
        }
        size_t at = i + nl;
        char buf[32];
        auto number = [&](size_t from, char end, float* v) {
            size_t k = 0;
            while (from < n && x[from] != end && k + 1 < sizeof(buf)) buf[k++] = x[from++];
            if (from >= n || x[from] != end || k == 0) return false;
            buf[k] = 0;
            char* stop = nullptr;
            *v = strtof(buf, &stop);
            return stop != buf && *stop == 0 && isfinite(*v);
        };
        if (x[at] == '=' && x[at + 1] == '"') {
            return number(at + 2, '"', &out[0]) ? 1 : 0;
        }
        if (x[at] != '>') continue;
        at++;
        while (at < n && (x[at] == ' ' || x[at] == '\n' || x[at] == '\r' || x[at] == '\t')) at++;
        if (at + 9 < n && memcmp(x + at, "<rdf:Seq>", 9) == 0) {
            int got = 0;
            for (size_t j = at; j + 8 < n && got < 3; j++) {
                if (memcmp(x + j, "</rdf:Seq>", 10) == 0) break;
                if (memcmp(x + j, "<rdf:li>", 8) == 0) {
                    if (!number(j + 8, '<', &out[got])) return 0;
                    got++;
                }
            }
            return got == 3 ? 3 : 0;
        }
        return number(at, '<', &out[0]) ? 1 : 0;
    }
    return 0;
}

// The parameter, one value for all channels or one per channel, else the default.
bool param(const char* x, size_t n, const char* key, float fallback, float out[3], bool required) {
    float v[3];
    int k = xmp_values(x, n, key, v);
    if (k == 0) {
        if (required) return false;
        out[0] = out[1] = out[2] = fallback;
        return true;
    }
    for (int c = 0; c < 3; c++) out[c] = v[k == 3 ? c : 0];
    return true;
}

}  // namespace

bool gainmap_params_ok(const float* p) {
    for (int i = 0; i < kGainParams; i++) {
        if (!isfinite(p[i])) return false;
    }
    for (int c = 0; c < 3; c++) {
        float lo = p[c], hi = p[3 + c], gamma = p[6 + c], es = p[9 + c], eh = p[12 + c];
        if (!(lo >= 1.0f / 65536 && lo <= hi && hi <= 65536)) return false;
        if (!(gamma > 0 && gamma <= 16)) return false;
        if (!(es >= 0 && es <= 1 && eh >= 0 && eh <= 1)) return false;
    }
    return p[15] >= 1 && p[15] <= p[16] && p[16] <= 65536;
}

bool gainmap_find(const uint8_t* file, size_t size, Gainmap* g) {
    *g = {};
    size_t off = 0, len = 0;
    if (!mpf_second(file, size, &off, &len)) return false;
    const uint8_t* d = file + off;
    // The gain map's own XMP holds its parameters, and its frame header its size.
    const char* xmp = nullptr;
    size_t xmpLen = 0;
    uint32_t w = 0, h = 0;
    static const char kXmp[] = "http://ns.adobe.com/xap/1.0/";
    bool ok = walk_markers(d, len, [&](uint8_t m, const uint8_t* p, size_t n, size_t) {
        if (m == 0xe1 && n > sizeof(kXmp) && memcmp(p, kXmp, sizeof(kXmp)) == 0 && xmp == nullptr) {
            xmp = reinterpret_cast<const char*>(p + sizeof(kXmp));
            xmpLen = n - sizeof(kXmp);
        } else if ((m >= 0xc0 && m <= 0xc3) && n >= 5) {  // baseline, extended or progressive
            h = be16(p + 1);
            w = be16(p + 3);
        }
        return true;
    });
    if (!ok || xmp == nullptr || w == 0 || h == 0) return false;
    float v[3];
    if (xmp_values(xmp, xmpLen, "Version", v) == 0 && memmem(xmp, xmpLen, "hdrgm:Version=\"", 15) == nullptr) {
        return false;
    }
    if (memmem(xmp, xmpLen, "hdrgm:BaseRenditionIsHDR=\"True\"", 31) != nullptr) return false;
    float lo[3], hi[3], gamma[3], es[3], eh[3], cmin[3], cmax[3];
    if (!param(xmp, xmpLen, "GainMapMin", 0, lo, false) || !param(xmp, xmpLen, "GainMapMax", 0, hi, true) ||
        !param(xmp, xmpLen, "Gamma", 1, gamma, false) || !param(xmp, xmpLen, "OffsetSDR", 1.0f / 64, es, false) ||
        !param(xmp, xmpLen, "OffsetHDR", 1.0f / 64, eh, false) ||
        !param(xmp, xmpLen, "HDRCapacityMin", 0, cmin, false) || !param(xmp, xmpLen, "HDRCapacityMax", 0, cmax, true)) {
        return false;
    }
    // Android's Gainmap takes ratios, the XMP gives their base-2 logarithms (except gamma and the offsets).
    for (int c = 0; c < 3; c++) {
        g->params[c] = exp2f(lo[c]);
        g->params[3 + c] = exp2f(hi[c]);
        g->params[6 + c] = gamma[c];
        g->params[9 + c] = es[c];
        g->params[12 + c] = eh[c];
    }
    g->params[15] = exp2f(cmin[0]);
    g->params[16] = exp2f(cmax[0]);
    if (!gainmap_params_ok(g->params)) return false;
    g->data = d;
    g->size = len;
    g->w = w;
    g->h = h;
    return true;
}

}  // namespace decoder
