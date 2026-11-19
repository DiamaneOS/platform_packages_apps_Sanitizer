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

// Colour: the pixels a worker hands back are in sRGB or in Display P3, and the header says which (proto.h
// ColorSpace), so the caller builds its Bitmap in that colour space, as Android's own decode does for the same file
// (SkAndroidCodec keeps the file's colour space). A file in sRGB or Display P3 is passed through untouched, which is
// exactly Android's result. A file in another colour space is converted with skcms (Android's own colour library):
// into Display P3 when its gamut reaches beyond sRGB, into sRGB otherwise. The profile comes from the file (an ICC
// profile, or HEIF and AVIF CICP values), and a profile skcms cannot read leaves the pixels as sRGB, as before.

#include <string.h>

#include <skcms.h>

#include "image.h"

namespace decoder {

uint32_t gColorSpace = kColorSrgb;

namespace {

// The largest ICC profile kept (PNG caps its chunks at 4 MiB in this program, JPEG's APP2 markers allow ~16 MiB).
constexpr size_t kMaxIccBytes = 4u << 20;

struct Xform {
    bool active;
    skcms_ICCProfile src;
    const skcms_ICCProfile* dst;
    uint8_t* icc;  // the bytes src points into, held for the worker's life
};
Xform gXform;

// Display P3: the P3 primaries with D65 white adapted to D50, and the sRGB curve (SkNamedGamut::kDisplayP3).
const skcms_ICCProfile* display_p3() {
    static skcms_ICCProfile p3;
    static bool made = false;
    if (!made) {
        skcms_Init(&p3);
        skcms_SetTransferFunction(&p3, skcms_sRGB_TransferFunction());
        const skcms_Matrix3x3 m = {{
                {0.515102f, 0.291965f, 0.157153f},
                {0.241182f, 0.692236f, 0.0665819f},
                {-0.00104941f, 0.0418818f, 0.784378f},
        }};
        skcms_SetXYZD50(&p3, &m);
        made = true;
    }
    return &p3;
}

// True when some colour of src lies outside sRGB: its primaries, converted to sRGB without clamping, leave [0, 1].
bool wider_than_srgb(const skcms_ICCProfile* src) {
    const uint8_t primaries[9] = {255, 0, 0, 0, 255, 0, 0, 0, 255};
    float out[9];
    if (!skcms_Transform(primaries, skcms_PixelFormat_RGB_888, skcms_AlphaFormat_Opaque, src, out,
                         skcms_PixelFormat_RGB_fff, skcms_AlphaFormat_Opaque, skcms_sRGB_profile(), 3)) {
        return false;
    }
    for (float v : out) {
        if (v < -1.0f / 255 || v > 1.0f + 1.0f / 255) return true;
    }
    return false;
}

// Sets up the conversion from src, which must point into memory that lives as long as the worker.
void use_profile(const skcms_ICCProfile& src) {
    if (skcms_ApproximatelyEqualProfiles(&src, skcms_sRGB_profile())) {
        gColorSpace = kColorSrgb;
        return;
    }
    if (skcms_ApproximatelyEqualProfiles(&src, display_p3())) {
        gColorSpace = kColorDisplayP3;
        return;
    }
    bool wide = wider_than_srgb(&src);
    const skcms_ICCProfile* dst = wide ? display_p3() : skcms_sRGB_profile();
    // A profile skcms cannot convert from (checked on one pixel) leaves the pixels as they are, in sRGB.
    uint8_t probe[4] = {128, 128, 128, 255};
    if (!skcms_Transform(probe, skcms_PixelFormat_RGBA_8888, skcms_AlphaFormat_Unpremul, &src, probe,
                         skcms_PixelFormat_RGBA_8888, skcms_AlphaFormat_Unpremul, dst, 1)) {
        gColorSpace = kColorSrgb;
        return;
    }
    gXform.src = src;
    gXform.dst = dst;
    gXform.active = true;
    gColorSpace = wide ? kColorDisplayP3 : kColorSrgb;
}

}  // namespace

void color_reset() {
    arena_free(gXform.icc);
    gXform = {};
    gColorSpace = kColorSrgb;
}

void color_from_icc(const uint8_t* icc, size_t len) {
    if (icc == nullptr || len == 0 || len > kMaxIccBytes || gXform.icc != nullptr) return;
    uint8_t* copy = static_cast<uint8_t*>(arena_alloc(len));
    if (copy == nullptr) return;
    memcpy(copy, icc, len);
    skcms_ICCProfile p;
    if (!skcms_Parse(copy, len, &p) || p.data_color_space != skcms_Signature_RGB) {
        arena_free(copy);
        return;  // grey, CMYK, Lab or a broken profile: sRGB, as before
    }
    gXform.icc = copy;
    use_profile(p);
}

void color_from_cicp(uint32_t primaries, uint32_t transfer) {
    // HDR transfers (PQ 16, HLG 18) are not converted here: such pixels stay as decoded, in sRGB, as before.
    if (transfer == 16 || transfer == 18) return;
    skcms_ICCProfile p;
    skcms_Init(&p);
    skcms_SetTransferFunction(&p, skcms_sRGB_TransferFunction());
    skcms_Matrix3x3 m;
    switch (primaries) {
        case 12:  // SMPTE EG 432-1: Display P3
            gColorSpace = kColorDisplayP3;
            return;
        case 9:  // BT.2020
            if (!skcms_PrimariesToXYZD50(0.708f, 0.292f, 0.170f, 0.797f, 0.131f, 0.046f, 0.3127f, 0.3290f, &m)) return;
            break;
        default:  // BT.709 / sRGB (1), unspecified (2) and the rest: sRGB, as before
            return;
    }
    skcms_SetXYZD50(&p, &m);
    use_profile(p);
}

void color_apply(uint8_t* row, uint32_t w, bool premultiplied) {
    if (!gXform.active) return;
    skcms_AlphaFormat a = premultiplied ? skcms_AlphaFormat_PremulAsEncoded : skcms_AlphaFormat_Unpremul;
    skcms_Transform(row, skcms_PixelFormat_RGBA_8888, a, &gXform.src, row, skcms_PixelFormat_RGBA_8888, a,
                    gXform.dst, w);
}

void color_warm_up() {
    skcms_DisableRuntimeCPUDetection();
    // A conversion runs once in the broker, so every first-use set-up of skcms is done before any worker is forked.
    skcms_ICCProfile p;
    skcms_Init(&p);
    skcms_SetTransferFunction(&p, skcms_sRGB_TransferFunction());
    skcms_Matrix3x3 m;
    if (skcms_PrimariesToXYZD50(0.708f, 0.292f, 0.170f, 0.797f, 0.131f, 0.046f, 0.3127f, 0.3290f, &m)) {
        skcms_SetXYZD50(&p, &m);
        use_profile(p);
        uint8_t px[8] = {10, 200, 30, 255, 250, 5, 128, 128};
        color_apply(px, 2, false);
        color_apply(px, 2, true);
    }
    color_reset();
}

}  // namespace decoder
