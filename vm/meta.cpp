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

// Metadata for MediaProvider, read inside the locked-down worker: EXIF (JPEG APP1, PNG eXIf) and three XMP
// identifiers plus the motion photo marker. No allocation, every offset checked against the buffer with 64-bit
// arithmetic, fixed limits on segments, chunks and IFD entries. Text goes into the fixed record only when it passes the
// field's rule, so a hostile file can at worst leave fields empty or pick values within the rules.

#include "meta.h"

#include <string.h>

namespace decoder {
namespace {

// --- Bounded reading ----------------------------------------------------------------------------------------------

struct Span {
    const uint8_t* p;
    uint64_t n;
};

bool has(Span s, uint64_t off, uint64_t len) {
    return off <= s.n && len <= s.n - off;
}

uint16_t be16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0] << 8 | p[1]);
}

uint32_t be32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) << 24 | p[1] << 16 | p[2] << 8 | p[3];
}

const uint8_t* find(Span s, const char* needle, uint64_t from) {
    uint64_t k = strlen(needle);
    if (k == 0 || s.n < k) return nullptr;
    for (uint64_t i = from; i + k <= s.n; i++) {
        if (s.p[i] == static_cast<uint8_t>(needle[0]) && memcmp(s.p + i, needle, k) == 0) return s.p + i;
    }
    return nullptr;
}

// --- Field rules (the same rules Android checks again) --------------------------------------------------------------

bool printable(uint8_t c) {
    return c >= 0x20 && c <= 0x7e;
}

bool number_char(uint8_t c) {
    return (c >= '0' && c <= '9') || c == '.' || c == '/' || c == ' ';
}

bool id_char(uint8_t c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == ':' || c == '.' ||
           c == '-' || c == '_';
}

// Copies at most cap - 1 bytes of [p, p + n) up to a NUL. The whole field stays empty when any byte breaks the rule.
void put_text(char* dst, uint32_t cap, const uint8_t* p, uint64_t n, bool (*rule)(uint8_t)) {
    memset(dst, 0, cap);
    uint64_t len = 0;
    while (len < n && p[len] != 0) len++;
    while (len > 0 && p[len - 1] == ' ') len--;
    if (len == 0 || len >= cap) return;
    for (uint64_t i = 0; i < len; i++) {
        if (!rule(p[i])) return;
    }
    memcpy(dst, p, len);
}

void put_uint(char* dst, uint32_t cap, uint64_t v) {
    char tmp[24];
    int i = sizeof(tmp);
    do {
        tmp[--i] = static_cast<char>('0' + v % 10);
        v /= 10;
    } while (v != 0 && i > 0);
    put_text(dst, cap, reinterpret_cast<const uint8_t*>(tmp + i), sizeof(tmp) - i, number_char);
}

// "num/den", as the rational stands in the file. Android turns it into the caller's own number format.
void put_rational(char* dst, uint32_t cap, uint32_t num, uint32_t den) {
    char a[16], b[16];
    memset(dst, 0, cap);
    if (den == 0) return;
    int i = sizeof(a), j = sizeof(b);
    do {
        a[--i] = static_cast<char>('0' + num % 10);
        num /= 10;
    } while (num != 0 && i > 0);
    do {
        b[--j] = static_cast<char>('0' + den % 10);
        den /= 10;
    } while (den != 0 && j > 0);
    uint32_t la = sizeof(a) - i, lb = sizeof(b) - j;
    if (la + 1 + lb >= cap) return;
    memcpy(dst, a + i, la);
    dst[la] = '/';
    memcpy(dst + la + 1, b + j, lb);
}

// --- Dates ----------------------------------------------------------------------------------------------------------

// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's days_from_civil).
int64_t days_from_civil(int64_t y, int64_t m, int64_t d) {
    y -= m <= 2;
    int64_t era = (y >= 0 ? y : y - 399) / 400;
    int64_t yoe = y - era * 400;
    int64_t doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    int64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

bool digits(const uint8_t* p, int n, int* out) {
    int v = 0;
    for (int i = 0; i < n; i++) {
        if (p[i] < '0' || p[i] > '9') return false;
        v = v * 10 + (p[i] - '0');
    }
    *out = v;
    return true;
}

// "YYYY:MM:DD HH:MM:SS", strictly. Milliseconds since the epoch, read as UTC.
bool parse_datetime(const uint8_t* p, uint64_t n, int64_t* ms) {
    if (n < 19) return false;
    int y, mo, d, h, mi, s;
    if (!digits(p, 4, &y) || p[4] != ':' || !digits(p + 5, 2, &mo) || p[7] != ':' || !digits(p + 8, 2, &d) ||
        p[10] != ' ' || !digits(p + 11, 2, &h) || p[13] != ':' || !digits(p + 14, 2, &mi) || p[16] != ':' ||
        !digits(p + 17, 2, &s)) {
        return false;
    }
    if (y < 1900 || y > 9999 || mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || s > 60) return false;
    *ms = ((days_from_civil(y, mo, d) * 24 + h) * 60 + mi) * 60000LL + s * 1000LL;
    return true;
}

// "+HH:MM" or "-HH:MM". Minutes east of UTC.
bool parse_offset(const uint8_t* p, uint64_t n, int* minutes) {
    if (n < 6 || (p[0] != '+' && p[0] != '-') || p[3] != ':') return false;
    int h, m;
    if (!digits(p + 1, 2, &h) || !digits(p + 4, 2, &m) || h > 14 || m > 59) return false;
    *minutes = (p[0] == '-' ? -1 : 1) * (h * 60 + m);
    return true;
}

// --- TIFF / EXIF ----------------------------------------------------------------------------------------------------

constexpr uint32_t kMaxIfdEntries = 512;

struct Tiff {
    Span s;
    bool little;
    uint16_t u16(uint64_t off) const {
        const uint8_t* p = s.p + off;
        return little ? static_cast<uint16_t>(p[0] | p[1] << 8) : be16(p);
    }
    uint32_t u32(uint64_t off) const {
        const uint8_t* p = s.p + off;
        return little ? static_cast<uint32_t>(p[0] | p[1] << 8 | p[2] << 16) | static_cast<uint32_t>(p[3]) << 24
                      : be32(p);
    }
};

uint32_t type_size(uint16_t type) {
    switch (type) {
        case 1: case 2: case 6: case 7: return 1;   // BYTE, ASCII, SBYTE, UNDEFINED
        case 3: case 8: return 2;                   // SHORT, SSHORT
        case 4: case 9: case 11: return 4;          // LONG, SLONG, FLOAT
        case 5: case 10: case 12: return 8;         // RATIONAL, SRATIONAL, DOUBLE
        default: return 0;
    }
}

struct Entry {
    uint16_t tag;
    uint16_t type;
    uint32_t count;
    uint64_t data;  // offset of the value in the TIFF span, checked to hold count values
};

// Calls fn for every entry of the IFD at off whose value lies inside the TIFF data.
template <typename Fn>
void walk_ifd(const Tiff& t, uint64_t off, Fn fn) {
    if (!has(t.s, off, 2)) return;
    uint32_t n = t.u16(off);
    if (n > kMaxIfdEntries || !has(t.s, off + 2, static_cast<uint64_t>(n) * 12)) return;
    for (uint32_t i = 0; i < n; i++) {
        uint64_t e = off + 2 + static_cast<uint64_t>(i) * 12;
        Entry en = {t.u16(e), t.u16(e + 2), t.u32(e + 4), 0};
        uint64_t size = static_cast<uint64_t>(type_size(en.type)) * en.count;
        if (size == 0) continue;
        en.data = size <= 4 ? e + 8 : t.u32(e + 8);
        if (!has(t.s, en.data, size)) continue;
        fn(en);
    }
}

struct ExifState {
    bool haveOrientation = false;
    uint16_t orientation = 0;
    const uint8_t* dateOriginal = nullptr;
    uint64_t dateOriginalLen = 0;
    const uint8_t* offsetOriginal = nullptr;
    uint64_t offsetOriginalLen = 0;
    const uint8_t* subsec = nullptr;
    uint64_t subsecLen = 0;
    uint32_t lat[6] = {}, lon[6] = {};
    bool haveLat = false, haveLon = false;
    char latRef = 0, lonRef = 0;
};

void read_tiff(Span s, Meta* m, ExifState* st) {
    if (s.n < 8) return;
    Tiff t = {s, false};
    if (s.p[0] == 'I' && s.p[1] == 'I') {
        t.little = true;
    } else if (!(s.p[0] == 'M' && s.p[1] == 'M')) {
        return;
    }
    if (t.u16(2) != 42) return;
    uint64_t ifd0 = t.u32(4), exifIfd = 0, gpsIfd = 0;
    walk_ifd(t, ifd0, [&](const Entry& e) {
        if (e.tag == 0x0112 && e.type == 3) {
            st->haveOrientation = true;
            st->orientation = t.u16(e.data);
        } else if (e.tag == 0x010e && e.type == 2) {
            put_text(m->description, kTextChars, s.p + e.data, e.count, printable);
        } else if (e.tag == 0x8769 && e.type == 4) {
            exifIfd = t.u32(e.data);
        } else if (e.tag == 0x8825 && e.type == 4) {
            gpsIfd = t.u32(e.data);
        }
    });
    if (exifIfd != 0 && exifIfd != ifd0) {
        walk_ifd(t, exifIfd, [&](const Entry& e) {
            if (e.tag == 0x9003 && e.type == 2) {
                st->dateOriginal = s.p + e.data;
                st->dateOriginalLen = e.count;
            } else if (e.tag == 0x9011 && e.type == 2) {
                st->offsetOriginal = s.p + e.data;
                st->offsetOriginalLen = e.count;
            } else if (e.tag == 0x9291 && e.type == 2) {
                st->subsec = s.p + e.data;
                st->subsecLen = e.count;
            } else if (e.tag == 0x829a && e.type == 5) {
                put_rational(m->exposureTime, kNumberChars, t.u32(e.data), t.u32(e.data + 4));
            } else if (e.tag == 0x829d && e.type == 5) {
                put_rational(m->fNumber, kNumberChars, t.u32(e.data), t.u32(e.data + 4));
            } else if (e.tag == 0x8827 && (e.type == 3 || e.type == 4)) {
                put_uint(m->iso, kNumberChars, e.type == 3 ? t.u16(e.data) : t.u32(e.data));
            } else if (e.tag == 0xa406 && e.type == 3) {
                put_uint(m->sceneCaptureType, kNumberChars, t.u16(e.data));
            }
        });
    }
    if (gpsIfd != 0 && gpsIfd != ifd0 && gpsIfd != exifIfd) {
        walk_ifd(t, gpsIfd, [&](const Entry& e) {
            if (e.tag == 0x0001 && e.type == 2) {
                st->latRef = static_cast<char>(s.p[e.data]);
            } else if (e.tag == 0x0003 && e.type == 2) {
                st->lonRef = static_cast<char>(s.p[e.data]);
            } else if ((e.tag == 0x0002 || e.tag == 0x0004) && e.type == 5 && e.count == 3) {
                uint32_t* v = e.tag == 0x0002 ? st->lat : st->lon;
                for (int i = 0; i < 6; i++) v[i] = t.u32(e.data + 4 * static_cast<uint64_t>(i));
                (e.tag == 0x0002 ? st->haveLat : st->haveLon) = true;
            }
        });
    }
}

// Degrees, minutes, seconds as rationals, to degrees * 1e7. False for a zero denominator or out of range.
bool dms_e7(const uint32_t* v, char ref, char pos, char neg, int64_t limit, int32_t* out) {
    if (v[1] == 0 || v[3] == 0 || v[5] == 0 || (ref != pos && ref != neg)) return false;
    // Each part in 1e-7 degrees, in 128-bit-safe steps: the numerators are 32-bit, so 1e7 * 2^32 fits in 64 bits.
    int64_t deg = static_cast<int64_t>(v[0]) * 10000000 / v[1];
    int64_t min = static_cast<int64_t>(v[2]) * 10000000 / v[3] / 60;
    int64_t sec = static_cast<int64_t>(v[4]) * 10000000 / v[5] / 3600;
    int64_t total = deg + min + sec;
    if (total > limit * 10000000) return false;
    *out = static_cast<int32_t>(ref == neg ? -total : total);
    return true;
}

void finish_exif(Meta* m, const ExifState& st) {
    if (st.haveOrientation) {
        // As ExifInterface.getRotationDegrees: mirrored orientations take the rotation of their pair.
        switch (st.orientation) {
            case 1: case 2: m->orientation = 0; break;
            case 3: case 4: m->orientation = 180; break;
            case 5: case 8: m->orientation = 270; break;
            case 6: case 7: m->orientation = 90; break;
            default: break;
        }
        if (m->orientation >= 0) m->flags |= kHasOrientation;
    }
    int64_t ms;
    if (st.dateOriginal != nullptr && parse_datetime(st.dateOriginal, st.dateOriginalLen, &ms)) {
        if (st.subsec != nullptr) {
            int frac = 0, k = 0;
            for (uint64_t i = 0; i < st.subsecLen && k < 3 && st.subsec[i] >= '0' && st.subsec[i] <= '9'; i++, k++) {
                frac = frac * 10 + (st.subsec[i] - '0');
            }
            if (k > 0) {
                while (k < 3) frac *= 10, k++;
                ms += frac;
            }
        }
        int offset;
        if (st.offsetOriginal != nullptr && parse_offset(st.offsetOriginal, st.offsetOriginalLen, &offset)) {
            ms -= offset * 60000LL;
            m->flags |= kOffsetKnown;
        }
        m->dateTakenMillis = ms;
        m->flags |= kHasDate;
    }
    int32_t lat, lon;
    if (st.haveLat && st.haveLon && dms_e7(st.lat, st.latRef, 'N', 'S', 90, &lat) &&
        dms_e7(st.lon, st.lonRef, 'E', 'W', 180, &lon)) {
        m->latitudeE7 = lat;
        m->longitudeE7 = lon;
        m->flags |= kHasGps;
    }
}

// --- XMP ------------------------------------------------------------------------------------------------------------

// The value of key="..." or <key>...</key>, into dst under the identifier rule.
void xmp_value(Span x, const char* key, char* dst) {
    char pat[64];
    size_t k = strlen(key);
    if (k + 3 > sizeof(pat)) return;
    memcpy(pat, key, k);
    pat[k] = '=';
    pat[k + 1] = '"';
    pat[k + 2] = 0;
    const uint8_t* v = find(x, pat, 0);
    uint8_t end = '"';
    if (v != nullptr) {
        v += k + 2;
    } else {
        pat[0] = '<';
        memcpy(pat + 1, key, k);
        pat[k + 1] = '>';
        pat[k + 2] = 0;
        v = find(x, pat, 0);
        if (v == nullptr) return;
        v += k + 2;
        end = '<';
    }
    uint64_t at = static_cast<uint64_t>(v - x.p), len = 0;
    while (at + len < x.n && x.p[at + len] != end && len < kIdChars) len++;
    if (at + len >= x.n || x.p[at + len] != end) return;
    put_text(dst, kIdChars, v, len, id_char);
}

void read_xmp(Span x, Meta* m) {
    xmp_value(x, "xmpMM:DocumentID", m->documentId);
    xmp_value(x, "xmpMM:InstanceID", m->instanceId);
    xmp_value(x, "xmpMM:OriginalDocumentID", m->originalDocumentId);
    if (find(x, "Camera:MotionPhoto=\"1\"", 0) != nullptr || find(x, "GCamera:MicroVideo=\"1\"", 0) != nullptr) {
        m->specialFormat = kSpecialMotionPhoto;
    }
}

// --- Containers -----------------------------------------------------------------------------------------------------

constexpr uint32_t kMaxSegments = 512;
constexpr uint32_t kMaxChunks = 4096;

void read_jpeg(Span s, Meta* m) {
    ExifState st;
    uint64_t at = 2;
    for (uint32_t i = 0; i < kMaxSegments && has(s, at, 4); i++) {
        if (s.p[at] != 0xff) return;
        uint8_t marker = s.p[at + 1];
        if (marker == 0xd8 || (marker >= 0xd0 && marker <= 0xd7) || marker == 0x01 || marker == 0xff) {
            at += marker == 0xff ? 1 : 2;
            continue;
        }
        if (marker == 0xda || marker == 0xd9) break;  // image data or the end: no metadata after this
        uint16_t len = be16(s.p + at + 2);
        if (len < 2 || !has(s, at + 2, len)) break;
        Span seg = {s.p + at + 4, static_cast<uint64_t>(len) - 2};
        if (marker == 0xe1 && seg.n >= 6 && memcmp(seg.p, "Exif\0\0", 6) == 0) {
            read_tiff({seg.p + 6, seg.n - 6}, m, &st);
        } else if (marker == 0xe1 && seg.n >= 29 && memcmp(seg.p, "http://ns.adobe.com/xap/1.0/\0", 29) == 0) {
            read_xmp({seg.p + 29, seg.n - 29}, m);
        }
        at += 2 + static_cast<uint64_t>(len);
    }
    finish_exif(m, st);
}

void read_png(Span s, Meta* m) {
    ExifState st;
    uint64_t at = 8;
    for (uint32_t i = 0; i < kMaxChunks && has(s, at, 12); i++) {
        uint32_t len = be32(s.p + at);
        const uint8_t* type = s.p + at + 4;
        if (!has(s, at + 8, static_cast<uint64_t>(len) + 4)) break;
        Span data = {s.p + at + 8, len};
        if (memcmp(type, "eXIf", 4) == 0) {
            read_tiff(data, m, &st);
        } else if (memcmp(type, "iTXt", 4) == 0 && data.n > 18 && memcmp(data.p, "XML:com.adobe.xmp\0", 18) == 0) {
            // keyword, NUL, compression flag, method, language tag NUL, translated keyword NUL, text. Only
            // uncompressed text: inflating is not worth the risk for three identifiers.
            uint64_t p = 18;
            if (has(data, p, 2) && data.p[p] == 0) {
                p += 2;
                while (p < data.n && data.p[p] != 0) p++;
                p++;
                while (p < data.n && data.p[p] != 0) p++;
                p++;
                if (p < data.n) read_xmp({data.p + p, data.n - p}, m);
            }
        } else if (memcmp(type, "IEND", 4) == 0) {
            break;
        }
        at += 12 + static_cast<uint64_t>(len);
    }
    finish_exif(m, st);
}

}  // namespace

void read_metadata(const uint8_t* data, size_t size, uint32_t format, Meta* m) {
    Span s = {data, size};
    if (format == kFormatJpeg) {
        read_jpeg(s, m);
    } else if (format == kFormatPng) {
        read_png(s, m);
    }
}

bool png_is_animated(const uint8_t* data, size_t size) {
    Span s = {data, size};
    uint64_t at = 8;
    for (uint32_t i = 0; i < kMaxChunks && has(s, at, 12); i++) {
        uint32_t len = be32(s.p + at);
        const uint8_t* type = s.p + at + 4;
        if (memcmp(type, "acTL", 4) == 0) return true;
        if (memcmp(type, "IDAT", 4) == 0 || memcmp(type, "IEND", 4) == 0) return false;
        if (!has(s, at + 8, static_cast<uint64_t>(len) + 4)) return false;
        at += 12 + static_cast<uint64_t>(len);
    }
    return false;
}

}  // namespace decoder
