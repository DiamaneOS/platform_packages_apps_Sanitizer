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

// HEIF (HEIC) and AVIF: a small, strict reader of the ISO base media file format (ISO/IEC 14496-12) and its image
// items (ISO/IEC 23008-12), with HEVC through the tree's libhevc and AV1 through the tree's dav1d, both in software
// and single-threaded. No HEIF reader in the tree runs outside Android's media framework, and libavif is not in the
// tree, hence this reader.
//
// What it reads: the primary item (pitm), a single coded image or a grid of them (camera photos are tiled HEVC
// grids), its alpha item (auxl with the alpha auxC), premultiplied alpha (prem), the display transform (irot, imir),
// the colour description (colr nclx, else the bitstream's own), and for image sequences (animated AVIF, HEIF
// sequences) the first sample of the first picture track and its alpha track. The Exif and XMP items go to the
// metadata record.
//
// Limits, all checked before the memory they guard is asked for: box nesting depth and count, items, properties,
// associations, extents and references, the grid's tile count, each coded image's size, all tiles' pixels together,
// and the rows of tiles held at once. A grid is decoded one row of tiles at a time and streamed through the scaler,
// so a 50 MP photo never needs its whole picture in memory.

#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>

#include <dav1d/dav1d.h>

#include "ihevc_typedefs.h"
#include "ihevc_defs.h"
#include "ihevcd_cxa.h"
#include "image.h"
#include "iv.h"
#include "ivd.h"
#include "meta.h"
#include "warmup_formats.h"

#if defined(__aarch64__)
// libhevc's arm64 assembly has no BTI landing pads. Its ARMv8 function table (ihevcd_function_selector_av8.c) is the
// only thing that refers to it, so defining the table's setup here keeps the table and all the assembly out of the
// link, and the program keeps BTI. Every arm64 processor choice gets the C routines.
extern "C" void ihevcd_init_function_ptr_noneon(void* codec);
extern "C" void ihevcd_init_function_ptr_av8(void* codec) { ihevcd_init_function_ptr_noneon(codec); }
#endif

namespace decoder {
namespace {

constexpr uint32_t kMaxDepth = 8;          // box nesting: meta/iprp/ipco/property, moov/trak/mdia/minf/stbl/stsd/entry/config
constexpr uint32_t kMaxBoxes = 16384;      // boxes read in the whole file
constexpr uint32_t kMaxItems = 4096;
constexpr uint32_t kMaxProps = 1024;
constexpr uint32_t kMaxAssoc = 32;         // property associations per item
constexpr uint32_t kMaxExtents = 64;       // per item
constexpr uint32_t kMaxRefs = 8192;        // item references, all types together
constexpr uint32_t kMaxTracks = 16;
constexpr uint32_t kMaxGridTiles = 1024;
constexpr uint32_t kMaxGridColumns = 64;  // a row of tiles is held at once
constexpr uint64_t kMaxCodedPixels = 16u << 20;  // one coded image: a tile or a whole image
constexpr uint64_t kMaxGridPixels = 256u << 20;  // all tiles of a grid together
constexpr size_t kSlack = 4u << 20;              // decoder state, scaler and stripe buffer, besides what is counted
// Measured (decoder_vm_hosttest --bench): what the decoders hold per pixel of one coded image, besides its picture.
// libhevc: 208.5 MiB for a 12 MP single image, about 14.4 bytes a pixel besides the two pictures.
constexpr uint64_t kHevcBytesPerPixel = 16;
constexpr uint64_t kAv1BytesPerPixel = 3;

constexpr uint32_t fourcc(const char* s) {
    return static_cast<uint32_t>(s[0]) << 24 | static_cast<uint32_t>(s[1]) << 16 | static_cast<uint32_t>(s[2]) << 8 |
           static_cast<uint32_t>(s[3]);
}

// ---------------------------------------------------------------------------------------------------------------
// Bounded reading.

struct Span {
    const uint8_t* p;
    uint64_t n;
};

struct Reader {
    Span s;
    uint64_t at;
    bool bad;
    bool has(uint64_t k) {
        if (bad || k > s.n || at > s.n - k) bad = true;
        return !bad;
    }
    uint64_t un(uint32_t bytes) {
        if (bytes > 8 || !has(bytes)) return 0;
        uint64_t v = 0;
        for (uint32_t i = 0; i < bytes; i++) v = v << 8 | s.p[at + i];
        at += bytes;
        return v;
    }
    uint8_t u8() { return static_cast<uint8_t>(un(1)); }
    uint16_t u16() { return static_cast<uint16_t>(un(2)); }
    uint32_t u32() { return static_cast<uint32_t>(un(4)); }
    uint64_t u64() { return un(8); }
    void skip(uint64_t k) {
        if (has(k)) at += k;
    }
    Span rest() { return bad ? Span{s.p, 0} : Span{s.p + at, s.n - at}; }
    // A NUL-terminated string: its bytes without the NUL.
    Span cstr() {
        uint64_t i = at;
        while (i < s.n && s.p[i] != 0) i++;
        if (i >= s.n) {
            bad = true;
            return {s.p, 0};
        }
        Span r = {s.p + at, i - at};
        at = i + 1;
        return r;
    }
};

struct Box {
    uint32_t type;
    Span body;  // after the header
};

// The children of a box, one at a time. A box that runs past its parent is an error, except at the top level of a
// cut-off file (a probe reads only the start), where it ends the walk.
struct BoxWalker {
    Span s;
    uint64_t at;
    uint32_t* budget;
    bool topLevel;
    bool bad;
    bool cut;
    bool next(Box* b) {
        if (bad || cut || at >= s.n) return false;
        if (*budget == 0) return fail();
        (*budget)--;
        if (s.n - at < 8) return topLevel ? stop() : fail();
        Reader r = {s, at, false};
        uint64_t size = r.u32();
        b->type = r.u32();
        if (size == 1) {
            if (!r.has(8)) return topLevel ? stop() : fail();
            size = r.u64();
        } else if (size == 0) {
            size = s.n - at;
        }
        if (b->type == fourcc("uuid")) r.skip(16);
        uint64_t hdr = r.at - at;
        if (r.bad || size < hdr) return topLevel && r.bad ? stop() : fail();
        if (size > s.n - at) {
            if (!topLevel) return fail();
            b->body = {s.p + at + hdr, s.n - at - hdr};
            cut = true;
            at = s.n;
            return true;
        }
        b->body = {s.p + at + hdr, size - hdr};
        at += size;
        return true;
    }
    bool fail() {
        bad = true;
        return false;
    }
    bool stop() {
        cut = true;
        return false;
    }
};

// ---------------------------------------------------------------------------------------------------------------
// The file's structure.

struct Prop {
    uint32_t type;
    Span body;
};

struct Item {
    uint32_t id;
    uint32_t type;
    Span contentType;  // 'mime' items
    bool hasLoc;
    uint8_t method;  // 0: file offsets, 1: idat
    uint64_t base;
    uint32_t ext0, nExt;
    uint8_t nAssoc;
    uint16_t assoc[kMaxAssoc];
    bool essential[kMaxAssoc];
};

struct Extent {
    uint64_t offset, length;
};

struct Ref {
    uint32_t type, from, to;
};

// The first sample of a picture track.
struct Track {
    uint32_t id;
    uint32_t auxFor;  // the track an auxl reference points to, 0 for none
    uint32_t codec;   // the sample entry: av01, hvc1, hev1
    Span config;      // its av1C or hvcC body
    Span nclx;        // its colr nclx body, if any
    uint32_t w, h;
    uint32_t samples;
    uint64_t offset, size;  // the first sample in the file
};

struct File {
    Span data;
    bool cut;  // the input ends inside a box (a probe)
    uint32_t boxes;
    Item* items;
    uint32_t nItems;
    uint16_t* index;  // item id -> position + 1, open addressing (kIndexSlots), so a lookup costs one or a few probes
    Prop* props;
    uint32_t nProps;
    Extent* extents;
    uint32_t nExtents;
    Ref* refs;
    uint32_t nRefs;
    Span idat;
    bool hasPrimary;
    uint32_t primary;
    bool hasMeta;
    Track tracks[kMaxTracks];
    uint32_t nTracks;
};

constexpr uint32_t kIndexSlots = 8192;  // twice kMaxItems, a power of two

uint32_t slot_of(uint32_t id) {
    return (id * 0x9e3779b1u) >> 19;  // the top 13 bits
}

Item* find_item(File* f, uint32_t id) {
    for (uint32_t s = slot_of(id), n = 0; n < kIndexSlots; s = (s + 1) & (kIndexSlots - 1), n++) {
        uint16_t v = f->index[s];
        if (v == 0) return nullptr;
        if (f->items[v - 1].id == id) return &f->items[v - 1];
    }
    return nullptr;
}

void index_item(File* f, uint32_t pos) {
    uint32_t s = slot_of(f->items[pos].id);
    while (f->index[s] != 0) s = (s + 1) & (kIndexSlots - 1);
    f->index[s] = static_cast<uint16_t>(pos + 1);
}

const Prop* item_prop(const File* f, const Item* it, uint32_t type) {
    for (uint32_t i = 0; i < it->nAssoc; i++) {
        const Prop& p = f->props[it->assoc[i] - 1];
        if (p.type == type) return &p;
    }
    return nullptr;
}

bool parse_iinf(File* f, Span body) {
    Reader r = {body, 0, false};
    uint32_t version = r.u8();
    r.skip(3);
    uint32_t count = version == 0 ? r.u16() : r.u32();
    if (r.bad || count > kMaxItems) return false;
    BoxWalker w = {r.rest(), 0, &f->boxes, false, false, false};
    Box b;
    for (uint32_t i = 0; i < count; i++) {
        if (!w.next(&b) || b.type != fourcc("infe")) return false;
        Reader e = {b.body, 0, false};
        uint32_t v = e.u8();
        e.skip(3);
        if (v < 2) continue;  // no item type in versions 0 and 1: not an image
        uint32_t id = v == 2 ? e.u16() : e.u32();
        uint16_t protection = e.u16();
        uint32_t type = e.u32();
        e.cstr();  // item_name
        Span content = {nullptr, 0};
        if (type == fourcc("mime")) content = e.cstr();
        if (e.bad || id == 0 || find_item(f, id) != nullptr) return false;
        Item& it = f->items[f->nItems];
        memset(&it, 0, sizeof(it));
        it.id = id;
        it.type = protection != 0 ? 0 : type;  // protected items are never decoded
        it.contentType = content;
        index_item(f, f->nItems++);
    }
    return !w.bad;
}

bool parse_iloc(File* f, Span body) {
    Reader r = {body, 0, false};
    uint32_t version = r.u8();
    r.skip(3);
    if (version > 2) return false;
    uint8_t a = r.u8(), b = r.u8();
    uint32_t offSize = a >> 4, lenSize = a & 15, baseSize = b >> 4, idxSize = version > 0 ? (b & 15) : 0;
    for (uint32_t s : {offSize, lenSize, baseSize, idxSize}) {
        if (s != 0 && s != 4 && s != 8) return false;
    }
    uint32_t count = version < 2 ? r.u16() : r.u32();
    if (r.bad || count > kMaxItems) return false;
    for (uint32_t i = 0; i < count; i++) {
        uint32_t id = version < 2 ? r.u16() : r.u32();
        uint8_t method = version > 0 ? static_cast<uint8_t>(r.u16() & 15) : 0;
        uint16_t dataRef = r.u16();
        uint64_t base = r.un(baseSize);
        uint32_t n = r.u16();
        if (r.bad || n > kMaxExtents || f->nExtents + n > kMaxItems * 4) return false;
        Item* it = find_item(f, id);
        bool keep = it != nullptr && !it->hasLoc;
        if (it != nullptr && it->hasLoc) return false;  // two locations for one item
        if (keep) {
            it->hasLoc = true;
            it->method = method;
            it->base = base;
            it->ext0 = f->nExtents;
            it->nExt = n;
            if (dataRef != 0 || method > 1) it->type = 0;  // elsewhere or derived from another item: not read
        }
        for (uint32_t k = 0; k < n; k++) {
            r.un(idxSize);
            uint64_t off = r.un(offSize), len = r.un(lenSize);
            if (keep) f->extents[f->nExtents++] = {off, len};
        }
        if (r.bad) return false;
    }
    return true;
}

bool parse_iprp(File* f, Span body, uint32_t depth) {
    if (depth > kMaxDepth) return false;
    BoxWalker w = {body, 0, &f->boxes, false, false, false};
    Box b;
    bool ipco = false;
    uint32_t ipmas = 0;
    while (w.next(&b)) {
        if (b.type == fourcc("ipco")) {
            if (ipco) return false;
            ipco = true;
            BoxWalker pw = {b.body, 0, &f->boxes, false, false, false};
            Box p;
            while (pw.next(&p)) {
                if (f->nProps >= kMaxProps) return false;
                f->props[f->nProps++] = {p.type, p.body};
            }
            if (pw.bad) return false;
        } else if (b.type == fourcc("ipma")) {
            // One per version and flags combination at most (ISO/IEC 23008-12): two in practice.
            if (++ipmas > 2) return false;
            Reader r = {b.body, 0, false};
            uint32_t version = r.u8();
            uint32_t flags = static_cast<uint32_t>(r.un(3));
            uint32_t count = r.u32();
            if (r.bad || count > kMaxItems) return false;
            for (uint32_t i = 0; i < count; i++) {
                uint32_t id = version < 1 ? r.u16() : r.u32();
                uint32_t n = r.u8();
                Item* it = find_item(f, id);
                if (r.bad || n > kMaxAssoc || (it != nullptr && it->nAssoc != 0)) return false;
                for (uint32_t k = 0; k < n; k++) {
                    uint32_t v = (flags & 1) ? r.u16() : r.u8();
                    bool essential = (flags & 1) ? (v & 0x8000) != 0 : (v & 0x80) != 0;
                    uint32_t index = (flags & 1) ? (v & 0x7fff) : (v & 0x7f);
                    if (r.bad) return false;
                    if (index == 0) continue;
                    if (index > f->nProps) return false;
                    if (it != nullptr) {
                        it->assoc[it->nAssoc] = static_cast<uint16_t>(index);
                        it->essential[it->nAssoc] = essential;
                        it->nAssoc++;
                    }
                }
            }
        }
    }
    return !w.bad && ipco;
}

bool parse_iref(File* f, Span body) {
    Reader r = {body, 0, false};
    uint32_t version = r.u8();
    r.skip(3);
    if (r.bad) return false;
    BoxWalker w = {r.rest(), 0, &f->boxes, false, false, false};
    Box b;
    while (w.next(&b)) {
        Reader e = {b.body, 0, false};
        uint32_t from = version == 0 ? e.u16() : e.u32();
        uint32_t n = e.u16();
        if (e.bad || f->nRefs + n > kMaxRefs) return false;
        for (uint32_t i = 0; i < n; i++) {
            uint32_t to = version == 0 ? e.u16() : e.u32();
            if (e.bad) return false;
            f->refs[f->nRefs++] = {b.type, from, to};
        }
    }
    return !w.bad;
}

bool parse_meta(File* f, Span body) {
    Reader r = {body, 0, false};
    r.skip(4);  // version, flags
    if (r.bad) return false;
    BoxWalker w = {r.rest(), 0, &f->boxes, false, false, false};
    Box b;
    Span iinf = {}, iloc = {}, iprp = {}, iref = {}, pitm = {};
    bool hdlr = false, haveIinf = false, haveIloc = false, haveIprp = false, haveIref = false, havePitm = false,
         haveIdat = false;
    auto once = [](bool* seen) {
        if (*seen) return false;
        *seen = true;
        return true;
    };
    while (w.next(&b)) {
        if (b.type == fourcc("hdlr")) {
            Reader h = {b.body, 0, false};
            h.skip(8);
            if (h.u32() != fourcc("pict") || h.bad) return false;
            hdlr = true;
        } else if (b.type == fourcc("iinf")) {
            if (!once(&haveIinf)) return false;
            iinf = b.body;
        } else if (b.type == fourcc("iloc")) {
            if (!once(&haveIloc)) return false;
            iloc = b.body;
        } else if (b.type == fourcc("iprp")) {
            if (!once(&haveIprp)) return false;
            iprp = b.body;
        } else if (b.type == fourcc("iref")) {
            if (!once(&haveIref)) return false;
            iref = b.body;
        } else if (b.type == fourcc("pitm")) {
            if (!once(&havePitm)) return false;
            pitm = b.body;
        } else if (b.type == fourcc("idat")) {
            if (!once(&haveIdat)) return false;
            f->idat = b.body;
        }
    }
    if (w.bad || !hdlr || !haveIinf || !parse_iinf(f, iinf)) return false;
    if (haveIloc && !parse_iloc(f, iloc)) return false;
    if (haveIprp && !parse_iprp(f, iprp, 2)) return false;
    if (haveIref && !parse_iref(f, iref)) return false;
    if (havePitm) {
        Reader p = {pitm, 0, false};
        uint32_t version = p.u8();
        p.skip(3);
        f->primary = version == 0 ? p.u16() : p.u32();
        if (p.bad) return false;
        f->hasPrimary = true;
    }
    f->hasMeta = true;
    return true;
}

// A picture track's first sample: moov/trak/{tkhd, tref, mdia/{hdlr, minf/stbl/{stsd, stsz, stco or co64}}}.
bool parse_trak(File* f, Span body, Track* t) {
    memset(t, 0, sizeof(*t));
    BoxWalker w = {body, 0, &f->boxes, false, false, false};
    Box b;
    bool picture = false;
    Span stbl = {nullptr, 0};
    while (w.next(&b)) {
        if (b.type == fourcc("tkhd")) {
            Reader r = {b.body, 0, false};
            uint32_t version = r.u8();
            r.skip(3);
            r.skip(version == 1 ? 16 : 8);
            t->id = r.u32();
            if (r.bad) return false;
        } else if (b.type == fourcc("tref")) {
            BoxWalker rw = {b.body, 0, &f->boxes, false, false, false};
            Box rb;
            while (rw.next(&rb)) {
                Reader r = {rb.body, 0, false};
                if (rb.type == fourcc("auxl") && rb.body.n >= 4) t->auxFor = r.u32();
            }
            if (rw.bad) return false;
        } else if (b.type == fourcc("mdia")) {
            BoxWalker mw = {b.body, 0, &f->boxes, false, false, false};
            Box mb;
            while (mw.next(&mb)) {
                if (mb.type == fourcc("hdlr")) {
                    Reader r = {mb.body, 0, false};
                    r.skip(8);
                    uint32_t handler = r.u32();
                    picture = !r.bad && (handler == fourcc("pict") || handler == fourcc("vide") ||
                                         handler == fourcc("auxv"));
                } else if (mb.type == fourcc("minf")) {
                    BoxWalker iw = {mb.body, 0, &f->boxes, false, false, false};
                    Box ib;
                    while (iw.next(&ib)) {
                        if (ib.type == fourcc("stbl")) stbl = ib.body;
                    }
                    if (iw.bad) return false;
                }
            }
            if (mw.bad) return false;
        }
    }
    if (w.bad) return false;
    if (!picture || stbl.p == nullptr) return true;  // not a picture track: ignored
    BoxWalker sw = {stbl, 0, &f->boxes, false, false, false};
    bool haveEntry = false, haveSize = false, haveOffset = false;
    while (sw.next(&b)) {
        Reader r = {b.body, 0, false};
        if (b.type == fourcc("stsd")) {
            r.skip(4);
            if (r.u32() == 0 || r.bad) return false;
            BoxWalker ew = {r.rest(), 0, &f->boxes, false, false, false};
            Box e;
            if (!ew.next(&e)) return false;
            t->codec = e.type;
            if (e.type != fourcc("av01") && e.type != fourcc("hvc1") && e.type != fourcc("hev1")) continue;
            Reader v = {e.body, 0, false};
            v.skip(24);
            t->w = v.u16();
            t->h = v.u16();
            v.skip(50);
            if (v.bad) return false;
            BoxWalker cw = {v.rest(), 0, &f->boxes, false, false, false};
            Box c;
            while (cw.next(&c)) {
                if (c.type == fourcc("av1C") || c.type == fourcc("hvcC")) t->config = c.body;
                if (c.type == fourcc("colr") && c.body.n >= 4 && memcmp(c.body.p, "nclx", 4) == 0) t->nclx = c.body;
            }
            if (cw.bad) return false;
            haveEntry = t->config.p != nullptr;
        } else if (b.type == fourcc("stsz")) {
            r.skip(4);
            uint32_t sampleSize = r.u32();
            t->samples = r.u32();
            t->size = sampleSize != 0 ? sampleSize : r.u32();
            if (r.bad || t->samples == 0) return false;
            haveSize = true;
        } else if (b.type == fourcc("stco") || b.type == fourcc("co64")) {
            r.skip(4);
            if (r.u32() == 0) return false;
            t->offset = b.type == fourcc("stco") ? r.u32() : r.u64();
            if (r.bad) return false;
            haveOffset = true;
        }
    }
    if (sw.bad) return false;
    if (!haveEntry || !haveSize || !haveOffset) t->codec = 0;
    return true;
}

bool parse_moov(File* f, Span body) {
    BoxWalker w = {body, 0, &f->boxes, false, false, false};
    Box b;
    while (w.next(&b)) {
        if (b.type != fourcc("trak")) continue;
        if (f->nTracks >= kMaxTracks) return false;
        Track* t = &f->tracks[f->nTracks];
        if (!parse_trak(f, b.body, t)) return false;
        if (t->codec != 0) f->nTracks++;
    }
    return !w.bad;
}

// Parses the whole file. Allocates the tables from the arena (freed with the worker).
bool parse_file(const uint8_t* data, size_t size, File* f) {
    memset(f, 0, sizeof(*f));
    f->data = {data, size};
    f->boxes = kMaxBoxes;
    f->items = static_cast<Item*>(arena_alloc(sizeof(Item) * kMaxItems));
    f->props = static_cast<Prop*>(arena_alloc(sizeof(Prop) * kMaxProps));
    f->extents = static_cast<Extent*>(arena_alloc(sizeof(Extent) * kMaxItems * 4));
    f->refs = static_cast<Ref*>(arena_alloc(sizeof(Ref) * kMaxRefs));
    f->index = static_cast<uint16_t*>(arena_calloc(kIndexSlots, sizeof(uint16_t)));
    if (f->items == nullptr || f->props == nullptr || f->extents == nullptr || f->refs == nullptr ||
        f->index == nullptr) {
        return false;
    }
    BoxWalker w = {f->data, 0, &f->boxes, true, false, false};
    Box b;
    bool ftyp = false, meta = false, moov = false;
    bool first = true;
    while (w.next(&b)) {
        if (first && b.type != fourcc("ftyp")) return false;
        first = false;
        bool complete = !w.cut;
        if (b.type == fourcc("ftyp")) {
            if (ftyp || !complete) return false;
            ftyp = true;
        } else if (b.type == fourcc("meta")) {
            if (meta || !complete || !parse_meta(f, b.body)) return false;
            meta = true;
        } else if (b.type == fourcc("moov")) {
            if (moov) return false;
            moov = true;
            if (complete && !parse_moov(f, b.body)) return false;
        }
    }
    f->cut = w.cut;
    return !w.bad && ftyp && (meta || moov);
}

// An item's bytes: one extent in place, several copied together into the arena.
bool item_data(const File* f, const Item* it, Span* out) {
    if (!it->hasLoc || it->nExt == 0) return false;
    Span src = it->method == 0 ? f->data : f->idat;
    const Extent* e = f->extents + it->ext0;
    uint64_t total = 0;
    for (uint32_t i = 0; i < it->nExt; i++) {
        uint64_t off = it->base + e[i].offset, len = e[i].length;
        if (off < it->base || off > src.n) return false;
        if (len == 0) {
            if (it->nExt != 1) return false;
            len = src.n - off;
        }
        if (len > src.n - off) return false;
        total += len;
    }
    if (total == 0 || total > f->data.n) return false;
    if (it->nExt == 1) {
        uint64_t off = it->base + e[0].offset;
        *out = {src.p + off, e[0].length == 0 ? src.n - off : e[0].length};
        return true;
    }
    uint8_t* buf = static_cast<uint8_t*>(arena_alloc(total));
    if (buf == nullptr) return false;
    uint64_t at = 0;
    for (uint32_t i = 0; i < it->nExt; i++) {
        memcpy(buf + at, src.p + it->base + e[i].offset, e[i].length);
        at += e[i].length;
    }
    *out = {buf, total};
    return true;
}

// The properties this reader acts on or may safely leave aside. An essential property outside this list changes
// what the image is (layers, a crop it would ignore at its peril): such an image is not decoded.
bool understood(uint32_t type) {
    switch (type) {
        case fourcc("ispe"): case fourcc("hvcC"): case fourcc("av1C"): case fourcc("colr"): case fourcc("pixi"):
        case fourcc("irot"): case fourcc("imir"): case fourcc("auxC"): case fourcc("pasp"): case fourcc("clap"):
        case fourcc("clli"): case fourcc("mdcv"): case fourcc("cclv"): case fourcc("amve"): case fourcc("rloc"):
            return true;
        default:
            return false;
    }
}

bool all_understood(const File* f, const Item* it) {
    for (uint32_t i = 0; i < it->nAssoc; i++) {
        if (it->essential[i] && !understood(f->props[it->assoc[i] - 1].type)) return false;
    }
    return true;
}

bool ispe(const File* f, const Item* it, uint32_t* w, uint32_t* h) {
    const Prop* p = item_prop(f, it, fourcc("ispe"));
    if (p == nullptr) return false;
    Reader r = {p->body, 0, false};
    r.skip(4);
    *w = r.u32();
    *h = r.u32();
    return !r.bad && *w != 0 && *h != 0 && *w <= kMaxDimension && *h <= kMaxDimension;
}

// The display transform: mirrored left to right first when flip, then turned clockwise by deg. irot and imir apply
// in the order the item lists them. Mirroring after a turn is the same as turning the other way after the mirror.
void transform_of(const File* f, const Item* it, bool* flip, uint32_t* deg) {
    bool fl = false;
    uint32_t r = 0;
    for (uint32_t i = 0; i < it->nAssoc; i++) {
        const Prop& p = f->props[it->assoc[i] - 1];
        if (p.body.n < 1) continue;
        if (p.type == fourcc("irot")) {
            r = (r + 360 - 90 * (p.body.p[0] & 3)) % 360;  // irot turns anticlockwise
        } else if (p.type == fourcc("imir")) {
            fl = !fl;
            // axis 0 exchanges top and bottom (a mirror and a half turn), axis 1 left and right, as libheif and libavif
            // read it (ISO/IEC 23008-12:2022).
            r = (p.body.p[0] & 1) == 0 ? (540 - r) % 360 : (360 - r) % 360;
        }
    }
    *flip = fl;
    *deg = r;
}

// ---------------------------------------------------------------------------------------------------------------
// Colour: YCbCr to RGB with the matrix and range the file declares.

struct Nclx {
    uint16_t matrix;
    bool full;
    bool known;
};

Nclx parse_nclx(Span body) {
    Reader r = {body, 0, false};
    if (r.u32() != fourcc("nclx")) return {};
    r.u16();  // primaries
    r.u16();  // transfer
    uint16_t m = r.u16();
    uint8_t full = r.u8();
    if (r.bad) return {};
    return {m, (full & 0x80) != 0, true};
}

struct Coeffs {
    int32_t yOff;
    int32_t cy, crv, cgu, cgv, cbu;  // 16.16
    int kind;                        // 0: YCbCr, 1: identity (GBR), 2: YCgCo, 3: grey
};

Coeffs coeffs_for(uint16_t matrix, bool full, bool mono) {
    double kr = 0.299, kb = 0.114;  // BT.601, also for unspecified
    Coeffs c = {};
    switch (matrix) {
        case 0: c.kind = 1; break;
        case 1: kr = 0.2126; kb = 0.0722; break;
        case 4: kr = 0.30; kb = 0.11; break;
        case 7: kr = 0.212; kb = 0.087; break;
        case 8: c.kind = 2; break;
        case 9: case 10: kr = 0.2627; kb = 0.0593; break;
        default: break;
    }
    if (mono) c.kind = 3;
    double ys = full ? 1.0 : 255.0 / 219.0, cs = full ? 1.0 : 255.0 / 224.0, kg = 1.0 - kr - kb;
    c.yOff = full ? 0 : 16;
    c.cy = static_cast<int32_t>(ys * 65536 + 0.5);
    c.crv = static_cast<int32_t>(cs * 2 * (1 - kr) * 65536 + 0.5);
    c.cbu = static_cast<int32_t>(cs * 2 * (1 - kb) * 65536 + 0.5);
    c.cgu = static_cast<int32_t>(cs * 2 * kb * (1 - kb) / kg * 65536 + 0.5);
    c.cgv = static_cast<int32_t>(cs * 2 * kr * (1 - kr) / kg * 65536 + 0.5);
    if (c.kind == 1 || c.kind == 2) c.crv = c.cbu = c.cgu = c.cgv = c.cy;
    return c;
}

uint8_t clamp8(int32_t v) {
    return static_cast<uint8_t>(v < 0 ? 0 : v > 255 ? 255 : v);
}

// One decoded picture: planes of 8-bit samples, or of 16-bit ones (high bit depth AV1) shifted down to 8.
struct Pic {
    const uint8_t* plane[3];
    ptrdiff_t stride[3];
    uint32_t w, h;
    int ssx, ssy;  // chroma subsampling shifts
    bool mono;
    int shift;  // bits above 8, 0 for 8-bit samples
    Nclx stream;  // what the bitstream says about colour
};

inline int sample(const Pic& p, int plane, uint32_t x, uint32_t y) {
    const uint8_t* row = p.plane[plane] + p.stride[plane] * static_cast<ptrdiff_t>(y);
    if (p.shift == 0) return row[x];
    uint32_t v = reinterpret_cast<const uint16_t*>(row)[x];
    v = (v + (1u << (p.shift - 1))) >> p.shift;
    return v > 255 ? 255 : static_cast<int>(v);
}

// Pixels [x0, x0 + n) of row y into out (RGBA), alpha from a when given.
void convert(const Pic& p, const Coeffs& c, const Pic* a, bool alphaFull, uint32_t x0, uint32_t n, uint32_t y,
             uint8_t* out) {
    for (uint32_t i = 0; i < n; i++) {
        uint32_t x = x0 + i;
        int32_t Y = sample(p, 0, x, y) - c.yOff;
        uint8_t* d = out + static_cast<size_t>(i) * 4;
        if (c.kind == 3 || p.mono) {
            d[0] = d[1] = d[2] = clamp8((c.cy * Y + 32768) >> 16);
        } else {
            int32_t U = sample(p, 1, x >> p.ssx, y >> p.ssy) - 128, V = sample(p, 2, x >> p.ssx, y >> p.ssy) - 128;
            if (c.kind == 0) {
                int32_t yy = c.cy * Y;
                d[0] = clamp8((yy + c.crv * V + 32768) >> 16);
                d[1] = clamp8((yy - c.cgu * U - c.cgv * V + 32768) >> 16);
                d[2] = clamp8((yy + c.cbu * U + 32768) >> 16);
            } else if (c.kind == 1) {  // GBR: Y is green, U blue, V red
                d[0] = clamp8((c.cy * (V + 128 - c.yOff) + 32768) >> 16);
                d[1] = clamp8((c.cy * Y + 32768) >> 16);
                d[2] = clamp8((c.cy * (U + 128 - c.yOff) + 32768) >> 16);
            } else {  // YCgCo: U is Cg, V is Co
                int32_t t = Y - U;
                d[0] = clamp8((c.cy * (t + V) + 32768) >> 16);
                d[1] = clamp8((c.cy * (Y + U) + 32768) >> 16);
                d[2] = clamp8((c.cy * (t - V) + 32768) >> 16);
            }
        }
        if (a == nullptr) {
            d[3] = 255;
        } else {
            int32_t av = sample(*a, 0, x, y);
            d[3] = alphaFull ? static_cast<uint8_t>(av) : clamp8(((av - 16) * 255 + 109) / 219);
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Codecs. Each decodes one coded image (an item or a sample) at a time and keeps its picture until the next call
// for the same slot. A grid row keeps one slot per column.

constexpr uint32_t kHevc = fourcc("hvc1");
constexpr uint32_t kAv1 = fourcc("av01");

// hvcC: the parameter sets, and the length of each NAL unit's size field in the samples.
struct Hvcc {
    Span arrays;
    uint32_t lengthSize;
    uint32_t chroma, depth;
};

bool parse_hvcc(Span body, Hvcc* h) {
    Reader r = {body, 0, false};
    if (r.u8() != 1) return false;
    r.skip(15);
    h->chroma = r.u8() & 3;
    h->depth = (r.u8() & 7) + 8;
    uint32_t chromaDepth = (r.u8() & 7) + 8;
    r.skip(2);
    h->lengthSize = (r.u8() & 3) + 1;
    if (r.bad || h->lengthSize == 3 || chromaDepth != h->depth) return false;
    h->arrays = r.rest();
    return true;
}

// The Annex B stream libhevc reads: the parameter sets from hvcC, then the sample's NAL units, each behind a start
// code instead of its size field.
bool annexb(const Hvcc& h, Span sample, uint8_t** out, size_t* outLen) {
    // First pass: the size. Second pass: the copy.
    for (int pass = 0; pass < 2; pass++) {
        size_t at = 0;
        Reader r = {h.arrays, 0, false};
        uint32_t arrays = r.u8();
        for (uint32_t i = 0; i < arrays; i++) {
            r.u8();
            uint32_t n = r.u16();
            for (uint32_t k = 0; k < n; k++) {
                uint32_t len = r.u16();
                if (!r.has(len)) return false;
                if (pass == 1) {
                    memcpy(*out + at, "\0\0\0\1", 4);
                    memcpy(*out + at + 4, r.s.p + r.at, len);
                }
                r.at += len;
                at += 4 + len;
            }
        }
        if (r.bad) return false;
        Reader s = {sample, 0, false};
        while (s.at < sample.n) {
            uint64_t len = s.un(h.lengthSize);
            if (len == 0 || !s.has(len)) return false;
            if (pass == 1) {
                memcpy(*out + at, "\0\0\0\1", 4);
                memcpy(*out + at + 4, s.s.p + s.at, len);
            }
            s.at += len;
            at += 4 + len;
        }
        if (pass == 0) {
            *out = static_cast<uint8_t*>(arena_alloc(at));
            if (*out == nullptr) return false;
            *outLen = at;
        }
    }
    return true;
}

void* hevc_alloc(void*, WORD32 alignment, WORD32 size) {
    return size <= 0 ? nullptr : arena_memalign(static_cast<size_t>(std::max<WORD32>(alignment, 16)), size);
}

void hevc_free(void*, void* p) {
    arena_free(p);
}

struct Hevc {
    iv_obj_t* codec;
    uint32_t w, h;
    uint8_t* out[kMaxGridColumns];  // one output picture per column
    uint32_t nOut;
};

bool hevc_ctl(iv_obj_t* c, void* ip, void* op) {
    return ihevcd_cxa_api_function(c, ip, op) == IV_SUCCESS;
}

bool hevc_open(Hevc* d, uint32_t w, uint32_t h, uint32_t cols, bool mono) {
    memset(d, 0, sizeof(*d));
    if (cols > kMaxGridColumns) return false;
    ihevcd_cxa_create_ip_t ip = {};
    ihevcd_cxa_create_op_t op = {};
    ip.s_ivd_create_ip_t.e_cmd = IVD_CMD_CREATE;
    ip.s_ivd_create_ip_t.u4_share_disp_buf = 0;
    ip.s_ivd_create_ip_t.e_output_format = IV_YUV_420P;
    ip.s_ivd_create_ip_t.pf_aligned_alloc = hevc_alloc;
    ip.s_ivd_create_ip_t.pf_aligned_free = hevc_free;
    ip.s_ivd_create_ip_t.u4_size = sizeof(ip);
    ip.u4_keep_threads_active = 0;
    ip.u4_enable_yuv_formats = (1u << CHROMA_FMT_IDC_YUV420) | (mono ? 1u << CHROMA_FMT_IDC_MONOCHROME : 0);
    op.s_ivd_create_op_t.u4_size = sizeof(op);
    if (ihevcd_cxa_api_function(nullptr, &ip, &op) != IV_SUCCESS) return false;
    d->codec = static_cast<iv_obj_t*>(op.s_ivd_create_op_t.pv_handle);
    d->codec->pv_fxns = reinterpret_cast<void*>(ihevcd_cxa_api_function);
    d->codec->u4_size = sizeof(iv_obj_t);
    d->w = w;
    d->h = h;
    // One core: libhevc starts no thread (its default, set again here).
    ihevcd_cxa_ctl_set_num_cores_ip_t cip = {};
    ihevcd_cxa_ctl_set_num_cores_op_t cop = {};
    cip.e_cmd = IVD_CMD_VIDEO_CTL;
    cip.e_sub_cmd = static_cast<IVD_CONTROL_API_COMMAND_TYPE_T>(IHEVCD_CXA_CMD_CTL_SET_NUM_CORES);
    cip.u4_num_cores = 1;
    cip.u4_size = sizeof(cip);
    cop.u4_size = sizeof(cop);
    if (!hevc_ctl(d->codec, &cip, &cop)) return false;
    // libhevc's C code only (on arm64 its assembly is not even linked, see ihevcd_init_function_ptr_av8 above).
    ihevcd_cxa_ctl_set_processor_ip_t pip = {};
    ihevcd_cxa_ctl_set_processor_op_t pop = {};
    pip.e_cmd = IVD_CMD_VIDEO_CTL;
    pip.e_sub_cmd = static_cast<IVD_CONTROL_API_COMMAND_TYPE_T>(IHEVCD_CXA_CMD_CTL_SET_PROCESSOR);
#if defined(__aarch64__)
    pip.u4_arch = ARCH_ARM_NONEON;
#else
    pip.u4_arch = getenv("DECODER_HEVC_SIMD") != nullptr ? ARCH_X86_SSE42 : ARCH_X86_GENERIC;  // host measurements
#endif
    pip.u4_soc = SOC_GENERIC;
    pip.u4_size = sizeof(pip);
    pop.u4_size = sizeof(pop);
    if (!hevc_ctl(d->codec, &pip, &pop)) return false;
    size_t ysize = static_cast<size_t>(w) * h, csize = static_cast<size_t>((w + 1) / 2) * ((h + 1) / 2);
    for (uint32_t c = 0; c < cols; c++) {
        d->out[c] = static_cast<uint8_t*>(arena_alloc(ysize + 2 * csize));
        if (d->out[c] == nullptr) return false;
    }
    d->nOut = cols;
    return true;
}

void hevc_close(Hevc* d) {
    if (d->codec == nullptr) return;
    ivd_delete_ip_t ip = {};
    ivd_delete_op_t op = {};
    ip.e_cmd = IVD_CMD_DELETE;
    ip.u4_size = sizeof(ip);
    op.u4_size = sizeof(op);
    ihevcd_cxa_api_function(d->codec, &ip, &op);
    d->codec = nullptr;
    for (uint32_t c = 0; c < d->nOut; c++) arena_free(d->out[c]);
    d->nOut = 0;
}

bool hevc_mode(Hevc* d, IVD_VIDEO_DECODE_MODE_T mode) {
    ivd_ctl_set_config_ip_t ip = {};
    ivd_ctl_set_config_op_t op = {};
    ip.u4_disp_wd = 0;
    ip.e_frm_skip_mode = IVD_SKIP_NONE;
    ip.e_frm_out_mode = IVD_DISPLAY_FRAME_OUT;
    ip.e_vid_dec_mode = mode;
    ip.e_cmd = IVD_CMD_VIDEO_CTL;
    ip.e_sub_cmd = IVD_CMD_CTL_SETPARAMS;
    ip.u4_size = sizeof(ip);
    op.u4_size = sizeof(op);
    return hevc_ctl(d->codec, &ip, &op);
}

bool hevc_simple_ctl(Hevc* d, IVD_CONTROL_API_COMMAND_TYPE_T cmd) {
    ivd_ctl_reset_ip_t ip = {};
    ivd_ctl_reset_op_t op = {};
    ip.e_cmd = IVD_CMD_VIDEO_CTL;
    ip.e_sub_cmd = cmd;
    ip.u4_size = sizeof(ip);
    op.u4_size = sizeof(op);
    return hevc_ctl(d->codec, &ip, &op);
}

bool hevc_decode(Hevc* d, const Hvcc& cfg, Span sample, uint32_t slot, Pic* pic) {
    uint8_t* stream = nullptr;
    size_t len = 0;
    if (!annexb(cfg, sample, &stream, &len)) return false;
    struct Freer {
        uint8_t* p;
        ~Freer() { arena_free(p); }
    } freer = {stream};
    if (!hevc_simple_ctl(d, IVD_CMD_CTL_RESET)) return false;
    // The header first: the coded size must be the size the container declared, before the decoder sizes its
    // buffers for the picture.
    if (!hevc_mode(d, IVD_DECODE_HEADER)) return false;
    ivd_video_decode_ip_t ip = {};
    ivd_video_decode_op_t op = {};
    ip.e_cmd = IVD_CMD_VIDEO_DECODE;
    ip.pv_stream_buffer = stream;
    ip.u4_num_Bytes = static_cast<UWORD32>(len);
    ip.u4_size = sizeof(ip);
    op.u4_size = sizeof(op);
    ihevcd_cxa_api_function(d->codec, &ip, &op);
    if (op.u4_pic_wd != d->w || op.u4_pic_ht != d->h) return false;
    size_t used = std::min<size_t>(op.u4_num_bytes_consumed, len);
    if (!hevc_mode(d, IVD_DECODE_FRAME)) return false;
    size_t ysize = static_cast<size_t>(d->w) * d->h, csize = static_cast<size_t>((d->w + 1) / 2) * ((d->h + 1) / 2);
    uint8_t* out = d->out[slot];
    ivd_out_bufdesc_t bufs = {};
    bufs.u4_num_bufs = 3;
    bufs.pu1_bufs[0] = out;
    bufs.pu1_bufs[1] = out + ysize;
    bufs.pu1_bufs[2] = out + ysize + csize;
    bufs.u4_min_out_buf_size[0] = static_cast<UWORD32>(ysize);
    bufs.u4_min_out_buf_size[1] = bufs.u4_min_out_buf_size[2] = static_cast<UWORD32>(csize);
    bool shown = false;
    // The picture comes out of the same call for a still image. One that waits for later pictures is flushed out.
    for (int calls = 0; calls < 64 && !shown; calls++) {
        bool flushing = used >= len;
        if (flushing && !hevc_simple_ctl(d, IVD_CMD_CTL_FLUSH)) return false;
        memset(&op, 0, sizeof(op));
        ip.pv_stream_buffer = flushing ? nullptr : stream + used;
        ip.u4_num_Bytes = flushing ? 0 : static_cast<UWORD32>(len - used);
        ip.s_out_buffer = bufs;
        op.u4_size = sizeof(op);
        IV_API_CALL_STATUS_T st = ihevcd_cxa_api_function(d->codec, &ip, &op);
        if ((op.u4_error_code & 0xff) == IVD_RES_CHANGED) return false;
        if (op.u4_output_present) {
            shown = true;
            break;
        }
        if (flushing) break;
        if (st != IV_SUCCESS && op.u4_num_bytes_consumed == 0) return false;
        used += std::max<size_t>(op.u4_num_bytes_consumed, 1);
        if (used > len) used = len;
    }
    const iv_yuv_buf_t& f = op.s_disp_frm_buf;
    if (!shown || f.u4_y_wd != d->w || f.u4_y_ht != d->h) return false;
    *pic = {};
    pic->plane[0] = static_cast<const uint8_t*>(f.pv_y_buf);
    pic->plane[1] = static_cast<const uint8_t*>(f.pv_u_buf);
    pic->plane[2] = static_cast<const uint8_t*>(f.pv_v_buf);
    pic->stride[0] = f.u4_y_strd;
    pic->stride[1] = f.u4_u_strd;
    pic->stride[2] = f.u4_v_strd;
    pic->w = d->w;
    pic->h = d->h;
    pic->ssx = pic->ssy = 1;
    if (pic->plane[0] < out || pic->plane[0] >= out + ysize + 2 * csize || pic->stride[0] < static_cast<ptrdiff_t>(d->w) ||
        pic->stride[1] < static_cast<ptrdiff_t>((d->w + 1) / 2)) {
        return false;
    }
    // The bitstream's colour description, for an image without colr.
    ihevcd_cxa_ctl_get_vui_params_ip_t vip = {};
    ihevcd_cxa_ctl_get_vui_params_op_t vop = {};
    vip.e_cmd = IVD_CMD_VIDEO_CTL;
    vip.e_sub_cmd = static_cast<IVD_CONTROL_API_COMMAND_TYPE_T>(IHEVCD_CXA_CMD_CTL_GET_VUI_PARAMS);
    vip.u4_size = sizeof(vip);
    vop.u4_size = sizeof(vop);
    if (hevc_ctl(d->codec, &vip, &vop)) {
        pic->stream.full = vop.u1_video_signal_type_present_flag && vop.u1_video_full_range_flag;
        pic->stream.matrix = vop.u1_colour_description_present_flag ? vop.u1_matrix_coefficients : 2;
        pic->stream.known = true;
    }
    return true;
}

void dav1d_quiet(void*, const char*, va_list) {}

struct Av1 {
    Dav1dContext* c;
    uint32_t w, h;
    Dav1dPicture pics[kMaxGridColumns];  // one per column
    bool held[kMaxGridColumns];
};

bool av1_open(Av1* d, uint32_t w, uint32_t h) {
    memset(d, 0, sizeof(*d));
    Dav1dSettings s;
    dav1d_default_settings(&s);
    s.n_threads = 1;  // no thread is started
    s.max_frame_delay = 1;
    s.frame_size_limit = w * h;
    s.all_layers = 0;
    s.logger.callback = dav1d_quiet;
    d->w = w;
    d->h = h;
    return dav1d_open(&d->c, &s) == 0;
}

void av1_release(Av1* d, uint32_t slot) {
    if (d->held[slot]) dav1d_picture_unref(&d->pics[slot]);
    d->held[slot] = false;
}

void av1_close(Av1* d) {
    for (uint32_t i = 0; i < kMaxGridColumns; i++) av1_release(d, i);
    if (d->c != nullptr) dav1d_close(&d->c);
}

void no_free(const uint8_t*, void*) {}

bool av1_decode(Av1* d, Span sample, uint32_t slot, Pic* pic) {
    if (slot >= kMaxGridColumns) return false;
    av1_release(d, slot);
    // The size the sequence header promises, before the decoder allocates anything for it.
    Dav1dSequenceHeader seq;
    if (dav1d_parse_sequence_header(&seq, sample.p, sample.n) != 0 || seq.max_width > static_cast<int>(d->w) ||
        seq.max_height > static_cast<int>(d->h)) {
        return false;
    }
    dav1d_flush(d->c);
    Dav1dData data = {};
    if (dav1d_data_wrap(&data, sample.p, sample.n, no_free, nullptr) != 0) return false;
    Dav1dPicture* p = &d->pics[slot];
    memset(p, 0, sizeof(*p));
    bool got = false;
    // One thread and a frame delay of 1: the picture comes out as soon as its data is in.
    for (int calls = 0; calls < 1024; calls++) {
        if (data.sz > 0) {
            int res = dav1d_send_data(d->c, &data);
            if (res < 0 && res != DAV1D_ERR(EAGAIN)) break;
        }
        int res = dav1d_get_picture(d->c, p);
        if (res == 0) {
            got = true;
            break;
        }
        if (res != DAV1D_ERR(EAGAIN) || data.sz == 0) break;
    }
    if (data.sz > 0) dav1d_data_unref(&data);
    if (!got) return false;
    d->held[slot] = true;
    if (p->p.w != static_cast<int>(d->w) || p->p.h != static_cast<int>(d->h) || (p->p.bpc != 8 && p->p.bpc != 10 &&
                                                                                 p->p.bpc != 12)) {
        return false;
    }
    *pic = {};
    for (int i = 0; i < 3; i++) pic->plane[i] = static_cast<const uint8_t*>(p->data[i]);
    pic->stride[0] = p->stride[0];
    pic->stride[1] = pic->stride[2] = p->stride[1];
    pic->w = d->w;
    pic->h = d->h;
    pic->mono = p->p.layout == DAV1D_PIXEL_LAYOUT_I400;
    pic->ssx = p->p.layout == DAV1D_PIXEL_LAYOUT_I420 || p->p.layout == DAV1D_PIXEL_LAYOUT_I422;
    pic->ssy = p->p.layout == DAV1D_PIXEL_LAYOUT_I420;
    pic->shift = p->p.bpc - 8;
    if (p->seq_hdr != nullptr) {
        pic->stream.matrix = static_cast<uint16_t>(p->seq_hdr->mtrx);
        pic->stream.full = p->seq_hdr->color_range != 0;
        pic->stream.known = true;
    }
    return true;
}

// ---------------------------------------------------------------------------------------------------------------
// A layer: the colour image or its alpha, as a grid of coded images (one tile for a plain image).

struct Layer {
    uint32_t codec;
    uint32_t rows, cols;
    uint32_t tileW, tileH;
    uint32_t outW, outH;
    Span config;
    Hvcc hvcc;
    Nclx nclx;
    // Where each tile's bytes are: items, or the one sample of a track.
    Item** tiles;
    Span sample;
    bool fromTrack;
};

bool codec_config(const File* f, const Item* it, Layer* l) {
    const Prop* p = item_prop(f, it, it->type == kHevc ? fourcc("hvcC") : fourcc("av1C"));
    if (p == nullptr) return false;
    if (l->config.p == nullptr) {
        l->config = p->body;
    } else if (l->config.n != p->body.n || memcmp(l->config.p, p->body.p, p->body.n) != 0) {
        return false;  // every tile of a grid is coded the same way
    }
    return true;
}

// The layer of image item it: a coded image or a grid of them. False for anything this reader does not decode
// (with gOutcome.unsupported for a valid file of a kind it does not read).
bool layer_from_item(File* f, Item* it, Layer* l) {
    memset(l, 0, sizeof(*l));
    if (!all_understood(f, it)) {
        gOutcome.unsupported = true;
        return false;
    }
    const Prop* colr = item_prop(f, it, fourcc("colr"));
    if (colr != nullptr) l->nclx = parse_nclx(colr->body);
    if (it->type == kHevc || it->type == kAv1) {
        l->codec = it->type;
        l->rows = l->cols = 1;
        if (!ispe(f, it, &l->tileW, &l->tileH) || !codec_config(f, it, l)) return false;
        l->outW = l->tileW;
        l->outH = l->tileH;
        l->tiles = static_cast<Item**>(arena_alloc(sizeof(Item*)));
        if (l->tiles == nullptr) return false;
        l->tiles[0] = it;
    } else if (it->type == fourcc("grid")) {
        Span g;
        if (!item_data(f, it, &g)) return false;
        Reader r = {g, 0, false};
        if (r.u8() != 0) return false;
        uint32_t flags = r.u8();
        l->rows = r.u8() + 1u;
        l->cols = r.u8() + 1u;
        l->outW = (flags & 1) ? r.u32() : r.u16();
        l->outH = (flags & 1) ? r.u32() : r.u16();
        if (r.bad || l->outW == 0 || l->outH == 0 || l->outW > kMaxDimension || l->outH > kMaxDimension) return false;
        uint32_t ew, eh;
        if (ispe(f, it, &ew, &eh) && (ew != l->outW || eh != l->outH)) return false;
        uint32_t n = l->rows * l->cols;
        if (n > kMaxGridTiles || l->cols > kMaxGridColumns) return false;
        l->tiles = static_cast<Item**>(arena_alloc(sizeof(Item*) * n));
        if (l->tiles == nullptr) return false;
        uint32_t k = 0;
        for (uint32_t i = 0; i < f->nRefs; i++) {
            const Ref& ref = f->refs[i];
            if (ref.type != fourcc("dimg") || ref.from != it->id) continue;
            if (k >= n) return false;
            Item* t = find_item(f, ref.to);
            if (t == nullptr) return false;
            l->tiles[k++] = t;
        }
        if (k != n) return false;  // a grid with missing tiles
        for (uint32_t i = 0; i < n; i++) {
            Item* t = l->tiles[i];
            uint32_t tw, th;
            if (t->type != kHevc && t->type != kAv1) {
                gOutcome.unsupported = t->type != 0;
                return false;
            }
            if (i == 0) l->codec = t->type;
            if (t->type != l->codec || !all_understood(f, t) || !ispe(f, t, &tw, &th) || !codec_config(f, t, l)) {
                return false;
            }
            if (i == 0) {
                l->tileW = tw;
                l->tileH = th;
            } else if (tw != l->tileW || th != l->tileH) {
                return false;
            }
        }
        // The tiles cover the output, and no column or row of tiles lies wholly outside it.
        if (static_cast<uint64_t>(l->tileW) * l->cols < l->outW || static_cast<uint64_t>(l->tileH) * l->rows < l->outH ||
            static_cast<uint64_t>(l->tileW) * (l->cols - 1) >= l->outW ||
            static_cast<uint64_t>(l->tileH) * (l->rows - 1) >= l->outH) {
            return false;
        }
        if (l->nclx.matrix == 0 && !l->nclx.known) {
            const Prop* tc = item_prop(f, l->tiles[0], fourcc("colr"));
            if (tc != nullptr) l->nclx = parse_nclx(tc->body);
        }
    } else {
        gOutcome.unsupported = it->type != 0;  // iden, iovl, another codec
        return false;
    }
    if (static_cast<uint64_t>(l->tileW) * l->tileH > kMaxCodedPixels ||
        static_cast<uint64_t>(l->tileW) * l->tileH * l->rows * l->cols > kMaxGridPixels) {
        return false;
    }
    if (l->codec == kHevc) {
        if (!parse_hvcc(l->config, &l->hvcc)) return false;
        if (l->hvcc.depth != 8 || (l->hvcc.chroma != 1 && l->hvcc.chroma != 0)) {
            gOutcome.unsupported = true;  // libhevc decodes 8-bit 4:2:0 and monochrome only
            return false;
        }
    }
    return true;
}

bool layer_from_track(const Track& t, Layer* l) {
    memset(l, 0, sizeof(*l));
    l->codec = t.codec == fourcc("av01") ? kAv1 : kHevc;
    l->rows = l->cols = 1;
    l->tileW = l->outW = t.w;
    l->tileH = l->outH = t.h;
    l->config = t.config;
    if (t.nclx.p != nullptr) l->nclx = parse_nclx(t.nclx);
    l->fromTrack = true;
    if (t.w == 0 || t.h == 0 || t.w > kMaxDimension || t.h > kMaxDimension ||
        static_cast<uint64_t>(t.w) * t.h > kMaxCodedPixels) {
        return false;
    }
    if (l->codec == kHevc) {
        if (!parse_hvcc(l->config, &l->hvcc)) return false;
        if (l->hvcc.depth != 8 || (l->hvcc.chroma != 1 && l->hvcc.chroma != 0)) {
            gOutcome.unsupported = true;
            return false;
        }
    }
    return true;
}

bool layer_sample(const File* f, const Layer& l, uint32_t index, Span* s) {
    if (l.fromTrack) {
        *s = l.sample;
        return true;
    }
    return item_data(f, l.tiles[index], s);
}

// The decoders of one layer.
struct Decoder {
    uint32_t codec;
    Hevc hevc;
    Av1 av1;
};

bool open_decoder(const Layer& l, Decoder* d, bool alpha) {
    d->codec = l.codec;
    if (l.codec == kHevc) return hevc_open(&d->hevc, l.tileW, l.tileH, l.cols, alpha || l.hvcc.chroma == 0);
    return av1_open(&d->av1, l.tileW, l.tileH);
}

void close_decoder(Decoder* d) {
    if (d->codec == kHevc) hevc_close(&d->hevc);
    if (d->codec == kAv1) av1_close(&d->av1);
    d->codec = 0;
}

bool decode_tile(const File* f, const Layer& l, Decoder* d, uint32_t index, uint32_t slot, Pic* pic) {
    Span s;
    if (!layer_sample(f, l, index, &s)) return false;
    bool ok = d->codec == kHevc ? hevc_decode(&d->hevc, l.hvcc, s, slot, pic) : av1_decode(&d->av1, s, slot, pic);
    if (ok && d->codec == kHevc) pic->mono = l.hvcc.chroma == 0;
    if (!l.fromTrack && s.p != nullptr && (s.p < f->data.p || s.p >= f->data.p + f->data.n) &&
        (s.p < f->idat.p || s.p >= f->idat.p + f->idat.n)) {
        arena_free(const_cast<uint8_t*>(s.p));  // a copy made of several extents
    }
    return ok;
}

// ---------------------------------------------------------------------------------------------------------------
// The image to show.

// The clean aperture (clap): the part of the image that is shown, in the image's own coordinates.
struct Crop {
    uint32_t x, y, w, h;
};

struct Plan {
    Crop crop;
    Layer color, alpha;
    bool hasAlpha, premultiplied;
    bool flip;
    uint32_t degrees;
    bool animated;
};

bool aux_is_alpha(const File* f, const Item* it) {
    const Prop* p = item_prop(f, it, fourcc("auxC"));
    if (p == nullptr) return false;
    Reader r = {p->body, 0, false};
    r.skip(4);
    Span urn = r.cstr();
    static const char* const kAlpha[] = {"urn:mpeg:mpegB:cicp:systems:auxiliary:alpha", "urn:mpeg:hevc:2015:auxid:1"};
    for (const char* a : kAlpha) {
        if (!r.bad && urn.n == strlen(a) && memcmp(urn.p, a, urn.n) == 0) return true;
    }
    return false;
}

const Track* color_track(const File* f) {
    for (uint32_t i = 0; i < f->nTracks; i++) {
        if (f->tracks[i].auxFor == 0) return &f->tracks[i];
    }
    return nullptr;
}

// Picks what to show: the primary item, else the first sample of the first picture track. Sizes only (no item
// data) when headerOnly.
// clap of item it, as libavif and libheif read it: an integer rectangle inside w x h, listed before any irot or imir
// (the crop applies to the image as stored). None: the whole image. False for a clap this reader cannot apply (not
// whole pixels, outside the image, after a turn): the image is not decoded (UNSUPPORTED).
bool crop_of(const File* f, const Item* it, uint32_t w, uint32_t h, Crop* c) {
    *c = {0, 0, w, h};
    const Prop* clap = nullptr;
    bool turned = false;
    for (uint32_t i = 0; i < it->nAssoc; i++) {
        const Prop& p = f->props[it->assoc[i] - 1];
        if (p.type == fourcc("irot") || p.type == fourcc("imir")) turned = true;
        if (p.type == fourcc("clap")) {
            if (turned || clap != nullptr) return false;
            clap = &p;
        }
    }
    if (clap == nullptr) return true;
    Reader r = {clap->body, 0, false};
    uint32_t wn = r.u32(), wd = r.u32(), hn = r.u32(), hd = r.u32();
    int32_t xn = static_cast<int32_t>(r.u32());
    uint32_t xd = r.u32();
    int32_t yn = static_cast<int32_t>(r.u32());
    uint32_t yd = r.u32();
    if (r.bad || wd == 0 || hd == 0 || xd == 0 || yd == 0 || wn % wd != 0 || hn % hd != 0) return false;
    int64_t cw = wn / wd, ch = hn / hd;
    if (cw < 1 || ch < 1 || cw > w || ch > h) return false;
    // The crop's left edge: horizOff + (w - cw) / 2, which must be a whole pixel. Likewise the top edge.
    int64_t xnum = 2 * static_cast<int64_t>(xn) + (static_cast<int64_t>(w) - cw) * xd, xden = 2 * static_cast<int64_t>(xd);
    int64_t ynum = 2 * static_cast<int64_t>(yn) + (static_cast<int64_t>(h) - ch) * yd, yden = 2 * static_cast<int64_t>(yd);
    if (xnum % xden != 0 || ynum % yden != 0) return false;
    int64_t x = xnum / xden, y = ynum / yden;
    if (x < 0 || y < 0 || x + cw > w || y + ch > h) return false;
    *c = {static_cast<uint32_t>(x), static_cast<uint32_t>(y), static_cast<uint32_t>(cw), static_cast<uint32_t>(ch)};
    return true;
}

bool make_plan(File* f, Plan* plan, bool headerOnly) {
    memset(plan, 0, sizeof(*plan));
    const Track* track = color_track(f);
    plan->animated = track != nullptr && track->samples > 1;
    if (f->hasPrimary) {
        Item* it = find_item(f, f->primary);
        if (it == nullptr) return false;
        transform_of(f, it, &plan->flip, &plan->degrees);
        if (headerOnly) {
            // The stored size: ispe, which every image item carries, after the crop (clap).
            plan->color.rows = plan->color.cols = 1;
            if (!ispe(f, it, &plan->color.outW, &plan->color.outH) && !layer_from_item(f, it, &plan->color)) {
                return false;  // a grid without ispe: its own header
            }
            if (!crop_of(f, it, plan->color.outW, plan->color.outH, &plan->crop)) {
                gOutcome.unsupported = true;
                return false;
            }
            plan->color.outW = plan->crop.w;
            plan->color.outH = plan->crop.h;
            return true;
        }
        if (!layer_from_item(f, it, &plan->color)) return false;
        if (!crop_of(f, it, plan->color.outW, plan->color.outH, &plan->crop)) {
            gOutcome.unsupported = true;
            return false;
        }
        for (uint32_t i = 0; i < f->nRefs; i++) {
            const Ref& r = f->refs[i];
            Item* a = r.type == fourcc("auxl") && r.to == it->id ? find_item(f, r.from) : nullptr;
            if (a == nullptr || !aux_is_alpha(f, a)) continue;
            if (!layer_from_item(f, a, &plan->alpha)) return false;
            plan->hasAlpha = true;
            break;
        }
        for (uint32_t i = 0; plan->hasAlpha && i < f->nRefs; i++) {
            if (f->refs[i].type == fourcc("prem") && f->refs[i].from == it->id) plan->premultiplied = true;
        }
    } else {
        if (track == nullptr) return false;
        if (!layer_from_track(*track, &plan->color)) return false;
        plan->crop = {0, 0, plan->color.outW, plan->color.outH};
        plan->color.sample = {nullptr, 0};
        if (headerOnly) return true;
        auto sample_of = [&](const Track& t, Span* s) {
            if (t.offset > f->data.n || t.size == 0 || t.size > f->data.n - t.offset) return false;
            *s = {f->data.p + t.offset, t.size};
            return true;
        };
        if (!sample_of(*track, &plan->color.sample)) return false;
        for (uint32_t i = 0; i < f->nTracks; i++) {
            const Track& t = f->tracks[i];
            if (t.auxFor != track->id) continue;
            if (!layer_from_track(t, &plan->alpha) || !sample_of(t, &plan->alpha.sample)) return false;
            plan->hasAlpha = true;
            break;
        }
    }
    if (plan->hasAlpha) {
        const Layer &c = plan->color, &a = plan->alpha;
        // The alpha plane is laid out like the colour: same grid, same tiles, same size.
        if (a.rows != c.rows || a.cols != c.cols || a.tileW != c.tileW || a.tileH != c.tileH || a.outW != c.outW ||
            a.outH != c.outH) {
            return false;
        }
    }
    return true;
}

bool decode_plan(const File* f, Plan* plan, uint32_t maxW, uint32_t maxH, Sink* sink) {
    Layer& c = plan->color;
    Layer& a = plan->alpha;
    // Memory, checked before any decoder exists: the pictures of one row of tiles and one more the decoder works in,
    // the row and the scaler. What the decoders take beyond that is bounded by the arena itself.
    uint64_t px = static_cast<uint64_t>(c.tileW) * c.tileH;
    uint64_t perTile = px * 3 / 2;
    uint64_t need = perTile * (c.cols + 1) * (plan->hasAlpha ? 2 : 1) + static_cast<uint64_t>(c.outW) * 4 * 6 + kSlack;
    // The decoders' own state per coded image: libhevc keeps whole-picture tables of about kHevcBytesPerPixel, dav1d
    // its picture pool. Sized from the declared size, so the worker asks for this much of the arena before it starts
    // (a 12 MP single image is not a grid and needs far more than the default).
    need += px * (c.codec == kHevc ? kHevcBytesPerPixel : kAv1BytesPerPixel) * (plan->hasAlpha ? 2 : 1);
    if (!arena_room(need)) return false;
    Decoder dc = {}, da = {};
    struct Closer {
        Decoder *a, *b;
        ~Closer() {
            close_decoder(a);
            close_decoder(b);
        }
    } closer = {&dc, &da};
    if (!open_decoder(c, &dc, false) || (plan->hasAlpha && !open_decoder(a, &da, true))) return false;
    uint8_t* row = static_cast<uint8_t*>(arena_alloc(static_cast<size_t>(c.outW) * 4));
    Pic* pics = static_cast<Pic*>(arena_alloc(sizeof(Pic) * c.cols * 2));
    if (row == nullptr || pics == nullptr) return false;
    Scaler scaler = {};
    const Crop& cr = plan->crop;
    if (!start_output(&scaler, cr.w, cr.h, maxW, maxH, sink)) return false;
    scaler.premultiplied = plan->premultiplied;
    Coeffs k = {};
    bool alphaFull = true;
    for (uint32_t ty = 0; ty < c.rows; ty++) {
        for (uint32_t tx = 0; tx < c.cols; tx++) {
            uint32_t index = ty * c.cols + tx;
            if (!decode_tile(f, c, &dc, index, tx, &pics[tx])) return false;
            if (plan->hasAlpha && !decode_tile(f, a, &da, index, tx, &pics[c.cols + tx])) return false;
        }
        if (ty == 0) {
            const Pic& p0 = pics[0];
            Nclx n = c.nclx.known ? c.nclx : p0.stream;
            k = coeffs_for(n.known ? n.matrix : 2, n.known && n.full, p0.mono);
            if (plan->hasAlpha) {
                const Pic& a0 = pics[c.cols];
                alphaFull = a.nclx.known ? a.nclx.full : (a0.stream.known ? a0.stream.full : true);
            }
        }
        for (uint32_t y = 0; y < c.tileH && ty * c.tileH + y < c.outH; y++) {
            uint32_t gy = ty * c.tileH + y;
            if (gy < cr.y || gy >= cr.y + cr.h) continue;  // outside the clean aperture
            for (uint32_t tx = 0; tx < c.cols; tx++) {
                uint32_t x0 = tx * c.tileW;
                if (x0 >= c.outW) break;
                uint32_t n = std::min(c.tileW, c.outW - x0);
                convert(pics[tx], k, plan->hasAlpha ? &pics[c.cols + tx] : nullptr, alphaFull, 0, n, y,
                        row + static_cast<size_t>(x0) * 4);
            }
            if (plan->premultiplied) {
                for (uint32_t x = 0; x < c.outW; x++) {
                    uint8_t* px = row + static_cast<size_t>(x) * 4;
                    for (int ch = 0; ch < 3; ch++) px[ch] = std::min(px[ch], px[3]);
                }
            }
            if (!scaler_push(&scaler, row + static_cast<size_t>(cr.x) * 4)) return false;
        }
    }
    bool done = scaler_done(&scaler);
    scaler_free(&scaler);
    arena_free(pics);
    arena_free(row);
    return done && sink_flush(sink);
}

// Frees what parse_file and make_plan took (in a worker it all goes with the process, but the broker's warm-up and
// the several parses of one request give it back).
struct Holder {
    File* f;
    Plan* plan;
    ~Holder() {
        if (plan != nullptr) {
            arena_free(plan->color.tiles);
            arena_free(plan->alpha.tiles);
            arena_free(plan);
        }
        if (f != nullptr) {
            arena_free(f->items);
            arena_free(f->props);
            arena_free(f->extents);
            arena_free(f->refs);
            arena_free(f->index);
            arena_free(f);
        }
    }
};

File* new_file() {
    File* f = static_cast<File*>(arena_alloc(sizeof(File)));
    if (f != nullptr) memset(f, 0, sizeof(*f));
    return f;
}

}  // namespace

bool decode_heif(const uint8_t* data, size_t size, uint32_t maxW, uint32_t maxH, Sink* sink, bool headerOnly,
                 uint32_t* outW, uint32_t* outH) {
    Holder h = {new_file(), static_cast<Plan*>(arena_alloc(sizeof(Plan)))};
    File* f = h.f;
    Plan* plan = h.plan;
    if (plan != nullptr) memset(plan, 0, sizeof(*plan));
    if (f == nullptr || plan == nullptr || !parse_file(data, size, f)) return false;
    // A cut-off file (a probe reads only the start) still names its size, never its pixels.
    if (f->cut && !headerOnly) return false;
    if (!make_plan(f, plan, headerOnly)) return false;
    if (headerOnly) {
        *outW = plan->color.outW;
        *outH = plan->color.outH;
        gOutcome.animated = plan->animated;
        return *outW != 0 && *outH != 0;
    }
    return decode_plan(f, plan, maxW, maxH, sink);
}

void heif_metadata(const uint8_t* data, size_t size, Meta* m, bool* mirror) {
    Holder h = {new_file(), nullptr};
    File* f = h.f;
    if (f == nullptr || !parse_file(data, size, f)) return;
    Item* primary = f->hasPrimary ? find_item(f, f->primary) : nullptr;
    // The Exif and XMP items that describe the primary image (cdsc), else the first of each.
    Item* exif = nullptr;
    Item* xmp = nullptr;
    for (int pass = 0; pass < 2; pass++) {
        for (uint32_t i = 0; i < f->nItems; i++) {
            Item* it = &f->items[i];
            bool linked = false;
            for (uint32_t k = 0; pass == 0 && primary != nullptr && k < f->nRefs; k++) {
                const Ref& r = f->refs[k];
                linked = linked || (r.type == fourcc("cdsc") && r.from == it->id && r.to == primary->id);
            }
            if (pass == 0 && !linked) continue;
            if (exif == nullptr && it->type == fourcc("Exif")) exif = it;
            static const char kXmp[] = "application/rdf+xml";
            if (xmp == nullptr && it->type == fourcc("mime") && it->contentType.n == sizeof(kXmp) - 1 &&
                memcmp(it->contentType.p, kXmp, sizeof(kXmp) - 1) == 0) {
                xmp = it;
            }
        }
    }
    Span s;
    auto copied = [&](Span x) { return x.p < f->data.p || x.p >= f->data.p + f->data.n; };
    if (exif != nullptr && item_data(f, exif, &s)) {
        if (s.n >= 4) {
            uint64_t skip = 4 + (static_cast<uint64_t>(s.p[0]) << 24 | s.p[1] << 16 | s.p[2] << 8 | s.p[3]);
            if (skip < s.n) read_exif_block(s.p + skip, s.n - skip, m);
        }
        if (copied(s) && (s.p < f->idat.p || s.p >= f->idat.p + f->idat.n)) arena_free(const_cast<uint8_t*>(s.p));
    }
    if (xmp != nullptr && item_data(f, xmp, &s)) {
        read_xmp_block(s.p, s.n, m);
        if (copied(s) && (s.p < f->idat.p || s.p >= f->idat.p + f->idat.n)) arena_free(const_cast<uint8_t*>(s.p));
    }
    // The orientation is the image's own transform. The file's EXIF orientation is not used, as the format says.
    m->flags &= ~kHasOrientation;
    m->orientation = -1;
    if (primary != nullptr) {
        bool flip;
        uint32_t deg;
        transform_of(f, primary, &flip, &deg);
        m->orientation = static_cast<int32_t>(deg);
        m->flags |= kHasOrientation;
        if (mirror != nullptr) *mirror = flip;
    }
}

bool warm_up_heif() {
    // dav1d reads /proc/cpuinfo once, when its first decoder opens. A real decode also sets up its tables, and a
    // 12-bit frame the tables of the C transforms (a pthread_once, whose first run in a worker was a futex call that
    // killed it: 12-bit AVIF on arm64, found in the arm64 test run).
    Sink sink = {-1, static_cast<uint8_t*>(arena_alloc(kStripeBytes)), 0};
    if (sink.buf == nullptr) return false;
    uint32_t w = 0, h = 0;
    bool ok = decode_heif(kWarmupAvif, sizeof(kWarmupAvif), 8, 8, &sink, false, &w, &h);
    ok &= decode_heif(kWarmupAvif12, sizeof(kWarmupAvif12), 8, 8, &sink, false, &w, &h);
    arena_free(sink.buf);
    return ok;
}

}  // namespace decoder
