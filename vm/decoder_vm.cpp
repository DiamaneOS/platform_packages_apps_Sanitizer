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

// /init of the decoder VM: a raw protected VM with our own kernel and nothing else in it. This one static program is
// the whole userspace. It serves the decode service on Android over one vsock stream (proto.h).
//
// For each file it forks a fresh worker. Before the worker parses a single byte it closes every file descriptor but
// its output pipe, caps CPU time, address space, files and processes, drops to an unprivileged user, sets no new
// privileges and enters seccomp strict mode, where only read, write and exit are left. If seccomp is not available the
// worker exits and the request fails: there is no decode without it. The worker decodes row by row from a fixed
// memory arena and streams to the broker, which checks every size before it passes anything on. A decoder exploit
// gets a process that can write to one pipe and nothing else, and that process ends with the file.

#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <setjmp.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/un.h>
#ifndef DECODER_HOST_TEST
#include <linux/vm_sockets.h>  // after sys/socket.h, which older headers need
#endif
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <cmath>
#include <cstdint>

#include <jpeglib.h>
#include <png.h>
extern "C" {
#include <jmemsys.h>  // the memory back end's interface, which this program implements
}

#include "image.h"
#include "meta.h"
#include "proto.h"

using namespace decoder;

// The host test build uses the host toolchain's older kernel headers and C library.
#ifndef __NR_close_range
#define __NR_close_range 436
#endif
#ifndef __NR_memfd_create
#if defined(__x86_64__)
#define __NR_memfd_create 319
#elif defined(__aarch64__)
#define __NR_memfd_create 279
#endif
#endif
#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 1U
#endif
#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif

// Clears memory in a way the compiler cannot drop as a dead store.
static void wipe(void* p, size_t n) {
    memset(p, 0, n);
    __asm__ volatile("" : : "r"(p) : "memory");
}

namespace {

// Deadlines. The worker's CPU time is capped by the kernel, its wall time by the broker. The host link is trusted but
// a stalled read still ends the connection.
constexpr int kWorkerCpuSeconds = 20;
constexpr int64_t kWorkerWallMs = 30000;
constexpr int kIdleMs = 15000;
constexpr int64_t kHostReadMs = 60000;

// The unprivileged user and group of a worker.
constexpr uid_t kWorkerId = 65534;

#ifdef DECODER_TEST_HOOKS
// Test builds only: kOpHook's arg0, a worker that breaks its lockdown on purpose.
constexpr uint32_t kHookOpen = 1;
constexpr uint32_t kHookMmap = 2;
constexpr uint32_t kHookSpin = 3;
constexpr uint32_t kHookLockdown = 4;
constexpr uint32_t kHookFork = 5;
constexpr uint32_t kHookScan = 6;
constexpr uint32_t kHookBadPixels = 7;
#endif

}  // namespace

// libjpeg-turbo's memory back end, in place of its jmemnobs.c: everything comes from the arena. There is no backing
// store for a whole image's coefficients, with one exception: a multi-scan (progressive) JPEG whose coefficients do
// not fit the arena is decoded at 1/8, where each 8x8 block shows as its DC value alone. Then the store keeps that
// one value per block (2 bytes instead of 128), in the arena, and gives the other 63 back as zeros. Anything else
// that would need a backing store fails cleanly.
namespace {

struct DcStore {
    int16_t* dc;
    size_t blocks;
};

bool gJpegDcOnly = false;  // set by decode_jpeg for the one decode that needs it

DcStore* dc_store(backing_store_ptr info) {
    DcStore* s;
    memcpy(&s, info->temp_name, sizeof(s));
    return s;
}

// The blocks [offset, offset + count) of the array, in bytes as jmemmgr.c asks for them: whole blocks only.
bool dc_range(j_common_ptr cinfo, backing_store_ptr info, long offset, long count, size_t* first, size_t* n) {
    DcStore* s = dc_store(info);
    if (offset < 0 || count < 0 || offset % sizeof(JBLOCK) != 0 || count % sizeof(JBLOCK) != 0) {
        (*cinfo->err->error_exit)(cinfo);
    }
    *first = static_cast<size_t>(offset) / sizeof(JBLOCK);
    *n = static_cast<size_t>(count) / sizeof(JBLOCK);
    if (*first > s->blocks || *n > s->blocks - *first) (*cinfo->err->error_exit)(cinfo);
    return true;
}

void dc_read(j_common_ptr cinfo, backing_store_ptr info, void* buffer, long offset, long count) {
    size_t first, n;
    dc_range(cinfo, info, offset, count, &first, &n);
    JBLOCK* b = static_cast<JBLOCK*>(buffer);
    const int16_t* dc = dc_store(info)->dc + first;
    for (size_t i = 0; i < n; i++) {
        memset(b[i], 0, sizeof(JBLOCK));
        b[i][0] = dc[i];
    }
}

void dc_write(j_common_ptr cinfo, backing_store_ptr info, void* buffer, long offset, long count) {
    size_t first, n;
    dc_range(cinfo, info, offset, count, &first, &n);
    const JBLOCK* b = static_cast<const JBLOCK*>(buffer);
    int16_t* dc = dc_store(info)->dc + first;
    for (size_t i = 0; i < n; i++) dc[i] = b[i][0];
}

void dc_close(j_common_ptr, backing_store_ptr info) {
    DcStore* s = dc_store(info);
    arena_free(s->dc);
    arena_free(s);
}

}  // namespace

extern "C" {
void* jpeg_get_small(j_common_ptr, size_t n) {
    return arena_alloc(n);
}
void jpeg_free_small(j_common_ptr, void* p, size_t) {
    arena_free(p);
}
void* jpeg_get_large(j_common_ptr, size_t n) {
    return arena_alloc(n);
}
void jpeg_free_large(j_common_ptr, void* p, size_t) {
    arena_free(p);
}
size_t jpeg_mem_available(j_common_ptr cinfo, size_t, size_t max_bytes_needed, size_t already_allocated) {
    long limit = cinfo->mem->max_memory_to_use;
    if (limit <= 0) return max_bytes_needed;
    return already_allocated < static_cast<size_t>(limit) ? static_cast<size_t>(limit) - already_allocated : 0;
}
void jpeg_open_backing_store(j_common_ptr cinfo, backing_store_ptr info, long total_bytes_needed) {
    if (!gJpegDcOnly || total_bytes_needed <= 0 || total_bytes_needed % sizeof(JBLOCK) != 0) {
        (*cinfo->err->error_exit)(cinfo);
    }
    DcStore* s = static_cast<DcStore*>(arena_alloc(sizeof(DcStore)));
    size_t blocks = static_cast<size_t>(total_bytes_needed) / sizeof(JBLOCK);
    int16_t* dc = s != nullptr ? static_cast<int16_t*>(arena_calloc(blocks, sizeof(int16_t))) : nullptr;
    if (dc == nullptr) {
        arena_free(s);
        (*cinfo->err->error_exit)(cinfo);
    }
    *s = {dc, blocks};
    static_assert(sizeof(s) <= sizeof(info->temp_name));
    memcpy(info->temp_name, &s, sizeof(s));
    info->read_backing_store = dc_read;
    info->write_backing_store = dc_write;
    info->close_backing_store = dc_close;
}
long jpeg_mem_init(j_common_ptr) {
    return 0;
}
void jpeg_mem_term(j_common_ptr) {}
}

namespace decoder {

// ---------------------------------------------------------------------------------------------------------------
// Output: a stripe buffer flushed to the pipe. fd -1 discards (the warm-up).

Outcome gOutcome = {};

bool write_all(int fd, const void* data, size_t n) {
    const uint8_t* p = static_cast<const uint8_t*>(data);
    while (n > 0) {
        ssize_t k = write(fd, p, n);
        if (k < 0 && errno == EINTR) continue;
        if (k <= 0) return false;
        p += k;
        n -= static_cast<size_t>(k);
    }
    return true;
}

bool sink_flush(Sink* s) {
    if (s->fd >= 0 && s->used > 0 && !write_all(s->fd, s->buf, s->used)) return false;
    s->used = 0;
    return true;
}

bool sink_put(Sink* s, const uint8_t* p, size_t n) {
    while (n > 0) {
        size_t k = std::min(n, kStripeBytes - s->used);
        memcpy(s->buf + s->used, p, k);
        s->used += k;
        p += k;
        n -= k;
        if (s->used == kStripeBytes && !sink_flush(s)) return false;
    }
    return true;
}

void put_le32(uint8_t* p, uint32_t v) {
    for (int i = 0; i < 4; i++) p[i] = static_cast<uint8_t>(v >> (8 * i));
}

uint32_t le32(const uint8_t* b) {
    return b[0] | b[1] << 8 | b[2] << 16 | static_cast<uint32_t>(b[3]) << 24;
}

uint32_t gRotation = 0;

bool sink_header(Sink* s, uint32_t w, uint32_t h) {
    uint8_t hdr[16] = {'D', 'S', 'R', '2'};
    put_le32(hdr + 4, w);
    put_le32(hdr + 8, h);
    put_le32(hdr + 12, gRotation);
    return sink_put(s, hdr, sizeof(hdr)) && sink_flush(s);
}

// ---------------------------------------------------------------------------------------------------------------
// Scaling: rows come in one at a time, straight RGBA, and are premultiplied. A fractional area filter fits the image
// exactly into the box asked for (a wallpaper gets its screen size, not the next integer factor below it), without
// ever holding the whole image. Weights are exact integers: input pixel x covers [x * ow, (x + 1) * ow) and output
// pixel o covers [o * iw, (o + 1) * iw) on a common grid, so every output pixel is a weighted mean with one rounding.
// A weighted mean of premultiplied pixels keeps every colour channel at or below alpha.

// The largest size within maxW x maxH and kMaxPixels with iw x ih's aspect ratio, never larger than the image.
void fit_box(uint32_t iw, uint32_t ih, uint32_t maxW, uint32_t maxH, uint32_t* ow, uint32_t* oh) {
    double s = std::min({1.0, static_cast<double>(maxW) / iw, static_cast<double>(maxH) / ih});
    s = std::min(s, std::sqrt(static_cast<double>(kMaxPixels) / (static_cast<double>(iw) * ih)));
    uint64_t w = static_cast<uint64_t>(iw * s + 0.5), h = static_cast<uint64_t>(ih * s + 0.5);
    w = std::clamp<uint64_t>(w, 1, std::min(iw, maxW));
    h = std::clamp<uint64_t>(h, 1, std::min(ih, maxH));
    while (w * h > kMaxPixels) {
        if (w > 1) w--;
        if (h > 1) h--;
    }
    *ow = static_cast<uint32_t>(w);
    *oh = static_cast<uint32_t>(h);
}

bool scaler_init(Scaler* s, uint32_t iw, uint32_t ih, uint32_t ow, uint32_t oh, Sink* sink) {
    *s = {iw, ih, ow, oh, 0, 0, nullptr, nullptr, nullptr, sink, false};
    if (ow > iw || oh > ih || ow == 0 || oh == 0) return false;
    if (ow == iw && oh == ih) return true;
    size_t n = static_cast<size_t>(ow) * 4;
    s->hrow = static_cast<uint64_t*>(arena_alloc(n * sizeof(uint64_t)));
    s->acc = static_cast<uint64_t*>(arena_alloc(n * sizeof(uint64_t)));
    s->out = static_cast<uint8_t*>(arena_alloc(n));
    if (s->hrow == nullptr || s->acc == nullptr || s->out == nullptr) return false;
    memset(s->acc, 0, n * sizeof(uint64_t));
    return true;
}

void scaler_free(Scaler* s) {
    arena_free(s->hrow);
    arena_free(s->acc);
    arena_free(s->out);
}

void premultiply(uint8_t* p, uint32_t w) {
    for (uint32_t x = 0; x < w; x++, p += 4) {
        uint32_t a = p[3];
        if (a == 255) continue;
        p[0] = static_cast<uint8_t>((p[0] * a + 127) / 255);
        p[1] = static_cast<uint8_t>((p[1] * a + 127) / 255);
        p[2] = static_cast<uint8_t>((p[2] * a + 127) / 255);
    }
}

void scaler_add(Scaler* s, uint64_t weight) {
    size_t n = static_cast<size_t>(s->ow) * 4;
    for (size_t i = 0; i < n; i++) s->acc[i] += s->hrow[i] * weight;
}

bool scaler_emit(Scaler* s) {
    uint64_t d = static_cast<uint64_t>(s->iw) * s->ih;
    size_t n = static_cast<size_t>(s->ow) * 4;
    for (size_t i = 0; i < n; i++) {
        s->out[i] = static_cast<uint8_t>((s->acc[i] + d / 2) / d);
        s->acc[i] = 0;
    }
    s->p++;
    return sink_put(s->sink, s->out, n);
}

bool scaler_push(Scaler* s, uint8_t* row) {
    if (s->y >= s->ih) return false;
    if (!s->premultiplied) premultiply(row, s->iw);
    if (s->hrow == nullptr) {  // same size
        s->y++;
        s->p++;
        return sink_put(s->sink, row, static_cast<size_t>(s->iw) * 4);
    }
    // Horizontal: each output column's weighted sum of the input pixels it covers.
    for (uint32_t o = 0; o < s->ow; o++) {
        uint64_t lo = static_cast<uint64_t>(o) * s->iw, hi = lo + s->iw;
        uint32_t x0 = static_cast<uint32_t>(lo / s->ow), x1 = static_cast<uint32_t>((hi - 1) / s->ow);
        uint64_t sum[4] = {};
        for (uint32_t x = x0; x <= x1; x++) {
            uint64_t xs = static_cast<uint64_t>(x) * s->ow;
            uint64_t w = std::min(hi, xs + s->ow) - std::max(lo, xs);
            const uint8_t* px = row + static_cast<size_t>(x) * 4;
            for (int c = 0; c < 4; c++) sum[c] += w * px[c];
        }
        for (int c = 0; c < 4; c++) s->hrow[static_cast<size_t>(o) * 4 + c] = sum[c];
    }
    // Vertical: the row covers [y * oh, (y + 1) * oh), at most two output rows since oh <= ih.
    uint64_t ys = static_cast<uint64_t>(s->y) * s->oh, ye = ys + s->oh;
    uint64_t pe = static_cast<uint64_t>(s->p + 1) * s->ih;
    s->y++;
    if (ye <= pe) {
        scaler_add(s, ye - ys);
        return ye < pe || scaler_emit(s);
    }
    scaler_add(s, pe - ys);
    if (!scaler_emit(s)) return false;
    scaler_add(s, ye - pe);
    return ye < static_cast<uint64_t>(s->p + 1) * s->ih || scaler_emit(s);
}

bool scaler_done(const Scaler* s) {
    return s->y == s->ih && s->p == s->oh;
}

bool start_output(Scaler* s, uint32_t iw, uint32_t ih, uint32_t maxW, uint32_t maxH, Sink* sink) {
    uint32_t ow, oh;
    fit_box(iw, ih, maxW, maxH, &ow, &oh);
    return scaler_init(s, iw, ih, ow, oh, sink) && sink_header(sink, ow, oh);
}

// ---------------------------------------------------------------------------------------------------------------
// Input for PNG and JPEG: the file in memory, or (streamed) the start of it in memory and the rest from a pipe the
// broker fills as the bytes arrive from Android, so the file is never held whole in the VM.

struct Src {
    const uint8_t* pre;  // the file, or its start
    size_t preLen;
    size_t preAt;
    int fd;              // the rest, or -1
    uint64_t fdLeft;     // bytes the rest still has, as the request declared
};

// Up to n bytes from the source, 0 at its end.
size_t src_read(Src* s, uint8_t* out, size_t n) {
    if (s->preAt < s->preLen) {
        size_t k = std::min(n, s->preLen - s->preAt);
        memcpy(out, s->pre + s->preAt, k);
        s->preAt += k;
        return k;
    }
    while (s->fd >= 0 && s->fdLeft > 0) {
        ssize_t k = read(s->fd, out, static_cast<size_t>(std::min<uint64_t>(n, s->fdLeft)));
        if (k < 0 && errno == EINTR) continue;
        if (k <= 0) {
            s->fdLeft = 0;
            break;
        }
        s->fdLeft -= static_cast<uint64_t>(k);
        return static_cast<size_t>(k);
    }
    return 0;
}

// ---------------------------------------------------------------------------------------------------------------
// PNG through libpng's row API. Every allocation goes through the arena, errors jump back without signal masks
// (_setjmp, _longjmp), since saving or restoring a mask is a system call.

void png_read_input(png_structp png, png_bytep out, size_t n) {
    Src* in = static_cast<Src*>(png_get_io_ptr(png));
    while (n > 0) {
        size_t k = src_read(in, out, n);
        if (k == 0) png_error(png, "truncated");
        out += k;
        n -= k;
    }
}

png_voidp png_arena_alloc(png_structp, png_alloc_size_t n) {
    return arena_alloc(n);
}

void png_arena_free(png_structp, png_voidp p) {
    arena_free(p);
}

void png_fail(png_structp png, png_const_charp) {
    png_longjmp(png, 1);
}

void png_quiet(png_structp, png_const_charp) {}

// headerOnly: stop after the header and report its size in *outW, *outH. Otherwise decode into the sink, fitted into
// maxW x maxH.
bool decode_png_src(Src* in, uint32_t maxW, uint32_t maxH, Sink* sink, bool headerOnly, uint32_t* outW,
                    uint32_t* outH) {
    png_structp png = png_create_read_struct_2(PNG_LIBPNG_VER_STRING, nullptr, png_fail, png_quiet, nullptr,
                                               png_arena_alloc, png_arena_free);
    if (png == nullptr) return false;
    png_infop info = png_create_info_struct(png);
    if (info == nullptr) {
        png_destroy_read_struct(&png, nullptr, nullptr);
        return false;
    }
    // Set before the jump point and only pointed into after it, so the error path sees what to free.
    Scaler* const scalerp = static_cast<Scaler*>(arena_calloc(1, sizeof(Scaler)));
    if (scalerp == nullptr) {
        png_destroy_read_struct(&png, &info, nullptr);
        return false;
    }
    Scaler& scaler = *scalerp;
    uint8_t* volatile pixels = nullptr;
    if (_setjmp(*png_set_longjmp_fn(png, _longjmp, sizeof(jmp_buf)))) {
        png_free(png, pixels);
        scaler_free(scalerp);
        arena_free(scalerp);
        png_destroy_read_struct(&png, &info, nullptr);
        return false;
    }
    png_set_read_fn(png, in, png_read_input);
    png_set_user_limits(png, kMaxDimension, kMaxDimension);
    png_set_chunk_malloc_max(png, 4u << 20);
    png_set_chunk_cache_max(png, 128);
    png_set_keep_unknown_chunks(png, PNG_HANDLE_CHUNK_NEVER, nullptr, 0);
    png_read_info(png, info);
    uint32_t w = png_get_image_width(png, info);
    uint32_t h = png_get_image_height(png, info);
    if (w == 0 || h == 0 || w > kMaxDimension || h > kMaxDimension) png_error(png, "size");
    if (headerOnly) {
        *outW = w;
        *outH = h;
        arena_free(scalerp);
        png_destroy_read_struct(&png, &info, nullptr);
        return true;
    }
    int depth = png_get_bit_depth(png, info);
    int color = png_get_color_type(png, info);
    png_set_expand(png);
    if (depth == 16) png_set_strip_16(png);
    if (color == PNG_COLOR_TYPE_GRAY || color == PNG_COLOR_TYPE_GRAY_ALPHA) png_set_gray_to_rgb(png);
    if (!(color & PNG_COLOR_MASK_ALPHA) && !png_get_valid(png, info, PNG_INFO_tRNS)) {
        png_set_filler(png, 0xff, PNG_FILLER_AFTER);
    }
    int passes = png_set_interlace_handling(png);
    png_read_update_info(png, info);
    if (png_get_rowbytes(png, info) != static_cast<size_t>(w) * 4) png_error(png, "format");
    uint32_t ow, oh;
    fit_box(w, h, maxW, maxH, &ow, &oh);
    if (!scaler_init(&scaler, w, h, ow, oh, sink) || !sink_header(sink, ow, oh)) png_error(png, "output");
    size_t stride = static_cast<size_t>(w) * 4;
    if (passes == 1) {
        pixels = static_cast<uint8_t*>(png_malloc(png, stride));
        for (uint32_t y = 0; y < h; y++) {
            png_read_row(png, pixels, nullptr);
            if (!scaler_push(&scaler, pixels)) png_error(png, "output");
        }
    } else {
        // Interlaced: the passes fill the whole image, so it needs room in the arena for all of it.
        if (static_cast<uint64_t>(stride) * h > arena_left()) png_error(png, "interlaced image too large");
        pixels = static_cast<uint8_t*>(png_malloc(png, stride * h));
        for (int pass = 0; pass < passes; pass++) {
            for (uint32_t y = 0; y < h; y++) png_read_row(png, pixels + stride * y, nullptr);
        }
        for (uint32_t y = 0; y < h; y++) {
            if (!scaler_push(&scaler, pixels + stride * y)) png_error(png, "output");
        }
    }
    bool done = scaler_done(&scaler);
    png_free(png, pixels);
    scaler_free(&scaler);
    arena_free(scalerp);
    png_destroy_read_struct(&png, &info, nullptr);
    return done && sink_flush(sink);
}

bool decode_png(const uint8_t* data, size_t size, uint32_t maxW, uint32_t maxH, Sink* sink, bool headerOnly,
                uint32_t* outW, uint32_t* outH) {
    Src in = {data, size, 0, -1, 0};
    return decode_png_src(&in, maxW, maxH, sink, headerOnly, outW, outH);
}

// ---------------------------------------------------------------------------------------------------------------
// JPEG through libjpeg-turbo, scaled by 1/2, 1/4 or 1/8 in the decoder as far as that stays at or above the size
// asked for, then exactly by the area filter.

struct JpegError {
    jpeg_error_mgr mgr;
    jmp_buf jump;
};

void jpeg_fail(j_common_ptr cinfo) {
    _longjmp(reinterpret_cast<JpegError*>(cinfo->err)->jump, 1);
}

void jpeg_quiet(j_common_ptr, int) {}

void jpeg_quiet_output(j_common_ptr) {}

// A progressive JPEG can carry thousands of tiny scans to burn CPU time.
void jpeg_progress(j_common_ptr cinfo) {
    if (reinterpret_cast<j_decompress_ptr>(cinfo)->input_scan_number > 500) (*cinfo->err->error_exit)(cinfo);
}

// A streamed JPEG: libjpeg-turbo pulls 64 KiB at a time. At the end of the input it gets an end-of-image marker, as
// libjpeg-turbo's own sources do, so a cut-off file decodes as far as it goes (the missing rows grey).
constexpr size_t kJpegChunk = 64u << 10;

struct JpegStream {
    jpeg_source_mgr pub;
    Src* src;
    JOCTET* buf;
};

void jstream_init(j_decompress_ptr) {}

boolean jstream_fill(j_decompress_ptr cinfo) {
    JpegStream* s = reinterpret_cast<JpegStream*>(cinfo->src);
    size_t n = src_read(s->src, s->buf, kJpegChunk);
    if (n == 0) {
        s->buf[0] = 0xff;
        s->buf[1] = JPEG_EOI;
        n = 2;
    }
    s->pub.next_input_byte = s->buf;
    s->pub.bytes_in_buffer = n;
    return TRUE;
}

void jstream_skip(j_decompress_ptr cinfo, long n) {
    JpegStream* s = reinterpret_cast<JpegStream*>(cinfo->src);
    if (n <= 0) return;
    while (static_cast<size_t>(n) > s->pub.bytes_in_buffer) {
        n -= static_cast<long>(s->pub.bytes_in_buffer);
        jstream_fill(cinfo);
    }
    s->pub.next_input_byte += n;
    s->pub.bytes_in_buffer -= static_cast<size_t>(n);
}

void jstream_term(j_decompress_ptr) {}

// The most a multi-scan JPEG's coefficients may take (full blocks), and the most its DC values may take when they do
// not fit: then it is decoded at 1/8 from DC values alone.
constexpr size_t kJpegSlack = 4u << 20;

bool decode_jpeg_src(Src* in, uint32_t maxW, uint32_t maxH, Sink* sink, bool headerOnly, uint32_t* outW,
                     uint32_t* outH) {
    jpeg_decompress_struct cinfo;
    JpegError err;
    jpeg_progress_mgr progress = {};
    Scaler scaler = {};
    JpegStream stream = {};
    cinfo.err = jpeg_std_error(&err.mgr);
    err.mgr.error_exit = jpeg_fail;
    err.mgr.emit_message = jpeg_quiet;
    err.mgr.output_message = jpeg_quiet_output;
    gJpegDcOnly = false;
    if (_setjmp(err.jump)) {
        jpeg_destroy_decompress(&cinfo);
        return false;
    }
    jpeg_create_decompress(&cinfo);
    progress.progress_monitor = jpeg_progress;
    cinfo.progress = &progress;
    if (in->fd < 0) {
        jpeg_mem_src(&cinfo, in->pre, in->preLen);
    } else {
        stream.buf = static_cast<JOCTET*>(
                (*cinfo.mem->alloc_small)(reinterpret_cast<j_common_ptr>(&cinfo), JPOOL_PERMANENT, kJpegChunk));
        stream.src = in;
        stream.pub.init_source = jstream_init;
        stream.pub.fill_input_buffer = jstream_fill;
        stream.pub.skip_input_data = jstream_skip;
        stream.pub.resync_to_restart = jpeg_resync_to_restart;
        stream.pub.term_source = jstream_term;
        cinfo.src = &stream.pub;
    }
    if (jpeg_read_header(&cinfo, TRUE) != JPEG_HEADER_OK || cinfo.image_width == 0 || cinfo.image_height == 0 ||
        cinfo.image_width > kMaxDimension || cinfo.image_height > kMaxDimension) {
        jpeg_destroy_decompress(&cinfo);
        return false;
    }
    if (headerOnly) {
        *outW = cinfo.image_width;
        *outH = cinfo.image_height;
        jpeg_destroy_decompress(&cinfo);
        return true;
    }
    uint32_t ow, oh;
    fit_box(cinfo.image_width, cinfo.image_height, maxW, maxH, &ow, &oh);
    cinfo.out_color_space = JCS_EXT_RGBA;
    cinfo.scale_num = 1;
    cinfo.scale_denom = 1;
    jpeg_calc_output_dimensions(&cinfo);
    while (cinfo.scale_denom < 8) {
        cinfo.scale_denom *= 2;
        jpeg_calc_output_dimensions(&cinfo);
        if (cinfo.output_width < ow || cinfo.output_height < oh) {
            cinfo.scale_denom /= 2;
            jpeg_calc_output_dimensions(&cinfo);
            break;
        }
    }
    // A progressive (multi-scan) image keeps all its coefficients until the last scan. When they fit the arena they
    // stay there. When not, it is decoded at 1/8 from its DC values, which the backing store keeps 2 bytes a block,
    // and the thumbnail is at most an eighth of the image on each side.
    size_t room = arena_left() - std::min(arena_left(), kJpegSlack);
    if (jpeg_has_multiple_scans(&cinfo)) {
        uint64_t coef = 0;
        for (int c = 0; c < cinfo.num_components; c++) {
            const jpeg_component_info& comp = cinfo.comp_info[c];
            coef += static_cast<uint64_t>(comp.width_in_blocks + comp.h_samp_factor) *
                    (comp.height_in_blocks + comp.v_samp_factor) * sizeof(JBLOCK);
        }
        if (coef > room) {
            if (coef / sizeof(JBLOCK) * sizeof(int16_t) > room / 2) {
                jpeg_destroy_decompress(&cinfo);
                return false;
            }
            gJpegDcOnly = true;
            cinfo.scale_denom = 8;
            cinfo.do_block_smoothing = FALSE;
            jpeg_calc_output_dimensions(&cinfo);
            fit_box(cinfo.output_width, cinfo.output_height, maxW, maxH, &ow, &oh);
            room = kJpegSlack;  // the band of full blocks in memory, the rest goes to the DC store
        }
    }
    cinfo.mem->max_memory_to_use = static_cast<long>(room);
    jpeg_start_decompress(&cinfo);
    if (!scaler_init(&scaler, cinfo.output_width, cinfo.output_height, ow, oh, sink) || !sink_header(sink, ow, oh)) {
        jpeg_destroy_decompress(&cinfo);
        return false;
    }
    JSAMPARRAY row = (*cinfo.mem->alloc_sarray)(reinterpret_cast<j_common_ptr>(&cinfo), JPOOL_IMAGE,
                                               cinfo.output_width * 4, 1);
    while (cinfo.output_scanline < cinfo.output_height) {
        if (jpeg_read_scanlines(&cinfo, row, 1) != 1 || !scaler_push(&scaler, row[0])) {
            scaler_free(&scaler);
            jpeg_destroy_decompress(&cinfo);
            return false;
        }
    }
    bool done = scaler_done(&scaler);
    scaler_free(&scaler);
    jpeg_destroy_decompress(&cinfo);
    return done && sink_flush(sink);
}

bool decode_jpeg(const uint8_t* data, size_t size, uint32_t maxW, uint32_t maxH, Sink* sink, bool headerOnly,
                 uint32_t* outW, uint32_t* outH) {
    Src in = {data, size, 0, -1, 0};
    return decode_jpeg_src(&in, maxW, maxH, sink, headerOnly, outW, outH);
}

}  // namespace decoder

namespace {

// The broker reads this much of the file's start to pick the decoder, and nothing else of it.
constexpr size_t kMagicBytes = 64;

bool brand_in(const uint8_t* b, const char* const* list) {
    for (; *list != nullptr; list++) {
        if (memcmp(b, *list, 4) == 0) return true;
    }
    return false;
}

// HEIF or AVIF from the ftyp box's major and compatible brands. A file that lists both is what its major brand says,
// else AVIF. The decoder reads either codec, so the choice only names the format.
uint32_t detect_isobmff(const uint8_t* b, size_t n) {
    static const char* const kHeif[] = {"heic", "heix", "heim", "heis", "hevc", "hevx", "hevm", "hevs", nullptr};
    static const char* const kAvif[] = {"avif", "avis", nullptr};
    uint32_t boxSize = static_cast<uint32_t>(b[0]) << 24 | b[1] << 16 | b[2] << 8 | b[3];
    if (n < 16 || boxSize < 16) return kFormatUnknown;
    if (brand_in(b + 8, kAvif)) return kFormatAvif;
    if (brand_in(b + 8, kHeif)) return kFormatHeif;
    size_t end = std::min<size_t>(n, boxSize);
    bool heif = false;
    for (size_t at = 16; at + 4 <= end; at += 4) {
        if (brand_in(b + at, kAvif)) return kFormatAvif;
        heif = heif || brand_in(b + at, kHeif);
    }
    return heif ? kFormatHeif : kFormatUnknown;
}

// WBMP has no signature: type 0, a fixed header byte with only the extension bits possibly set, then width and height
// as multi-byte integers. Checked as strictly as the format allows, against the whole input's length, and only after
// every format with a signature.
bool is_wbmp(const uint8_t* b, size_t n, uint64_t total) {
    if (n < 4 || b[0] != 0 || (b[1] & 0x9f) != 0) return false;
    size_t at = 2;
    uint32_t dim[2];
    for (uint32_t& d : dim) {
        uint64_t v = 0;
        int k = 0;
        for (;; k++) {
            if (at >= n || k >= 3) return false;
            uint8_t c = b[at++];
            v = v << 7 | (c & 0x7f);
            if ((c & 0x80) == 0) break;
        }
        if (v == 0 || v > kMaxDimension) return false;
        d = static_cast<uint32_t>(v);
    }
    return at + static_cast<uint64_t>((dim[0] + 7) / 8) * dim[1] <= total;
}

uint32_t detect_format(const uint8_t* b, size_t n, uint64_t total) {
    if (n >= 8 && memcmp(b, "\x89PNG\r\n\x1a\n", 8) == 0) return kFormatPng;
    if (n >= 3 && b[0] == 0xff && b[1] == 0xd8 && b[2] == 0xff) return kFormatJpeg;
    if (n >= 6 && (memcmp(b, "GIF87a", 6) == 0 || memcmp(b, "GIF89a", 6) == 0)) return kFormatGif;
    if (n >= 12 && memcmp(b, "RIFF", 4) == 0 && memcmp(b + 8, "WEBP", 4) == 0) return kFormatWebp;
    if (n >= 14 && b[0] == 'B' && b[1] == 'M') return kFormatBmp;
    if (n >= 6 && b[0] == 0 && b[1] == 0 && (b[2] == 1 || b[2] == 2) && b[3] == 0 && (b[4] | b[5]) != 0) {
        return kFormatIco;
    }
    if (n >= 16 && memcmp(b + 4, "ftyp", 4) == 0) return detect_isobmff(b, n);
    // A TIFF file: the worker decodes it only when it is a DNG, and answers UNSUPPORTED otherwise.
    if (n >= 8 && (memcmp(b, "II*\0", 4) == 0 || memcmp(b, "MM\0*", 4) == 0)) return kFormatDng;
    if (is_wbmp(b, n, total)) return kFormatWbmp;
    return kFormatUnknown;
}

DecodeFn decoder_for(uint32_t format) {
    switch (format) {
        case kFormatJpeg: return decode_jpeg;
        case kFormatPng: return decode_png;
        case kFormatGif: return decode_gif;
        case kFormatWebp: return decode_webp;
        case kFormatBmp: return decode_bmp;
        case kFormatHeif: return decode_heif;
        case kFormatAvif: return decode_heif;
        case kFormatDng: return decode_dng;
        case kFormatIco: return decode_ico;
        case kFormatWbmp: return decode_wbmp;
        default: return nullptr;
    }
}

bool decode_any(uint32_t format, const uint8_t* data, size_t size, uint32_t maxW, uint32_t maxH, Sink* sink,
                bool headerOnly, uint32_t* w, uint32_t* h) {
    DecodeFn fn = decoder_for(format);
    return fn != nullptr && fn(data, size, maxW, maxH, sink, headerOnly, w, h);
}

// Formats whose files can hold more than one frame (the contract allows animated only for these).
bool may_be_animated(uint32_t format) {
    return format == kFormatGif || format == kFormatWebp || format == kFormatPng || format == kFormatHeif ||
           format == kFormatAvif;
}

// ---------------------------------------------------------------------------------------------------------------
// Warm-up. libjpeg-turbo and libpng check the CPU's features once on first use, which may read /proc. libjpeg-turbo
// keeps the result per thread, so the broker decodes two tiny images before it forks any worker. dav1d reads
// /proc/cpuinfo once per process when its first decoder opens, and libwebp sets up its function tables once: their
// warm-ups run here too. A locked-down worker would be killed by any of these checks.

#include "warmup_images.h"

void warm_up() {
    Sink sink = {-1, static_cast<uint8_t*>(malloc(kStripeBytes)), 0};
    if (sink.buf == nullptr) return;
    uint32_t w, h;
    decode_png(kWarmupPng, sizeof(kWarmupPng), 5, 3, &sink, false, &w, &h);
    decode_jpeg(kWarmupJpeg, sizeof(kWarmupJpeg), 5, 3, &sink, false, &w, &h);
    free(sink.buf);
    warm_up_webp();
    warm_up_heif();
}

// ---------------------------------------------------------------------------------------------------------------
// The worker. Workers are forked by the zygote, a child the broker forks once at start, before any request: so no
// worker ever inherits another request's file, pixels or metadata from the broker's memory. A worker gets its file
// as a memory file mapped read-only, and its output pipe.

// Worker exit codes. A signal (seccomp's kill, the CPU limit, the broker's kill at the wall deadline) or an exit code
// other than these counts as internal: not a verdict on the file.
constexpr int kExitOk = 0;
constexpr int kExitDecodeFailed = 3;
constexpr int kExitLockdown = 4;
constexpr int kExitUnsupported = 6;  // a valid file of a kind the VM does not decode

[[noreturn]] void worker_exit(int code) {
    syscall(__NR_exit, code);
    __builtin_unreachable();
}

#ifdef DECODER_TEST_HOOKS
// Test builds: a hook's outcome as a 1x1 thumbnail (three values and alpha 255), so a hook the lockdown did not stop
// shows up in the result instead of looking like a failed decode.
[[noreturn]] void hook_report(uint8_t a, uint8_t b, uint8_t c) {
    uint8_t px[4] = {a, b, c, 255};
    Sink sink = {0, static_cast<uint8_t*>(arena_alloc(kStripeBytes)), 0};
    worker_exit(sink_header(&sink, 1, 1) && sink_put(&sink, px, 4) && sink_flush(&sink) ? 0 : 3);
}

// Test builds: looks for the request's bytes anywhere in the worker's readable memory but the file's own mapping,
// before the lockdown (it needs /proc/self/maps). 1 means another request's data reached this worker.
[[noreturn]] void hook_scan(const uint8_t* data, size_t size) {
    int found = 0, regions = 0;
    int fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
    static char maps[1 << 16];
    ssize_t n = fd >= 0 ? read(fd, maps, sizeof(maps) - 1) : -1;
    if (fd >= 0) close(fd);
    if (n <= 0 || size == 0) hook_report(2, 0, 2);
    maps[n] = 0;
    for (char* line = maps; line != nullptr && *line != 0;) {
        char* next = strchr(line, '\n');
        if (next != nullptr) *next++ = 0;
        unsigned long lo, hi;
        char perms[5] = {};
        if (sscanf(line, "%lx-%lx %4s", &lo, &hi, perms) == 3 && perms[0] == 'r' && strstr(line, "[vvar") == nullptr &&
            strstr(line, "[vsyscall") == nullptr) {
            const uint8_t* b = reinterpret_cast<const uint8_t*>(lo);
            size_t len = hi - lo;
            bool own = data >= b && data < b + len;
            if (!own && memmem(b, len, data, size) != nullptr) found = 1;
            regions++;
        }
        line = next;
    }
    hook_report(static_cast<uint8_t>(found), static_cast<uint8_t>(std::min(regions, 255)), 3);
}
#endif

// The lockdown, in this order: rlimits (no new file descriptors, no new processes, no more address space, capped CPU
// time, no core or file writes), an unprivileged user, no new privileges, then seccomp strict mode. Everything before
// seccomp is a second layer only. Returns 0, or the errno of seccomp. Exits for anything else that fails. The output
// pipe becomes fd 0 and a streamed input (in, or -1) fd 1: nothing else stays open.
int lockdown(int out, int in = -1) {
    int adj = open("/proc/self/oom_score_adj", O_WRONLY | O_CLOEXEC);
    if (adj >= 0) {
        (void)!write(adj, "1000", 4);
        close(adj);
    }
    uint64_t vmBytes = 0;
    int statm = open("/proc/self/statm", O_RDONLY | O_CLOEXEC);
    if (statm >= 0) {
        char buf[64] = {};
        if (read(statm, buf, sizeof(buf) - 1) > 0) vmBytes = strtoull(buf, nullptr, 10) * getpagesize();
        close(statm);
    }
    if (vmBytes == 0) worker_exit(kExitLockdown);
    // Only the output pipe stays open, as fd 0, and a streamed input as fd 1.
    if (in == 0) {
        in = dup(in);  // out's place: move it away first
        if (in < 0) worker_exit(kExitLockdown);
    }
    if (out != 0 && dup2(out, 0) != 0) worker_exit(kExitLockdown);
    if (in >= 0 && in != 1 && dup2(in, 1) != 1) worker_exit(kExitLockdown);
    unsigned firstClosed = in >= 0 ? 2u : 1u;
    if (syscall(__NR_close_range, firstClosed, ~0u, 0u) != 0) worker_exit(kExitLockdown);
    struct {
        int resource;
        rlim_t value;
    } limits[] = {
            {RLIMIT_CPU, kWorkerCpuSeconds},
            {RLIMIT_NOFILE, in >= 0 ? 2u : 1u},  // the open descriptors take every number allowed
            {RLIMIT_NPROC, 0},
            {RLIMIT_AS, vmBytes + (16u << 20)},
            {RLIMIT_FSIZE, 0},
            {RLIMIT_CORE, 0},
    };
    for (const auto& l : limits) {
        rlimit r = {l.value, l.value};
        if (setrlimit(l.resource, &r) != 0) worker_exit(kExitLockdown);
    }
#ifdef DECODER_HOST_TEST
    // Host test builds run as an ordinary user, who cannot change users.
    bool dropUser = getuid() == 0;
#else
    bool dropUser = true;
#endif
    if (dropUser && (setgroups(0, nullptr) != 0 || setresgid(kWorkerId, kWorkerId, kWorkerId) != 0 ||
                     setresuid(kWorkerId, kWorkerId, kWorkerId) != 0)) {
        worker_exit(kExitLockdown);
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) worker_exit(kExitLockdown);
    arena_enter_worker();
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT, 0, 0, 0) != 0) return errno;
    return 0;
}

// The start of a streamed file the worker reads before it decodes: the metadata of a JPEG or PNG comes before its
// image data, so this covers it, and the decoders continue from here with the rest of the stream.
constexpr size_t kPrefixBytes = 1u << 20;

[[noreturn]] void worker_main(const Request& rq, uint32_t format, const uint8_t* data, size_t size, int out,
                              int in) {
#ifdef DECODER_TEST_HOOKS
    if (rq.op == kOpHook && rq.arg0 == kHookScan) {
        if (out != 0 && dup2(out, 0) != 0) worker_exit(kExitLockdown);
        hook_scan(data, size);
    }
#endif
    int seccompError = lockdown(out, in);
#ifndef DECODER_TEST_HOOKS
    // Production builds never decode without seccomp.
    if (seccompError != 0) worker_exit(kExitLockdown);
#else
    if (rq.op == kOpHook) {
        if (rq.arg0 == kHookOpen) {
            long r = syscall(__NR_openat, AT_FDCWD, "/proc/self/status", O_RDONLY);
            hook_report(r < 0, r < 0 ? errno : 0, 0);
        }
        if (rq.arg0 == kHookMmap) {
            long r = syscall(__NR_mmap, 0, 64u << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            hook_report(r == -1, r == -1 ? errno : 0, 0);
        }
        if (rq.arg0 == kHookSpin) {
            for (;;) __asm__ volatile("" ::: "memory");
        }
        if (rq.arg0 == kHookLockdown) hook_report(seccompError == 0, seccompError, 1);
        if (rq.arg0 == kHookFork) {
            long r = syscall(__NR_clone, SIGCHLD, 0, 0, 0, 0);
            if (r == 0) worker_exit(0);
            hook_report(r < 0, r < 0 ? errno : 0, 0);
        }
        if (rq.arg0 == kHookBadPixels) {
            // A compromised worker sending colours above alpha: the broker must answer INVALID itself.
            uint8_t px[8] = {200, 0, 0, 10, 1, 1, 1, 1};
            Sink sink = {0, static_cast<uint8_t*>(arena_alloc(kStripeBytes)), 0};
            worker_exit(sink_header(&sink, 2, 1) && sink_put(&sink, px, 8) && sink_flush(&sink) ? 0 : 3);
        }
        worker_exit(5);
    }
    if (seccompError != 0) worker_exit(kExitLockdown);
#endif

    Sink sink = {0, static_cast<uint8_t*>(arena_alloc(kStripeBytes)), 0};
    if (sink.buf == nullptr) worker_exit(kExitDecodeFailed);
    // A decode that failed: UNSUPPORTED when the decoder found a valid file of a kind it does not read.
    auto failed = [] { return gOutcome.unsupported ? kExitUnsupported : kExitDecodeFailed; };
    // A streamed JPEG or PNG (thumbnail or metadata): its start into the arena, the rest stays in the pipe.
    Src stream = {nullptr, 0, 0, -1, 0};
    if (in >= 0) {
        size_t want = static_cast<size_t>(std::min<uint64_t>(rq.inputLen, kPrefixBytes));
        uint8_t* pre = static_cast<uint8_t*>(arena_alloc(std::max<size_t>(want, 1)));
        if (pre == nullptr) worker_exit(kExitDecodeFailed);
        size_t got = 0;
        while (got < want) {
            ssize_t k = read(1, pre + got, want - got);
            if (k < 0 && errno == EINTR) continue;
            if (k <= 0) break;
            got += static_cast<size_t>(k);
        }
        stream = {pre, got, 0, 1, rq.inputLen - got};
        data = pre;
        size = got;
    }
    // Header-only and full decodes: from the stream when there is one, else from memory.
    auto decode = [&](uint32_t maxW, uint32_t maxH, bool headerOnly, uint32_t* w, uint32_t* h) {
        if (in < 0) return decode_any(format, data, size, maxW, maxH, &sink, headerOnly, w, h);
        return format == kFormatPng ? decode_png_src(&stream, maxW, maxH, &sink, headerOnly, w, h)
                                    : decode_jpeg_src(&stream, maxW, maxH, &sink, headerOnly, w, h);
    };
    if (rq.op == kOpProbe) {
        uint32_t w = 0, h = 0;
        if (!decode_any(format, data, size, 0, 0, &sink, true, &w, &h)) worker_exit(failed());
        bool animated = format == kFormatPng ? png_is_animated(data, size) : gOutcome.animated;
        uint8_t msg[20] = {'D', 'P', 'R', '1'};
        put_le32(msg + 4, format);
        put_le32(msg + 8, w);
        put_le32(msg + 12, h);
        put_le32(msg + 16, animated && may_be_animated(format) ? 1 : 0);
        worker_exit(write_all(0, msg, sizeof(msg)) ? kExitOk : kExitDecodeFailed);
    }
    Meta* m = static_cast<Meta*>(arena_alloc(sizeof(Meta)));
    if (m == nullptr) worker_exit(kExitDecodeFailed);
    memset(m, 0, sizeof(*m));
    m->orientation = -1;
    m->dateTakenMillis = -1;
    if (rq.op == kOpMetadata) {
        m->magic = kMetaMagic;
        m->version = 1;
        m->format = format;
        read_metadata(data, size, format, m);
        if (!decode(0, 0, true, &m->width, &m->height)) worker_exit(failed());
        worker_exit(write_all(0, m, sizeof(*m)) ? kExitOk : kExitDecodeFailed);
    }
    // Thumbnail: the rotation comes from the file's EXIF orientation, read first.
    read_metadata(data, size, format, m);
    gRotation = m->orientation > 0 ? static_cast<uint32_t>(m->orientation) : 0;
    // The box is for the image as shown. Turned by 90 or 270 degrees, the stored image fits it the other way round.
    bool turned = gRotation == 90 || gRotation == 270;
    uint32_t w, h;
    worker_exit(decode(turned ? rq.arg1 : rq.arg0, turned ? rq.arg0 : rq.arg1, false, &w, &h) ? kExitOk : failed());
}

// ---------------------------------------------------------------------------------------------------------------
// The zygote: forked once, after the warm-up and the lockdown self-test, before the first request. It never sees a
// file: the broker hands it a memory file and a pipe per request, it forks the worker, reports its pid, waits for it
// and reports how it ended.

struct ZygoteRequest {
    Request rq;
    uint32_t format;
    uint32_t len;
    uint32_t streamed;  // the input descriptor is a pipe to read the file from, not a memory file to map
};

struct ZygoteReply {
    int32_t kind;  // 1: started (value is the pid), 2: ended (value is the wait status), 3: fork failed
    int32_t value;
};

int gZygote = -1;  // the broker's end of the zygote socket
pid_t gZygotePid = -1;

[[noreturn]] void zygote_main(int sock) {
    for (;;) {
        ZygoteRequest zr;
        char control[CMSG_SPACE(2 * sizeof(int))];
        iovec iov = {&zr, sizeof(zr)};
        msghdr mh = {};
        mh.msg_iov = &iov;
        mh.msg_iovlen = 1;
        mh.msg_control = control;
        mh.msg_controllen = sizeof(control);
        ssize_t n = recvmsg(sock, &mh, MSG_CMSG_CLOEXEC);
        if (n == 0) _exit(0);  // the broker is gone
        cmsghdr* cm = CMSG_FIRSTHDR(&mh);
        if (n != static_cast<ssize_t>(sizeof(zr)) || cm == nullptr || cm->cmsg_type != SCM_RIGHTS ||
            cm->cmsg_len != CMSG_LEN(2 * sizeof(int))) {
            _exit(1);
        }
        int fds[2];
        memcpy(fds, CMSG_DATA(cm), sizeof(fds));
        pid_t pid = fork();
        if (pid == 0) {
            close(sock);
            const uint8_t* data = nullptr;
            if (zr.streamed) worker_main(zr.rq, zr.format, nullptr, 0, fds[1], fds[0]);
            if (zr.len > 0) {
                void* p = mmap(nullptr, zr.len, PROT_READ, MAP_PRIVATE, fds[0], 0);
                if (p == MAP_FAILED) worker_exit(kExitLockdown);
                data = static_cast<const uint8_t*>(p);
            }
            close(fds[0]);
            worker_main(zr.rq, zr.format, data, zr.len, fds[1], -1);
        }
        close(fds[0]);
        close(fds[1]);
        ZygoteReply started = {pid > 0 ? 1 : 3, static_cast<int32_t>(pid)};
        if (!write_all(sock, &started, sizeof(started))) _exit(1);
        if (pid < 0) continue;
        int status = 0;
        while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
        }
        ZygoteReply ended = {2, status};
        if (!write_all(sock, &ended, sizeof(ended))) _exit(1);
    }
}

bool start_zygote() {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv) != 0) return false;
    pid_t pid = fork();
    if (pid == 0) {
        close(sv[0]);
        zygote_main(sv[1]);
    }
    close(sv[1]);
    if (pid < 0) return false;
    gZygote = sv[0];
    gZygotePid = pid;
    return true;
}

// ---------------------------------------------------------------------------------------------------------------
// The broker.

int64_t now_ms() {
    timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<int64_t>(ts.tv_sec) * 1000 + ts.tv_nsec / 1000000;
}

// Reads n bytes unless the other side ends, stays silent for idleMs or passes the deadline. Returns the bytes read,
// or -1 for a read error, -2 for a timeout.
ssize_t read_full(int fd, void* data, size_t n, int64_t deadline, int idleMs) {
    uint8_t* p = static_cast<uint8_t*>(data);
    size_t got = 0;
    while (got < n) {
        int64_t left = deadline - now_ms();
        if (left <= 0) return -2;
        pollfd pfd = {fd, POLLIN, 0};
        int r = poll(&pfd, 1, static_cast<int>(std::min<int64_t>(left, idleMs)));
        if (r < 0 && errno == EINTR) continue;
        if (r < 0) return -1;
        if (r == 0) return -2;
        ssize_t k = read(fd, p + got, n - got);
        if (k < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (k < 0) return -1;
        if (k == 0) break;
        got += static_cast<size_t>(k);
    }
    return static_cast<ssize_t>(got);
}

// The zygote must answer within this, or the broker gives up on itself (the VM is restarted by Android).
constexpr int kZygoteMs = 10000;

[[noreturn]] void broker_fail() {
    _exit(1);  // PID 1 ends: the VM stops, Android answers "unavailable" and starts it again
}

// How a worker ended.
enum class Ended { kClean, kDecodeFailed, kUnsupported, kInternal };

struct Worker {
    pid_t pid = -1;
    int pipe = -1;
    int64_t deadline = 0;
    // What a streaming worker wrote while the broker was still passing it the file: kept in a memory file, read
    // before the pipe.
    int bufFd = -1;
    uint64_t bufLen = 0;
    uint64_t bufAt = 0;
};

// Ends the current worker, at once with kill, else after it exits on its own (a grace period, then killed anyway).
Ended end_worker(Worker* w, bool kill) {
    if (w->pid < 0) return Ended::kInternal;
    ZygoteReply ended = {};
    ssize_t n = 0;
    if (!kill) n = read_full(gZygote, &ended, sizeof(ended), now_ms() + 2000, 2000);
    if (n != static_cast<ssize_t>(sizeof(ended))) {
        ::kill(w->pid, SIGKILL);
        n = read_full(gZygote, &ended, sizeof(ended), now_ms() + kZygoteMs, kZygoteMs);
        if (n != static_cast<ssize_t>(sizeof(ended))) broker_fail();
    }
    close(w->pipe);
    if (w->bufFd >= 0) close(w->bufFd);
    *w = Worker();
    if (ended.kind != 2) broker_fail();
    int status = ended.value;
    if (WIFEXITED(status) && WEXITSTATUS(status) == kExitOk) return Ended::kClean;
    if (WIFEXITED(status) && WEXITSTATUS(status) == kExitDecodeFailed) return Ended::kDecodeFailed;
    if (WIFEXITED(status) && WEXITSTATUS(status) == kExitUnsupported) return Ended::kUnsupported;
    return Ended::kInternal;  // a signal (seccomp, CPU limit, our kill), the lockdown, anything else
}

int32_t status_of(Ended e) {
    return e == Ended::kDecodeFailed ? kInvalid : e == Ended::kUnsupported ? kUnsupported : kInternal;
}

// A worker's output, the part kept while the file was streaming first, then the pipe. Like read_full.
ssize_t worker_read(Worker* w, void* data, size_t n, int64_t deadline, int idleMs) {
    uint8_t* p = static_cast<uint8_t*>(data);
    size_t got = 0;
    if (w->bufFd >= 0 && w->bufAt < w->bufLen) {
        size_t k = static_cast<size_t>(std::min<uint64_t>(n, w->bufLen - w->bufAt));
        if (pread(w->bufFd, p, k, static_cast<off_t>(w->bufAt)) != static_cast<ssize_t>(k)) return -1;
        w->bufAt += k;
        got = k;
    }
    if (got == n) return static_cast<ssize_t>(got);
    ssize_t r = read_full(w->pipe, p + got, n - got, deadline, idleMs);
    if (r < 0) return got > 0 ? static_cast<ssize_t>(got) : r;
    return static_cast<ssize_t>(got) + r;
}

uint8_t gStripe[kStripeBytes];
uint8_t gXfer[kStripeBytes];  // the file's bytes on their way from the link to a worker

// Reads n bytes of the request's file from the link and drops them: the stream stays in step when the file is
// refused before a worker takes it.
bool discard_input(int c, uint64_t n) {
    while (n > 0) {
        size_t k = static_cast<size_t>(std::min<uint64_t>(n, sizeof(gXfer)));
        if (read_full(c, gXfer, k, now_ms() + kHostReadMs, kHostReadMs) != static_cast<ssize_t>(k)) return false;
        n -= k;
    }
    return true;
}

// The request's file goes into a memory file the worker maps read-only. The broker reads it straight from the link
// into that file, so the broker's own memory never holds a caller's file. pre: its first bytes, read already.
// -1: no memory file, -2: the link broke.
int read_input(int c, const uint8_t* pre, size_t preLen, uint32_t len) {
    int fd = static_cast<int>(syscall(__NR_memfd_create, "decoder-input", MFD_CLOEXEC));
    if (fd < 0) return discard_input(c, len - preLen) ? -1 : -2;
    if (len == 0) return fd;
    void* p = MAP_FAILED;
    if (ftruncate(fd, len) == 0) p = mmap(nullptr, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    bool ok = p != MAP_FAILED;
    if (ok) {
        memcpy(p, pre, preLen);
        size_t rest = len - preLen;
        ok = read_full(c, static_cast<uint8_t*>(p) + preLen, rest, now_ms() + kHostReadMs, kHostReadMs) ==
             static_cast<ssize_t>(rest);
    }
    if (p != MAP_FAILED) munmap(p, len);
    if (!ok) {
        close(fd);
        return -2;
    }
    return fd;
}

// The most a streaming worker may write before the broker has passed it the whole file: a full-size thumbnail.
constexpr uint64_t kMaxEarlyOutput = 16 + static_cast<uint64_t>(kMaxPixels) * 4 + sizeof(Meta);

// Passes the rest of the request's file from the link to a streaming worker's input pipe, 64 KiB at a time. Android
// sends the whole file before it reads the answer, so whatever the worker writes meanwhile goes into a memory file
// (at most kMaxEarlyOutput) and is answered from there afterwards. A worker that ends early, stops reading or passes
// its deadline gets the rest of the file dropped. False when the link broke.
bool pump_input(int c, const uint8_t* pre, size_t preLen, uint64_t rest, int in, Worker* w) {
    const uint8_t* pending = pre;
    size_t pendingLen = preLen;
    bool workerGone = false, outputDone = false;
    fcntl(in, F_SETFL, O_NONBLOCK);
    for (;;) {
        if (pendingLen == 0) {
            if (rest == 0) break;
            size_t k = static_cast<size_t>(std::min<uint64_t>(rest, sizeof(gXfer)));
            if (read_full(c, gXfer, k, now_ms() + kHostReadMs, kHostReadMs) != static_cast<ssize_t>(k)) return false;
            rest -= k;
            pending = gXfer;
            pendingLen = k;
        }
        if (workerGone) {
            pendingLen = 0;
            continue;
        }
        int64_t left = w->deadline - now_ms();
        if (left <= 0) {
            ::kill(w->pid, SIGKILL);  // the deadline: end_worker reports it as internal
            workerGone = true;
            continue;
        }
        pollfd pfd[2] = {{in, POLLOUT, 0}, {outputDone ? -1 : w->pipe, POLLIN, 0}};
        int r = poll(pfd, 2, static_cast<int>(std::min<int64_t>(left, kIdleMs)));
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) {
            ::kill(w->pid, SIGKILL);  // stopped reading and writing alike
            workerGone = true;
            continue;
        }
        if (pfd[1].revents != 0) {
            ssize_t k = read(w->pipe, gStripe, sizeof(gStripe));
            if (k < 0 && (errno == EINTR || errno == EAGAIN)) continue;
            if (k <= 0) {
                outputDone = true;
            } else {
                if (w->bufFd < 0) {
                    w->bufFd = static_cast<int>(syscall(__NR_memfd_create, "decoder-early", MFD_CLOEXEC));
                }
                if (w->bufFd < 0 || w->bufLen + static_cast<uint64_t>(k) > kMaxEarlyOutput ||
                    pwrite(w->bufFd, gStripe, static_cast<size_t>(k), static_cast<off_t>(w->bufLen)) != k) {
                    ::kill(w->pid, SIGKILL);
                    workerGone = true;
                    continue;
                }
                w->bufLen += static_cast<uint64_t>(k);
            }
        }
        if (pfd[0].revents & (POLLERR | POLLHUP)) {
            workerGone = true;  // the worker closed its input: done with the file, or gone
            continue;
        }
        if (pfd[0].revents & POLLOUT) {
            ssize_t k = write(in, pending, pendingLen);
            if (k < 0 && (errno == EINTR || errno == EAGAIN)) continue;
            if (k < 0) {
                workerGone = true;
                continue;
            }
            pending += k;
            pendingLen -= static_cast<size_t>(k);
        }
    }
    wipe(gXfer, sizeof(gXfer));
    return true;
}

bool start_worker(const Request& rq, uint32_t format, int input, uint32_t len, bool streamed, Worker* w) {
    int fds[2];
    if (pipe2(fds, O_CLOEXEC) != 0) return false;
    ZygoteRequest zr = {rq, format, len, streamed ? 1u : 0u};
    int pass[2] = {input, fds[1]};
    char control[CMSG_SPACE(sizeof(pass))] = {};
    iovec iov = {&zr, sizeof(zr)};
    msghdr mh = {};
    mh.msg_iov = &iov;
    mh.msg_iovlen = 1;
    mh.msg_control = control;
    mh.msg_controllen = sizeof(control);
    cmsghdr* cm = CMSG_FIRSTHDR(&mh);
    cm->cmsg_level = SOL_SOCKET;
    cm->cmsg_type = SCM_RIGHTS;
    cm->cmsg_len = CMSG_LEN(sizeof(pass));
    memcpy(CMSG_DATA(cm), pass, sizeof(pass));
    bool sent = sendmsg(gZygote, &mh, MSG_NOSIGNAL) == static_cast<ssize_t>(sizeof(zr));
    close(fds[1]);
    if (!sent) broker_fail();
    ZygoteReply started = {};
    if (read_full(gZygote, &started, sizeof(started), now_ms() + kZygoteMs, kZygoteMs) !=
        static_cast<ssize_t>(sizeof(started))) {
        broker_fail();
    }
    if (started.kind != 1 || started.value <= 0) {
        close(fds[0]);
        return false;
    }
    w->pid = started.value;
    w->pipe = fds[0];
    w->deadline = now_ms() + kWorkerWallMs;
    return true;
}

bool send_reply(int c, int32_t status, uint32_t format, uint32_t w, uint32_t h, uint32_t extra, uint32_t len) {
    Reply r = {kReplyMagic, status, format, w, h, extra, len, 0};
    return write_all(c, &r, sizeof(r));
}

bool send_end(int c, int32_t status) {
    End e = {kEndMagic, status};
    return write_all(c, &e, sizeof(e));
}

// A failure before anything was sent: a reply without payload and its trailer.
bool send_failure(int c, int32_t status) {
    return send_reply(c, status, kFormatUnknown, 0, 0, 0, 0) && send_end(c, status);
}

bool premultiplied(const uint8_t* p, size_t n) {
    for (size_t i = 0; i + 3 < n; i += 4) {
        if (p[i] > p[i + 3] || p[i + 1] > p[i + 3] || p[i + 2] > p[i + 3]) return false;
    }
    return true;
}

// The worker's answer to the host. Returns false when the connection must end.
bool serve_worker(int c, const Request& rq, uint32_t format, bool hook, Worker* w) {
    if (rq.op == kOpProbe) {
        uint8_t msg[20];
        ssize_t n = worker_read(w, msg, sizeof(msg), w->deadline, kIdleMs);
        Ended e = end_worker(w, n != static_cast<ssize_t>(sizeof(msg)));
        uint32_t fmt = le32(msg + 4), pw = le32(msg + 8), ph = le32(msg + 12), anim = le32(msg + 16);
        if (e != Ended::kClean || n != static_cast<ssize_t>(sizeof(msg))) {
            return send_failure(c, e == Ended::kClean ? kInvalid : status_of(e));
        }
        if (memcmp(msg, "DPR1", 4) != 0 || fmt != format || pw == 0 || ph == 0 || pw > kMaxDimension ||
            ph > kMaxDimension || anim > 1 || (anim == 1 && !may_be_animated(format))) {
            return send_failure(c, kInvalid);
        }
        return send_reply(c, kOk, format, pw, ph, anim, 0) && send_end(c, kOk);
    }

    if (rq.op == kOpMetadata) {
        Meta m;
        ssize_t n = worker_read(w, &m, sizeof(m), w->deadline, kIdleMs);
        Ended e = end_worker(w, n != static_cast<ssize_t>(sizeof(m)));
        bool ok = e == Ended::kClean && n == static_cast<ssize_t>(sizeof(m)) && m.magic == kMetaMagic &&
                  m.version == 1 && m.format == format && m.width != 0 && m.height != 0 &&
                  m.width <= kMaxDimension && m.height <= kMaxDimension;
        bool sent = ok ? send_reply(c, kOk, format, m.width, m.height, 0, sizeof(m)) && write_all(c, &m, sizeof(m)) &&
                                 send_end(c, kOk)
                       : send_failure(c, e == Ended::kClean ? kInvalid : status_of(e));
        wipe(&m, sizeof(m));
        return sent;
    }

    // Thumbnail (and the test hooks, which answer as a 1x1 or 2x1 thumbnail): header, exact pixels, trailer.
    uint8_t hdr[16];
    ssize_t n = worker_read(w, hdr, sizeof(hdr), w->deadline, kIdleMs);
    uint32_t tw = le32(hdr + 4), th = le32(hdr + 8), rot = le32(hdr + 12);
    bool turned = rot == 90 || rot == 270;
    bool box = hook || (turned ? (tw <= rq.arg1 && th <= rq.arg0) : (tw <= rq.arg0 && th <= rq.arg1));
    if (n != static_cast<ssize_t>(sizeof(hdr))) {
        Ended e = end_worker(w, true);
        return send_failure(c, status_of(e));
    }
    if (memcmp(hdr, "DSR2", 4) != 0 || tw == 0 || th == 0 || static_cast<uint64_t>(tw) * th > kMaxPixels || !box ||
        (rot != 0 && rot != 180 && !turned)) {
        end_worker(w, true);
        return send_failure(c, kInvalid);
    }
    uint64_t left = static_cast<uint64_t>(tw) * th * 4;
    if (!send_reply(c, kOk, format, tw, th, rot, static_cast<uint32_t>(left))) {
        end_worker(w, true);
        return false;
    }
    int32_t verdict = kOk;
    while (left > 0) {
        size_t want = static_cast<size_t>(std::min<uint64_t>(sizeof(gStripe), left));
        ssize_t got = worker_read(w, gStripe, want, w->deadline, kIdleMs);
        // A worker that stops early, or sends a colour above alpha (only a compromised one does), ends here. The
        // promised length is kept with zeros and the trailer carries the verdict, so Android tells a bad file or a
        // failed worker from a broken link.
        if (got != static_cast<ssize_t>(want) || !premultiplied(gStripe, want)) {
            bool bad = got == static_cast<ssize_t>(want);
            Ended e = end_worker(w, true);
            verdict = bad || e == Ended::kDecodeFailed ? kInvalid : kInternal;
            wipe(gStripe, sizeof(gStripe));
            while (left > 0) {
                size_t k = static_cast<size_t>(std::min<uint64_t>(sizeof(gStripe), left));
                if (!write_all(c, gStripe, k)) return false;
                left -= k;
            }
            return send_end(c, verdict);
        }
        if (!write_all(c, gStripe, want)) {
            end_worker(w, true);
            return false;
        }
        left -= want;
    }
    // All pixels are here. The worker must now end, cleanly and with nothing more to say.
    uint8_t extra;
    ssize_t more = worker_read(w, &extra, 1, w->deadline, kIdleMs);
    Ended e = end_worker(w, more != 0);
    verdict = more != 0 ? kInvalid : e == Ended::kClean ? kOk : status_of(e);
    return send_end(c, verdict);
}

// One request. Returns false when the connection must end (the host's stream is broken).
bool serve_one(int c) {
    Request rq;
    if (read_full(c, &rq, sizeof(rq), now_ms() + kHostReadMs, kHostReadMs) != static_cast<ssize_t>(sizeof(rq))) {
        return false;
    }
    if (rq.magic != kRequestMagic || rq.inputLen > kMaxInputBytes) return false;
    // Only the first bytes, to pick the decoder. They are wiped when the request ends.
    uint8_t magic[kMagicBytes] = {};
    size_t got = std::min<size_t>(rq.inputLen, sizeof(magic));
    if (read_full(c, magic, got, now_ms() + kHostReadMs, kHostReadMs) != static_cast<ssize_t>(got)) return false;
    struct Wiper {
        uint8_t* p;
        ~Wiper() {
            wipe(p, kMagicBytes);
            wipe(gStripe, sizeof(gStripe));
            wipe(gXfer, sizeof(gXfer));
        }
    } wiper = {magic};
    uint64_t rest = rq.inputLen - got;
    uint32_t format = detect_format(magic, got, rq.inputLen);
#ifdef DECODER_TEST_HOOKS
    bool hook = rq.op == kOpHook;
#else
    bool hook = false;
#endif
    if (rq.op != kOpPing && rq.op != kOpProbe && rq.op != kOpThumbnail && rq.op != kOpMetadata && !hook) return false;
    // JPEG and PNG thumbnails and records stream: the file goes to the worker as it arrives and is never held whole.
    // Everything else is read into a memory file first, at most kMaxBufferedBytes.
    bool streamed = !hook && (format == kFormatJpeg || format == kFormatPng) &&
                    (rq.op == kOpThumbnail || rq.op == kOpMetadata);
    int32_t refuse = -1;
    if (rq.op == kOpPing) {
        refuse = kOk;
    } else if (!hook && format == kFormatUnknown) {
        refuse = kUnsupported;
    } else if (!streamed && rq.inputLen > kMaxBufferedBytes) {
        refuse = kInvalid;
    } else if (rq.op == kOpThumbnail &&
               (rq.arg0 == 0 || rq.arg1 == 0 || rq.arg0 > kMaxDimension || rq.arg1 > kMaxDimension)) {
        refuse = kInvalid;
    }
    if (refuse >= 0) {
        if (!discard_input(c, rest)) return false;
        if (refuse == kOk) return send_reply(c, kOk, 0, 0, 0, 0, 0) && send_end(c, kOk);
        return send_failure(c, refuse);
    }
    Worker w;
    if (streamed) {
        int in[2];
        if (pipe2(in, O_CLOEXEC) != 0) return discard_input(c, rest) && send_failure(c, kInternal);
        bool started = start_worker(rq, format, in[0], rq.inputLen, true, &w);
        close(in[0]);
        if (!started) {
            close(in[1]);
            return discard_input(c, rest) && send_failure(c, kInternal);
        }
        bool linkOk = pump_input(c, magic, got, rest, in[1], &w);
        close(in[1]);
        if (!linkOk) {
            end_worker(&w, true);
            return false;
        }
    } else {
        int input = read_input(c, magic, got, rq.inputLen);
        if (input == -2) return false;
        if (input < 0) return send_failure(c, kInternal);
        bool started = start_worker(rq, format, input, rq.inputLen, false, &w);
        close(input);
        if (!started) return send_failure(c, kInternal);
    }
    // Nothing of this request stays in the broker's memory either (the wiper, on the way out).
    return serve_worker(c, rq, format, hook, &w);
}

// The lockdown itself is tested before the broker serves anyone: a child locks down, says so, then makes a forbidden
// system call and must be killed for it. Without a working seccomp the broker refuses to listen at all.
bool lockdown_works() {
    int fds[2];
    if (pipe2(fds, O_CLOEXEC) != 0) return false;
    pid_t pid = fork();
    if (pid == 0) {
        close(fds[0]);
        if (lockdown(fds[1]) != 0) worker_exit(kExitLockdown);
        (void)!write(0, "S", 1);
        syscall(__NR_getppid);  // forbidden under strict mode: the kernel kills the process here
        worker_exit(kExitOk);
    }
    close(fds[1]);
    if (pid < 0) {
        close(fds[0]);
        return false;
    }
    char said = 0;
    ssize_t n = read_full(fds[0], &said, 1, now_ms() + kZygoteMs, kZygoteMs);
    close(fds[0]);
    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
    }
    return n == 1 && said == 'S' && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL;
}

void setup() {
#ifndef DECODER_HOST_TEST
    mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, nullptr);
#endif
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_DFL);
    // A worker runs under another user, but it must not be able to attach to the broker either way.
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
}

int listen_host(int argc, char** argv) {
#ifdef DECODER_HOST_TEST
    // Host test builds: a Unix socket instead of vsock, at the path given.
    if (argc < 2) return -1;
    int ls = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    sockaddr_un addr = {};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, argv[1], sizeof(addr.sun_path) - 1);
    unlink(argv[1]);
    if (ls < 0 || bind(ls, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 || listen(ls, 1) != 0) return -1;
    return ls;
#else
    (void)argc;
    (void)argv;
    int ls = socket(AF_VSOCK, SOCK_STREAM | SOCK_CLOEXEC, 0);
    sockaddr_vm addr = {};
    addr.svm_family = AF_VSOCK;
    addr.svm_port = kPort;
    addr.svm_cid = VMADDR_CID_ANY;
    if (ls < 0 || bind(ls, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 || listen(ls, 1) != 0) return -1;
    return ls;
#endif
}

#ifdef DECODER_HOST_TEST
// Host test builds only: "--bench W H FILE...". Each file is decoded into a W x H thumbnail by a forked worker under
// the real lockdown, strict seccomp included. Prints the wall time from fork to exit and the arena's peak, the most of
// it the decoders touched.
int bench(int argc, char** argv) {
    uint32_t bw = static_cast<uint32_t>(atoi(argv[2])), bh = static_cast<uint32_t>(atoi(argv[3]));
    for (int i = 4; i < argc; i++) {
        int fd = open(argv[i], O_RDONLY | O_CLOEXEC);
        struct stat st;
        if (fd < 0 || fstat(fd, &st) != 0) {
            printf("bench %s: cannot read\n", argv[i]);
            continue;
        }
        size_t size = static_cast<size_t>(st.st_size);
        void* map = mmap(nullptr, size, PROT_READ, MAP_PRIVATE, fd, 0);
        close(fd);
        if (map == MAP_FAILED) continue;
        const uint8_t* data = static_cast<const uint8_t*>(map);
        uint32_t format = detect_format(data, std::min(size, kMagicBytes), size);
        int fds[2];
        if (pipe2(fds, O_CLOEXEC) != 0) return 1;
        int64_t t0 = now_ms();
        pid_t pid = fork();
        if (pid == 0) {
            close(fds[0]);
            if (lockdown(fds[1]) != 0) worker_exit(kExitLockdown);
            Sink sink = {-1, static_cast<uint8_t*>(arena_alloc(kStripeBytes)), 0};
            uint32_t w = 0, h = 0;
            bool ok = decode_any(format, data, size, bw, bh, &sink, false, &w, &h);
            uint32_t msg[3] = {ok ? 1u : 0u, static_cast<uint32_t>(arena_peak() >> 10), gOutcome.unsupported};
            (void)!write(0, msg, sizeof(msg));
            worker_exit(0);
        }
        close(fds[1]);
        uint32_t msg[3] = {};
        ssize_t n = read_full(fds[0], msg, sizeof(msg), now_ms() + 60000, 60000);
        close(fds[0]);
        int status = 0;
        waitpid(pid, &status, 0);
        int64_t ms = now_ms() - t0;
        munmap(map, size);
        if (n != static_cast<ssize_t>(sizeof(msg))) {
            printf("bench %s format %u: worker died (status 0x%x) after %lld ms\n", argv[i], format, status,
                   static_cast<long long>(ms));
        } else {
            printf("bench %s format %u %ux%u: %s in %lld ms, arena peak %.1f MiB\n", argv[i], format, bw, bh,
                   msg[0] ? "ok" : msg[2] ? "unsupported" : "refused", static_cast<long long>(ms), msg[1] / 1024.0);
        }
        fflush(stdout);
    }
    return 0;
}
#endif

}  // namespace

int main(int argc, char** argv) {
    setup();
    void* arena = mmap(nullptr, kArenaBytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (arena == MAP_FAILED) return 1;
    arena_setup(static_cast<uint8_t*>(arena), kArenaBytes);
    warm_up();
#ifdef DECODER_HOST_TEST
    if (argc >= 4 && strcmp(argv[1], "--bench") == 0) return bench(argc, argv);
#endif
    // No seccomp, no service: Android sees a VM that never answers and fails closed.
    if (!lockdown_works()) return 1;
    if (!start_zygote()) return 1;
    int ls = listen_host(argc, argv);
    if (ls < 0) return 1;
    for (;;) {
        int c = accept4(ls, nullptr, nullptr, SOCK_CLOEXEC);
        if (c < 0) continue;
        // A host that stops reading ends the connection instead of blocking the broker.
        timeval tv = {60, 0};
        setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        while (serve_one(c)) {
        }
        close(c);
    }
}
