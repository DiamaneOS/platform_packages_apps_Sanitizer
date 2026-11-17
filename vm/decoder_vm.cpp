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
#include <fcntl.h>
#include <grp.h>
#include <linux/seccomp.h>
#include <linux/vm_sockets.h>
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
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <cmath>
#include <cstdint>

#include <jpeglib.h>
#include <png.h>

#include "meta.h"
#include "proto.h"

using namespace decoder;

namespace {

// A worker's whole heap. Under strict seccomp it cannot map more, so this is the most a worker can use besides its
// stack. It fits an interlaced PNG of kMaxPixels or the coefficients of a progressive JPEG of about 20 MP.
constexpr size_t kArenaBytes = 64u << 20;
constexpr size_t kStripeBytes = 64u << 10;

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
#endif

// ---------------------------------------------------------------------------------------------------------------
// Memory. In a worker: a bump allocator over a mapping the broker reserved and never touches, so each worker starts
// from fresh zero pages and gives everything back by exiting. In the broker (the warm-up decode): malloc.

uint8_t* gArena = nullptr;
size_t gArenaUsed = 0;
bool gInWorker = false;

void* arena_alloc(size_t n) {
    if (!gInWorker) return malloc(n);
    size_t need = (n + 15) & ~static_cast<size_t>(15);
    if (need < n || need > kArenaBytes - gArenaUsed) return nullptr;
    void* p = gArena + gArenaUsed;
    gArenaUsed += need;
    return p;
}

void arena_free(void* p) {
    if (!gInWorker) free(p);
}

size_t arena_left() {
    return gInWorker ? kArenaBytes - gArenaUsed : kArenaBytes;
}

}  // namespace

// libjpeg-turbo's memory back end, in place of its jmemnobs.c: everything comes from the arena and there is no
// backing store, so an image that needs more than the arena fails cleanly.
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
void jpeg_open_backing_store(j_common_ptr cinfo, void*, long) {
    (*cinfo->err->error_exit)(cinfo);
}
long jpeg_mem_init(j_common_ptr) {
    return 0;
}
void jpeg_mem_term(j_common_ptr) {}
}

namespace {

// ---------------------------------------------------------------------------------------------------------------
// Output: a stripe buffer flushed to the pipe. fd -1 discards (the warm-up).

struct Sink {
    int fd;
    uint8_t* buf;
    size_t used;
};

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

// The worker's thumbnail header to the broker: "DSR2", width, height, rotation.
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

struct Scaler {
    uint32_t iw, ih, ow, oh;
    uint32_t y;  // input rows taken
    uint32_t p;  // output rows sent
    uint64_t* hrow;
    uint64_t* acc;
    uint8_t* out;
    Sink* sink;
};

bool scaler_init(Scaler* s, uint32_t iw, uint32_t ih, uint32_t ow, uint32_t oh, Sink* sink) {
    *s = {iw, ih, ow, oh, 0, 0, nullptr, nullptr, nullptr, sink};
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
    premultiply(row, s->iw);
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

// ---------------------------------------------------------------------------------------------------------------
// PNG through libpng's row API. Every allocation goes through the arena, errors jump back without signal masks
// (_setjmp, _longjmp), since saving or restoring a mask is a system call.

struct PngInput {
    const uint8_t* data;
    size_t size;
    size_t at;
};

void png_read_input(png_structp png, png_bytep out, size_t n) {
    PngInput* in = static_cast<PngInput*>(png_get_io_ptr(png));
    if (n > in->size - in->at) png_error(png, "truncated");
    memcpy(out, in->data + in->at, n);
    in->at += n;
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
bool decode_png(const uint8_t* data, size_t size, uint32_t maxW, uint32_t maxH, Sink* sink, bool headerOnly,
                uint32_t* outW, uint32_t* outH) {
    png_structp png = png_create_read_struct_2(PNG_LIBPNG_VER_STRING, nullptr, png_fail, png_quiet, nullptr,
                                               png_arena_alloc, png_arena_free);
    if (png == nullptr) return false;
    png_infop info = png_create_info_struct(png);
    if (info == nullptr) {
        png_destroy_read_struct(&png, nullptr, nullptr);
        return false;
    }
    PngInput in = {data, size, 0};
    Scaler scaler = {};
    uint8_t* volatile pixels = nullptr;
    if (_setjmp(*png_set_longjmp_fn(png, _longjmp, sizeof(jmp_buf)))) {
        png_destroy_read_struct(&png, &info, nullptr);
        return false;
    }
    png_set_read_fn(png, &in, png_read_input);
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
    png_destroy_read_struct(&png, &info, nullptr);
    return done && sink_flush(sink);
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

bool decode_jpeg(const uint8_t* data, size_t size, uint32_t maxW, uint32_t maxH, Sink* sink, bool headerOnly,
                 uint32_t* outW, uint32_t* outH) {
    jpeg_decompress_struct cinfo;
    JpegError err;
    jpeg_progress_mgr progress = {};
    Scaler scaler = {};
    cinfo.err = jpeg_std_error(&err.mgr);
    err.mgr.error_exit = jpeg_fail;
    err.mgr.emit_message = jpeg_quiet;
    err.mgr.output_message = jpeg_quiet_output;
    if (_setjmp(err.jump)) {
        jpeg_destroy_decompress(&cinfo);
        return false;
    }
    jpeg_create_decompress(&cinfo);
    progress.progress_monitor = jpeg_progress;
    cinfo.progress = &progress;
    jpeg_mem_src(&cinfo, data, size);
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
    // Without a backing store, a progressive image whose coefficients do not fit the arena fails here.
    cinfo.mem->max_memory_to_use = static_cast<long>(arena_left() - std::min(arena_left(), size_t{1} << 20));
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

uint32_t detect_format(const uint8_t* b, size_t n) {
    if (n >= 8 && memcmp(b, "\x89PNG\r\n\x1a\n", 8) == 0) return kFormatPng;
    if (n >= 3 && b[0] == 0xff && b[1] == 0xd8 && b[2] == 0xff) return kFormatJpeg;
    return kFormatUnknown;
}

bool decode_any(uint32_t format, const uint8_t* data, size_t size, uint32_t maxW, uint32_t maxH, Sink* sink,
                bool headerOnly, uint32_t* w, uint32_t* h) {
    return format == kFormatPng ? decode_png(data, size, maxW, maxH, sink, headerOnly, w, h)
                                : decode_jpeg(data, size, maxW, maxH, sink, headerOnly, w, h);
}

// ---------------------------------------------------------------------------------------------------------------
// Warm-up. Both decoders check the CPU's features once on first use, which may read /proc. libjpeg-turbo keeps the
// result per thread, so the broker decodes two tiny images before it forks any worker. A locked-down worker would be
// killed by the check.

#include "warmup_images.h"

void warm_up() {
    Sink sink = {-1, static_cast<uint8_t*>(malloc(kStripeBytes)), 0};
    if (sink.buf == nullptr) return;
    uint32_t w, h;
    decode_png(kWarmupPng, sizeof(kWarmupPng), 5, 3, &sink, false, &w, &h);
    decode_jpeg(kWarmupJpeg, sizeof(kWarmupJpeg), 5, 3, &sink, false, &w, &h);
    free(sink.buf);
}

// ---------------------------------------------------------------------------------------------------------------
// The worker.

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
#endif

// The lockdown, in this order: rlimits (no new file descriptors, no new processes, no more address space, capped CPU
// time, no core or file writes), an unprivileged user, no new privileges, then seccomp strict mode. Everything before
// seccomp is a second layer only. Without seccomp the worker exits: production builds never decode without it.
[[noreturn]] void worker_main(const Request& rq, uint32_t format, const uint8_t* data, size_t size, int out) {
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
    if (vmBytes == 0) worker_exit(4);
    // Only the output pipe stays open, as fd 0. The broker's vsock connection must be out of reach.
    if (out != 0 && dup2(out, 0) != 0) worker_exit(4);
    if (syscall(__NR_close_range, 1u, ~0u, 0u) != 0) worker_exit(4);
    struct {
        int resource;
        rlim_t value;
    } limits[] = {
            {RLIMIT_CPU, kWorkerCpuSeconds},
            {RLIMIT_NOFILE, 1},  // fd 0 is taken, so every new descriptor fails
            {RLIMIT_NPROC, 0},
            {RLIMIT_AS, vmBytes + (16u << 20)},
            {RLIMIT_FSIZE, 0},
            {RLIMIT_CORE, 0},
    };
    for (const auto& l : limits) {
        rlimit r = {l.value, l.value};
        if (setrlimit(l.resource, &r) != 0) worker_exit(4);
    }
    if (setgroups(0, nullptr) != 0 || setresgid(kWorkerId, kWorkerId, kWorkerId) != 0 ||
        setresuid(kWorkerId, kWorkerId, kWorkerId) != 0) {
        worker_exit(4);
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) worker_exit(4);
    gInWorker = true;
    gArenaUsed = 0;
    int seccompError = 0;
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT, 0, 0, 0) != 0) {
        seccompError = errno;
#ifndef DECODER_TEST_HOOKS
        worker_exit(4);
#endif
    }

#ifdef DECODER_TEST_HOOKS
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
        worker_exit(5);
    }
#else
    (void)seccompError;
#endif

    Sink sink = {0, static_cast<uint8_t*>(arena_alloc(kStripeBytes)), 0};
    if (sink.buf == nullptr) worker_exit(3);
    if (rq.op == kOpProbe) {
        uint32_t w = 0, h = 0;
        if (!decode_any(format, data, size, 0, 0, &sink, true, &w, &h)) worker_exit(3);
        uint8_t msg[20] = {'D', 'P', 'R', '1'};
        put_le32(msg + 4, format);
        put_le32(msg + 8, w);
        put_le32(msg + 12, h);
        put_le32(msg + 16, format == kFormatPng && png_is_animated(data, size) ? 1 : 0);
        worker_exit(write_all(0, msg, sizeof(msg)) ? 0 : 3);
    }
    if (rq.op == kOpMetadata) {
        Meta* m = static_cast<Meta*>(arena_alloc(sizeof(Meta)));
        if (m == nullptr) worker_exit(3);
        memset(m, 0, sizeof(*m));
        m->magic = kMetaMagic;
        m->version = 1;
        m->orientation = -1;
        m->dateTakenMillis = -1;
        m->format = format;
        if (!decode_any(format, data, size, 0, 0, &sink, true, &m->width, &m->height)) worker_exit(3);
        read_metadata(data, size, format, m);
        worker_exit(write_all(0, m, sizeof(*m)) ? 0 : 3);
    }
    // Thumbnail: the rotation comes from the file's EXIF orientation, read first.
    Meta* m = static_cast<Meta*>(arena_alloc(sizeof(Meta)));
    if (m == nullptr) worker_exit(3);
    memset(m, 0, sizeof(*m));
    m->orientation = -1;
    read_metadata(data, size, format, m);
    gRotation = m->orientation > 0 ? static_cast<uint32_t>(m->orientation) : 0;
    // The box is for the image as shown. Turned by 90 or 270 degrees, the stored image fits it the other way round.
    bool turned = gRotation == 90 || gRotation == 270;
    uint32_t w, h;
    worker_exit(decode_any(format, data, size, turned ? rq.arg1 : rq.arg0, turned ? rq.arg0 : rq.arg1, &sink, false,
                           &w, &h) ? 0 : 3);
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

// The current worker. Ends it, at once with kill, else after it exits on its own (a short grace period, then killed
// anyway). Returns true for a clean exit.
struct Worker {
    pid_t pid = -1;
    int pipe = -1;
    int64_t deadline = 0;
};

bool end_worker(Worker* w, bool kill) {
    if (w->pid < 0) return false;
    int status = 0;
    pid_t r = 0;
    if (!kill) {
        for (int i = 0; i < 2000 && (r = waitpid(w->pid, &status, WNOHANG)) == 0; i++) usleep(1000);
    }
    if (r == 0) {
        ::kill(w->pid, SIGKILL);
        r = waitpid(w->pid, &status, 0);
    }
    close(w->pipe);
    *w = Worker();
    return r > 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

bool start_worker(const Request& rq, uint32_t format, const uint8_t* data, size_t size, Worker* w) {
    int fds[2];
    if (pipe2(fds, O_CLOEXEC) != 0) return false;
    pid_t pid = fork();
    if (pid == 0) {
        close(fds[0]);
        worker_main(rq, format, data, size, fds[1]);
    }
    close(fds[1]);
    if (pid < 0) {
        close(fds[0]);
        return false;
    }
    w->pid = pid;
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

uint8_t* gInput = nullptr;

// One request. Returns false when the connection must end (the host's stream is broken, or a worker failed after the
// reply header went out, so the only honest signal left is to close).
bool serve_one(int c) {
    Request rq;
    if (read_full(c, &rq, sizeof(rq), now_ms() + kHostReadMs, kHostReadMs) != static_cast<ssize_t>(sizeof(rq))) {
        return false;
    }
    if (rq.magic != kRequestMagic || rq.inputLen > kMaxInputBytes) return false;
    if (rq.inputLen > 0 &&
        read_full(c, gInput, rq.inputLen, now_ms() + kHostReadMs, kHostReadMs) != static_cast<ssize_t>(rq.inputLen)) {
        return false;
    }
    if (rq.op == kOpPing) return send_reply(c, kOk, 0, 0, 0, 0, 0) && send_end(c, kOk);
#ifdef DECODER_TEST_HOOKS
    bool hook = rq.op == kOpHook;
#else
    bool hook = false;
#endif
    if (rq.op != kOpProbe && rq.op != kOpThumbnail && rq.op != kOpMetadata && !hook) return false;
    uint32_t format = detect_format(gInput, rq.inputLen);
    if (!hook && format == kFormatUnknown) return send_failure(c, kUnsupported);
    if (rq.op == kOpThumbnail &&
        (rq.arg0 == 0 || rq.arg1 == 0 || rq.arg0 > kMaxDimension || rq.arg1 > kMaxDimension)) {
        return send_failure(c, kInvalid);
    }

    Worker w;
    if (!start_worker(rq, format, gInput, rq.inputLen, &w)) return send_failure(c, kInternal);

    if (rq.op == kOpProbe) {
        uint8_t msg[20];
        ssize_t n = read_full(w.pipe, msg, sizeof(msg), w.deadline, kIdleMs);
        bool clean = end_worker(&w, n != static_cast<ssize_t>(sizeof(msg)));
        uint32_t fmt = le32(msg + 4), pw = le32(msg + 8), ph = le32(msg + 12), anim = le32(msg + 16);
        if (n != static_cast<ssize_t>(sizeof(msg)) || !clean || memcmp(msg, "DPR1", 4) != 0 || fmt != format ||
            pw == 0 || ph == 0 || pw > kMaxDimension || ph > kMaxDimension || anim > 1) {
            return send_failure(c, kInvalid);
        }
        return send_reply(c, kOk, format, pw, ph, anim, 0) && send_end(c, kOk);
    }

    if (rq.op == kOpMetadata) {
        Meta m;
        ssize_t n = read_full(w.pipe, &m, sizeof(m), w.deadline, kIdleMs);
        bool clean = end_worker(&w, n != static_cast<ssize_t>(sizeof(m)));
        if (n != static_cast<ssize_t>(sizeof(m)) || !clean || m.magic != kMetaMagic || m.version != 1 ||
            m.format != format || m.width == 0 || m.height == 0 || m.width > kMaxDimension ||
            m.height > kMaxDimension) {
            return send_failure(c, kInvalid);
        }
        return send_reply(c, kOk, format, m.width, m.height, 0, sizeof(m)) && write_all(c, &m, sizeof(m)) &&
               send_end(c, kOk);
    }

    // Thumbnail (and the test hooks, which answer as a 1x1 thumbnail): header, exact pixels, trailer.
    uint8_t hdr[16];
    ssize_t n = read_full(w.pipe, hdr, sizeof(hdr), w.deadline, kIdleMs);
    uint32_t tw = le32(hdr + 4), th = le32(hdr + 8), rot = le32(hdr + 12);
    bool turned = rot == 90 || rot == 270;
    bool box = hook || (turned ? (tw <= rq.arg1 && th <= rq.arg0) : (tw <= rq.arg0 && th <= rq.arg1));
    if (n != static_cast<ssize_t>(sizeof(hdr)) || memcmp(hdr, "DSR2", 4) != 0 || tw == 0 || th == 0 ||
        static_cast<uint64_t>(tw) * th > kMaxPixels || !box || (rot != 0 && rot != 90 && rot != 180 && rot != 270)) {
        end_worker(&w, true);
        return send_failure(c, kInvalid);
    }
    uint64_t left = static_cast<uint64_t>(tw) * th * 4;
    if (!send_reply(c, kOk, format, tw, th, rot, static_cast<uint32_t>(left))) {
        end_worker(&w, true);
        return false;
    }
    static uint8_t buf[kStripeBytes];
    while (left > 0) {
        size_t want = static_cast<size_t>(std::min<uint64_t>(sizeof(buf), left));
        if (read_full(w.pipe, buf, want, w.deadline, kIdleMs) != static_cast<ssize_t>(want)) {
            // The worker failed or timed out after its header went out: the promised length is kept with zeros and
            // the trailer says INVALID, so Android tells a bad file from a broken link.
            end_worker(&w, true);
            memset(buf, 0, sizeof(buf));
            while (left > 0) {
                size_t k = static_cast<size_t>(std::min<uint64_t>(sizeof(buf), left));
                if (!write_all(c, buf, k)) return false;
                left -= k;
            }
            return send_end(c, kInvalid);
        }
        if (!write_all(c, buf, want)) {
            end_worker(&w, true);
            return false;
        }
        left -= want;
    }
    // All pixels are here. The worker must now end, cleanly and with nothing more to say.
    uint8_t extra;
    ssize_t more = read_full(w.pipe, &extra, 1, w.deadline, kIdleMs);
    bool clean = end_worker(&w, more != 0) && more == 0;
    return send_end(c, clean ? kOk : kInvalid) && clean;
}

void setup() {
    mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, nullptr);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_DFL);
    // A worker runs under another user, but it must not be able to attach to the broker either way.
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
}

}  // namespace

int main() {
    setup();
    void* arena = mmap(nullptr, kArenaBytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    void* input = mmap(nullptr, kMaxInputBytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
                       -1, 0);
    if (arena == MAP_FAILED || input == MAP_FAILED) return 1;
    gArena = static_cast<uint8_t*>(arena);
    gInput = static_cast<uint8_t*>(input);
    warm_up();
    int ls = socket(AF_VSOCK, SOCK_STREAM | SOCK_CLOEXEC, 0);
    sockaddr_vm addr = {};
    addr.svm_family = AF_VSOCK;
    addr.svm_port = kPort;
    addr.svm_cid = VMADDR_CID_ANY;
    if (ls < 0 || bind(ls, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 || listen(ls, 1) != 0) return 1;
    for (;;) {
        int c = accept4(ls, nullptr, nullptr, SOCK_CLOEXEC);
        if (c < 0) continue;
        // A host that stops reading ends the connection instead of blocking the broker.
        timeval tv = {60, 0};
        setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        // The input of each request is dropped once its worker is gone, so the VM holds no file between requests.
        while (serve_one(c)) madvise(gInput, kMaxInputBytes, MADV_DONTNEED);
        madvise(gInput, kMaxInputBytes, MADV_DONTNEED);
        close(c);
    }
}
