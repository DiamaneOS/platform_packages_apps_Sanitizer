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

// The file sanitizer's payload, running inside a protected VM that stays up between requests.
//
// A broker serves Android over vsock. For each file it forks a fresh worker. Before the worker parses a single byte
// it closes every file descriptor but its output pipe, caps its CPU time and enters seccomp strict mode, where only
// read, write and exit are left. It decodes row by row from a fixed memory arena and streams premultiplied RGBA to
// the broker, which checks the sizes and passes the rows on. A decoder exploit gets a process that can write pixels
// to one pipe and nothing else, and that process ends with the file.

#include <aidl/de/diamaneos/sanitizer/BnSanitizer.h>
#include <android/log.h>
#include <vm_payload.h>

#include <errno.h>
#include <fcntl.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

#include <jpeglib.h>
#include <png.h>

using aidl::de::diamaneos::sanitizer::BnSanitizer;
using ndk::ScopedAStatus;

namespace {

constexpr const char* kTag = "DiamaneOSSanitizer";
constexpr uint32_t kMaxSide = BnSanitizer::MAX_SIDE;
constexpr uint64_t kMaxPixels = BnSanitizer::MAX_PIXELS;

// A worker's whole heap. Under strict seccomp it cannot map more, so this is the most a worker can use besides its
// stack. It fits an interlaced PNG of MAX_PIXELS or the coefficients of a progressive JPEG of about 20 MP.
constexpr size_t kArenaBytes = 64u << 20;
constexpr size_t kStripeBytes = 64u << 10;

// Deadlines. The worker's CPU time is capped by the kernel, its wall time by the broker.
constexpr int kWorkerCpuSeconds = 20;
constexpr int64_t kWorkerWallMs = 30000;
constexpr int kIdleMs = 15000;

#ifdef SANITIZER_TEST_HOOKS
// Test builds only: maxSide values that make the worker break its lockdown on purpose.
constexpr int32_t kHookOpen = -1;
constexpr int32_t kHookMmap = -2;
constexpr int32_t kHookSpin = -3;
constexpr int32_t kHookLockdown = -4;
constexpr int32_t kHookFork = -5;
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

bool sink_flush(Sink* s) {
    size_t off = 0;
    while (s->fd >= 0 && off < s->used) {
        ssize_t n = write(s->fd, s->buf + off, s->used - off);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        off += static_cast<size_t>(n);
    }
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

// "DSR1", width, height, sent at once so the broker can check them before any pixels.
bool sink_header(Sink* s, uint32_t w, uint32_t h) {
    uint8_t hdr[12] = {'D', 'S', 'R', '1'};
    for (int i = 0; i < 4; i++) {
        hdr[4 + i] = static_cast<uint8_t>(w >> (8 * i));
        hdr[8 + i] = static_cast<uint8_t>(h >> (8 * i));
    }
    return sink_put(s, hdr, sizeof(hdr)) && sink_flush(s);
}

// ---------------------------------------------------------------------------------------------------------------
// Scaling: rows come in one at a time, straight RGBA. They are premultiplied and, for a factor above 1, averaged
// over f × f boxes (partial boxes at the right and bottom edges), so a large image never needs to be held whole.

uint32_t div_up(uint32_t a, uint32_t b) {
    return (a + b - 1) / b;
}

// The smallest factor that keeps the result within maxSide (0: no side limit) and MAX_PIXELS.
uint32_t box_factor(uint32_t w, uint32_t h, uint32_t maxSide) {
    uint32_t f = 1;
    if (maxSide > 0) f = std::max(1u, div_up(std::max(w, h), maxSide));
    while (static_cast<uint64_t>(div_up(w, f)) * div_up(h, f) > kMaxPixels) f++;
    return f;
}

struct Scaler {
    uint32_t iw, ih, f, ow, oh;
    uint32_t rowsIn, boxRows;
    uint64_t* acc;
    uint8_t* out;
    Sink* sink;
};

bool scaler_init(Scaler* s, uint32_t iw, uint32_t ih, uint32_t f, Sink* sink) {
    *s = {iw, ih, f, div_up(iw, f), div_up(ih, f), 0, 0, nullptr, nullptr, sink};
    if (f == 1) return true;
    s->acc = static_cast<uint64_t*>(arena_alloc(static_cast<size_t>(s->ow) * 4 * sizeof(uint64_t)));
    s->out = static_cast<uint8_t*>(arena_alloc(static_cast<size_t>(s->ow) * 4));
    if (s->acc == nullptr || s->out == nullptr) return false;
    memset(s->acc, 0, static_cast<size_t>(s->ow) * 4 * sizeof(uint64_t));
    return true;
}

void scaler_free(Scaler* s) {
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

bool scaler_push(Scaler* s, uint8_t* row) {
    premultiply(row, s->iw);
    s->rowsIn++;
    if (s->f == 1) return sink_put(s->sink, row, static_cast<size_t>(s->iw) * 4);
    for (uint32_t x = 0; x < s->iw; x++) {
        uint64_t* a = s->acc + static_cast<size_t>(x / s->f) * 4;
        const uint8_t* p = row + static_cast<size_t>(x) * 4;
        a[0] += p[0];
        a[1] += p[1];
        a[2] += p[2];
        a[3] += p[3];
    }
    s->boxRows++;
    if (s->boxRows < s->f && s->rowsIn < s->ih) return true;
    for (uint32_t o = 0; o < s->ow; o++) {
        uint64_t cols = std::min(s->f, s->iw - o * s->f);
        uint64_t n = cols * s->boxRows;
        for (int c = 0; c < 4; c++) {
            uint64_t* a = s->acc + static_cast<size_t>(o) * 4 + c;
            s->out[static_cast<size_t>(o) * 4 + c] = static_cast<uint8_t>((*a + n / 2) / n);
            *a = 0;
        }
    }
    s->boxRows = 0;
    return sink_put(s->sink, s->out, static_cast<size_t>(s->ow) * 4);
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

bool decode_png(const uint8_t* data, size_t size, uint32_t maxSide, Sink* sink) {
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
    png_set_user_limits(png, kMaxSide, kMaxSide);
    png_set_chunk_malloc_max(png, 4u << 20);
    png_set_chunk_cache_max(png, 128);
    png_set_keep_unknown_chunks(png, PNG_HANDLE_CHUNK_NEVER, nullptr, 0);
    png_read_info(png, info);
    uint32_t w = png_get_image_width(png, info);
    uint32_t h = png_get_image_height(png, info);
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
    if (w == 0 || h == 0 || w > kMaxSide || h > kMaxSide || png_get_rowbytes(png, info) != static_cast<size_t>(w) * 4) {
        png_error(png, "format");
    }
    if (!scaler_init(&scaler, w, h, box_factor(w, h, maxSide), sink) || !sink_header(sink, scaler.ow, scaler.oh)) {
        png_error(png, "output");
    }
    size_t stride = static_cast<size_t>(w) * 4;
    if (passes == 1) {
        // One row at a time.
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
    png_free(png, pixels);
    scaler_free(&scaler);
    png_destroy_read_struct(&png, &info, nullptr);
    return sink_flush(sink);
}

// ---------------------------------------------------------------------------------------------------------------
// JPEG through libjpeg-turbo, scaled by 1/2, 1/4 or 1/8 in the decoder where that helps, then by the box scaler.

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

bool decode_jpeg(const uint8_t* data, size_t size, uint32_t maxSide, Sink* sink) {
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
    if (jpeg_read_header(&cinfo, TRUE) != JPEG_HEADER_OK || cinfo.image_width > kMaxSide ||
        cinfo.image_height > kMaxSide) {
        jpeg_destroy_decompress(&cinfo);
        return false;
    }
    cinfo.out_color_space = JCS_EXT_RGBA;
    cinfo.scale_num = 1;
    cinfo.scale_denom = 1;
    jpeg_calc_output_dimensions(&cinfo);
    // The decoder's own scaling first: as far as it goes without dropping below the size asked for.
    while (cinfo.scale_denom < 8) {
        uint32_t w = div_up(cinfo.image_width, cinfo.scale_denom * 2);
        uint32_t h = div_up(cinfo.image_height, cinfo.scale_denom * 2);
        bool tooBig = static_cast<uint64_t>(cinfo.output_width) * cinfo.output_height > kMaxPixels;
        bool roomForSide = maxSide > 0 && std::max(w, h) >= maxSide;
        if (!tooBig && !roomForSide) break;
        cinfo.scale_denom *= 2;
        jpeg_calc_output_dimensions(&cinfo);
    }
    uint32_t f = box_factor(cinfo.output_width, cinfo.output_height, maxSide);
    // Without a backing store, a progressive image whose coefficients do not fit the arena fails here.
    cinfo.mem->max_memory_to_use = static_cast<long>(arena_left() - std::min(arena_left(), size_t{1} << 20));
    jpeg_start_decompress(&cinfo);
    if (!scaler_init(&scaler, cinfo.output_width, cinfo.output_height, f, sink) ||
        !sink_header(sink, scaler.ow, scaler.oh)) {
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
    scaler_free(&scaler);
    jpeg_destroy_decompress(&cinfo);
    return sink_flush(sink);
}

bool is_png(const uint8_t* b, size_t n) {
    return n >= 8 && memcmp(b, "\x89PNG\r\n\x1a\n", 8) == 0;
}

bool is_jpeg(const uint8_t* b, size_t n) {
    return n >= 3 && b[0] == 0xff && b[1] == 0xd8 && b[2] == 0xff;
}

// ---------------------------------------------------------------------------------------------------------------
// Warm-up. Both decoders check the CPU's features once, through /proc, on first use. libjpeg-turbo keeps that
// result per thread, so the thread that forks a worker decodes two tiny images first. A locked-down worker would be
// killed by the check.

#include "warmup_images.h"

thread_local bool tWarm = false;

void warm_up() {
    if (tWarm) return;
    Sink sink = {-1, static_cast<uint8_t*>(malloc(kStripeBytes)), 0};
    if (sink.buf == nullptr) return;
    decode_png(kWarmupPng, sizeof(kWarmupPng), 0, &sink);
    decode_jpeg(kWarmupJpeg, sizeof(kWarmupJpeg), 0, &sink);
    free(sink.buf);
    tWarm = true;
}

// ---------------------------------------------------------------------------------------------------------------
// The worker.

[[noreturn]] void worker_exit(int code) {
    syscall(__NR_exit, code);
    __builtin_unreachable();
}

#ifdef SANITIZER_TEST_HOOKS
// Test builds: a hook's outcome as a 1x1 image (three values and alpha 255), so a hook the lockdown did not stop
// shows up in the results instead of looking like a failed decode.
[[noreturn]] void hook_report(uint8_t a, uint8_t b, uint8_t c) {
    uint8_t px[4] = {a, b, c, 255};
    Sink sink = {0, static_cast<uint8_t*>(arena_alloc(kStripeBytes)), 0};
    worker_exit(sink_header(&sink, 1, 1) && sink_put(&sink, px, 4) && sink_flush(&sink) ? 0 : 3);
}
#endif

// The worker's lockdown, in this order: rlimits that need no seccomp (no new file descriptors, no new processes, no
// more address space, capped CPU time, no core or file writes), no new privileges, then seccomp strict mode. The
// rlimits are a second layer: they leave the full system call interface open. Seccomp is required, a worker without
// it exits. Test builds go on without it, to measure the rest on a guest kernel that lacks it.
[[noreturn]] void worker_main(const uint8_t* data, size_t size, int32_t maxSide, int out) {
    // The kernel kills this process first when the VM runs short of memory.
    int adj = open("/proc/self/oom_score_adj", O_WRONLY | O_CLOEXEC);
    if (adj >= 0) {
        (void)!write(adj, "1000", 4);
        close(adj);
    }
    // The current address space (the arena included), for the address space limit.
    uint64_t vmBytes = 0;
    int statm = open("/proc/self/statm", O_RDONLY | O_CLOEXEC);
    if (statm >= 0) {
        char buf[64] = {};
        if (read(statm, buf, sizeof(buf) - 1) > 0) vmBytes = strtoull(buf, nullptr, 10) * getpagesize();
        close(statm);
    }
    if (vmBytes == 0) worker_exit(4);
    // Only the output pipe stays open, as fd 0. The broker's vsock connection to Android must be out of reach.
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
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) worker_exit(4);
    gInWorker = true;
    gArenaUsed = 0;
    int seccompError = 0;
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT, 0, 0, 0) != 0) {
        seccompError = errno;
#ifndef SANITIZER_TEST_HOOKS
        worker_exit(4);
#endif
    }

#ifdef SANITIZER_TEST_HOOKS
    if (maxSide == kHookOpen) {
        long r = syscall(__NR_openat, AT_FDCWD, "/proc/self/status", O_RDONLY);
        hook_report(r < 0, r < 0 ? errno : 0, 0);
    }
    if (maxSide == kHookMmap) {
        long r = syscall(__NR_mmap, 0, 64u << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        hook_report(r == -1, r == -1 ? errno : 0, 0);
    }
    if (maxSide == kHookSpin) {
        for (;;) __asm__ volatile("" ::: "memory");
    }
    if (maxSide == kHookLockdown) hook_report(seccompError == 0, seccompError, 1);
    if (maxSide == kHookFork) {
        long r = syscall(__NR_clone, SIGCHLD, 0, 0, 0, 0);
        if (r == 0) worker_exit(0);
        hook_report(r < 0, r < 0 ? errno : 0, 0);
    }
    if (maxSide < 0) worker_exit(5);
#else
    (void)seccompError;
#endif

    Sink sink = {0, static_cast<uint8_t*>(arena_alloc(kStripeBytes)), 0};
    bool ok = is_png(data, size) ? decode_png(data, size, static_cast<uint32_t>(maxSide), &sink)
                                 : decode_jpeg(data, size, static_cast<uint32_t>(maxSide), &sink);
    worker_exit(ok ? 0 : 3);
}

// ---------------------------------------------------------------------------------------------------------------
// The broker.

int64_t now_ms() {
    timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<int64_t>(ts.tv_sec) * 1000 + ts.tv_nsec / 1000000;
}

// Reads n bytes unless the worker ends, stays silent for kIdleMs or passes its deadline. Returns the bytes read, or
// -1 for a read error, -2 for a timeout.
ssize_t read_full(int fd, uint8_t* p, size_t n, int64_t deadline) {
    size_t got = 0;
    while (got < n) {
        int64_t left = deadline - now_ms();
        if (left <= 0) return -2;
        pollfd pfd = {fd, POLLIN, 0};
        int r = poll(&pfd, 1, static_cast<int>(std::min<int64_t>(left, kIdleMs)));
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

ScopedAStatus fail(int code, const std::string& why) {
    __android_log_print(ANDROID_LOG_WARN, kTag, "%s", why.c_str());
    return ScopedAStatus::fromServiceSpecificErrorWithMessage(code, why.c_str());
}

uint32_t le32(const uint8_t* b) {
    return b[0] | b[1] << 8 | b[2] << 16 | static_cast<uint32_t>(b[3]) << 24;
}

// One request at a time: a single worker, so VM memory only has to fit one arena. Further calls wait on the lock.
class Sanitizer : public BnSanitizer {
public:
    ScopedAStatus begin(int32_t size) override {
        std::lock_guard<std::mutex> lock(mLock);
        endWorker(false);
        std::vector<uint8_t>().swap(mInput);
        if (size <= 0 || size > MAX_INPUT_BYTES) return fail(1, "size");
        mInput.reserve(static_cast<size_t>(size));
        mExpectedInput = static_cast<size_t>(size);
        return ScopedAStatus::ok();
    }

    ScopedAStatus addInput(const std::vector<uint8_t>& piece) override {
        std::lock_guard<std::mutex> lock(mLock);
        endWorker(false);
        if (piece.size() > static_cast<size_t>(CHUNK) || mInput.size() + piece.size() > mExpectedInput) {
            std::vector<uint8_t>().swap(mInput);
            return fail(1, "size");
        }
        mInput.insert(mInput.end(), piece.begin(), piece.end());
        return ScopedAStatus::ok();
    }

    ScopedAStatus decode(int32_t maxSide, std::vector<uint8_t>* header) override {
        std::lock_guard<std::mutex> lock(mLock);
        endWorker(false);
        std::vector<uint8_t> file;
        file.swap(mInput);
        mExpectedInput = 0;
#ifdef SANITIZER_TEST_HOOKS
        bool hook = maxSide < 0;
#else
        bool hook = false;
#endif
        if (file.empty()) return fail(1, "no input");
        if (!is_png(file.data(), file.size()) && !is_jpeg(file.data(), file.size())) return fail(2, "format");
        if ((maxSide < 0 && !hook) || maxSide > MAX_SIDE) return fail(1, "maxSide");
        warm_up();
        int fds[2];
        if (pipe2(fds, O_CLOEXEC) != 0) return fail(4, "pipe");
        pid_t pid = fork();
        if (pid == 0) {
            close(fds[0]);
            worker_main(file.data(), file.size(), maxSide, fds[1]);
        }
        close(fds[1]);
        if (pid < 0) {
            close(fds[0]);
            return fail(4, "fork");
        }
        mWorker = pid;
        mPipe = fds[0];
        mDeadline = now_ms() + kWorkerWallMs;
        std::vector<uint8_t>().swap(file);  // the worker has its own copy

        uint8_t h[12];
        ssize_t n = read_full(mPipe, h, sizeof(h), mDeadline);
        if (n != static_cast<ssize_t>(sizeof(h))) {
            std::string why = endWorker(n < 0);
            return fail(3, std::string("no header: ") + (n == -2 ? "timeout, " : "") + why);
        }
        uint32_t w = le32(h + 4), ht = le32(h + 8);
        if (memcmp(h, "DSR1", 4) != 0 || w == 0 || ht == 0 || w > kMaxSide || ht > kMaxSide ||
            static_cast<uint64_t>(w) * ht > kMaxPixels ||
            (maxSide > 0 && (w > static_cast<uint32_t>(maxSide) || ht > static_cast<uint32_t>(maxSide)))) {
            endWorker(true);
            return fail(3, "bad header");
        }
        mLeft = static_cast<uint64_t>(w) * ht * 4;
        header->assign(h, h + sizeof(h));
        return ScopedAStatus::ok();
    }

    ScopedAStatus readPixels(std::vector<uint8_t>* out) override {
        std::lock_guard<std::mutex> lock(mLock);
        out->clear();
        if (mWorker < 0) return fail(1, "no decode running");
        if (mLeft == 0) {
            // All pixels are here. The worker must now end, cleanly and with nothing more to say.
            uint8_t extra;
            ssize_t n = read_full(mPipe, &extra, 1, mDeadline);
            std::string why = endWorker(n != 0);
            if (n != 0) return fail(3, n > 0 ? "worker sent too much" : "worker did not end: " + why);
            if (!why.empty()) return fail(3, "worker failed: " + why);
            return ScopedAStatus::ok();
        }
        size_t want = static_cast<size_t>(std::min<uint64_t>(CHUNK, mLeft));
        out->resize(want);
        ssize_t n = read_full(mPipe, out->data(), want, mDeadline);
        if (n != static_cast<ssize_t>(want)) {
            out->clear();
            std::string why = endWorker(true);
            return fail(3, std::string("pixels cut short: ") + (n == -2 ? "timeout, " : "") + why);
        }
        mLeft -= want;
        return ScopedAStatus::ok();
    }

private:
    // Ends the current worker, at once with kill, else after it exits on its own (a short grace period, then
    // killed anyway). Returns how it ended, empty for a clean exit.
    std::string endWorker(bool kill) {
        if (mWorker < 0) return "";
        int status = 0;
        pid_t r = 0;
        if (!kill) {
            for (int i = 0; i < 2000 && (r = waitpid(mWorker, &status, WNOHANG)) == 0; i++) usleep(1000);
        }
        if (r == 0) {
            ::kill(mWorker, SIGKILL);
            r = waitpid(mWorker, &status, 0);
        }
        close(mPipe);
        mPipe = -1;
        mWorker = -1;
        mLeft = 0;
        if (r < 0) return "lost";
        if (WIFEXITED(status)) return WEXITSTATUS(status) == 0 ? "" : "exit " + std::to_string(WEXITSTATUS(status));
        if (WIFSIGNALED(status)) return "signal " + std::to_string(WTERMSIG(status));
        return "unknown";
    }

    std::mutex mLock;
    std::vector<uint8_t> mInput;
    size_t mExpectedInput = 0;
    pid_t mWorker = -1;
    int mPipe = -1;
    uint64_t mLeft = 0;
    int64_t mDeadline = 0;
};

}  // namespace

extern "C" int AVmPayload_main() {
    // Workers are reaped by the broker, which needs their exit status. A worker runs as the same user as the broker:
    // the broker is not dumpable, so a worker cannot attach to it or read or write its memory.
    signal(SIGCHLD, SIG_DFL);
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) return 1;
    void* arena = mmap(nullptr, kArenaBytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
                       -1, 0);
    if (arena == MAP_FAILED) return 1;
    gArena = static_cast<uint8_t*>(arena);
    auto service = ndk::SharedRefBase::make<Sanitizer>();
    AVmPayload_runVsockRpcServer(
            service->asBinder().get(), Sanitizer::PORT,
            [](void*) { AVmPayload_notifyPayloadReady(); }, nullptr);
}
