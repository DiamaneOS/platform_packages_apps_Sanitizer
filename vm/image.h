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

// What the worker's decoders share: the arena, the output sink, the scaler and the decoder entry points. Each
// decoder runs in the locked-down worker: memory only from the arena, no files, no threads, no system calls but read,
// write and exit.

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "proto.h"

namespace decoder {

// ---------------------------------------------------------------------------------------------------------------
// Memory (arena.cpp). In a worker every allocation, the libraries' malloc included (the link wraps malloc, calloc,
// realloc, free and the aligned forms), comes from one fixed arena with a real free list, so a decoder that frees
// and allocates again per tile or frame stays within it. In the broker (the warm-up) it is the C library's heap.
//
// The arena is mapped as large as the VM's memory (decoder_vm.cpp, arena_bytes_for), and each worker may grow into it
// only as far as the memory the VM has free when that worker starts, less a margin (worker_memory): so a worker is
// refused memory cleanly instead of being killed by the kernel. A worker starts with kArenaDefault (or less, when less
// is free) and a decoder that knows from the declared size that it needs more (a large single HEVC image, a large
// progressive JPEG) asks for it with arena_allow.

constexpr size_t kArenaDefault = 64u << 20;

void arena_setup(uint8_t* base, size_t size);
// Lets this worker use up to n bytes of the arena in all (never more than its memory). True when that much is allowed.
bool arena_allow(size_t n);
// True when another n bytes fit, asking for them when they do not fit the current allowance.
bool arena_room(size_t n);
size_t arena_limit();  // the whole arena, in a worker what it may grow to
// From now on malloc and friends use the arena, which starts empty, and this worker may grow to memory bytes of it.
void arena_enter_worker(size_t memory);
bool arena_in_worker();
void* arena_alloc(size_t n);
void* arena_calloc(size_t n, size_t k);
void* arena_realloc(void* p, size_t n);
void* arena_memalign(size_t align, size_t n);
void arena_free(void* p);
size_t arena_left();  // bytes not in use (a request may still fail on fragmentation)
size_t arena_peak();  // the most the arena was ever filled to (pages touched)

// ---------------------------------------------------------------------------------------------------------------
// Output: a stripe buffer flushed to the pipe. fd -1 discards (the warm-up and the measurements).

constexpr size_t kStripeBytes = 64u << 10;

struct Sink {
    int fd;
    uint8_t* buf;
    size_t used;
};

bool sink_flush(Sink* s);
bool sink_put(Sink* s, const uint8_t* p, size_t n);
// The worker's thumbnail header to the broker: "DSR2", width, height, gRotation.
bool sink_header(Sink* s, uint32_t w, uint32_t h);
extern uint32_t gRotation;
// The image is mirrored left to right before its turn (EXIF 2, 4, 5, 7, HEIF imir): scaler_push reverses each row.
extern bool gFlip;

// ---------------------------------------------------------------------------------------------------------------
// Scaling (decoder_vm.cpp): rows in, one at a time, straight RGBA unless premultiplied is set, premultiplied RGBA out,
// fitted exactly into the box asked for.

void fit_box(uint32_t iw, uint32_t ih, uint32_t maxW, uint32_t maxH, uint32_t* ow, uint32_t* oh);

struct Scaler {
    uint32_t iw, ih, ow, oh;
    uint32_t y;  // input rows taken
    uint32_t p;  // output rows sent
    uint64_t* hrow;
    uint64_t* acc;
    uint8_t* out;
    Sink* sink;
    bool premultiplied;  // rows come premultiplied already (every colour clamped to its alpha)
};

bool scaler_init(Scaler* s, uint32_t iw, uint32_t ih, uint32_t ow, uint32_t oh, Sink* sink);
void scaler_free(Scaler* s);
bool scaler_push(Scaler* s, uint8_t* row);
bool scaler_done(const Scaler* s);

// Fits the image into the box, sends the header and sets up the scaler: the common start of every decoder's pixels.
bool start_output(Scaler* s, uint32_t iw, uint32_t ih, uint32_t maxW, uint32_t maxH, Sink* sink);

// ---------------------------------------------------------------------------------------------------------------
// What a decoder reports besides success. Set by the decoder, read by the worker.

struct Outcome {
    bool animated;     // probe: more than one frame
    bool unsupported;  // a valid file of a kind the VM does not decode (answered UNSUPPORTED, not INVALID)
};
extern Outcome gOutcome;

// Every decoder: headerOnly stops after the header and reports the stored size in *w, *h (and gOutcome.animated).
// Otherwise it decodes the first frame into the sink, fitted into maxW x maxH. False for a broken or hostile file or
// a limit that was hit.
using DecodeFn = bool (*)(const uint8_t* data, size_t size, uint32_t maxW, uint32_t maxH, Sink* sink,
                          bool headerOnly, uint32_t* w, uint32_t* h);

bool decode_png(const uint8_t*, size_t, uint32_t, uint32_t, Sink*, bool, uint32_t*, uint32_t*);
bool decode_jpeg(const uint8_t*, size_t, uint32_t, uint32_t, Sink*, bool, uint32_t*, uint32_t*);
bool decode_gif(const uint8_t*, size_t, uint32_t, uint32_t, Sink*, bool, uint32_t*, uint32_t*);    // fmt_wuffs.cpp
bool decode_bmp(const uint8_t*, size_t, uint32_t, uint32_t, Sink*, bool, uint32_t*, uint32_t*);    // fmt_wuffs.cpp
bool decode_wbmp(const uint8_t*, size_t, uint32_t, uint32_t, Sink*, bool, uint32_t*, uint32_t*);   // fmt_wuffs.cpp
bool decode_webp(const uint8_t*, size_t, uint32_t, uint32_t, Sink*, bool, uint32_t*, uint32_t*);   // fmt_webp.cpp
bool decode_ico(const uint8_t*, size_t, uint32_t, uint32_t, Sink*, bool, uint32_t*, uint32_t*);    // fmt_ico.cpp
bool decode_heif(const uint8_t*, size_t, uint32_t, uint32_t, Sink*, bool, uint32_t*, uint32_t*);   // fmt_heif.cpp
bool decode_dng(const uint8_t*, size_t, uint32_t, uint32_t, Sink*, bool, uint32_t*, uint32_t*);    // fmt_dng.cpp

// Warm-ups that the broker runs before it forks: libraries that check the CPU through /proc or set up their tables
// once per process do it here, never in a worker.
bool warm_up_webp();  // false when a warm-up image did not decode
bool warm_up_heif();

}  // namespace decoder
