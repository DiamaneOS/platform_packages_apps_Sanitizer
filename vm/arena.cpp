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

// The worker's heap: a fixed arena the broker mapped once and never touches. Under strict seccomp a worker cannot
// map more, so this and its stack are all the memory it has. The libraries allocate with malloc, which the link
// wraps (--wrap=malloc and the rest, Android.bp), and C++ operator new comes here too.
//
// Blocks carry boundary tags (the previous block's size and their own), free blocks sit in size-class lists and
// merge with free neighbours, and a free block at the end goes back to the untouched rest of the arena. The worker is
// single-threaded and lives for one file, so there is no locking.

#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <algorithm>
#include <new>

#include "image.h"

namespace decoder {
namespace {

constexpr size_t kHdr = 16;       // header: previous block's size, this block's size and the in-use bit
constexpr size_t kMinBlock = 32;  // header plus the two free-list links
constexpr size_t kUsedBit = 1;
constexpr size_t kNone = ~static_cast<size_t>(0);

struct Block {
    size_t prev;  // size of the block before, 0 for the first
    size_t head;  // size of this block (header included, a multiple of 16) | kUsedBit
};

struct Links {
    Block* next;
    Block* prev;
};

uint8_t* gBase = nullptr;
size_t gLimit = 0;  // the mapping: a worker can never go beyond it
size_t gCap = 0;    // what this worker may use now (arena_allow raises it)
size_t gTop = 0;       // everything from here on was never handed out since the worker started
size_t gLast = kNone;  // offset of the block that ends at gTop
size_t gInUse = 0;
size_t gPeak = 0;
bool gWorker = false;

constexpr int kBins = 40;
Block* gBins[kBins];

size_t off(const Block* b) {
    return static_cast<size_t>(reinterpret_cast<const uint8_t*>(b) - gBase);
}
Block* at(size_t o) {
    return reinterpret_cast<Block*>(gBase + o);
}
size_t size_of(const Block* b) {
    return b->head & ~kUsedBit;
}
bool used(const Block* b) {
    return (b->head & kUsedBit) != 0;
}
Links* links(Block* b) {
    return reinterpret_cast<Links*>(reinterpret_cast<uint8_t*>(b) + kHdr);
}
void* payload(Block* b) {
    return reinterpret_cast<uint8_t*>(b) + kHdr;
}
Block* next_of(Block* b) {
    size_t o = off(b) + size_of(b);
    return o < gTop ? at(o) : nullptr;
}
Block* prev_of(Block* b) {
    return off(b) == 0 ? nullptr : at(off(b) - b->prev);
}

int bin_of(size_t size) {
    int b = 63 - __builtin_clzll(size) - 5;  // 32..63 in bin 0
    return b < kBins ? b : kBins - 1;
}

void unlink_free(Block* b) {
    Links* l = links(b);
    if (l->prev != nullptr) {
        links(l->prev)->next = l->next;
    } else {
        gBins[bin_of(size_of(b))] = l->next;
    }
    if (l->next != nullptr) links(l->next)->prev = l->prev;
}

void push_free(Block* b) {
    int i = bin_of(size_of(b));
    Links* l = links(b);
    l->prev = nullptr;
    l->next = gBins[i];
    if (l->next != nullptr) links(l->next)->prev = b;
    gBins[i] = b;
}

// Sets b's size and flag and tells the block after it.
void set_block(Block* b, size_t size, bool inUse) {
    b->head = size | (inUse ? kUsedBit : 0);
    Block* n = next_of(b);
    if (n != nullptr) n->prev = size;
}

// b is not in use (its bit is clear): merge it with free neighbours, give it back to the untouched end when it is
// last, else list it.
void release(Block* b) {
    size_t size = size_of(b);
    Block* n = next_of(b);
    if (n != nullptr && !used(n)) {
        unlink_free(n);
        if (off(n) == gLast) gLast = off(b);
        size += size_of(n);
        set_block(b, size, false);
    }
    Block* p = prev_of(b);
    if (p != nullptr && !used(p)) {
        unlink_free(p);
        if (off(b) == gLast) gLast = off(p);
        size += size_of(p);
        b = p;
        set_block(b, size, false);
    }
    if (off(b) == gLast) {
        gTop = off(b);
        gLast = off(b) == 0 ? kNone : off(b) - b->prev;
        return;
    }
    push_free(b);
}

// Cuts b (in use) down to need bytes when the rest makes a block of its own, and releases the rest.
void trim(Block* b, size_t need) {
    size_t size = size_of(b);
    if (size - need < kMinBlock) return;
    bool last = off(b) == gLast;
    b->head = need | kUsedBit;
    Block* rest = at(off(b) + need);
    rest->prev = need;
    rest->head = size - need;
    Block* n = next_of(rest);
    if (n != nullptr) n->prev = size - need;
    if (last) gLast = off(rest);
    gInUse -= size - need;
    release(rest);
}

bool round_size(size_t n, size_t* need) {
    if (n > gCap) return false;
    size_t s = (n + kHdr + 15) & ~static_cast<size_t>(15);
    *need = s < kMinBlock ? kMinBlock : s;
    return true;
}

void* take(size_t n) {
    size_t need;
    if (!round_size(n, &need)) return nullptr;
    for (int i = bin_of(need); i < kBins; i++) {
        for (Block* b = gBins[i]; b != nullptr; b = links(b)->next) {
            if (size_of(b) < need) continue;
            unlink_free(b);
            b->head |= kUsedBit;
            gInUse += size_of(b);
            trim(b, need);
            return payload(b);
        }
    }
    if (gCap - gTop < need) return nullptr;
    Block* b = at(gTop);
    b->prev = gLast == kNone ? 0 : size_of(at(gLast));
    b->head = need | kUsedBit;
    gLast = gTop;
    gTop += need;
    if (gTop > gPeak) gPeak = gTop;
    gInUse += need;
    return payload(b);
}

bool in_arena(const void* p) {
    const uint8_t* q = static_cast<const uint8_t*>(p);
    return gBase != nullptr && q >= gBase + kHdr && q < gBase + gLimit;
}

// A pointer the worker may free: inside the arena, at a block start that is in use. Anything else (a broker
// allocation from before the fork, a stray pointer) is ignored.
Block* owned(void* p) {
    if (!in_arena(p) || (reinterpret_cast<uintptr_t>(p) & 15) != 0) return nullptr;
    Block* b = reinterpret_cast<Block*>(static_cast<uint8_t*>(p) - kHdr);
    if (off(b) >= gTop || !used(b) || size_of(b) < kMinBlock || off(b) + size_of(b) > gTop) return nullptr;
    return b;
}

}  // namespace

void arena_setup(uint8_t* base, size_t size) {
    gBase = base;
    gLimit = size & ~static_cast<size_t>(15);
    gCap = std::min(kArenaDefault, gLimit);
}

bool arena_allow(size_t n) {
    n = (n + 15) & ~static_cast<size_t>(15);
    if (n > gCap) gCap = std::min(n, gLimit);
    return n <= gCap;
}

bool arena_room(size_t n) {
    if (!gWorker) return n <= kArenaDefault;
    if (n <= gCap - gInUse) return true;
    return n <= gLimit - gInUse && arena_allow(gInUse + n);
}

size_t arena_limit() {
    return gLimit;
}

void arena_enter_worker() {
    gCap = std::min(kArenaDefault, gLimit);
    gTop = 0;
    gLast = kNone;
    gInUse = 0;
    gPeak = 0;
    for (Block*& b : gBins) b = nullptr;
    gWorker = true;
}

bool arena_in_worker() {
    return gWorker;
}

size_t arena_left() {
    return gWorker ? gCap - gInUse : kArenaDefault;
}

size_t arena_peak() {
    return gPeak;
}

}  // namespace decoder

// The C library's allocator, for the broker. The wrapped names below are what every object in the program calls.
extern "C" {
void* __real_malloc(size_t n);
void* __real_calloc(size_t n, size_t k);
void* __real_realloc(void* p, size_t n);
void __real_free(void* p);
int __real_posix_memalign(void** out, size_t align, size_t n);
void* __real_memalign(size_t align, size_t n);
void* __real_aligned_alloc(size_t align, size_t n);
size_t __real_malloc_usable_size(const void* p);
}

namespace decoder {

void* arena_alloc(size_t n) {
    return gWorker ? take(n) : __real_malloc(n);
}

void* arena_calloc(size_t n, size_t k) {
    size_t total;
    if (__builtin_mul_overflow(n, k, &total)) return nullptr;
    if (!gWorker) return __real_calloc(n, k);
    void* p = take(total);
    if (p != nullptr) memset(p, 0, total);
    return p;
}

void arena_free(void* p) {
    if (p == nullptr) return;
    if (!gWorker) {
        if (!in_arena(p)) __real_free(p);
        return;
    }
    Block* b = owned(p);
    if (b == nullptr) return;
    gInUse -= size_of(b);
    b->head &= ~kUsedBit;
    release(b);
}

void* arena_realloc(void* p, size_t n) {
    if (!gWorker) return __real_realloc(p, n);
    if (p == nullptr) return take(n);
    Block* b = owned(p);
    if (b == nullptr) return nullptr;
    if (n == 0) {
        arena_free(p);
        return nullptr;
    }
    size_t need;
    if (!round_size(n, &need)) return nullptr;
    size_t size = size_of(b);
    if (size >= need) return p;
    Block* nx = next_of(b);
    if (nx != nullptr && !used(nx) && size + size_of(nx) >= need) {
        unlink_free(nx);
        if (off(nx) == gLast) gLast = off(b);
        gInUse += size_of(nx);
        set_block(b, size + size_of(nx), true);
        trim(b, need);
        return p;
    }
    if (off(b) == gLast && gCap - off(b) >= need) {
        gInUse += need - size;
        b->head = need | kUsedBit;
        gTop = off(b) + need;
        if (gTop > gPeak) gPeak = gTop;
        return p;
    }
    void* q = take(n);
    if (q == nullptr) return nullptr;
    memcpy(q, p, size - kHdr);
    arena_free(p);
    return q;
}

void* arena_memalign(size_t align, size_t n) {
    if (align == 0 || (align & (align - 1)) != 0) return nullptr;
    if (!gWorker) {
        void* p = nullptr;
        return __real_posix_memalign(&p, align < sizeof(void*) ? sizeof(void*) : align, n) == 0 ? p : nullptr;
    }
    if (align <= 16) return take(n);
    if (align > (1u << 20) || n > gCap) return nullptr;
    uint8_t* p = static_cast<uint8_t*>(take(n + align + kMinBlock));
    if (p == nullptr) return nullptr;
    uintptr_t a = (reinterpret_cast<uintptr_t>(p) + align - 1) & ~(static_cast<uintptr_t>(align) - 1);
    size_t lead = a - reinterpret_cast<uintptr_t>(p);
    if (lead != 0 && lead < kMinBlock) {
        a += align;
        lead += align;
    }
    Block* b = reinterpret_cast<Block*>(p - kHdr);
    if (lead != 0) {
        // The front becomes a free block of its own, the aligned rest stays in use.
        size_t size = size_of(b);
        bool last = off(b) == gLast;
        Block* nb = at(off(b) + lead);
        nb->prev = lead;
        nb->head = (size - lead) | kUsedBit;
        Block* n2 = next_of(nb);
        if (n2 != nullptr) n2->prev = size - lead;
        if (last) gLast = off(nb);
        b->head = lead;
        gInUse -= lead;
        release(b);
        b = nb;
    }
    size_t need;
    round_size(n, &need);
    trim(b, need);
    return payload(b);
}

size_t arena_usable(const void* p) {
    if (!gWorker) return in_arena(p) ? 0 : __real_malloc_usable_size(p);
    Block* b = owned(const_cast<void*>(p));
    return b == nullptr ? 0 : size_of(b) - kHdr;
}

// A failed operator new: in a worker, the file needed more memory than the limits give (a decode failure, INVALID).
[[noreturn]] void out_of_memory() {
    if (gWorker) syscall(__NR_exit, 3);
    abort();
}

}  // namespace decoder

using namespace decoder;

extern "C" {
void* __wrap_malloc(size_t n) {
    return arena_alloc(n);
}
void* __wrap_calloc(size_t n, size_t k) {
    return arena_calloc(n, k);
}
void* __wrap_realloc(void* p, size_t n) {
    return arena_realloc(p, n);
}
void __wrap_free(void* p) {
    arena_free(p);
}
int __wrap_posix_memalign(void** out, size_t align, size_t n) {
    if (align < sizeof(void*) || (align & (align - 1)) != 0) return 22;  // EINVAL
    void* p = arena_memalign(align, n);
    if (p == nullptr) return 12;  // ENOMEM
    *out = p;
    return 0;
}
void* __wrap_memalign(size_t align, size_t n) {
    return arena_memalign(align, n);
}
void* __wrap_aligned_alloc(size_t align, size_t n) {
    return arena_memalign(align, n);
}
size_t __wrap_malloc_usable_size(const void* p) {
    return arena_usable(p);
}
}

// C++ allocation goes the same way (on the build machine libc++ is a shared library, whose own operator new would
// call the C library directly).
void* operator new(size_t n) {
    void* p = arena_alloc(n == 0 ? 1 : n);
    if (p == nullptr) out_of_memory();
    return p;
}
void* operator new[](size_t n) {
    return operator new(n);
}
void* operator new(size_t n, const std::nothrow_t&) noexcept {
    return arena_alloc(n == 0 ? 1 : n);
}
void* operator new[](size_t n, const std::nothrow_t&) noexcept {
    return arena_alloc(n == 0 ? 1 : n);
}
void* operator new(size_t n, std::align_val_t a) {
    void* p = arena_memalign(static_cast<size_t>(a) < 16 ? 16 : static_cast<size_t>(a), n == 0 ? 1 : n);
    if (p == nullptr) out_of_memory();
    return p;
}
void* operator new[](size_t n, std::align_val_t a) {
    return operator new(n, a);
}
void operator delete(void* p) noexcept {
    arena_free(p);
}
void operator delete[](void* p) noexcept {
    arena_free(p);
}
void operator delete(void* p, size_t) noexcept {
    arena_free(p);
}
void operator delete[](void* p, size_t) noexcept {
    arena_free(p);
}
void operator delete(void* p, std::align_val_t) noexcept {
    arena_free(p);
}
void operator delete[](void* p, std::align_val_t) noexcept {
    arena_free(p);
}
void operator delete(void* p, size_t, std::align_val_t) noexcept {
    arena_free(p);
}
void operator delete[](void* p, size_t, std::align_val_t) noexcept {
    arena_free(p);
}
