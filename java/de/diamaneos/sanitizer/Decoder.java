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

package de.diamaneos.sanitizer;

import android.os.SystemClock;
import android.util.Log;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/**
 * The decode service's core: the queue, the cache, the VM and its restarts, and one memory budget for everything the
 * service holds for callers (their files while read and queued, decoded thumbnails until fetched). Every way to fail
 * ends in an answer the caller treats as fail closed: {@link #UNAVAILABLE} (ask again later) or a VM status. Nothing
 * here ever parses a file: the bytes go to the VM as they are.
 *
 * <p>Two clocks: a request's deadline bounds how long its caller waits (queue included). Once the VM works on it, the
 * call gets its own budget, longer than the VM's own worker limit, so a request that waited in the queue never cuts
 * the VM short. Only a VM that stays silent past that budget, or breaks the protocol, is restarted.
 */
final class Decoder {
    private static final String TAG = "DecoderService";

    /** Not a VM status: the VM could not answer in time, try again later. */
    static final int UNAVAILABLE = -1;

    // The VM ends a worker after 30 s of wall time and answers INVALID. Its answer then still has to cross the link.
    static final long CALL_BUDGET_MILLIS = 45000;
    // Restart backoff after a failed start or a broken link: 1 s doubling to 5 minutes, never giving up.
    static final long BACKOFF_MIN = 1000;
    static final long BACKOFF_MAX = 300000;
    // Everything held for callers at once: files being read or queued, thumbnails not yet fetched.
    static final long MAX_HELD_BYTES = 128L << 20;
    // A file that broke the link this many times is answered INVALID from then on.
    static final int STRIKES = 2;

    private final GuestVm mVm;
    private final Scheduler mScheduler = new Scheduler();
    private final ResultCache mCache = new ResultCache();
    private final AtomicLong mHeld = new AtomicLong();
    private final Map<String, Integer> mStrikes = new LinkedHashMap<String, Integer>(64, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Integer> eldest) {
            return size() > 256;
        }
    };
    private long mBackoff = BACKOFF_MIN;
    private long mNextStart;

    Decoder(GuestVm vm) {
        mVm = vm;
        Thread t = new Thread(this::loop, "decoder-vm");
        t.setDaemon(true);
        t.start();
    }

    GuestVm vm() {
        return mVm;
    }

    void clearCache() {
        mCache.clear();
    }

    /** Takes n bytes from the memory budget. False when that would pass it: the caller answers unavailable. */
    boolean reserve(long n) {
        for (;;) {
            long held = mHeld.get();
            if (n < 0 || held + n > MAX_HELD_BYTES) return false;
            if (mHeld.compareAndSet(held, held + n)) return true;
        }
    }

    void release(long n) {
        mHeld.addAndGet(-n);
    }

    long held() {
        return mHeld.get();
    }

    /** Starts the VM in the background, so the first request does not wait for it. */
    void warmUp() {
        mScheduler.offer(new Request(GuestLink.OP_PING, 0, 0, null, 0, 0, "", false,
                SystemClock.uptimeMillis() + CALL_BUDGET_MILLIS));
    }

    /** One request to the VM, with its answer once done. */
    static final class Request extends Scheduler.Job {
        final int op, a, b;
        final byte[] file;
        final int len;
        final long reserved; // budget held for this request, given back when it is done
        volatile int status = UNAVAILABLE;
        volatile GuestLink.Answer answer;

        Request(int op, int a, int b, byte[] file, int len, long reserved, String lane, boolean userWaiting,
                long deadline) {
            super(lane, userWaiting, deadline);
            this.op = op;
            this.a = a;
            this.b = b;
            this.file = file;
            this.len = len;
            this.reserved = reserved;
        }

        @Override
        void run() {
            // The work is done by Decoder.loop, which knows the VM.
        }
    }

    /**
     * Runs the request and returns it with its status: a VM status for a clean answer, or UNAVAILABLE. Blocks the
     * calling thread until done or until the request's deadline. The request's reserved budget is given back here or
     * by the worker, exactly once.
     */
    Request run(Request r) {
        String digest = null;
        Object key = null;
        if (r.op != GuestLink.OP_PING && r.op != GuestLink.OP_HOOK) {
            byte[] d = ResultCache.digest(r.file, r.len);
            digest = hex(d);
            key = ResultCache.key(d, r.op, r.a, r.b);
            GuestLink.Answer hit = mCache.get(key);
            if (hit != null) {
                release(r.reserved);
                r.answer = hit;
                r.status = hit.status;
                return r;
            }
        }
        if (!mScheduler.offer(r)) {
            release(r.reserved);
            return r;
        }
        try {
            if (!r.await(SystemClock::uptimeMillis)) return r; // UNAVAILABLE: the queue was too slow
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return r;
        }
        if (key != null && r.answer != null && r.status != UNAVAILABLE) {
            mCache.put(key, r.answer);
        } else if (digest != null && r.status == UNAVAILABLE && r.answer == BROKE_LINK) {
            strike(digest, key, r);
        }
        return r;
    }

    // Marks an answer the worker set when this request's file broke the link.
    private static final GuestLink.Answer BROKE_LINK = new GuestLink.Answer();

    private void strike(String digest, Object key, Request r) {
        int n;
        synchronized (mStrikes) {
            n = mStrikes.getOrDefault(digest, 0) + 1;
            mStrikes.put(digest, n);
        }
        if (n >= STRIKES) {
            // Twice now: not bad luck but the file. Answered INVALID and remembered, so it cannot keep the VM
            // restarting.
            GuestLink.Answer a = new GuestLink.Answer();
            a.status = GuestLink.INVALID;
            mCache.put(key, a);
            r.answer = a;
            r.status = GuestLink.INVALID;
        } else {
            r.answer = null;
        }
    }

    private void loop() {
        for (;;) {
            Scheduler.Job job;
            try {
                job = mScheduler.take();
            } catch (InterruptedException e) {
                return;
            }
            Request r = (Request) job;
            try {
                if (r.deadline > SystemClock.uptimeMillis()) handle(r);
            } catch (RuntimeException e) {
                Log.e(TAG, "request failed", e);
                r.status = UNAVAILABLE;
            } finally {
                release(r.reserved);
                r.finish();
            }
        }
    }

    private void handle(Request r) {
        long now = SystemClock.uptimeMillis();
        if (now < mNextStart && !mVm.isRunning()) return; // backing off: UNAVAILABLE
        long budget = now + CALL_BUDGET_MILLIS;
        GuestLink link;
        try {
            link = mVm.link(budget);
        } catch (IOException e) {
            Log.w(TAG, "VM not available: " + e.getMessage());
            mVm.stop();
            backOff();
            return;
        }
        try {
            GuestLink.Answer a;
            switch (r.op) {
                case GuestLink.OP_PING: a = link.ping(budget); break;
                case GuestLink.OP_PROBE: a = link.probe(r.file, r.len, budget); break;
                case GuestLink.OP_THUMBNAIL: a = link.thumbnail(r.file, r.len, r.a, r.b, budget); break;
                case GuestLink.OP_METADATA: a = link.metadata(r.file, r.len, budget); break;
                case GuestLink.OP_HOOK: a = link.hook(r.a, budget); break;
                default: throw new IllegalArgumentException("op");
            }
            r.answer = a;
            r.status = a.status == GuestLink.INTERNAL ? UNAVAILABLE : a.status;
            mBackoff = BACKOFF_MIN;
        } catch (IOException e) {
            // Silent past the budget, or a reply that broke the protocol: the link and the VM are not trusted any
            // more. The request is unavailable, never cached as a verdict on the file, unless the same file does it
            // again (see strike).
            Log.w(TAG, "VM link broken: " + e.getMessage());
            r.status = UNAVAILABLE;
            r.answer = r.op == GuestLink.OP_PING || r.op == GuestLink.OP_HOOK ? null : BROKE_LINK;
            mVm.stop();
            backOff();
        }
    }

    private void backOff() {
        mNextStart = SystemClock.uptimeMillis() + mBackoff;
        mBackoff = Math.min(mBackoff * 2, BACKOFF_MAX);
    }

    private static String hex(byte[] b) {
        StringBuilder s = new StringBuilder(b.length * 2);
        for (byte x : b) s.append(Character.forDigit((x >> 4) & 15, 16)).append(Character.forDigit(x & 15, 16));
        return s.toString();
    }
}
