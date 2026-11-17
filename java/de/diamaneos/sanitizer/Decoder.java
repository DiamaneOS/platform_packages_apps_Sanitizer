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
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The decode service's core: the queue, the cache, the VM and its restarts, and one memory budget for everything the
 * service holds for callers (their files while read and queued, pixels while received, decoded thumbnails until
 * fetched). Every way to fail ends in an answer the caller treats as fail closed: {@link #UNAVAILABLE} (ask again
 * later) or a VM status. Nothing here ever parses a file: the bytes go to the VM as they are.
 *
 * <p>Fairness comes before memory: each lane (the package that supplied the bytes) may have at most
 * {@link #MAX_ACTIVE_PER_LANE} requests in the service and at most a quarter of the budget, checked before anything
 * is allocated, so one app cannot take the budget from the others.
 *
 * <p>Two clocks: a request's deadline bounds how long its caller waits (queue included). Once the VM works on it, the
 * call gets its own budget, longer than the VM's own worker limit, so a request that waited in the queue never cuts
 * the VM short. Only a VM that stays silent past that budget, or breaks the protocol, is restarted. A worker that died
 * (seccomp's kill, the CPU limit, the wall deadline) costs no restart: it answers "unavailable", and the same file
 * doing it twice is answered INVALID from then on.
 */
final class Decoder implements GuestLink.Budget {
    private static final String TAG = "DecoderService";

    /** Not a VM status: the VM could not answer in time, try again later. */
    static final int UNAVAILABLE = -1;

    // The VM ends a worker after 30 s of wall time. Its answer then still has to cross the link.
    static final long CALL_BUDGET_MILLIS = 45000;
    // Restart backoff after a failed start or a broken link: 1 s doubling to 5 minutes, never giving up.
    static final long BACKOFF_MIN = 1000;
    static final long BACKOFF_MAX = 300000;
    // Everything held for callers at once, and the share one lane may hold.
    static final long MAX_HELD_BYTES = 128L << 20;
    static final long MAX_LANE_BYTES = MAX_HELD_BYTES / 4;
    // Requests one lane may have in the service at once (reading, queued or with the VM).
    static final int MAX_ACTIVE_PER_LANE = 32;
    // Reads that never ended (a stalled pipe or FUSE file): per lane, and in all.
    static final int MAX_STUCK_PER_LANE = 2;
    static final int MAX_STUCK = 16;
    // A file that made a worker die this many times is answered INVALID from then on.
    static final int STRIKES = 2;

    private final GuestVm mVm;
    private final Scheduler mScheduler = new Scheduler();
    private final ResultCache mCache = new ResultCache();
    private final Object mLock = new Object();
    private long mHeld;
    private final Map<String, Long> mLaneHeld = new HashMap<>();
    private final Map<String, Integer> mActive = new HashMap<>();
    private final Map<String, Integer> mStuck = new HashMap<>();
    private int mStuckTotal;
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

    // --- Admission and memory ---------------------------------------------------------------------------------------

    /** Lets a request of this lane into the service, or refuses it (its lane is busy or stuck). Pair with leave. */
    boolean admit(String lane) {
        synchronized (mLock) {
            int active = mActive.getOrDefault(lane, 0);
            if (active >= MAX_ACTIVE_PER_LANE || mStuck.getOrDefault(lane, 0) >= MAX_STUCK_PER_LANE
                    || mStuckTotal >= MAX_STUCK) {
                return false;
            }
            mActive.put(lane, active + 1);
            return true;
        }
    }

    void leave(String lane) {
        synchronized (mLock) {
            int active = mActive.getOrDefault(lane, 0) - 1;
            if (active <= 0) mActive.remove(lane); else mActive.put(lane, active);
        }
    }

    /** A read of this lane did not end in time. Counted until it does end (if ever). */
    void stuck(String lane, int delta) {
        synchronized (mLock) {
            int n = mStuck.getOrDefault(lane, 0) + delta;
            if (n <= 0) mStuck.remove(lane); else mStuck.put(lane, n);
            mStuckTotal += delta;
        }
    }

    @Override
    public boolean reserve(String lane, long n) {
        synchronized (mLock) {
            long laneHeld = mLaneHeld.getOrDefault(lane, 0L);
            if (n < 0 || mHeld + n > MAX_HELD_BYTES || laneHeld + n > MAX_LANE_BYTES) return false;
            mHeld += n;
            mLaneHeld.put(lane, laneHeld + n);
            return true;
        }
    }

    @Override
    public void release(String lane, long n) {
        if (n == 0) return;
        synchronized (mLock) {
            mHeld -= n;
            long laneHeld = mLaneHeld.getOrDefault(lane, 0L) - n;
            if (laneHeld <= 0) mLaneHeld.remove(lane); else mLaneHeld.put(lane, laneHeld);
        }
    }

    long held() {
        synchronized (mLock) {
            return mHeld;
        }
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
        final long reserved; // budget held for the file, given back when the request is done
        // A large regular file streamed to the VM instead of file, and its SHA-256 read beforehand. Closed when the
        // request is done.
        FdChannel.FileSource source;
        byte[] digest;
        volatile byte[] sentDigest;
        volatile int status = UNAVAILABLE;
        volatile GuestLink.Answer answer;
        volatile boolean died; // a worker died, or the link broke, on this file

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
     * by the worker thread, exactly once.
     */
    Request run(Request r) {
        String digest = null;
        Object key = null;
        if (r.op != GuestLink.OP_PING && r.op != GuestLink.OP_HOOK) {
            byte[] d = r.source != null ? r.digest : ResultCache.digest(r.file, r.len);
            digest = hex(d);
            key = ResultCache.key(d, r.op, r.a, r.b);
            GuestLink.Answer hit = mCache.get(key);
            if (hit != null) {
                release(r.lane, r.reserved);
                r.answer = hit;
                r.status = hit.status;
                return r;
            }
        }
        if (!mScheduler.offer(r)) {
            release(r.lane, r.reserved);
            closeSource(r);
            return r;
        }
        try {
            if (!r.await(SystemClock::uptimeMillis)) return r; // UNAVAILABLE: the queue was too slow
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return r;
        }
        // A streamed file is cached only when what was sent is what was hashed before: a file that changed in
        // between gets its answer, but never under the old content's key.
        boolean sameFile = r.source == null || java.util.Arrays.equals(r.digest, r.sentDigest);
        if (key != null && r.answer != null && r.status != UNAVAILABLE && sameFile) {
            mCache.put(key, r.answer);
        } else if (digest != null && r.died) {
            strike(digest, key, r);
        }
        return r;
    }

    private void strike(String digest, Object key, Request r) {
        int n;
        synchronized (mStrikes) {
            n = mStrikes.getOrDefault(digest, 0) + 1;
            mStrikes.put(digest, n);
        }
        if (n >= STRIKES) {
            // Twice now: not bad luck but the file. Answered INVALID and remembered.
            GuestLink.Answer a = new GuestLink.Answer();
            a.status = GuestLink.INVALID;
            mCache.put(key, a);
            r.answer = a;
            r.status = GuestLink.INVALID;
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
            } catch (Throwable t) {
                // Out of memory included: this request is unavailable, the service stays up.
                Log.e(TAG, "request failed", t);
                r.status = UNAVAILABLE;
                r.answer = null;
            } finally {
                if (r.source != null) r.sentDigest = r.source.sentDigest();
                closeSource(r);
                release(r.lane, r.reserved);
                GuestLink.Answer a = r.answer;
                if (a != null && a.reserved > 0) {
                    release(r.lane, a.reserved);
                    a.reserved = 0;
                }
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
        link.setBudget(this, r.lane);
        try {
            GuestLink.Answer a;
            switch (r.op) {
                case GuestLink.OP_PING: a = link.ping(budget); break;
                case GuestLink.OP_PROBE: a = link.probe(r.file, r.len, budget); break;
                case GuestLink.OP_THUMBNAIL:
                    a = r.source != null ? link.call(r.op, r.a, r.b, r.source, budget)
                                         : link.thumbnail(r.file, r.len, r.a, r.b, budget);
                    break;
                case GuestLink.OP_METADATA:
                    a = r.source != null ? link.call(r.op, 0, 0, r.source, budget) : link.metadata(r.file, r.len, budget);
                    break;
                case GuestLink.OP_HOOK: a = link.hook(r.a, budget); break;
                default: throw new IllegalArgumentException("op");
            }
            mBackoff = BACKOFF_MIN;
            if (a.status == GuestLink.INTERNAL) {
                // A worker died, or the service had no memory for the pixels: no verdict on the file, not cached.
                r.status = UNAVAILABLE;
                r.died = true;
                return;
            }
            r.answer = a;
            r.status = a.status;
        } catch (IOException e) {
            // Silent past the budget, or a reply that broke the protocol: the link and the VM are not trusted any
            // more. The request is unavailable, never cached as a verdict on the file, unless the same file does it
            // again. A worker cannot cause this: the broker checks everything a worker sends.
            Log.w(TAG, "VM link broken: " + e.getMessage());
            r.status = UNAVAILABLE;
            r.died = r.op != GuestLink.OP_PING && r.op != GuestLink.OP_HOOK;
            mVm.stop();
            backOff();
        }
    }

    private static void closeSource(Request r) {
        if (r.source == null) return;
        try {
            r.source.close();
        } catch (IOException ignored) {
            // closed already
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
