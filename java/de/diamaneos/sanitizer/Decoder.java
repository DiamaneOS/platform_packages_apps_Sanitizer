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
 * {@link #MAX_ACTIVE_PER_LANE} requests in the service and a share of the budget ({@link #MAX_LANE_BYTES}, and never
 * more than half of what the other lanes leave), checked before anything is allocated, so one app cannot take the
 * budget from the others. A request holds its input or its answer, never both: the input's share goes back when the
 * VM's reply begins (no second attempt follows a reply), before the pixels are reserved.
 *
 * <p>Two clocks: a request's deadline bounds how long its caller waits (queue included). Once the VM works on it, the
 * call gets its own budget, longer than the VM's own worker limit, so a request that waited in the queue never cuts
 * the VM short. Only a VM that stays silent past that budget, or breaks the protocol, is restarted. A worker that died
 * (seccomp's kill, a crash, the CPU limit) costs no restart: it answers "unavailable", and the same file doing it
 * twice is answered INVALID from then on. A worker stopped for a reason outside the file (the VM's memory, a starved
 * CPU: BUSY) is never counted against the file.
 */
final class Decoder implements GuestLink.Budget {
    private static final String TAG = "DecoderService";
    private static final String TAG_TIMING = "DecoderTiming";
    // A line per request (lane, queue wait, VM time, status): set on debuggable builds by the application.
    static volatile boolean sTimingLog;

    /** Not a VM status: the VM could not answer in time, try again later. */
    static final int UNAVAILABLE = -1;

    // Starting the VM and connecting: its own deadline.
    static final long LINK_BUDGET_MILLIS = 30000;
    // The call, once the link is up: longer than the VM's own worst case for an honest request. A worker runs at most
    // 30 s of wall time, and the broker starts one more worker after a BUSY only when the first ended within 5 s and
    // waits at most 6 s for memory first (41 s), then the answer crosses the link.
    static final long CALL_BUDGET_MILLIS = 60000;
    // Restart backoff after a failed start or a broken link: 1 s doubling to 5 minutes, never giving up.
    static final long BACKOFF_MIN = 1000;
    static final long BACKOFF_MAX = 300000;
    // Everything held for callers at once. A lane may hold at most MAX_LANE_BYTES, enough for the largest buffered
    // input or the largest answer (8 MP), which a request holds one after the other (see the class comment), and the
    // growth of a buffer read from a pipe (FdChannel.readInput). And it may hold at most half of what the other lanes
    // leave: then however many lanes are busy, the next one always finds room, at least for small files.
    static final long MAX_HELD_BYTES = 128L << 20;
    static final long MAX_LANE_BYTES = GuestLink.MAX_BUFFERED_BYTES + GuestLink.MAX_BUFFERED_BYTES / 4 + (1L << 20);
    // Requests one lane may have in the service at once (reading, queued or with the VM).
    static final int MAX_ACTIVE_PER_LANE = 32;
    // Reads that never ended (a stalled pipe or FUSE file): per lane, and in all.
    static final int MAX_STUCK_PER_LANE = 2;
    static final int MAX_STUCK = 16;
    // A file that made a worker die this many times is answered INVALID from then on.
    static final int STRIKES = 2;

    /** The VM as the decoder needs it (GuestVm, a fake one in the host checks). */
    interface Vm {
        /** Counts the VM's starts: a request that sees it change knows another request stopped the VM. */
        int generation();

        /**
         * A working link to the big or the small lane, starting the VM when needed. Throws when it does not come up
         * within the deadline.
         */
        GuestLink link(boolean small, long deadline) throws IOException;

        void stop();

        boolean isRunning();

        /** Whether the last link() of that lane handed back a connection made earlier. */
        boolean lastLinkReused(boolean small);

        /** Drops the lane's connection but keeps the VM. */
        void dropLink(boolean small);

        /** Whether the VM has the small lane. */
        boolean lanes();

        /** The vCPUs the VM was started with: a count, or how they were chosen. */
        String cpus();

        /** Why the last start failed, or "". */
        String lastError();

        /** Debuggable builds only: a test holds the VM down (stopped, no start) for now. */
        boolean heldDown();
    }

    /** A regular file streamed to the VM in pieces: what was sent is hashed as it goes. */
    interface StreamedSource extends GuestLink.Source, java.io.Closeable {
        /** SHA-256 of every byte sent, or null unless the whole file was sent. */
        byte[] sentDigest();
    }

    private final Vm mVm;
    private final Scheduler.Clock mClock;
    // Two lanes into the VM, each with its own queue and thread, so small files never wait behind a large decode:
    // a file of at most GuestLink.SMALL_INPUT_BYTES goes to the small lane first, which sends it on to the big lane
    // when the VM finds it too large there (BIG_LANE). Urgent requests go first within each queue.
    private final Scheduler mScheduler = new Scheduler();
    private final Scheduler mSmall = new Scheduler();
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
    private final Object mStartLock = new Object();
    // Per lane ([0] big, [1] small): held while the lane's thread talks to the VM, and when it last heard from it.
    private final java.util.concurrent.locks.ReentrantLock[] mLaneLock = {
        new java.util.concurrent.locks.ReentrantLock(), new java.util.concurrent.locks.ReentrantLock()};
    private final long[] mLastHeard = new long[2];
    private long mBackoff = BACKOFF_MIN; // guarded by mStartLock, like mNextStart
    private long mNextStart;

    Decoder(Vm vm) {
        this(vm, SystemClock::uptimeMillis);
    }

    /** With a clock of its own: the host checks drive backoff and deadlines with a fake one. */
    Decoder(Vm vm, Scheduler.Clock clock) {
        mVm = vm;
        mClock = clock;
        Thread t = new Thread(() -> loop(mScheduler, false), "decoder-vm");
        t.setDaemon(true);
        t.start();
        if (vm.lanes()) {
            Thread small = new Thread(() -> loop(mSmall, true), "decoder-vm-small");
            small.setDaemon(true);
            small.start();
        }
    }

    Vm vm() {
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
            long others = mHeld - laneHeld;
            if (n < 0 || mHeld + n > MAX_HELD_BYTES || laneHeld + n > MAX_LANE_BYTES
                    || (laneHeld + n) * 2 > MAX_HELD_BYTES - others) {
                return false;
            }
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
                mClock.now() + CALL_BUDGET_MILLIS));
    }

    /** One request to the VM, with its answer once done. */
    static final class Request extends Scheduler.Job {
        final int op, a, b;
        volatile byte[] file; // dropped with its budget once the VM's big lane replies
        int user; // the calling Android user: answers are cached per user (ResultCache)
        long queuedAt; // when it was queued, for the timing log
        Object cacheKey; // the result cache's key and the file's digest, set when the request is not a ping
        String digestHex;
        volatile boolean bigLane; // the small lane sent it on: it goes to the big lane
        final int len;
        private long mInput; // budget held for the file, given back once the reply begins or the request ends
        // A large regular file streamed to the VM instead of file, and its SHA-256 read beforehand. Closed when the
        // request is done.
        StreamedSource source;
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
            this.mInput = reserved;
        }

        /** The budget held for the input, taken once: the caller gives it back. */
        synchronized long takeInput() {
            long n = mInput;
            mInput = 0;
            return n;
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
            key = ResultCache.key(d, r.op, r.a, r.b, r.user);
            r.cacheKey = key;
            r.digestHex = digest;
            GuestLink.Answer hit = mCache.get(key);
            if (hit != null) {
                release(r.lane, r.takeInput());
                closeSource(r);
                r.answer = hit;
                r.status = hit.status;
                return r;
            }
        }
        r.queuedAt = mClock.now();
        // Animations always take the big lane (the small lane answers them BIG_LANE).
        boolean small = mVm.lanes() && r.op != GuestLink.OP_PING && r.op != GuestLink.OP_HOOK
                && r.op != GuestLink.OP_FRAMES && r.source == null && r.len <= GuestLink.SMALL_INPUT_BYTES;
        if (!(small ? mSmall : mScheduler).offer(r)) {
            release(r.lane, r.takeInput());
            closeSource(r);
            return r;
        }
        boolean done = false;
        try {
            done = r.await(mClock);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        if (done) return r;
        // Given up: the caller gets UNAVAILABLE and nothing it could read half written. The worker thread may still
        // finish the request, and its answer is cached then (settle).
        return new Request(r.op, r.a, r.b, null, r.len, 0, r.lane, r.userWaiting, r.deadline);
    }

    // When the VM is done with a request, whether its caller still waits or not: a late answer is cached, so the next
    // request for the file finds it instead of doing the work again. A streamed file is cached only when what was sent
    // is what was hashed before: a file that changed in between gets its answer, never under the old content's key.
    private void settle(Request r) {
        if (r.cacheKey == null) return;
        boolean sameFile = r.source == null || java.util.Arrays.equals(r.digest, r.sentDigest);
        if (r.answer != null && r.status != UNAVAILABLE && sameFile) {
            mCache.put(r.cacheKey, r.answer);
        } else if (r.died && sameFile) {
            strike(r.digestHex, r.cacheKey, r);
        }
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

    private void loop(Scheduler queue, boolean small) {
        for (;;) {
            Scheduler.Job job;
            try {
                job = queue.take();
            } catch (InterruptedException e) {
                return;
            }
            Request r = (Request) job;
            long started = mClock.now();
            try {
                if (r.deadline > started) handle(r, small);
            } catch (Throwable t) {
                // Out of memory included: this request is unavailable, the service stays up.
                Log.e(TAG, "request failed", t);
                r.status = UNAVAILABLE;
                r.answer = null;
                r.bigLane = false;
            } finally {
                if (sTimingLog) {
                    Log.i(TAG_TIMING, (small ? "small" : "big") + " caller " + r.lane + " op " + r.op + " urgent "
                            + r.userWaiting + " bytes " + r.len + " wait " + (started - r.queuedAt) + " ms vm "
                            + (mClock.now() - started) + " ms status " + r.status + (r.bigLane ? " to big lane" : ""));
                }
                boolean onward = false;
                if (r.bigLane) {
                    // The small lane found it too large: on to the big lane, input and all, still waited on.
                    r.bigLane = false;
                    r.queuedAt = mClock.now();
                    onward = mScheduler.offer(r);
                    if (!onward) r.status = UNAVAILABLE;
                }
                if (!onward) {
                    if (r.source != null) r.sentDigest = r.source.sentDigest();
                    settle(r);
                    closeSource(r);
                    releaseInput(r);
                    GuestLink.Answer a = r.answer;
                    if (a != null && a.reserved > 0) {
                        release(r.lane, a.reserved);
                        a.reserved = 0;
                    }
                    r.finish();
                }
            }
        }
    }

    /** The request's input is no longer needed: its budget goes back and the bytes may be collected. */
    private void releaseInput(Request r) {
        release(r.lane, r.takeInput());
        r.file = null;
    }

    private void handle(Request r, boolean small) {
        mLaneLock[small ? 1 : 0].lock();
        try {
            handleLocked(r, small);
        } finally {
            mLaneLock[small ? 1 : 0].unlock();
        }
    }

    /**
     * Whether the VM still answers on the other lane: then a deadline missed on this lane means a slow VM, not a
     * broken one. An idle other lane is pinged on its own connection, a busy one counts when it heard from the VM in
     * the last 10 s.
     */
    private boolean otherLaneAlive(boolean small) {
        if (!mVm.lanes()) return false;
        int other = small ? 0 : 1;
        if (mLaneLock[other].tryLock()) {
            try {
                long deadline = mClock.now() + 3000;
                mVm.link(!small, deadline).ping(deadline);
                return true;
            } catch (IOException e) {
                return false;
            } finally {
                mLaneLock[other].unlock();
            }
        }
        synchronized (mLastHeard) {
            return mClock.now() - mLastHeard[other] < 10000;
        }
    }

    private void handleLocked(Request r, boolean small) {
        if (mVm.heldDown()) {
            // A test holds the VM down (debuggable builds only): it stays stopped, every request is unavailable and
            // nothing is decoded anywhere else. No backoff, so it comes back as soon as the hold ends.
            mVm.stop();
            return;
        }
        long now = mClock.now();
        synchronized (mStartLock) {
            if (now < mNextStart && !mVm.isRunning()) return; // backing off: UNAVAILABLE
        }
        for (int attempt = 0; ; attempt++) {
            GuestLink link;
            try {
                link = mVm.link(small, mClock.now() + LINK_BUDGET_MILLIS);
            } catch (IOException e) {
                Log.w(TAG, "VM not available: " + e.getMessage());
                mVm.stop();
                backOff();
                return;
            }
            // The call's budget starts once the link is up: a slow VM start never eats into the decode's time.
            long budget = mClock.now() + CALL_BUDGET_MILLIS;
            int generation = mVm.generation();
            boolean reused = mVm.lastLinkReused(small);
            // The big lane's reply ends the input's use: no second attempt follows. A small-lane reply may still send
            // the request on to the big lane, so its (small) input stays until the request ends.
            link.setBudget(this, r.lane, small ? null : () -> releaseInput(r));
            try {
                GuestLink.Answer a = call(link, r, budget);
                synchronized (mStartLock) {
                    mBackoff = BACKOFF_MIN;
                }
                synchronized (mLastHeard) {
                    mLastHeard[small ? 1 : 0] = mClock.now();
                }
                if (a.status == GuestLink.BIG_LANE) {
                    // Too large for the small lane, decided in the VM. Not an answer: the big lane gets it.
                    if (!small) throw new GuestLink.ProtocolException("BIG_LANE from the big lane");
                    if (r.source != null) r.source.rewind();
                    r.bigLane = true;
                    return;
                }
                if (a.status == GuestLink.INTERNAL || a.status == GuestLink.BUSY) {
                    // A worker died: no verdict on the file, not cached, counted towards a strike. The service had no
                    // memory for the pixels, or the VM stopped the worker for a reason outside the file (BUSY): just
                    // try later, no strike.
                    r.status = UNAVAILABLE;
                    r.died = a.status == GuestLink.INTERNAL && !a.noBudget;
                    return;
                }
                r.answer = a;
                r.status = a.status;
                return;
            } catch (GuestLink.SourceFailedException e) {
                // The caller's file failed while it was sent (it shrank or stalled). The connection is gone, the VM
                // is fine and the file gets no strike: the next request connects again.
                Log.w(TAG, "source failed while sending: " + e.getMessage());
                r.status = UNAVAILABLE;
                return;
            } catch (GuestLink.HostFailureException e) {
                // This service failed (its own heap), not the VM and not the file: the connection is gone, nothing
                // else changes.
                Log.w(TAG, "service failed during the call: " + e.getMessage());
                mVm.dropLink(small);
                r.status = UNAVAILABLE;
                return;
            } catch (IOException e) {
                if (mVm.generation() != generation || !mVm.isRunning()) {
                    // Another request stopped the VM meanwhile: this one only lost its connection. No strike.
                    r.status = UNAVAILABLE;
                    return;
                }
                if (link.timedOut() && otherLaneAlive(small)) {
                    // Past the deadline while the other lane still answers: the VM is slow, not broken. This
                    // connection goes (the broker sees it closed when its worker is done), the VM stays, no strike.
                    Log.w(TAG, "VM slow on this lane, the other lane answers: " + e.getMessage());
                    mVm.dropLink(small);
                    r.status = UNAVAILABLE;
                    return;
                }
                if (attempt == 0 && reused && !link.replied() && !link.timedOut()) {
                    // A connection kept from earlier that died meanwhile, before it said anything: connect again
                    // once before calling the VM broken.
                    Log.i(TAG, "kept VM connection was dead, connecting again: " + e.getMessage());
                    mVm.dropLink(small);
                    if (r.source != null) r.source.rewind();
                    continue;
                }
                // Silent past the budget, or a reply that broke the protocol, on a fresh connection: the link and
                // the VM are not trusted any more. The request is unavailable, never cached as a verdict on the
                // file, unless the same file does it again. A worker cannot cause this: the broker checks
                // everything a worker sends.
                Log.w(TAG, "VM link broken: " + e.getMessage());
                r.status = UNAVAILABLE;
                r.died = r.op != GuestLink.OP_PING && r.op != GuestLink.OP_HOOK;
                mVm.stop();
                backOff();
                return;
            }
        }
    }

    private static GuestLink.Answer call(GuestLink link, Request r, long budget) throws IOException {
        switch (r.op) {
            case GuestLink.OP_PING: return link.ping(budget);
            case GuestLink.OP_PROBE: return link.probe(r.file, r.len, budget);
            case GuestLink.OP_THUMBNAIL:
                return r.source != null ? link.call(r.op, r.a, r.b, r.source, budget)
                                        : link.thumbnail(r.file, r.len, r.a, r.b, budget);
            case GuestLink.OP_METADATA:
                return r.source != null ? link.call(r.op, 0, 0, r.source, budget) : link.metadata(r.file, r.len, budget);
            case GuestLink.OP_FRAMES: return link.frames(r.file, r.len, r.a, r.b, budget);
            case GuestLink.OP_HOOK: return link.hook(r.a, budget);
            default: throw new IllegalArgumentException("op");
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
        synchronized (mStartLock) {
            mNextStart = mClock.now() + mBackoff;
            mBackoff = Math.min(mBackoff * 2, BACKOFF_MAX);
        }
    }

    private static String hex(byte[] b) {
        StringBuilder s = new StringBuilder(b.length * 2);
        for (byte x : b) s.append(Character.forDigit((x >> 4) & 15, 16)).append(Character.forDigit(x & 15, 16));
        return s.toString();
    }
}
