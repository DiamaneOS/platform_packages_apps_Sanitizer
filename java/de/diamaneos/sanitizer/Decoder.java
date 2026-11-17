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
import java.io.InterruptedIOException;
import java.util.concurrent.atomic.AtomicLong;

/**
 * The decode service's core: the queue, the cache, the VM and its restarts. Every way to fail ends in an answer the
 * caller treats as fail closed: {@link #UNAVAILABLE} (ask again later) or a VM status. Nothing here ever parses a
 * file: the bytes go to the VM as they are.
 */
final class Decoder {
    private static final String TAG = "DecoderService";

    /** Not a VM status: the VM could not answer in time, try again later. */
    static final int UNAVAILABLE = -1;

    // How long one VM call may take, on top of the time a request waited in the queue.
    static final long CALL_MILLIS = 35000;
    // Restart backoff after a failed start or a broken link: 1 s doubling to 5 minutes, never giving up.
    static final long BACKOFF_MIN = 1000;
    static final long BACKOFF_MAX = 300000;
    // Input held for queued requests in all, so a flood cannot exhaust this process's memory.
    static final long MAX_QUEUED_INPUT = 96L << 20;

    private final GuestVm mVm;
    private final Scheduler mScheduler = new Scheduler(SystemClock::uptimeMillis);
    private final ResultCache mCache = new ResultCache();
    private final AtomicLong mQueuedInput = new AtomicLong();
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

    /** Starts the VM in the background, so the first request does not wait for it. */
    void warmUp() {
        submit(new Request(GuestLink.OP_PING, 0, 0, null, 0, "", false,
                SystemClock.uptimeMillis() + CALL_MILLIS));
    }

    /** One request to the VM, with its answer once done. */
    static final class Request extends Scheduler.Job {
        final int op, a, b;
        final byte[] file;
        final int len;
        volatile int status = UNAVAILABLE;
        volatile GuestLink.Answer answer;

        Request(int op, int a, int b, byte[] file, int len, String lane, boolean userWaiting, long deadline) {
            super(lane, userWaiting, deadline);
            this.op = op;
            this.a = a;
            this.b = b;
            this.file = file;
            this.len = len;
        }

        @Override
        void run() {
            // Set by Decoder.loop, which knows the VM.
        }
    }

    /**
     * Runs the request and returns it with its status: a VM status for a clean answer, or UNAVAILABLE. Blocks the
     * calling thread until done or until the request's deadline.
     */
    Request run(Request r) {
        Object key = null;
        if (r.op != GuestLink.OP_PING && r.op != GuestLink.OP_HOOK) {
            key = ResultCache.key(ResultCache.digest(r.file, r.len), r.op, r.a, r.b);
            GuestLink.Answer hit = mCache.get(key);
            if (hit != null) {
                r.answer = hit;
                r.status = hit.status;
                return r;
            }
        }
        if (!submit(r)) return r;
        try {
            if (!r.await(SystemClock::uptimeMillis)) return r; // UNAVAILABLE: the queue was too slow
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return r;
        }
        if (key != null && r.answer != null && r.status != UNAVAILABLE && r.status != GuestLink.INTERNAL) {
            mCache.put(key, r.answer);
        }
        return r;
    }

    private boolean submit(Request r) {
        if (mQueuedInput.addAndGet(r.len) > MAX_QUEUED_INPUT || !mScheduler.offer(r)) {
            mQueuedInput.addAndGet(-r.len);
            return false;
        }
        return true;
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
                handle(r);
            } catch (RuntimeException e) {
                Log.e(TAG, "request failed", e);
                r.status = UNAVAILABLE;
            } finally {
                mQueuedInput.addAndGet(-r.len);
                r.finish();
            }
        }
    }

    private void handle(Request r) {
        long now = SystemClock.uptimeMillis();
        if (now < mNextStart && !mVm.isRunning()) return; // backing off: UNAVAILABLE
        long deadline = Math.min(r.deadline, now + CALL_MILLIS);
        GuestLink link;
        try {
            link = mVm.link(deadline);
        } catch (IOException e) {
            Log.w(TAG, "VM not available: " + e.getMessage());
            failedStart();
            return;
        }
        try {
            GuestLink.Answer a;
            switch (r.op) {
                case GuestLink.OP_PING: a = link.ping(deadline); break;
                case GuestLink.OP_PROBE: a = link.probe(r.file, r.len, deadline); break;
                case GuestLink.OP_THUMBNAIL: a = link.thumbnail(r.file, r.len, r.a, r.b, deadline); break;
                case GuestLink.OP_METADATA: a = link.metadata(r.file, r.len, deadline); break;
                case GuestLink.OP_HOOK: a = link.hook(r.a, deadline); break;
                default: throw new IllegalArgumentException("op");
            }
            r.answer = a;
            r.status = a.status == GuestLink.INTERNAL ? UNAVAILABLE : a.status;
            mBackoff = BACKOFF_MIN;
        } catch (GuestLink.ProtocolException e) {
            // A timeout is the VM being slow: try again later. Anything else is the VM breaking the protocol for
            // this file: the file is treated as hostile (INVALID, never retried) and the VM is started afresh.
            boolean timeout = e.getMessage() != null && e.getMessage().contains("InterruptedIOException");
            Log.w(TAG, "VM answer refused: " + e.getMessage());
            r.status = timeout ? UNAVAILABLE : GuestLink.INVALID;
            if (!timeout) {
                // Remembered like any answer, so the same file cannot make the VM restart again and again.
                r.answer = new GuestLink.Answer();
                r.answer.status = GuestLink.INVALID;
            }
            mVm.stop();
            failedStart();
        } catch (InterruptedIOException e) {
            r.status = UNAVAILABLE;
            mVm.stop();
            failedStart();
        } catch (IOException e) {
            r.status = UNAVAILABLE;
            mVm.stop();
            failedStart();
        }
    }

    private void failedStart() {
        mNextStart = SystemClock.uptimeMillis() + mBackoff;
        mBackoff = Math.min(mBackoff * 2, BACKOFF_MAX);
    }
}
