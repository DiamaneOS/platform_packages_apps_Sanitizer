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

import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The VM works on one file at a time. Requests queue in lanes, one lane per package that supplied the bytes, so a
 * flood from one app only lengthens its own lane. Lanes take turns. Requests a user waits on (an open file, thumbnails
 * on screen) go before background requests, but after WAITING_BURST of them in a row one background request goes. Each lane and the whole queue have caps: a full queue answers at
 * once with "unavailable", which callers treat as fail closed and ask again later.
 *
 * <p>Thread-safe. Jobs are taken by one worker thread with {@link #take}.
 */
final class Scheduler {
    static final int MAX_PER_LANE = 32;
    static final int MAX_TOTAL = 256;

    /** A unit of work. The worker sets the result and the waiter collects it. */
    abstract static class Job {
        final String lane;
        final boolean userWaiting;
        final long deadline;
        private boolean mDone;

        Job(String lane, boolean userWaiting, long deadline) {
            this.lane = lane == null ? "" : lane;
            this.userWaiting = userWaiting;
            this.deadline = deadline;
        }

        /** Runs on the worker thread. */
        abstract void run();

        synchronized void finish() {
            mDone = true;
            notifyAll();
        }

        /** Waits until the job ran or the deadline passed. Returns true when it ran. */
        synchronized boolean await(Clock clock) throws InterruptedException {
            while (!mDone) {
                long left = deadline - clock.now();
                if (left <= 0) return false;
                wait(left);
            }
            return true;
        }
    }

    interface Clock {
        long now();
    }

    // Insertion-ordered so turns rotate: a served lane moves to the end.
    private final LinkedHashMap<String, ArrayDeque<Job>> mWaiting = new LinkedHashMap<>();
    private final LinkedHashMap<String, ArrayDeque<Job>> mBackground = new LinkedHashMap<>();
    private final Map<String, Integer> mPerLane = new HashMap<>();
    private int mTotal;
    // Waiting jobs served in a row while background jobs wait. After WAITING_BURST of them one background job goes
    // first, so background work (scan sizes, special formats) is never starved by a steady stream of waiting ones.
    static final int WAITING_BURST = 4;
    private int mWaitingInRow;

    Scheduler() {
    }

    /** Queues the job. False when its lane or the whole queue is full. */
    synchronized boolean offer(Job job) {
        int lane = mPerLane.getOrDefault(job.lane, 0);
        if (lane >= MAX_PER_LANE || mTotal >= MAX_TOTAL) return false;
        (job.userWaiting ? mWaiting : mBackground).computeIfAbsent(job.lane, k -> new ArrayDeque<>()).add(job);
        mPerLane.put(job.lane, lane + 1);
        mTotal++;
        notifyAll();
        return true;
    }

    /**
     * The next job, waiting for one. A job whose deadline passed is returned too: the worker completes it as
     * unavailable and releases what it holds, so nothing leaves the queue without an answer.
     */
    synchronized Job take() throws InterruptedException {
        for (;;) {
            Job job = null;
            if (mWaitingInRow >= WAITING_BURST) job = next(mBackground);
            if (job == null) job = next(mWaiting);
            if (job == null) job = next(mBackground);
            if (job != null) {
                mWaitingInRow = job.userWaiting ? mWaitingInRow + 1 : 0;
                return job;
            }
            wait();
        }
    }

    synchronized int size() {
        return mTotal;
    }

    private Job next(LinkedHashMap<String, ArrayDeque<Job>> lanes) {
        Iterator<Map.Entry<String, ArrayDeque<Job>>> it = lanes.entrySet().iterator();
        if (!it.hasNext()) return null;
        Map.Entry<String, ArrayDeque<Job>> e = it.next();
        it.remove();
        ArrayDeque<Job> q = e.getValue();
        Job job = q.poll();
        if (!q.isEmpty()) lanes.put(e.getKey(), q); // to the back: the other lanes go first
        int left = mPerLane.get(job.lane) - 1;
        if (left == 0) {
            mPerLane.remove(job.lane);
        } else {
            mPerLane.put(job.lane, left);
        }
        mTotal--;
        return job;
    }
}
