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

import android.os.ParcelFileDescriptor;
import android.os.SystemClock;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructPollfd;
import android.system.StructStat;

import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InterruptedIOException;

/**
 * A stream over a file descriptor where every read and write waits with poll first, so no call can block past its
 * deadline. Used for the vsock connection to the VM and for reading the callers' files, which may be pipes that never
 * end.
 */
final class FdChannel implements GuestLink.Channel {
    private final ParcelFileDescriptor mPfd;
    private final FileDescriptor mFd;

    // Writes go out in pieces of this size, each after poll says there is room, on a non-blocking descriptor.
    private static final int WRITE_CHUNK = 64 * 1024;

    FdChannel(ParcelFileDescriptor pfd) {
        mPfd = pfd;
        mFd = pfd.getFileDescriptor();
    }

    /** For the VM link: never blocks in read or write, so every deadline holds. */
    static FdChannel nonBlocking(ParcelFileDescriptor pfd) throws IOException {
        FdChannel c = new FdChannel(pfd);
        try {
            int flags = Os.fcntlInt(c.mFd, OsConstants.F_GETFL, 0);
            Os.fcntlInt(c.mFd, OsConstants.F_SETFL, flags | OsConstants.O_NONBLOCK);
        } catch (ErrnoException e) {
            throw new IOException(e);
        }
        return c;
    }

    private void await(short events, long deadline) throws IOException {
        for (;;) {
            long left = deadline - SystemClock.uptimeMillis();
            if (left <= 0) throw new InterruptedIOException("deadline");
            StructPollfd p = new StructPollfd();
            p.fd = mFd;
            p.events = events;
            try {
                int r = Os.poll(new StructPollfd[] {p}, (int) Math.min(left, Integer.MAX_VALUE));
                if (r > 0) return;
            } catch (ErrnoException e) {
                if (e.errno != OsConstants.EINTR) throw new IOException(e);
            }
        }
    }

    @Override
    public int read(byte[] b, int off, int len, long deadline) throws IOException {
        for (;;) {
            await((short) OsConstants.POLLIN, deadline);
            try {
                return Os.read(mFd, b, off, len);
            } catch (ErrnoException e) {
                if (e.errno != OsConstants.EINTR && e.errno != OsConstants.EAGAIN) throw new IOException(e);
            }
        }
    }

    @Override
    public void write(byte[] b, int off, int len, long deadline) throws IOException {
        while (len > 0) {
            await((short) OsConstants.POLLOUT, deadline);
            try {
                int k = Os.write(mFd, b, off, Math.min(len, WRITE_CHUNK));
                off += k;
                len -= k;
            } catch (ErrnoException e) {
                if (e.errno != OsConstants.EINTR && e.errno != OsConstants.EAGAIN) throw new IOException(e);
            }
        }
    }

    /** A caller's file as read: the bytes in data[0, len), and how much of the memory budget it holds. */
    static final class Input {
        static final int OK = 0;
        static final int TOO_LARGE = 1; // or unreadable in time: a verdict on the caller's file
        static final int NO_MEMORY = 2; // the service holds too much right now: try again later

        int status;
        byte[] data;
        int len;
        long reserved;
    }

    /**
     * Reads the stream, at most max bytes, taking every buffer from the lane's budget before it is allocated. With
     * prefix, a longer stream is cut at max instead of refused (a probe needs only the header). A regular file is read
     * into one buffer of its size. On OK the caller owns input.reserved (charged to lane) and gives it back. Blocking
     * reads (FUSE files) are bounded by the caller, which runs this on a reader thread with a deadline.
     */
    Input readInput(int max, boolean prefix, long deadline, Decoder budget, String lane) {
        Input in = new Input();
        long size = -1;
        try {
            StructStat st = Os.fstat(mFd);
            if (OsConstants.S_ISREG(st.st_mode)) size = st.st_size;
        } catch (ErrnoException ignored) {
            // read as a stream
        }
        if (size > max && !prefix) {
            in.status = Input.TOO_LARGE;
            return in;
        }
        int cap = size >= 0 ? (int) Math.min(size + 1, (long) max + 1) : Math.min(64 * 1024, max + 1);
        if (!budget.reserve(lane, cap)) {
            in.status = Input.NO_MEMORY;
            return in;
        }
        long reserved = cap;
        boolean done = false;
        try {
            byte[] buf = new byte[cap];
            int used = 0;
            for (;;) {
                if (used == buf.length) {
                    if (buf.length > max) break;
                    int next = (int) Math.min((long) buf.length * 2, (long) max + 1);
                    if (!budget.reserve(lane, next)) {
                        in.status = Input.NO_MEMORY;
                        return in;
                    }
                    reserved += next;
                    byte[] grown = new byte[next];
                    System.arraycopy(buf, 0, grown, 0, used);
                    budget.release(lane, buf.length);
                    reserved -= buf.length;
                    buf = grown;
                }
                int k = read(buf, used, buf.length - used, deadline);
                if (k <= 0) break;
                used += k;
            }
            if (used > max) {
                if (!prefix) {
                    in.status = Input.TOO_LARGE;
                    return in;
                }
                used = max;
            }
            in.status = Input.OK;
            in.data = buf;
            in.len = used;
            in.reserved = reserved;
            done = true;
            return in;
        } catch (IOException e) {
            in.status = Input.TOO_LARGE;
            return in;
        } catch (Throwable t) {
            in.status = Input.NO_MEMORY;
            return in;
        } finally {
            if (!done) budget.release(lane, reserved);
        }
    }

    @Override
    public void close() throws IOException {
        mPfd.close();
    }
}
