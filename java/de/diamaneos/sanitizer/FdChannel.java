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

    FdChannel(ParcelFileDescriptor pfd) {
        mPfd = pfd;
        mFd = pfd.getFileDescriptor();
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
                int k = Os.write(mFd, b, off, len);
                off += k;
                len -= k;
            } catch (ErrnoException e) {
                if (e.errno != OsConstants.EINTR && e.errno != OsConstants.EAGAIN) throw new IOException(e);
            }
        }
    }

    /** Reads the whole stream, at most max bytes. Returns null when the stream is longer than max. */
    byte[] readAll(int max, long deadline) throws IOException {
        byte[] buf = new byte[64 * 1024];
        int used = 0;
        for (;;) {
            if (used == buf.length) {
                if (buf.length > max) return null;
                byte[] grown = new byte[(int) Math.min((long) buf.length * 2, (long) max + 1)];
                System.arraycopy(buf, 0, grown, 0, used);
                buf = grown;
            }
            int k = read(buf, used, buf.length - used, deadline);
            if (k <= 0) break;
            used += k;
            if (used > max) return null;
        }
        byte[] out = new byte[used];
        System.arraycopy(buf, 0, out, 0, used);
        return out;
    }

    @Override
    public void close() throws IOException {
        mPfd.close();
    }
}
