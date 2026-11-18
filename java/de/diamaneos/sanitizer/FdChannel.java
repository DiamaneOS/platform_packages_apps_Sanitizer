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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

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
        static final int LATER = 3; // the read did not finish in time or had to wait its turn: try again later

        int status;
        byte[] data;
        int len;
        long reserved;
        // A streamed file instead of data: read as it is sent to the VM, and its SHA-256 read beforehand.
        FileSource source;
        byte[] digest;
    }

    // What a streamed file holds of the budget while it waits: the piece it is sent in.
    private static final int STREAM_RESERVE = 64 * 1024;
    private static final int HASH_CHUNK = 256 * 1024;
    // Hash passes over large files run at most two at a time in the whole service, whatever the lanes.
    private static final java.util.concurrent.Semaphore HASHING = new java.util.concurrent.Semaphore(2);

    /**
     * A large regular JPEG or PNG on a local file system, as a source the decoder sends to the VM in pieces, never
     * held whole. Its SHA-256 is read first (the cache key). Null when the file is not one to stream: not regular,
     * not starting with a JPEG or PNG signature (only those decode as a stream, the rest is refused above maxBuffered
     * without reading it), within maxBuffered (read into memory as before), above maxStreamed, or not on a device
     * the mount table names as f2fs, ext4 or erofs (FUSE, removable media and anything unknown can stall a read
     * without end, and the decoder thread must not). Runs on a reader thread, like readInput.
     */
    Input streamInput(long maxBuffered, long maxStreamed, long deadline, Decoder budget, String lane) {
        long size;
        long dev;
        try {
            StructStat st = Os.fstat(mFd);
            if (!OsConstants.S_ISREG(st.st_mode)) return null;
            size = st.st_size;
            dev = st.st_dev;
        } catch (ErrnoException e) {
            return null;
        }
        if (size <= maxBuffered || size > maxStreamed || !onLocalDevice(dev) || !jpegOrPng()) return null;
        Input in = new Input();
        if (!budget.reserve(lane, STREAM_RESERVE)) {
            in.status = Input.NO_MEMORY;
            return in;
        }
        boolean done = false;
        boolean hashing = false;
        ParcelFileDescriptor dup = null;
        try {
            long wait = deadline - SystemClock.uptimeMillis();
            if (wait <= 0 || !HASHING.tryAcquire(wait, java.util.concurrent.TimeUnit.MILLISECONDS)) {
                in.status = Input.LATER;
                return in;
            }
            hashing = true;
            dup = ParcelFileDescriptor.dup(mFd);
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] buf = new byte[HASH_CHUNK];
            for (long at = 0; at < size; ) {
                if (SystemClock.uptimeMillis() > deadline) throw new InterruptedIOException("deadline");
                int k = Os.pread(dup.getFileDescriptor(), buf, 0, (int) Math.min(buf.length, size - at), at);
                if (k <= 0) throw new IOException("file shorter than its size");
                md.update(buf, 0, k);
                at += k;
            }
            in.status = Input.OK;
            in.source = new FileSource(dup, size);
            in.digest = md.digest();
            in.len = (int) size;
            in.reserved = STREAM_RESERVE;
            done = true;
            return in;
        } catch (InterruptedIOException | InterruptedException e) {
            // Slow or busy storage is no verdict on the file.
            in.status = Input.LATER;
            return in;
        } catch (IOException | ErrnoException | NoSuchAlgorithmException e) {
            in.status = Input.TOO_LARGE;
            return in;
        } finally {
            if (hashing) HASHING.release();
            if (!done) {
                budget.release(lane, STREAM_RESERVE);
                if (dup != null) {
                    try {
                        dup.close();
                    } catch (IOException ignored) {
                        // closed already
                    }
                }
            }
        }
    }

    /**
     * A regular file sent from its start, read with pread as it goes, hashing what it sends: the decoder caches the
     * answer only when that hash is the one read beforehand, so a file changed in between never fills the cache.
     */
    static final class FileSource implements GuestLink.Source, java.io.Closeable {
        private final ParcelFileDescriptor mPfd;
        private final long mSize;
        private long mAt;
        private final MessageDigest mSent;

        FileSource(ParcelFileDescriptor pfd, long size) throws NoSuchAlgorithmException {
            mPfd = pfd;
            mSize = size;
            mSent = MessageDigest.getInstance("SHA-256");
        }

        @Override
        public long length() {
            return mSize;
        }

        @Override
        public void rewind() {
            mAt = 0;
            mSent.reset();
        }

        @Override
        public void readFully(byte[] b, int off, int len, long deadline) throws IOException {
            int got = 0;
            while (got < len) {
                if (SystemClock.uptimeMillis() > deadline) throw new InterruptedIOException("deadline");
                int k;
                try {
                    k = Os.pread(mPfd.getFileDescriptor(), b, off + got, len - got, mAt);
                } catch (ErrnoException e) {
                    throw new IOException(e);
                }
                if (k <= 0) throw new IOException("file ended early");
                mSent.update(b, off + got, k);
                got += k;
                mAt += k;
            }
        }

        /** The SHA-256 of what was sent, once all of it was. Null before. */
        byte[] sentDigest() {
            return mAt == mSize ? mSent.digest() : null;
        }

        @Override
        public void close() throws IOException {
            mPfd.close();
        }
    }

    /** The file starts with a JPEG or PNG signature (pread, the position stays). */
    private boolean jpegOrPng() {
        byte[] b = new byte[8];
        try {
            if (Os.pread(mFd, b, 0, 8, 0) != 8) return false;
        } catch (ErrnoException | java.io.InterruptedIOException e) {
            return false;
        }
        boolean jpeg = (b[0] & 0xff) == 0xff && (b[1] & 0xff) == 0xd8 && (b[2] & 0xff) == 0xff;
        boolean png = (b[0] & 0xff) == 0x89 && b[1] == 'P' && b[2] == 'N' && b[3] == 'G' && b[4] == '\r'
                && b[5] == '\n' && b[6] == 0x1a && b[7] == '\n';
        return jpeg || png;
    }

    /** The file's own device is in the mount table, as a local file system that cannot stall a read. */
    static boolean onLocalDevice(long dev) {
        try {
            String mountinfo = new String(Files.readAllBytes(Paths.get("/proc/self/mountinfo")),
                    StandardCharsets.UTF_8);
            return Mounts.localDevice(Mounts.major(dev), Mounts.minor(dev), mountinfo);
        } catch (IOException | RuntimeException e) {
            return false;
        }
    }

    /**
     * Reads the stream, at most max bytes, taking every buffer from the lane's budget before it is allocated. With
     * prefix, a longer stream is cut at max instead of refused (a probe needs only the header). A regular file is read
     * into one buffer of its size. On OK the caller owns input.reserved (charged to lane) and gives it back. Blocking
     * reads (FUSE files) are bounded by the caller, which runs this on a reader thread with a deadline.
     */
    Input readInput(int max, boolean prefix, long deadline, Decoder budget, String lane) {
        return readInput(max, prefix, Long.MAX_VALUE, max, deadline, budget, lane);
    }

    /** As above, and a regular file longer than headAbove is read only to its first headMax bytes (its head). */
    Input readInput(int max, boolean prefix, long headAbove, int headMax, long deadline, Decoder budget, String lane) {
        Input in = new Input();
        long size = -1;
        try {
            StructStat st = Os.fstat(mFd);
            if (OsConstants.S_ISREG(st.st_mode)) size = st.st_size;
        } catch (ErrnoException ignored) {
            // read as a stream
        }
        if (size > headAbove) {
            max = headMax;
            prefix = true;
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
