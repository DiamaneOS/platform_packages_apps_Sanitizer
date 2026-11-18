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

import java.io.Closeable;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

/**
 * The Android end of the decoder VM's wire protocol (vm/proto.h). Everything the VM sends is hostile: every header
 * field is range-checked, every length is fixed by the request or by an earlier checked field, and nothing is
 * allocated before its size passed the checks. The only bytes taken without structure are the pixels, whose length
 * the checked header fixes, and they are checked too (no colour channel above alpha).
 *
 * <p>Text fields are ASCII only (each byte 0x20 to 0x7e or the field's narrower set), so no line or paragraph
 * separator, bidi control or zero-width character can reach a caller.
 *
 * <p>A reply that breaks any rule throws {@link ProtocolException}: the caller drops the link, restarts the VM and
 * answers its own caller with STATUS_UNAVAILABLE. Each call has one total deadline that covers the request and the
 * whole reply.
 */
final class GuestLink implements Closeable {
    static final int PORT = 5685;
    // The small lane beside it (vm/proto.h kSmallPort): files of at most SMALL_INPUT_BYTES whose header declares at
    // most a megapixel, decided in the VM. Anything else it answers BIG_LANE.
    static final int SMALL_PORT = 5686;
    static final int SMALL_INPUT_BYTES = 1 << 20;

    static final int REQUEST_MAGIC = 0x31305144; // "DQ01"
    static final int REPLY_MAGIC = 0x31305344; // "DS01"
    static final int END_MAGIC = 0x31304544; // "DE01"
    static final int META_MAGIC = 0x31304d44; // "DM01"

    static final int OP_PING = 1;
    static final int OP_PROBE = 2;
    static final int OP_THUMBNAIL = 3;
    static final int OP_METADATA = 4;
    static final int OP_HOOK = 5;

    static final int OK = 0;
    static final int UNSUPPORTED = 2;
    static final int INVALID = 3;
    static final int INTERNAL = 4;
    // The worker was stopped for a reason outside the file (the VM ran out of memory, the worker got too little CPU):
    // never a verdict on the file, never a strike. Only on the link: callers see "unavailable".
    static final int BUSY = 5;
    // Small lane only: the file is too large for that lane. Not a verdict: the request goes to the big lane.
    static final int BIG_LANE = 6;

    // The contract's FORMAT_* values (IDecodeService), all of which the VM reads.
    static final int FORMAT_JPEG = 1;
    static final int FORMAT_PNG = 2;
    static final int FORMAT_GIF = 3;
    static final int FORMAT_WEBP = 4;
    static final int FORMAT_BMP = 5;
    static final int FORMAT_HEIF = 6;
    static final int FORMAT_AVIF = 7;
    static final int FORMAT_DNG = 8;
    static final int FORMAT_ICO = 9;
    static final int FORMAT_WBMP = 10;

    // vm/proto.h: a JPEG or PNG streams through the VM up to MAX_INPUT_BYTES, any other file is held there while it
    // is decoded, up to MAX_BUFFERED_BYTES (the VM answers INVALID above that).
    static final int MAX_INPUT_BYTES = 256 << 20;
    static final int MAX_BUFFERED_BYTES = 32 << 20;
    static final int MAX_DIMENSION = 65535;
    static final int MAX_PIXELS = 8 << 20;

    static final int META_BYTES = 1024;
    static final int TEXT_CHARS = 256;
    static final int NUMBER_CHARS = 32;
    static final int ID_CHARS = 128;

    static final int HEADER_BYTES = 32;
    static final int END_BYTES = 8;

    /** The file to send: in memory, or read in pieces as it is sent (a regular file, which is never held whole). */
    interface Source {
        long length();

        /** Back to the start, for a second attempt on a new connection. */
        default void rewind() {}

        /** Fills b[off, off + len) with the next bytes, exactly. Throws if the source ends early or stalls. */
        void readFully(byte[] b, int off, int len, long deadlineMillis) throws IOException;
    }

    static Source source(byte[] file, int len) {
        return new Source() {
            int mAt = 0;

            @Override public long length() {
                return len;
            }

            @Override public void rewind() {
                mAt = 0;
            }

            @Override public void readFully(byte[] b, int off, int n, long deadlineMillis) {
                System.arraycopy(file, mAt, b, off, n);
                mAt += n;
            }
        };
    }

    /** A stream with deadlines: a vsock socket on the phone, a socket pair in the tests. */
    interface Channel extends Closeable {
        /** Reads 1 to len bytes, 0 at the end of the stream. Throws on a passed deadline. */
        int read(byte[] b, int off, int len, long deadlineMillis) throws IOException;

        void write(byte[] b, int off, int len, long deadlineMillis) throws IOException;
    }

    /** The VM broke the protocol or the deadline passed. The link must not be used again. */
    static final class ProtocolException extends IOException {
        ProtocolException(String message) {
            super(message);
        }
    }

    /**
     * The caller's file failed while it was being sent (it shrank, a read failed, its deadline passed). Not the VM's
     * fault: the connection is closed (the VM is mid-request), but the VM is not restarted and nothing is held
     * against the file.
     */
    static final class SourceFailedException extends IOException {
        SourceFailedException(String message) {
            super(message);
        }
    }

    /** A clean answer: a status, and for OK the checked values. */
    static final class Answer {
        int status;
        int format;
        int width;
        int height;
        int extra; // probe: animated, thumbnail: rotation
        byte[] pixels; // thumbnail
        Meta meta; // metadata
        long reserved; // budget taken for the pixels, given back by whoever ran the call
        boolean noBudget; // INTERNAL because the service had no memory for the pixels, not because a worker died

        /** The checked values, for logs and test reports. Never the pixels or the metadata's text. */
        @Override
        public String toString() {
            return "Answer{status " + status + ", format " + format + ", " + width + "x" + height + ", extra " + extra
                    + (pixels != null ? ", " + pixels.length + " pixel bytes" : "") + (meta != null ? ", metadata" : "")
                    + (noBudget ? ", no budget" : "") + "}";
        }
    }

    /** The metadata record after its checks. Absent values are -1, NaN or "". */
    static final class Meta {
        int format;
        int width;
        int height;
        int orientation;
        long dateTakenMillis;
        boolean offsetKnown;
        double latitude;
        double longitude;
        int specialFormat;
        String description;
        String exposureTime;
        String fNumber;
        String iso;
        String sceneCaptureType;
        String documentId;
        String instanceId;
        String originalDocumentId;
    }

    /** Memory for the pixels of a reply, taken before they are allocated. */
    interface Budget {
        boolean reserve(String lane, long n);

        void release(String lane, long n);
    }

    private final Channel mChannel;
    private boolean mBroken;
    private boolean mReplied; // the last call read at least one byte of a reply
    private Budget mBudget;
    private String mLane = "";
    private Runnable mOnReply;

    /** Pixels are read only within this budget, charged to this lane. Without one, they are read freely (tests). */
    void setBudget(Budget budget, String lane) {
        setBudget(budget, lane, null);
    }

    /**
     * As above, and onReply runs once the reply's header has arrived, before any pixel is reserved: the request's
     * input is no longer needed then (no second attempt follows a reply), so its memory can go first.
     */
    void setBudget(Budget budget, String lane, Runnable onReply) {
        mBudget = budget;
        mLane = lane;
        mOnReply = onReply;
    }

    GuestLink(Channel channel) {
        mChannel = channel;
    }

    boolean isBroken() {
        return mBroken;
    }

    @Override
    public void close() {
        mBroken = true;
        try {
            mChannel.close();
        } catch (IOException ignored) {
            // nothing left to do
        }
    }

    Answer ping(long deadlineMillis) throws IOException {
        return call(OP_PING, 0, 0, null, 0, 0, deadlineMillis);
    }

    Answer probe(byte[] file, int len, long deadlineMillis) throws IOException {
        return call(OP_PROBE, 0, 0, file, len, 0, deadlineMillis);
    }

    Answer thumbnail(byte[] file, int len, int maxWidth, int maxHeight, long deadlineMillis) throws IOException {
        return call(OP_THUMBNAIL, maxWidth, maxHeight, file, len, 0, deadlineMillis);
    }

    Answer metadata(byte[] file, int len, long deadlineMillis) throws IOException {
        return call(OP_METADATA, 0, 0, file, len, 0, deadlineMillis);
    }

    /** Any operation, with the file sent from a source in pieces. */
    Answer call(int op, int arg0, int arg1, Source src, long deadlineMillis) throws IOException {
        return call(op, arg0, arg1, src, deadlineMillis, true);
    }

    /** Test builds only: the VM's test image answers with a 1x1 or 2x1 thumbnail or fails, see vm/decoder_vm.cpp. */
    Answer hook(int hook, long deadlineMillis) throws IOException {
        return call(OP_HOOK, hook, 0, null, 0, 0, deadlineMillis);
    }

    /** Test builds only: a hook with input (the leak scan looks for these bytes). */
    Answer hook(int hook, byte[] input, int len, long deadlineMillis) throws IOException {
        return call(OP_HOOK, hook, 0, input, len, 0, deadlineMillis);
    }

    private Answer call(int op, int arg0, int arg1, byte[] file, int len, int unused, long deadline)
            throws IOException {
        if (len < 0 || len > MAX_INPUT_BYTES || (file == null && len != 0) || (file != null && len > file.length)) {
            throw new IllegalArgumentException("input length");
        }
        return call(op, arg0, arg1, file == null ? source(new byte[0], 0) : source(file, len), deadline, true);
    }

    private static final int PIECE_BYTES = 64 << 10;

    /** Whether the last call got any byte of a reply: when not, a reused connection may simply have been dead. */
    boolean replied() {
        return mReplied;
    }

    private Answer call(int op, int arg0, int arg1, Source src, long deadline, boolean unused) throws IOException {
        if (mBroken) throw new ProtocolException("link already broken");
        mReplied = false;
        long len = src.length();
        if (len < 0 || len > MAX_INPUT_BYTES) throw new IllegalArgumentException("input length");
        long held = 0; // pixel budget reserved here and not handed over with an answer
        try {
            ByteBuffer rq = ByteBuffer.allocate(HEADER_BYTES).order(ByteOrder.LITTLE_ENDIAN);
            rq.putInt(REQUEST_MAGIC).putInt(op).putInt(arg0).putInt(arg1).putInt((int) len);
            mChannel.write(rq.array(), 0, HEADER_BYTES, deadline);
            // The file in pieces: a regular file is read as it is sent, never held whole.
            byte[] piece = new byte[(int) Math.min(len, PIECE_BYTES)];
            for (long sent = 0; sent < len; ) {
                int n = (int) Math.min(piece.length, len - sent);
                try {
                    src.readFully(piece, 0, n, deadline);
                } catch (IOException | RuntimeException e) {
                    throw new SourceFailedException(e.getClass().getSimpleName() + ": " + e.getMessage());
                }
                mChannel.write(piece, 0, n, deadline);
                sent += n;
            }

            ByteBuffer h = readExact(HEADER_BYTES, deadline);
            Answer a = new Answer();
            int magic = h.getInt();
            a.status = h.getInt();
            a.format = h.getInt();
            a.width = h.getInt();
            a.height = h.getInt();
            a.extra = h.getInt();
            int payload = h.getInt();
            int reserved = h.getInt();
            check(magic == REPLY_MAGIC && reserved == 0, "reply header");
            if (mOnReply != null) {
                Runnable r = mOnReply;
                mOnReply = null;
                r.run();
            }
            if (a.status != OK) {
                check(a.status == UNSUPPORTED || a.status == INVALID || a.status == INTERNAL || a.status == BUSY
                        || a.status == BIG_LANE, "status");
                check(a.format == 0 && a.width == 0 && a.height == 0 && a.extra == 0 && payload == 0,
                        "failure with values");
                readEnd(a.status, deadline);
                return a;
            }
            switch (op) {
                case OP_PING:
                    check(a.format == 0 && a.width == 0 && a.height == 0 && a.extra == 0 && payload == 0, "ping");
                    break;
                case OP_PROBE:
                    checkFormat(a.format);
                    checkSize(a.width, a.height, MAX_DIMENSION, MAX_DIMENSION);
                    // Only GIF, WebP, PNG (APNG), HEIF and AVIF can be animated.
                    check(a.extra == 0 || (a.extra == 1 && mayBeAnimated(a.format)), "animated");
                    check(payload == 0, "probe payload");
                    break;
                case OP_THUMBNAIL:
                case OP_HOOK:
                    check(a.extra == 0 || a.extra == 90 || a.extra == 180 || a.extra == 270, "rotation");
                    if (op == OP_THUMBNAIL) {
                        checkFormat(a.format);
                        // The box is for the image as shown: turned by 90 or 270 degrees, the stored image fits it
                        // the other way round.
                        boolean turned = a.extra == 90 || a.extra == 270;
                        checkSize(a.width, a.height, turned ? arg1 : arg0, turned ? arg0 : arg1);
                    } else {
                        check(a.width >= 1 && a.width <= 2 && a.height == 1, "hook size");
                    }
                    check((long) a.width * a.height <= MAX_PIXELS, "pixels");
                    check((long) payload == (long) a.width * a.height * 4, "pixel length");
                    if (mBudget != null && !mBudget.reserve(mLane, payload)) {
                        // No memory for these pixels now: read past them, keep the link, answer "try later".
                        drain(payload, deadline);
                        ByteBuffer skipped = readExact(END_BYTES, deadline);
                        check(skipped.getInt() == END_MAGIC, "end");
                        Answer later = new Answer();
                        later.status = INTERNAL;
                        later.noBudget = true;
                        return later;
                    }
                    // From here the reservation is given back on every way out (held), unless the answer with its
                    // pixels is handed over: then the caller gives it back when done (a.reserved).
                    held = mBudget != null ? payload : 0;
                    byte[] pixels = readExact(payload, deadline).array();
                    // A worker that failed after its header: the VM kept the length with zeros and its trailer says
                    // INVALID (the file), INTERNAL (the worker died), BUSY (not the file) or, from the small lane,
                    // BIG_LANE. A clean answer, not a broken link. Never UNSUPPORTED after pixels.
                    ByteBuffer e = readExact(END_BYTES, deadline);
                    check(e.getInt() == END_MAGIC, "end");
                    int endStatus = e.getInt();
                    if (endStatus == INVALID || endStatus == INTERNAL || endStatus == BUSY || endStatus == BIG_LANE) {
                        Answer bad = new Answer();
                        bad.status = endStatus;
                        return bad;
                    }
                    check(endStatus == OK, "end status " + endStatus);
                    checkPremultiplied(pixels);
                    a.pixels = pixels;
                    a.reserved = held;
                    held = 0;
                    return a;
                case OP_METADATA:
                    checkFormat(a.format);
                    checkSize(a.width, a.height, MAX_DIMENSION, MAX_DIMENSION);
                    check(a.extra == 0 && payload == META_BYTES, "metadata length");
                    a.meta = parseMeta(readExact(META_BYTES, deadline), a.format, a.width, a.height);
                    break;
                default:
                    throw new IllegalArgumentException("op");
            }
            readEnd(OK, deadline);
            return a;
        } catch (IOException | RuntimeException | Error e) {
            // Anything at all, out of memory included, leaves the link in an unknown state: it is not used again.
            close();
            if (e instanceof SourceFailedException) throw (SourceFailedException) e;
            if (e instanceof ProtocolException) throw (ProtocolException) e;
            if (e instanceof IllegalArgumentException) throw (IllegalArgumentException) e;
            throw new ProtocolException(e.getClass().getSimpleName() + ": " + e.getMessage());
        } finally {
            // A link that failed between the pixels and the trailer, a late failure, bad pixels: the reservation goes
            // back here, so it can never leak.
            if (held > 0) mBudget.release(mLane, held);
        }
    }

    private void drain(int n, long deadline) throws IOException {
        byte[] b = new byte[(int) Math.min(n, 64 * 1024)];
        while (n > 0) {
            int k = mChannel.read(b, 0, Math.min(n, b.length), deadline);
            if (k <= 0) throw new ProtocolException("stream ended in skipped pixels");
            n -= k;
        }
    }

    private void readEnd(int status, long deadline) throws IOException {
        ByteBuffer e = readExact(END_BYTES, deadline);
        int magic = e.getInt();
        int endStatus = e.getInt();
        check(magic == END_MAGIC, "end");
        check(endStatus == status, "end status " + endStatus);
    }

    private ByteBuffer readExact(int n, long deadline) throws IOException {
        byte[] b = new byte[n];
        int got = 0;
        while (got < n) {
            int k = mChannel.read(b, got, n - got, deadline);
            if (k <= 0) throw new ProtocolException("stream ended after " + got + " of " + n);
            got += k;
            mReplied = true;
        }
        return ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN);
    }

    private static void check(boolean ok, String what) throws ProtocolException {
        if (!ok) throw new ProtocolException("bad " + what);
    }

    /** The contract's rule, as DecodeChecks.mayBeAnimated: only GIF, WebP, PNG (APNG), HEIF and AVIF. */
    static boolean mayBeAnimated(int format) {
        return format == FORMAT_GIF || format == FORMAT_WEBP || format == FORMAT_PNG || format == FORMAT_HEIF
                || format == FORMAT_AVIF;
    }

    private static void checkFormat(int format) throws ProtocolException {
        check(format >= FORMAT_JPEG && format <= FORMAT_WBMP, "format");
    }

    private static void checkSize(int w, int h, int maxW, int maxH) throws ProtocolException {
        check(w >= 1 && h >= 1 && w <= maxW && h <= maxH && w <= MAX_DIMENSION && h <= MAX_DIMENSION, "size");
    }

    private static void checkPremultiplied(byte[] p) throws ProtocolException {
        for (int i = 0; i < p.length; i += 4) {
            int a = p[i + 3] & 0xff;
            if ((p[i] & 0xff) > a || (p[i + 1] & 0xff) > a || (p[i + 2] & 0xff) > a) {
                throw new ProtocolException("colour above alpha at pixel " + i / 4);
            }
        }
    }

    // --- The metadata record (vm/proto.h struct Meta) ---------------------------------------------------------------

    static final int HAS_ORIENTATION = 1;
    static final int HAS_DATE = 1 << 1;
    static final int OFFSET_KNOWN = 1 << 2;
    static final int HAS_GPS = 1 << 3;

    static final int SPECIAL_GIF = 1;
    static final int SPECIAL_MOTION_PHOTO = 2;
    static final int SPECIAL_ANIMATED_WEBP = 3;
    private static final int KNOWN_FLAGS = HAS_ORIENTATION | HAS_DATE | OFFSET_KNOWN | HAS_GPS;

    // Dates the record may carry: 1900-01-01 to 9999-12-31 with a day of slack for the offset, and never more than a
    // day in the future.
    private static final long MIN_DATE = -2208988800000L - 86400000L;
    private static final long MAX_DATE = 253402300799999L + 86400000L;

    static Meta parseMeta(ByteBuffer b, int format, int width, int height) throws ProtocolException {
        Meta m = new Meta();
        check(b.getInt() == META_MAGIC && b.getInt() == 1, "record version");
        int flags = b.getInt();
        check((flags & ~KNOWN_FLAGS) == 0, "flags");
        check(b.getInt() == format && b.getInt() == width && b.getInt() == height, "record size");
        m.format = format;
        m.width = width;
        m.height = height;
        m.orientation = b.getInt();
        m.specialFormat = b.getInt();
        m.dateTakenMillis = b.getLong();
        int lat = b.getInt();
        int lon = b.getInt();
        if ((flags & HAS_ORIENTATION) != 0) {
            check(m.orientation == 0 || m.orientation == 90 || m.orientation == 180 || m.orientation == 270,
                    "orientation");
        } else {
            check(m.orientation == -1, "orientation without flag");
        }
        // GIF is always a GIF, an animated WebP is one, a motion photo is marked in its XMP (JPEG, PNG, WebP, HEIF,
        // AVIF).
        check(m.specialFormat == 0 || (m.specialFormat == SPECIAL_GIF && format == FORMAT_GIF)
                || (m.specialFormat == SPECIAL_MOTION_PHOTO && (format == FORMAT_JPEG || format == FORMAT_PNG
                        || format == FORMAT_WEBP || format == FORMAT_HEIF || format == FORMAT_AVIF))
                || (m.specialFormat == SPECIAL_ANIMATED_WEBP && format == FORMAT_WEBP), "special format");
        if ((flags & HAS_DATE) != 0) {
            check(m.dateTakenMillis >= MIN_DATE && m.dateTakenMillis <= MAX_DATE
                    && m.dateTakenMillis <= System.currentTimeMillis() + 86400000L, "date");
        } else {
            check(m.dateTakenMillis == -1 && (flags & OFFSET_KNOWN) == 0, "date without flag");
        }
        m.offsetKnown = (flags & OFFSET_KNOWN) != 0;
        if ((flags & HAS_GPS) != 0) {
            check(lat >= -900000000 && lat <= 900000000 && lon >= -1800000000 && lon <= 1800000000, "position");
            m.latitude = lat / 1e7;
            m.longitude = lon / 1e7;
        } else {
            check(lat == 0 && lon == 0, "position without flag");
            m.latitude = Double.NaN;
            m.longitude = Double.NaN;
        }
        m.description = text(b, TEXT_CHARS, GuestLink::printable);
        m.exposureTime = text(b, NUMBER_CHARS, GuestLink::numberChar);
        m.fNumber = text(b, NUMBER_CHARS, GuestLink::numberChar);
        m.iso = text(b, NUMBER_CHARS, GuestLink::numberChar);
        m.sceneCaptureType = text(b, NUMBER_CHARS, GuestLink::numberChar);
        m.documentId = text(b, ID_CHARS, GuestLink::idChar);
        m.instanceId = text(b, ID_CHARS, GuestLink::idChar);
        m.originalDocumentId = text(b, ID_CHARS, GuestLink::idChar);
        while (b.hasRemaining()) check(b.get() == 0, "reserved bytes");
        return m;
    }

    private interface CharRule {
        boolean ok(int c);
    }

    // A NUL-padded field: the text, then only NULs, at least one. Every text byte must pass the rule.
    private static String text(ByteBuffer b, int cap, CharRule rule) throws ProtocolException {
        byte[] f = new byte[cap];
        b.get(f);
        int len = 0;
        while (len < cap && f[len] != 0) len++;
        check(len < cap, "unterminated text");
        for (int i = 0; i < len; i++) check(rule.ok(f[i] & 0xff), "text byte");
        for (int i = len; i < cap; i++) check(f[i] == 0, "text padding");
        return new String(f, 0, len, StandardCharsets.US_ASCII);
    }

    static boolean printable(int c) {
        return c >= 0x20 && c <= 0x7e;
    }

    static boolean numberChar(int c) {
        return (c >= '0' && c <= '9') || c == '.' || c == '/' || c == ' ';
    }

    static boolean idChar(int c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == ':' || c == '.'
                || c == '-' || c == '_';
    }
}
