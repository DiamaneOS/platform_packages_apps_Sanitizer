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

    static final int FORMAT_JPEG = 1;
    static final int FORMAT_PNG = 2;

    static final int MAX_INPUT_BYTES = 32 << 20;
    static final int MAX_DIMENSION = 65535;
    static final int MAX_PIXELS = 8 << 20;

    static final int META_BYTES = 1024;
    static final int TEXT_CHARS = 256;
    static final int NUMBER_CHARS = 32;
    static final int ID_CHARS = 128;

    static final int HEADER_BYTES = 32;
    static final int END_BYTES = 8;

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

    /** A clean answer: a status, and for OK the checked values. */
    static final class Answer {
        int status;
        int format;
        int width;
        int height;
        int extra; // probe: animated, thumbnail: rotation
        byte[] pixels; // thumbnail
        Meta meta; // metadata
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

    private final Channel mChannel;
    private boolean mBroken;

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

    /** Test builds only: the VM's test image answers with a 1x1 thumbnail or fails, see vm/decoder_vm.cpp. */
    Answer hook(int hook, long deadlineMillis) throws IOException {
        return call(OP_HOOK, hook, 0, null, 0, 0, deadlineMillis);
    }

    private Answer call(int op, int arg0, int arg1, byte[] file, int len, int unused, long deadline)
            throws IOException {
        if (mBroken) throw new ProtocolException("link already broken");
        if (len < 0 || len > MAX_INPUT_BYTES || (file == null && len != 0) || (file != null && len > file.length)) {
            throw new IllegalArgumentException("input length");
        }
        try {
            ByteBuffer rq = ByteBuffer.allocate(HEADER_BYTES).order(ByteOrder.LITTLE_ENDIAN);
            rq.putInt(REQUEST_MAGIC).putInt(op).putInt(arg0).putInt(arg1).putInt(len);
            mChannel.write(rq.array(), 0, HEADER_BYTES, deadline);
            if (len > 0) mChannel.write(file, 0, len, deadline);

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
            if (a.status != OK) {
                check(a.status == UNSUPPORTED || a.status == INVALID || a.status == INTERNAL, "status");
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
                    // Only an animated PNG can be animated among the formats the VM reads.
                    check(a.extra == 0 || (a.extra == 1 && a.format == FORMAT_PNG), "animated");
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
                        check(a.width == 1 && a.height == 1, "hook size");
                    }
                    check((long) a.width * a.height <= MAX_PIXELS, "pixels");
                    check((long) payload == (long) a.width * a.height * 4, "pixel length");
                    byte[] pixels = readExact(payload, deadline).array();
                    // A worker that failed after its header: the VM kept the length with zeros and its trailer says
                    // INVALID. A clean verdict on the file, not a broken link.
                    ByteBuffer e = readExact(END_BYTES, deadline);
                    check(e.getInt() == END_MAGIC, "end");
                    int endStatus = e.getInt();
                    if (endStatus == INVALID) {
                        Answer bad = new Answer();
                        bad.status = INVALID;
                        return bad;
                    }
                    check(endStatus == OK, "end status " + endStatus);
                    checkPremultiplied(pixels);
                    a.pixels = pixels;
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
        } catch (IOException | RuntimeException e) {
            close();
            if (e instanceof ProtocolException) throw (ProtocolException) e;
            if (e instanceof IllegalArgumentException) throw (IllegalArgumentException) e;
            throw new ProtocolException(e.getClass().getSimpleName() + ": " + e.getMessage());
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
        }
        return ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN);
    }

    private static void check(boolean ok, String what) throws ProtocolException {
        if (!ok) throw new ProtocolException("bad " + what);
    }

    private static void checkFormat(int format) throws ProtocolException {
        check(format == FORMAT_JPEG || format == FORMAT_PNG, "format");
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
        check(m.specialFormat == 0 || m.specialFormat == 2, "special format");
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
