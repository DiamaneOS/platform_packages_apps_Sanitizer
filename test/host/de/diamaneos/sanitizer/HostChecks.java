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

import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * Host checks of the decode service's Android side, without a phone: GuestLink against a hostile fuzzing server
 * that plays a broken or malicious VM over a local socket, the Scheduler, the ResultCache, and Decoder's decisions
 * (retries, strikes, budget) against a fake VM. Plain Java with two small stubs (test/host/stubs): run with any JDK. Prints one line per check and "DONE pass=N fail=M", exits 1 on any failure.
 *
 * <p>The fuzzing server sends scripted bad replies, random bytes, and mutations of valid replies (bit flips, cut
 * streams, changed length and size fields, slow drips). Every call must end in a ProtocolException or an answer
 * that meets every rule, within its deadline, with no other exception.
 */
public final class HostChecks {
    private static int sPass;
    private static int sFail;

    private static void pass(String what, String detail) {
        sPass++;
        System.out.println("PASS " + what + (detail.isEmpty() ? "" : ": " + detail));
    }

    private static void fail(String what, String detail) {
        sFail++;
        System.out.println("FAIL " + what + (detail.isEmpty() ? "" : ": " + detail));
    }

    // --- A GuestLink channel over a TCP socket on the loopback, with real deadlines --------------------------------

    static final class SocketChannel implements GuestLink.Channel {
        private final Socket mSocket;
        private final InputStream mIn;
        private final OutputStream mOut;

        SocketChannel(Socket s) throws IOException {
            mSocket = s;
            mIn = s.getInputStream();
            mOut = s.getOutputStream();
        }

        private static long now() {
            return System.nanoTime() / 1000000;
        }

        @Override
        public int read(byte[] b, int off, int len, long deadline) throws IOException {
            long left = deadline - now();
            if (left <= 0) throw new InterruptedIOException("deadline");
            mSocket.setSoTimeout((int) Math.max(1, left));
            try {
                int n = mIn.read(b, off, len);
                return Math.max(n, 0);
            } catch (SocketTimeoutException e) {
                throw new InterruptedIOException("deadline");
            }
        }

        @Override
        public void write(byte[] b, int off, int len, long deadline) throws IOException {
            if (deadline - now() <= 0) throw new InterruptedIOException("deadline");
            mOut.write(b, off, len);
            mOut.flush();
        }

        @Override
        public void close() throws IOException {
            mSocket.close();
        }
    }

    interface Script {
        void serve(InputStream in, OutputStream out) throws Exception;
    }

    private static void readRequest(InputStream in) throws IOException {
        byte[] h = new byte[GuestLink.HEADER_BYTES];
        int got = 0;
        while (got < h.length) {
            int k = in.read(h, got, h.length - got);
            if (k <= 0) return;
            got += k;
        }
        long len = ByteBuffer.wrap(h).order(ByteOrder.LITTLE_ENDIAN).getInt(16) & 0xffffffffL;
        while (len > 0) {
            long k = in.skip(len);
            if (k <= 0) return;
            len -= k;
        }
    }

    private static final InetAddress LOOPBACK = InetAddress.getLoopbackAddress();
    private static final long T0 = System.nanoTime();

    private static long now() {
        return System.nanoTime() / 1000000;
    }

    // How long the last stub call took, from the request to its answer or exception, without the scripted VM's own
    // tail (it may still sleep after the client gave up).
    static long sLastCallMs;

    /** One call against a scripted VM. Returns the answer, or the exception it threw. */
    static Object stub(Script script, int op, int maxW, int maxH, long deadlineMillis) throws Exception {
        try (ServerSocket server = new ServerSocket(0, 1, LOOPBACK)) {
            Thread vm = new Thread(() -> {
                try (Socket s = server.accept()) {
                    readRequest(s.getInputStream());
                    script.serve(s.getInputStream(), s.getOutputStream());
                    s.getOutputStream().flush();
                } catch (Exception ignored) {
                    // the client may close first
                }
            });
            vm.start();
            Socket client = new Socket(LOOPBACK, server.getLocalPort());
            GuestLink link = new GuestLink(new SocketChannel(client));
            long start = now();
            long deadline = start + deadlineMillis;
            byte[] file = {(byte) 0xff, (byte) 0xd8, (byte) 0xff, 0};
            Object result;
            try {
                switch (op) {
                    case GuestLink.OP_THUMBNAIL: result = link.thumbnail(file, file.length, maxW, maxH, deadline);
                        break;
                    case GuestLink.OP_METADATA: result = link.metadata(file, file.length, deadline); break;
                    case GuestLink.OP_FRAMES: result = link.frames(file, file.length, maxW, maxH, deadline); break;
                    default: result = link.probe(file, file.length, deadline); break;
                }
            } catch (IOException e) {
                result = e;
            } catch (RuntimeException e) {
                result = e; // a failure of the checks themselves: reported as unexpected
            }
            sLastCallMs = now() - start;
            link.close();
            vm.interrupt();
            vm.join(5000);
            return result;
        }
    }

    static byte[] reply(int magic, int status, int format, int w, int h, int extra, int payload) {
        return reply(magic, status, format, w, h, extra, payload, 0);
    }

    static byte[] reply(int magic, int status, int format, int w, int h, int extra, int payload, int colorSpace) {
        return ByteBuffer.allocate(32).order(ByteOrder.LITTLE_ENDIAN).putInt(magic).putInt(status).putInt(format)
                .putInt(w).putInt(h).putInt(extra).putInt(payload).putInt(colorSpace).array();
    }

    static byte[] end(int status) {
        return ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putInt(GuestLink.END_MAGIC).putInt(status)
                .array();
    }

    static byte[] cat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) n += p.length;
        ByteBuffer b = ByteBuffer.allocate(n);
        for (byte[] p : parts) b.put(p);
        return b.array();
    }

    static byte[] meta(int flags, int w, int h, int orientation, long date, String description, String id) {
        return meta(GuestLink.FORMAT_JPEG, 0, flags, w, h, orientation, date, description, id);
    }

    static byte[] meta(int format, int special, int flags, int w, int h, int orientation, long date,
            String description, String id) {
        ByteBuffer b = ByteBuffer.allocate(GuestLink.META_BYTES).order(ByteOrder.LITTLE_ENDIAN);
        b.putInt(GuestLink.META_MAGIC).putInt(1).putInt(flags).putInt(format).putInt(w).putInt(h)
                .putInt(orientation).putInt(special).putLong(date).putInt(0).putInt(0);
        b.put(description.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1));
        b.position(432);
        b.put(id.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1));
        return b.array();
    }

    /** Every rule an accepted answer must meet. Null when it does, else what it broke. */
    static String broken(Object r, int op, int maxW, int maxH) {
        if (!(r instanceof GuestLink.Answer)) return null;
        GuestLink.Answer a = (GuestLink.Answer) r;
        if (a.status != GuestLink.OK) {
            boolean clean = a.status == GuestLink.UNSUPPORTED || a.status == GuestLink.INVALID
                    || a.status == GuestLink.INTERNAL || a.status == GuestLink.BUSY;
            return clean && a.pixels == null && a.meta == null ? null : "bad failure answer " + a.status;
        }
        if (a.format < GuestLink.FORMAT_JPEG || a.format > GuestLink.FORMAT_WBMP) return "format";
        if (op == GuestLink.OP_FRAMES) {
            if (a.format != GuestLink.FORMAT_GIF && a.format != GuestLink.FORMAT_WEBP) return "frames format";
            if (a.width < 1 || a.height < 1 || a.width > maxW || a.height > maxH) return "size";
            if (a.extra < 1 || a.extra > GuestLink.MAX_FRAMES || a.durations == null || a.durations.length != a.extra) {
                return "frame count";
            }
            if (a.pixels == null || a.pixels.length != (long) a.extra * a.width * a.height * 4) return "pixel length";
            if (a.pixels.length > GuestLink.MAX_FRAMES_BYTES) return "too many bytes";
            for (int d : a.durations) if (d < 0 || d > GuestLink.MAX_FRAME_MILLIS) return "duration";
            for (int i = 0; i < a.pixels.length; i += 4) {
                int al = a.pixels[i + 3] & 0xff;
                for (int c = 0; c < 3; c++) if ((a.pixels[i + c] & 0xff) > al) return "colour above alpha";
            }
            return null;
        }
        if (op == GuestLink.OP_THUMBNAIL) {
            boolean turned = a.extra == 90 || a.extra == 270;
            if (a.extra != 0 && a.extra != 180 && !turned) return "rotation";
            int bw = turned ? maxH : maxW, bh = turned ? maxW : maxH;
            if (a.width < 1 || a.height < 1 || a.width > bw || a.height > bh) return "size";
            if (a.pixels == null || a.pixels.length != a.width * a.height * 4) return "pixel length";
            for (int i = 0; i < a.pixels.length; i += 4) {
                int al = a.pixels[i + 3] & 0xff;
                for (int c = 0; c < 3; c++) if ((a.pixels[i + c] & 0xff) > al) return "colour above alpha";
            }
        } else if (op == GuestLink.OP_METADATA) {
            GuestLink.Meta m = a.meta;
            if (m == null) return "no record";
            for (String t : new String[] {m.description, m.exposureTime, m.fNumber, m.iso, m.sceneCaptureType,
                    m.documentId, m.instanceId, m.originalDocumentId}) {
                for (char ch : t.toCharArray()) if (ch < 0x20 || ch > 0x7e) return "text character " + (int) ch;
            }
            if (m.description.length() >= GuestLink.TEXT_CHARS || m.documentId.length() >= GuestLink.ID_CHARS) {
                return "text length";
            }
        } else {
            if (a.extra != 0 && !(a.extra == 1 && GuestLink.mayBeAnimated(a.format))) {
                return "animated";
            }
        }
        return null;
    }

    static void expectRefused(String what, Script s, int op) throws Exception {
        Object r = stub(s, op, 2, 1, 2000);
        long ms = sLastCallMs;
        if (r instanceof GuestLink.ProtocolException && ms < 2200) {
            pass("stub " + what, ((Exception) r).getMessage() + ", " + ms + " ms");
        } else {
            fail("stub " + what, r + ", " + ms + " ms");
        }
    }

    static void linkChecks() throws Exception {
        vmImageChecks();
        int R = GuestLink.REPLY_MAGIC;
        byte[] px = {1, 2, 3, 4, 5, 6, 7, 8};
        Object ok = stub((in, out) -> out.write(cat(reply(R, 0, 1, 2, 1, 0, 8), px, end(0))),
                GuestLink.OP_THUMBNAIL, 2, 1, 2000);
        if (ok instanceof GuestLink.Answer && broken(ok, GuestLink.OP_THUMBNAIL, 2, 1) == null
                && ((GuestLink.Answer) ok).pixels.length == 8) {
            pass("control thumbnail", "");
        } else {
            fail("control thumbnail", String.valueOf(ok));
        }
        // The colour space: Display P3 on a thumbnail is fine, anything else, or on another answer, breaks the link.
        Object p3 = stub((in, out) -> out.write(cat(reply(R, 0, 1, 2, 1, 0, 8, GuestLink.COLOR_DISPLAY_P3), px,
                end(0))), GuestLink.OP_THUMBNAIL, 2, 1, 2000);
        if (p3 instanceof GuestLink.Answer && ((GuestLink.Answer) p3).colorSpace == GuestLink.COLOR_DISPLAY_P3) {
            pass("stub thumbnail in Display P3", "");
        } else {
            fail("stub thumbnail in Display P3", String.valueOf(p3));
        }
        expectRefused("unknown colour space", (in, out) -> out.write(cat(reply(R, 0, 1, 2, 1, 0, 8, 2), px, end(0))),
                GuestLink.OP_THUMBNAIL);
        expectRefused("colour space on a failure", (in, out) -> out.write(cat(reply(R, 3, 0, 0, 0, 0, 0, 1),
                end(3))), GuestLink.OP_THUMBNAIL);
        // Frames: two 1x1 frames with their times and a loop count, checked like a thumbnail's pixels.
        byte[] two = ByteBuffer.allocate(4 + 2 * 8).order(ByteOrder.LITTLE_ENDIAN).putInt(3).putInt(100)
                .put(new byte[] {1, 2, 3, 4}).putInt(40).put(new byte[] {5, 6, 7, 8}).array();
        Object fr = stub((in, out) -> out.write(cat(reply(R, 0, GuestLink.FORMAT_GIF, 1, 1, 2, two.length), two,
                end(0))), GuestLink.OP_FRAMES, 2, 1, 2000);
        if (fr instanceof GuestLink.Answer && ((GuestLink.Answer) fr).loops == 3
                && java.util.Arrays.equals(((GuestLink.Answer) fr).durations, new int[] {100, 40})
                && broken(fr, GuestLink.OP_FRAMES, 2, 1) == null) {
            pass("stub frames", "");
        } else {
            fail("stub frames", String.valueOf(fr));
        }
        byte[] slow = two.clone();
        ByteBuffer.wrap(slow).order(ByteOrder.LITTLE_ENDIAN).putInt(4, 70000);
        expectRefused("frame longer than the limit", (in, out) -> out.write(cat(reply(R, 0, GuestLink.FORMAT_GIF, 1, 1,
                2, slow.length), slow, end(0))), GuestLink.OP_FRAMES);
        expectRefused("frames of the wrong length", (in, out) -> out.write(cat(reply(R, 0, GuestLink.FORMAT_GIF, 1, 1,
                3, two.length), two, end(0))), GuestLink.OP_FRAMES);
        expectRefused("frames of a JPEG", (in, out) -> out.write(cat(reply(R, 0, GuestLink.FORMAT_JPEG, 1, 1, 2,
                two.length), two, end(0))), GuestLink.OP_FRAMES);
        byte[] above = two.clone();
        above[8] = 9; // red 9 over alpha 4
        expectRefused("frame colour above alpha", (in, out) -> out.write(cat(reply(R, 0, GuestLink.FORMAT_GIF, 1, 1,
                2, above.length), above, end(0))), GuestLink.OP_FRAMES);
        long date = System.currentTimeMillis() - 86400000L;
        Object okm = stub((in, out) -> out.write(cat(reply(R, 0, 1, 4, 3, 0, 1024),
                meta(3, 4, 3, 90, date, "A camera", "xmp.did:1"), end(0))), GuestLink.OP_METADATA, 0, 0, 2000);
        if (okm instanceof GuestLink.Answer && "xmp.did:1".equals(((GuestLink.Answer) okm).meta.documentId)) {
            pass("control metadata", "");
        } else {
            fail("control metadata", String.valueOf(okm));
        }
        Object late = stub((in, out) -> out.write(cat(reply(R, 0, 1, 2, 1, 0, 8), new byte[8], end(3))),
                GuestLink.OP_THUMBNAIL, 2, 1, 2000);
        if (late instanceof GuestLink.Answer && ((GuestLink.Answer) late).status == GuestLink.INVALID) {
            pass("late failure is a clean INVALID", "");
        } else {
            fail("late failure is a clean INVALID", String.valueOf(late));
        }
        Object turned = stub((in, out) -> out.write(cat(reply(R, 0, 1, 1, 2, 90, 8), px, end(0))),
                GuestLink.OP_THUMBNAIL, 2, 1, 2000);
        if (turned instanceof GuestLink.Answer && ((GuestLink.Answer) turned).status == GuestLink.OK) {
            pass("turned box accepted", "");
        } else {
            fail("turned box accepted", String.valueOf(turned));
        }
        expectRefused("wrong magic", (in, out) -> out.write(cat(reply(0x41414141, 0, 1, 2, 1, 0, 8), px, end(0))),
                GuestLink.OP_THUMBNAIL);
        expectRefused("larger than asked", (in, out) -> out.write(cat(reply(R, 0, 1, 3, 1, 0, 12), new byte[12],
                end(0))), GuestLink.OP_THUMBNAIL);
        expectRefused("turned box unturned size", (in, out) -> out.write(cat(reply(R, 0, 1, 2, 1, 90, 8), px,
                end(0))), GuestLink.OP_THUMBNAIL);
        expectRefused("length not w*h*4", (in, out) -> out.write(cat(reply(R, 0, 1, 2, 1, 0, 12), new byte[12],
                end(0))), GuestLink.OP_THUMBNAIL);
        expectRefused("huge length", (in, out) -> out.write(reply(R, 0, 1, 2, 1, 0, Integer.MAX_VALUE)),
                GuestLink.OP_THUMBNAIL);
        expectRefused("negative size", (in, out) -> out.write(cat(reply(R, 0, 1, -1, 1, 0, -4), end(0))),
                GuestLink.OP_THUMBNAIL);
        expectRefused("colour above alpha", (in, out) -> out.write(cat(reply(R, 0, 1, 2, 1, 0, 8),
                new byte[] {9, 0, 0, 1, 0, 0, 0, 0}, end(0))), GuestLink.OP_THUMBNAIL);
        expectRefused("rotation 45", (in, out) -> out.write(cat(reply(R, 0, 1, 2, 1, 45, 8), px, end(0))),
                GuestLink.OP_THUMBNAIL);
        expectRefused("no trailer", (in, out) -> out.write(cat(reply(R, 0, 1, 2, 1, 0, 8), px)),
                GuestLink.OP_THUMBNAIL);
        expectRefused("trailer status 7", (in, out) -> out.write(cat(reply(R, 0, 1, 2, 1, 0, 8), px, end(7))),
                GuestLink.OP_THUMBNAIL);
        expectRefused("cut pixels", (in, out) -> out.write(cat(reply(R, 0, 1, 2, 1, 0, 8), new byte[5])),
                GuestLink.OP_THUMBNAIL);
        expectRefused("slow drip", (in, out) -> {
            for (byte b : cat(reply(R, 0, 1, 2, 1, 0, 8), px, end(0))) {
                out.write(b);
                out.flush();
                Thread.sleep(400);
            }
        }, GuestLink.OP_THUMBNAIL);
        expectRefused("silent VM", (in, out) -> Thread.sleep(4000), GuestLink.OP_THUMBNAIL);
        expectRefused("unknown status", (in, out) -> out.write(cat(reply(R, 7, 0, 0, 0, 0, 0), end(7))),
                GuestLink.OP_PROBE);
        expectRefused("failure with values", (in, out) -> out.write(cat(reply(R, 3, 1, 5, 5, 0, 0), end(3))),
                GuestLink.OP_PROBE);
        expectRefused("animated JPEG", (in, out) -> out.write(cat(reply(R, 0, 1, 5, 5, 1, 0), end(0))),
                GuestLink.OP_PROBE);
        expectRefused("format 11", (in, out) -> out.write(cat(reply(R, 0, 11, 5, 5, 0, 0), end(0))),
                GuestLink.OP_PROBE);
        expectRefused("animated BMP", (in, out) -> out.write(cat(reply(R, 0, 5, 5, 5, 1, 0), end(0))),
                GuestLink.OP_PROBE);
        expectRefused("meta GIF marker on a JPEG", (in, out) -> out.write(cat(reply(R, 0, 1, 4, 3, 0, 1024),
                meta(GuestLink.FORMAT_JPEG, 1, 0, 4, 3, -1, -1, "", ""), end(0))), GuestLink.OP_METADATA);
        expectRefused("meta animated WebP marker on a PNG", (in, out) -> out.write(cat(reply(R, 0, 2, 4, 3, 0, 1024),
                meta(GuestLink.FORMAT_PNG, 3, 0, 4, 3, -1, -1, "", ""), end(0))), GuestLink.OP_METADATA);
        streamChecks();
        mountChecks();
        // The new formats' answers are accepted: an animated GIF's probe, a GIF's record with its marker.
        Object gif = stub((in, out) -> out.write(cat(reply(R, 0, 3, 5, 4, 1, 0), end(0))), GuestLink.OP_PROBE, 0, 0,
                2000);
        Object gifMeta = stub((in, out) -> out.write(cat(reply(R, 0, 3, 4, 3, 0, 1024),
                meta(GuestLink.FORMAT_GIF, 1, 0, 4, 3, -1, -1, "", ""), end(0))), GuestLink.OP_METADATA, 0, 0, 2000);
        if (gif instanceof GuestLink.Answer && ((GuestLink.Answer) gif).extra == 1
                && gifMeta instanceof GuestLink.Answer && ((GuestLink.Answer) gifMeta).meta.specialFormat == 1) {
            pass("animated GIF probe and GIF record accepted", "");
        } else {
            fail("animated GIF probe and GIF record accepted", gif + " " + gifMeta);
        }
        expectRefused("meta control char", (in, out) -> out.write(cat(reply(R, 0, 1, 4, 3, 0, 1024),
                meta(1, 4, 3, 90, -1, "A\u001bcamera", ""), end(0))), GuestLink.OP_METADATA);
        expectRefused("meta line separator", (in, out) -> out.write(cat(reply(R, 0, 1, 4, 3, 0, 1024),
                meta(1, 4, 3, 90, -1, "Aâ\u0080¨camera", ""), end(0))), GuestLink.OP_METADATA);
        // A date in the future is the file's or the phone clock's matter, not a broken link: the record is accepted
        // (DecodeChecks.dropFutureDate drops the date later). A date outside 1900 to 9999 is still a break.
        Object future = stub((in, out) -> out.write(cat(reply(R, 0, 1, 4, 3, 0, 1024),
                meta(3, 4, 3, 90, System.currentTimeMillis() + 3 * 86400000L, "", ""), end(0))),
                GuestLink.OP_METADATA, 2, 1, 2000);
        if (future instanceof GuestLink.Answer && ((GuestLink.Answer) future).meta != null) {
            pass("stub meta future date accepted", "");
        } else {
            fail("stub meta future date accepted", String.valueOf(future));
        }
        expectRefused("meta year 10000", (in, out) -> out.write(cat(reply(R, 0, 1, 4, 3, 0, 1024),
                meta(3, 4, 3, 90, 253402300799999L + 3 * 86400000L, "", ""), end(0))), GuestLink.OP_METADATA);
        expectRefused("meta unterminated id", (in, out) -> out.write(cat(reply(R, 0, 1, 4, 3, 0, 1024),
                meta(1, 4, 3, 90, -1, "", "a".repeat(128)), end(0))), GuestLink.OP_METADATA);
        expectRefused("meta size mismatch", (in, out) -> out.write(cat(reply(R, 0, 1, 4, 3, 0, 1024),
                meta(1, 5, 3, 90, -1, "", ""), end(0))), GuestLink.OP_METADATA);
        expectRefused("meta orientation without flag", (in, out) -> out.write(cat(reply(R, 0, 1, 4, 3, 0, 1024),
                meta(0, 4, 3, 90, -1, "", ""), end(0))), GuestLink.OP_METADATA);
    }

    // The VM manager's label rule for a protected VM's kernel files (virtmgr's own test cases, and the label of the
    // copy in app data an earlier version made, which the phone refused).
    static void vmImageChecks() {
        Object[][] cases = {
            {"u:object_r:system_file:s0", true},
            {"u:object_r:shell_data_file:s0", true},
            {"u:object_r:apk_data_file:s0", true},
            {"u:object_r:app_data_file:s0", false},
            {"u:object_r:app_data_file:s0:c512,c768", false},
            {"u:object_r:privapp_data_file:s0:c512,c768", false},
            {"invalid", false},
            {"user:role:apk_data_file:severity:categories", true},
            {"user:role:apk_data_file:severity:categories:extraneous", false},
            {"u:object_r:vendor_unknowable:s0", false},
        };
        int bad = 0;
        for (Object[] c : cases) {
            if (VmImages.virtmgrAllows((String) c[0]) != (Boolean) c[1]) bad++;
        }
        // The product takes system_file alone, the self-test also shell_data_file.
        if (!VmImages.labelAllowed("u:object_r:system_file:s0", false)) bad++;
        if (VmImages.labelAllowed("u:object_r:shell_data_file:s0", false)) bad++;
        if (VmImages.labelAllowed("u:object_r:apk_data_file:s0", false)) bad++;
        if (!VmImages.labelAllowed("u:object_r:shell_data_file:s0", true)) bad++;
        if (VmImages.labelAllowed("u:object_r:app_data_file:s0:c512,c768", true)) bad++;
        if (bad == 0) pass("VM image labels as the VM manager takes them", cases.length + " labels");
        else fail("VM image labels as the VM manager takes them", bad + " wrong");
    }

    // A file sent from a source arrives whole, in order, and a source that ends early drops the link.
    static void streamChecks() throws Exception {
        int R = GuestLink.REPLY_MAGIC;
        byte[] big = new byte[3 * 64 * 1024 + 12345];
        new Random(7).nextBytes(big);
        try (ServerSocket server = new ServerSocket(0, 1, LOOPBACK)) {
            byte[][] seen = {null};
            Thread vm = new Thread(() -> {
                try (Socket s = server.accept()) {
                    java.io.DataInputStream in = new java.io.DataInputStream(s.getInputStream());
                    byte[] h = new byte[GuestLink.HEADER_BYTES];
                    in.readFully(h);
                    int len = ByteBuffer.wrap(h).order(ByteOrder.LITTLE_ENDIAN).getInt(16);
                    byte[] body = new byte[len];
                    in.readFully(body);
                    seen[0] = body;
                    s.getOutputStream().write(cat(reply(R, 0, 1, 2, 1, 0, 8), new byte[] {1, 2, 3, 4, 5, 6, 7, 8},
                            end(0)));
                } catch (Exception ignored) {
                    // the check below reports it
                }
            });
            vm.start();
            GuestLink link = new GuestLink(new SocketChannel(new Socket(LOOPBACK, server.getLocalPort())));
            GuestLink.Answer a = link.call(GuestLink.OP_THUMBNAIL, 2, 1, GuestLink.source(big, big.length),
                    now() + 5000);
            vm.join(5000);
            link.close();
            if (a.status == 0 && java.util.Arrays.equals(seen[0], big)) {
                pass("streamed source arrives whole", big.length + " bytes in pieces");
            } else {
                fail("streamed source arrives whole", show(a));
            }
        }
        GuestLink.Source broken = new GuestLink.Source() {
            int mCalls;

            @Override public long length() {
                return 200000;
            }

            @Override public void readFully(byte[] b, int off, int len, long deadline) throws IOException {
                if (++mCalls > 1) throw new IOException("file ended early");
            }
        };
        try (ServerSocket server = new ServerSocket(0, 1, LOOPBACK)) {
            Thread vm = new Thread(() -> {
                try (Socket s = server.accept()) {
                    s.getInputStream().readAllBytes();
                } catch (Exception ignored) {
                    // the client goes away
                }
            });
            vm.start();
            GuestLink link = new GuestLink(new SocketChannel(new Socket(LOOPBACK, server.getLocalPort())));
            Object r;
            try {
                r = link.call(GuestLink.OP_THUMBNAIL, 2, 1, broken, now() + 3000);
            } catch (IOException e) {
                r = e;
            }
            boolean dropped;
            try {
                link.ping(now() + 1000);
                dropped = false;
            } catch (IOException e) {
                dropped = true;
            }
            link.close();
            vm.join(5000);
            // A failure of the caller's file, told apart from a broken VM: the connection is closed, nothing more.
            if (r instanceof GuestLink.SourceFailedException && dropped) {
                pass("source ending early is a source failure and drops the connection", String.valueOf(r));
            } else {
                fail("source ending early is a source failure and drops the connection", r + " dropped " + dropped);
            }
        }
    }

    // Which files the service may stream: only those whose own device the mount table names as local, every mount
    // of it local. Unknown devices, FUSE, vfat and mixed devices are not streamed.
    /** Who may call: on a user build exactly the two production callers, the client tests on a debuggable build only. */
    static void callerChecks() {
        String[] user = Callers.allowed(false);
        check("callers: a user build has exactly the two production callers",
                java.util.Arrays.equals(user, new String[] {"com.android.providers.media.module", "com.android.systemui"}),
                java.util.Arrays.toString(user));
        String[] debug = Callers.allowed(true);
        check("callers: a debuggable build adds the client tests and nothing else",
                java.util.Arrays.equals(debug, new String[] {"com.android.providers.media.module", "com.android.systemui",
                        "de.diamaneos.decode.client.tests"}),
                java.util.Arrays.toString(debug));
        user[0] = "changed";
        check("callers: the list handed out is a copy", Callers.allowed(false)[0].equals("com.android.providers.media.module")
                && Callers.PRODUCTION[0].equals("com.android.providers.media.module"), Callers.allowed(false)[0]);
    }

    static void mountChecks() {
        String mi = String.join("\n",
                "1 0 254:0 / / ro,relatime - erofs /dev/block/dm-0 ro",
                "40 1 254:50 / /data rw,nosuid,nodev - f2fs /dev/block/dm-50 rw",
                "90 40 0:44 / /storage/emulated rw,nosuid,nodev - fuse /dev/fuse rw,user_id=0",
                "91 90 254:50 /media/0/Android/data /storage/emulated/0/Android/data rw - f2fs /dev/block/dm-50 rw",
                "95 1 8:1 / /mnt/media_rw/ABCD rw - vfat /dev/block/vold/public:8,1 rw",
                "96 1 254:60 / /mnt/a rw - ext4 /dev/block/dm-60 rw",
                "97 1 254:60 / /mnt/b rw - fuseblk /dev/block/dm-60 rw",
                "98 1 179:65 / /mnt/media_rw/1234-5678 rw - ext4 /dev/block/vold/public:179,65 rw",
                "99 1 8:17 / /mnt/x rw - f2fs /dev/block/vold/public:8,17 rw");
        Object[][] cases = {
            {254, 50, true},   // /data, also bind-mounted under the FUSE tree
            {254, 0, true},    // the system partition
            {0, 44, false},    // the FUSE mount itself
            {8, 1, false},     // a USB drive (vfat)
            {254, 60, false},  // one device, one mount of it not local
            {0, 1, false},     // not in the table (an internal mount, a memory file)
            {179, 65, false},  // an SD card formatted ext4: removable, never local
            {8, 17, false},    // a USB drive formatted f2fs, from vold's public volumes
        };
        int bad = 0;
        for (Object[] c : cases) {
            if (Mounts.localDevice((Integer) c[0], (Integer) c[1], mi) != (Boolean) c[2]) bad++;
        }
        // dev_t encoding: major 254, minor 50, and a large minor.
        long dev = (254L << 8) | 50;
        if (Mounts.major(dev) != 254 || Mounts.minor(dev) != 50) bad++;
        long big = ((300L & 0xff) | ((300L & ~0xffL) << 12)) | (7L << 8);
        if (Mounts.major(big) != 7 || Mounts.minor(big) != 300) bad++;
        if (bad == 0) pass("local device check by mount table", cases.length + " devices, dev_t decoding");
        else fail("local device check by mount table", bad + " wrong");
    }

    // The fuzzing server: random replies, then mutations of valid ones.
    static void fuzz(int rounds) throws Exception {
        Random rnd = new Random(20261117);
        int R = GuestLink.REPLY_MAGIC;
        byte[][] seeds = {
            cat(reply(R, 0, 1, 2, 1, 0, 8), new byte[] {1, 2, 3, 4, 5, 6, 7, 8}, end(0)),
            cat(reply(R, 0, 2, 1, 2, 90, 8), new byte[] {0, 0, 0, 0, 9, 9, 9, 9}, end(0)),
            cat(reply(R, 0, 1, 2, 1, 0, 8), new byte[8], end(3)),
            cat(reply(R, 0, 1, 4, 3, 0, 1024), meta(15, 4, 3, 180, 1700000000000L, "Holiday", "uuid:x-1"), end(0)),
            cat(reply(R, 0, 2, 7, 9, 1, 0), end(0)),
            cat(reply(R, 3, 0, 0, 0, 0, 0), end(3)),
        };
        int[] ops = {GuestLink.OP_THUMBNAIL, GuestLink.OP_THUMBNAIL, GuestLink.OP_THUMBNAIL, GuestLink.OP_METADATA,
            GuestLink.OP_PROBE, GuestLink.OP_PROBE};
        int refused = 0, accepted = 0, bad = 0;
        long worst = 0;
        List<String> problems = new ArrayList<>();
        for (int i = 0; i < rounds; i++) {
            int s = rnd.nextInt(seeds.length + 1);
            byte[] reply;
            int op;
            if (s == seeds.length) {
                reply = new byte[rnd.nextInt(2200)];
                rnd.nextBytes(reply);
                op = new int[] {GuestLink.OP_THUMBNAIL, GuestLink.OP_METADATA, GuestLink.OP_PROBE}[rnd.nextInt(3)];
            } else {
                reply = seeds[s].clone();
                op = ops[s];
                int k = 1 + rnd.nextInt(4);
                for (int j = 0; j < k; j++) {
                    int at = rnd.nextInt(reply.length);
                    switch (rnd.nextInt(5)) {
                        case 0: reply[at] = (byte) rnd.nextInt(); break;
                        case 1: reply[at] ^= (byte) (1 << rnd.nextInt(8)); break;
                        case 2: reply = java.util.Arrays.copyOf(reply, at); break;
                        case 3: if (reply.length >= 32) ByteBuffer.wrap(reply).order(ByteOrder.LITTLE_ENDIAN)
                                .putInt(4 * (3 + rnd.nextInt(5)), rnd.nextInt(5) == 0 ? -1 : rnd.nextInt(70000));
                            break;
                        default: reply = cat(reply, new byte[rnd.nextInt(64)]); break;
                    }
                    if (reply.length == 0) break;
                }
            }
            byte[] send = reply;
            boolean drip = rnd.nextInt(50) == 0;
            int maxW = 1 + rnd.nextInt(4), maxH = 1 + rnd.nextInt(4);
            Object r = stub((in, out) -> {
                if (drip) {
                    for (byte b : send) {
                        out.write(b);
                        out.flush();
                        Thread.sleep(50);
                    }
                } else {
                    out.write(send);
                }
            }, op, maxW, maxH, 1500);
            long ms = sLastCallMs;
            worst = Math.max(worst, ms);
            String why = broken(r, op, maxW, maxH);
            if (r instanceof GuestLink.ProtocolException) {
                refused++;
            } else if (r instanceof GuestLink.Answer && why == null) {
                accepted++;
            } else {
                bad++;
                if (problems.size() < 5) problems.add(r + " " + why);
            }
        }
        if (bad == 0 && worst < 1700) {
            pass("fuzzing server", rounds + " replies: " + refused + " refused, " + accepted
                    + " accepted within every rule, worst " + worst + " ms");
        } else {
            fail("fuzzing server", bad + " broke a rule or threw: " + problems + ", worst " + worst + " ms");
        }
    }

    static void schedulerChecks() throws Exception {
        Scheduler s = new Scheduler();
        List<Scheduler.Job> flood = new ArrayList<>();
        int accepted = 0;
        for (int i = 0; i < 40; i++) {
            Scheduler.Job j = new Scheduler.Job("flooder", false, 1) {
                @Override void run() {}
            };
            if (s.offer(j)) accepted++;
            flood.add(j);
        }
        Scheduler.Job other = new Scheduler.Job("other", false, Long.MAX_VALUE) {
            @Override void run() {}
        };
        Scheduler.Job urgent = new Scheduler.Job("flooder", true, Long.MAX_VALUE) {
            @Override void run() {}
        };
        boolean otherIn = s.offer(other);
        boolean urgentIn = s.offer(urgent);
        Scheduler.Job first = s.take(); // an expired job is still handed out, so its holder can release
        Scheduler.Job second = s.take();
        int drained = 2;
        while (s.size() > 0) {
            s.take();
            drained++;
        }
        boolean ok = accepted == Scheduler.MAX_PER_LANE && otherIn && !urgentIn && first == flood.get(0)
                && second == other && drained == accepted + 1;
        Scheduler s2 = new Scheduler();
        Scheduler.Job bg = new Scheduler.Job("x", false, Long.MAX_VALUE) {
            @Override void run() {}
        };
        Scheduler.Job fg = new Scheduler.Job("y", true, Long.MAX_VALUE) {
            @Override void run() {}
        };
        s2.offer(bg);
        s2.offer(fg);
        ok &= s2.take() == fg;
        // Aging: a steady stream of waiting jobs lets one background job through after every WAITING_BURST.
        Scheduler s4 = new Scheduler();
        Scheduler.Job slowBg = new Scheduler.Job("scan", false, Long.MAX_VALUE) {
            @Override void run() {}
        };
        s4.offer(slowBg);
        int servedBefore = -1;
        for (int i = 0; i < 2 * Scheduler.WAITING_BURST && servedBefore < 0; i++) {
            s4.offer(new Scheduler.Job("app" + (i % 3), true, Long.MAX_VALUE) {
                @Override void run() {}
            });
            s4.offer(new Scheduler.Job("app" + (i % 3), true, Long.MAX_VALUE) {
                @Override void run() {}
            });
            if (s4.take() == slowBg) servedBefore = i;
        }
        check("scheduler: background work ages past a stream of waiting jobs",
                servedBefore == Scheduler.WAITING_BURST, "background served at take " + servedBefore);
        // The total cap: many lanes fill the queue to MAX_TOTAL and no further.
        Scheduler s3 = new Scheduler();
        int total = 0;
        for (int lane = 0; lane < 20; lane++) {
            for (int i = 0; i < Scheduler.MAX_PER_LANE; i++) {
                if (s3.offer(new Scheduler.Job("l" + lane, false, 1) {
                    @Override void run() {}
                })) {
                    total++;
                }
            }
        }
        ok &= total == Scheduler.MAX_TOTAL;
        if (ok) {
            pass("scheduler", "flood capped at " + accepted + ", other lane second, user first, expired jobs handed"
                    + " out, total capped at " + total);
        } else {
            fail("scheduler", "accepted " + accepted + " other " + otherIn + " urgent " + urgentIn + " drained "
                    + drained + " total " + total);
        }
    }

    static void cacheChecks() {
        ResultCache c = new ResultCache();
        GuestLink.Answer big = new GuestLink.Answer();
        big.pixels = new byte[ResultCache.MAX_ENTRY_BYTES + 1];
        Object kBig = ResultCache.key(new byte[32], 3, 1, 1, 0);
        c.put(kBig, big);
        boolean ok = c.get(kBig) == null;
        int stored = 0;
        for (int i = 0; i < 40; i++) {
            GuestLink.Answer a = new GuestLink.Answer();
            a.pixels = new byte[1 << 20];
            byte[] d = new byte[32];
            d[0] = (byte) i;
            c.put(ResultCache.key(d, 3, 1, 1, 0), a);
        }
        for (int i = 0; i < 40; i++) {
            byte[] d = new byte[32];
            d[0] = (byte) i;
            if (c.get(ResultCache.key(d, 3, 1, 1, 0)) != null) stored++;
        }
        ok &= stored > 0 && stored * ((1 << 20) + 1024L) <= ResultCache.MAX_BYTES;
        byte[] d = new byte[32];
        d[0] = 39;
        ok &= c.get(ResultCache.key(d, 3, 1, 1, 0)) != null && c.get(ResultCache.key(d, 3, 2, 1, 0)) == null;
        if (ok) pass("result cache", stored + " of 40 one-MiB answers kept, oversize refused, keys exact");
        else fail("result cache", "stored " + stored);
    }

    // --- The real VM program, built for the build machine (decoder_vm_hosttest), over a Unix socket ---------------

    static final class UnixChannel implements GuestLink.Channel {
        private final java.nio.channels.SocketChannel mCh;
        private final java.nio.channels.Selector mSel;

        UnixChannel(String path) throws IOException {
            mCh = java.nio.channels.SocketChannel.open(java.net.StandardProtocolFamily.UNIX);
            mCh.connect(java.net.UnixDomainSocketAddress.of(path));
            mCh.configureBlocking(false);
            mSel = java.nio.channels.Selector.open();
        }

        private void await(int ops, long deadline) throws IOException {
            for (;;) {
                long left = deadline - now();
                if (left <= 0) throw new InterruptedIOException("deadline");
                java.nio.channels.SelectionKey k = mCh.register(mSel, ops);
                int n = mSel.select(left);
                mSel.selectedKeys().clear();
                k.interestOps(0);
                if (n > 0) return;
            }
        }

        @Override
        public int read(byte[] b, int off, int len, long deadline) throws IOException {
            for (;;) {
                int n = mCh.read(java.nio.ByteBuffer.wrap(b, off, len));
                if (n < 0) return 0;
                if (n > 0) return n;
                await(java.nio.channels.SelectionKey.OP_READ, deadline);
            }
        }

        @Override
        public void write(byte[] b, int off, int len, long deadline) throws IOException {
            java.nio.ByteBuffer buf = java.nio.ByteBuffer.wrap(b, off, len);
            while (buf.hasRemaining()) {
                if (mCh.write(buf) == 0) await(java.nio.channels.SelectionKey.OP_WRITE, deadline);
            }
        }

        @Override
        public void close() throws IOException {
            mSel.close();
            mCh.close();
        }
    }

    static byte[] file(java.io.File dir, String name) throws IOException {
        return java.nio.file.Files.readAllBytes(new java.io.File(dir, name).toPath());
    }

    static byte[] replace(byte[] in, byte[] from, byte[] to) {
        byte[] out = in.clone();
        outer:
        for (int i = 0; i + from.length <= in.length; i++) {
            for (int j = 0; j < from.length; j++) if (in[i + j] != from[j]) continue outer;
            System.arraycopy(to, 0, out, i, to.length);
            return out;
        }
        return out;
    }

    static String show(Object r) {
        if (!(r instanceof GuestLink.Answer)) return String.valueOf(r);
        GuestLink.Answer a = (GuestLink.Answer) r;
        return "status " + a.status + (a.status == 0 ? " " + a.width + "x" + a.height + " extra " + a.extra : "");
    }

    // --- Decoder's decisions, with a fake VM and a fake clock -------------------------------------------------------

    /** A link's other end: serves a scripted reply and swallows the request. Optionally ends or fails early. */
    static final class FakeChannel implements GuestLink.Channel {
        private final byte[] mReply;
        private final int mServe; // bytes of the reply served before the stream ends
        private int mAt;

        FakeChannel(byte[] reply) {
            this(reply, reply.length);
        }

        FakeChannel(byte[] reply, int serve) {
            mReply = reply;
            mServe = serve;
        }

        @Override
        public int read(byte[] b, int off, int len, long deadline) {
            int k = Math.min(len, mServe - mAt);
            if (k <= 0) return 0;
            System.arraycopy(mReply, mAt, b, off, k);
            mAt += k;
            return k;
        }

        @Override
        public void write(byte[] b, int off, int len, long deadline) {}

        @Override
        public void close() {}
    }

    /** The VM as Decoder sees it: links from a script, counters of what Decoder asked for. */
    static final class FakeVm implements Decoder.Vm {
        // Each entry: a channel, a reply (byte[], a fresh channel each time) or an IOException (no start).
        final java.util.ArrayDeque<Object> script = new java.util.ArrayDeque<>();
        final java.util.ArrayDeque<Object> smallScript = new java.util.ArrayDeque<>(); // the small lane's
        Object always; // used when the script is empty
        Object smallAlways;
        boolean nextReused;
        boolean lanes;
        volatile boolean held;
        volatile int links, smallLinks, stops, drops;
        private boolean mReused;
        private boolean mRunning;

        @Override
        public GuestLink link(boolean small, long deadline) throws IOException {
            Object next;
            synchronized (this) {
                if (small) {
                    smallLinks++;
                    next = smallScript.isEmpty() ? smallAlways : smallScript.poll();
                } else {
                    links++;
                    next = script.isEmpty() ? always : script.poll();
                }
                mReused = nextReused;
                nextReused = false;
                if (next instanceof IOException) throw (IOException) next;
                mRunning = true;
            }
            if (generationOnRead && next instanceof FailingChannel) {
                FakeVm self = this;
                FailingChannel f = (FailingChannel) next;
                return new GuestLink(new GuestLink.Channel() {
                    @Override public int read(byte[] b, int off, int len, long deadline) throws IOException {
                        self.generation++; // another request stopped and started the VM meanwhile
                        return f.read(b, off, len, deadline);
                    }

                    @Override public void write(byte[] b, int off, int len, long deadline) {}

                    @Override public void close() {}
                });
            }
            return new GuestLink(next instanceof byte[] ? new FakeChannel((byte[]) next) : (GuestLink.Channel) next);
        }

        @Override public boolean lanes() {
            return lanes;
        }

        volatile int generation = 1;
        boolean generationOnRead; // the next failing read happens while another request restarts the VM

        @Override public int generation() {
            return generation;
        }

        @Override public String cpus() {
            return lanes ? "2" : "1";
        }

        @Override public synchronized void stop() {
            stops++;
            mRunning = false;
        }

        @Override public synchronized boolean isRunning() {
            return mRunning;
        }

        @Override public synchronized boolean lastLinkReused(boolean small) {
            return mReused;
        }

        @Override public synchronized void dropLink(boolean small) {
            drops++;
        }

        @Override public String lastError() {
            return "";
        }

        @Override public boolean heldDown() {
            return held;
        }
    }

    /** A link whose reads fail: with an OutOfMemoryError (the service's own heap) or past its deadline. */
    static final class FailingChannel implements GuestLink.Channel {
        final boolean outOfMemory;

        FailingChannel(boolean outOfMemory) {
            this.outOfMemory = outOfMemory;
        }

        @Override
        public int read(byte[] b, int off, int len, long deadline) throws IOException {
            if (outOfMemory) throw new OutOfMemoryError("service heap");
            throw new java.io.InterruptedIOException("deadline");
        }

        @Override public void write(byte[] b, int off, int len, long deadline) {}

        @Override public void close() {}
    }

    /** A big lane that holds its reply until released: a large decode in progress. */
    static final class HeldChannel implements GuestLink.Channel {
        final java.util.concurrent.CountDownLatch release = new java.util.concurrent.CountDownLatch(1);
        private final FakeChannel mReply;

        HeldChannel(byte[] reply) {
            mReply = new FakeChannel(reply);
        }

        @Override
        public int read(byte[] b, int off, int len, long deadline) throws IOException {
            try {
                release.await();
            } catch (InterruptedException e) {
                throw new java.io.InterruptedIOException();
            }
            return mReply.read(b, off, len, deadline);
        }

        @Override public void write(byte[] b, int off, int len, long deadline) {}

        @Override public void close() {}
    }

    /** A streamed file: fails while sent when asked to, and reports a digest of what was sent. */
    static final class FakeSource implements Decoder.StreamedSource {
        final int len;
        final boolean fails;
        final byte[] sent;

        FakeSource(int len, boolean fails, byte[] sent) {
            this.len = len;
            this.fails = fails;
            this.sent = sent;
        }

        @Override public long length() {
            return len;
        }

        @Override public void readFully(byte[] b, int off, int n, long deadline) throws IOException {
            if (fails) throw new IOException("file shrank");
        }

        @Override public byte[] sentDigest() {
            return sent;
        }

        @Override public void close() {}
    }

    static final long FAR = Long.MAX_VALUE / 4;

    static byte[] probeOk() {
        return cat(reply(GuestLink.REPLY_MAGIC, 0, 1, 5, 5, 0, 0), end(0));
    }

    static byte[] failure(int status) {
        return cat(reply(GuestLink.REPLY_MAGIC, status, 0, 0, 0, 0, 0), end(status));
    }

    static byte[] thumbOk(int w, int h) {
        return cat(reply(GuestLink.REPLY_MAGIC, 0, 1, w, h, 0, w * h * 4), new byte[w * h * 4], end(0));
    }

    static Decoder.Request probe(Decoder d, byte[] file, String lane) {
        if (!d.reserve(lane, file.length)) throw new IllegalStateException("no budget for the test input");
        return d.run(new Decoder.Request(GuestLink.OP_PROBE, 0, 0, file, file.length, file.length, lane, false, FAR));
    }

    static Decoder.Request thumb(Decoder d, byte[] file, int box, String lane) {
        if (!d.reserve(lane, file.length)) throw new IllegalStateException("no budget for the test input");
        return d.run(new Decoder.Request(GuestLink.OP_THUMBNAIL, box, box, file, file.length, file.length, lane, false,
                FAR));
    }

    static Decoder.Request streamed(Decoder d, FakeSource src, byte[] digest, String lane) {
        Decoder.Request r = new Decoder.Request(GuestLink.OP_THUMBNAIL, 64, 64, null, src.len, 0, lane, false, FAR);
        r.source = src;
        r.digest = digest;
        return d.run(r);
    }

    static void check(String what, boolean ok, String detail) {
        if (ok) pass(what, detail); else fail(what, detail);
    }

    static void decoderChecks() throws Exception {
        java.util.concurrent.atomic.AtomicLong clock = new java.util.concurrent.atomic.AtomicLong(1000);
        Scheduler.Clock c = clock::get;

        // A kept connection that died before saying anything: connected again once, no stop, no strike.
        FakeVm vm = new FakeVm();
        vm.nextReused = true;
        vm.script.add(new FakeChannel(new byte[0]));
        vm.script.add(new FakeChannel(probeOk()));
        Decoder d = new Decoder(vm, c);
        Decoder.Request r = probe(d, new byte[] {1, 2, 3}, "a");
        check("decoder: a dead kept link is tried once more", r.status == GuestLink.OK && vm.links == 2 && vm.drops == 1
                && vm.stops == 0 && d.held() == 0, "status " + r.status + ", links " + vm.links + ", stops " + vm.stops);

        // A fresh connection that breaks: the VM is stopped and the file gets a strike, twice is INVALID, cached.
        vm = new FakeVm();
        vm.always = new byte[0];
        d = new Decoder(vm, c);
        byte[] file = {4, 5, 6};
        Decoder.Request r1 = probe(d, file, "a");
        clock.addAndGet(Decoder.BACKOFF_MIN + 1);
        vm.always = new byte[0];
        Decoder.Request r2 = probe(d, file, "a");
        int linksBefore = vm.links;
        Decoder.Request r3 = probe(d, file, "a");
        check("decoder: a broken fresh link twice is a cached INVALID", r1.status == Decoder.UNAVAILABLE
                && r2.status == GuestLink.INVALID && r3.status == GuestLink.INVALID && vm.links == linksBefore
                && vm.stops >= 2 && d.held() == 0, r1.status + " " + r2.status + " " + r3.status + ", stops " + vm.stops);

        // Workers that died (INTERNAL) twice: a strike each, INVALID. BUSY twice: never a strike.
        vm = new FakeVm();
        d = new Decoder(vm, c);
        vm.script.add(new FakeChannel(failure(GuestLink.INTERNAL)));
        vm.script.add(new FakeChannel(failure(GuestLink.INTERNAL)));
        Decoder.Request i1 = probe(d, new byte[] {7}, "a");
        Decoder.Request i2 = probe(d, new byte[] {7}, "a");
        vm.script.add(new FakeChannel(failure(GuestLink.BUSY)));
        vm.script.add(new FakeChannel(failure(GuestLink.BUSY)));
        vm.script.add(new FakeChannel(probeOk()));
        Decoder.Request b1 = probe(d, new byte[] {8}, "a");
        Decoder.Request b2 = probe(d, new byte[] {8}, "a");
        Decoder.Request b3 = probe(d, new byte[] {8}, "a");
        check("decoder: INTERNAL twice is INVALID, BUSY never a strike", i1.status == Decoder.UNAVAILABLE
                && i2.status == GuestLink.INVALID && b1.status == Decoder.UNAVAILABLE && b2.status == Decoder.UNAVAILABLE
                && b3.status == GuestLink.OK && vm.stops == 0 && d.held() == 0,
                i1.status + " " + i2.status + " / " + b1.status + " " + b2.status + " " + b3.status);

        // A late BUSY after the pixels: also no strike, and the pixel budget goes back.
        vm = new FakeVm();
        d = new Decoder(vm, c);
        byte[] lateBusy = cat(reply(GuestLink.REPLY_MAGIC, 0, 1, 8, 8, 0, 256), new byte[256], end(GuestLink.BUSY));
        vm.script.add(new FakeChannel(lateBusy));
        vm.script.add(new FakeChannel(lateBusy));
        vm.script.add(new FakeChannel(thumbOk(8, 8)));
        Decoder.Request l1 = thumb(d, new byte[] {9}, 8, "a");
        Decoder.Request l2 = thumb(d, new byte[] {9}, 8, "a");
        Decoder.Request l3 = thumb(d, new byte[] {9}, 8, "a");
        check("decoder: a late BUSY is no strike and frees its pixels", l1.status == Decoder.UNAVAILABLE
                && l2.status == Decoder.UNAVAILABLE && l3.status == GuestLink.OK && d.held() == 0,
                l1.status + " " + l2.status + " " + l3.status + ", held " + d.held());

        // The caller's file fails while sent: no stop, no strike, again and again.
        vm = new FakeVm();
        vm.always = thumbOk(4, 4);
        d = new Decoder(vm, c);
        byte[] digest = new byte[32];
        Decoder.Request s1 = streamed(d, new FakeSource(1 << 20, true, null), digest, "a");
        Decoder.Request s2 = streamed(d, new FakeSource(1 << 20, true, null), digest, "a");
        Decoder.Request s3 = streamed(d, new FakeSource(1 << 20, true, null), digest, "a");
        check("decoder: a source failure is no stop and no strike", s1.status == Decoder.UNAVAILABLE
                && s2.status == Decoder.UNAVAILABLE && s3.status == Decoder.UNAVAILABLE && vm.stops == 0,
                s1.status + " " + s2.status + " " + s3.status + ", stops " + vm.stops);

        // A streamed file that changed between hash and send: answered, but never cached under the old digest.
        vm = new FakeVm();
        vm.always = thumbOk(4, 4);
        d = new Decoder(vm, c);
        byte[] other = new byte[32];
        other[0] = 1;
        Decoder.Request c1 = streamed(d, new FakeSource(1 << 20, false, other), digest, "a");
        vm.always = thumbOk(4, 4);
        Decoder.Request c2 = streamed(d, new FakeSource(1 << 20, false, other), digest, "a");
        check("decoder: a changed file is not cached", c1.status == GuestLink.OK && c2.status == GuestLink.OK
                && vm.links == 2, "links " + vm.links);

        // N2: a lane's large input and its large answer, one after the other: the input goes when the reply begins.
        vm = new FakeVm();
        int w = 4096, h = 2048; // 32 MiB of pixels, as large as an answer gets
        vm.always = cat(reply(GuestLink.REPLY_MAGIC, 0, 1, w, h, 0, w * h * 4), new byte[w * h * 4], end(0));
        d = new Decoder(vm, c);
        Decoder.Request big = thumb(d, new byte[GuestLink.MAX_BUFFERED_BYTES], 4096, "big");
        check("decoder: 32 MiB in, 32 MiB out on one lane", big.status == GuestLink.OK && d.held() == 0,
                "status " + big.status + ", held " + d.held());

        // Fairness: busy lanes leave room for the next, and a lane gets at most half of what the others leave.
        d = new Decoder(new FakeVm(), c);
        boolean h1 = d.reserve("h1", Decoder.MAX_LANE_BYTES);
        boolean h2 = d.reserve("h2", Decoder.MAX_LANE_BYTES);
        boolean h3big = d.reserve("h3", Decoder.MAX_LANE_BYTES);
        boolean h3 = d.reserve("h3", (Decoder.MAX_HELD_BYTES - 2 * Decoder.MAX_LANE_BYTES) / 2);
        boolean small = d.reserve("h4", 1 << 20);
        check("decoder: the lane share is fair", h1 && h2 && !h3big && h3 && small, h1 + " " + h2 + " " + h3big + " "
                + h3 + " " + small);
        d.release("h1", Decoder.MAX_LANE_BYTES);
        d.release("h2", Decoder.MAX_LANE_BYTES);
        d.release("h3", (Decoder.MAX_HELD_BYTES - 2 * Decoder.MAX_LANE_BYTES) / 2);
        d.release("h4", 1 << 20);

        // No room for the pixels: drained, "try later", no strike, nothing held.
        vm = new FakeVm();
        vm.always = cat(reply(GuestLink.REPLY_MAGIC, 0, 1, 2048, 2048, 0, 2048 * 2048 * 4), new byte[2048 * 2048 * 4],
                end(0));
        d = new Decoder(vm, c);
        long third = (Decoder.MAX_HELD_BYTES - 2 * Decoder.MAX_LANE_BYTES) / 2;
        d.reserve("h1", Decoder.MAX_LANE_BYTES);
        d.reserve("h2", Decoder.MAX_LANE_BYTES);
        d.reserve("h3", third);
        Decoder.Request nb1 = thumb(d, new byte[] {10}, 2048, "y");
        Decoder.Request nb2 = thumb(d, new byte[] {10}, 2048, "y");
        long hogs = 2 * Decoder.MAX_LANE_BYTES + third;
        check("decoder: no budget for the pixels is no strike", nb1.status == Decoder.UNAVAILABLE
                && nb2.status == Decoder.UNAVAILABLE && d.held() == hogs && vm.stops == 0, nb1.status + " "
                + nb2.status + ", held " + d.held());
        d.release("h1", Decoder.MAX_LANE_BYTES);
        d.release("h2", Decoder.MAX_LANE_BYTES);
        d.release("h3", third);

        // N3: the link ends between the pixels and the trailer: the pixel budget goes back.
        vm = new FakeVm();
        byte[] cut = thumbOk(64, 64);
        vm.script.add(new FakeChannel(cut, cut.length - 4));
        d = new Decoder(vm, c);
        Decoder.Request leak = thumb(d, new byte[] {11}, 64, "a");
        check("decoder: a link lost before the trailer leaks no budget", leak.status == Decoder.UNAVAILABLE
                && d.held() == 0 && vm.stops == 1, "status " + leak.status + ", held " + d.held());

        // A test holds the VM down: stopped, nothing linked, unavailable, and no backoff afterwards.
        vm = new FakeVm();
        vm.held = true;
        vm.always = probeOk();
        d = new Decoder(vm, c);
        Decoder.Request hd = probe(d, new byte[] {12}, "a");
        vm.held = false;
        Decoder.Request after = probe(d, new byte[] {12}, "a");
        check("decoder: held down is unavailable, then back at once", hd.status == Decoder.UNAVAILABLE
                && vm.stops >= 1 && after.status == GuestLink.OK && vm.links == 1, hd.status + " " + after.status
                + ", links " + vm.links);

        // Two lanes: a small file goes to the small lane, one the VM finds too large there goes on to the big lane,
        // a file over a MiB goes to the big lane at once.
        vm = new FakeVm();
        vm.lanes = true;
        vm.smallAlways = thumbOk(8, 8);
        vm.always = thumbOk(8, 8);
        d = new Decoder(vm, c);
        Decoder.Request sm = thumb(d, new byte[] {20}, 8, "a");
        int bigBefore = vm.links;
        vm.smallAlways = failure(GuestLink.BIG_LANE);
        Decoder.Request on = thumb(d, new byte[] {21}, 8, "a");
        Decoder.Request large = thumb(d, new byte[GuestLink.SMALL_INPUT_BYTES + 1], 8, "a");
        check("decoder: small lane first, BIG_LANE goes on, large inputs straight to the big lane",
                sm.status == GuestLink.OK && bigBefore == 0 && on.status == GuestLink.OK && large.status == GuestLink.OK
                        && vm.smallLinks == 2 && vm.links == 2 && vm.stops == 0 && d.held() == 0,
                sm.status + " " + on.status + " " + large.status + ", small links " + vm.smallLinks + ", big links "
                        + vm.links + ", held " + d.held());

        // The lanes run side by side: small files are answered while the big lane is held up by a large decode.
        vm = new FakeVm();
        vm.lanes = true;
        HeldChannel slow = new HeldChannel(thumbOk(8, 8));
        vm.script.add(slow);
        vm.smallAlways = thumbOk(8, 8);
        Decoder dl = new Decoder(vm, c);
        Decoder.Request[] bigOne = new Decoder.Request[1];
        Thread t = new Thread(() -> bigOne[0] = thumb(dl, new byte[GuestLink.SMALL_INPUT_BYTES + 1], 8, "b"));
        t.start();
        long t0 = System.nanoTime();
        int smallOk = 0;
        for (int i = 0; i < 20; i++) {
            if (thumb(dl, new byte[] {(byte) (30 + i)}, 8, "c").status == GuestLink.OK) smallOk++;
        }
        long smallMs = (System.nanoTime() - t0) / 1000000;
        boolean bigWaiting = t.isAlive();
        slow.release.countDown();
        t.join(5000);
        check("decoder: small files pass a held big lane", smallOk == 20 && bigWaiting && bigOne[0] != null
                && bigOne[0].status == GuestLink.OK, smallOk + " small in " + smallMs + " ms while the big lane waited");

        // The service's own heap fails while it reads a reply: the connection goes, the VM stays, no strike.
        vm = new FakeVm();
        vm.script.add(new FailingChannel(true));
        vm.script.add(new FailingChannel(true));
        vm.always = probeOk();
        d = new Decoder(vm, c);
        Decoder.Request o1 = probe(d, new byte[] {40}, "a");
        Decoder.Request o2 = probe(d, new byte[] {40}, "a");
        Decoder.Request o3 = probe(d, new byte[] {40}, "a");
        check("decoder: the service's out of memory is no VM restart and no strike", o1.status == Decoder.UNAVAILABLE
                && o2.status == Decoder.UNAVAILABLE && o3.status == GuestLink.OK && vm.stops == 0,
                o1.status + " " + o2.status + " " + o3.status + ", stops " + vm.stops);

        // A deadline missed on the big lane while the small lane still answers: a slow VM, not a broken one.
        vm = new FakeVm();
        vm.lanes = true;
        vm.script.add(new FailingChannel(false));
        vm.always = probeOk();
        vm.smallAlways = cat(reply(GuestLink.REPLY_MAGIC, 0, 0, 0, 0, 0, 0), end(0));
        d = new Decoder(vm, c);
        Decoder.Request laneSlow = probe(d, new byte[GuestLink.SMALL_INPUT_BYTES + 1], "a");
        Decoder.Request late2 = probe(d, new byte[GuestLink.SMALL_INPUT_BYTES + 1], "a");
        check("decoder: a slow lane with the other lane alive is no restart and no strike",
                laneSlow.status == Decoder.UNAVAILABLE && vm.stops == 0 && late2.status == GuestLink.OK,
                laneSlow.status + " " + late2.status + ", stops " + vm.stops + ", drops " + vm.drops);

        // A request whose VM another request stopped meanwhile only lost its connection: no strike.
        vm = new FakeVm();
        vm.script.add(new FailingChannel(false));
        vm.script.add(new FailingChannel(false));
        vm.always = probeOk();
        vm.generationOnRead = true;
        d = new Decoder(vm, c);
        Decoder.Request lost1 = probe(d, new byte[] {41}, "a");
        clock.addAndGet(Decoder.BACKOFF_MIN + 1);
        Decoder.Request lost2 = probe(d, new byte[] {41}, "a");
        Decoder.Request lost3 = probe(d, new byte[] {41}, "a");
        check("decoder: a VM stopped by another request strikes no file", lost1.status == Decoder.UNAVAILABLE
                && lost2.status == Decoder.UNAVAILABLE && lost3.status == GuestLink.OK,
                lost1.status + " " + lost2.status + " " + lost3.status);

        // A late answer is cached: the caller gave up, the next request finds it without the VM.
        vm = new FakeVm();
        HeldChannel late = new HeldChannel(probeOk());
        vm.script.add(late);
        d = new Decoder(vm, c);
        byte[] lf = {42};
        if (!d.reserve("a", lf.length)) throw new IllegalStateException("budget");
        Thread giveUp = new Thread(() -> {
            try {
                Thread.sleep(200);
                clock.addAndGet(10); // the caller's deadline passes, then the VM answers
                Thread.sleep(200);
            } catch (InterruptedException ignored) {
                // done
            }
            late.release.countDown();
        });
        giveUp.start();
        Decoder.Request quick = d.run(new Decoder.Request(GuestLink.OP_PROBE, 0, 0, lf, lf.length, lf.length, "a",
                false, clock.get() + 5));
        giveUp.join();
        Thread.sleep(300); // the worker thread settles the answer
        Decoder.Request again = probe(d, lf, "a");
        boolean fromCache = quick.status == Decoder.UNAVAILABLE && again.status == GuestLink.OK && vm.links == 1;
        check("decoder: a late answer is cached", fromCache, "first " + quick.status + ", links " + vm.links);

        // A VM that does not start: backoff, no link attempt until it ends.
        vm = new FakeVm();
        vm.always = new IOException("VM start: refused");
        d = new Decoder(vm, c);
        Decoder.Request f1 = probe(d, new byte[] {13}, "a");
        Decoder.Request f2 = probe(d, new byte[] {13}, "a");
        int during = vm.links;
        clock.addAndGet(Decoder.BACKOFF_MIN + 1);
        vm.always = probeOk();
        Decoder.Request f3 = probe(d, new byte[] {13}, "a");
        check("decoder: a failed start backs off", f1.status == Decoder.UNAVAILABLE && f2.status == Decoder.UNAVAILABLE
                && during == 1 && f3.status == GuestLink.OK && vm.links == 2 && d.held() == 0,
                f1.status + " " + f2.status + " " + f3.status + ", links " + vm.links);
    }

    static void brokerChecks(String socket, java.io.File images) throws Exception {
        GuestLink link = new GuestLink(new UnixChannel(socket));
        long t;
        GuestLink.Answer ping = link.ping(now() + 5000);
        if (ping.status == GuestLink.OK && ping.extra >= 1) pass("broker ping", ping.extra + " CPUs online");
        else fail("broker ping", show(ping));

        byte[] seed = file(images, "exif-seed.jpg");
        t = now();
        GuestLink.Answer meta = link.metadata(seed, seed.length, now() + 30000);
        GuestLink.Meta m = meta.meta;
        if (meta.status == 0 && m.orientation == 90 && "Holiday shot".equals(m.description)
                && m.dateTakenMillis == 1794904890123L && "xmp.did:1234-abcd".equals(m.documentId)
                && m.offsetKnown && Math.abs(m.latitude - 52.52009) < 0.001 && m.specialFormat == 2) {
            pass("broker metadata", (now() - t) + " ms");
        } else {
            fail("broker metadata", show(meta));
        }
        String[][] thumbs = {
            {"photo12.jpg", "1080", "2400", "1080", "810", "0"},
            {"photo12-rot90.jpg", "300", "200", "200", "150", "90"},
            {"photo12.jpg", "64", "64", "64", "48", "0"},
            {"test-rgba.png", "256", "256", "256", "192", "0"},
            {"interlaced.png", "512", "512", "-1", "-1", "0"},
            {"png8mp.png", "1080", "1080", "-1", "-1", "0"},
            {"photo12p.jpg", "1080", "1080", "-1", "-1", "0"},
        };
        for (String[] c : thumbs) {
            byte[] f = file(images, c[0]);
            int bw = Integer.parseInt(c[1]), bh = Integer.parseInt(c[2]);
            t = now();
            GuestLink.Answer a = link.thumbnail(f, f.length, bw, bh, now() + 45000);
            long ms = now() - t;
            boolean ok = a.status == 0 && a.extra == Integer.parseInt(c[5])
                    && (c[3].equals("-1") || (a.width == Integer.parseInt(c[3]) && a.height == Integer.parseInt(c[4])))
                    && broken(a, GuestLink.OP_THUMBNAIL, bw, bh) == null;
            if (ok) pass("broker thumbnail " + c[0] + " in " + bw + "x" + bh, show(a) + ", " + ms + " ms");
            else fail("broker thumbnail " + c[0] + " in " + bw + "x" + bh, show(a) + ", " + ms + " ms");
        }
        for (String big : new String[] {"photo50.jpg", "photo50p.jpg", "photo50n.jpg"}) {
            byte[] f = file(images, big);
            t = now();
            GuestLink.Answer a = link.thumbnail(f, f.length, 1080, 1080, now() + 45000);
            System.out.println("info broker thumbnail " + big + ": " + show(a) + ", " + (now() - t) + " ms");
        }
        byte[] broken = {(byte) 0xff, (byte) 0xd8, (byte) 0xff, 0, 1, 2, 3};
        GuestLink.Answer bad = link.thumbnail(broken, broken.length, 8, 8, now() + 30000);
        if (bad.status == GuestLink.INVALID) pass("broker broken jpeg", ""); else fail("broker broken jpeg", show(bad));
        byte[] text = "hello".getBytes();
        GuestLink.Answer other = link.probe(text, text.length, now() + 30000);
        if (other.status == GuestLink.UNSUPPORTED) pass("broker unsupported", ""); else fail("broker unsupported",
                show(other));

        // The lockdown: seccomp strict entered, and every forbidden call kills the worker (no verdict on a file).
        GuestLink.Answer report = link.hook(4, now() + 30000);
        if (report.status == 0 && report.pixels[0] == 1 && report.pixels[1] == 0) {
            pass("broker lockdown entered", "");
        } else {
            fail("broker lockdown entered", show(report));
        }
        String[] names = {"", "open", "mmap", "spin", "", "fork"};
        for (int hook : new int[] {1, 2, 5, 3}) {
            t = now();
            GuestLink.Answer a = link.hook(hook, now() + 45000);
            long ms = now() - t;
            if (a.status == GuestLink.INTERNAL) pass("broker lockdown kills " + names[hook], ms + " ms");
            else fail("broker lockdown kills " + names[hook], show(a) + ", " + ms + " ms");
        }
        GuestLink.Answer colours = link.hook(7, now() + 30000);
        if (colours.status == GuestLink.INVALID) pass("broker refuses colours above alpha", "");
        else fail("broker refuses colours above alpha", show(colours));

        // No leak: another request's metadata and pixels must not reach the next worker.
        Random rnd = new Random();
        String marker = String.format("LK%010x", rnd.nextLong() & 0xffffffffffL);
        byte[] withMarker = replace(seed, "Holiday shot".getBytes(), marker.getBytes());
        GuestLink.Answer mm = link.metadata(withMarker, withMarker.length, now() + 30000);
        java.awt.image.BufferedImage img = new java.awt.image.BufferedImage(32, 1,
                java.awt.image.BufferedImage.TYPE_INT_ARGB);
        byte[] rgba = new byte[32 * 4];
        for (int x = 0; x < 32; x++) {
            int r = rnd.nextInt(256), g = rnd.nextInt(256), b = rnd.nextInt(256);
            img.setRGB(x, 0, 0xff000000 | r << 16 | g << 8 | b);
            rgba[x * 4] = (byte) r;
            rgba[x * 4 + 1] = (byte) g;
            rgba[x * 4 + 2] = (byte) b;
            rgba[x * 4 + 3] = (byte) 255;
        }
        java.io.ByteArrayOutputStream png = new java.io.ByteArrayOutputStream();
        javax.imageio.ImageIO.write(img, "png", png);
        byte[] pngBytes = png.toByteArray();
        GuestLink.Answer px = link.thumbnail(pngBytes, pngBytes.length, 64, 64, now() + 30000);
        boolean sent = mm.status == 0 && marker.equals(mm.meta.description) && px.status == 0
                && java.util.Arrays.equals(px.pixels, rgba);
        GuestLink.Answer scanMeta = link.hook(6, marker.getBytes(), marker.length(), now() + 30000);
        GuestLink.Answer scanPixels = link.hook(6, rgba, rgba.length, now() + 30000);
        byte[] dsr = "DSR3".getBytes();
        GuestLink.Answer control = link.hook(6, dsr, dsr.length, now() + 30000);
        if (sent && scanMeta.status == 0 && scanMeta.pixels[0] == 0 && scanPixels.status == 0
                && scanPixels.pixels[0] == 0 && control.status == 0 && control.pixels[0] == 1) {
            pass("broker no leak between requests", "metadata and pixels markers not found by the next worker ("
                    + (scanMeta.pixels[1] & 0xff) + " regions scanned), the control found");
        } else {
            fail("broker no leak between requests", "sent " + sent + " meta " + show(scanMeta) + " found "
                    + (scanMeta.pixels != null ? scanMeta.pixels[0] : -1) + " pixels " + show(scanPixels) + " found "
                    + (scanPixels.pixels != null ? scanPixels.pixels[0] : -1) + " control " + show(control));
        }
        formatChecks(link, images);
        link.close();
        // The broker serves the next connection.
        GuestLink again = new GuestLink(new UnixChannel(socket));
        GuestLink.Answer p2 = again.ping(now() + 5000);
        if (p2.status == 0) pass("broker second connection", ""); else fail("broker second connection", show(p2));
        again.close();
        smallLaneChecks(socket + ".small", images);
    }

    /**
     * The real small lane (the host program's second broker, at the socket path and ".small"): icons are answered
     * there, and everything too large or too slow for it is answered BIG_LANE, never as a verdict on the file.
     */
    static void smallLaneChecks(String socket, java.io.File images) throws Exception {
        GuestLink small = new GuestLink(new UnixChannel(socket));
        GuestLink.Answer ping = small.ping(now() + 5000);
        if (ping.status == GuestLink.OK) pass("small lane ping", ""); else fail("small lane ping", show(ping));
        byte[] icon = file(images, "test-rgba.png");
        GuestLink.Answer a = small.thumbnail(icon, icon.length, 64, 64, now() + 10000);
        if (a.status == GuestLink.OK && a.width == 64 && broken(a, GuestLink.OP_THUMBNAIL, 64, 64) == null) {
            pass("small lane icon", show(a));
        } else {
            fail("small lane icon", show(a));
        }
        byte[] large = file(images, "photo50.jpg");
        a = small.thumbnail(large, large.length, 64, 64, now() + 10000);
        if (large.length > GuestLink.SMALL_INPUT_BYTES && a.status == GuestLink.BIG_LANE) {
            pass("small lane: input above 1 MiB goes to the big lane", large.length + " bytes");
        } else {
            fail("small lane: input above 1 MiB goes to the big lane", large.length + " bytes, " + show(a));
        }
        byte[] wide = file(images, "gen/heic-single2mp.heic");
        a = small.thumbnail(wide, wide.length, 64, 64, now() + 10000);
        if (a.status == GuestLink.BIG_LANE) pass("small lane: header above 1 MP goes to the big lane", "");
        else fail("small lane: header above 1 MP goes to the big lane", show(a));
        // 1024x768 HEVC: below 1 MP, but the decoder needs more than the small arena.
        byte[] heic = file(images, "gen/heic-singlegray.heic");
        a = small.thumbnail(heic, heic.length, 64, 64, now() + 10000);
        if (a.status == GuestLink.BIG_LANE) pass("small lane: arena short goes to the big lane", "");
        else fail("small lane: arena short goes to the big lane", show(a));
        // A worker that spins: the small lane's CPU limit ends it within seconds, and the big lane takes it.
        long t = now();
        a = small.hook(3, now() + 15000);
        long ms = now() - t;
        if (a.status == GuestLink.BIG_LANE && ms < 4500) pass("small lane: a slow worker goes to the big lane", ms + " ms");
        else fail("small lane: a slow worker goes to the big lane", show(a) + ", " + ms + " ms");
        // Animations always take the big lane.
        byte[] gif = file(images, "r5/anim.gif");
        a = small.frames(gif, gif.length, 64, 64, now() + 10000);
        if (a.status == GuestLink.BIG_LANE) pass("small lane: frames go to the big lane", "");
        else fail("small lane: frames go to the big lane", show(a));
        // seccomp's kill stays a kill there too (no detour through the big lane).
        a = small.hook(1, now() + 15000);
        if (a.status == GuestLink.INTERNAL) pass("small lane lockdown kills open", "");
        else fail("small lane lockdown kills open", show(a));
        a = small.thumbnail(icon, icon.length, 64, 64, now() + 10000);
        if (a.status == GuestLink.OK) pass("small lane answers after the limits", "");
        else fail("small lane answers after the limits", show(a));
        small.close();
    }

    /**
     * The format table, images/formats.txt: one check per line, "FILE OP W H STATUS [f=FORMAT] [s=WxH] [x=EXTRA]
     * [sp=SPECIAL] [o=ORIENTATION]". OP is probe (with the first MAX_PROBE_BYTES only, as the service sends), thumb
     * or meta. STATUS is a status number, or "noint": any clean answer but INTERNAL (a worker that died: a crash or a
     * seccomp kill). A file name ending in "/" runs the check on every file of that folder.
     */
    static void formatChecks(GuestLink link, java.io.File images) throws Exception {
        java.io.File table = new java.io.File(images, "formats.txt");
        if (!table.exists()) return;
        for (String line : java.nio.file.Files.readAllLines(table.toPath())) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;
            String[] t = line.split("\\s+");
            java.util.List<String> files = new java.util.ArrayList<>();
            if (t[0].endsWith("/")) {
                String[] names = new java.io.File(images, t[0]).list();
                java.util.Arrays.sort(names);
                for (String n : names) files.add(t[0] + n);
            } else {
                files.add(t[0]);
            }
            for (String name : files) formatCheck(link, images, name, t);
        }
    }

    static void formatCheck(GuestLink link, java.io.File images, String name, String[] t) throws Exception {
        byte[] f = file(images, name);
        String op = t[1];
        int bw = Integer.parseInt(t[2]), bh = Integer.parseInt(t[3]);
        long start = now();
        GuestLink.Answer a;
        int opCode;
        if (op.equals("probe")) {
            a = link.probe(f, Math.min(f.length, 1 << 20), now() + 45000);
            opCode = GuestLink.OP_PROBE;
        } else if (op.equals("frames")) {
            a = link.frames(f, f.length, bw, bh, now() + 45000);
            opCode = GuestLink.OP_FRAMES;
        } else if (op.equals("meta")) {
            // As the service sends it: a file above the buffered cap goes as its head only.
            int len = f.length > GuestLink.MAX_BUFFERED_BYTES ? 1 << 20 : f.length;
            a = link.metadata(f, len, now() + 45000);
            opCode = GuestLink.OP_METADATA;
        } else {
            a = link.thumbnail(f, f.length, bw, bh, now() + 45000);
            opCode = GuestLink.OP_THUMBNAIL;
        }
        long ms = now() - start;
        String why = broken(a, opCode, bw, bh);
        if (t[4].equals("noint")) {
            if (a.status == GuestLink.INTERNAL || a.status == GuestLink.BUSY) why = "status " + a.status;
        } else if (a.status != Integer.parseInt(t[4])) {
            why = "status " + a.status;
        }
        for (int i = 5; i < t.length && why == null && a.status == 0; i++) {
            String[] kv = t[i].split("=", 2);
            switch (kv[0]) {
                case "f": if (a.format != Integer.parseInt(kv[1])) why = "format " + a.format; break;
                case "s": if (!(a.width + "x" + a.height).equals(kv[1])) why = "size " + a.width + "x" + a.height; break;
                case "x": if (a.extra != Integer.parseInt(kv[1])) why = "extra " + a.extra; break;
                case "cs": if (a.colorSpace != Integer.parseInt(kv[1])) why = "colour space " + a.colorSpace; break;
                case "n": if (a.extra != Integer.parseInt(kv[1])) why = "frames " + a.extra; break;
                case "l": if (a.loops != Integer.parseInt(kv[1])) why = "loops " + a.loops; break;
                case "d": {
                    StringBuilder ds = new StringBuilder();
                    for (int k = 0; a.durations != null && k < a.durations.length; k++) {
                        ds.append(k == 0 ? "" : ",").append(a.durations[k]);
                    }
                    if (!ds.toString().equals(kv[1])) why = "durations " + ds;
                    break;
                }
                case "sp": if (a.meta == null || a.meta.specialFormat != Integer.parseInt(kv[1])) why = "special"; break;
                case "o": if (a.meta == null || a.meta.orientation != Integer.parseInt(kv[1])) {
                        why = "orientation " + (a.meta == null ? "none" : a.meta.orientation);
                    }
                    break;
                default: why = "bad table key " + kv[0];
            }
        }
        String dump = System.getenv("FORMAT_DUMP");
        if (dump != null && a.status == 0 && a.pixels != null && opCode == GuestLink.OP_FRAMES) {
            // Test runs only: every frame as a PNG (straight alpha), for compare-frames.py.
            int frameBytes = a.width * a.height * 4;
            for (int fi = 0; fi < a.extra; fi++) {
                java.awt.image.BufferedImage img = new java.awt.image.BufferedImage(a.width, a.height,
                        java.awt.image.BufferedImage.TYPE_INT_ARGB);
                for (int i = 0; i < a.width * a.height; i++) {
                    int o = fi * frameBytes + i * 4;
                    int al = a.pixels[o + 3] & 0xff;
                    int[] c = new int[3];
                    for (int k = 0; k < 3; k++) {
                        int v = a.pixels[o + k] & 0xff;
                        c[k] = al == 0 ? 0 : Math.min(255, (v * 255 + al / 2) / al);
                    }
                    img.setRGB(i % a.width, i / a.width, al << 24 | c[0] << 16 | c[1] << 8 | c[2]);
                }
                javax.imageio.ImageIO.write(img, "png", new java.io.File(dump,
                        name.replace('/', '_') + "-" + bw + "x" + bh + "-f" + fi + ".png"));
            }
        } else if (dump != null && a.status == 0 && a.pixels != null) {
            // Test runs only: the thumbnail as a PNG (straight alpha) for comparison with a reference decoder.
            java.awt.image.BufferedImage img = new java.awt.image.BufferedImage(a.width, a.height,
                    java.awt.image.BufferedImage.TYPE_INT_ARGB);
            for (int i = 0; i < a.width * a.height; i++) {
                int al = a.pixels[i * 4 + 3] & 0xff;
                int[] c = new int[3];
                for (int k = 0; k < 3; k++) {
                    int v = a.pixels[i * 4 + k] & 0xff;
                    c[k] = al == 0 ? 0 : Math.min(255, (v * 255 + al / 2) / al);
                }
                img.setRGB(i % a.width, i / a.width, al << 24 | c[0] << 16 | c[1] << 8 | c[2]);
            }
            java.io.File out = new java.io.File(dump, name.replace('/', '_') + "-" + bw + "x" + bh + ".png");
            javax.imageio.ImageIO.write(img, "png", out);
        }
        String what = "format " + op + " " + name + (opCode == GuestLink.OP_THUMBNAIL ? " in " + bw + "x" + bh : "");
        if (why == null) pass(what, show(a) + ", " + ms + " ms"); else fail(what, why + ": " + show(a) + ", " + ms + " ms");
    }

    public static void main(String[] args) throws Exception {
        if (args.length >= 3 && args[0].equals("broker")) {
            brokerChecks(args[1], new java.io.File(args[2]));
            System.out.println("DONE pass=" + sPass + " fail=" + sFail);
            System.exit(sFail == 0 ? 0 : 1);
        }
        int rounds = args.length > 0 ? Integer.parseInt(args[0]) : 3000;
        linkChecks();
        fuzz(rounds);
        schedulerChecks();
        callerChecks();
        cacheChecks();
        decoderChecks();
        System.out.println("DONE pass=" + sPass + " fail=" + sFail + " in " + (System.nanoTime() - T0) / 1000000
                + " ms");
        System.exit(sFail == 0 ? 0 : 1);
    }
}
