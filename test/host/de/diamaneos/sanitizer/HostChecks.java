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
 * that plays a broken or malicious VM over a local socket, the Scheduler and the ResultCache. Plain Java, no Android
 * classes: run with any JDK. Prints one line per check and "DONE pass=N fail=M", exits 1 on any failure.
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
        return ByteBuffer.allocate(32).order(ByteOrder.LITTLE_ENDIAN).putInt(magic).putInt(status).putInt(format)
                .putInt(w).putInt(h).putInt(extra).putInt(payload).putInt(0).array();
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
        ByteBuffer b = ByteBuffer.allocate(GuestLink.META_BYTES).order(ByteOrder.LITTLE_ENDIAN);
        b.putInt(GuestLink.META_MAGIC).putInt(1).putInt(flags).putInt(GuestLink.FORMAT_JPEG).putInt(w).putInt(h)
                .putInt(orientation).putInt(0).putLong(date).putInt(0).putInt(0);
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
                    || a.status == GuestLink.INTERNAL;
            return clean && a.pixels == null && a.meta == null ? null : "bad failure answer " + a.status;
        }
        if (a.format != GuestLink.FORMAT_JPEG && a.format != GuestLink.FORMAT_PNG) return "format";
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
            if (m.dateTakenMillis > System.currentTimeMillis() + 86400000L) return "future date";
        } else {
            if (a.extra != 0 && !(a.extra == 1 && a.format == GuestLink.FORMAT_PNG)) return "animated";
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
        expectRefused("format 9", (in, out) -> out.write(cat(reply(R, 0, 9, 5, 5, 0, 0), end(0))),
                GuestLink.OP_PROBE);
        expectRefused("meta control char", (in, out) -> out.write(cat(reply(R, 0, 1, 4, 3, 0, 1024),
                meta(1, 4, 3, 90, -1, "A\u001bcamera", ""), end(0))), GuestLink.OP_METADATA);
        expectRefused("meta line separator", (in, out) -> out.write(cat(reply(R, 0, 1, 4, 3, 0, 1024),
                meta(1, 4, 3, 90, -1, "Aâ\u0080¨camera", ""), end(0))), GuestLink.OP_METADATA);
        expectRefused("meta future date", (in, out) -> out.write(cat(reply(R, 0, 1, 4, 3, 0, 1024),
                meta(3, 4, 3, 90, System.currentTimeMillis() + 3 * 86400000L, "", ""), end(0))),
                GuestLink.OP_METADATA);
        expectRefused("meta unterminated id", (in, out) -> out.write(cat(reply(R, 0, 1, 4, 3, 0, 1024),
                meta(1, 4, 3, 90, -1, "", "a".repeat(128)), end(0))), GuestLink.OP_METADATA);
        expectRefused("meta size mismatch", (in, out) -> out.write(cat(reply(R, 0, 1, 4, 3, 0, 1024),
                meta(1, 5, 3, 90, -1, "", ""), end(0))), GuestLink.OP_METADATA);
        expectRefused("meta orientation without flag", (in, out) -> out.write(cat(reply(R, 0, 1, 4, 3, 0, 1024),
                meta(0, 4, 3, 90, -1, "", ""), end(0))), GuestLink.OP_METADATA);
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
        Object kBig = ResultCache.key(new byte[32], 3, 1, 1);
        c.put(kBig, big);
        boolean ok = c.get(kBig) == null;
        int stored = 0;
        for (int i = 0; i < 40; i++) {
            GuestLink.Answer a = new GuestLink.Answer();
            a.pixels = new byte[1 << 20];
            byte[] d = new byte[32];
            d[0] = (byte) i;
            c.put(ResultCache.key(d, 3, 1, 1), a);
        }
        for (int i = 0; i < 40; i++) {
            byte[] d = new byte[32];
            d[0] = (byte) i;
            if (c.get(ResultCache.key(d, 3, 1, 1)) != null) stored++;
        }
        ok &= stored > 0 && stored * ((1 << 20) + 1024L) <= ResultCache.MAX_BYTES;
        byte[] d = new byte[32];
        d[0] = 39;
        ok &= c.get(ResultCache.key(d, 3, 1, 1)) != null && c.get(ResultCache.key(d, 3, 2, 1)) == null;
        if (ok) pass("result cache", stored + " of 40 one-MiB answers kept, oversize refused, keys exact");
        else fail("result cache", "stored " + stored);
    }

    public static void main(String[] args) throws Exception {
        int rounds = args.length > 0 ? Integer.parseInt(args[0]) : 3000;
        linkChecks();
        fuzz(rounds);
        schedulerChecks();
        cacheChecks();
        System.out.println("DONE pass=" + sPass + " fail=" + sFail + " in " + (System.nanoTime() - T0) / 1000000
                + " ms");
        System.exit(sFail == 0 ? 0 : 1);
    }
}
