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

import android.app.Activity;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.os.SystemClock;
import android.system.Os;
import android.system.OsConstants;
import android.util.Log;

import java.io.File;
import java.io.FileDescriptor;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * Test builds only. Runs the decode service's checks and logs one line per check under the tag DecoderSelfTest, then
 * "DONE pass=N fail=M". Modes (intent extra "mode"): "host" runs only the checks without a VM (the hostile guest stub
 * and the scheduler), "all" adds the VM checks: memory sizes, timings, the lockdown hooks and failing closed.
 *
 * <p>The VM's kernel and initramfs (signed with the test key that test builds' pvmfw trusts) and the test images are
 * pushed to this app's external files directory under decoder-vm/ and images/.
 */
public class SelfTestActivity extends Activity {
    private static final String TAG = "DecoderSelfTest";
    private int mPass;
    private int mFail;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        String mode = getIntent().getStringExtra("mode");
        new Thread(() -> {
            try {
                hostChecks();
                if (!"host".equals(mode)) vmChecks();
            } catch (Throwable t) {
                fail("crash", Log.getStackTraceString(t));
            }
            log("DONE pass=" + mPass + " fail=" + mFail);
        }, "selftest").start();
    }

    private static void log(String s) {
        Log.i(TAG, s);
    }

    private void pass(String what, String detail) {
        mPass++;
        log("PASS " + what + (detail.isEmpty() ? "" : ": " + detail));
    }

    private void fail(String what, String detail) {
        mFail++;
        log("FAIL " + what + (detail.isEmpty() ? "" : ": " + detail));
    }

    // --- The hostile guest stub: a scripted server on a socket pair plays a broken or malicious VM ----------------

    private interface Script {
        void serve(FileDescriptor fd) throws Exception;
    }

    private static void writeAll(FileDescriptor fd, byte[] b) throws Exception {
        int off = 0;
        while (off < b.length) off += Os.write(fd, b, off, b.length - off);
    }

    private static void readRequest(FileDescriptor fd) throws Exception {
        byte[] h = new byte[GuestLink.HEADER_BYTES];
        int got = 0;
        while (got < h.length) {
            int k = Os.read(fd, h, got, h.length - got);
            if (k <= 0) return;
            got += k;
        }
        int len = ByteBuffer.wrap(h).order(ByteOrder.LITTLE_ENDIAN).getInt(16);
        byte[] skip = new byte[65536];
        while (len > 0) {
            int k = Os.read(fd, skip, 0, Math.min(len, skip.length));
            if (k <= 0) return;
            len -= k;
        }
    }

    private static byte[] reply(int magic, int status, int format, int w, int h, int extra, int payload) {
        return ByteBuffer.allocate(32).order(ByteOrder.LITTLE_ENDIAN).putInt(magic).putInt(status).putInt(format)
                .putInt(w).putInt(h).putInt(extra).putInt(payload).putInt(0).array();
    }

    private static byte[] end(int magic, int status) {
        return ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putInt(magic).putInt(status).array();
    }

    private static byte[] cat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) n += p.length;
        ByteBuffer b = ByteBuffer.allocate(n);
        for (byte[] p : parts) b.put(p);
        return b.array();
    }

    private static byte[] meta(java.util.function.Consumer<ByteBuffer> edit) {
        ByteBuffer b = ByteBuffer.allocate(GuestLink.META_BYTES).order(ByteOrder.LITTLE_ENDIAN);
        b.putInt(GuestLink.META_MAGIC).putInt(1).putInt(GuestLink.HAS_ORIENTATION).putInt(GuestLink.FORMAT_JPEG)
                .putInt(4).putInt(3).putInt(90).putInt(0).putLong(-1).putInt(0).putInt(0);
        b.put("A camera".getBytes());
        if (edit != null) edit.accept(b);
        return b.array();
    }

    /** Runs one call against a scripted VM. Returns the answer, or the exception it threw. */
    private Object stub(Script script, int op, long deadlineMillis) throws Exception {
        FileDescriptor ours = new FileDescriptor(), theirs = new FileDescriptor();
        Os.socketpair(OsConstants.AF_UNIX, OsConstants.SOCK_STREAM, 0, ours, theirs);
        Thread server = new Thread(() -> {
            try {
                readRequest(theirs);
                script.serve(theirs);
            } catch (Exception ignored) {
                // the client may close first
            } finally {
                try {
                    Os.close(theirs);
                } catch (Exception ignored) {
                    // already closed
                }
            }
        });
        server.start();
        GuestLink link = new GuestLink(new FdChannel(ParcelFileDescriptor.dup(ours)));
        Os.close(ours);
        long deadline = SystemClock.uptimeMillis() + deadlineMillis;
        byte[] file = {(byte) 0xff, (byte) 0xd8, (byte) 0xff, 0};
        try {
            switch (op) {
                case GuestLink.OP_THUMBNAIL: return link.thumbnail(file, file.length, 2, 2, deadline);
                case GuestLink.OP_METADATA: return link.metadata(file, file.length, deadline);
                default: return link.probe(file, file.length, deadline);
            }
        } catch (IOException e) {
            return e;
        } finally {
            link.close();
            server.join(5000);
        }
    }

    private void expectRefused(String what, Script script, int op) throws Exception {
        long t0 = SystemClock.uptimeMillis();
        Object r = stub(script, op, 2000);
        long ms = SystemClock.uptimeMillis() - t0;
        if (r instanceof GuestLink.ProtocolException && ms < 3000) {
            pass("stub " + what, ((Exception) r).getMessage() + ", " + ms + " ms");
        } else {
            fail("stub " + what, String.valueOf(r) + ", " + ms + " ms");
        }
    }

    private void hostChecks() throws Exception {
        int R = GuestLink.REPLY_MAGIC, E = GuestLink.END_MAGIC;
        byte[] px = {1, 2, 3, 4, 5, 6, 7, 8}; // 2x1, channels below alpha
        // Positive controls first: a correct VM is accepted.
        Object ok = stub(fd -> writeAll(fd, cat(reply(R, 0, 1, 2, 1, 90, 8), px, end(E, 0))), GuestLink.OP_THUMBNAIL,
                2000);
        if (ok instanceof GuestLink.Answer && ((GuestLink.Answer) ok).pixels.length == 8) {
            pass("stub control thumbnail", "");
        } else {
            fail("stub control thumbnail", String.valueOf(ok));
        }
        Object okm = stub(fd -> writeAll(fd, cat(reply(R, 0, 1, 4, 3, 0, 1024), meta(null), end(E, 0))),
                GuestLink.OP_METADATA, 2000);
        if (okm instanceof GuestLink.Answer && "A camera".equals(((GuestLink.Answer) okm).meta.description)) {
            pass("stub control metadata", "");
        } else {
            fail("stub control metadata", String.valueOf(okm));
        }

        expectRefused("wrong magic", fd -> writeAll(fd, cat(reply(0x41414141, 0, 1, 2, 1, 0, 8), px, end(E, 0))),
                GuestLink.OP_THUMBNAIL);
        expectRefused("larger than asked", fd -> writeAll(fd, cat(reply(R, 0, 1, 3, 1, 0, 12), new byte[12],
                end(E, 0))), GuestLink.OP_THUMBNAIL);
        expectRefused("length not w*h*4", fd -> writeAll(fd, cat(reply(R, 0, 1, 2, 1, 0, 12), new byte[12],
                end(E, 0))), GuestLink.OP_THUMBNAIL);
        expectRefused("huge length", fd -> writeAll(fd, reply(R, 0, 1, 2, 1, 0, Integer.MAX_VALUE)),
                GuestLink.OP_THUMBNAIL);
        expectRefused("colour above alpha", fd -> writeAll(fd, cat(reply(R, 0, 1, 2, 1, 0, 8),
                new byte[] {9, 0, 0, 1, 0, 0, 0, 0}, end(E, 0))), GuestLink.OP_THUMBNAIL);
        expectRefused("rotation 45", fd -> writeAll(fd, cat(reply(R, 0, 1, 2, 1, 45, 8), px, end(E, 0))),
                GuestLink.OP_THUMBNAIL);
        expectRefused("no trailer", fd -> writeAll(fd, cat(reply(R, 0, 1, 2, 1, 0, 8), px)), GuestLink.OP_THUMBNAIL);
        expectRefused("trailer status", fd -> writeAll(fd, cat(reply(R, 0, 1, 2, 1, 0, 8), px, end(E, 3))),
                GuestLink.OP_THUMBNAIL);
        expectRefused("cut pixels", fd -> writeAll(fd, cat(reply(R, 0, 1, 2, 1, 0, 8), new byte[5])),
                GuestLink.OP_THUMBNAIL);
        expectRefused("slow drip", fd -> {
            byte[] all = cat(reply(R, 0, 1, 2, 1, 0, 8), px, end(E, 0));
            for (byte b : all) {
                writeAll(fd, new byte[] {b});
                SystemClock.sleep(400);
            }
        }, GuestLink.OP_THUMBNAIL);
        expectRefused("unknown status", fd -> writeAll(fd, cat(reply(R, 7, 0, 0, 0, 0, 0), end(E, 7))),
                GuestLink.OP_PROBE);
        expectRefused("failure with values", fd -> writeAll(fd, cat(reply(R, 3, 1, 5, 5, 0, 0), end(E, 3))),
                GuestLink.OP_PROBE);
        expectRefused("probe payload", fd -> writeAll(fd, cat(reply(R, 0, 1, 5, 5, 0, 4), new byte[4], end(E, 0))),
                GuestLink.OP_PROBE);
        expectRefused("format 9", fd -> writeAll(fd, cat(reply(R, 0, 9, 5, 5, 0, 0), end(E, 0))), GuestLink.OP_PROBE);
        expectRefused("meta control char", fd -> writeAll(fd, cat(reply(R, 0, 1, 4, 3, 0, 1024),
                meta(b -> b.put(48, (byte) 0x1b)), end(E, 0))), GuestLink.OP_METADATA);
        expectRefused("meta unterminated id", fd -> writeAll(fd, cat(reply(R, 0, 1, 4, 3, 0, 1024),
                meta(b -> {
                    for (int i = 0; i < 128; i++) b.put(432 + i, (byte) 'a');
                }), end(E, 0))), GuestLink.OP_METADATA);
        expectRefused("meta bidi id byte", fd -> writeAll(fd, cat(reply(R, 0, 1, 4, 3, 0, 1024),
                meta(b -> b.put(432, (byte) 0xe2)), end(E, 0))), GuestLink.OP_METADATA);
        expectRefused("meta unknown flag", fd -> writeAll(fd, cat(reply(R, 0, 1, 4, 3, 0, 1024),
                meta(b -> b.putInt(8, 1 << 9)), end(E, 0))), GuestLink.OP_METADATA);
        expectRefused("meta latitude", fd -> writeAll(fd, cat(reply(R, 0, 1, 4, 3, 0, 1024),
                meta(b -> b.putInt(8, GuestLink.HAS_ORIENTATION | GuestLink.HAS_GPS).putInt(40, 950000000)),
                end(E, 0))), GuestLink.OP_METADATA);
        expectRefused("meta size mismatch", fd -> writeAll(fd, cat(reply(R, 0, 1, 4, 3, 0, 1024),
                meta(b -> b.putInt(16, 5)), end(E, 0))), GuestLink.OP_METADATA);
        expectRefused("meta reserved bytes", fd -> writeAll(fd, cat(reply(R, 0, 1, 4, 3, 0, 1024),
                meta(b -> b.put(1023, (byte) 1)), end(E, 0))), GuestLink.OP_METADATA);

        // Random replies: every one must be refused or fully checked, never crash, never pass the deadline.
        Random rnd = new Random(20261117);
        int refused = 0, accepted = 0, bad = 0;
        long worst = 0;
        for (int i = 0; i < 300; i++) {
            byte[] junk = new byte[rnd.nextInt(2100)];
            rnd.nextBytes(junk);
            if (rnd.nextBoolean() && junk.length >= 32) System.arraycopy(reply(R, 0, 1, 2, 1, 0, 8), 0, junk, 0, 28);
            int op = rnd.nextInt(3) == 0 ? GuestLink.OP_METADATA : GuestLink.OP_THUMBNAIL;
            long t0 = SystemClock.uptimeMillis();
            Object r = stub(fd -> writeAll(fd, junk), op, 1500);
            worst = Math.max(worst, SystemClock.uptimeMillis() - t0);
            if (r instanceof GuestLink.ProtocolException) {
                refused++;
            } else if (r instanceof GuestLink.Answer) {
                accepted++;
            } else {
                bad++;
            }
        }
        if (bad == 0 && worst < 2500) {
            pass("stub random replies", refused + " refused, " + accepted + " accepted, worst " + worst + " ms");
        } else {
            fail("stub random replies", bad + " unexpected, worst " + worst + " ms");
        }

        schedulerChecks();
    }

    private void schedulerChecks() throws Exception {
        long[] now = {0};
        Scheduler s = new Scheduler(() -> now[0]);
        List<Scheduler.Job> a = new ArrayList<>();
        int accepted = 0;
        for (int i = 0; i < 40; i++) {
            Scheduler.Job j = new Scheduler.Job("flooder", false, 1000) {
                @Override void run() {}
            };
            if (s.offer(j)) accepted++;
            a.add(j);
        }
        Scheduler.Job other = new Scheduler.Job("other", false, 1000) {
            @Override void run() {}
        };
        Scheduler.Job urgent = new Scheduler.Job("flooder", true, 1000) {
            @Override void run() {}
        };
        boolean otherIn = s.offer(other);
        boolean urgentIn = s.offer(urgent); // the flooder's lane is full: refused even when urgent
        Scheduler.Job first = s.take();
        Scheduler.Job second = s.take();
        boolean ok = accepted == Scheduler.MAX_PER_LANE && otherIn && !urgentIn && first == a.get(0)
                && second == other;
        Scheduler s2 = new Scheduler(() -> now[0]);
        Scheduler.Job bg = new Scheduler.Job("x", false, 1000) {
            @Override void run() {}
        };
        Scheduler.Job fg = new Scheduler.Job("y", true, 1000) {
            @Override void run() {}
        };
        s2.offer(bg);
        s2.offer(fg);
        ok &= s2.take() == fg;
        if (ok) {
            pass("scheduler lanes", "flood capped at " + accepted + ", other lane served second, user first");
        } else {
            fail("scheduler lanes", "accepted " + accepted + " other " + otherIn + " urgent " + urgentIn);
        }
    }

    // --- Against the real VM --------------------------------------------------------------------------------------

    private byte[] read(File f) throws IOException {
        return Files.readAllBytes(f.toPath());
    }

    private Decoder.Request call(Decoder d, int op, int a, int b, byte[] file, long millis) {
        return d.run(new Decoder.Request(op, a, b, file, file == null ? 0 : file.length, "selftest", true,
                SystemClock.uptimeMillis() + millis));
    }

    private void vmChecks() throws Exception {
        File base = getExternalFilesDir(null);
        File source = new File(base, "decoder-vm");
        File images = new File(base, "images");
        File[] files = images.listFiles();
        if (files == null || files.length == 0) {
            fail("vm images", "none in " + images);
            return;
        }
        java.util.Arrays.sort(files);
        for (long mib : new long[] {64, 96, 128}) {
            GuestVm vm = new GuestVm(this, new File(source, "kernel"), new File(source, "initrd.img"), mib << 20);
            Decoder d = new Decoder(vm);
            long t0 = SystemClock.uptimeMillis();
            Decoder.Request ping = call(d, GuestLink.OP_PING, 0, 0, null, 60000);
            long startMs = SystemClock.uptimeMillis() - t0;
            if (ping.status != GuestLink.OK) {
                fail("vm " + mib + " MiB start", "status " + ping.status + " after " + startMs + " ms");
                vm.stop();
                continue;
            }
            pass("vm " + mib + " MiB start", startMs + " ms to the first answer");
            for (File f : files) {
                byte[] bytes = read(f);
                for (int box : new int[] {256, 1080}) {
                    d.clearCache();
                    long s0 = SystemClock.uptimeMillis();
                    Decoder.Request r = call(d, GuestLink.OP_THUMBNAIL, box, box, bytes, 40000);
                    long ms = SystemClock.uptimeMillis() - s0;
                    String what = "vm " + mib + " MiB thumb " + box + " " + f.getName();
                    String detail = (r.answer != null && r.answer.pixels != null
                            ? r.answer.width + "x" + r.answer.height + " rot " + r.answer.extra : "status " + r.status)
                            + ", " + ms + " ms, " + bytes.length + " bytes";
                    if (r.status == GuestLink.OK) pass(what, detail); else fail(what, detail);
                }
                long s0 = SystemClock.uptimeMillis();
                Decoder.Request m = call(d, GuestLink.OP_METADATA, 0, 0, bytes, 20000);
                long ms = SystemClock.uptimeMillis() - s0;
                if (m.status == GuestLink.OK && m.answer.meta != null) {
                    GuestLink.Meta v = m.answer.meta;
                    pass("vm " + mib + " MiB meta " + f.getName(), v.width + "x" + v.height + " orient "
                            + v.orientation + " date " + v.dateTakenMillis + " exp '" + v.exposureTime + "' iso '"
                            + v.iso + "' doc '" + v.documentId + "', " + ms + " ms");
                } else {
                    fail("vm " + mib + " MiB meta " + f.getName(), "status " + m.status + ", " + ms + " ms");
                }
                // The cache: the same file again costs no VM time.
                long c0 = SystemClock.uptimeMillis();
                Decoder.Request again = call(d, GuestLink.OP_METADATA, 0, 0, bytes, 20000);
                long cms = SystemClock.uptimeMillis() - c0;
                if (again.status == m.status && cms < 200) {
                    pass("vm " + mib + " MiB cache " + f.getName(), cms + " ms");
                } else {
                    fail("vm " + mib + " MiB cache " + f.getName(), cms + " ms");
                }
            }
            if (mib == 128) lockdownChecks(d);
            if (mib == 128) failClosedChecks(vm, d, read(files[0]), source);
            vm.stop();
        }
    }

    private void lockdownChecks(Decoder d) {
        // 1: open, 2: mmap, 3: spin, 4: lockdown report, 5: fork. With seccomp strict, every hook that makes a
        // forbidden system call is killed by the kernel: no 1x1 report comes back, the request fails as INVALID.
        Decoder.Request report = call(d, GuestLink.OP_HOOK, 4, 0, null, 40000);
        if (report.status == GuestLink.OK && report.answer.pixels[0] == 1 && report.answer.pixels[1] == 0) {
            pass("lockdown seccomp strict entered", "errno 0");
        } else {
            fail("lockdown seccomp strict entered", "status " + report.status
                    + (report.answer != null && report.answer.pixels != null
                            ? " errno " + (report.answer.pixels[1] & 0xff) : ""));
        }
        String[] names = {"", "open", "mmap", "spin", "", "fork"};
        for (int hook : new int[] {1, 2, 5, 3}) {
            long t0 = SystemClock.uptimeMillis();
            Decoder.Request r = call(d, GuestLink.OP_HOOK, hook, 0, null, 45000);
            long ms = SystemClock.uptimeMillis() - t0;
            if (r.status == GuestLink.INVALID) {
                pass("lockdown kills " + names[hook], ms + " ms");
            } else {
                fail("lockdown kills " + names[hook], "status " + r.status + (r.answer != null
                        && r.answer.pixels != null ? " report " + (r.answer.pixels[0] & 0xff) : "") + ", " + ms
                        + " ms");
            }
        }
    }

    private void failClosedChecks(GuestVm vm, Decoder d, byte[] file, File source) throws Exception {
        // 1. The VM stops while a request runs: the request answers UNAVAILABLE, nothing is decoded here.
        d.clearCache();
        Thread stopper = new Thread(() -> {
            SystemClock.sleep(50);
            vm.stop();
        });
        stopper.start();
        Decoder.Request r = call(d, GuestLink.OP_THUMBNAIL, 4096, 4096, file, 20000);
        stopper.join();
        log("info fail-closed mid-request: status " + r.status);
        // 2. The VM cannot start (its kernel is gone): requests answer UNAVAILABLE within their deadline.
        File hidden = new File(source.getParentFile(), "decoder-vm.hidden");
        if (!source.renameTo(hidden)) {
            fail("fail closed without a VM", "could not hide the kernel");
            return;
        }
        File staged = new File(getDataDir(), "files/decoder-vm");
        File stagedDe = new File(createDeviceProtectedStorageContext().getFilesDir(), "decoder-vm");
        deleteTree(staged);
        deleteTree(stagedDe);
        vm.stop();
        d.clearCache();
        int unavailable = 0;
        long worst = 0;
        for (int i = 0; i < 3; i++) {
            long t0 = SystemClock.uptimeMillis();
            Decoder.Request x = call(d, GuestLink.OP_THUMBNAIL, 256, 256, file, 5000);
            worst = Math.max(worst, SystemClock.uptimeMillis() - t0);
            if (x.status == Decoder.UNAVAILABLE && x.answer == null) unavailable++;
        }
        if (!hidden.renameTo(source)) log("info could not restore the kernel");
        if (unavailable == 3 && worst <= 5500) {
            pass("fail closed without a VM", "3 of 3 unavailable, worst " + worst + " ms, no decode outside the VM");
        } else {
            fail("fail closed without a VM", unavailable + " of 3 unavailable, worst " + worst + " ms");
        }
        // 3. With the kernel back, the service recovers on its own after its backoff.
        long t0 = SystemClock.uptimeMillis();
        Decoder.Request back = null;
        while (SystemClock.uptimeMillis() - t0 < 90000) {
            back = call(d, GuestLink.OP_THUMBNAIL, 256, 256, file, 10000);
            if (back.status == GuestLink.OK) break;
            SystemClock.sleep(1000);
        }
        long ms = SystemClock.uptimeMillis() - t0;
        if (back != null && back.status == GuestLink.OK) {
            pass("recovers after backoff", ms + " ms");
        } else {
            fail("recovers after backoff", "status " + (back == null ? "none" : back.status) + " after " + ms + " ms");
        }
    }

    private static void deleteTree(File f) {
        File[] kids = f.listFiles();
        if (kids != null) for (File k : kids) deleteTree(k);
        f.delete();
    }
}
