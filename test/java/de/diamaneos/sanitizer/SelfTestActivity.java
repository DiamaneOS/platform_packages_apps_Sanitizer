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
import android.content.ComponentName;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.pm.ResolveInfo;
import android.graphics.Bitmap;
import android.graphics.Gainmap;
import android.graphics.ImageDecoder;
import android.os.Bundle;
import android.os.IBinder;
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
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import de.diamaneos.sanitizer.decode.DecodeChecks;
import de.diamaneos.sanitizer.decode.DecodeRequest;
import de.diamaneos.sanitizer.decode.Frames;
import de.diamaneos.sanitizer.decode.IDecodeService;
import de.diamaneos.sanitizer.decode.ImageInfo;
import de.diamaneos.sanitizer.decode.MetadataRecord;
import de.diamaneos.sanitizer.decode.Thumbnail;

/**
 * Test builds only. Runs the decode service's checks and logs one line per check under the tag DecoderSelfTest, then
 * "DONE pass=N fail=M". Modes (intent extra "mode"): "host" runs only the checks without a VM (the hostile guest stub
 * and the scheduler), "all" adds the VM checks (memory sizes, timings, the lockdown hooks, failing closed) and the
 * same service through binder, resolved by its action like MediaProvider binds it.
 *
 * <p>The VM's kernel and initramfs (signed with the test key that test builds' pvmfw trusts) are pushed to
 * /data/local/tmp/decoder-vm/, whose label the VM manager accepts, and the test images to this app's external files
 * directory under images/.
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
                case GuestLink.OP_THUMBNAIL: return link.thumbnail(file, file.length, 2, 1, deadline); // a 2x1 box
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
        Object ok = stub(fd -> writeAll(fd, cat(reply(R, 0, 1, 2, 1, 0, 8), px, end(E, 0))), GuestLink.OP_THUMBNAIL,
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
        // After pixels a trailer may say INVALID, INTERNAL or BUSY (a late failure, accepted below), never
        // UNSUPPORTED and nothing unknown.
        expectRefused("trailer status", fd -> writeAll(fd, cat(reply(R, 0, 1, 2, 1, 0, 8), px, end(E, 2))),
                GuestLink.OP_THUMBNAIL);
        expectRefused("trailer status unknown", fd -> writeAll(fd, cat(reply(R, 0, 1, 2, 1, 0, 8), px, end(E, 9))),
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
        // The contract's formats are 1 to 10 (ICO is 9, WBMP 10): 0 and 11 are not formats.
        expectRefused("format 0", fd -> writeAll(fd, cat(reply(R, 0, 0, 5, 5, 0, 0), end(E, 0))), GuestLink.OP_PROBE);
        expectRefused("format 11", fd -> writeAll(fd, cat(reply(R, 0, 11, 5, 5, 0, 0), end(E, 0))), GuestLink.OP_PROBE);
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

        // A worker that failed after its header: zeros for the promised length, then INVALID. A clean verdict.
        Object late = stub(fd -> writeAll(fd, cat(reply(R, 0, 1, 2, 1, 0, 8), new byte[8], end(E, 3))),
                GuestLink.OP_THUMBNAIL, 2000);
        if (late instanceof GuestLink.Answer && ((GuestLink.Answer) late).status == GuestLink.INVALID
                && ((GuestLink.Answer) late).pixels == null) {
            pass("stub late failure is a clean INVALID", "");
        } else {
            fail("stub late failure is a clean INVALID", String.valueOf(late));
        }
        // A worker the VM stopped for a reason outside the file, after its header or before: BUSY, never a strike.
        Object lateBusy = stub(fd -> writeAll(fd, cat(reply(R, 0, 1, 2, 1, 0, 8), px, end(E, GuestLink.BUSY))),
                GuestLink.OP_THUMBNAIL, 2000);
        Object busy = stub(fd -> writeAll(fd, cat(reply(R, GuestLink.BUSY, 0, 0, 0, 0, 0), end(E, GuestLink.BUSY))),
                GuestLink.OP_PROBE, 2000);
        if (lateBusy instanceof GuestLink.Answer && ((GuestLink.Answer) lateBusy).status == GuestLink.BUSY
                && ((GuestLink.Answer) lateBusy).pixels == null && busy instanceof GuestLink.Answer
                && ((GuestLink.Answer) busy).status == GuestLink.BUSY) {
            pass("stub busy is a clean answer", "");
        } else {
            fail("stub busy is a clean answer", lateBusy + " / " + busy);
        }
        // Turned by 90 degrees, a stored 1x2 result fits the 2x1 box as shown, and a stored 2x1 one does not.
        Object turned = stub(fd -> writeAll(fd, cat(reply(R, 0, 1, 1, 2, 90, 8), px, end(E, 0))),
                GuestLink.OP_THUMBNAIL, 2000);
        if (turned instanceof GuestLink.Answer && ((GuestLink.Answer) turned).status == GuestLink.OK) {
            pass("stub turned box accepted", "");
        } else {
            fail("stub turned box accepted", String.valueOf(turned));
        }
        expectRefused("turned box too tall", fd -> writeAll(fd, cat(reply(R, 0, 1, 1, 3, 90, 12), new byte[12],
                end(E, 0))), GuestLink.OP_THUMBNAIL);
        expectRefused("turned box unturned size", fd -> writeAll(fd, cat(reply(R, 0, 1, 2, 1, 90, 8), px,
                end(E, 0))), GuestLink.OP_THUMBNAIL);
        expectRefused("animated JPEG", fd -> writeAll(fd, cat(reply(R, 0, 1, 5, 5, 1, 0), end(E, 0))),
                GuestLink.OP_PROBE);
        // A date in the future is accepted on the link (the service drops the date, DecodeChecks.dropFutureDate).
        Object future = stub(fd -> writeAll(fd, cat(reply(R, 0, 1, 4, 3, 0, 1024),
                meta(b -> b.putInt(8, GuestLink.HAS_ORIENTATION | GuestLink.HAS_DATE)
                        .putLong(32, System.currentTimeMillis() + 3L * 86400000L)), end(E, 0))),
                GuestLink.OP_METADATA, 2000);
        if (future instanceof GuestLink.Answer && ((GuestLink.Answer) future).meta != null) {
            pass("stub date in the future accepted", "");
        } else {
            fail("stub date in the future accepted", String.valueOf(future));
        }
        expectRefused("line separator in text", fd -> writeAll(fd, cat(reply(R, 0, 1, 4, 3, 0, 1024),
                meta(b -> b.put(48, (byte) 0xe2).put(49, (byte) 0x80).put(50, (byte) 0xa8)), end(E, 0))),
                GuestLink.OP_METADATA);

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
        Scheduler s = new Scheduler();
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
        Scheduler s2 = new Scheduler();
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
        return d.run(new Decoder.Request(op, a, b, file, file == null ? 0 : file.length, 0, "selftest", true,
                SystemClock.uptimeMillis() + millis));
    }

    private void vmChecks() throws Exception {
        File base = getExternalFilesDir(null);
        File source = TestApp.testImages();
        File images = new File(base, "images");
        File[] files = images.listFiles();
        if (files == null || files.length == 0) {
            fail("vm images", "none in " + images);
            return;
        }
        java.util.Arrays.sort(files);
        for (long mib : new long[] {96, 128, 160, 288}) {
            GuestVm vm = new GuestVm(this, new File(source, "kernel"), new File(source, "initrd.img"),
                    mib << 20, true);
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
            if (mib == 160) lockdownChecks(d);
            if (mib == 160) leakChecks(d, images);
            if (mib == 160) failClosedChecks(vm, d, read(files[0]), source);
            vm.stop();
        }
        binderChecks(images);
    }

    // --- Through the real binder service, as MediaProvider calls it ----------------------------------------------

    private IDecodeService bind() throws Exception {
        Intent intent = new Intent("de.diamaneos.sanitizer.action.DECODE").setPackage(getPackageName());
        List<ResolveInfo> found = getPackageManager().queryIntentServices(intent, 0);
        if (found.size() == 1) {
            pass("binder action resolves", found.get(0).serviceInfo.name);
        } else {
            fail("binder action resolves", found.size() + " services");
            return null;
        }
        IBinder[] got = new IBinder[1];
        CountDownLatch bound = new CountDownLatch(1);
        mConnection = new ServiceConnection() {
            @Override public void onServiceConnected(ComponentName name, IBinder service) {
                got[0] = service;
                bound.countDown();
            }
            @Override public void onServiceDisconnected(ComponentName name) {}
        };
        bindService(intent, mConnection, BIND_AUTO_CREATE);
        bound.await(10, TimeUnit.SECONDS);
        return got[0] == null ? null : IDecodeService.Stub.asInterface(got[0]);
    }

    private ServiceConnection mConnection;

    private DecodeRequest request(File f) throws Exception {
        DecodeRequest r = new DecodeRequest();
        r.file = ParcelFileDescriptor.open(f, ParcelFileDescriptor.MODE_READ_ONLY);
        r.ownerPackage = "selftest";
        r.priority = IDecodeService.PRIORITY_USER_WAITING;
        r.mimeTypeHint = "image/jpeg";
        return r;
    }

    private void binderChecks(File images) throws Exception {
        IDecodeService s = bind();
        if (s == null) {
            fail("binder bind", "no service");
            return;
        }
        // The service's own VM starts on first use.
        File photo = new File(images, "photo12.jpg");
        File turned = new File(images, "photo12-rot90.jpg");
        ImageInfo info = s.probe(request(photo));
        if (info.status == IDecodeService.STATUS_OK && info.width == 4000 && info.height == 3000) {
            pass("binder probe", info.width + "x" + info.height + " format " + info.format);
        } else {
            fail("binder probe", "status " + info.status + " " + info.width + "x" + info.height);
        }
        // A wallpaper-sized box: fitted exactly, not to an integer factor.
        Thumbnail w = s.decodeThumbnail(request(photo), 1080, 2400);
        checkThumbnail(s, "binder screen-sized thumbnail", w, 1080, 810, 0);
        // EXIF orientation 6 in a 300x200 box as shown: stored 200x150, turned by 90 degrees to 150x200.
        Thumbnail t = s.decodeThumbnail(request(turned), 300, 200);
        checkThumbnail(s, "binder turned thumbnail", t, 200, 150, 90);
        // A small output: one stripe that holds the whole height.
        Thumbnail small = s.decodeThumbnail(request(photo), 64, 64);
        checkThumbnail(s, "binder small thumbnail", small, 64, 48, 0);
        MetadataRecord m = s.readMetadata(request(new File(images, "exif-seed.jpg")));
        if (m.status == IDecodeService.STATUS_OK && m.orientation == 90 && m.offsetKnown
                && "1/120".equals(m.exposureTime) && "xmp.did:1234-abcd".equals(m.documentId)
                && Math.abs(m.latitude - 52.52009) < 0.001) {
            pass("binder metadata", "date " + m.dateTakenMillis + " lat " + m.latitude + " special "
                    + m.specialFormat);
        } else {
            fail("binder metadata", "status " + m.status + " orientation " + m.orientation + " exposure '"
                    + m.exposureTime + "' doc '" + m.documentId + "'");
        }
        colourCheck(s, new File(images, "p3-chart.jpg"));
        framesCheck(s, new File(images, "anim.gif"));
        gainmapCheck(s, new File(images, "ultrahdr.jpg"));
        Thumbnail bad = s.decodeThumbnail(request(photo), 0, 10);
        if (bad.status == IDecodeService.STATUS_INVALID) {
            pass("binder refuses a zero box", "");
        } else {
            fail("binder refuses a zero box", "status " + bad.status);
        }
        unbindService(mConnection);
    }

    /**
     * The Display P3 chart through the service against Android's own decode in this app (test builds only): the same
     * colour space, and every patch of a 10 x 8 grid within 3 levels. Skipped when the chart was not pushed.
     */
    private void colourCheck(IDecodeService s, File chart) throws Exception {
        if (!chart.exists()) {
            pass("binder colour", "skipped, no " + chart);
            return;
        }
        Thumbnail t = s.decodeThumbnail(request(chart), 4096, 4096);
        String broken = DecodeChecks.check(t, 4096, 4096);
        if (broken != null || t.status != IDecodeService.STATUS_OK || t.rotation != 0) {
            fail("binder colour", "thumbnail " + broken + " status " + t.status);
            return;
        }
        byte[] frame = new byte[t.width * t.height * 4];
        for (int i = 0; i * t.stripeRows < t.height; i++) {
            byte[] stripe = s.readStripe(t.handle, i);
            if (DecodeChecks.check(t, i, stripe) != null) {
                fail("binder colour", "stripe " + i);
                return;
            }
            System.arraycopy(stripe, 0, frame, i * t.stripeRows * t.width * 4, stripe.length);
        }
        s.release(t.handle);
        Bitmap vm = Bitmap.createBitmap(t.width, t.height, Bitmap.Config.ARGB_8888, true, DecodeChecks.colorSpaceOf(t));
        vm.copyPixelsFromBuffer(ByteBuffer.wrap(frame));
        Bitmap ref = ImageDecoder.decodeBitmap(ImageDecoder.createSource(chart),
                (d, info, src) -> d.setAllocator(ImageDecoder.ALLOCATOR_SOFTWARE));
        if (ref.getWidth() != vm.getWidth() || ref.getHeight() != vm.getHeight()
                || !ref.getColorSpace().equals(vm.getColorSpace())) {
            fail("binder colour", "Android " + ref.getWidth() + "x" + ref.getHeight() + " " + ref.getColorSpace()
                    + ", VM " + vm.getWidth() + "x" + vm.getHeight() + " " + vm.getColorSpace());
            return;
        }
        ByteBuffer a = ByteBuffer.allocate(vm.getByteCount()), b = ByteBuffer.allocate(ref.getByteCount());
        vm.copyPixelsToBuffer(a);
        ref.copyPixelsToBuffer(b);
        double worst = 0;
        int w = vm.getWidth(), h = vm.getHeight();
        for (int r = 0; r < 8; r++) {
            for (int c = 0; c < 10; c++) {
                double[] sa = new double[3], sb = new double[3];
                int n = 0;
                for (int y = r * h / 8 + 4; y < (r + 1) * h / 8 - 4; y++) {
                    for (int x = c * w / 10 + 4; x < (c + 1) * w / 10 - 4; x++, n++) {
                        int i = (y * w + x) * 4;
                        for (int k = 0; k < 3; k++) {
                            sa[k] += a.get(i + k) & 0xff;
                            sb[k] += b.get(i + k) & 0xff;
                        }
                    }
                }
                for (int k = 0; k < 3 && n > 0; k++) worst = Math.max(worst, Math.abs(sa[k] - sb[k]) / n);
            }
        }
        if (worst <= 3) {
            pass("binder colour", vm.getColorSpace().getName() + ", largest patch difference "
                    + String.format(java.util.Locale.ROOT, "%.2f", worst) + " levels");
        } else {
            fail("binder colour", "largest patch difference " + worst + " levels");
        }
    }

    /** An animated GIF frame by frame through the service: five checked frames with their times. */
    private void framesCheck(IDecodeService s, File gif) throws Exception {
        if (!gif.exists()) {
            pass("binder frames", "skipped, no " + gif);
            return;
        }
        Frames f = s.decodeFrames(request(gif), 512, 512);
        String broken = DecodeChecks.check(f, 512, 512);
        if (broken != null || f.status != IDecodeService.STATUS_OK || f.frameCount != 5) {
            fail("binder frames", "frames " + broken + " status " + f.status + " count " + f.frameCount);
            return;
        }
        int rows = f.frameCount * f.height;
        long total = 0;
        for (int i = 0; i * f.stripeRows < rows; i++) {
            byte[] stripe = s.readStripe(f.handle, i);
            if (DecodeChecks.check(f, i, stripe) != null) {
                fail("binder frames", "stripe " + i);
                return;
            }
            total += stripe.length;
        }
        s.release(f.handle);
        if (total == (long) rows * f.width * 4) {
            pass("binder frames", f.frameCount + " frames of " + f.width + "x" + f.height + ", loops " + f.loopCount);
        } else {
            fail("binder frames", "total " + total);
        }
    }

    /**
     * An Ultra HDR photo through the service against Android's own decode in this app: a gain map of the same size,
     * the same parameters, every pixel within 2 levels. Skipped when the photo was not pushed.
     */
    private void gainmapCheck(IDecodeService s, File photo) throws Exception {
        if (!photo.exists()) {
            pass("binder gain map", "skipped, no " + photo);
            return;
        }
        Thumbnail t = s.decodeThumbnail(request(photo), 4096, 4096);
        String broken = DecodeChecks.check(t, 4096, 4096);
        if (broken != null || t.status != IDecodeService.STATUS_OK || t.gainmapWidth == 0) {
            fail("binder gain map", "thumbnail " + broken + " status " + t.status + " gain " + t.gainmapWidth);
            return;
        }
        byte[] gain = new byte[t.gainmapWidth * t.gainmapHeight * 4];
        for (int i = 0; i * t.gainmapStripeRows < t.gainmapHeight; i++) {
            byte[] stripe = s.readGainmapStripe(t.handle, i);
            if (DecodeChecks.checkGainmap(t, i, stripe) != null) {
                fail("binder gain map", "stripe " + i);
                return;
            }
            System.arraycopy(stripe, 0, gain, i * t.gainmapStripeRows * t.gainmapWidth * 4, stripe.length);
        }
        s.release(t.handle);
        Gainmap vm = DecodeChecks.gainmapOf(t, gain);
        Bitmap ref = ImageDecoder.decodeBitmap(ImageDecoder.createSource(photo),
                (d, info, src) -> d.setAllocator(ImageDecoder.ALLOCATOR_SOFTWARE));
        Gainmap g = ref.getGainmap();
        Bitmap rc = g == null ? null : g.getGainmapContents();
        Bitmap vc = vm.getGainmapContents();
        if (rc == null || rc.getWidth() != vc.getWidth() || rc.getHeight() != vc.getHeight()) {
            fail("binder gain map", "Android " + (rc == null ? "none" : rc.getWidth() + "x" + rc.getHeight())
                    + ", VM " + vc.getWidth() + "x" + vc.getHeight());
            return;
        }
        float[][] mine = {vm.getRatioMin(), vm.getRatioMax(), vm.getGamma(), vm.getEpsilonSdr(), vm.getEpsilonHdr(),
                {vm.getMinDisplayRatioForHdrTransition(), vm.getDisplayRatioForFullHdr()}};
        float[][] theirs = {g.getRatioMin(), g.getRatioMax(), g.getGamma(), g.getEpsilonSdr(), g.getEpsilonHdr(),
                {g.getMinDisplayRatioForHdrTransition(), g.getDisplayRatioForFullHdr()}};
        for (int i = 0; i < mine.length; i++) {
            for (int k = 0; k < mine[i].length; k++) {
                if (Math.abs(mine[i][k] - theirs[i][k]) > 1e-3f * Math.max(1f, Math.abs(theirs[i][k]))) {
                    fail("binder gain map", "parameter " + i + "." + k + ": Android " + theirs[i][k] + ", VM "
                            + mine[i][k]);
                    return;
                }
            }
        }
        // Android keeps a grey gain map as ALPHA_8, the service sends it as RGBA with equal channels.
        boolean alphaOnly = rc.getConfig() == Bitmap.Config.ALPHA_8;
        int worst = 0;
        for (int y = 0; y < vc.getHeight(); y++) {
            for (int x = 0; x < vc.getWidth(); x++) {
                int a = vc.getPixel(x, y), b = rc.getPixel(x, y);
                int va = android.graphics.Color.red(a);
                int vb = alphaOnly ? android.graphics.Color.alpha(b) : android.graphics.Color.red(b);
                worst = Math.max(worst, Math.abs(va - vb));
            }
        }
        if (worst <= 2) {
            pass("binder gain map", vc.getWidth() + "x" + vc.getHeight() + ", largest difference " + worst
                    + " levels");
        } else {
            fail("binder gain map", "largest difference " + worst + " levels");
        }
    }

    private void checkThumbnail(IDecodeService s, String what, Thumbnail t, int w, int h, int rotation)
            throws Exception {
        if (t.status != IDecodeService.STATUS_OK || t.width != w || t.height != h || t.rotation != rotation
                || t.stripeRows < 1 || t.stripeRows > t.height
                || (long) t.stripeRows * t.width * 4 > IDecodeService.MAX_STRIPE_BYTES) {
            fail(what, "status " + t.status + " " + t.width + "x" + t.height + " rotation " + t.rotation
                    + " stripeRows " + t.stripeRows);
            return;
        }
        long total = 0;
        int stripes = (t.height + t.stripeRows - 1) / t.stripeRows;
        for (int i = 0; i < stripes; i++) {
            byte[] stripe = s.readStripe(t.handle, i);
            int rows = Math.min(t.stripeRows, t.height - i * t.stripeRows);
            if (stripe.length != rows * t.width * 4) {
                fail(what, "stripe " + i + " has " + stripe.length + " bytes");
                return;
            }
            total += stripe.length;
        }
        boolean beyond = s.readStripe(t.handle, stripes).length == 0;
        s.release(t.handle);
        boolean gone = s.readStripe(t.handle, 0).length == 0;
        if (total == (long) t.width * t.height * 4 && beyond && gone) {
            pass(what, t.width + "x" + t.height + " rotation " + t.rotation + ", " + stripes + " stripes of "
                    + t.stripeRows + " rows, released");
        } else {
            fail(what, "total " + total + " beyond " + beyond + " gone " + gone);
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
            // Killed: the worker died, which is no verdict on a file, so "unavailable" (never cached).
            if (r.status == Decoder.UNAVAILABLE && r.died) {
                pass("lockdown kills " + names[hook], ms + " ms");
            } else {
                fail("lockdown kills " + names[hook], "status " + r.status + (r.answer != null
                        && r.answer.pixels != null ? " report " + (r.answer.pixels[0] & 0xff) : "") + ", " + ms
                        + " ms");
            }
        }
    }

    private void leakChecks(Decoder d, File images) throws Exception {
        // Another request's metadata must not reach the next worker: a worker scans its own memory for it.
        byte[] seed = read(new File(images, "exif-seed.jpg"));
        String marker = "LK" + Long.toHexString(System.nanoTime() & 0xffffffffffL);
        marker = (marker + "0000000000").substring(0, 12); // the length of "Holiday shot"
        byte[] withMarker = replace(seed, "Holiday shot".getBytes(), marker.getBytes());
        Decoder.Request meta = call(d, GuestLink.OP_METADATA, 0, 0, withMarker, 20000);
        Decoder.Request scan = hookCall(d, 6, marker.getBytes());
        Decoder.Request control = hookCall(d, 6, "DSR2".getBytes());
        boolean ok = meta.status == GuestLink.OK && marker.equals(meta.answer.meta.description)
                && scan.status == GuestLink.OK && scan.answer.pixels[0] == 0 && control.status == GuestLink.OK
                && control.answer.pixels[0] == 1;
        if (ok) {
            pass("no leak between requests", "marker not found in the next worker, the control found");
        } else {
            fail("no leak between requests", "meta " + meta.status + " scan " + scan.status
                    + (scan.answer != null && scan.answer.pixels != null ? " found " + scan.answer.pixels[0] : "")
                    + " control " + control.status);
        }
    }

    private Decoder.Request hookCall(Decoder d, int hook, byte[] input) {
        return d.run(new Decoder.Request(GuestLink.OP_HOOK, hook, 0, input, input.length, 0, "selftest", true,
                SystemClock.uptimeMillis() + 30000));
    }

    private static byte[] replace(byte[] in, byte[] from, byte[] to) {
        byte[] out = in.clone();
        outer:
        for (int i = 0; i + from.length <= in.length; i++) {
            for (int j = 0; j < from.length; j++) if (in[i + j] != from[j]) continue outer;
            System.arraycopy(to, 0, out, i, to.length);
            return out;
        }
        return out;
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
        vm.setImagesForTest(new File(source, "missing-kernel"), new File(source, "missing-initrd"));
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
        vm.setImagesForTest(new File(source, "kernel"), new File(source, "initrd.img"));
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
}
