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

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;
import android.os.SystemClock;

import java.io.FileDescriptor;
import java.io.PrintWriter;

/**
 * The decode service's health check for the release suite (F46). It exists only for its dump: only shell or root
 * (the DUMP permission) can run it, with
 *
 * <pre>adb shell dumpsys activity provider de.diamaneos.sanitizer/.HealthProvider health</pre>
 *
 * It goes through the real path: the decoder VM is started through the custom VM API by reflection, from the signed
 * kernel and initramfs in the virtualization APEX, and decodes three built-in images. The last line is "health ok" or
 * "health FAIL". It holds no data and answers no queries.
 */
public final class HealthProvider extends ContentProvider {
    @Override
    public boolean onCreate() {
        return true;
    }

    @Override
    public void dump(FileDescriptor fd, PrintWriter pw, String[] args) {
        if (args == null || args.length == 0 || !"health".equals(args[0])) {
            pw.println("decode service: run with the argument 'health' for the health check");
            return;
        }
        Decoder d = ((DecoderProvider) getContext().getApplicationContext()).decoder();
        boolean ok = true;
        long t0 = SystemClock.uptimeMillis();
        Decoder.Request ping = call(d, GuestLink.OP_PING, 0, 0, null, 60000);
        ok &= line(pw, "vm start", ping.status == GuestLink.OK, (SystemClock.uptimeMillis() - t0) + " ms"
                + (ping.status == GuestLink.OK || d.vm().lastError().isEmpty() ? "" : ": " + d.vm().lastError()));
        // The vCPUs the VM really has (its ping counts them): two for the two lanes, through our VM framework's
        // count. A framework without it (a rebase that lost vm-vcpus) shows here instead of passing unseen.
        int online = ping.answer != null ? ping.answer.extra : 0;
        ok &= line(pw, "vcpus", !d.vm().lanes() || online == GuestVm.LANE_VCPUS,
                online + " online, asked " + d.vm().cpus());
        Decoder.Request png = call(d, GuestLink.OP_THUMBNAIL, 5, 3, HealthImages.PNG, 30000);
        ok &= line(pw, "png thumbnail", png.status == GuestLink.OK && png.answer != null
                && png.answer.width == 3 && png.answer.height == 3, describe(png));
        Decoder.Request jpg = call(d, GuestLink.OP_THUMBNAIL, 8, 8, HealthImages.JPEG, 30000);
        ok &= line(pw, "jpeg thumbnail", jpg.status == GuestLink.OK && jpg.answer != null
                && jpg.answer.width == 8 && jpg.answer.height == 8, describe(jpg));
        Decoder.Request meta = call(d, GuestLink.OP_METADATA, 0, 0, HealthImages.EXIF_JPEG, 30000);
        GuestLink.Meta m = meta.answer != null ? meta.answer.meta : null;
        ok &= line(pw, "metadata", meta.status == GuestLink.OK && m != null && m.orientation == 90
                && "Holiday shot".equals(m.description) && m.dateTakenMillis == 1794904890123L
                && "xmp.did:1234-abcd".equals(m.documentId), m == null ? "status " + meta.status
                        : "orientation " + m.orientation + ", date " + m.dateTakenMillis);
        Decoder.Request bad = call(d, GuestLink.OP_THUMBNAIL, 8, 8, new byte[] {(byte) 0xff, (byte) 0xd8, (byte) 0xff,
            0, 1, 2, 3}, 30000);
        ok &= line(pw, "broken jpeg refused", bad.status == GuestLink.INVALID, "status " + bad.status);
        pw.println(ok ? "health ok" : "health FAIL");
    }

    // Each run its own lane, past the cache, so every check reaches the VM.
    private static Decoder.Request call(Decoder d, int op, int a, int b, byte[] file, long millis) {
        d.clearCache();
        return d.run(new Decoder.Request(op, a, b, file, file == null ? 0 : file.length, 0, "health", true,
                SystemClock.uptimeMillis() + millis));
    }

    private static String describe(Decoder.Request r) {
        return r.answer != null && r.answer.pixels != null ? r.answer.width + "x" + r.answer.height
                : "status " + r.status;
    }

    private static boolean line(PrintWriter pw, String what, boolean ok, String detail) {
        pw.println((ok ? "ok   " : "FAIL ") + what + ": " + detail);
        return ok;
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] args, String order) {
        return null;
    }

    @Override
    public String getType(Uri uri) {
        return null;
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        return null;
    }

    @Override
    public int delete(Uri uri, String selection, String[] args) {
        return 0;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] args) {
        return 0;
    }
}
