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

import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.IBinder;
import android.os.Process;
import android.os.SystemClock;

import de.diamaneos.sanitizer.decode.DecodeRequest;
import de.diamaneos.sanitizer.decode.IDecodeService;
import de.diamaneos.sanitizer.decode.ImageInfo;
import de.diamaneos.sanitizer.decode.MetadataRecord;
import de.diamaneos.sanitizer.decode.Thumbnail;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * IDecodeService for MediaProvider, SystemUI and the system server. Callers need the DECODE permission (signature or
 * privileged, allowlisted) and must be on this service's own list. The service reads the caller's file as opaque bytes
 * and hands it to the VM: it never parses it. Every failure answers STATUS_UNAVAILABLE or a VM status, so callers fail
 * closed. There is no setting or flag that turns any of this off.
 */
public final class DecodeService extends Service {
    static final String PERMISSION = "de.diamaneos.sanitizer.permission.DECODE";

    /** Packages that may call, besides the system server (uid 1000). */
    private static final String[] CALLERS = {
        "com.android.providers.media.module",
        "com.google.android.providers.media.module",
        "com.android.systemui",
    };

    // Reading the caller's file, which may be a pipe that never ends.
    private static final long READ_MILLIS = 10000;
    // Total time for a request, queue included.
    private static final long USER_WAITING_MILLIS = 20000;
    private static final long BACKGROUND_MILLIS = 60000;
    // Handles of decoded thumbnails: per caller, at most this many and this long.
    private static final int MAX_HANDLES_PER_UID = 16;

    private Decoder mDecoder;
    private final SecureRandom mRandom = new SecureRandom();
    private final Map<Long, Held> mHandles = new HashMap<>();

    private static final class Held {
        final int uid;
        final byte[] pixels;
        final int width, height, stripeRows;
        final long expires;

        Held(int uid, byte[] pixels, int width, int height, int stripeRows, long expires) {
            this.uid = uid;
            this.pixels = pixels;
            this.width = width;
            this.height = height;
            this.stripeRows = stripeRows;
            this.expires = expires;
        }
    }

    @Override
    public void onCreate() {
        mDecoder = DecoderApp.decoder(this);
    }

    @Override
    public IBinder onBind(Intent intent) {
        return mBinder;
    }

    private void checkCaller() {
        enforceCallingPermission(PERMISSION, "decode service");
        int uid = Binder.getCallingUid();
        if (uid == Process.SYSTEM_UID) return;
        String[] packages = getPackageManager().getPackagesForUid(uid);
        if (packages != null) {
            for (String p : packages) {
                for (String allowed : CALLERS) {
                    if (allowed.equals(p)) return;
                }
            }
        }
        throw new SecurityException("not an allowed caller of the decode service");
    }

    /** The caller's file as opaque bytes, or null when it cannot be read in time or is too large. */
    private static byte[] readInput(DecodeRequest request) {
        if (request == null || request.file == null) return null;
        try (FdChannel in = new FdChannel(request.file)) {
            return in.readAll(IDecodeService.MAX_INPUT_BYTES, SystemClock.uptimeMillis() + READ_MILLIS);
        } catch (IOException e) {
            return null;
        }
    }

    private Decoder.Request run(DecodeRequest request, int op, int a, int b) {
        byte[] file = readInput(request);
        boolean waiting = request != null && request.priority == IDecodeService.PRIORITY_USER_WAITING;
        long deadline = SystemClock.uptimeMillis() + (waiting ? USER_WAITING_MILLIS : BACKGROUND_MILLIS);
        String lane = request != null && request.ownerPackage != null ? request.ownerPackage : "";
        if (file == null) {
            Decoder.Request r = new Decoder.Request(op, a, b, null, 0, lane, waiting, deadline);
            r.status = GuestLink.INVALID;
            return r;
        }
        return mDecoder.run(new Decoder.Request(op, a, b, file, file.length, lane, waiting, deadline));
    }

    static int status(int vmStatus) {
        switch (vmStatus) {
            case GuestLink.OK: return IDecodeService.STATUS_OK;
            case GuestLink.UNSUPPORTED: return IDecodeService.STATUS_UNSUPPORTED;
            case GuestLink.INVALID: return IDecodeService.STATUS_INVALID;
            default: return IDecodeService.STATUS_UNAVAILABLE;
        }
    }

    private final IDecodeService.Stub mBinder = new IDecodeService.Stub() {
        @Override
        public ImageInfo probe(DecodeRequest request) {
            checkCaller();
            Decoder.Request r = DecodeService.this.run(request, GuestLink.OP_PROBE, 0, 0);
            ImageInfo info = new ImageInfo();
            info.status = status(r.status);
            if (info.status == IDecodeService.STATUS_OK) {
                info.format = r.answer.format;
                info.width = r.answer.width;
                info.height = r.answer.height;
                info.animated = r.answer.extra == 1;
            }
            return info;
        }

        @Override
        public Thumbnail decodeThumbnail(DecodeRequest request, int maxWidth, int maxHeight) {
            checkCaller();
            Thumbnail t = new Thumbnail();
            if (maxWidth < 1 || maxHeight < 1 || maxWidth > GuestLink.MAX_DIMENSION
                    || maxHeight > GuestLink.MAX_DIMENSION) {
                t.status = IDecodeService.STATUS_INVALID;
                return t;
            }
            Decoder.Request r = DecodeService.this.run(request, GuestLink.OP_THUMBNAIL, maxWidth, maxHeight);
            t.status = status(r.status);
            if (t.status != IDecodeService.STATUS_OK) return t;
            GuestLink.Answer a = r.answer;
            t.width = a.width;
            t.height = a.height;
            t.rotation = a.extra;
            t.stripeRows = Math.max(1, IDecodeService.MAX_STRIPE_BYTES / (a.width * 4));
            int uid = Binder.getCallingUid();
            synchronized (mHandles) {
                expire();
                int held = 0;
                for (Held h : mHandles.values()) if (h.uid == uid) held++;
                if (held >= MAX_HANDLES_PER_UID) {
                    t.status = IDecodeService.STATUS_UNAVAILABLE;
                    return t;
                }
                long handle;
                do {
                    handle = mRandom.nextLong();
                } while (handle == 0 || mHandles.containsKey(handle));
                mHandles.put(handle, new Held(uid, a.pixels, a.width, a.height, t.stripeRows,
                        SystemClock.uptimeMillis() + IDecodeService.HANDLE_TIMEOUT_MILLIS));
                t.handle = handle;
            }
            return t;
        }

        @Override
        public byte[] readStripe(long handle, int index) {
            checkCaller();
            Held h;
            synchronized (mHandles) {
                expire();
                h = mHandles.get(handle);
            }
            if (h == null || h.uid != Binder.getCallingUid()) return new byte[0];
            long first = (long) index * h.stripeRows;
            if (index < 0 || first >= h.height) return new byte[0];
            int rows = (int) Math.min(h.stripeRows, h.height - first);
            int stride = h.width * 4;
            byte[] out = new byte[rows * stride];
            System.arraycopy(h.pixels, (int) (first * stride), out, 0, out.length);
            return out;
        }

        @Override
        public void release(long handle) {
            checkCaller();
            synchronized (mHandles) {
                Held h = mHandles.get(handle);
                if (h != null && h.uid == Binder.getCallingUid()) mHandles.remove(handle);
            }
        }

        @Override
        public MetadataRecord readMetadata(DecodeRequest request) {
            checkCaller();
            Decoder.Request r = DecodeService.this.run(request, GuestLink.OP_METADATA, 0, 0);
            return metadata(r);
        }
    };

    static MetadataRecord metadata(Decoder.Request r) {
        MetadataRecord m = new MetadataRecord();
        m.status = status(r.status);
        m.orientation = -1;
        m.dateTakenMillis = -1;
        m.latitude = Double.NaN;
        m.longitude = Double.NaN;
        m.description = "";
        m.exposureTime = "";
        m.fNumber = "";
        m.iso = "";
        m.sceneCaptureType = "";
        m.documentId = "";
        m.instanceId = "";
        m.originalDocumentId = "";
        if (m.status != IDecodeService.STATUS_OK || r.answer == null || r.answer.meta == null) {
            if (m.status == IDecodeService.STATUS_OK) m.status = IDecodeService.STATUS_INVALID;
            return m;
        }
        GuestLink.Meta v = r.answer.meta;
        m.format = v.format;
        m.width = v.width;
        m.height = v.height;
        m.orientation = v.orientation;
        m.dateTakenMillis = v.dateTakenMillis;
        m.offsetKnown = v.offsetKnown;
        m.latitude = v.latitude;
        m.longitude = v.longitude;
        m.description = v.description;
        m.exposureTime = v.exposureTime;
        m.fNumber = v.fNumber;
        m.iso = v.iso;
        m.sceneCaptureType = v.sceneCaptureType;
        m.documentId = v.documentId;
        m.instanceId = v.instanceId;
        m.originalDocumentId = v.originalDocumentId;
        m.specialFormat = v.specialFormat;
        return m;
    }

    private void expire() {
        long now = SystemClock.uptimeMillis();
        Iterator<Held> it = mHandles.values().iterator();
        while (it.hasNext()) if (it.next().expires <= now) it.remove();
    }

    @Override
    public void onTrimMemory(int level) {
        if (level >= TRIM_MEMORY_RUNNING_LOW) mDecoder.clearCache();
    }

}
