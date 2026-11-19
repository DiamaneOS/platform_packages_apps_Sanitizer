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
import android.os.UserHandle;
import android.util.Log;

import de.diamaneos.sanitizer.decode.DecodeChecks;
import de.diamaneos.sanitizer.decode.DecodeRequest;
import de.diamaneos.sanitizer.decode.Frames;
import de.diamaneos.sanitizer.decode.IDecodeService;
import de.diamaneos.sanitizer.decode.ImageInfo;
import de.diamaneos.sanitizer.decode.MetadataRecord;
import de.diamaneos.sanitizer.decode.Thumbnail;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * IDecodeService for MediaProvider, SystemUI and the system server, bound with the action
 * de.diamaneos.sanitizer.action.DECODE. One instance serves every user and profile (singleUser). Callers need the
 * DECODE permission (signature or privileged, allowlisted) and must be on the application's own list. The service
 * reads the caller's file as opaque bytes and hands it to the VM: it never parses it. Every failure answers
 * STATUS_UNAVAILABLE or a VM status, so callers fail closed. There is no setting or flag that turns any of this off.
 */
public final class DecodeService extends Service {
    private static final String TAG = "DecoderService";

    // Reading the caller's file, which may be a pipe that never ends.
    private static final long READ_MILLIS = 10000;
    // How long a caller waits, queue included. The VM's own work has its own budget (Decoder).
    private static final long USER_WAITING_MILLIS = 20000;
    private static final long BACKGROUND_MILLIS = 60000;
    // Handles of decoded thumbnails: per caller, at most this many and this long. Their pixels count against the
    // decoder's memory budget until released or expired.
    private static final int MAX_HANDLES_PER_UID = 16;

    private DecoderProvider mProvider;
    private Decoder mDecoder;
    private final SecureRandom mRandom = new SecureRandom();
    private final Map<Long, Held> mHandles = new HashMap<>();
    // Expires handles when they are due, not only on the next call: a caller that died leaves nothing held.
    private final android.os.Handler mExpiry = new android.os.Handler(android.os.Looper.getMainLooper());
    private final Runnable mExpireTask = () -> {
        synchronized (mHandles) {
            expire();
        }
    };

    private static final class Held {
        final int uid;
        final byte[] pixels;
        final int width, height, stripeRows;
        final long expires;
        // Ultra HDR: the gain map, if any, read through readGainmapStripe.
        byte[] gain;
        int gainWidth, gainHeight, gainStripeRows;

        Held(int uid, byte[] pixels, int width, int height, int stripeRows, long expires) {
            this.uid = uid;
            this.pixels = pixels;
            this.width = width;
            this.height = height;
            this.stripeRows = stripeRows;
            this.expires = expires;
        }

        long bytes() {
            return pixels.length + (gain != null ? gain.length : 0);
        }
    }

    @Override
    public void onCreate() {
        mProvider = (DecoderProvider) getApplication();
        mDecoder = mProvider.decoder();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return mBinder;
    }

    private void checkCaller() {
        enforceCallingPermission(mProvider.callerPermission(), "decode service");
        int uid = Binder.getCallingUid();
        if (UserHandle.getAppId(uid) == Process.SYSTEM_UID) return;
        String[] packages = getPackageManager().getPackagesForUid(uid);
        if (packages != null) {
            for (String p : packages) {
                for (String allowed : mProvider.allowedCallers()) {
                    if (allowed.equals(p)) return;
                }
            }
        }
        throw new SecurityException("not an allowed caller of the decode service");
    }

    // Reads of caller files run here, so a read that never returns (a stalled FUSE file) costs a reader thread, not a
    // binder thread. Such reads are counted per lane until they end, and capped (Decoder.admit).
    private static final ExecutorService READERS = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "decoder-read");
        t.setDaemon(true);
        return t;
    });

    private Decoder.Request run(DecodeRequest request, int op, int a, int b) {
        boolean waiting = request != null && request.priority == IDecodeService.PRIORITY_USER_WAITING;
        long deadline = SystemClock.uptimeMillis() + (waiting ? USER_WAITING_MILLIS : BACKGROUND_MILLIS);
        String lane = request != null && request.ownerPackage != null ? request.ownerPackage : "";
        Decoder.Request failed = new Decoder.Request(op, a, b, null, 0, 0, lane, waiting, deadline);
        if (request == null || request.file == null) {
            failed.status = GuestLink.INVALID;
            return failed;
        }
        // Fairness before memory: a lane that is busy or has stuck reads is refused before anything is allocated.
        if (!mDecoder.admit(lane)) {
            closeQuietly(request);
            return failed;
        }
        try {
            FdChannel.Input in = read(request, op, lane);
            if (in == null) return failed; // the read did not end in time: unavailable
            if (in.status != FdChannel.Input.OK) {
                // Only a file too large or unreadable is a verdict. No memory now, a slow read or a turn to wait for
                // is "try again later".
                failed.status = in.status == FdChannel.Input.TOO_LARGE ? GuestLink.INVALID : Decoder.UNAVAILABLE;
                return failed;
            }
            Decoder.Request r = new Decoder.Request(op, a, b, in.data, in.len, in.reserved, lane, waiting, deadline);
            r.user = Binder.getCallingUid() / 100000; // the Android user (UserHandle.PER_USER_RANGE)
            r.source = in.source;
            r.digest = in.digest;
            in = null; // the request owns the bytes now, and drops them when the VM's reply begins
            return mDecoder.run(r);
        } finally {
            mDecoder.leave(lane);
        }
    }

    // Reads the caller's file on a reader thread, waiting at most READ_MILLIS. Null when it did not end in time: the
    // thread stays stuck in the read, counted against the lane until it ends, and gives back its memory then.
    private FdChannel.Input read(DecodeRequest request, int op, String lane) {
        // A probe reads the head. A thumbnail of a large local JPEG or PNG streams. Metadata of a file too large to
        // hold reads the head too: a JPEG or PNG keeps its metadata before its image data.
        boolean head = op == GuestLink.OP_PROBE;
        int max = head ? IDecodeService.MAX_PROBE_BYTES : IDecodeService.MAX_BUFFERED_BYTES;
        // Decided on the reader thread from fstat, which can stall on FUSE too.
        long headAbove = op == GuestLink.OP_METADATA ? IDecodeService.MAX_BUFFERED_BYTES : Long.MAX_VALUE;
        boolean stream = op == GuestLink.OP_THUMBNAIL;
        long deadline = SystemClock.uptimeMillis() + READ_MILLIS;
        FdChannel channel = new FdChannel(request.file);
        Object lock = new Object();
        boolean[] abandoned = {false};
        Future<FdChannel.Input> f = READERS.submit(() -> {
            // A large regular file (not on FUSE) streams to the VM, anything else is read into memory here.
            FdChannel.Input in = stream ? channel.streamInput(IDecodeService.MAX_BUFFERED_BYTES,
                    IDecodeService.MAX_INPUT_BYTES, deadline, mDecoder, lane) : null;
            if (in == null) {
                in = channel.readInput(max, head, headAbove, IDecodeService.MAX_PROBE_BYTES, deadline, mDecoder, lane);
            }
            synchronized (lock) {
                if (abandoned[0]) {
                    // Too late: nobody takes this input any more.
                    if (in.status == FdChannel.Input.OK) mDecoder.release(lane, in.reserved);
                    if (in.source != null) {
                        try {
                            in.source.close();
                        } catch (IOException ignored) {
                            // closed already
                        }
                    }
                    mDecoder.stuck(lane, -1);
                    in = null;
                }
            }
            try {
                channel.close();
            } catch (IOException ignored) {
                // closed already
            }
            return in;
        });
        try {
            return f.get(READ_MILLIS + 1000, TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            synchronized (lock) {
                if (!f.isDone()) {
                    abandoned[0] = true;
                    mDecoder.stuck(lane, 1);
                }
            }
            if (!abandoned[0]) {
                try {
                    return f.get();
                } catch (Exception again) {
                    return null;
                }
            }
            try {
                channel.close(); // may not wake a FUSE read, but frees what it can
            } catch (IOException ignored) {
                // closed already
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    private static void closeQuietly(DecodeRequest request) {
        try {
            request.file.close();
        } catch (IOException ignored) {
            // closed already
        }
    }

    static int status(int vmStatus) {
        switch (vmStatus) {
            case GuestLink.OK: return IDecodeService.STATUS_OK;
            case GuestLink.UNSUPPORTED: return IDecodeService.STATUS_UNSUPPORTED;
            case GuestLink.INVALID: return IDecodeService.STATUS_INVALID;
            default: return IDecodeService.STATUS_UNAVAILABLE;
        }
    }

    // Every binder method: a refused caller gets its SecurityException, anything else that goes wrong answers
    // "unavailable" instead of reaching the caller as an exception.
    private final IDecodeService.Stub mBinder = new IDecodeService.Stub() {
        @Override
        public ImageInfo probe(DecodeRequest request) {
            checkCaller();
            ImageInfo info = new ImageInfo();
            try {
                Decoder.Request r = DecodeService.this.run(request, GuestLink.OP_PROBE, 0, 0);
                info.status = status(r.status);
                if (info.status == IDecodeService.STATUS_OK) {
                    info.format = r.answer.format;
                    info.width = r.answer.width;
                    info.height = r.answer.height;
                    info.animated = r.answer.extra == 1;
                }
                // The callers' own checks, once more before anything leaves.
                if (DecodeChecks.check(info) != null) {
                    info = new ImageInfo();
                    info.status = IDecodeService.STATUS_INVALID;
                }
            } catch (Throwable t) {
                Log.e(TAG, "probe", t);
                info = new ImageInfo();
                info.status = IDecodeService.STATUS_UNAVAILABLE;
            }
            return info;
        }

        @Override
        public Thumbnail decodeThumbnail(DecodeRequest request, int maxWidth, int maxHeight) {
            checkCaller();
            try {
                return thumbnail(request, maxWidth, maxHeight, Binder.getCallingUid());
            } catch (Throwable t) {
                Log.e(TAG, "decodeThumbnail", t);
                Thumbnail th = new Thumbnail();
                th.status = IDecodeService.STATUS_UNAVAILABLE;
                return th;
            }
        }

        @Override
        public Frames decodeFrames(DecodeRequest request, int maxWidth, int maxHeight) {
            checkCaller();
            try {
                return frames(request, maxWidth, maxHeight, Binder.getCallingUid());
            } catch (Throwable t) {
                Log.e(TAG, "decodeFrames", t);
                Frames f = new Frames();
                f.status = IDecodeService.STATUS_UNAVAILABLE;
                return f;
            }
        }

        @Override
        public byte[] readStripe(long handle, int index) {
            checkCaller();
            try {
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
            } catch (Throwable t) {
                Log.e(TAG, "readStripe", t);
                return new byte[0];
            }
        }

        @Override
        public byte[] readGainmapStripe(long handle, int index) {
            checkCaller();
            try {
                Held h;
                synchronized (mHandles) {
                    expire();
                    h = mHandles.get(handle);
                }
                if (h == null || h.uid != Binder.getCallingUid() || h.gain == null) return new byte[0];
                long first = (long) index * h.gainStripeRows;
                if (index < 0 || first >= h.gainHeight) return new byte[0];
                int rows = (int) Math.min(h.gainStripeRows, h.gainHeight - first);
                int stride = h.gainWidth * 4;
                byte[] out = new byte[rows * stride];
                System.arraycopy(h.gain, (int) (first * stride), out, 0, out.length);
                return out;
            } catch (Throwable t) {
                Log.e(TAG, "readGainmapStripe", t);
                return new byte[0];
            }
        }

        @Override
        public void release(long handle) {
            checkCaller();
            synchronized (mHandles) {
                Held h = mHandles.get(handle);
                if (h != null && h.uid == Binder.getCallingUid()) drop(handle, h);
                expire();
            }
        }

        @Override
        public MetadataRecord readMetadata(DecodeRequest request) {
            checkCaller();
            try {
                return metadata(DecodeService.this.run(request, GuestLink.OP_METADATA, 0, 0));
            } catch (Throwable t) {
                Log.e(TAG, "readMetadata", t);
                Decoder.Request r = new Decoder.Request(GuestLink.OP_METADATA, 0, 0, null, 0, 0, "", false, 0);
                return metadata(r);
            }
        }
    };

    private Thumbnail thumbnail(DecodeRequest request, int maxWidth, int maxHeight, int uid) {
        Thumbnail t = new Thumbnail();
        if (maxWidth < 1 || maxHeight < 1 || maxWidth > GuestLink.MAX_DIMENSION
                || maxHeight > GuestLink.MAX_DIMENSION) {
            t.status = IDecodeService.STATUS_INVALID;
            return t;
        }
        Decoder.Request r = run(request, GuestLink.OP_THUMBNAIL, maxWidth, maxHeight);
        t.status = status(r.status);
        if (t.status != IDecodeService.STATUS_OK) return t;
        GuestLink.Answer a = r.answer;
        synchronized (mHandles) {
            expire();
            int held = 0;
            for (Held h : mHandles.values()) if (h.uid == uid) held++;
            long bytes = a.pixels.length + (a.gainPixels != null ? a.gainPixels.length : 0);
            if (held >= MAX_HANDLES_PER_UID || !mDecoder.reserve("uid:" + uid, bytes)) {
                t.status = IDecodeService.STATUS_UNAVAILABLE;
                return t;
            }
            t.width = a.width;
            t.height = a.height;
            t.rotation = a.extra;
            t.colorSpace = a.colorSpace;
            t.stripeRows = Math.min(a.height, Math.max(1, IDecodeService.MAX_STRIPE_BYTES / (a.width * 4)));
            long handle;
            do {
                handle = mRandom.nextLong();
            } while (handle == 0 || mHandles.containsKey(handle));
            Held kept = new Held(uid, a.pixels, a.width, a.height, t.stripeRows,
                    SystemClock.uptimeMillis() + IDecodeService.HANDLE_TIMEOUT_MILLIS);
            t.gainmapParams = new float[0];
            if (a.gainPixels != null) {
                kept.gain = a.gainPixels;
                kept.gainWidth = t.gainmapWidth = a.gainWidth;
                kept.gainHeight = t.gainmapHeight = a.gainHeight;
                kept.gainStripeRows = t.gainmapStripeRows = Math.min(a.gainHeight,
                        Math.max(1, IDecodeService.MAX_STRIPE_BYTES / (a.gainWidth * 4)));
                t.gainmapParams = a.gainParams.clone();
            }
            mHandles.put(handle, kept);
            mExpiry.postDelayed(mExpireTask, IDecodeService.HANDLE_TIMEOUT_MILLIS + 100);
            t.handle = handle;
            if (DecodeChecks.check(t, maxWidth, maxHeight) != null) {
                drop(handle, mHandles.get(handle));
                Thumbnail bad = new Thumbnail();
                bad.status = IDecodeService.STATUS_INVALID;
                return bad;
            }
        }
        return t;
    }

    // An animation's frames, held as one tall image (frame after frame) behind a handle, read in stripes like a
    // thumbnail.
    private Frames frames(DecodeRequest request, int maxWidth, int maxHeight, int uid) {
        Frames f = new Frames();
        if (maxWidth < 1 || maxHeight < 1 || maxWidth > GuestLink.MAX_DIMENSION
                || maxHeight > GuestLink.MAX_DIMENSION) {
            f.status = IDecodeService.STATUS_INVALID;
            return f;
        }
        Decoder.Request r = run(request, GuestLink.OP_FRAMES, maxWidth, maxHeight);
        f.status = status(r.status);
        if (f.status != IDecodeService.STATUS_OK) return f;
        GuestLink.Answer a = r.answer;
        synchronized (mHandles) {
            expire();
            int held = 0;
            for (Held h : mHandles.values()) if (h.uid == uid) held++;
            if (held >= MAX_HANDLES_PER_UID || !mDecoder.reserve("uid:" + uid, a.pixels.length)) {
                f.status = IDecodeService.STATUS_UNAVAILABLE;
                return f;
            }
            f.width = a.width;
            f.height = a.height;
            f.frameCount = a.extra;
            f.loopCount = a.loops;
            f.durations = a.durations.clone();
            f.colorSpace = a.colorSpace;
            f.stripeRows = Math.min(a.height * a.extra, Math.max(1, IDecodeService.MAX_STRIPE_BYTES / (a.width * 4)));
            long handle;
            do {
                handle = mRandom.nextLong();
            } while (handle == 0 || mHandles.containsKey(handle));
            mHandles.put(handle, new Held(uid, a.pixels, a.width, a.height * a.extra, f.stripeRows,
                    SystemClock.uptimeMillis() + IDecodeService.HANDLE_TIMEOUT_MILLIS));
            mExpiry.postDelayed(mExpireTask, IDecodeService.HANDLE_TIMEOUT_MILLIS + 100);
            f.handle = handle;
            if (DecodeChecks.check(f, maxWidth, maxHeight) != null) {
                drop(handle, mHandles.get(handle));
                Frames bad = new Frames();
                bad.status = IDecodeService.STATUS_INVALID;
                return bad;
            }
        }
        return f;
    }

    // With mHandles held.
    private void drop(long handle, Held h) {
        mHandles.remove(handle);
        mDecoder.release("uid:" + h.uid, h.bytes());
    }

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
        DecodeChecks.dropFutureDate(m, System.currentTimeMillis());
        if (DecodeChecks.check(m, System.currentTimeMillis()) != null) {
            Decoder.Request bad = new Decoder.Request(GuestLink.OP_METADATA, 0, 0, null, 0, 0, "", false, 0);
            bad.status = GuestLink.INVALID;
            return metadata(bad);
        }
        return m;
    }

    // With mHandles held.
    private void expire() {
        long now = SystemClock.uptimeMillis();
        Iterator<Map.Entry<Long, Held>> it = mHandles.entrySet().iterator();
        while (it.hasNext()) {
            Held h = it.next().getValue();
            if (h.expires <= now) {
                it.remove();
                mDecoder.release("uid:" + h.uid, h.bytes());
            }
        }
    }

    @Override
    public void onTrimMemory(int level) {
        if (level >= TRIM_MEMORY_RUNNING_LOW) mDecoder.clearCache();
    }
}
