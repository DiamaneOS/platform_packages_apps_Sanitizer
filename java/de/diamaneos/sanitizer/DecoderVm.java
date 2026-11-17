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

import android.content.Context;
import android.os.IBinder;
import android.os.ServiceSpecificException;
import android.os.SystemClock;
import android.system.virtualmachine.VirtualMachine;
import android.system.virtualmachine.VirtualMachineCallback;
import android.system.virtualmachine.VirtualMachineConfig;
import android.system.virtualmachine.VirtualMachineException;
import android.system.virtualmachine.VirtualMachineManager;
import android.util.Log;

import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/**
 * One protected VM, started on first use and kept running, with the sanitizer's broker inside. Requests run one at a
 * time. Every request has a deadline: a VM that misses it, crashes or breaks the protocol is stopped and replaced on
 * a later request, with a growing pause between starts while it keeps failing. There is no fallback and no switch
 * that turns the VM off: when the VM cannot decode, the request fails, so breaking or jamming the VM can never push a
 * file to Android's own decoders.
 */
final class DecoderVm {
    static final String TAG = "DiamaneOSSanitizer";
    private static final String VM_NAME = "decoder";
    private static final String PAYLOAD = "libdiamaneos_sanitizer_payload.so";
    private static final int HEADER = 12;
    private static final long READY_MS = 60_000;
    private static final long FIRST_BACKOFF_MS = 5_000;
    private static final long MAX_BACKOFF_MS = 5 * 60_000;

    /** VM memory: Microdroid, the largest input file and one worker arena (64 MiB). */
    static final long DEFAULT_MEMORY = 256L << 20;

    private static final ScheduledExecutorService WATCHDOG = Executors.newSingleThreadScheduledExecutor();
    private static final ExecutorService CALLBACKS = Executors.newSingleThreadExecutor();
    private static DecoderVm sInstance;

    private final Context mContext;
    private int mFailures;
    private long mNotBefore;
    private long mMemory = DEFAULT_MEMORY;
    private VirtualMachine mVm;
    private ISanitizer mService;
    // Read by the watchdog without the lock: the VM to stop when a request misses its deadline.
    private volatile VirtualMachine mRunning;
    private volatile boolean mStopped;
    /** Time of the last VM start, from run() to the payload being ready, and how many tries it took. */
    long lastStartMs = -1;
    int lastStartTries;
    /** How many VMs this process started. */
    int starts;

    static synchronized DecoderVm get(Context context) {
        if (sInstance == null) sInstance = new DecoderVm(context.getApplicationContext());
        return sInstance;
    }

    private DecoderVm(Context context) {
        mContext = context;
    }

    /** A decoded image: premultiplied RGBA, every colour value at most its alpha. */
    static final class Image {
        final int width;
        final int height;
        final byte[] pixels;

        Image(int width, int height, byte[] pixels) {
            this.width = width;
            this.height = height;
            this.pixels = pixels;
        }
    }

    /** For tests: a different VM size takes effect with the next start. */
    synchronized void setMemory(long bytes) {
        if (bytes != mMemory) {
            mMemory = bytes;
            discard();
        }
    }

    /** Starts the VM now if it is not running. */
    synchronized void warmUp(long deadlineMs) throws Exception {
        ScheduledFuture<?> watchdog = WATCHDOG.schedule(this::kill, deadlineMs, TimeUnit.MILLISECONDS);
        try {
            service();
        } catch (Exception e) {
            failed();
            throw e;
        } finally {
            watchdog.cancel(false);
        }
    }

    /**
     * Decodes a PNG or JPEG file in the VM. maxSide 0 asks for the full size (scaled down to MAX_PIXELS at most),
     * otherwise neither side is longer than maxSide. Throws when the VM cannot do it, in time or at all.
     */
    synchronized Image decode(byte[] file, int maxSide, long deadlineMs) throws Exception {
        if (file.length == 0 || file.length > ISanitizer.MAX_INPUT_BYTES) {
            throw new IllegalArgumentException("file size " + file.length);
        }
        ScheduledFuture<?> watchdog = WATCHDOG.schedule(this::kill, deadlineMs, TimeUnit.MILLISECONDS);
        try {
            ISanitizer s = service();
            s.begin(file.length);
            for (int at = 0; at < file.length; at += ISanitizer.CHUNK) {
                s.addInput(Arrays.copyOfRange(file, at, Math.min(file.length, at + ISanitizer.CHUNK)));
            }
            byte[] header = s.decode(maxSide);
            if (header == null || header.length != HEADER || header[0] != 'D' || header[1] != 'S'
                    || header[2] != 'R' || header[3] != '1') {
                throw new IllegalStateException("bad header");
            }
            // Each side is checked before the product, so it cannot wrap.
            long width = le32(header, 4);
            long height = le32(header, 8);
            if (width < 1 || height < 1 || width > ISanitizer.MAX_SIDE || height > ISanitizer.MAX_SIDE
                    || width * height > ISanitizer.MAX_PIXELS
                    || (maxSide > 0 && (width > maxSide || height > maxSide))) {
                throw new IllegalStateException("bad size " + width + "x" + height);
            }
            byte[] pixels = new byte[(int) (width * height * 4)];
            for (int at = 0; at < pixels.length; ) {
                byte[] piece = s.readPixels();
                if (piece == null || piece.length == 0 || piece.length > pixels.length - at) {
                    throw new IllegalStateException("bad piece at " + at);
                }
                System.arraycopy(piece, 0, pixels, at, piece.length);
                at += piece.length;
            }
            // The empty answer confirms that the worker ended cleanly after exactly these pixels.
            byte[] end = s.readPixels();
            if (end == null || end.length != 0) throw new IllegalStateException("worker sent too much");
            clampToAlpha(pixels);
            mFailures = 0;
            return new Image((int) width, (int) height, pixels);
        } catch (IllegalArgumentException | ServiceSpecificException e) {
            // Refused before the VM was used, or by the broker, which has already ended its worker: the VM is fine.
            throw e;
        } catch (Exception e) {
            // The VM missed its deadline, broke the protocol or went away: it is never reused.
            failed();
            throw e;
        } finally {
            watchdog.cancel(false);
        }
    }

    /** Stops and deletes the VM. The next request starts a new one. */
    synchronized void discard() {
        VirtualMachine vm = mVm;
        mVm = null;
        mRunning = null;
        mService = null;
        if (vm != null) {
            try {
                vm.stop();
            } catch (Exception e) {
                // Already stopped.
            }
            try {
                vm.close();
            } catch (Exception e) {
                Log.w(TAG, "close", e);
            }
        }
        try {
            mContext.getSystemService(VirtualMachineManager.class).delete(VM_NAME);
        } catch (Exception e) {
            // No instance.
        }
    }

    /** For tests: forget earlier failures, so the next request may start a VM at once. */
    synchronized void resetBackoff() {
        mFailures = 0;
        mNotBefore = 0;
    }

    // A failed VM is dropped and the next start waits 5 s, then twice as long after each further failure in a row, up
    // to 5 minutes. Requests meanwhile fail.
    private void failed() {
        discard();
        mFailures++;
        long backoff = Math.min(MAX_BACKOFF_MS, FIRST_BACKOFF_MS << Math.min(mFailures - 1, 6));
        mNotBefore = SystemClock.elapsedRealtime() + backoff;
        Log.w(TAG, "VM failed " + mFailures + " times in a row, next start in " + backoff / 1000 + " s at the earliest");
    }

    // The watchdog: stopping the VM ends any binder call waiting on it, and the request fails.
    private void kill() {
        VirtualMachine vm = mRunning;
        if (vm == null) return;
        Log.w(TAG, "deadline passed, stopping the VM");
        try {
            vm.stop();
        } catch (Exception e) {
            Log.w(TAG, "stop", e);
        }
    }

    private ISanitizer service() throws Exception {
        if (mService != null && !mStopped) return mService;
        if (mService != null) {
            failed();  // it stopped on its own since the last request
        } else {
            discard();
        }
        long wait = mNotBefore - SystemClock.elapsedRealtime();
        if (wait > 0) throw new IllegalStateException("VM failed, next start in " + (wait + 999) / 1000 + " s");
        try {
            lastStartTries = 1;
            return start();
        } catch (VirtualMachineException | IllegalStateException e) {
            // A start the hypervisor refused (scattered memory) can succeed a moment later.
            Log.w(TAG, "VM start failed, trying once more: " + e.getMessage());
            discard();
            Thread.sleep(2000);
            lastStartTries = 2;
            return start();
        }
    }

    private ISanitizer start() throws Exception {
        VirtualMachineConfig config = new VirtualMachineConfig.Builder(mContext)
                .setPayloadBinaryName(PAYLOAD)
                .setProtectedVm(true)
                .setDebugLevel(VirtualMachineConfig.DEBUG_LEVEL_NONE)
                .setMemoryBytes(mMemory)
                .setShouldUseHugepages(true)
                .build();
        VirtualMachineManager vmm = mContext.getSystemService(VirtualMachineManager.class);
        VirtualMachine vm = vmm.get(VM_NAME);
        if (vm != null && !vm.getConfig().isCompatibleWith(config)) {
            vm.close();
            vmm.delete(VM_NAME);
            vm = null;
        }
        if (vm == null) vm = vmm.create(VM_NAME, config);
        CountDownLatch ready = new CountDownLatch(1);
        String[] problem = new String[1];
        mStopped = false;
        mVm = vm;
        mRunning = vm;
        vm.setCallback(CALLBACKS, new VirtualMachineCallback() {
            @Override public void onPayloadStarted(VirtualMachine v) {}
            @Override public void onPayloadReady(VirtualMachine v) { ready.countDown(); }
            @Override public void onPayloadFinished(VirtualMachine v, int exitCode) {
                problem[0] = "payload ended with " + exitCode;
                if (v == mRunning) mStopped = true;
                ready.countDown();
            }
            @Override public void onError(VirtualMachine v, int errorCode, String message) {
                problem[0] = "error " + errorCode + ": " + message;
                if (v == mRunning) mStopped = true;
                ready.countDown();
            }
            @Override public void onStopped(VirtualMachine v, int reason) {
                if (problem[0] == null) problem[0] = "stopped, reason " + reason;
                if (v == mRunning) mStopped = true;
                ready.countDown();
            }
        });
        long t0 = SystemClock.elapsedRealtime();
        starts++;
        vm.run();
        if (!ready.await(READY_MS, TimeUnit.MILLISECONDS) || problem[0] != null) {
            throw new IllegalStateException("VM did not start: " + problem[0]);
        }
        IBinder binder = vm.connectToVsockServer(ISanitizer.PORT);
        mService = ISanitizer.Stub.asInterface(binder);
        lastStartMs = SystemClock.elapsedRealtime() - t0;
        Log.i(TAG, "VM ready in " + lastStartMs + " ms, " + (mMemory >> 20) + " MiB, try " + lastStartTries);
        return mService;
    }

    // Premultiplied pixels with a colour above its alpha are invalid for Skia. The VM must not be able to hand
    // them over.
    private static void clampToAlpha(byte[] p) {
        for (int i = 0; i < p.length; i += 4) {
            int a = p[i + 3] & 0xff;
            if (a == 255) continue;
            for (int c = 0; c < 3; c++) {
                if ((p[i + c] & 0xff) > a) p[i + c] = (byte) a;
            }
        }
    }

    private static long le32(byte[] b, int at) {
        return (b[at] & 0xffL) | (b[at + 1] & 0xffL) << 8 | (b[at + 2] & 0xffL) << 16 | (b[at + 3] & 0xffL) << 24;
    }
}
