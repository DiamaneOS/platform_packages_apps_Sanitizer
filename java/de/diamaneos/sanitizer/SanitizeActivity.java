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
import android.content.ContentResolver;
import android.content.ContentValues;
import android.content.Intent;
import android.graphics.Bitmap;
import android.net.Uri;
import android.os.Bundle;
import android.os.IBinder;
import android.provider.MediaStore;
import android.system.virtualmachine.VirtualMachine;
import android.system.virtualmachine.VirtualMachineCallback;
import android.system.virtualmachine.VirtualMachineConfig;
import android.system.virtualmachine.VirtualMachineManager;
import android.util.Log;
import android.view.Gravity;
import android.widget.TextView;
import android.widget.Toast;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * Share target "Sanitize": the shared image is decoded inside a protected VM. Android gets back plain pixels only,
 * writes them as a new PNG to Pictures/Sanitized and offers to share that copy.
 */
public class SanitizeActivity extends Activity {
    private static final String TAG = "DiamaneOSSanitizer";
    private static final String VM_NAME = "sanitizer";
    // The FP6 hypervisor refuses a VM whose memory comes in more than about 20000 physically separate pieces. 320 MiB
    // comes in few enough even when free memory is scattered.
    private static final long VM_MEMORY = 320L << 20;
    private static final int HEADER = 12;

    // The work waits for the VM, so the VM callbacks need a thread of their own. Neither is shut down with the
    // activity: a running request finishes and saves its copy.
    private static final ExecutorService WORK = Executors.newSingleThreadExecutor();
    private static final ExecutorService CALLBACKS = Executors.newSingleThreadExecutor();
    private TextView mStatus;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        mStatus = new TextView(this);
        mStatus.setGravity(Gravity.CENTER);
        mStatus.setPadding(48, 48, 48, 48);
        mStatus.setText(R.string.working);
        setContentView(mStatus);
        Uri source = getIntent().getParcelableExtra(Intent.EXTRA_STREAM, Uri.class);
        if (source == null) {
            done(getString(R.string.no_file), null);
            return;
        }
        WORK.execute(() -> {
            try {
                Uri copy = sanitize(source);
                runOnUiThread(() -> done(getString(R.string.saved), copy));
            } catch (Exception e) {
                Log.w(TAG, "sanitize failed", e);
                runOnUiThread(() -> done(getString(R.string.failed), null));
            }
        });
    }

    private Uri sanitize(Uri source) throws Exception {
        long t0 = System.nanoTime();
        byte[] file = read(source, ISanitizer.MAX_INPUT_BYTES);
        byte[] raster;
        try {
            raster = decodeInVm(file);
        } catch (IllegalStateException e) {
            // A start the hypervisor refused (scattered memory) can succeed a moment later.
            Log.w(TAG, "VM start failed, trying once more: " + e.getMessage());
            Thread.sleep(2000);
            raster = decodeInVm(file);
        }
        long t1 = System.nanoTime();
        Bitmap bitmap = toBitmap(raster);
        Uri copy = save(bitmap);
        Log.i(TAG, "sanitized " + file.length + " bytes to " + bitmap.getWidth() + "x" + bitmap.getHeight()
                + " in " + (t1 - t0) / 1000000 + " ms (VM), " + (System.nanoTime() - t1) / 1000000 + " ms (PNG)");
        return copy;
    }

    private byte[] read(Uri source, int limit) throws Exception {
        ContentResolver resolver = getContentResolver();
        try (InputStream in = resolver.openInputStream(source)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[65536];
            int n;
            while ((n = in.read(buffer)) > 0) {
                if (out.size() + n > limit) throw new IllegalArgumentException("file too large");
                out.write(buffer, 0, n);
            }
            return out.toByteArray();
        }
    }

    private byte[] decodeInVm(byte[] file) throws Exception {
        VirtualMachineConfig config = new VirtualMachineConfig.Builder(this)
                .setPayloadBinaryName("libdiamaneos_sanitizer_payload.so")
                .setProtectedVm(true)
                .setDebugLevel(VirtualMachineConfig.DEBUG_LEVEL_NONE)
                .setMemoryBytes(VM_MEMORY)
                .setShouldUseHugepages(true)
                .build();
        VirtualMachineManager vmm = getSystemService(VirtualMachineManager.class);
        VirtualMachine vm = vmm.get(VM_NAME);
        if (vm != null && !vm.getConfig().isCompatibleWith(config)) {
            vm.close();
            vmm.delete(VM_NAME);
            vm = null;
        }
        if (vm == null) vm = vmm.create(VM_NAME, config);
        CountDownLatch ready = new CountDownLatch(1);
        String[] problem = new String[1];
        vm.setCallback(CALLBACKS, new VirtualMachineCallback() {
            @Override public void onPayloadStarted(VirtualMachine v) {}
            @Override public void onPayloadReady(VirtualMachine v) { ready.countDown(); }
            @Override public void onPayloadFinished(VirtualMachine v, int exitCode) {
                problem[0] = "payload ended with " + exitCode;
                ready.countDown();
            }
            @Override public void onError(VirtualMachine v, int errorCode, String message) {
                problem[0] = "error " + errorCode + ": " + message;
                ready.countDown();
            }
            @Override public void onStopped(VirtualMachine v, int reason) {
                if (problem[0] == null) problem[0] = "stopped, reason " + reason;
                ready.countDown();
            }
        });
        try {
            vm.run();
            if (!ready.await(60, TimeUnit.SECONDS) || problem[0] != null) {
                throw new IllegalStateException("VM did not start: " + problem[0]);
            }
            IBinder binder = vm.connectToVsockServer(ISanitizer.PORT);
            ISanitizer sanitizer = ISanitizer.Stub.asInterface(binder);
            for (int at = 0; at < file.length; at += ISanitizer.CHUNK) {
                sanitizer.addInput(Arrays.copyOfRange(file, at, Math.min(file.length, at + ISanitizer.CHUNK)));
            }
            long length = sanitizer.decode();
            if (length < HEADER || length > HEADER + 4L * ISanitizer.MAX_PIXELS) {
                throw new IllegalArgumentException("bad result length " + length);
            }
            byte[] raster = new byte[(int) length];
            for (int at = 0; at < raster.length; ) {
                byte[] piece = sanitizer.readResult(at);
                if (piece.length == 0 || piece.length > raster.length - at) throw new IllegalArgumentException("bad piece");
                System.arraycopy(piece, 0, raster, at, piece.length);
                at += piece.length;
            }
            return raster;
        } finally {
            try {
                vm.stop();
            } catch (Exception e) {
                Log.w(TAG, "stop", e);
            }
            vm.close();
        }
    }

    // The only parsing on Android: a fixed header and a pixel count that must match exactly.
    private static Bitmap toBitmap(byte[] raster) {
        if (raster == null || raster.length < HEADER || raster[0] != 'D' || raster[1] != 'S'
                || raster[2] != 'R' || raster[3] != '1') {
            throw new IllegalArgumentException("bad result");
        }
        long width = le32(raster, 4);
        long height = le32(raster, 8);
        if (width <= 0 || height <= 0 || width * height > ISanitizer.MAX_PIXELS
                || raster.length != HEADER + width * height * 4) {
            throw new IllegalArgumentException("bad size");
        }
        Bitmap bitmap = Bitmap.createBitmap((int) width, (int) height, Bitmap.Config.ARGB_8888);
        bitmap.copyPixelsFromBuffer(ByteBuffer.wrap(raster, HEADER, raster.length - HEADER));
        return bitmap;
    }

    private static long le32(byte[] b, int at) {
        return (b[at] & 0xffL) | (b[at + 1] & 0xffL) << 8 | (b[at + 2] & 0xffL) << 16 | (b[at + 3] & 0xffL) << 24;
    }

    private Uri save(Bitmap bitmap) throws Exception {
        ContentValues values = new ContentValues();
        values.put(MediaStore.Images.Media.DISPLAY_NAME, "sanitized-" + System.currentTimeMillis() + ".png");
        values.put(MediaStore.Images.Media.MIME_TYPE, "image/png");
        values.put(MediaStore.Images.Media.RELATIVE_PATH, "Pictures/Sanitized");
        values.put(MediaStore.Images.Media.IS_PENDING, 1);
        ContentResolver resolver = getContentResolver();
        Uri uri = resolver.insert(MediaStore.Images.Media.getContentUri(MediaStore.VOLUME_EXTERNAL_PRIMARY), values);
        try (OutputStream out = resolver.openOutputStream(uri)) {
            if (!bitmap.compress(Bitmap.CompressFormat.PNG, 100, out)) throw new IllegalStateException("png");
        }
        values.clear();
        values.put(MediaStore.Images.Media.IS_PENDING, 0);
        resolver.update(uri, values, null, null);
        return uri;
    }

    private void done(String message, Uri copy) {
        Toast.makeText(this, message, Toast.LENGTH_LONG).show();
        if (copy != null) {
            Intent share = new Intent(Intent.ACTION_SEND).setType("image/png")
                    .putExtra(Intent.EXTRA_STREAM, copy).addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            startActivity(Intent.createChooser(share, getString(R.string.share_copy)));
        }
        finish();
    }

}
