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
import android.os.ParcelFileDescriptor;
import android.provider.MediaStore;
import android.util.Log;
import android.view.Gravity;
import android.widget.TextView;
import android.widget.Toast;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Share target "Sanitize": the shared image is decoded inside a protected VM. Android gets back plain pixels only,
 * writes them as a new PNG to Pictures/Sanitized and offers to share that copy. Any app can send a file here, so
 * requests are queued and capped. When the VM cannot decode, the request fails: there is no fallback to Android's
 * own decoders.
 */
public class SanitizeActivity extends Activity {
    private static final String TAG = DecoderVm.TAG;
    private static final long READ_DEADLINE_MS = 30_000;
    private static final long DECODE_DEADLINE_MS = 60_000;
    private static final int MAX_QUEUED = 4;

    // The work waits for the VM and outlives the activity: a running request finishes and saves its copy.
    private static final ExecutorService WORK = Executors.newSingleThreadExecutor();
    // A sender's stream can stall forever. Its reader is left behind and the request fails.
    private static final ExecutorService READERS = Executors.newCachedThreadPool();
    private static final AtomicInteger sQueued = new AtomicInteger();
    private TextView mStatus;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        mStatus = new TextView(this);
        mStatus.setGravity(Gravity.CENTER);
        mStatus.setPadding(48, 48, 48, 48);
        mStatus.setText(R.string.working);
        setContentView(mStatus);
        if (state != null) return;  // recreated: the request from the first creation is still running
        Uri source = getIntent().getParcelableExtra(Intent.EXTRA_STREAM, Uri.class);
        if (source == null) {
            done(getString(R.string.no_file), null);
            return;
        }
        if (sQueued.incrementAndGet() > MAX_QUEUED) {
            sQueued.decrementAndGet();
            done(getString(R.string.failed), null);
            return;
        }
        WORK.execute(() -> {
            try {
                Uri copy = sanitize(source);
                runOnUiThread(() -> done(getString(R.string.saved), copy));
            } catch (Exception e) {
                Log.w(TAG, "sanitize failed", e);
                runOnUiThread(() -> done(getString(R.string.failed), null));
            } finally {
                sQueued.decrementAndGet();
            }
        });
    }

    private Uri sanitize(Uri source) throws Exception {
        long t0 = System.nanoTime();
        byte[] file = read(source, ISanitizer.MAX_INPUT_BYTES);
        DecoderVm.Image image = DecoderVm.get(this).decode(file, 0, DECODE_DEADLINE_MS);
        long t1 = System.nanoTime();
        Bitmap bitmap = Bitmap.createBitmap(image.width, image.height, Bitmap.Config.ARGB_8888);
        bitmap.copyPixelsFromBuffer(ByteBuffer.wrap(image.pixels));
        Uri copy = save(bitmap);
        Log.i(TAG, "sanitized " + file.length + " bytes to " + image.width + "x" + image.height
                + " in " + (t1 - t0) / 1000000 + " ms (VM), " + (System.nanoTime() - t1) / 1000000 + " ms (PNG)");
        return copy;
    }

    private byte[] read(Uri source, int limit) throws Exception {
        ContentResolver resolver = getContentResolver();
        ParcelFileDescriptor pfd = resolver.openFileDescriptor(source, "r");
        if (pfd == null) throw new IOException("no file");
        Future<byte[]> reading = READERS.submit(() -> {
            try (InputStream in = new ParcelFileDescriptor.AutoCloseInputStream(pfd)) {
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                byte[] buffer = new byte[65536];
                int n;
                while ((n = in.read(buffer)) > 0) {
                    if (out.size() + n > limit) throw new IllegalArgumentException("file too large");
                    out.write(buffer, 0, n);
                }
                return out.toByteArray();
            }
        });
        try {
            return reading.get(READ_DEADLINE_MS, TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            reading.cancel(true);
            throw new IOException("reading the file took too long");
        } finally {
            try {
                pfd.close();
            } catch (IOException e) {
                // Closed by the reader.
            }
        }
    }

    private Uri save(Bitmap bitmap) throws Exception {
        ContentValues values = new ContentValues();
        values.put(MediaStore.Images.Media.DISPLAY_NAME, "sanitized-" + System.currentTimeMillis() + ".png");
        values.put(MediaStore.Images.Media.MIME_TYPE, "image/png");
        values.put(MediaStore.Images.Media.RELATIVE_PATH, "Pictures/Sanitized");
        values.put(MediaStore.Images.Media.IS_PENDING, 1);
        ContentResolver resolver = getContentResolver();
        Uri uri = resolver.insert(MediaStore.Images.Media.getContentUri(MediaStore.VOLUME_EXTERNAL_PRIMARY), values);
        if (uri == null) throw new IOException("no media store entry");
        try {
            try (OutputStream out = resolver.openOutputStream(uri)) {
                if (out == null || !bitmap.compress(Bitmap.CompressFormat.PNG, 100, out)) {
                    throw new IOException("png");
                }
            }
            values.clear();
            values.put(MediaStore.Images.Media.IS_PENDING, 0);
            resolver.update(uri, values, null, null);
            return uri;
        } catch (Exception e) {
            resolver.delete(uri, null, null);
            throw e;
        }
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
