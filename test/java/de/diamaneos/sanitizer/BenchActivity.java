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
import android.content.Intent;
import android.graphics.Bitmap;
import android.os.Bundle;
import android.os.SystemClock;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.util.zip.CRC32;

/**
 * Test builds only: measures the warm VM. Started by a test script with extras: mem (MiB), files (names in the app's
 * external files directory, comma separated), sides (maxSide values, comma separated, 0 = full size), repeat, fresh
 * (stop the VM first, to time a start), save (write each first result as PNG to out/), hooks (run the lockdown
 * checks). Every result is one log line under the tag SanitizerBench, the last one is "BENCH done".
 */
public class BenchActivity extends Activity {
    private static final String TAG = "SanitizerBench";

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        if (state != null) return;
        Intent intent = getIntent();
        new Thread(() -> {
            try {
                run(intent);
            } catch (Throwable t) {
                Log.i(TAG, "BENCH error " + t);
            }
            Log.i(TAG, "BENCH done");
            runOnUiThread(this::finish);
        }).start();
    }

    private void run(Intent intent) throws Exception {
        File dir = getExternalFilesDir(null);  // created here, so a script can push files into it
        int mem = intent.getIntExtra("mem", (int) (DecoderVm.DEFAULT_MEMORY >> 20));
        String[] files = intent.getStringExtra("files") == null ? new String[0]
                : intent.getStringExtra("files").split(",");
        String[] sides = (intent.getStringExtra("sides") == null ? "512,0" : intent.getStringExtra("sides")).split(",");
        int repeat = intent.getIntExtra("repeat", 3);
        DecoderVm vm = DecoderVm.get(this);
        vm.setMemory((long) mem << 20);
        if (intent.getBooleanExtra("fresh", true)) {
            vm.discard();
            vm.resetBackoff();
        }
        long t0 = SystemClock.elapsedRealtime();
        try {
            vm.warmUp(120_000);
            Log.i(TAG, "BENCH start mem=" + mem + " ms=" + vm.lastStartMs + " tries=" + vm.lastStartTries
                    + " total=" + (SystemClock.elapsedRealtime() - t0));
        } catch (Exception e) {
            Log.i(TAG, "BENCH start mem=" + mem + " FAIL " + e);
            return;
        }
        for (String name : files) {
            byte[] data = Files.readAllBytes(new File(dir, name).toPath());
            for (String side : sides) {
                int maxSide = Integer.parseInt(side.trim());
                for (int r = 0; r < repeat; r++) {
                    long t = SystemClock.elapsedRealtime();
                    try {
                        DecoderVm.Image image = vm.decode(data, maxSide, 60_000);
                        long ms = SystemClock.elapsedRealtime() - t;
                        CRC32 crc = new CRC32();
                        crc.update(image.pixels);
                        Log.i(TAG, String.format("BENCH file=%s bytes=%d side=%d run=%d w=%d h=%d ms=%d crc=%08x",
                                name, data.length, maxSide, r, image.width, image.height, ms, crc.getValue()));
                        if (r == 0 && intent.getBooleanExtra("save", false)) save(image, name + "-" + maxSide);
                    } catch (Exception e) {
                        Log.i(TAG, String.format("BENCH file=%s bytes=%d side=%d run=%d FAIL ms=%d %s", name,
                                data.length, maxSide, r, SystemClock.elapsedRealtime() - t, e));
                    }
                }
            }
        }
        if (intent.getBooleanExtra("hooks", false)) hooks(files.length > 0 ? new File(dir, files[0]) : null);
    }

    // Each hook makes the worker try something its lockdown forbids, after the lockdown. Killed (signal 9) means
    // seccomp stopped it. A 1x1 result means the worker survived and reports: blocked (1 or 0), errno. Hook -4
    // reports the lockdown itself: seccomp on (1 or 0), its errno, rlimits on. The VM must go on serving.
    private void hooks(File sample) throws Exception {
        DecoderVm vm = DecoderVm.get(this);
        byte[] data = Files.readAllBytes(sample.toPath());
        int startsBefore = vm.starts;
        String[] names = {"open a file", "map 64 MiB", "spin past the deadline", "report the lockdown", "fork"};
        for (int hook = -1; hook >= -5; hook--) {
            long t = SystemClock.elapsedRealtime();
            String what = "BENCH hook=" + hook + " (" + names[-hook - 1] + ")";
            try {
                DecoderVm.Image image = vm.decode(data, hook, 90_000);
                byte[] p = image.pixels;
                Log.i(TAG, what + " survived " + image.width + "x" + image.height + " values " + (p[0] & 0xff) + ","
                        + (p[1] & 0xff) + "," + (p[2] & 0xff) + " ms=" + (SystemClock.elapsedRealtime() - t));
            } catch (Exception e) {
                Log.i(TAG, what + " ended ms=" + (SystemClock.elapsedRealtime() - t) + " " + e.getMessage());
            }
        }
        long t = SystemClock.elapsedRealtime();
        try {
            DecoderVm.Image image = vm.decode(data, 512, 60_000);
            Log.i(TAG, "BENCH after-hooks ok " + image.width + "x" + image.height + " ms="
                    + (SystemClock.elapsedRealtime() - t) + " VM starts before " + startsBefore + " after "
                    + vm.starts);
        } catch (Exception e) {
            Log.i(TAG, "BENCH after-hooks FAIL " + e);
        }
    }

    private void save(DecoderVm.Image image, String name) throws Exception {
        Bitmap bitmap = Bitmap.createBitmap(image.width, image.height, Bitmap.Config.ARGB_8888);
        bitmap.copyPixelsFromBuffer(ByteBuffer.wrap(image.pixels));
        File out = new File(getExternalFilesDir("out"), name + ".png");
        try (FileOutputStream stream = new FileOutputStream(out)) {
            bitmap.compress(Bitmap.CompressFormat.PNG, 100, stream);
        }
    }
}
