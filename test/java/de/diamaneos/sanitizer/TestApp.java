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

import android.app.Application;

import java.io.File;

/**
 * Test builds only: the self-test app's application. Its decode service runs the test VM image adb pushed to
 * /data/local/tmp/decoder-vm/ (shell_data_file, a label the VM manager accepts for a protected VM's kernel, unlike
 * this app's own files), under a test permission, and only the app itself may call it. Debuggable builds only.
 */
public final class TestApp extends Application implements DecoderProvider {
    static final String PERMISSION = "de.diamaneos.sanitizer.test.permission.DECODE";
    static final File TEST_IMAGES = new File("/data/local/tmp/decoder-vm");

    /** The test VM images, only where adb could have put them: a debuggable build. */
    static File testImages() {
        // Not ro.debuggable itself: an ordinary app may not read it, and the read answered false on userdebug.
        if (!DebugBuild.debuggable()) {
            throw new IllegalStateException("the self-test runs on debuggable builds only");
        }
        return TEST_IMAGES;
    }
    private Decoder mDecoder;

    @Override
    public synchronized Decoder decoder() {
        if (mDecoder == null) {
            File dir = testImages();
            mDecoder = new Decoder(new GuestVm(this, new File(dir, "kernel"), new File(dir, "initrd.img"),
                    DecoderApp.VM_MEMORY_BYTES, true));
        }
        return mDecoder;
    }

    @Override
    public String callerPermission() {
        return PERMISSION;
    }

    @Override
    public String[] allowedCallers() {
        return new String[] {getPackageName()};
    }
}
