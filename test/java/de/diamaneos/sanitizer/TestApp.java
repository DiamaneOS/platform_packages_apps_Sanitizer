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
 * Test builds only: the self-test app's application. Its decode service runs the test VM image pushed into the app's
 * external files (decoder-vm/), under a test permission, and only the app itself may call it.
 */
public final class TestApp extends Application implements DecoderProvider {
    static final String PERMISSION = "de.diamaneos.sanitizer.test.permission.DECODE";
    private Decoder mDecoder;

    @Override
    public synchronized Decoder decoder() {
        if (mDecoder == null) {
            File dir = new File(getExternalFilesDir(null), "decoder-vm");
            mDecoder = new Decoder(new GuestVm(this, new File(dir, "kernel"), new File(dir, "initrd.img"),
                    DecoderApp.VM_MEMORY_BYTES));
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
