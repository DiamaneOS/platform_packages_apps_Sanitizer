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
import android.content.Context;

import java.io.File;

/**
 * The decode service's process. It is persistent and direct boot aware, so it starts early in boot, before the first
 * unlock, and starts the VM right away: early in uptime the VM's memory is least scattered, and the first request
 * does not wait for a VM start.
 */
public final class DecoderApp extends Application {
    /** The decoder VM's kernel and initramfs, in the virtualization APEX, signed by sign_virt_apex. */
    static final File VM_KERNEL = new File("/apex/com.android.virt/etc/fs/decoder_vm_kernel");
    static final File VM_INITRD = new File("/apex/com.android.virt/etc/decoder_vm_initrd.img");

    /** The VM's memory. Measured on the FP6: see the decode service notes. */
    static final long VM_MEMORY_BYTES = 128L << 20;

    private static Decoder sDecoder;

    @Override
    public void onCreate() {
        super.onCreate();
        decoder(this).warmUp();
    }

    static synchronized Decoder decoder(Context context) {
        if (sDecoder == null) {
            sDecoder = new Decoder(
                    new GuestVm(context.getApplicationContext(), VM_KERNEL, VM_INITRD, VM_MEMORY_BYTES));
        }
        return sDecoder;
    }
}
