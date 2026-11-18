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
 * The decode service's process. It is persistent and direct boot aware, so it starts early in boot, before the first
 * unlock, and starts the VM right away: early in uptime the VM's memory is least scattered, and the first request
 * does not wait for a VM start.
 */
public final class DecoderApp extends Application implements DecoderProvider {
    /** The decoder VM's kernel and initramfs, in the virtualization APEX, signed by sign_virt_apex. */
    static final File VM_KERNEL = new File("/apex/com.android.virt/etc/fs/decoder_vm_kernel");
    static final File VM_INITRD = new File("/apex/com.android.virt/etc/decoder_vm_initrd.img");

    /**
     * The VM's memory. A worker may use what the VM has free when it starts, less a margin (vm/decoder_vm.cpp,
     * worker_memory), so no size can make a worker run out: a file that needs more is refused. Measured in the arm64
     * test VM (qemu, the same kernel and program): at 160 MiB the kernel shows 141 MiB, 119 MiB free after the
     * broker's start, so a worker gets about 103 MiB, about 71 MiB beside a 32 MiB file. A 12 MP single-image HEIC
     * needs about 296 MiB. A protected VM keeps a little more for itself than qemu, so these are upper bounds until
     * a phone run measures them. 160 MiB until the VM memory plan decides.
     */
    static final long VM_MEMORY_BYTES = 160L << 20;

    private static final String PERMISSION = "de.diamaneos.sanitizer.permission.DECODE";
    private static final String[] CALLERS = {
        "com.android.providers.media.module",
        "com.google.android.providers.media.module",
        "com.android.systemui",
    };

    private Decoder mDecoder;

    @Override
    public void onCreate() {
        super.onCreate();
        decoder().warmUp();
    }

    @Override
    public synchronized Decoder decoder() {
        if (mDecoder == null) mDecoder = new Decoder(new GuestVm(this, VM_KERNEL, VM_INITRD, VM_MEMORY_BYTES));
        return mDecoder;
    }

    @Override
    public String callerPermission() {
        return PERMISSION;
    }

    @Override
    public String[] allowedCallers() {
        return CALLERS.clone();
    }
}
