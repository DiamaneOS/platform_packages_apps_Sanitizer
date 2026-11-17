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
import android.os.ParcelFileDescriptor;
import android.os.SystemClock;
import android.system.virtualmachine.VirtualMachine;
import android.system.virtualmachine.VirtualMachineCallback;
import android.system.virtualmachine.VirtualMachineConfig;
import android.system.virtualmachine.VirtualMachineManager;
import android.util.Log;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

/**
 * The decoder VM: a raw protected VM with our own kernel and a one-program initramfs (vm/decoder_vm.cpp), no
 * Microdroid. It is started early, kept running, and started again with backoff when it stops or stops answering.
 *
 * <p>The kernel and initramfs ship in the virtualization APEX, where release signing signs them again with the key
 * pvmfw trusts (sign_virt_apex). The VM manager may only read app data files, not system files, so they are copied
 * into this app's device-protected storage first. That copy needs no trust: pvmfw refuses a kernel that is not signed
 * with the build's key, and the kernel's signature covers the initramfs.
 *
 * <p>Raw VMs are configured through the VM framework's hidden custom image API, reached by reflection: this app is
 * platform-signed and holds USE_CUSTOM_VIRTUAL_MACHINE.
 */
final class GuestVm {
    private static final String TAG = "DecoderVm";
    static final String NAME = "decoder";
    private static final String KERNEL = "kernel";
    private static final String INITRD = "initrd.img";

    private final Context mContext; // device-protected storage, so the VM runs before the first unlock
    private final File mKernelSource;
    private final File mInitrdSource;
    private final long mMemoryBytes;
    private final Executor mCallbacks = Executors.newSingleThreadExecutor();

    private VirtualMachine mVm;
    private GuestLink mLink;
    private volatile boolean mStopped = true;
    private long mStartedAt;
    private long mReadyAt;

    GuestVm(Context context, File kernel, File initrd, long memoryBytes) {
        mContext = context.createDeviceProtectedStorageContext();
        mKernelSource = kernel;
        mInitrdSource = initrd;
        mMemoryBytes = memoryBytes;
    }

    /** Milliseconds from run() to the first answer of the last start, -1 before. */
    synchronized long lastStartMillis() {
        return mReadyAt > 0 ? mReadyAt - mStartedAt : -1;
    }

    synchronized boolean isRunning() {
        return mVm != null && !mStopped;
    }

    /**
     * Starts the VM unless it runs, and returns a working link, pinged within the deadline. Throws when the VM does
     * not come up in time: the caller fails closed and the scheduler starts again with backoff.
     */
    synchronized GuestLink link(long deadline) throws IOException {
        if (mLink != null && !mLink.isBroken() && !mStopped) return mLink;
        if (mLink != null) mLink.close();
        mLink = null;
        if (mVm == null || mStopped) start();
        IOException last = null;
        while (SystemClock.uptimeMillis() < deadline) {
            try {
                ParcelFileDescriptor pfd = mVm.connectVsock(GuestLink.PORT);
                GuestLink link = new GuestLink(new FdChannel(pfd));
                link.ping(Math.min(deadline, SystemClock.uptimeMillis() + 2000));
                if (mReadyAt == 0) mReadyAt = SystemClock.uptimeMillis();
                mLink = link;
                return link;
            } catch (Exception e) {
                last = e instanceof IOException ? (IOException) e : new IOException(e);
                if (mStopped) break;
                SystemClock.sleep(100);
            }
        }
        throw last != null ? last : new IOException("VM not ready");
    }

    /** Stops the VM. The next link() starts it again. */
    synchronized void stop() {
        if (mLink != null) mLink.close();
        mLink = null;
        if (mVm != null) {
            try {
                mVm.stop();
            } catch (Exception e) {
                Log.w(TAG, "stop", e);
            }
            try {
                mVm.close();
            } catch (Exception e) {
                Log.w(TAG, "close", e);
            }
        }
        mVm = null;
        mStopped = true;
    }

    private void start() throws IOException {
        stop();
        File dir = new File(mContext.getFilesDir(), "decoder-vm");
        if (!dir.isDirectory() && !dir.mkdirs()) throw new IOException("no directory");
        File kernel = new File(dir, KERNEL);
        File initrd = new File(dir, INITRD);
        copy(mKernelSource, kernel);
        copy(mInitrdSource, initrd);
        try {
            VirtualMachineConfig config = rawConfig(kernel, initrd);
            VirtualMachineManager vmm = mContext.getSystemService(VirtualMachineManager.class);
            VirtualMachine vm = vmm.get(NAME);
            if (vm != null) {
                vm.close();
                vmm.delete(NAME);
            }
            // A fresh instance each start: the VM keeps no state, so it never needs its old instance data.
            vm = vmm.create(NAME, config);
            vm.setCallback(mCallbacks, new VirtualMachineCallback() {
                @Override public void onPayloadStarted(VirtualMachine v) {}
                @Override public void onPayloadReady(VirtualMachine v) {}
                @Override public void onPayloadFinished(VirtualMachine v, int exitCode) {}
                @Override public void onError(VirtualMachine v, int errorCode, String message) {
                    Log.w(TAG, "VM error " + errorCode + ": " + message);
                    mStopped = true;
                }
                @Override public void onStopped(VirtualMachine v, int reason) {
                    Log.w(TAG, "VM stopped, reason " + reason);
                    mStopped = true;
                }
            });
            mStartedAt = SystemClock.uptimeMillis();
            mReadyAt = 0;
            mStopped = false;
            vm.run();
            mVm = vm;
            Log.i(TAG, "VM started, " + (mMemoryBytes >> 20) + " MiB");
        } catch (ReflectiveOperationException e) {
            mStopped = true;
            throw new IOException("custom VM API", e);
        } catch (Exception e) {
            mStopped = true;
            throw new IOException("VM start: " + e.getMessage(), e);
        }
    }

    private VirtualMachineConfig rawConfig(File kernel, File initrd) throws ReflectiveOperationException {
        String p = "android.system.virtualmachine.VirtualMachineCustomImageConfig";
        Class<?> imageConfig = Class.forName(p);
        Class<?> builderClass = Class.forName(p + "$Builder");
        Class<?> diskClass = Class.forName(p + "$Disk");
        Class<?> partitionClass = Class.forName(p + "$Partition");
        Object b = builderClass.getConstructor().newInstance();
        builderClass.getMethod("setName", String.class).invoke(b, NAME);
        builderClass.getMethod("setKernelPath", String.class).invoke(b, kernel.getPath());
        builderClass.getMethod("setInitrdPath", String.class).invoke(b, initrd.getPath());
        // A protected raw VM needs an instance partition. The framework creates and initialises instance.img in the
        // VM's directory when the VM is created, before run() opens this path.
        File instance = new File(new File(new File(mContext.getDataDir(), "vm"), NAME), "instance.img");
        Object disk = diskClass.getMethod("RWDisk", String.class).invoke(null, (Object) null);
        Object partition = partitionClass.getConstructor(String.class, String.class, boolean.class, String.class)
                .newInstance("vm-instance", instance.getPath(), true, null);
        diskClass.getMethod("addPartition", partitionClass).invoke(disk, partition);
        builderClass.getMethod("addDisk", diskClass).invoke(b, disk);
        Object image = builderClass.getMethod("build").invoke(b);

        VirtualMachineConfig.Builder vb = new VirtualMachineConfig.Builder(mContext);
        Method set = VirtualMachineConfig.Builder.class.getMethod("setCustomImageConfig", imageConfig);
        set.invoke(vb, image);
        return vb.setProtectedVm(true)
                .setDebugLevel(VirtualMachineConfig.DEBUG_LEVEL_NONE)
                .setMemoryBytes(mMemoryBytes)
                .build();
    }

    // Copies when the size or the time differs. pvmfw checks the kernel's signature at every start either way.
    private static void copy(File from, File to) throws IOException {
        if (to.length() == from.length() && to.lastModified() == from.lastModified() && to.length() > 0) return;
        File tmp = new File(to.getPath() + ".tmp");
        try (InputStream in = new FileInputStream(from); OutputStream out = new FileOutputStream(tmp)) {
            byte[] buf = new byte[1 << 16];
            int n;
            while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
        }
        tmp.setLastModified(from.lastModified());
        if (!tmp.renameTo(to)) throw new IOException("copy " + to);
    }
}
