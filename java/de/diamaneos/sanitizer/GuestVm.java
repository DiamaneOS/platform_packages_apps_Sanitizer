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
import android.system.ErrnoException;
import android.system.Os;
import android.system.virtualmachine.VirtualMachine;
import android.system.virtualmachine.VirtualMachineCallback;
import android.system.virtualmachine.VirtualMachineConfig;
import android.system.virtualmachine.VirtualMachineManager;
import android.util.Log;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

/**
 * The decoder VM: a raw protected VM with our own kernel and a one-program initramfs (vm/decoder_vm.cpp), no
 * Microdroid. It is started early, kept running, and started again with backoff when it stops or stops answering.
 *
 * <p>The kernel and initramfs ship in the virtualization APEX, where release signing signs them again with the key
 * pvmfw trusts (sign_virt_apex). They are passed to the VM manager where they are: for a protected VM it takes kernel
 * files only with a label from a trusted source (VmImages), and the APEX's files are system_file. A copy in app data
 * (app_data_file) is refused, which an earlier version did. The label is checked here before each start, so a wrong
 * path fails with its reason. pvmfw still refuses a kernel not signed with the build's key, and the kernel's
 * signature covers the initramfs.
 *
 * <p>Raw VMs are configured through the VM framework's hidden custom image API, reached by reflection: this app is
 * platform-signed and holds USE_CUSTOM_VIRTUAL_MACHINE.
 */
final class GuestVm {
    private static final String TAG = "DecoderVm";
    static final String NAME = "decoder";
    // Where an earlier version copied the images, in device-protected storage. Removed at every start.
    private static final String OLD_COPY = "decoder-vm";

    private final Context mContext; // device-protected storage, so the VM runs before the first unlock
    private File mKernel;
    private File mInitrd;
    private final long mMemoryBytes;
    private final Executor mCallbacks = Executors.newSingleThreadExecutor();

    private VirtualMachine mVm;
    private GuestLink mLink;
    private volatile boolean mStopped = true;
    private long mStartedAt;
    private long mReadyAt;

    GuestVm(Context context, File kernel, File initrd, long memoryBytes) {
        mContext = context.createDeviceProtectedStorageContext();
        mKernel = kernel;
        mInitrd = initrd;
        mMemoryBytes = memoryBytes;
    }

    /** Test builds only: other image files for the next start (the self-test's fail-closed check). */
    synchronized void setImagesForTest(File kernel, File initrd) {
        mKernel = kernel;
        mInitrd = initrd;
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
                GuestLink link = new GuestLink(FdChannel.nonBlocking(pfd));
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
        deleteTree(new File(mContext.getFilesDir(), OLD_COPY));
        File kernel = mKernel;
        File initrd = mInitrd;
        checkLabel(kernel);
        checkLabel(initrd);
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

    // The VM manager's own rule for a protected VM's kernel files, checked first so a refusal names its cause.
    private static void checkLabel(File f) throws IOException {
        String label;
        try {
            byte[] v = Os.getxattr(f.getPath(), "security.selinux");
            int n = v.length;
            while (n > 0 && v[n - 1] == 0) n--;
            label = new String(v, 0, n, StandardCharsets.US_ASCII);
        } catch (ErrnoException e) {
            throw new IOException("VM image " + f + " not readable: " + e.getMessage());
        }
        if (!VmImages.labelAllowed(label)) {
            throw new IOException("VM image " + f + " has label " + label + ", which the VM manager refuses");
        }
    }

    private static void deleteTree(File f) {
        File[] kids = f.listFiles();
        if (kids != null) for (File k : kids) deleteTree(k);
        f.delete();
    }
}
