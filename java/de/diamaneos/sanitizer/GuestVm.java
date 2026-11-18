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
final class GuestVm implements Decoder.Vm {
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
    // A kept connection per lane: [0] the big lane, [1] the small lane.
    private final GuestLink[] mLinks = new GuestLink[2];
    private volatile boolean mStopped = true;
    // Counts starts. Each start's callbacks carry its number, so a late callback of an instance stopped earlier never
    // marks the current one stopped.
    private volatile int mGeneration;
    private long mStartedAt;
    private long mReadyAt;

    // The test app's VM (images from /data/local/tmp on a debuggable build). The product's takes system_file only.
    private final boolean mTest;
    private final boolean[] mLastReused = new boolean[2];
    // Two lanes (the small one beside the big one) and two vCPUs or more for them, unless a debuggable build's test
    // asks for the single lane (DebugBuild.SINGLE_LANE).
    private final boolean mLanes = !DebugBuild.singleLaneForTest();
    private volatile String mLastError = "";

    GuestVm(Context context, File kernel, File initrd, long memoryBytes) {
        this(context, kernel, initrd, memoryBytes, false);
    }

    GuestVm(Context context, File kernel, File initrd, long memoryBytes, boolean test) {
        mContext = context.createDeviceProtectedStorageContext();
        mKernel = kernel;
        mInitrd = initrd;
        mMemoryBytes = memoryBytes;
        mTest = test;
    }

    /** Test builds only: other image files for the next start (the self-test's fail-closed check). */
    synchronized void setImagesForTest(File kernel, File initrd) {
        if (!mTest) throw new IllegalStateException("not a test VM");
        mKernel = kernel;
        mInitrd = initrd;
    }

    /** Milliseconds from run() to the first answer of the last start, -1 before. */
    synchronized long lastStartMillis() {
        return mReadyAt > 0 ? mReadyAt - mStartedAt : -1;
    }

    @Override
    public synchronized boolean isRunning() {
        return mVm != null && !mStopped;
    }

    /**
     * Starts the VM unless it runs, and returns a working link, pinged within the deadline. Throws when the VM does
     * not come up in time: the caller fails closed and the scheduler starts again with backoff.
     */
    @Override
    public synchronized GuestLink link(boolean small, long deadline) throws IOException {
        int lane = small ? 1 : 0;
        GuestLink kept = mLinks[lane];
        mLastReused[lane] = kept != null && !kept.isBroken() && !mStopped;
        if (mLastReused[lane]) return kept;
        if (kept != null) kept.close();
        mLinks[lane] = null;
        if (mVm == null || mStopped) start();
        IOException last = null;
        while (SystemClock.uptimeMillis() < deadline) {
            try {
                ParcelFileDescriptor pfd = mVm.connectVsock(small ? GuestLink.SMALL_PORT : GuestLink.PORT);
                GuestLink link = new GuestLink(FdChannel.nonBlocking(pfd));
                link.ping(Math.min(deadline, SystemClock.uptimeMillis() + 2000));
                if (mReadyAt == 0) mReadyAt = SystemClock.uptimeMillis();
                mLinks[lane] = link;
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
    @Override
    public synchronized void stop() {
        for (int i = 0; i < mLinks.length; i++) {
            if (mLinks[i] != null) mLinks[i].close();
            mLinks[i] = null;
        }
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
        mLastError = ""; // an error is the last start's, never an older one's
        final int generation = ++mGeneration;
        deleteTree(new File(mContext.getFilesDir(), OLD_COPY));
        File kernel = mKernel;
        File initrd = mInitrd;
        checkLabel(kernel, mTest);
        checkLabel(initrd, mTest);
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
                    if (generation != mGeneration) return; // an instance stopped earlier
                    mLastError = printable("VM error " + errorCode + ": " + message);
                    Log.e(TAG, mLastError);
                    mStopped = true;
                }
                @Override public void onStopped(VirtualMachine v, int reason) {
                    if (generation != mGeneration) return;
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
            // The VM manager's own reason (a refused label, scattered memory, no protected VMs) goes to the log in
            // full, with every cause.
            mLastError = printable(causes(e));
            Log.e(TAG, "VM start failed, " + (mMemoryBytes >> 20) + " MiB: " + mLastError, e);
            throw new IOException("VM start: " + causes(e), e);
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
        // Two lanes need two vCPUs. The VM framework offers one vCPU or one per host CPU (MATCH_HOST), no count in
        // between: the lanes use two of them, the rest stay idle (a halted vCPU costs no CPU time).
        return vb.setProtectedVm(true)
                .setDebugLevel(VirtualMachineConfig.DEBUG_LEVEL_NONE)
                .setMemoryBytes(mMemoryBytes)
                .setCpuTopology(mLanes ? VirtualMachineConfig.CPU_TOPOLOGY_MATCH_HOST
                                       : VirtualMachineConfig.CPU_TOPOLOGY_ONE_CPU)
                .build();
    }

    /** Why the last start failed, as the VM manager said it, or "". Cleared at every start. */
    @Override
    public String lastError() {
        return mLastError;
    }

    /** Debuggable builds only: a test holds the VM down (DebugBuild.DOWN_UNTIL). */
    @Override
    public boolean heldDown() {
        if (!DebugBuild.vmHeldDown()) return false;
        mLastError = "held down for a test (" + DebugBuild.DOWN_UNTIL + ")";
        return true;
    }

    /** Whether the last link() handed back a connection made earlier (which may have died meanwhile). */
    @Override
    public synchronized boolean lastLinkReused(boolean small) {
        return mLastReused[small ? 1 : 0];
    }

    /** Drops the lane's connection but keeps the VM: the next link() connects again. */
    @Override
    public synchronized void dropLink(boolean small) {
        int lane = small ? 1 : 0;
        if (mLinks[lane] != null) mLinks[lane].close();
        mLinks[lane] = null;
    }

    /** Whether this VM has the small lane (two lanes, two vCPUs or more). */
    @Override
    public boolean lanes() {
        return mLanes;
    }

    /** Text as it may be printed: control characters become spaces, at most 2000 characters. */
    static String printable(String s) {
        StringBuilder b = new StringBuilder(Math.min(s.length(), 2000));
        for (int i = 0; i < s.length() && b.length() < 2000; i++) {
            char c = s.charAt(i);
            b.append(c < 0x20 || c == 0x7f || (c >= 0x80 && c < 0xa0) || c == 0x2028 || c == 0x2029 ? ' ' : c);
        }
        return b.toString();
    }

    private static String causes(Throwable e) {
        StringBuilder b = new StringBuilder();
        for (Throwable t = e; t != null && b.length() < 2000; t = t.getCause()) {
            if (b.length() > 0) b.append(" <- ");
            b.append(t.getClass().getSimpleName()).append(": ").append(t.getMessage());
            if (t.getCause() == t) break;
        }
        return b.toString();
    }

    // The VM manager's own rule for a protected VM's kernel files, checked first so a refusal names its cause.
    private static void checkLabel(File f, boolean test) throws IOException {
        String label;
        try {
            byte[] v = Os.getxattr(f.getPath(), "security.selinux");
            int n = v.length;
            while (n > 0 && v[n - 1] == 0) n--;
            label = new String(v, 0, n, StandardCharsets.US_ASCII);
        } catch (ErrnoException e) {
            throw new IOException("VM image " + f + " not readable: " + e.getMessage());
        }
        if (!VmImages.labelAllowed(label, test)) {
            throw new IOException("VM image " + f + " has label " + label + ", which the VM manager refuses");
        }
    }

    private static void deleteTree(File f) {
        File[] kids = f.listFiles();
        if (kids != null) for (File k : kids) deleteTree(k);
        f.delete();
    }
}
