# The decoder VM in the virtualization APEX

The decode service starts a raw protected VM: our own guest kernel and a one-program initramfs (`vm/`). pvmfw boots
it only when the kernel's AVB hash footer is signed with the key pvmfw trusts, and that footer also covers the
initramfs (an `initrd_normal` and an `initrd_debug` hash descriptor).

Release signing replaces pvmfw's trusted key with the virtualization APEX's payload key (`avb.pem` in our signer) and
`sign_virt_apex.py` signs the guest kernels inside the APEX again with that key. A kernel shipped anywhere else would
keep the build's test key, and a release build's pvmfw would refuse it. So the decoder VM's two files go into the APEX
and are signed the way the filesystem VM's are: the shared DiamaneOS guest kernel, signed once per VM over that VM's
initramfs. Our signer needs no change: it already passes `avb.pem` as the APEX's payload key.

## Changes in packages/modules/Virtualization (the DiamaneOS fork)

Two branches on the pinned base.

### decode-vm: the files in the APEX and their signing

1. `guest/decoder_vm/Android.bp` (new): the two initramfs hash descriptors (`decoder_vm_initrd_normal_hashdesc`,
   `decoder_vm_initrd_debug_hashdesc`, both over `decoder_vm_initrd`), the kernel signed over them
   (`decoder_vm_kernel_signed`, from `diamaneos_guest_kernel_prebuilt` with Microdroid's kernel defaults), and the
   two installed files (`decoder_vm_kernel`, an empty file on every arch but arm64, and `decoder_vm_initrd_apex`).
   No debuggable variant: the same initramfs stands for both descriptors pvmfw knows.

2. `build/apex/Android.bp`: `decoder_vm_initrd_apex` and `decoder_vm_kernel` in the APEX's prebuilts, after
   `microdroid_kernel`. On the phone: `/apex/com.android.virt/etc/fs/decoder_vm_kernel` and
   `/apex/com.android.virt/etc/decoder_vm_initrd.img`, the paths `DecoderApp` uses.

3. `build/apex/sign_virt_apex.py`:
   - `DecoderVmFiles` adds the kernel and its initramfs to the files to sign. A missing kernel, or a kernel without
     its initramfs, stops the signing with an error. An empty kernel (an APEX for another arch) signs nothing. The
     initramfs carries no bootconfig, so its key does not end in `initrd_normal.img` or `initrd_debuggable.img`
     (`IsInitrdImage`).
   - `SignVirtApex` signs the kernel again over the unchanged initramfs and then checks the result
     (`VerifyDecoderVmKernel`): the payload key's signature, and the initramfs digest in both descriptors. The
     kernel stays out of `original_kernels` on purpose: the service VM holds no digests of it, and its initramfs
     digests do not change, which `update_initrd_digests_in_service_vm` would reject.
   - `--verify` runs the same check and leaves the initramfs itself out of the footer check (it has none).

4. Tests: `sign_virt_apex_decoder_test.py` (a throwaway tree: the missing and empty kernel, a kernel signed again
   with another key, an initramfs changed after signing), run by `sign_virt_apex_test`, which also checks the real
   APEX: re-signed and verified, a changed initramfs refused, signing refused without the kernel.

The kernel and initramfs are system_file in the APEX, one of the labels virtmgr takes for a protected VM's kernel
(`check_label_is_allowed`). A copy in app data would be refused.

### vm-vcpus: two vCPUs for the two lanes

The VM framework offers only one vCPU or one per host CPU. `VirtualMachineCustomImageConfig.Builder.setCpuCount`
(hidden, kept in the config's bundle as `cpu_count`) asks for an exact count, and `VirtualMachineConfig` passes it
to virtmgr as a CPU count topology. virtmgr (`android/virtmgr/src/crosvm.rs`) takes one vCPU as before, without
asking the host, and any other count from 2 up to the host's CPUs (`checked_cpu_count`, unit tested). Anything else
is an error. The service asks for two through reflection, and the health check reports the vCPUs the VM really has
(the VM's ping counts them), so a framework without the count shows there.

## Checks

- Build time: `sign_virt_apex_test` (above). The tools' image checks should also open the signed virt APEX of a
  release and verify `etc/fs/decoder_vm_kernel` against the release key, like the pvmfw key check. Until then, a
  release build that kept the test key fails closed at runtime: pvmfw refuses the kernel, the VM never starts, and
  the service answers "unavailable".
- F46 on every build: `dumpsys activity provider de.diamaneos.sanitizer/.HealthProvider health` starts the decoder VM
  from these files through the real path, checks its vCPUs and decodes three built-in images.
