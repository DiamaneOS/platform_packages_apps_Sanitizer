# The decoder VM in the virtualization APEX

The decode service starts a raw protected VM: our own guest kernel and a one-program initramfs (`vm/`). pvmfw boots
it only when the kernel's AVB hash footer is signed with the key pvmfw trusts, and that footer also covers the
initramfs (an `initrd_normal` and an `initrd_debug` hash descriptor).

Release signing replaces pvmfw's trusted key with the virtualization APEX's payload key (`avb.pem` in our signer) and
`sign_virt_apex.py` signs the guest kernels inside the APEX again with that key. A kernel shipped anywhere else would
keep the build's test key, and a release build's pvmfw would refuse it. So the decoder VM's two files go into the APEX
and are signed exactly the way the filesystem VM's are (the SD card work, `packages/modules/Virtualization`
`guest/diamaneos`, its branch 3c75187bb on the builder under `vmcheck-20261115/fsprod/virt`): one guest kernel, signed
once per DiamaneOS VM over that VM's initramfs. Our signer needs no change: it already passes `avb.pem` as the APEX's
payload key.

## Changes in packages/modules/Virtualization (the DiamaneOS fork), next to the filesystem VM's

1. `guest/diamaneos/Android.bp`, beside `fsvm_kernel_signed` (same shared kernel `diamaneos_guest_kernel_prebuilt`,
   same defaults):

   ```
   // The decode service's VM (packages/apps/DiamaneOSSanitizer). No debuggable variant: the same initramfs stands
   // for both descriptors pvmfw knows.
   avb_gen_vbmeta_image {
       name: "decoder_vm_initrd_normal_hashdesc",
       defaults: ["microdroid_initrd_normal_defaults"],
       src: ":decoder_vm_initrd",
   }

   avb_gen_vbmeta_image {
       name: "decoder_vm_initrd_debug_hashdesc",
       defaults: ["microdroid_initrd_debug_defaults"],
       src: ":decoder_vm_initrd",
   }

   avb_add_hash_footer {
       name: "decoder_vm_kernel_signed",
       defaults: ["microdroid_kernel_signed_defaults"],
       filename: "decoder_vm_kernel",
       arch: {
           arm64: {
               src: ":diamaneos_guest_kernel_prebuilt",
           },
       },
       include_descriptors_from_images: [
           ":decoder_vm_initrd_normal_hashdesc",
           ":decoder_vm_initrd_debug_hashdesc",
       ],
   }

   prebuilt_etc {
       name: "decoder_vm_kernel",
       src: ":empty_file",
       relative_install_path: "fs",
       filename: "decoder_vm_kernel",
       arch: {
           arm64: {
               src: ":decoder_vm_kernel_signed",
           },
       },
   }

   prebuilt_etc {
       name: "decoder_vm_initrd_apex",
       src: ":decoder_vm_initrd",
       filename: "decoder_vm_initrd.img",
   }
   ```

2. `build/apex/Android.bp`, the APEX's prebuilts, after `fsvm_initrd` and `fsvm_kernel`: `decoder_vm_initrd_apex`
   and `decoder_vm_kernel`. On the phone: `/apex/com.android.virt/etc/fs/decoder_vm_kernel` and
   `/apex/com.android.virt/etc/decoder_vm_initrd.img`, the paths `DecoderApp` uses.

3. `build/apex/sign_virt_apex.py`, the same two steps as the filesystem VM's:

   ```diff
   @@ def TargetFiles(input_dir):
   +    # DiamaneOS: the decode service VM's kernel and its initramfs. The initramfs carries no bootconfig, so its
   +    # key must not end in initrd_normal.img or initrd_debuggable.img (IsInitrdImage).
   +    decoder_kernel = os.path.join(input_dir, 'etc/fs/decoder_vm_kernel')
   +    if os.path.isfile(decoder_kernel):
   +        ret['decoder_vm_kernel'] = decoder_kernel
   +        ret['decoder_vm_initrd'] = os.path.join(input_dir, 'etc/decoder_vm_initrd.img')
   @@ def SignVirtApex(args):
   +    # DiamaneOS: sign the decode service VM's kernel again over its unchanged initramfs. Left out of
   +    # original_kernels on purpose, like the filesystem VM's: the service VM holds no digests of it, and its
   +    # initramfs digests do not change, which update_initrd_digests_in_service_vm would reject.
   +    if 'decoder_vm_kernel' in files:
   +        resign_kernel_tasks.append(resign_kernel('decoder_vm_kernel', 'decoder_vm_initrd', 'decoder_vm_initrd'))
   ```

   Adding the kernel to `original_kernels` makes signing fail (found by the SD card work with a throwaway key).

4. `virtmgr` needs no change: the service passes both files from the APEX as they are. They are system_file, one of the
   labels virtmgr takes for a protected VM's kernel (`check_label_is_allowed`). A copy in app data would be refused.

## Checks

- The tools' image checks should open the signed virt APEX and verify `etc/fs/decoder_vm_kernel` (and
  `fsvm_kernel`) against the release key, like the pvmfw key check. Until then, a release build that kept the test
  key fails closed at runtime: pvmfw refuses the kernel, the VM never starts, and the service answers
  "unavailable".
- F46 on every build: `dumpsys activity provider de.diamaneos.sanitizer/.HealthProvider health` starts the decoder VM
  from these files through the real path and decodes three built-in images.
