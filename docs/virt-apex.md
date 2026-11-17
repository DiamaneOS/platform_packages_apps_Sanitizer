# The decoder VM in the virtualization APEX

The decode service starts a raw protected VM: our own guest kernel and a one-program initramfs (`vm/`). pvmfw boots
it only when the kernel's AVB hash footer is signed with the key pvmfw trusts, and that footer also covers the
initramfs (an `initrd_normal` and an `initrd_debug` hash descriptor).

Release signing replaces pvmfw's trusted key with the virtualization APEX's payload key (`avb.pem` in our signer) and
`sign_virt_apex.py` signs every guest kernel inside the APEX again with that key. A kernel shipped anywhere else would
keep the build's test key, and a release build's pvmfw would refuse it. So the decoder VM's two files go into the APEX,
and `sign_virt_apex.py` learns their names. Our signer needs no change: it already passes `avb.pem` as the APEX's
payload key.

## Changes in packages/modules/Virtualization (a DiamaneOS fork)

1. The APEX takes the files, next to Microdroid's (`build/apex/Android.bp`, `prebuilts` of `com.android.virt`):

   - `decoder_vm_kernel`: an `avb_add_hash_footer` of our guest kernel (kernel_common microdroid_defconfig with
     seccomp), partition `boot`, signed with the build's key, with the descriptors of the initramfs as `initrd_normal`
     and `initrd_debug`, installed as `etc/fs/decoder_vm_kernel`.
   - `decoder_vm_initrd`: the `decoder_vm_initrd` genrule of this repository, installed as
     `etc/decoder_vm_initrd.img`.

2. `build/apex/sign_virt_apex.py` signs them again:

   ```diff
   @@ def TargetFiles(input_dir):
        if os.path.isfile(kernel_16k):
            ...
   +    # DiamaneOS decode service: our guest kernel and its one-program initramfs. The initramfs has no bootconfig,
   +    # so its keys must not end in initrd_normal.img or initrd_debuggable.img (IsInitrdImage).
   +    decoder_kernel = os.path.join(input_dir, 'etc/fs/decoder_vm_kernel')
   +    if os.path.isfile(decoder_kernel):
   +        ret['decoder_vm_kernel'] = decoder_kernel
   +        ret['decoder_vm_initrd'] = os.path.join(input_dir, 'etc/decoder_vm_initrd.img')
        return ret
   @@ def SignVirtApex(args):
   +    if 'decoder_vm_kernel' in files:
   +        _, original = AvbInfo(args, files['decoder_vm_kernel'])
   +        resign_kernel_tasks.append(resign_kernel('decoder_vm_kernel', 'decoder_vm_initrd', 'decoder_vm_initrd'))
   +        original_kernels['decoder_vm_kernel'] = original
   ```

   The same initramfs serves as the normal and the debug descriptor: the decoder VM has no debug variant.

3. `virtmgr` needs no change: the service copies both files into its own data, which the VM manager may read.

## Checks

- The tools' image checks should open the signed virt APEX and verify `etc/fs/decoder_vm_kernel` against the release
  key, like the pvmfw key check. Until then, a release build that kept the test key fails closed at runtime: pvmfw
  refuses the kernel, the VM never starts, and the service answers "unavailable".
- F46 on a release-signed build: the decoder VM starts.
