# LKM Source

This page contains the source code for Re:Kernel LKM

## Building against a device kernel

The release modules are built against the kernels in the DDK build matrix.
A custom kernel can have different configuration, symbol exports, and Binder
layouts even when its major/minor version matches a release module.

For such kernels, build the LKM against the source and build output used for the
running kernel. The build directory must contain the matching generated headers,
configuration, and `Module.symvers`. Use the toolchain and build options required
by that kernel, including its LTO/CFI settings.

For example, from the Re:Kernel repository root, with a Clang-built arm64 kernel:

```sh
KERNEL_SOURCE=/path/to/matching/kernel/source
KERNEL_BUILD=/path/to/matching/kernel/build

make -C "$KERNEL_BUILD" \
    ARCH=arm64 LLVM=1 LLVM_IAS=1 \
    M="$PWD/LKM-Source" \
    REKERNEL_BINDER_DIR="$KERNEL_SOURCE/drivers/android" \
    modules
```

`REKERNEL_BINDER_DIR` defaults to `$(srctree)/drivers/android`. Set it explicitly
when the private Binder headers live outside the build directory's source tree.
The DDK workflow can continue to copy the sources into `drivers/android`.

`make modules_prepare` alone does not generate `Module.symvers`; use the output
of a matching kernel build when `CONFIG_MODVERSIONS` is enabled.

One configuration mismatch can appear as:

```text
rekernel: Unknown symbol _raw_spin_lock (err -2)
rekernel: Unknown symbol _raw_spin_unlock (err -2)
rekernel: Unknown symbol _raw_spin_trylock (err -2)
```

With `CONFIG_INLINE_SPIN_LOCK=y`, `CONFIG_INLINE_SPIN_TRYLOCK=y`, and
`CONFIG_UNINLINE_SPIN_UNLOCK` disabled, the kernel implements these operations
inline and does not export the corresponding out-of-line functions. A module
built with different settings may still import them. Rebuilding with the target
kernel's configuration removes those imports; changing vermagic alone does not.

This does not make a prebuilt module compatible with every custom kernel.
