# KernelSU — alioth 4.19 research fork

Forked from [tiann/KernelSU](https://github.com/tiann/KernelSU) v3.2.4 (commit `0e4dafca`).

**Target:** Xiaomi alioth (Redmi K40 / POCO F3 / Mi 11X)
**Kernel:** Linux 4.19.325-cip128 (LineageOS 23.2 nightly, Android 16)
**Purpose:** BPF + security research kernel; KSU integrated for root management

## Why fork?

KernelSU upstream officially [dropped non-GKI support starting v1.0](https://kernelsu.org/zh_CN/guide/how-to-integrate-for-non-gki.html). The latest upstream (v3.2.4) won't build cleanly on Linux 4.19 and the manager APK refuses to recognize 4.19 kernels.

This fork adds the compat patches needed to make the **latest** KSU work on 4.19.

## Companion repos

- **Research kernel**: [`ltlly/android_kernel_xiaomi_sm8250-bpf-research`](https://github.com/ltlly/android_kernel_xiaomi_sm8250-bpf-research) — the actual kernel that pulls this KSU as a submodule
- **Project workspace**: [`ltlly/alioth-kernel-research`](https://github.com/ltlly/alioth-kernel-research) — engineering log, build scripts, Phase 0/1 documentation

## Patches in this fork

### Kernel-side (drivers/kernelsu/, except `manager/`)

| File | Why |
|---|---|
| `core/init.c` | `MODULE_IMPORT_NS` version-guarded for <5.4 |
| `policy/allowlist.c` | `TWA_RESUME` compat + `<linux/sched/task.h>` for `put_task_struct` |
| `policy/app_profile.c` | `seccomp.filter_count` (5.13+) and `seccomp_filter_release` (5.9+) version-guarded |
| `infra/seccomp_cache.c` | Wrapped in `#if >= 5.13` (`SECCOMP_ARCH_NATIVE_NR`) with 4.x stubs |
| `infra/su_mount_ns.c` | Wrapped in `#if >= 5.9` (`<uapi/linux/mount.h>`, `path_mount`) with 4.x stubs |
| `infra/file_wrapper.c` | Wrapped in `#if >= 5.1` (`file_operations.iopoll`) with 4.x stubs |
| `selinux/selinux.c` | **Replaced 5.7+-only impl with real 4.19 implementation** (uses `selinux_state.ss`, `enforcing_set`, `security_secctx_to_secid`, `selinux_cred()` directly) |
| `selinux/rules.c, sepolicy.c` | Wrapped in `#if >= 5.7` (selinux_state.policy refactor) with stubs — runtime sepolicy modification deferred |
| `supercall/dispatch.c` | Wrapped in `#if >= 5.0` with stubs (tasklist_lock not exported) |
| `sulog/event.c` | `<linux/minmax.h>` (5.10+) → `<linux/kernel.h>` fallback |
| `feature/kernel_umount.c` | `path_umount` (5.9+) version guarded |
| `runtime/ksud_integration.c` | Inject `setenforce 0` into init.rc fragment at multiple stages |

### **The breakthrough fix** ⭐

`hook/arm64/patch_memory.c`: 6-line `pmd_leaf`/`pud_leaf` fallback to `pmd_sect`/`pud_sect`. Without this, KSU's `phys_from_virt()` walks page tables incorrectly on arm64 4.19 (kernel text uses PMD section mapping), all syscall table patches silently fail, KSU is "loaded but inert". With this fix, all hooks install correctly.

### Manager APK side

- `manager/app/src/main/java/me/weishu/kernelsu/Kernels.kt`: `isGKI()` accepts `major == 4 && patchLevel >= 19` so the UI surfaces real status instead of "不支持".

## Building

### Kernel module

In a kernel build with `CONFIG_KSU=y`, this drops in via the standard KSU integration script:

```
curl -LSs "https://raw.githubusercontent.com/ltlly/KernelSU-alioth-4.19-research/alioth-4.19-research/kernel/setup.sh" | bash -s alioth-4.19-research
```

Or as a submodule. See companion kernel repo's defconfig for `CONFIG_KSU=y`.

### Manager APK

Standard upstream build instructions (gradle in `manager/`). Requires Android SDK + NDK + Rust toolchain.

## Status (as of 2026-04-28)

**Working on this 4.19 fork:**
- ✅ Compiles + module loads with all hooks active
- ✅ Syscall table patches (setresuid/execve/newfstatat/faccessat) installed live
- ✅ kretprobes for syscall_regfunc/unregfunc
- ✅ sys_enter tracepoint registered
- ✅ KSU init.rc injection
- ✅ on_post_fs_data fires
- ✅ ksud daemon ↔ kernel ioctl verified via logcat
- ✅ Manager APK shows correct kernel version + Permissive SELinux state (after our isGKI patch)

**Not done in this fork** (deferred):
- ⚠️ `selinux/rules.c, sepolicy.c` runtime ksu domain registration — uses 5.7+ `selinux_state.policy` structure; on 4.19 we kept stubs and rely on `setenforce 0` injection instead. To fix properly, ~6-10 hours of work to rewrite sepolicy.c for 4.19's `selinux_state.ss->policydb` and `flex_array` accessors.

## Limitations / known issues

- The `ksu` SELinux domain isn't registered at runtime, so SELinux is set globally permissive at boot. Re-enable enforcing manually with `adb shell setenforce 1` if needed.

## License

Same as upstream KernelSU: GPL-2.0
