#ifndef __KSU_H_COMPAT_SYSCALL_NR
#define __KSU_H_COMPAT_SYSCALL_NR

#include <linux/version.h>

#if defined(__aarch64__) && defined(CONFIG_COMPAT)

// AArch32 syscall numbers, for hooking 32-bit userspace on a 64-bit kernel.
// Use as KSU_COMPAT_NR(execve); the name must match arch/arm64's 32-bit table.
// https://github.com/torvalds/linux/commit/7fe33e9f662c0a2f5110be4afff0a24e0c123540
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 11, 0) || defined(KSU_COMPAT_HAS_NR_COMPAT32_SYSCALLS)

#include <asm/unistd_compat_32.h>

#define KSU_COMPAT_NR(name) __NR_compat32_##name
#define KSU_NR_COMPAT_SYSCALLS __NR_compat32_syscalls

#else

// unistd32.h has no include guard and defines the plain __NR_* names with
// AArch32 values, so pull unistd.h back in afterwards to restore the native ones.
#undef __SYSCALL
#define __SYSCALL(nr, sym) __KSU_COMPAT##nr = (nr),

enum ksu_compat_syscall_nr {
#include <asm/unistd32.h>
};

#undef __SYSCALL
#include <asm/unistd.h>
#undef __SYSCALL

#define KSU_COMPAT_NR(name) __KSU_COMPAT__NR_##name
#define KSU_NR_COMPAT_SYSCALLS __NR_compat_syscalls

#endif

#endif /* __aarch64__ && CONFIG_COMPAT */

#endif
