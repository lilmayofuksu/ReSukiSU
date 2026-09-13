#ifndef __KSU_H_SECCOMP_CACHE
#define __KSU_H_SECCOMP_CACHE

#include <linux/fs.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
// The native and compat caches are indexed by their own architecture's syscall
// numbering, so each needs its own number. Pass a negative @compat_nr when the
// syscall has no compat equivalent, or when its number is unknown.
extern void ksu_seccomp_clear_cache(struct seccomp_filter *filter, int nr, int compat_nr);
extern void ksu_seccomp_allow_cache(struct seccomp_filter *filter, int nr, int compat_nr);
#endif

#endif