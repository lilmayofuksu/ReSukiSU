#ifndef __KSU_SAMSUNG_RKP_H
#define __KSU_SAMSUNG_RKP_H

// kprobe-based syscall interception for Samsung RKP kernels, where the syscall
// table cannot be written. Covers both the native and the AArch32 compat tables.
int ksu_samsung_rkp_init(void);
void ksu_samsung_rkp_exit(void);

#endif
