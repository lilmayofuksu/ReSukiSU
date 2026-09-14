#ifndef __KSU_H_KSU_SYSCALL_HOOK
#define __KSU_H_KSU_SYSCALL_HOOK
#include <asm/syscall.h>
#if defined(__aarch64__) && defined(CONFIG_COMPAT)
// only the compat branch of ksu_invoke_orig_syscall needs is_compat_task();
// pulling this in on x86 collides with kernel_compat.h's in_compat_syscall macro
#include <linux/compat.h>
#endif

#if defined(__x86_64__)
typedef sys_call_ptr_t syscall_fn_t;
#endif

extern syscall_fn_t *ksu_syscall_table;

#if defined(__aarch64__) && defined(CONFIG_COMPAT)
extern syscall_fn_t *ksu_compat_syscall_table;
#endif

// Dispatcher slot number in syscall table
extern int ksu_dispatcher_nr;

#if defined(__aarch64__) && defined(CONFIG_COMPAT)
// Dispatcher slot number in compat syscall table
extern int ksu_compat_dispatcher_nr;
#endif

// Syscall hook handler type.
// orig_nr: the original syscall number before redirection
// regs: the original pt_regs from userspace
// Handler is responsible for calling ksu_syscall_table[orig_nr](regs) if needed.
typedef long (*ksu_syscall_hook_fn)(int orig_nr, const struct pt_regs *regs);

// --- Dispatcher-based hook API (register/unregister) ---
// Register a handler into the dispatcher's routing table for syscall @nr.
// When a marked process invokes syscall @nr, the sys_enter tracepoint redirects
// it to the unified dispatcher, which looks up @fn by @nr and calls it.
// Does NOT modify the syscall table itself — the dispatcher slot is shared.
// Returns 0 on success, -EEXIST if already registered, -EINVAL if nr invalid.
int ksu_register_syscall_hook(int nr, ksu_syscall_hook_fn fn);

// Remove a handler from the dispatcher's routing table for syscall @nr.
// The syscall table is not touched — only the dispatcher stops routing @nr.
void ksu_unregister_syscall_hook(int nr);

// Check if a handler is registered in the dispatcher for syscall @nr.
bool ksu_has_syscall_hook(int nr);

// --- Direct syscall table patching API (hook/unhook) ---
// Directly overwrite syscall_table[@nr] with @fn using fixmap + stop_machine.
// Saves the original handler to *@old (if non-NULL) and records the entry
// for restoration at module exit. Use this for boot-time hooks that replace
// a real syscall entry (e.g. ksud hooking __NR_execve/__NR_read/__NR_fstat).
int ksu_syscall_table_hook(int nr, syscall_fn_t fn, syscall_fn_t *old);

// Restore syscall_table[@nr] to its original value recorded by
// ksu_syscall_table_hook(), and remove the entry from the tracking list.
// Use this to cleanly undo a direct hook when it is no longer needed
// (e.g. ksud unhooking __NR_read after init.rc injection is done).
void ksu_syscall_table_unhook(int nr);

// --- AArch32-on-AArch64 (compat) hook API ---
// Same split as above, against compat_sys_call_table and the AArch32 syscall
// numbers. The dispatcher recovers the original number from r7 rather than from
// a stash, since AArch32 has no register to spare.
#if defined(__aarch64__) && defined(CONFIG_COMPAT)
int ksu_register_compat_syscall_hook(int nr, ksu_syscall_hook_fn fn);
void ksu_unregister_compat_syscall_hook(int nr);
bool ksu_has_compat_syscall_hook(int nr);

void ksu_compat_syscall_table_hook(int nr, syscall_fn_t fn, syscall_fn_t *old);
void ksu_compat_syscall_table_unhook(int nr);
#endif

// Call the original handler for @nr out of the table the calling task belongs to.
// @nr is in that task's own numbering, which is what a hook receives as orig_nr.
static inline long __nocfi ksu_invoke_orig_syscall(int nr, const struct pt_regs *regs)
{
#if defined(__aarch64__) && defined(CONFIG_COMPAT)
    if (is_compat_task())
        return ksu_compat_syscall_table[nr](regs);
#endif
    return ksu_syscall_table[nr](regs);
}

void ksu_syscall_hook_init(void);
void ksu_syscall_hook_exit(void);

#endif
