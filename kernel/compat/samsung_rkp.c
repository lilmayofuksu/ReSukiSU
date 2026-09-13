#include <asm/syscall.h>
#include <linux/compat.h>
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <linux/slab.h>
#include <linux/task_work.h>

#include "arch.h"
#include "compat/samsung_rkp.h"
#include "feature/sucompat.h"
#include "hook/setuid_hook.h"
#include "hook/syscall_event_bridge.h"
#include "hook/syscall_hook.h"
#include "klog.h"
#include "policy/allowlist.h"

#if defined(CONFIG_KSU_SAMSUNG_RKP) && defined(CONFIG_KRETPROBES) && defined(__aarch64__)

#include "compat_syscall_nr.h"

// r7 is not involved here; unlike the tracepoint dispatcher this path never
// rewrites the caller's syscall number to reach us. Instead each hooked entry
// carries its own kprobe, so the entry that fired identifies the syscall, and
// is_compat_task() tells us which table to invoke the original through.
#define SAMSUNG_RKP_BYPASS_NR (-2)

#ifdef CONFIG_COMPAT
#define RKP_COMPAT_NR(name) KSU_COMPAT_NR(name)
#else
#define RKP_COMPAT_NR(name) (-1)
#endif

struct samsung_setresuid_work {
    struct callback_head callback;
    uid_t old_uid;
    uid_t new_uid;
};

struct samsung_rkp_hook {
    struct kprobe native; // kprobe on the AArch64 handler
    struct kprobe compat; // kprobe on the AArch32 handler, if distinct
    bool native_reg;
    bool compat_reg;
    int native_nr;
    int compat_nr;
    long (*trampoline)(const struct pt_regs *regs);
    kprobe_pre_handler_t pre;
};

static bool setresuid_registered;

// The caller's syscall number in its own numbering: a compat task indexes the
// AArch32 table, everyone else the native one.
static int rkp_caller_nr(int native_nr, int compat_nr)
{
#ifdef CONFIG_COMPAT
    if (is_compat_task())
        return compat_nr;
#endif
    return native_nr;
}

// Detect re-entry: our trampoline stamps syscallno with the sentinel before
// re-invoking the original, so the kprobe firing again must let it through.
static bool consume_bypass(int native_nr, int compat_nr)
{
    struct pt_regs *regs = task_pt_regs(current);

    if (unlikely(regs->syscallno == SAMSUNG_RKP_BYPASS_NR)) {
        regs->syscallno = rkp_caller_nr(native_nr, compat_nr);
        return true;
    }
    return false;
}

#define DEFINE_RKP_SYSCALL(sym, hookfn, nat_nr, cmp_nr)                                                                 \
    static long __nocfi samsung_##sym(const struct pt_regs *regs)                                                       \
    {                                                                                                                    \
        struct pt_regs *r = (struct pt_regs *)regs;                                                                     \
        int nr = rkp_caller_nr(nat_nr, cmp_nr);                                                                         \
        long ret;                                                                                                        \
        r->syscallno = SAMSUNG_RKP_BYPASS_NR;                                                                           \
        ret = hookfn(nr, regs);                                                                                          \
        r->syscallno = nr;                                                                                              \
        return ret;                                                                                                      \
    }                                                                                                                    \
    static int samsung_##sym##_pre(struct kprobe *probe, struct pt_regs *regs)                                          \
    {                                                                                                                    \
        (void)probe;                                                                                                     \
        if (consume_bypass(nat_nr, cmp_nr))                                                                             \
            return 0;                                                                                                    \
        instruction_pointer_set(regs, (unsigned long)samsung_##sym);                                                    \
        return 1;                                                                                                        \
    }

DEFINE_RKP_SYSCALL(execve, ksu_hook_execve, __NR_execve, RKP_COMPAT_NR(execve))
DEFINE_RKP_SYSCALL(execveat, ksu_hook_execveat, __NR_execveat, RKP_COMPAT_NR(execveat))
DEFINE_RKP_SYSCALL(newfstatat, ksu_hook_newfstatat, __NR_newfstatat, RKP_COMPAT_NR(fstatat64))
DEFINE_RKP_SYSCALL(faccessat, ksu_hook_faccessat, __NR_faccessat, RKP_COMPAT_NR(faccessat))

static struct samsung_rkp_hook rkp_hooks[] = {
    { .native_nr = __NR_execve, .compat_nr = RKP_COMPAT_NR(execve),
      .trampoline = samsung_execve, .pre = samsung_execve_pre },
    { .native_nr = __NR_execveat, .compat_nr = RKP_COMPAT_NR(execveat),
      .trampoline = samsung_execveat, .pre = samsung_execveat_pre },
    { .native_nr = __NR_newfstatat, .compat_nr = RKP_COMPAT_NR(fstatat64),
      .trampoline = samsung_newfstatat, .pre = samsung_newfstatat_pre },
    { .native_nr = __NR_faccessat, .compat_nr = RKP_COMPAT_NR(faccessat),
      .trampoline = samsung_faccessat, .pre = samsung_faccessat_pre },
};

// setresuid needs the post-transition uid, so it uses a kretprobe rather than a
// pre-handler redirect. The AArch32 setresuid32 shares this handler, so one
// kretprobe catches both ABIs.
static void setresuid_work(struct callback_head *callback)
{
    struct samsung_setresuid_work *work = container_of(callback, struct samsung_setresuid_work, callback);

    ksu_handle_setuid(work->new_uid, work->old_uid);
    kfree(work);
}

static int setresuid_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    (void)regs;
    *(uid_t *)ri->data = current_uid().val;
    return 0;
}

static int setresuid_return(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct samsung_setresuid_work *work;
    uid_t old_uid = *(uid_t *)ri->data;
    uid_t new_uid;

    if (regs_return_value(regs) < 0)
        return 0;
    new_uid = current_uid().val;
    if (old_uid == new_uid)
        return 0;

    // kretprobe context is atomic; defer the actual handling to task work.
    work = kzalloc(sizeof(*work), GFP_ATOMIC);
    if (!work)
        return 0;
    work->old_uid = old_uid;
    work->new_uid = new_uid;
    work->callback.func = setresuid_work;
    if (task_work_add(current, &work->callback, TWA_RESUME))
        kfree(work);
    return 0;
}

static struct kretprobe setresuid_kretprobe = {
    .entry_handler = setresuid_entry,
    .handler = setresuid_return,
    .data_size = sizeof(uid_t),
};

static void unregister_syscall_hooks(void)
{
    int i;

    for (i = ARRAY_SIZE(rkp_hooks) - 1; i >= 0; i--) {
        if (rkp_hooks[i].compat_reg) {
            unregister_kprobe(&rkp_hooks[i].compat);
            rkp_hooks[i].compat_reg = false;
        }
        if (rkp_hooks[i].native_reg) {
            unregister_kprobe(&rkp_hooks[i].native);
            rkp_hooks[i].native_reg = false;
        }
    }
}

static int register_one(struct samsung_rkp_hook *h)
{
    void *native_addr = (void *)READ_ONCE(ksu_syscall_table[h->native_nr]);
    int ret;

    h->native.pre_handler = h->pre;
    h->native.addr = (kprobe_opcode_t *)native_addr;
    ret = register_kprobe(&h->native);
    if (ret)
        return ret;
    h->native_reg = true;

#ifdef CONFIG_COMPAT
    if (ksu_compat_syscall_table && h->compat_nr >= 0) {
        void *compat_addr = (void *)READ_ONCE(ksu_compat_syscall_table[h->compat_nr]);

        // Only plant a second probe when the AArch32 handler is a distinct
        // function; when it shares the native handler the first probe already
        // covers 32-bit callers.
        if (compat_addr != native_addr) {
            h->compat.pre_handler = h->pre;
            h->compat.addr = (kprobe_opcode_t *)compat_addr;
            ret = register_kprobe(&h->compat);
            if (ret) {
                unregister_kprobe(&h->native);
                h->native_reg = false;
                return ret;
            }
            h->compat_reg = true;
        }
    }
#endif
    return 0;
}
#endif

int ksu_samsung_rkp_init(void)
{
#if defined(CONFIG_KSU_SAMSUNG_RKP) && defined(CONFIG_KRETPROBES) && defined(__aarch64__)
    int i, ret;

    if (!ksu_syscall_table)
        return -ENOENT;

    for (i = 0; i < ARRAY_SIZE(rkp_hooks); i++) {
        ret = register_one(&rkp_hooks[i]);
        if (ret) {
            pr_err("Samsung RKP: failed to hook nr=%d: %d\n", rkp_hooks[i].native_nr, ret);
            goto fail;
        }
    }

    setresuid_kretprobe.kp.addr = (kprobe_opcode_t *)READ_ONCE(ksu_syscall_table[__NR_setresuid]);
    ret = register_kretprobe(&setresuid_kretprobe);
    if (ret)
        goto fail;
    setresuid_registered = true;

    pr_info("Samsung RKP syscall fallback enabled (native + compat)\n");
    return 0;

fail:
    unregister_syscall_hooks();
    return ret;
#else
    return -EOPNOTSUPP;
#endif
}

void ksu_samsung_rkp_exit(void)
{
#if defined(CONFIG_KSU_SAMSUNG_RKP) && defined(CONFIG_KRETPROBES) && defined(__aarch64__)
    if (setresuid_registered) {
        unregister_kretprobe(&setresuid_kretprobe);
        setresuid_registered = false;
    }
    unregister_syscall_hooks();
#endif
}
