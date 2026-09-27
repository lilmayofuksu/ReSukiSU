#include "linux/printk.h"
#include <linux/spinlock.h>
#include <linux/kprobes.h>
#include <linux/tracepoint.h>
#include <asm/syscall.h>
#include <linux/ptrace.h>
#include <linux/slab.h>
#include <linux/task_work.h>
#include <trace/events/syscalls.h>

#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/task_stack.h>
#endif
#include <linux/compat.h>

#include "compat/syscall_no.h"

#include "arch.h"
#include "klog.h" // IWYU pragma: keep
#include "hook/syscall_hook_manager.h"
#include "hook/tp_marker.h"
#include "feature/sucompat.h"
#include "hook/setuid_hook.h"
#include "hook/syscall_hook.h"
#include "hook/syscall_event_bridge.h"
#include "policy/allowlist.h"
#if defined(__riscv)
#include "hook/riscv64/syscall_regs.h"
#endif

static bool syscall_hook_manager_initialized;

#if defined(CONFIG_KSU_SAMSUNG_RKP) && defined(CONFIG_KRETPROBES) && defined(__aarch64__)
struct ksu_setresuid_task_work {
    struct callback_head callback;
    uid_t old_uid;
    uid_t new_uid;
};

static bool setresuid_kretprobe_registered;
static bool samsung_sucompat_kprobes_registered;

#define SAMSUNG_SUCOMPAT_BYPASS_NR (-2)

static bool samsung_sucompat_should_redirect(int syscall_nr)
{
    struct pt_regs *syscall_regs = task_pt_regs(current);

    if (unlikely(syscall_regs->syscallno == SAMSUNG_SUCOMPAT_BYPASS_NR)) {
        syscall_regs->syscallno = syscall_nr;
        return false;
    }

#ifdef CONFIG_COMPAT
    // A 32-bit task can only be redirected safely once the compat syscall table
    // is resolved: the wrappers hand ksu_call_syscall() a compat number, and it
    // dereferences ksu_compat_syscall_table for compat tasks. If that table is
    // unavailable, leave the syscall untouched rather than deref NULL.
    if (is_compat_task() && !ksu_compat_syscall_table)
        return false;
#endif

#ifdef KSU_COMPAT_USE_STATIC_KEY
    if (!static_branch_unlikely(&ksu_su_compat_enabled))
        return false;
#else
    if (!ksu_su_compat_enabled)
        return false;
#endif

    return ksu_is_allow_uid_for_current(current_uid().val);
}

// ksu_call_syscall() picks the native vs compat syscall table by is_compat_task(),
// indexing it with the number we pass. So each wrapper must hand ksu_hook_*() the
// number that matches the *current* task's ABI: the native nr for a 64-bit task,
// the compat (arm32) nr for a 32-bit task. This is what lets a single wrapper serve
// both the native-table kprobe and (where the address differs) the compat-table kprobe,
// and it also fixes the case where a 32-bit task hits a syscall whose native and compat
// table entries share one address (e.g. faccessat).
static long __nocfi samsung_sucompat_execve(const struct pt_regs *regs)
{
    struct pt_regs *syscall_regs = (struct pt_regs *)regs;
    int syscall_nr = syscall_regs->syscallno;
    int nr = __NR_execve;
    long ret;

#ifdef CONFIG_COMPAT
    if (is_compat_task())
        nr = ksu_get_compat_syscall_no(execve);
#endif

    syscall_regs->syscallno = SAMSUNG_SUCOMPAT_BYPASS_NR;
    ret = ksu_hook_execve(nr, regs);
    syscall_regs->syscallno = syscall_nr;
    return ret;
}

static long __nocfi samsung_sucompat_newfstatat(const struct pt_regs *regs)
{
    struct pt_regs *syscall_regs = (struct pt_regs *)regs;
    int syscall_nr = syscall_regs->syscallno;
    int nr = __NR_newfstatat;
    long ret;

#ifdef CONFIG_COMPAT
    // arm32 has no newfstatat; the equivalent stat-by-fd-and-path is fstatat64.
    if (is_compat_task())
        nr = ksu_get_compat_syscall_no(fstatat64);
#endif

    syscall_regs->syscallno = SAMSUNG_SUCOMPAT_BYPASS_NR;
    ret = ksu_hook_newfstatat(nr, regs);
    syscall_regs->syscallno = syscall_nr;
    return ret;
}

static long __nocfi samsung_sucompat_faccessat(const struct pt_regs *regs)
{
    struct pt_regs *syscall_regs = (struct pt_regs *)regs;
    int syscall_nr = syscall_regs->syscallno;
    int nr = __NR_faccessat;
    long ret;

#ifdef CONFIG_COMPAT
    if (is_compat_task())
        nr = ksu_get_compat_syscall_no(faccessat);
#endif

    syscall_regs->syscallno = SAMSUNG_SUCOMPAT_BYPASS_NR;
    ret = ksu_hook_faccessat(nr, regs);
    syscall_regs->syscallno = syscall_nr;
    return ret;
}

static long __nocfi samsung_sucompat_statx(const struct pt_regs *regs)
{
    struct pt_regs *syscall_regs = (struct pt_regs *)regs;
    int syscall_nr = syscall_regs->syscallno;
    long ret;

    syscall_regs->syscallno = SAMSUNG_SUCOMPAT_BYPASS_NR;
    ret = ksu_hook_newfstatat(__NR_statx, regs);
    syscall_regs->syscallno = syscall_nr;
    return ret;
}

static long __nocfi samsung_sucompat_faccessat2(const struct pt_regs *regs)
{
    struct pt_regs *syscall_regs = (struct pt_regs *)regs;
    int syscall_nr = syscall_regs->syscallno;
    long ret;

    syscall_regs->syscallno = SAMSUNG_SUCOMPAT_BYPASS_NR;
    ret = ksu_hook_faccessat(__NR_faccessat2, regs);
    syscall_regs->syscallno = syscall_nr;
    return ret;
}

static int samsung_sucompat_execve_pre_handler(struct kprobe *probe, struct pt_regs *regs)
{
    if (!samsung_sucompat_should_redirect(__NR_execve))
        return 0;

    instruction_pointer_set(regs, (unsigned long)samsung_sucompat_execve);
    return 1;
}

static int samsung_sucompat_newfstatat_pre_handler(struct kprobe *probe, struct pt_regs *regs)
{
    if (!samsung_sucompat_should_redirect(__NR_newfstatat))
        return 0;

    instruction_pointer_set(regs, (unsigned long)samsung_sucompat_newfstatat);
    return 1;
}

static int samsung_sucompat_faccessat_pre_handler(struct kprobe *probe, struct pt_regs *regs)
{
    if (!samsung_sucompat_should_redirect(__NR_faccessat))
        return 0;

    instruction_pointer_set(regs, (unsigned long)samsung_sucompat_faccessat);
    return 1;
}

static int samsung_sucompat_statx_pre_handler(struct kprobe *probe, struct pt_regs *regs)
{
#ifdef CONFIG_COMPAT
    // statx has no distinct compat number in our resolvable set, and its native
    // and compat table entries share one address. Don't redirect compat tasks
    // here, or ksu_call_syscall() would index the compat table with the native
    // statx number. 32-bit statx runs unmodified.
    if (is_compat_task())
        return 0;
#endif
    if (!samsung_sucompat_should_redirect(__NR_statx))
        return 0;

    instruction_pointer_set(regs, (unsigned long)samsung_sucompat_statx);
    return 1;
}

static int samsung_sucompat_faccessat2_pre_handler(struct kprobe *probe, struct pt_regs *regs)
{
#ifdef CONFIG_COMPAT
    // Same reasoning as statx: leave 32-bit faccessat2 unmodified.
    if (is_compat_task())
        return 0;
#endif
    if (!samsung_sucompat_should_redirect(__NR_faccessat2))
        return 0;

    instruction_pointer_set(regs, (unsigned long)samsung_sucompat_faccessat2);
    return 1;
}

// Native (AArch64) syscall-table kprobes.
static struct kprobe samsung_sucompat_execve_kprobe = {
    .pre_handler = samsung_sucompat_execve_pre_handler,
};

static struct kprobe samsung_sucompat_newfstatat_kprobe = {
    .pre_handler = samsung_sucompat_newfstatat_pre_handler,
};

static struct kprobe samsung_sucompat_faccessat_kprobe = {
    .pre_handler = samsung_sucompat_faccessat_pre_handler,
};

static struct kprobe samsung_sucompat_statx_kprobe = {
    .pre_handler = samsung_sucompat_statx_pre_handler,
};

static struct kprobe samsung_sucompat_faccessat2_kprobe = {
    .pre_handler = samsung_sucompat_faccessat2_pre_handler,
};

#ifdef CONFIG_COMPAT
// Compat (AArch32) syscall-table kprobes. They reuse the native pre_handlers —
// which redirect to the is_compat_task()-aware wrappers — and are only registered
// when the compat table entry differs from the native one (see the init below).
static struct kprobe samsung_sucompat_compat_execve_kprobe = {
    .pre_handler = samsung_sucompat_execve_pre_handler,
};

static struct kprobe samsung_sucompat_compat_fstatat64_kprobe = {
    .pre_handler = samsung_sucompat_newfstatat_pre_handler,
};

static struct kprobe samsung_sucompat_compat_faccessat_kprobe = {
    .pre_handler = samsung_sucompat_faccessat_pre_handler,
};
#endif

// Track which kprobes we actually registered so init rollback and exit can
// unregister exactly that set (the compat ones are conditional).
static struct kprobe *samsung_sucompat_registered[8];
static int samsung_sucompat_registered_count;

static int __init samsung_sucompat_register_probe(struct kprobe *kp, kprobe_opcode_t *addr)
{
    int ret;

    if (!addr)
        return 0;

    kp->addr = addr;
    ret = register_kprobe(kp);
    if (ret)
        return ret;

    samsung_sucompat_registered[samsung_sucompat_registered_count++] = kp;
    return 0;
}

static void samsung_sucompat_unregister_all(void)
{
    while (samsung_sucompat_registered_count > 0)
        unregister_kprobe(samsung_sucompat_registered[--samsung_sucompat_registered_count]);
}

static int __init samsung_sucompat_hook_init(void)
{
    kprobe_opcode_t *execve_addr, *newfstatat_addr, *faccessat_addr, *statx_addr, *faccessat2_addr;
    int ret;

    if (!ksu_syscall_table)
        return -ENOENT;

    samsung_sucompat_registered_count = 0;

    execve_addr = (kprobe_opcode_t *)READ_ONCE(ksu_syscall_table[__NR_execve]);
    newfstatat_addr = (kprobe_opcode_t *)READ_ONCE(ksu_syscall_table[__NR_newfstatat]);
    faccessat_addr = (kprobe_opcode_t *)READ_ONCE(ksu_syscall_table[__NR_faccessat]);
    statx_addr = (kprobe_opcode_t *)READ_ONCE(ksu_syscall_table[__NR_statx]);
    faccessat2_addr = (kprobe_opcode_t *)READ_ONCE(ksu_syscall_table[__NR_faccessat2]);

    ksu_sucompat_init();

    ret = samsung_sucompat_register_probe(&samsung_sucompat_execve_kprobe, execve_addr);
    if (ret)
        goto fail;
    ret = samsung_sucompat_register_probe(&samsung_sucompat_newfstatat_kprobe, newfstatat_addr);
    if (ret)
        goto fail;
    ret = samsung_sucompat_register_probe(&samsung_sucompat_faccessat_kprobe, faccessat_addr);
    if (ret)
        goto fail;
    ret = samsung_sucompat_register_probe(&samsung_sucompat_statx_kprobe, statx_addr);
    if (ret)
        goto fail;
    ret = samsung_sucompat_register_probe(&samsung_sucompat_faccessat2_kprobe, faccessat2_addr);
    if (ret)
        goto fail;

#ifdef CONFIG_COMPAT
    // 32-bit userspace dispatches through compat_sys_call_table. Hook the compat
    // entries for execve / fstatat64 / faccessat, but only when they resolve to a
    // different address than their native counterparts — a shared entry is already
    // covered by the native kprobe above, whose wrapper picks the compat number.
    if (ksu_compat_syscall_table) {
        kprobe_opcode_t *c_execve =
            (kprobe_opcode_t *)READ_ONCE(ksu_compat_syscall_table[ksu_get_compat_syscall_no(execve)]);
        kprobe_opcode_t *c_fstatat64 =
            (kprobe_opcode_t *)READ_ONCE(ksu_compat_syscall_table[ksu_get_compat_syscall_no(fstatat64)]);
        kprobe_opcode_t *c_faccessat =
            (kprobe_opcode_t *)READ_ONCE(ksu_compat_syscall_table[ksu_get_compat_syscall_no(faccessat)]);

        if (c_execve && c_execve != execve_addr) {
            ret = samsung_sucompat_register_probe(&samsung_sucompat_compat_execve_kprobe, c_execve);
            if (ret)
                goto fail;
        }
        if (c_fstatat64 && c_fstatat64 != newfstatat_addr) {
            ret = samsung_sucompat_register_probe(&samsung_sucompat_compat_fstatat64_kprobe, c_fstatat64);
            if (ret)
                goto fail;
        }
        if (c_faccessat && c_faccessat != faccessat_addr) {
            ret = samsung_sucompat_register_probe(&samsung_sucompat_compat_faccessat_kprobe, c_faccessat);
            if (ret)
                goto fail;
        }
    }
#endif

    samsung_sucompat_kprobes_registered = true;
    pr_info("hook_manager: Samsung sucompat kprobes registered (%d probes)\n", samsung_sucompat_registered_count);
    return 0;

fail:
    samsung_sucompat_unregister_all();
    ksu_sucompat_exit();
    return ret;
}

static void __exit samsung_sucompat_hook_exit(void)
{
    if (!samsung_sucompat_kprobes_registered)
        return;

    samsung_sucompat_unregister_all();
    samsung_sucompat_kprobes_registered = false;
    ksu_sucompat_exit();
}

static void setresuid_task_work_func(struct callback_head *callback)
{
    struct ksu_setresuid_task_work *work = container_of(callback, struct ksu_setresuid_task_work, callback);

    // ReSukiSU's ksu_handle_setresuid() takes the raw syscall args; the equivalent
    // uid-transition notification here is ksu_handle_setuid(new_uid, old_uid),
    // matching the LSM setuid hook path.
    ksu_handle_setuid(work->new_uid, work->old_uid);
    kfree(work);
}

static int setresuid_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    *(uid_t *)ri->data = current_uid().val;
    return 0;
}

static int setresuid_return_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct ksu_setresuid_task_work *work;
    uid_t old_uid = *(uid_t *)ri->data;
    uid_t new_uid;

    if (regs_return_value(regs) < 0)
        return 0;

    new_uid = current_uid().val;
    if (old_uid == new_uid)
        return 0;

    work = kzalloc(sizeof(*work), GFP_ATOMIC);
    if (!work)
        return 0;

    work->old_uid = old_uid;
    work->new_uid = new_uid;
    work->callback.func = setresuid_task_work_func;

    if (task_work_add(current, &work->callback, TWA_RESUME))
        kfree(work);

    return 0;
}

static struct kretprobe setresuid_kretprobe = {
    .kp.symbol_name = "__arm64_sys_setresuid",
    .entry_handler = setresuid_entry_handler,
    .handler = setresuid_return_handler,
    .data_size = sizeof(uid_t),
};

#ifdef CONFIG_COMPAT
// 32-bit userspace calls setresuid32; hook it by address only when it resolves to a
// different handler than native setresuid (otherwise the native kretprobe above
// already fires for compat callers). The handlers are ABI-independent (they read
// current_uid() before/after), so they are reused as-is.
static bool setresuid32_kretprobe_registered;
static struct kretprobe setresuid32_kretprobe = {
    .entry_handler = setresuid_entry_handler,
    .handler = setresuid_return_handler,
    .data_size = sizeof(uid_t),
};
#endif

static int __init samsung_setresuid_hook_init(void)
{
    int ret = register_kretprobe(&setresuid_kretprobe);

    if (ret) {
        pr_err("hook_manager: Samsung setresuid kretprobe failed: %d\n", ret);
        return ret;
    }

    setresuid_kretprobe_registered = true;

#ifdef CONFIG_COMPAT
    if (ksu_syscall_table && ksu_compat_syscall_table) {
        kprobe_opcode_t *native = (kprobe_opcode_t *)READ_ONCE(ksu_syscall_table[__NR_setresuid]);
        kprobe_opcode_t *compat =
            (kprobe_opcode_t *)READ_ONCE(ksu_compat_syscall_table[ksu_get_compat_syscall_no(setresuid32)]);

        if (compat && compat != native) {
            setresuid32_kretprobe.kp.addr = compat;
            ret = register_kretprobe(&setresuid32_kretprobe);
            if (ret)
                // Non-fatal: native setresuid tracking still works; only the
                // 32-bit setresuid32 path is left uncovered.
                pr_err("hook_manager: Samsung setresuid32 kretprobe failed: %d\n", ret);
            else
                setresuid32_kretprobe_registered = true;
        }
    }
#endif

    ksu_setuid_hook_init();
    pr_info("hook_manager: Samsung setresuid kretprobe registered\n");
    return 0;
}

static void __exit samsung_setresuid_hook_exit(void)
{
    if (!setresuid_kretprobe_registered)
        return;

#ifdef CONFIG_COMPAT
    if (setresuid32_kretprobe_registered) {
        unregister_kretprobe(&setresuid32_kretprobe);
        setresuid32_kretprobe_registered = false;
    }
#endif
    unregister_kretprobe(&setresuid_kretprobe);
    setresuid_kretprobe_registered = false;
    ksu_setuid_hook_exit();
}
#endif

#ifdef CONFIG_KRETPROBES

static struct kretprobe *init_kretprobe(const char *name, kretprobe_handler_t handler)
{
    struct kretprobe *rp = kzalloc(sizeof(struct kretprobe), GFP_KERNEL);
    if (!rp)
        return NULL;
    rp->kp.symbol_name = name;
    rp->handler = handler;
    rp->data_size = 0;
    rp->maxactive = 0;

    int ret = register_kretprobe(rp);
    pr_info("hook_manager: register_%s kretprobe: %d\n", name, ret);
    if (ret) {
        kfree(rp);
        return NULL;
    }

    return rp;
}

static void destroy_kretprobe(struct kretprobe **rp_ptr)
{
    struct kretprobe *rp = *rp_ptr;
    if (!rp)
        return;
    unregister_kretprobe(rp);
    synchronize_rcu();
    kfree(rp);
    *rp_ptr = NULL;
}

static int syscall_regfunc_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    unsigned long flags;
    ksu_tp_marker_lock(&flags);
    if (ksu_tp_marker_reg_count() < 1) {
        // while install our tracepoint, mark our processes
        ksu_mark_running_process_locked();
    } else if (ksu_tp_marker_reg_count() == 1) {
        // while other tracepoint first added, mark all processes
        ksu_mark_all_process();
    }
    ksu_tp_marker_inc_reg_count();
    ksu_tp_marker_unlock(&flags);
    return 0;
}

static int syscall_unregfunc_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    unsigned long flags;
    ksu_tp_marker_lock(&flags);
    ksu_tp_marker_dec_reg_count();
    if (ksu_tp_marker_reg_count() <= 0) {
        // while no tracepoint left, unmark all processes
        ksu_unmark_all_process();
    } else if (ksu_tp_marker_reg_count() == 1) {
        // while just our tracepoint left, unmark disallowed processes
        ksu_mark_running_process_locked();
    }
    ksu_tp_marker_unlock(&flags);
    return 0;
}

static struct kretprobe *syscall_regfunc_rp = NULL;
static struct kretprobe *syscall_unregfunc_rp = NULL;
#endif

#ifdef CONFIG_HAVE_SYSCALL_TRACEPOINTS
// sys_enter handler: redirect hooked syscalls to the dispatcher
static void ksu_sys_enter_handler(void *data, struct pt_regs *regs, long id)
{
// we need handle arm64 kernel with arm32 userspace
// clang-format off
#ifdef CONFIG_COMPAT
    #if defined(__x86_64__)
        if (unlikely(in_compat_syscall()))
            return;
    #elif defined(__riscv)
        if (unlikely(is_compat_task()))
            return;
    #elif defined(__aarch64__)
        if (unlikely(is_compat_task()))
            goto aarch64_compat;
    #else
        #error Unsupported arch
    #endif
#endif
    // clang-format on

    if (ksu_dispatcher_nr < 0)
        return;

    if (ksu_has_syscall_hook(id)) {
        struct pt_regs *current_regs = task_pt_regs(current);

#if defined(__x86_64__)
        // Stash the original syscall number in ax.
        // We use ax because it currently just holds -ENOSYS and is safe to overwrite.
        current_regs->ax = id;
        current_regs->orig_ax = ksu_dispatcher_nr;
#elif defined(__aarch64__)
        PT_REGS_ORIG_SYSCALL(current_regs) = id;
        current_regs->syscallno = ksu_dispatcher_nr;
#elif defined(__riscv)
        /* orig_a0 retains argument zero; a0 is the -ENOSYS return slot. */
        ksu_riscv_redirect_syscall(current_regs, id, ksu_dispatcher_nr);
#endif
    }

    return;
#if defined(__aarch64__) && defined(CONFIG_COMPAT)
aarch64_compat:
    if (ksu_compat_dispatcher_nr < 0)
        return;

    if (ksu_has_compat_syscall_hook(id)) {
        struct pt_regs *current_regs = task_pt_regs(current);

        /* arm32 syscall numbers are passed in r7, not arm64 x8. */
        PT_REGS_ORIG_SYSCALL(current_regs) = (u32)id;
        current_regs->syscallno = ksu_compat_dispatcher_nr;
    }
#endif
}
#endif

void __init ksu_syscall_hook_manager_init(void)
{
    int ret;
    pr_info("hook_manager: ksu_hook_manager_init called\n");

    if (ksu_dispatcher_nr < 0) {
        pr_warn("hook_manager: dispatcher unavailable; syscall event hooks disabled\n");
#if defined(CONFIG_KSU_SAMSUNG_RKP) && defined(CONFIG_KRETPROBES) && defined(__aarch64__)
        samsung_setresuid_hook_init();
        ret = samsung_sucompat_hook_init();
        if (ret)
            pr_err("hook_manager: Samsung sucompat hook init failed: %d\n", ret);
#endif
        return;
    }

    syscall_hook_manager_initialized = true;

#ifdef CONFIG_KRETPROBES
    syscall_regfunc_rp = init_kretprobe("syscall_regfunc", syscall_regfunc_handler);
    syscall_unregfunc_rp = init_kretprobe("syscall_unregfunc", syscall_unregfunc_handler);
#endif

    // Register syscall hooks via dispatcher
    ksu_register_syscall_hook(__NR_setresuid, ksu_hook_setresuid);
    ksu_register_syscall_hook(__NR_execve, ksu_hook_execve);
    ksu_register_syscall_hook(__NR_execveat, ksu_hook_execveat);
    ksu_register_syscall_hook(__NR_newfstatat, ksu_hook_newfstatat);
    ksu_register_syscall_hook(__NR_faccessat, ksu_hook_faccessat);

#if defined(CONFIG_COMPAT) && defined(__aarch64__)
    ksu_register_compat_syscall_hook(ksu_get_compat_syscall_no(setresuid32), ksu_hook_setresuid);
    ksu_register_compat_syscall_hook(ksu_get_compat_syscall_no(execve), ksu_hook_execve);
    ksu_register_compat_syscall_hook(ksu_get_compat_syscall_no(execveat), ksu_hook_execveat);
    ksu_register_compat_syscall_hook(ksu_get_compat_syscall_no(fstatat64), ksu_hook_newfstatat);
    ksu_register_compat_syscall_hook(ksu_get_compat_syscall_no(faccessat), ksu_hook_faccessat);
#endif

#ifdef CONFIG_HAVE_SYSCALL_TRACEPOINTS
    ret = register_trace_prio_sys_enter(ksu_sys_enter_handler, NULL, INT_MIN);
#ifndef CONFIG_KRETPROBES
    ksu_mark_running_process_locked();
#endif
    if (ret) {
        pr_err("hook_manager: failed to register sys_enter tracepoint: %d\n", ret);
    } else {
        pr_info("hook_manager: sys_enter tracepoint registered\n");
    }
#endif

    ksu_setuid_hook_init();
    ksu_sucompat_init();
}

void __exit ksu_syscall_hook_manager_exit(void)
{
    pr_info("hook_manager: ksu_hook_manager_exit called\n");

    if (!syscall_hook_manager_initialized) {
#if defined(CONFIG_KSU_SAMSUNG_RKP) && defined(CONFIG_KRETPROBES) && defined(__aarch64__)
        samsung_sucompat_hook_exit();
        samsung_setresuid_hook_exit();
#endif
        ksu_syscall_hook_exit();
        return;
    }
#ifdef CONFIG_HAVE_SYSCALL_TRACEPOINTS
    unregister_trace_sys_enter(ksu_sys_enter_handler, NULL);
    tracepoint_synchronize_unregister();
    pr_info("hook_manager: sys_enter tracepoint unregistered\n");
#endif

#ifdef CONFIG_KRETPROBES
    destroy_kretprobe(&syscall_regfunc_rp);
    destroy_kretprobe(&syscall_unregfunc_rp);
#endif

    ksu_unregister_syscall_hook(__NR_setresuid);
    ksu_unregister_syscall_hook(__NR_execve);
    ksu_unregister_syscall_hook(__NR_execveat);
    ksu_unregister_syscall_hook(__NR_newfstatat);
    ksu_unregister_syscall_hook(__NR_faccessat);

#if defined(CONFIG_COMPAT) && defined(__aarch64__)
    ksu_unregister_compat_syscall_hook(ksu_get_compat_syscall_no(setresuid32));
    ksu_unregister_compat_syscall_hook(ksu_get_compat_syscall_no(execve));
    ksu_unregister_compat_syscall_hook(ksu_get_compat_syscall_no(execveat));
    ksu_unregister_compat_syscall_hook(ksu_get_compat_syscall_no(fstatat64));
    ksu_unregister_compat_syscall_hook(ksu_get_compat_syscall_no(faccessat));
#endif

    ksu_syscall_hook_exit();

    ksu_sucompat_exit();
    ksu_setuid_hook_exit();
}
