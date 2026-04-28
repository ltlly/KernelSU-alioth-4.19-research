#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
/* SELinux internals were heavily refactored in 5.7 (selinux_state.policy etc).
 * On 4.19, this whole file is replaced by stubs at the bottom. */
#include "selinux.h"
#include "linux/cred.h"
#include "linux/sched.h"
#include "objsec.h"
#include "linux/version.h"
#include "klog.h" // IWYU pragma: keep
#include "ksu.h"

/*
 * Cached SID values for frequently checked contexts.
 * These are resolved once at init and used for fast u32 comparison
 * instead of expensive string operations on every check.
 *
 * A value of 0 means "no cached SID is available" for that context.
 * This covers both the initial "not yet cached" state and any case
 * where resolving the SID (e.g. via security_secctx_to_secid) failed.
 * In all such cases we intentionally fall back to the slower
 * string-based comparison path; this degrades performance only and
 * does not cause a functional failure.
 */
static u32 cached_su_sid __read_mostly = 0;
static u32 cached_zygote_sid __read_mostly = 0;
static u32 cached_init_sid __read_mostly = 0;
u32 ksu_file_sid __read_mostly = 0;

static int transive_to_domain(const char *domain, struct cred *cred, bool clear_exec_sid)
{
    u32 sid;
    int error;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 18, 0)
    struct task_security_struct *tsec;
#else
    struct cred_security_struct *tsec;
#endif
    tsec = selinux_cred(cred);
    if (!tsec) {
        pr_err("tsec == NULL!\n");
        return -1;
    }
    error = security_secctx_to_secid(domain, strlen(domain), &sid);
    if (error) {
        pr_info("security_secctx_to_secid %s -> sid: %d, error: %d\n", domain, sid, error);
    }
    if (!error) {
        tsec->sid = sid;
        tsec->create_sid = 0;
        tsec->keycreate_sid = 0;
        tsec->sockcreate_sid = 0;
        if (clear_exec_sid) {
            tsec->exec_sid = 0;
        }
    }
    return error;
}

void setup_selinux(const char *domain, struct cred *cred)
{
    if (transive_to_domain(domain, cred, false)) {
        pr_err("transive domain failed.\n");
        return;
    }
}

void setup_ksu_cred(void)
{
    if (ksu_cred && transive_to_domain(KERNEL_SU_CONTEXT, ksu_cred, false)) {
        pr_err("setup ksu cred failed.\n");
    }
}

void setenforce(bool enforce)
{
#ifdef CONFIG_SECURITY_SELINUX_DEVELOP
    selinux_state.enforcing = enforce;
#endif
}

bool getenforce(void)
{
#ifdef CONFIG_SECURITY_SELINUX_DISABLE
    if (selinux_state.disabled) {
        return false;
    }
#endif

#ifdef CONFIG_SECURITY_SELINUX_DEVELOP
    return selinux_state.enforcing;
#else
    return true;
#endif
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 14, 0)
struct lsm_context {
    char *context;
    u32 len;
};

static int __security_secid_to_secctx(u32 secid, struct lsm_context *cp)
{
    return security_secid_to_secctx(secid, &cp->context, &cp->len);
}
static void __security_release_secctx(struct lsm_context *cp)
{
    security_release_secctx(cp->context, cp->len);
}
#else
#define __security_secid_to_secctx security_secid_to_secctx
#define __security_release_secctx security_release_secctx
#endif

/*
 * Initialize cached SID values for frequently checked SELinux contexts.
 * Called once after SELinux policy is loaded (post-fs-data).
 * This eliminates expensive string comparisons in hot paths.
 */
void cache_sid(void)
{
    int err;

    err = security_secctx_to_secid(KERNEL_SU_CONTEXT, strlen(KERNEL_SU_CONTEXT), &cached_su_sid);
    if (err) {
        pr_warn("Failed to cache kernel su domain SID: %d\n", err);
        cached_su_sid = 0;
    } else {
        pr_info("Cached su SID: %u\n", cached_su_sid);
    }

    err = security_secctx_to_secid(ZYGOTE_CONTEXT, strlen(ZYGOTE_CONTEXT), &cached_zygote_sid);
    if (err) {
        pr_warn("Failed to cache zygote SID: %d\n", err);
        cached_zygote_sid = 0;
    } else {
        pr_info("Cached zygote SID: %u\n", cached_zygote_sid);
    }

    err = security_secctx_to_secid(INIT_CONTEXT, strlen(INIT_CONTEXT), &cached_init_sid);
    if (err) {
        pr_warn("Failed to cache init SID: %d\n", err);
        cached_init_sid = 0;
    } else {
        pr_info("Cached init SID: %u\n", cached_init_sid);
    }

    err = security_secctx_to_secid(KSU_FILE_CONTEXT, strlen(KSU_FILE_CONTEXT), &ksu_file_sid);
    if (err) {
        pr_warn("Failed to cache ksu_file SID: %d\n", err);
        ksu_file_sid = 0;
    } else {
        pr_info("Cached ksu_file SID: %u\n", ksu_file_sid);
    }
}

/*
 * Fast path: compare task's SID directly against cached value.
 * Falls back to string comparison if cache is not initialized.
 */
static bool is_sid_match(const struct cred *cred, u32 cached_sid, const char *fallback_context)
{
    if (!cred) {
        return false;
    }
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 18, 0)
    const struct task_security_struct *tsec = selinux_cred(cred);
#else
    const struct cred_security_struct *tsec = selinux_cred(cred);
#endif
    if (!tsec) {
        return false;
    }

    // Fast path: use cached SID if available
    if (likely(cached_sid != 0)) {
        return tsec->sid == cached_sid;
    }

    // Slow path fallback: string comparison (only before cache is initialized)
    struct lsm_context ctx;
    bool result;
    if (__security_secid_to_secctx(tsec->sid, &ctx)) {
        return false;
    }
    result = strncmp(fallback_context, ctx.context, ctx.len) == 0;
    __security_release_secctx(&ctx);
    return result;
}

bool is_task_ksu_domain(const struct cred *cred)
{
    return is_sid_match(cred, cached_su_sid, KERNEL_SU_CONTEXT);
}

bool is_ksu_domain(void)
{
    return is_task_ksu_domain(current_cred());
}

bool is_zygote(const struct cred *cred)
{
    return is_sid_match(cred, cached_zygote_sid, ZYGOTE_CONTEXT);
}

bool is_init(const struct cred *cred)
{
    return is_sid_match(cred, cached_init_sid, INIT_CONTEXT);
}

void escape_to_root_for_adb_root(void)
{
    struct cred *cred = prepare_creds();
    if (!cred) {
        pr_err("Failed to prepare adbd's creds!\n");
        return;
    }

    if (transive_to_domain(KERNEL_SU_CONTEXT, cred, true)) {
        pr_err("transive domain failed.\n");
        abort_creds(cred);
        return;
    }
    commit_creds(cred);
}

#else
/* 4.x SELinux integration: use 4.19's existing APIs.
 *
 * The 5.7+ version of this file uses selinux_state.policy / RCU policy
 * derefs that don't exist on 4.19. But the FUNCTIONAL primitives we
 * actually need (security_secctx_to_secid, enforcing_set, selinux_cred,
 * commit_creds + caps) all work the same on 4.19.
 *
 * Note: ksu_domain SID lookup will fail unless the running SELinux policy
 * actually has "u:r:ksu:s0" defined. For unmodified Android policy this
 * IS NOT the case — so cred SID stays at original value after escalation.
 * Effects:
 *   - uid=0 escalation works (privileged caps granted)
 *   - SELinux DAC checks pass (running as root)
 *   - SELinux MAC checks may still deny if context can't access target
 * Workaround on userdebug ROM: `adb shell setenforce 0`.
 *
 * For unmodified-policy + enforcing scenarios, full functionality requires
 * runtime sepolicy modification (rules.c/sepolicy.c) which is OOS for now.
 */
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/capability.h>
#include "objsec.h"
#include "selinux.h"
#include "klog.h"

extern struct selinux_state selinux_state;
extern const struct cred *ksu_cred;  /* defined in core/init.c */

static u32 cached_su_sid __read_mostly = 0;
static u32 cached_zygote_sid __read_mostly = 0;
static u32 cached_init_sid __read_mostly = 0;
u32 ksu_file_sid __read_mostly = 0;

void cache_sid(void)
{
    int ret;
    ret = security_secctx_to_secid(KERNEL_SU_CONTEXT, strlen(KERNEL_SU_CONTEXT), &cached_su_sid);
    pr_info("cache_sid: ksu sid=%u (rc=%d)\n", cached_su_sid, ret);
    ret = security_secctx_to_secid(ZYGOTE_CONTEXT, strlen(ZYGOTE_CONTEXT), &cached_zygote_sid);
    pr_info("cache_sid: zygote sid=%u (rc=%d)\n", cached_zygote_sid, ret);
    ret = security_secctx_to_secid(INIT_CONTEXT, strlen(INIT_CONTEXT), &cached_init_sid);
    pr_info("cache_sid: init sid=%u (rc=%d)\n", cached_init_sid, ret);
    ret = security_secctx_to_secid(KSU_FILE_CONTEXT, strlen(KSU_FILE_CONTEXT), &ksu_file_sid);
    pr_info("cache_sid: ksu_file sid=%u (rc=%d)\n", ksu_file_sid, ret);
}

void setup_selinux(const char *domain, struct cred *cred)
{
    u32 sid;
    int ret = security_secctx_to_secid(domain, strlen(domain), &sid);
    if (ret == 0 && sid != 0) {
        struct task_security_struct *tsec = selinux_cred(cred);
        tsec->sid = sid;
        tsec->osid = sid;
        tsec->exec_sid = sid;
        pr_info("setup_selinux: set domain=%s sid=%u\n", domain, sid);
    } else {
        pr_warn("setup_selinux: domain=%s lookup failed (rc=%d) — running with original SID\n", domain, ret);
    }
}

void setenforce(bool enforcing)
{
    enforcing_set(&selinux_state, enforcing);
    pr_info("setenforce: %s\n", enforcing ? "enforcing" : "permissive");
}

bool getenforce(void)
{
    return enforcing_enabled(&selinux_state);
}

bool is_task_ksu_domain(const struct cred *cred)
{
    struct task_security_struct *tsec;
    if (cached_su_sid == 0) return false;
    if (!cred) return false;
    tsec = selinux_cred(cred);
    return tsec->sid == cached_su_sid;
}

bool is_ksu_domain(void)
{
    return is_task_ksu_domain(current_cred());
}

bool is_zygote(const struct cred *cred)
{
    struct task_security_struct *tsec;
    if (cached_zygote_sid == 0) return false;
    if (!cred) return false;
    tsec = selinux_cred(cred);
    return tsec->sid == cached_zygote_sid;
}

bool is_init(const struct cred *cred)
{
    struct task_security_struct *tsec;
    if (cached_init_sid == 0) return false;
    if (!cred) return false;
    tsec = selinux_cred(cred);
    return tsec->sid == cached_init_sid;
}

void setup_ksu_cred(void)
{
    /* ksu_cred is the global cred used as override for KSU operations.
     * Set its SID to ksu_domain (if available) so override_creds() places
     * the calling task in ksu domain temporarily. */
    cache_sid();
    if (ksu_cred && cached_su_sid != 0) {
        struct task_security_struct *tsec = selinux_cred((struct cred *)ksu_cred);
        tsec->sid = cached_su_sid;
        tsec->osid = cached_su_sid;
        tsec->exec_sid = cached_su_sid;
        pr_info("setup_ksu_cred: ksu_cred SID set to %u\n", cached_su_sid);
    } else if (ksu_cred) {
        pr_info("setup_ksu_cred: ksu_cred kept at original SID (ksu domain not in policy)\n");
    }
}

void escape_to_root_for_adb_root(void)
{
    struct cred *new = prepare_creds();
    if (!new) {
        pr_err("escape_to_root: prepare_creds failed\n");
        return;
    }

    /* Full uid/gid escalation */
    new->uid.val = new->euid.val = new->fsuid.val = new->suid.val = 0;
    new->gid.val = new->egid.val = new->fsgid.val = new->sgid.val = 0;

    /* Full capability set */
    memset(&new->cap_inheritable, 0xff, sizeof(new->cap_inheritable));
    memset(&new->cap_permitted, 0xff, sizeof(new->cap_permitted));
    memset(&new->cap_effective, 0xff, sizeof(new->cap_effective));
    memset(&new->cap_bset, 0xff, sizeof(new->cap_bset));
    memset(&new->cap_ambient, 0xff, sizeof(new->cap_ambient));

    /* SELinux SID transition (best-effort) */
    if (cached_su_sid != 0) {
        struct task_security_struct *tsec = selinux_cred(new);
        tsec->sid = cached_su_sid;
        tsec->osid = cached_su_sid;
        tsec->exec_sid = cached_su_sid;
    }

    commit_creds(new);
    pr_info("escape_to_root_for_adb_root: done\n");
}
#endif /* >= 5.7 */
