#ifndef RTGUM_KPM_SUPERCALL_H
#define RTGUM_KPM_SUPERCALL_H

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

/*
 * Userspace-only subset of KernelPatch's SuperCall UAPI.
 *
 * The upstream user/supercall.h currently includes kernel-only ktypes.h,
 * which conflicts with Android libc types. Keep this small ABI mirror pinned
 * to the selected toolchain lock and use upstream headers directly for KPM code.
 */

#ifndef RTGUM_KP_VERSION_MAJOR
#define RTGUM_KP_VERSION_MAJOR 0U
#endif
#ifndef RTGUM_KP_VERSION_MINOR
#define RTGUM_KP_VERSION_MINOR 12U
#endif
#ifndef RTGUM_KP_VERSION_PATCH
#define RTGUM_KP_VERSION_PATCH 2U
#endif
#define RTGUM_KP_VERSION_CODE \
    ((RTGUM_KP_VERSION_MAJOR << 16) | (RTGUM_KP_VERSION_MINOR << 8) | RTGUM_KP_VERSION_PATCH)

#define RTGUM_NR_SUPERCALL 45L
#define RTGUM_SUPERCALL_HELLO 0x1000L
#define RTGUM_SUPERCALL_KERNELPATCH_VER 0x1008L
#define RTGUM_SUPERCALL_KERNEL_VER 0x1009L
#define RTGUM_SUPERCALL_SU 0x1010L
#define RTGUM_SUPERCALL_KPM_LOAD 0x1020L
#define RTGUM_SUPERCALL_KPM_UNLOAD 0x1021L
#define RTGUM_SUPERCALL_KPM_CONTROL 0x1022L
#define RTGUM_SUPERCALL_KPM_NUMS 0x1030L
#define RTGUM_SUPERCALL_KPM_LIST 0x1031L
#define RTGUM_SUPERCALL_KPM_INFO 0x1032L

#define RTGUM_SUPERCALL_HELLO_MAGIC 0x11581158L
#define RTGUM_SUPERCALL_KEY_MAX_LEN 0x40U
#define RTGUM_SUPERCALL_SCONTEXT_LEN 0x60U
#define RTGUM_KPM_LOAD_RESULT_MAGIC 0x4b504d52U
#define RTGUM_KPM_LOAD_ERROR_MESSAGE_LEN 160U

struct rtgum_kpm_load_result {
    unsigned int magic;
    unsigned int size;
    int code;
    char message[RTGUM_KPM_LOAD_ERROR_MESSAGE_LEN];
};

struct rtgum_su_profile {
    uint32_t uid;
    uint32_t to_uid;
    char scontext[RTGUM_SUPERCALL_SCONTEXT_LEN];
};

static inline long rtgum_sc_versioned_command(long command)
{
    return ((long)RTGUM_KP_VERSION_CODE << 32) | (0x1158L << 16) | (command & 0xffffL);
}

static inline long rtgum_sc_hello(const char *key)
{
    if (!key || !key[0]) return -EINVAL;
    return syscall(RTGUM_NR_SUPERCALL, key, rtgum_sc_versioned_command(RTGUM_SUPERCALL_HELLO));
}

static inline uint32_t rtgum_sc_kp_ver(const char *key)
{
    if (!key || !key[0]) return (uint32_t)-EINVAL;
    return (uint32_t)syscall(
        RTGUM_NR_SUPERCALL, key, rtgum_sc_versioned_command(RTGUM_SUPERCALL_KERNELPATCH_VER));
}

static inline uint32_t rtgum_sc_k_ver(const char *key)
{
    if (!key || !key[0]) return (uint32_t)-EINVAL;
    return (uint32_t)syscall(
        RTGUM_NR_SUPERCALL, key, rtgum_sc_versioned_command(RTGUM_SUPERCALL_KERNEL_VER));
}

static inline long rtgum_sc_su(const char *key, struct rtgum_su_profile *profile)
{
    if (!key || !key[0] || !profile) return -EINVAL;
    return syscall(RTGUM_NR_SUPERCALL,
                   key,
                   rtgum_sc_versioned_command(RTGUM_SUPERCALL_SU),
                   profile);
}

static inline long rtgum_sc_kpm_load(
    const char *key, const char *path, const char *args, struct rtgum_kpm_load_result *result)
{
    if (!key || !key[0] || !path || !path[0]) return -EINVAL;
    return syscall(RTGUM_NR_SUPERCALL,
                   key,
                   rtgum_sc_versioned_command(RTGUM_SUPERCALL_KPM_LOAD),
                   path,
                   args,
                   result);
}

static inline long rtgum_sc_kpm_control(
    const char *key, const char *name, const char *args, char *output, long output_size)
{
    if (!key || !key[0] || !name || !name[0] || !args || !args[0]) return -EINVAL;
    return syscall(RTGUM_NR_SUPERCALL,
                   key,
                   rtgum_sc_versioned_command(RTGUM_SUPERCALL_KPM_CONTROL),
                   name,
                   args,
                   output,
                   output_size);
}

static inline long rtgum_sc_kpm_unload(const char *key, const char *name)
{
    if (!key || !key[0] || !name || !name[0]) return -EINVAL;
    return syscall(RTGUM_NR_SUPERCALL,
                   key,
                   rtgum_sc_versioned_command(RTGUM_SUPERCALL_KPM_UNLOAD),
                   name,
                   NULL);
}

static inline long rtgum_sc_kpm_nums(const char *key)
{
    if (!key || !key[0]) return -EINVAL;
    return syscall(RTGUM_NR_SUPERCALL, key, rtgum_sc_versioned_command(RTGUM_SUPERCALL_KPM_NUMS));
}

static inline long rtgum_sc_kpm_list(const char *key, char *output, int output_size)
{
    if (!key || !key[0] || !output || output_size <= 0) return -EINVAL;
    return syscall(RTGUM_NR_SUPERCALL,
                   key,
                   rtgum_sc_versioned_command(RTGUM_SUPERCALL_KPM_LIST),
                   output,
                   output_size);
}

static inline long rtgum_sc_kpm_info(const char *key, const char *name, char *output, int output_size)
{
    if (!key || !key[0] || !name || !name[0] || !output || output_size <= 0) return -EINVAL;
    return syscall(RTGUM_NR_SUPERCALL,
                   key,
                   rtgum_sc_versioned_command(RTGUM_SUPERCALL_KPM_INFO),
                   name,
                   output,
                   output_size);
}

#endif
