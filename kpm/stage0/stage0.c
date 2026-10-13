/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <common.h>
#include <compiler.h>
#include <kpmodule.h>
#include <kputils.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <syscall.h>
#include <uapi/asm-generic/unistd.h>

#define RTGUM_PAGE_SIZE 4096UL
#define RTGUM_PROT_READ 0x1UL
#define RTGUM_PROT_WRITE 0x2UL
#define RTGUM_MAP_PRIVATE 0x02UL
#define RTGUM_MAP_ANONYMOUS 0x20UL

KPM_NAME("rtgum-stage0");
KPM_VERSION("0.1.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("rt-gum-sdk");
KPM_DESCRIPTION("Stage 0 KernelPatch transport and ordinary anonymous mmap probe");

static long stage0_init(const char *args, const char *event, void *__user reserved)
{
    (void)reserved;
    pr_info("rtgum-stage0: loaded event=%s args=%s kpver=%x kver=%x\n",
            event ? event : "(null)", args ? args : "", kpver, kver);
    return 0;
}

static long copy_reply(char *__user out_msg, int outlen, const char *message)
{
    int length;

    if (!out_msg || outlen <= 0 || !message) return -1;

    length = (int)strnlen(message, (unsigned long)outlen - 1UL) + 1;
    /* KernelPatch returns the number of bytes copied, not zero, on success. */
    if (compat_copy_to_user(out_msg, message, length) <= 0) return -1;
    return 0;
}

static long stage0_control0(const char *args, char *__user out_msg, int outlen)
{
    char reply[160];
    long pid;

    if (!args) return copy_reply(out_msg, outlen, "error=missing-command");

    pid = raw_syscall0(__NR_getpid);

    if (!strcmp(args, "ping")) {
        snprintf(reply, sizeof(reply), "pong pid=%ld kpver=0x%x kver=0x%x", pid, kpver, kver);
        return copy_reply(out_msg, outlen, reply);
    }

    if (!strcmp(args, "alloc")) {
        long address = raw_syscall6(__NR3264_mmap,
                                    0,
                                    RTGUM_PAGE_SIZE,
                                    RTGUM_PROT_READ | RTGUM_PROT_WRITE,
                                    RTGUM_MAP_PRIVATE | RTGUM_MAP_ANONYMOUS,
                                    -1,
                                    0);

        if (address < 0) {
            snprintf(reply, sizeof(reply), "error=mmap-failed errno=%ld pid=%ld", -address, pid);
            return copy_reply(out_msg, outlen, reply);
        }

        snprintf(reply,
                 sizeof(reply),
                 "ok address=0x%lx size=%lu pid=%ld",
                 (unsigned long)address,
                 RTGUM_PAGE_SIZE,
                 pid);
        return copy_reply(out_msg, outlen, reply);
    }

    return copy_reply(out_msg, outlen, "error=unknown-command expected=ping|alloc");
}

static long stage0_exit(void *__user reserved)
{
    (void)reserved;
    pr_info("rtgum-stage0: unloaded\n");
    return 0;
}

KPM_INIT(stage0_init);
KPM_CTL0(stage0_control0);
KPM_EXIT(stage0_exit);
