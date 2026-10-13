/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Read-only architecture and kernel-symbol probe for Pixel 8 Stage 1. */

#include <common.h>
#include <kallsyms.h>
#include <kpmodule.h>
#include <kputils.h>
#include <linux/kernel.h>
#include <linux/mm_types.h>
#include <linux/string.h>

extern int thread_size;

KPM_NAME("rtgum-stage1-probe");
KPM_VERSION("0.1.3");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("rt-gum-sdk");
KPM_DESCRIPTION("Read-only Pixel 8 Stage 1 architecture and symbol probe");

/* The bit index of each result is its position in this array. */
static const char *const required_symbols[] = {
    "__get_free_pages", "free_pages", "get_task_mm", "mmput",
    "get_unmapped_area", "find_vma", "__pmd_alloc", "__pte_alloc",
    "mmap_region", "copy_process", "exit_mmap", "__sync_icache_dcache",
    "__flush_icache_range", "memstart_addr", "on_each_cpu", "kernel_read",
    "vmalloc", "vfree", "filp_open", "filp_close", "vfs_llseek",
    "get_random_bytes", "task_work_add", "task_work_cancel",
    "wake_up_process", "__set_task_comm", "sys_ni_syscall",
    "get_user_pages_remote", "__put_page",
    "find_get_task_by_vpid", "find_task_by_vpid", "flush_icache_range",
    "__get_task_comm", "set_task_comm", "init_cred", "override_creds",
    "revert_creds", "do_sys_poll", "sys_epoll_wait", "__kernel_write",
    "vfs_fsync", "put_page",
    "flush_tlb_page", "__flush_tlb_range", "smp_call_function",
    "smp_call_function_many", "on_each_cpu_mask", "flush_tlb_mm",
    "flush_tlb_mm_range", "flush_tlb_all", "__flush_dcache_area",
    "__flush_icache_all", "__flush_cache_user_range", "flush_cache_all",
    "copy_page_range", "dup_mmap", "__put_task_struct",
};

static unsigned long long symbol_mask(void)
{
    unsigned long long mask = 0;
    unsigned int index;

    for (index = 0; index < sizeof(required_symbols) / sizeof(required_symbols[0]); ++index) {
        if (kallsyms_lookup_name(required_symbols[index])) mask |= 1ULL << index;
    }
    return mask;
}

static long probe_init(const char *args, const char *event, void *__user reserved)
{
    (void)args;
    (void)event;
    (void)reserved;
    return 0;
}

static long probe_control(const char *args, char *__user output, int output_length)
{
    unsigned long long tcr, mmfr1, sctlr, mair, mpidr;
    unsigned int tg0, shift, va_bits, levels, pan, epan;
    unsigned long long mask;
    char reply[320];
    int length;

    if (!args || strcmp(args, "probe") || !output || output_length <= 0) return -1;

    asm volatile("mrs %0, tcr_el1" : "=r"(tcr));
    asm volatile("mrs %0, id_aa64mmfr1_el1" : "=r"(mmfr1));
    asm volatile("mrs %0, sctlr_el1" : "=r"(sctlr));
    asm volatile("mrs %0, mair_el1" : "=r"(mair));
    asm volatile("mrs %0, mpidr_el1" : "=r"(mpidr));

    tg0 = (unsigned int)((tcr >> 14U) & 3U);
    shift = tg0 == 0U ? 12U : (tg0 == 2U ? 14U : (tg0 == 1U ? 16U : 0U));
    va_bits = 64U - (unsigned int)(tcr & 63U);
    levels = shift == 12U && va_bits > 12U ? (va_bits - 12U + 8U) / 9U : 0U;
    pan = (unsigned int)((mmfr1 >> 20U) & 15U);
    epan = (unsigned int)((sctlr >> 57U) & 1U);
    mask = symbol_mask();

    length = snprintf(reply, sizeof(reply),
                      "mpidr=0x%llx tcr=0x%llx mmfr1=0x%llx sctlr=0x%llx mair=0x%llx "
                      "tg0=%u page_shift=%u va_bits=%u levels=%u pan=%u epan=%u "
                      "pgd_offset=%d thread_size=%d symbols=0x%llx",
                      mpidr, tcr, mmfr1, sctlr, mair, tg0, shift, va_bits, levels,
                      pan, epan, (int)mm_struct_offset.pgd_offset, thread_size, mask);
    if (length < 0 || length >= (int)sizeof(reply) || length + 1 > output_length) return -1;
    if (compat_copy_to_user(output, reply, length + 1) != length + 1) return -1;
    return 0;
}

static long probe_exit(void *__user reserved)
{
    (void)reserved;
    return 0;
}

KPM_INIT(probe_init);
KPM_CTL0(probe_control);
KPM_EXIT(probe_exit);
