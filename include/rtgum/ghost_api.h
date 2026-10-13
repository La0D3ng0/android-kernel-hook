/*
 * rt-gum-sdk ghost ABI: shared between the stage-2 Daemon, user modules
 * (.ghm), and the KPM. This header must stay declaration-only: user modules
 * include it and receive a ready-made GhostApi* instead of linking anything.
 */

#ifndef RTGUM_GHOST_API_H
#define RTGUM_GHOST_API_H

#include "rtgum/host_api_v2.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RTGUM_GHOST_API_VERSION 1UL

/* Daemon channel on arm64 membarrier (283). Android app seccomp allows this
 * syscall, and the KPM must pass every unauthenticated or unknown call to the
 * original implementation. This number is device-specific. Ops are
 * authenticated with the 32-byte session key split into four words:
 *   syscall(nr, op, a1, s0, s1, s2, s3)
 * where s0..s3 hold session bytes 0..7, 8..15, 16..23, 24..31 (little-endian).
 * String replies (module link/ifunc enumeration) are written by the KPM into
 * the daemon bootstrap context payload (RTGUM_CTX_PAYLOAD). */
#define RTGUM_DAEMON_SYSCALL 283L

#define RTGUM_DAEMON_OP_CALIBRATE 0L /* authenticated channel probe */
#define RTGUM_DAEMON_OP_LOG 1L /* a1 = text pointer */
#define RTGUM_DAEMON_OP_CMDLINE 2L /* legacy kernel path; GhostApi reads /proc/self */
#define RTGUM_DAEMON_OP_MODULE_LINK 3L /* a1 = path; reply in ctx payload */
#define RTGUM_DAEMON_OP_MODULE_RESOLVE 4L /* a1 = base; returns remaining */
#define RTGUM_DAEMON_OP_MODULE_IFUNC_NEXT 5L /* a1 = base; reply in ctx payload */
#define RTGUM_DAEMON_OP_MODULE_IFUNC_COMMIT 6L /* a1 = base; {token,target} in ctx payload */
#define RTGUM_DAEMON_OP_MODULE_ENTRY 7L /* a1 = base; returns ghostEntry address */
#define RTGUM_DAEMON_OP_MODULE_UNLINK 8L /* a1 = base; returns status */
#define RTGUM_DAEMON_OP_GHOST_ALLOC 9L /* a1 = (size << 3) | protection */
#define RTGUM_DAEMON_OP_GHOST_PROTECT 10L /* a1 = page-aligned address | (prot & 7) */
#define RTGUM_DAEMON_OP_GHOST_FREE 11L /* a1 = address */
#define RTGUM_DAEMON_OP_MODULE_UNLOAD_ENTRY 12L /* a1 = base; returns optional callback */

/* ART data-page shadowing (Shadow Data Page). The page stays owned by its
 * original VMA; the KPM installs a blocked PTE (EL0 no-access, PFN still the
 * original page), keeps a private tampered copy, and serves reads per caller
 * identity on DABT. Payload layout (ctx payload, little-endian u64s):
 *   ART_PAGE_REGISTER:   {page_va, 0}          -> returns 0 or -errno
 *   ART_PAGE_UNREGISTER: a1 = page_va          -> returns 0 or -errno
 *   ART_PAGE_PATCH:      {page_va, offset, value} -> returns 0 or -errno
 *   ART_PAGE_READ:       {page_va, offset}     -> u64 result written to payload
 *   ART_PAGE_UNPATCH:    {page_va, offset}     -> restore latest clean word
 *   ART_TRUST_ADD:       {start, end}          -> returns 0 or -errno
 *   ART_TRUST_CLEAR:     (no payload)          -> returns 0
 *   MODULE_SYMBOL:       a1 = base, payload = symbol name -> u64 address in payload
 */
#define RTGUM_DAEMON_OP_ART_PAGE_REGISTER 13L
#define RTGUM_DAEMON_OP_ART_PAGE_UNREGISTER 14L
#define RTGUM_DAEMON_OP_ART_PAGE_PATCH 15L
#define RTGUM_DAEMON_OP_ART_PAGE_READ 16L
#define RTGUM_DAEMON_OP_ART_TRUST_ADD 17L
#define RTGUM_DAEMON_OP_ART_TRUST_CLEAR 18L
#define RTGUM_DAEMON_OP_MODULE_SYMBOL 19L
#define RTGUM_DAEMON_OP_ART_SHADOW_QUERY 20L /* returns 1 when DABT hooks are live */
#define RTGUM_DAEMON_OP_ART_PAGE_UNPATCH 21L
/* Symbol resolver transport.  These operations expose only read-only process
 * metadata to the authenticated Daemon; all ELF interpretation stays in user
 * mode inside the Daemon.
 *
 * VMA_SNAPSHOT payload: {u64 output, u64 capacity_records}; result=count.
 * MEMORY_READ payload:  {u64 source, u64 output, u64 length}; max 4096.
 * MODULE_FILE_SIZE:      a1=ghost image base; result=original ELF byte size.
 * MODULE_FILE_COPY payload: {u64 base, u64 output, u64 length}; whole image.
 */
#define RTGUM_DAEMON_OP_VMA_SNAPSHOT 22L
#define RTGUM_DAEMON_OP_MEMORY_READ 23L
#define RTGUM_DAEMON_OP_MODULE_FILE_SIZE 24L
#define RTGUM_DAEMON_OP_MODULE_FILE_COPY 25L
/* Contiguous multi-chunk ghost span used by the Daemon's in-memory DEX
 * runtime. GHOST_ALLOC_SPAN has the same packed size/protection argument as
 * GHOST_ALLOC, but may span several allocator records (up to the linker's
 * 16 MiB image limit). GHOST_FREE_SPAN packs (page_count - 1) into the low
 * 12 address bits, so freeing never races another user of the shared context
 * payload page. These are Daemon/KPM transport operations, not new GhostApi
 * v1 fields. */
#define RTGUM_DAEMON_OP_GHOST_ALLOC_SPAN 26L
#define RTGUM_DAEMON_OP_GHOST_FREE_SPAN 27L
/* Code Shadow Page replacement channel.  The request lives in the Daemon
 * context payload so patch bytes never cross through /proc or ptrace:
 *
 *   SHADOW_CODE_PATCH:   { target, length, fork_propagate, bytes[32] }
 *   SHADOW_CODE_UNPATCH: { target, length }
 *   SHADOW_CODE_QUERY:   { target, length }, returns 1 while active
 *
 * A request is scoped to the authenticated caller's mm.  The KPM keeps the
 * original PFN clean and only writes the private execute view.
 */
#define RTGUM_DAEMON_OP_SHADOW_CODE_PATCH 28L
#define RTGUM_DAEMON_OP_SHADOW_CODE_UNPATCH 29L
#define RTGUM_DAEMON_OP_SHADOW_CODE_QUERY 30L
/* Authenticated code commit into an existing ghost allocation. `a1` points to
 * RtGumGhostCodeWriteRequest in the caller. The KPM copies at most one Mako
 * trampoline, writes through its kernel alias even when the user PTE is RX,
 * then flushes every touched pool page as a page-aligned range. */
#define RTGUM_DAEMON_OP_GHOST_CODE_WRITE 31L
#define RTGUM_GHOST_CODE_WRITE_MAX 512UL

/* VMA-less allocation constrained to a GumAddressSpec window. `a1` points to
 * this request in the authenticated Daemon. The result is the allocated user
 * VA, or a negative errno. */
#define RTGUM_DAEMON_OP_GHOST_ALLOC_NEAR_SPAN 32L

/* Fork propagation is an explicit property of VMA-less allocations and
 * linker images.  A code patch must never be inherited without every ghost
 * target it can branch to.  GHOST_FORK_POLICY takes the request below;
 * MODULE_FORK_POLICY packs the boolean in bit 0 of a page-aligned image base. */
#define RTGUM_DAEMON_OP_GHOST_FORK_POLICY 33L
#define RTGUM_DAEMON_OP_MODULE_FORK_POLICY 34L
#define RTGUM_DAEMON_OP_MEMORY_WRITE 35L

struct RtGumGhostAllocNearRequest {
    unsigned long size;
    unsigned long alignment;
    unsigned long protection;
    unsigned long near_address;
    unsigned long max_distance;
};

struct RtGumGhostForkPolicyRequest {
    unsigned long address;
    unsigned long span_size;
    unsigned long propagate;
};

struct RtGumGhostCodeWriteRequest {
    unsigned long target;
    unsigned long source;
    unsigned long length;
};

/* Context payload area is shared between the KPM replies and the daemon's
 * per-command input strings. */
#define RTGUM_DAEMON_REPLY_CAPACITY 192UL

/* Dispatch commands written by the KPM into the bootstrap context. */
#define RTGUM_DAEMON_CMD_INIT 0UL
#define RTGUM_DAEMON_CMD_FORK_CHILD 1UL
#define RTGUM_DAEMON_CMD_PACKAGE 2UL
#define RTGUM_DAEMON_CMD_RELOAD 3UL
#define RTGUM_DAEMON_CMD_SHUTDOWN 4UL

/* Status word indexes inside rtgum_stage2_daemon_status[8].  The last three
 * words are published by lazy runtime backends so the controller can verify
 * their actual image addresses against /proc/<pid>/{maps,smaps}. */
#define RTGUM_DAEMON_STATUS_PHASE 0U
#define RTGUM_DAEMON_STATUS_MODULES 1U
#define RTGUM_DAEMON_STATUS_EXTRA 2U
#define RTGUM_DAEMON_STATUS_MAGIC 3U
#define RTGUM_DAEMON_STATUS_MODULE_BASE 4U
#define RTGUM_DAEMON_STATUS_GUM_BASE 5U
#define RTGUM_DAEMON_STATUS_LUA_BASE 6U
#define RTGUM_DAEMON_STATUS_BACKEND_FLAGS 7U

/* RTGUM_DAEMON_STATUS_BACKEND_FLAGS bits. */
#define RTGUM_DAEMON_BACKEND_GUM_GHOST (1UL << 0)
#define RTGUM_DAEMON_BACKEND_LUA_GHOST (1UL << 1)
#define RTGUM_DAEMON_BACKEND_GUM_ALLOCATIONS_GHOST (1UL << 2)

/* Phase values written by the Daemon. */
#define RTGUM_DAEMON_PHASE_NONE 0UL
#define RTGUM_DAEMON_PHASE_INIT 1UL
#define RTGUM_DAEMON_PHASE_FORK 2UL
#define RTGUM_DAEMON_PHASE_MODULE 3UL
#define RTGUM_DAEMON_PHASE_RELOADED 4UL
#define RTGUM_DAEMON_PHASE_SHUTDOWN 6UL

#define RTGUM_DAEMON_MAGIC 0x4441454d4f4e3230UL /* "DAEMON20" */
#define RTGUM_DAEMON_IFUNC_MAGIC 0x1234UL

/*
 * Bootstrap context layout (kernel-written, in the Daemon's RW data page).
 * The trampoline receives a pointer to this structure in x0.
 */
#define RTGUM_CTX_RESUME_PC 0x00UL
#define RTGUM_CTX_DISPATCH 0x08UL
#define RTGUM_CTX_CMD 0x10UL
#define RTGUM_CTX_ARG 0x18UL
#define RTGUM_CTX_FIXUP 0x20UL
#define RTGUM_CTX_SESSION 0x28UL
#define RTGUM_CTX_STATUS 0x48UL
#define RTGUM_CTX_API 0x50UL
#define RTGUM_CTX_SAVED 0x58UL /* 21 registers * 8 bytes */
#define RTGUM_CTX_PAYLOAD 0x100UL
/* Trampoline callee-saved area occupies 0x200..0x250. The following legacy
 * cmdline reply slot is unused by the Pixel 8 Daemon's user-mode reader. */
#define RTGUM_CTX_CMDLINE 0x250UL
#define RTGUM_CTX_CMDLINE_SIZE 176UL
#define RTGUM_CTX_FIXUP_TABLE 0x300UL
/* FP/SIMD restore area ends at 0xC10. The next four words carry the
 * Android arm64 IFUNC resolver ABI for the kernel-generated bootstrap. */
#define RTGUM_CTX_IFUNC_ARG 0xC10UL
#define RTGUM_CTX_IFUNC_FIRST_ARG 0xC28UL
#define RTGUM_CTX_SIZE 0x1000UL

/* One bootstrap IFUNC fixup record: resolver | slot_va | addend. */
#define RTGUM_CTX_FIXUP_RECORD_SIZE 24UL

/*
 * The interface passed to user modules. Core callbacks reside in the Daemon;
 * optional HostApiV2 helpers may be loaded by the Android system linker and
 * can have ordinary process mappings.
 */
struct GhostApi {
    unsigned long version;
    unsigned long reserved;
    long (*log)(const char *text); /* KPM printk channel */
    long (*cmdline)(char *out, unsigned long capacity); /* /proc/self/cmdline */
    long (*status)(unsigned int index, unsigned long value); /* local status word */
    long (*module_load)(const char *path,
                        unsigned long *out_base,
                        unsigned long *out_entry,
                        unsigned long *out_size);
    long (*module_unload)(unsigned long base);
    long (*ghost_alloc)(unsigned long size, unsigned int protection, unsigned long *out_address);
    long (*ghost_protect)(unsigned long address, unsigned int protection);
    long (*ghost_free)(unsigned long address);
    void (*exit)(int code);
    /* v1 modules must not read this field. v2 modules check host->version
     * and host->size before calling any function pointer. */
    const struct HostApiV2 *host;
};

typedef void (*GhostEntry)(struct GhostApi *api);
typedef void (*GhostModuleUnload)(struct GhostApi *api);

#ifdef __cplusplus
}
#endif

#endif /* RTGUM_GHOST_API_H */
