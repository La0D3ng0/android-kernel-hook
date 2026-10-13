/*
 * rt-gum-sdk Gum ghost-backend ABI.
 *
 * Shared between the stage-2 Daemon (which ghost-loads librtgum-gum-ghost.so
 * through the KPM's private linker) and the Gum backend image itself. The
 * backend is compiled against the Frida Gum devkit (libfrida-gum.a) and keeps
 * the declaration-only contract of the other ghost images: the host passes a
 * function table in, the backend passes its own table out.
 */

#ifndef RTGUM_GUM_API_H
#define RTGUM_GUM_API_H

#include "rtgum/host_api_v2.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RTGUM_GUM_API_VERSION 12UL

/* RtGumHost::reserved capability bits. The backend copies the host table at
 * bind time because Gum owns asynchronous worker threads. Memory
 * interposition is opt-in: a platform-dlopen backend must not call through a
 * VMA-less Daemon table merely to discover that ghost memory is disabled. */
#define RTGUM_GUM_HOST_GHOST_MEMORY (1UL << 0)

/* A Stalker session belongs to the calling thread. Statistics retain only
 * counters and page offsets; no full code address leaves the process. The
 * caller keeps this record alive until stalker_stop returns. */
struct RtGumStalkerStats {
    unsigned long blocks;
    unsigned long calls;
    unsigned long returns;
    unsigned long compiled;
    unsigned long matched_returns;
    unsigned long mismatched_returns;
    unsigned long unpaired_returns;
    unsigned long unwound_frames;
    unsigned long shadow_overflow;
    unsigned long pac_checks;
    unsigned long bti_checks;
    unsigned long bti_guarded;
    unsigned long bti_rejected;
    /* First four unmatched returns, with only page offsets retained. */
    struct {
        unsigned short call_offset;
        unsigned short ret_offset;
        unsigned short expected_offset;
        unsigned short actual_offset;
        int call_depth;
        int ret_depth;
    } mismatch_samples[4];
    unsigned long mismatch_samples_used;
    /* Watched call frames still pending when stalker_stop returns. */
    unsigned long shadow_remaining;
    /* Optional caller-owned GTrace ring.  Set buffer/capacity before start;
     * old callers leave both zero and pay no per-instruction callout cost.
     * stop() rotates a wrapped ring into chronological order, so [0,count)
     * can be passed directly to HostApiV2.gtrace_format_path. */
    struct RtGumGtraceStep *gtrace_buffer;
    unsigned long gtrace_capacity;
    unsigned long gtrace_count;
    unsigned long gtrace_head;
    unsigned long gtrace_total;
    unsigned long gtrace_dropped;
};

/* Marshaled Interceptor invocation: register arguments and return value of
 * the hooked call. context is the raw GumCpuContext* (opaque to the module). */
struct RtGumInvocation {
    unsigned long context;
    unsigned long function;
    unsigned long args[8];
    unsigned long return_value;
    unsigned int system_error;
    unsigned int reserved;
};

/* Provided by the Daemon. ghost_* route allocations through the KPM's
 * VMA-less allocator so Gum's code/data pages stay out of /proc/maps. */
struct RtGumHost {
    unsigned long version;
    unsigned long reserved; /* RTGUM_GUM_HOST_* capability bits */
    long (*log)(const char *text);
    long (*ghost_alloc)(unsigned long size,
                        unsigned int protection,
                        unsigned long *out_address);
    long (*ghost_protect)(unsigned long address, unsigned int protection);
    long (*ghost_free)(unsigned long address);
    long (*sleep_ms)(unsigned int milliseconds);
    /* Size-aware variants preserve ownership across the allocator's 512 KiB
     * chunk boundary.  Gum's mmap interposer prefers these callbacks and
     * retains the returned span size until munmap. */
    long (*ghost_alloc_span)(unsigned long size,
                             unsigned int protection,
                             unsigned long *out_address,
                             unsigned long *out_span_size);
    long (*ghost_protect_span)(unsigned long address,
                               unsigned long span_size,
                               unsigned int protection);
    long (*ghost_free_span)(unsigned long address, unsigned long span_size);
    /* ARM64 Interceptor/Stalker code must be placed inside the branch window
     * supplied by GumAddressSpec. The KPM chooses a VMA-less hole in that
     * window and returns an independently owned span. */
    long (*ghost_alloc_near_span)(unsigned long size,
                                  unsigned long alignment,
                                  unsigned int protection,
                                  unsigned long near_address,
                                  unsigned long max_distance,
                                  unsigned long *out_address,
                                  unsigned long *out_span_size);
    /* Code-page writes are kept out of mprotect(2).  Gum builds the new
     * contents in a private RW ghost span, then commits only changed ARM64
     * instruction ranges through one of these kernel-backed paths. */
    long (*code_read_clean)(unsigned long address,
                            void *buffer,
                            unsigned long length);
    long (*ghost_code_write)(unsigned long address,
                             const void *bytes,
                             unsigned long length);
    long (*shadow_code_patch)(unsigned long address,
                              const void *bytes,
                              unsigned long length);
    long (*shadow_code_unpatch)(unsigned long address,
                                unsigned long length);
    /* Resolver and guarded memory access supplied by the Daemon.  These are
     * appended so the backend can resolve VMA-less images and report bad
     * addresses as errors instead of directly faulting in the target. */
    long (*find_export)(const char *soname,
                        const char *symbol,
                        unsigned long *out_address);
    long (*memory_read)(unsigned long address,
                        void *buffer,
                        unsigned long length);
    long (*memory_write)(unsigned long address,
                         const void *buffer,
                         unsigned long length);
};

/* Implemented by librtgum-gum-ghost.so. */
struct RtGumApi {
    unsigned long version;
    unsigned long reserved;
    long (*find_export)(const char *soname,
                        const char *symbol,
                        unsigned long *out_address);
    long (*intercept_attach)(const char *soname,
                             const char *symbol,
                             void (*on_enter)(struct RtGumInvocation *invocation,
                                              void *user_data),
                             void (*on_leave)(struct RtGumInvocation *invocation,
                                              void *user_data),
                             void *user_data,
                             unsigned long *out_handle);
    long (*intercept_attach_address)(unsigned long address,
                                     void (*on_enter)(struct RtGumInvocation *invocation,
                                                      void *user_data),
                                     void (*on_leave)(struct RtGumInvocation *invocation,
                                                      void *user_data),
                                     void *user_data,
                                     unsigned long *out_handle);
    long (*intercept_revert)(unsigned long handle);
    long (*replace)(unsigned long target,
                    unsigned long replacement,
                    unsigned long *out_original,
                    unsigned long *out_handle);
    long (*memory_read)(unsigned long address, void *buffer, unsigned long length);
    long (*memory_write)(unsigned long address, const void *buffer, unsigned long length);
    long (*memory_alloc)(unsigned long size, unsigned long *out_address);
    long (*memory_free)(unsigned long address);
    long (*stalker_start)(struct RtGumStalkerStats *stats,
                          unsigned long watched_start,
                          unsigned long watched_size);
    long (*stalker_invalidate)(unsigned long address);
    long (*stalker_stop)(void);
    long (*trace_start)(const struct RtGumTraceConfig *config,
                        unsigned long *out_handle);
    long (*trace_stop)(unsigned long handle);
    long (*trace_query)(unsigned long handle,
                        struct RtGumTraceStats *out_stats);
};

typedef long (*RtGumEntry)(const struct RtGumHost *host, struct RtGumApi *out_api);

#ifdef __cplusplus
}
#endif

#endif /* RTGUM_GUM_API_H */
