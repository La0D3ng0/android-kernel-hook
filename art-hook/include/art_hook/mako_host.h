// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#pragma once

// Declaration-only binding surface between the ghost-loaded Mako SO and its
// host (the stage-2 Daemon). Mako is a standalone SHARED library that is
// lazily linked into ghost memory by the KPM on the Daemon's first artHook
// call; it never links the Daemon and never statically imports SDK code.
//
// The Daemon fills a MakoHostApi with function pointers (all of which proxy
// the authenticated daemon syscall) and calls rtgum_mako_entry. Mako fills
// MakoHookApi with its hook/revert entry points, which the Daemon publishes
// through HostApiV2.art_hook_*.
//
// Pointer ABI rules mirror ghost_api.h: no struct version mixing without a
// version/size check. Both sides compile the header from this single source.

#ifdef __cplusplus
extern "C" {
#endif

#define MAKO_HOST_API_VERSION 6UL
#define MAKO_HOOK_API_VERSION 5UL
#define MAKO_REFLECTION_CACHE_VERSION 1UL

/* Values reported by MakoHookApi.probe_id. They mirror the classification in
 * art_hook/art_probe.h so a caller can act on the mode without re-deriving it. */
#define MAKO_JNI_ID_NULL 0U
#define MAKO_JNI_ID_POINTER 1U          /* the id is the ArtMethod* itself */
#define MAKO_JNI_ID_INDEX 2U            /* the id is a table token */
#define MAKO_JNI_ID_SWAPABLE_POINTER 3U /* the id indexes a runtime-owned table */
#define MAKO_JNI_ID_UNRESOLVED 4U       /* nothing could be proven about it */

/* probe_id status codes. A negative value is a failure; the mode word alone is
 * informational, because an unresolved id is a normal outcome on a runtime
 * whose decode path is not exported. */
#define MAKO_ID_OK 0L
#define MAKO_ID_ERR_REJECTED (-10L)  /* not a usable id (null, or malformed) */
#define MAKO_ID_ERR_UNSUPPORTED (-11L) /* index mode: address needs the runtime */

/* Raw ARM64 quick-ABI callback. `context` points to an Arm64CpuContext; the
 * callback must be noexcept and must not let exceptions cross it. on_leave may
 * rewrite context->x[0] (the return value). */
typedef void (*MakoArtCallback)(void *context, void *user_data);

/* Method IDs resolved once by the Daemon on the Zygote INIT path. They are
 * process-local ART handles and are only consumed by children of that same
 * JavaVM after fork. No jobject/global-reference ownership crosses this ABI,
 * so daemon hot replacement has no JNI reference to release. */
struct MakoReflectionCache {
  unsigned long version;
  unsigned long size;
  void *object_hash_code;
  void *method_get_return_type;
  void *method_get_parameter_types;
  void *class_get_name;
};

/* Capabilities supplied by the host. Every pointer is valid before
 * rtgum_mako_entry returns. */
struct MakoHostApi {
  unsigned long version;
  unsigned long size;
  long (*log)(const char *text);
  /* VMA-less ghost allocations for the jump pool. W+X combinations are
   * rejected by the kernel side, so allocators allocate RW and switch to RX
   * via ghost_protect once the code bytes are written. */
  long (*ghost_alloc)(unsigned long size, unsigned int protection,
                      unsigned long *out_address);
  long (*ghost_free)(unsigned long address);
  long (*ghost_protect)(unsigned long address, unsigned int protection);
  /* Commit generated code through the KPM-owned kernel alias. This remains
   * writable after a shared jump-pool page has been sealed RX and performs a
   * page-aligned D/I cache flush for every touched pool page. */
  long (*ghost_code_write)(unsigned long address, const void *bytes,
                           unsigned long length);
  /* Shadow Data Page ops. page must be the page-aligned VA of the ArtMethod
   * page; patch/read operate on the tampered (trusted) copy. */
  long (*art_page_register)(unsigned long page, unsigned long *out_handle);
  long (*art_page_unregister)(unsigned long page);
  long (*art_page_patch)(unsigned long page, unsigned long offset,
                         unsigned long value);
  /* Restore one patched word from the continuously maintained clean page and
   * clear its hook mask. */
  long (*art_page_unpatch)(unsigned long page, unsigned long offset);
  long (*art_page_read)(unsigned long page, unsigned long offset,
                        unsigned long *out_value);
  /* ART runtime code ranges: readers whose PC lands inside see the tampered
   * page; everyone else (scanners) sees the clean original page. */
  long (*art_trust_add)(unsigned long start, unsigned long end);
  long (*art_trust_clear)(void);
  /* Returns 1 while the kernel DABT fault hooks are live. Mako uses this to
   * gate its in-band scanner-view self-check (a direct read through the
   * blocked PTE would SIGSEGV without the fault handler). */
  long (*art_shadow_query)(void);
  /* Resolve a symbol from an image already mapped in the target. This uses the
   * Daemon's ELF resolver and therefore does not depend on Android linker
   * namespace visibility. */
  long (*find_export)(const char *soname, const char *symbol,
                      unsigned long *out_address);
  const struct MakoReflectionCache *reflection;
};

/* Filled by rtgum_mako_entry. */
struct MakoHookApi {
  unsigned long version;
  unsigned long size;
  long (*hook_method)(void *env, const char *class_name,
                      const char *method_name, const char *signature,
                      int is_static, MakoArtCallback on_enter,
                      MakoArtCallback on_leave, void *user_data,
                      unsigned long *out_handle);
  long (*hook_reflected)(void *env, void *method_object,
                         MakoArtCallback on_enter, MakoArtCallback on_leave,
                         void *user_data, unsigned long *out_handle);
  /* Activity.onCreate hook. "*" targets the bootstrap Activity base method;
   * an explicit JNI class name resolves and hooks that class directly. */
  long (*hook_activity_create)(void *env, const char *class_name,
                               MakoArtCallback on_enter,
                               MakoArtCallback on_leave, void *user_data,
                               unsigned long *out_handle);
  long (*revert)(unsigned long handle);
  long (*status)(unsigned long handle, unsigned int *out_state);
  /* Reports how this runtime encodes a jmethodID and, when the encoding allows
   * it, the ArtMethod record address.
   *
   * This exists because a jmethodID is not promised to be a pointer: AOSP
   * jni_id_type.h defines kPointer, kIndices and kSwapablePointer, and in the
   * last two the address lives in a table owned by the runtime. Callers that
   * treat the id as an address therefore read from a small integer on some
   * builds. Every consumer that needs the record - a scanner view, a test, a
   * diagnostics page - should ask here instead of casting.
   *
   * On success *out_mode is one of MakoJniIdMode and *out_record is the
   * ArtMethod address, or 0 when the mode does not expose one. Returning an
   * error is the expected outcome on a runtime whose decode is not reachable
   * without private symbols; it means "do not guess", not "the method is
   * invalid".
   *
   * The address is metadata. Nothing about the shadow-page scheme changes when
   * a caller has it: the value of a shadowed field still has to be read by
   * whatever reader identity the caller wants to test. */
  long (*probe_id)(void *env, void *method_object, unsigned int *out_mode,
                   unsigned long *out_record, unsigned long *out_offset_hint);
};

/* Ghost module entry. The KPM linker loads the SO with rtgum_mako_entry and
 * ghostModuleUnload as its exports. */
typedef void (*MakoEntry)(const struct MakoHostApi *host,
                          struct MakoHookApi *out);

#ifdef __cplusplus
}
#endif
