/*
 * HostApiV2: versioned capability table beside GhostApi v1.
 *
 * GhostApi v1 keeps its original field layout. New modules read api->host
 * only after checking version/size/capabilities. Unknown capability bits are
 * ignored; missing bits mean the call is unavailable.
 */

#ifndef RTGUM_HOST_API_V2_H
#define RTGUM_HOST_API_V2_H

#ifdef __cplusplus
extern "C" {
#endif

struct RtGumStalkerStats;

#define RTGUM_HOST_API_V2_VERSION 2UL

#define RTGUM_HOST_CAP_FIND_EXPORT (1UL << 0)
#define RTGUM_HOST_CAP_NATIVE_REPLACE (1UL << 1)
#define RTGUM_HOST_CAP_DEFER (1UL << 2)
#define RTGUM_HOST_CAP_JAVA_HOOK (1UL << 3)
#define RTGUM_HOST_CAP_NATIVE_SYMBOL (1UL << 4)
#define RTGUM_HOST_CAP_WAIT_EXPORT (1UL << 5)
#define RTGUM_HOST_CAP_LOAD_DEX (1UL << 6)
#define RTGUM_HOST_CAP_LUA (1UL << 7)
#define RTGUM_HOST_CAP_BINDER (1UL << 8)
#define RTGUM_HOST_CAP_GTRACE (1UL << 9)
#define RTGUM_HOST_CAP_HWBP (1UL << 10)
#define RTGUM_HOST_CAP_CPU_SS (1UL << 11)
#define RTGUM_HOST_CAP_SHADOW_PAGE (1UL << 12)
#define RTGUM_HOST_CAP_ART_MAKO (1UL << 13)
#define RTGUM_HOST_CAP_GUM (1UL << 14)
/* Bit 15 described the original one-argument start ABI. Keep it unset so
 * an older module cannot accidentally call the new range-aware signature. */
#define RTGUM_HOST_CAP_DBI_STALKER (1UL << 15)
#define RTGUM_HOST_CAP_DBI_STALKER_RANGE (1UL << 16)
#define RTGUM_HOST_CAP_DBI_STALKER_PAC_CHECKED (1UL << 17)
#define RTGUM_HOST_CAP_DBI_STALKER_BTI_CHECKED (1UL << 18)
#define RTGUM_HOST_CAP_ART_METHOD_FLAGS (1UL << 19)
#define RTGUM_HOST_CAP_SYMBOL_RESOLVER (1UL << 20)
#define RTGUM_HOST_CAP_LOG (1UL << 21)
#define RTGUM_HOST_CAP_BINDER_INTERCEPTOR (1UL << 22)
#define RTGUM_HOST_CAP_LINKER_INTERCEPTOR (1UL << 23)
#define RTGUM_HOST_CAP_SO_LIFECYCLE (1UL << 24)
#define RTGUM_HOST_CAP_JNI_TRACE (1UL << 25)
#define RTGUM_HOST_CAP_GTRACE_RUNTIME (1UL << 26)
#define RTGUM_HOST_CAP_MULTI_TRACE (1UL << 27)
#define RTGUM_HOST_CAP_LUA_ASYNC (1UL << 28)

#define RTGUM_ART_METHOD_INSTANCE 0U
#define RTGUM_ART_METHOD_STATIC (1U << 0)

/* Default poll window for the legacy wait_export path.  Modules which need
 * constructor/JNI_OnLoad ordering should use so_lifecycle_register instead. */
#define RTGUM_HOST_WAIT_EXPORT_DEFAULT_MS 8000U

#define RTGUM_HOST_BACKEND_NATIVE 1U
#define RTGUM_HOST_BACKEND_JAVA 2U
#define RTGUM_HOST_HOOK_INACTIVE 0U
#define RTGUM_HOST_HOOK_ACTIVE 1U

#define RTGUM_HOST_ERR_PERM -1L
#define RTGUM_HOST_ERR_NOENT -2L
#define RTGUM_HOST_ERR_NXIO -6L
#define RTGUM_HOST_ERR_BADF -9L
#define RTGUM_HOST_ERR_AGAIN -11L
#define RTGUM_HOST_ERR_NOMEM -12L
#define RTGUM_HOST_ERR_BUSY -16L
#define RTGUM_HOST_ERR_EXIST -17L
#define RTGUM_HOST_ERR_INVAL -22L
#define RTGUM_HOST_ERR_NOTSUP -95L

/* JNINativeInterface.NewStringUTF index, including the four reserved slots. */
#define RTGUM_JNI_NEW_STRING_UTF_INDEX 167U
/* JNINativeInterface.RegisterNatives, including the four reserved slots. */
#define RTGUM_JNI_REGISTER_NATIVES_INDEX 215U

/* Forward declaration for the Gum backend callbacks (full definition lives
 * in rtgum/gum_api.h). */
struct RtGumInvocation;

#define RTGUM_JNI_STRING_FROM_JNI \
    "Java_com_laodeng_jnicode_MainActivity_stringFromJNI"
#define RTGUM_JNI_MISSING_SYMBOL \
    "Java_com_laodeng_jnicode_MainActivity_thisSymbolDoesNotExist"
#define RTGUM_JNI_ORIGINAL_TEXT "Hello from C++"
#define RTGUM_JNI_REPLACEMENT_TEXT "Hooked from JNI"

/* Daemon status extra words written by .ghm modules (printed decimal). */
#define RTGUM_MODULE_EXTRA_POLL_ARMED 3UL
#define RTGUM_MODULE_EXTRA_REPLACED 4UL
#define RTGUM_LAB_MODULE_EXTRA_HOOK_ARMED 5UL
#define RTGUM_MODULE_EXTRA_HOST_UNAVAILABLE 0xE0UL /* extra=224 */
#define RTGUM_MODULE_EXTRA_DEFER_FAILED 0xE1UL     /* extra=225 */
#define RTGUM_MODULE_EXTRA_JAVA_REPLACE_FAILED 0xE2UL /* extra=226 */
#define RTGUM_MODULE_EXTRA_LOOKUP_FAILED 0xE3UL    /* extra=227 */
#define RTGUM_MODULE_EXTRA_NATIVE_REPLACE_FAILED 0xE4UL /* extra=228 */
#define RTGUM_MODULE_EXTRA_LOADDEX_FAILED 0xE5UL       /* extra=229 */
#define RTGUM_MODULE_EXTRA_LUA_FAILED 0xE6UL           /* extra=230 */
#define RTGUM_MODULE_EXTRA_BINDER_FAILED 0xE7UL        /* extra=231 */
#define RTGUM_MODULE_EXTRA_GUMLUA_FAILED 0xE8UL        /* extra=232 */
#define RTGUM_MODULE_EXTRA_GUMLUA_ARMED 0x200UL        /* extra=512 */
#define RTGUM_MODULE_EXTRA_SYMBOLS_READY 0x5359UL       /* extra=21337 */
#define RTGUM_MODULE_EXTRA_SYMBOLS_FAILED 0xEAUL        /* extra=234 */
#define RTGUM_MODULE_EXTRA_DEX_READY 0x444558UL          /* extra="DEX" */
#define RTGUM_MODULE_EXTRA_DEX_FAILED 0xEBUL             /* extra=235 */
#define RTGUM_MODULE_EXTRA_INTERCEPTORS_READY 0x424cUL    /* extra="BL" */
#define RTGUM_MODULE_EXTRA_INTERCEPTORS_FAILED 0xECUL     /* extra=236 */
#define RTGUM_MODULE_EXTRA_LIFECYCLE_READY 0x534f4cUL      /* extra="SOL" */
#define RTGUM_MODULE_EXTRA_LIFECYCLE_FAILED 0xEDUL         /* extra=237 */
#define RTGUM_LIFECYCLE_NATIVE_MAGIC 0x534f4c43L            /* "SOLC" */
#define RTGUM_MODULE_EXTRA_GTRACE_READY 0x475452UL            /* extra="GTR" */
#define RTGUM_MODULE_EXTRA_GTRACE_FAILED 0xEEUL               /* extra=238 */
#define RTGUM_MODULE_EXTRA_MULTI_TRACE_READY 0x4d5452UL         /* extra="MTR" */
#define RTGUM_MODULE_EXTRA_MULTI_TRACE_FAILED 0xEFUL           /* extra=239 */

/* One instruction which was actually executed by a runtime trace source.
 * `pc` names the retired/emulated instruction and `next_pc` is its immediate
 * architectural landing point.  Keeping the landing in the same record is
 * essential for the last BR/BLR/RET in a batch and for BLR X30, whose target
 * register is overwritten with the link address by the instruction itself. */
#define RTGUM_GTRACE_STEP_INSN_VALID (1U << 0)
#define RTGUM_GTRACE_STEP_NEXT_VALID (1U << 1)
#define RTGUM_GTRACE_STEP_DYNAMIC (1U << 2)
#define RTGUM_GTRACE_STEP_CPU_SINGLE_STEP (1U << 3)
#define RTGUM_GTRACE_STEP_DBI_CALLOUT (1U << 4)

struct RtGumGtraceStep {
    unsigned long long sequence;
    unsigned long pc;
    unsigned long next_pc;
    unsigned int instruction;
    unsigned int flags;
};

/* Per-handle asynchronous function trace.  trace_start copies this entire
 * configuration, so callers may reuse the source object immediately.  The
 * writer and writer_user_data must remain valid until trace_stop succeeds.
 * Calls on different target threads may reach the same writer concurrently;
 * writers that mutate user_data must provide their own synchronization.
 *
 * EXECUTED_PATH emits one RtGumGtraceStep for each instruction in the watched
 * range. SUMMARY keeps the Gum block/call/return counters and may be combined
 * with EXECUTED_PATH. CODE reads the instruction from Gum's decoded block and
 * marks INSN_VALID; NONE still records PC/next-PC but intentionally withholds
 * the opcode. Unknown mode bits are rejected instead of silently changing a
 * later backend's meaning. */
#define RTGUM_TRACE_CONFIG_VERSION 1UL
#define RTGUM_TRACE_BATCH_VERSION 1UL
#define RTGUM_TRACE_STATS_VERSION 1UL
#define RTGUM_TRACE_MODE_EXECUTED_PATH (1U << 0)
#define RTGUM_TRACE_MODE_SUMMARY (1U << 1)
#define RTGUM_TRACE_MEM_READ_NONE 0U
#define RTGUM_TRACE_MEM_READ_CODE 1U

struct RtGumTraceBatch;
typedef long (*RtGumTraceWriter)(const struct RtGumTraceBatch *batch,
                                 void *user_data);

struct RtGumTraceConfig {
    unsigned long version;
    unsigned long size;
    unsigned long target;
    unsigned long watched_start;
    unsigned long watched_size;
    unsigned int trace_mode;
    unsigned int mem_read_mode;
    unsigned long step_capacity;
    RtGumTraceWriter writer;
    void *writer_user_data;
};

/* steps is owned by the runtime and is valid only for the duration of the
 * writer callback.  A failed/nested invocation is still delivered once with
 * result set to a negative errno and count == 0, so loss is observable. */
struct RtGumTraceBatch {
    unsigned long version;
    unsigned long size;
    unsigned long handle;
    unsigned long target;
    unsigned long invocation;
    unsigned long thread_id;
    unsigned int trace_mode;
    unsigned int mem_read_mode;
    long result;
    const struct RtGumGtraceStep *steps;
    unsigned long count;
    unsigned long total;
    unsigned long dropped;
    unsigned long blocks;
    unsigned long calls;
    unsigned long returns;
    unsigned long compiled;
};

struct RtGumTraceStats {
    unsigned long version;
    unsigned long size;
    unsigned long handle;
    unsigned long target;
    unsigned long invocations;
    unsigned long completed;
    unsigned long busy;
    unsigned long failures;
    unsigned long writer_errors;
    unsigned long active;
    unsigned int trace_mode;
    unsigned int mem_read_mode;
    unsigned int retiring;
    unsigned int reserved;
};

/* ART (mako) acceptance fixture, dev.rtgum.lab. The lab's ArtMethod self-check
 * can only produce a PASS for a method whose entry field the framework actually
 * rewrote, so the module that runs in that scenario has to hook the method the
 * lab displays. The status word carries the value the hook writes, which is what
 * makes "the hook is live" and "the scanner still sees the original" two
 * separately observable facts instead of one assumption. */
#define RTGUM_LAB_MODULE_CLASS "dev/rtgum/lab/LabTarget"
#define RTGUM_LAB_MODULE_METHOD "add"
#define RTGUM_LAB_MODULE_SIGNATURE "(II)I"
#define RTGUM_LAB_MODULE_UNTOUCHED "untouched"
#define RTGUM_LAB_HOOK_RESULT 42L     /* what the hook makes add(1,2) return */
#define RTGUM_LAB_BASELINE_RESULT 3L  /* what it returns with no hook */
/* Daemon status extra word once the add() hook is installed: the rewritten
 * return value itself, so a poller asserts the exact behaviour the lab shows. */
#define RTGUM_LAB_MODULE_EXTRA_HOOKED ((unsigned long)RTGUM_LAB_HOOK_RESULT) /* 42 */
#define RTGUM_LAB_MODULE_EXTRA_HOOK_FAILED 0xE9UL      /* extra=233 */

#define RTGUM_LUA_HELPER_SONAME "librtgum-lua-helper.so"
#define RTGUM_LUA_HELPER_STAGING_PATH \
    "/data/local/tmp/rtgum-stage1-pixel8/librtgum-lua-helper.so"
#define RTGUM_LUA_HELPER_APP_PATH \
    "/data/data/com.laodeng.jnicode/code_cache/librtgum-lua-helper.so"

#define RTGUM_DEX_PROBE_CLASS "com/laodeng/jnicode/LoadedDexProbe"
#define RTGUM_DEX_PROBE_METHOD "message"
#define RTGUM_DEX_PROBE_SIG "()Ljava/lang/String;"
#define RTGUM_DEX_PROBE_TEXT "Loaded from DEX"

#define RTGUM_BINDER_CLASS "android/os/BinderProxy"
#define RTGUM_BINDER_NAME "transactNative"
#define RTGUM_BINDER_SIG "(ILandroid/os/Parcel;Landroid/os/Parcel;I)Z"

#define RTGUM_INTERCEPT_MATCH_EXACT (1U << 0)
#define RTGUM_INTERCEPT_MATCH_SUBSTRING (1U << 1)
#define RTGUM_INTERCEPT_CONTINUE 0L
/* A before callback may return this after writing call->result to bypass the
 * original function.  An after callback only needs to edit call->result. */
#define RTGUM_INTERCEPT_SKIP_OR_OVERRIDE 1L
#define RTGUM_INTERCEPTOR_BINDER 1U
#define RTGUM_INTERCEPTOR_LINKER 2U
#define RTGUM_INTERCEPTOR_SO_LIFECYCLE 3U
#define RTGUM_INTERCEPTOR_JNI_TRACE 4U

#define RTGUM_SO_EVENT_CONSTRUCTORS (1U << 0)
#define RTGUM_SO_EVENT_JNI_ONLOAD (1U << 1)
#define RTGUM_SO_PHASE_BEFORE_CONSTRUCTORS 1U
#define RTGUM_SO_PHASE_AFTER_CONSTRUCTORS 2U
#define RTGUM_SO_PHASE_BEFORE_JNI_ONLOAD 3U
#define RTGUM_SO_PHASE_AFTER_JNI_ONLOAD 4U

#define RTGUM_JNI_TRACE_PHASE_BEFORE_REGISTER 1U
#define RTGUM_JNI_TRACE_PHASE_AFTER_REGISTER 2U

struct RtGumBinderCall {
    unsigned long version;
    unsigned long size;
    void *env;
    void *binder_proxy;
    int code;
    unsigned int flags;
    void *data;
    void *reply;
    const char *interface_token;
    unsigned long interface_token_length;
    int result;
    unsigned int skipped;
};

struct RtGumLinkerCall {
    unsigned long version;
    unsigned long size;
    const char *filename;
    int flags;
    const void *extinfo;
    const void *caller_address;
    void *result;
    unsigned int skipped;
};

typedef long (*RtGumBinderInterceptor)(struct RtGumBinderCall *call,
                                       void *user_data);
typedef long (*RtGumLinkerInterceptor)(struct RtGumLinkerCall *call,
                                       void *user_data);

/* call_constructors is intercepted before its first .init/.init_array call.
 * JNI_OnLoad is armed after the linker returns the newly mapped image but
 * before ART regains control and resolves/calls that entry point. */
struct RtGumSoLifecycleEvent {
    unsigned long version;
    unsigned long size;
    const char *library_name;
    void *soinfo;
    unsigned long address;
    unsigned int phase;
    int result;
    void *vm;
    void *reserved;
};

typedef long (*RtGumSoLifecycleCallback)(
    const struct RtGumSoLifecycleEvent *event, void *user_data);

/* One event is emitted for each matching JNINativeMethod entry.  The function
 * pointer is the exact address submitted to ART and may be passed directly to
 * the existing Gum/Shadow/CPU-trace APIs.  The observer never edits the
 * caller-owned JNINativeMethod array. */
struct RtGumJniTraceEvent {
    unsigned long version;
    unsigned long size;
    void *env;
    void *clazz;
    const char *class_name;
    const char *method_name;
    const char *signature;
    unsigned long function;
    unsigned int phase;
    int register_result;
};

typedef long (*RtGumJniTraceCallback)(
    const struct RtGumJniTraceEvent *event, void *user_data);

struct RtGumInterceptorStats {
    unsigned long version;
    unsigned long size;
    unsigned long calls;
    unsigned long matched;
    unsigned long callback_errors;
    unsigned int initialized;
    unsigned int rules;
    unsigned int logging_enabled;
    unsigned int reserved;
};

#define RTGUM_HWBP_EXECUTE 0U
#define RTGUM_HWBP_WRITE 1U
#define RTGUM_HWBP_READWRITE 2U

#define RTGUM_JAVA_MAIN_CLASS "com/laodeng/jnicode/MainActivity"
#define RTGUM_JAVA_ONCREATE_NAME "onCreate"
#define RTGUM_JAVA_ONCREATE_SIG "(Landroid/os/Bundle;)V"
#define RTGUM_JAVA_REPLACEMENT_TEXT "Hooked by onCreate"
#define RTGUM_JAVA_HELPER_SONAME "librtgum-jnicode-java-hook.so"
#define RTGUM_JAVA_HELPER_STAGING_PATH \
    "/data/local/tmp/rtgum-stage1-pixel8/librtgum-jnicode-java-hook.so"
#define RTGUM_JAVA_HELPER_APP_PATH \
    "/data/data/com.laodeng.jnicode/code_cache/librtgum-jnicode-java-hook.so"

struct HostApiV2 {
    unsigned long version;
    unsigned long size;
    unsigned long capabilities;
    long (*find_export)(const char *soname,
                        const char *symbol,
                        unsigned long *out_address);
    long (*hook_native_replace)(unsigned long target,
                                unsigned long replacement,
                                unsigned long *out_original,
                                unsigned long *out_handle);
    long (*hook_native_revert)(unsigned long handle);
    long (*hook_query)(unsigned long handle,
                       unsigned int *out_backend,
                       unsigned int *out_state);
    long (*defer)(void (*function)(void *), void *argument);
    long (*sleep_ms)(unsigned int milliseconds);
    /* Java backend. Pointers may be null when JAVA_HOOK is unset.
     * env / reflected_method / hooker_object / callback_method are JNI
     * JNIEnv* and jobject values. The callback must be
     * Object callback(Object[] args); the original implementation is invoked
     * from that callback. */
    long (*hook_java_replace)(void *env,
                              void *reflected_method,
                              void *hooker_object,
                              void *callback_method,
                              unsigned long *out_handle);
    long (*hook_java_revert)(unsigned long handle);
    /* Locate a Java method by JNI class/name/signature and install the bound
     * backend. env may be null; the backend attaches a JNIEnv. Kept before
     * hook_native_symbol so older Java modules keep working. */
    long (*hook_java_method)(void *env,
                             const char *jni_class,
                             const char *name,
                             const char *signature,
                             unsigned long *out_handle);
    /* Combined Native install matching the 无痕 module API:
     * api->shadowHook(soname, symbol, replacement, &original).
     * Appended after Java pointers so older v2 modules keep working. */
    long (*hook_native_symbol)(const char *soname,
                               const char *symbol,
                               unsigned long replacement,
                               unsigned long *out_original,
                               unsigned long *out_handle);
    /* Poll find_export until the SONAME/symbol is mapped or timeout_ms elapses.
     * timeout_ms == 0 tries once. Appended after hook_native_symbol so older
     * v2 modules keep working. */
    long (*wait_export)(const char *soname,
                        const char *symbol,
                        unsigned int timeout_ms,
                        unsigned long *out_address);
    /* In-memory DEX via the Daemon-owned InMemoryDexClassLoader runtime.
     * bytes are copied to an independent RW ghost span before JNI sees them;
     * use_app_parent must be 0 (bootstrap isolation) or 1 (app delegation).
     * find_class_from_dex returns a tracked global jclass reference that stays
     * valid until unload_dex. unload_dex invalidates the handle, deletes every
     * tracked JNI reference and frees the ghost span; repeating the same
     * unload is idempotent. Appended after wait_export so older v2 modules
     * keep working. */
    long (*load_dex)(const unsigned char *bytes,
                     unsigned long size,
                     unsigned int use_app_parent,
                     unsigned long *out_handle);
    long (*find_class_from_dex)(unsigned long handle,
                                const char *jni_class,
                                unsigned long *out_class);
    long (*unload_dex)(unsigned long handle);
    /* Sandboxed Lua 5.4 helper (SHARED SO, never linked into Daemon). */
    long (*lua_eval)(const char *script, char *error, unsigned long error_capacity);
    long (*lua_stop)(void);
    /* Legacy lazy-start entry.  New modules should register a native Binder
     * interceptor through binder_interceptor_register below. */
    long (*hook_binder)(unsigned long *out_handle);
    /* ARM64 junk-aware decode of a code window (花指令 GTrace, no DBI). */
    long (*gtrace_decode)(const unsigned char *code,
                          unsigned long size,
                          unsigned long pc,
                          char *out,
                          unsigned long capacity);
    /* Debug-path hardware breakpoint / CPU SS / visible shadow remap.
     * Missing capability bits mean the call is unavailable. */
    long (*hwbp_set)(unsigned long address,
                     unsigned int type,
                     unsigned long *out_handle);
    long (*hwbp_clear)(unsigned long handle);
    long (*cpu_ss_trace)(unsigned long start_pc,
                         unsigned int max_insns,
                         char *out,
                         unsigned long capacity);
    long (*shadow_replace)(unsigned long target,
                           unsigned long replacement,
                           unsigned long *out_original,
                           unsigned long *out_handle);
    /* Mako ART hook backend (lazy-loaded ghost SO, Shadow Data Page hiding).
     * Appended after shadow_replace so older v2 modules keep working.
     * on_enter/on_leave receive the raw ARM64 quick-ABI context; on_leave may
     * rewrite the return value. env may be null (the backend attaches). */
    long (*art_hook_method)(void *env,
                            const char *jni_class,
                            const char *name,
                            const char *signature,
                            void (*on_enter)(void *context, void *user_data),
                            void (*on_leave)(void *context, void *user_data),
                            void *user_data,
                            unsigned long *out_handle);
    long (*art_hook_reflected)(void *env,
                               void *method_object,
                               void (*on_enter)(void *context, void *user_data),
                               void (*on_leave)(void *context, void *user_data),
                               void *user_data,
                               unsigned long *out_handle);
    long (*art_hook_revert)(unsigned long handle);
    long (*art_hook_status)(unsigned long handle, unsigned int *out_state);
    /* Activity.onCreate hook. "*" targets android.app.Activity's base method;
     * an explicit slash-form class name hooks that class directly. */
    long (*art_hook_activity_create)(void *env,
                                     const char *jni_class,
                                     void (*on_enter)(void *context,
                                                      void *user_data),
                                     void (*on_leave)(void *context,
                                                      void *user_data),
                                     void *user_data,
                                     unsigned long *out_handle);
    /* Frida Gum backend (librtgum-gum-ghost.so, ghost-loaded by the Daemon).
     * Appended after the ART hooks so older v2 modules keep working.
     * invocation is a struct RtGumInvocation* (rtgum/gum_api.h); the
     * callbacks run on the hooked thread. */
    long (*gum_find_export)(const char *soname,
                            const char *symbol,
                            unsigned long *out_address);
    long (*gum_intercept_attach)(const char *soname,
                                 const char *symbol,
                                 void (*on_enter)(struct RtGumInvocation *invocation,
                                                  void *user_data),
                                 void (*on_leave)(struct RtGumInvocation *invocation,
                                                  void *user_data),
                                 void *user_data,
                                 unsigned long *out_handle);
    long (*gum_intercept_attach_address)(unsigned long address,
                                         void (*on_enter)(struct RtGumInvocation *invocation,
                                                          void *user_data),
                                         void (*on_leave)(struct RtGumInvocation *invocation,
                                                          void *user_data),
                                         void *user_data,
                                         unsigned long *out_handle);
    long (*gum_intercept_revert)(unsigned long handle);
    long (*gum_replace)(unsigned long target,
                        unsigned long replacement,
                        unsigned long *out_original,
                        unsigned long *out_handle);
    long (*gum_memory_read)(unsigned long address, void *buffer, unsigned long length);
    long (*gum_memory_write)(unsigned long address,
                             const void *buffer,
                             unsigned long length);
    long (*gum_memory_alloc)(unsigned long size, unsigned long *out_address);
    long (*gum_memory_free)(unsigned long address);
    /* Optional per-thread Gum Stalker session. This uses Gum's dynamic block
     * translator/cache; it does not certify the custom relocator's PAC/BTI
     * semantics. The stats pointer must remain valid through stop(). */
    long (*dbi_stalker_start)(struct RtGumStalkerStats *stats,
                              unsigned long watched_start,
                              unsigned long watched_size);
    long (*dbi_stalker_invalidate)(unsigned long address);
    long (*dbi_stalker_stop)(void);
    /* Flag-aware ART lookup. Appended so all existing HostApiV2 offsets remain
     * stable; the legacy art_hook_method continues to mean instance method. */
    long (*art_hook_method_ex)(void *env,
                               const char *jni_class,
                               const char *name,
                               const char *signature,
                               unsigned int flags,
                               void (*on_enter)(void *context, void *user_data),
                               void (*on_leave)(void *context, void *user_data),
                               void *user_data,
                               unsigned long *out_handle);
    /* Shared Hook/Trace resolver.  Both callbacks consume the same kernel VMA
     * snapshot and sorted ELF cache used by find_export.  Failure is an
     * explicit negative errno; an unresolved PC is rendered as
     * "symbol not found", never as a successful address zero. */
    long (*symbolize_pc)(unsigned long pc,
                         char *out,
                         unsigned long capacity);
    long (*symbolize_batch)(const unsigned long *pcs,
                            unsigned long count,
                            char *out,
                            unsigned long capacity);
    /* Process-safe diagnostic transport. This is backed by the authenticated
     * Daemon/KPM channel, so hooks on libc open/openat cannot suppress it. */
    long (*log)(const char *message);
    /* Daemon-owned Binder/Linker interceptors.  Both install through the KPM
     * code Shadow Page channel and place their original trampolines in ghost
     * memory.  Binder matches default to exact interface-token matching;
     * Linker matches default to a filename substring.  Before callbacks run
     * in registration order and after callbacks in reverse order. */
    long (*binder_interceptor_register)(
        const char *interface_token,
        unsigned int match_flags,
        RtGumBinderInterceptor before,
        RtGumBinderInterceptor after,
        void *user_data,
        unsigned long *out_handle);
    long (*linker_interceptor_register)(
        const char *library_name,
        unsigned int match_flags,
        RtGumLinkerInterceptor before,
        RtGumLinkerInterceptor after,
        void *user_data,
        unsigned long *out_handle);
    long (*interceptor_unregister)(unsigned long handle);
    long (*binder_interceptor_set_logging)(unsigned int enabled);
    long (*interceptor_query)(unsigned int kind,
                              struct RtGumInterceptorStats *out_stats);
    /* Early native-library lifecycle. event_mask is a non-empty combination
     * of RTGUM_SO_EVENT_*; matching follows the Linker interceptor rules. */
    long (*so_lifecycle_register)(
        const char *library_name,
        unsigned int match_flags,
        unsigned int event_mask,
        RtGumSoLifecycleCallback callback,
        void *user_data,
        unsigned long *out_handle);
    /* Dynamic JNI registration observer. "*" in any of the three textual
     * selectors is a wildcard. Class names are normalized to slash form. */
    long (*jni_trace_register)(
        const char *class_name,
        const char *method_name,
        const char *signature,
        unsigned int match_flags,
        RtGumJniTraceCallback callback,
        void *user_data,
        unsigned long *out_handle);
    /* Format an already executed ARM64 path.  The formatter never scans bytes
     * between records: it emits path records for executed instructions, edge
     * records for control transfers, and explicit gap intervals for internal
     * non-contiguous landings.  This is shared by Gum Stalker and kernel CPU
     * single-step consumers so automation sees one stable representation. */
    long (*gtrace_format_path)(
        const struct RtGumGtraceStep *steps,
        unsigned long count,
        unsigned long image_start,
        unsigned long image_end,
        char *out,
        unsigned long capacity);
    /* Register a function entry now and trace later invocations.  Each handle
     * owns an immutable configuration and each invocation owns its Stalker
     * scope/ring. trace_stop detaches first and returns BUSY while an existing
     * callback is draining; retrying completes teardown. */
    long (*trace_start)(const struct RtGumTraceConfig *config,
                        unsigned long *out_handle);
    long (*trace_stop)(unsigned long handle);
    long (*trace_query)(unsigned long handle,
                        struct RtGumTraceStats *out_stats);
    /* Optional non-blocking submission. lua_eval remains synchronous and
     * returns the script result/error; this entry only confirms that the
     * helper copied and queued the text. Appended to preserve every older
     * HostApiV2 offset. */
    long (*lua_eval_async)(const char *script,
                           char *error,
                           unsigned long error_capacity);
};

#ifdef __cplusplus
}
#endif

#endif /* RTGUM_HOST_API_V2_H */
