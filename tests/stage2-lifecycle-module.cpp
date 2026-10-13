/* End-to-end SO constructor/JNI_OnLoad + RegisterNatives trace fixture. */

#include <rtgum/ghost_api.h>

#include <jni.h>
#include <stddef.h>

namespace {

GhostApi *g_api = nullptr;
const HostApiV2 *g_host = nullptr;
unsigned long g_lifecycle_rule = 0UL;
unsigned long g_jni_rule = 0UL;
unsigned long g_linker_rule = 0UL;
unsigned long g_native_hook = 0UL;
volatile unsigned long g_native_original = 0UL;
volatile unsigned int g_order = 0U;
volatile unsigned int g_register_order = 0U;
volatile unsigned int g_native_hits = 0U;
volatile unsigned long g_native_function = 0UL;
jclass g_probe_class = nullptr;

using GetCreatedJavaVMs = jint (*)(JavaVM **, jsize, jsize *);
using NativeValue = jint (*)(JNIEnv *, jclass);

struct AttachedEnv final {
    JavaVM *vm;
    JNIEnv *env;
    bool attached_here;
};

void Fail(const char *message)
{
    if (g_api && g_api->status)
        g_api->status(RTGUM_DAEMON_STATUS_EXTRA,
                      RTGUM_MODULE_EXTRA_LIFECYCLE_FAILED);
    if (g_api && g_api->log) g_api->log(message);
}

bool Attach(AttachedEnv &attached)
{
    attached = {};
    unsigned long address = 0UL;
    if (!g_host || !g_host->find_export ||
        g_host->find_export("libart.so", "JNI_GetCreatedJavaVMs", &address) != 0 ||
        address == 0UL)
        return false;
    JavaVM *vm = nullptr;
    jsize count = 0;
    if (reinterpret_cast<GetCreatedJavaVMs>(address)(&vm, 1, &count) != JNI_OK ||
        !vm || count == 0)
        return false;
    JNIEnv *env = nullptr;
    const jint state = vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6);
    if (state == JNI_OK && env) {
        attached.vm = vm;
        attached.env = env;
        return true;
    }
    if (state != JNI_EDETACHED || vm->AttachCurrentThread(&env, nullptr) != JNI_OK ||
        !env)
        return false;
    attached.vm = vm;
    attached.env = env;
    attached.attached_here = true;
    return true;
}

void Detach(AttachedEnv &attached)
{
    if (attached.attached_here && attached.vm)
        (void)attached.vm->DetachCurrentThread();
    attached = {};
}

bool ReadFixtureState(int expected)
{
    unsigned long address = 0UL;
    if (!g_host || !g_host->find_export ||
        g_host->find_export("libghostlab.so", "rtgum_lifecycle_probe_state",
                            &address) != 0 ||
        address == 0UL)
        return false;
    return __atomic_load_n(reinterpret_cast<volatile int *>(address),
                           __ATOMIC_ACQUIRE) == expected;
}

extern "C" __attribute__((noinline)) jint NativeTraceReplacement(JNIEnv *env,
                                                                    jclass clazz)
{
    const unsigned long original =
        __atomic_load_n(&g_native_original, __ATOMIC_ACQUIRE);
    if (original == 0UL) return 0;
    __atomic_add_fetch(&g_native_hits, 1U, __ATOMIC_RELAXED);
    return reinterpret_cast<NativeValue>(original)(env, clazz);
}

long LifecycleEvent(const RtGumSoLifecycleEvent *event, void *)
{
    if (!event || event->version != 1UL || !event->library_name ||
        event->address == 0UL)
        return RTGUM_HOST_ERR_INVAL;
    const unsigned int order = __atomic_load_n(&g_order, __ATOMIC_ACQUIRE);
    switch (event->phase) {
        case RTGUM_SO_PHASE_BEFORE_CONSTRUCTORS:
            if (g_api && g_api->log)
                g_api->log("rtgum-lifecycle: callback before constructors");
            if (order != 0U || event->soinfo == nullptr || !ReadFixtureState(0)) {
                if (g_api && g_api->log)
                    g_api->log("rtgum-lifecycle: before constructors check failed");
                return RTGUM_HOST_ERR_INVAL;
            }
            __atomic_store_n(&g_order, 1U, __ATOMIC_RELEASE);
            break;
        case RTGUM_SO_PHASE_AFTER_CONSTRUCTORS:
            if (g_api && g_api->log)
                g_api->log("rtgum-lifecycle: callback after constructors");
            if (order != 1U || !ReadFixtureState(1)) {
                if (g_api && g_api->log)
                    g_api->log("rtgum-lifecycle: after constructors check failed");
                return RTGUM_HOST_ERR_INVAL;
            }
            __atomic_store_n(&g_order, 2U, __ATOMIC_RELEASE);
            break;
        case RTGUM_SO_PHASE_BEFORE_JNI_ONLOAD:
            if (g_api && g_api->log)
                g_api->log("rtgum-lifecycle: callback before JNI_OnLoad");
            if (order != 2U || !event->vm || !ReadFixtureState(1)) {
                if (g_api && g_api->log)
                    g_api->log("rtgum-lifecycle: before JNI_OnLoad check failed");
                return RTGUM_HOST_ERR_INVAL;
            }
            __atomic_store_n(&g_order, 3U, __ATOMIC_RELEASE);
            break;
        case RTGUM_SO_PHASE_AFTER_JNI_ONLOAD:
            if (g_api && g_api->log)
                g_api->log("rtgum-lifecycle: callback after JNI_OnLoad");
            if (order != 3U || event->result != JNI_VERSION_1_6 ||
                __atomic_load_n(&g_register_order, __ATOMIC_ACQUIRE) != 2U ||
                !ReadFixtureState(2)) {
                if (g_api && g_api->log)
                    g_api->log("rtgum-lifecycle: after JNI_OnLoad check failed");
                return RTGUM_HOST_ERR_INVAL;
            }
            __atomic_store_n(&g_order, 4U, __ATOMIC_RELEASE);
            break;
        default:
            return RTGUM_HOST_ERR_INVAL;
    }
    return 0L;
}

long JniRegistration(const RtGumJniTraceEvent *event, void *)
{
    if (!event || event->version != 1UL || !event->env || !event->clazz ||
        !event->class_name || !event->method_name || !event->signature ||
        event->function == 0UL)
        return RTGUM_HOST_ERR_INVAL;
    JNIEnv *env = static_cast<JNIEnv *>(event->env);
    if (event->phase == RTGUM_JNI_TRACE_PHASE_BEFORE_REGISTER) {
        if (g_api && g_api->log)
            g_api->log("rtgum-lifecycle: callback before RegisterNatives");
        if (__atomic_load_n(&g_register_order, __ATOMIC_ACQUIRE) != 0U ||
            __atomic_load_n(&g_order, __ATOMIC_ACQUIRE) != 3U)
            return RTGUM_HOST_ERR_INVAL;
        g_probe_class = static_cast<jclass>(env->NewGlobalRef(
            static_cast<jclass>(event->clazz)));
        if (!g_probe_class || env->ExceptionCheck()) {
            if (env->ExceptionCheck()) env->ExceptionClear();
            return RTGUM_HOST_ERR_NOMEM;
        }
        unsigned long original = 0UL;
        unsigned long handle = 0UL;
        const long installed = g_host->shadow_replace(
            event->function,
            reinterpret_cast<unsigned long>(&NativeTraceReplacement),
            &original, &handle);
        if (installed != 0 || original == 0UL || handle == 0UL) {
            if (g_api && g_api->log) {
                if (installed == RTGUM_HOST_ERR_NOTSUP)
                    g_api->log("rtgum-lifecycle: native trace install ENOTSUP");
                else if (installed == RTGUM_HOST_ERR_BUSY)
                    g_api->log("rtgum-lifecycle: native trace install EBUSY");
                else if (installed == RTGUM_HOST_ERR_EXIST)
                    g_api->log("rtgum-lifecycle: native trace install EEXIST");
                else if (installed == RTGUM_HOST_ERR_INVAL)
                    g_api->log("rtgum-lifecycle: native trace install EINVAL");
                else
                    g_api->log("rtgum-lifecycle: native trace install failed");
            }
            env->DeleteGlobalRef(g_probe_class);
            g_probe_class = nullptr;
            return installed != 0 ? installed : RTGUM_HOST_ERR_INVAL;
        }
        __atomic_store_n(&g_native_original, original, __ATOMIC_RELEASE);
        g_native_hook = handle;
        __atomic_store_n(&g_native_function, event->function, __ATOMIC_RELEASE);
        __atomic_store_n(&g_register_order, 1U, __ATOMIC_RELEASE);
    } else if (event->phase == RTGUM_JNI_TRACE_PHASE_AFTER_REGISTER) {
        if (g_api && g_api->log)
            g_api->log("rtgum-lifecycle: callback after RegisterNatives");
        if (__atomic_load_n(&g_register_order, __ATOMIC_ACQUIRE) != 1U ||
            event->register_result != JNI_OK ||
            __atomic_load_n(&g_native_function, __ATOMIC_ACQUIRE) !=
                event->function || g_native_hook == 0UL ||
            __atomic_load_n(&g_native_original, __ATOMIC_ACQUIRE) == 0UL)
            return RTGUM_HOST_ERR_INVAL;
        __atomic_store_n(&g_register_order, 2U, __ATOMIC_RELEASE);
    } else {
        return RTGUM_HOST_ERR_INVAL;
    }
    return 0L;
}

long KeepSharedLinkerAlive(RtGumLinkerCall *, void *)
{
    return 0L;
}

void RunAcceptance(void *)
{
    for (unsigned int attempt = 0U; attempt < 160U; ++attempt) {
        if (__atomic_load_n(&g_order, __ATOMIC_ACQUIRE) == 4U &&
            __atomic_load_n(&g_register_order, __ATOMIC_ACQUIRE) == 2U)
            break;
        (void)g_host->sleep_ms(50U);
    }
    if (__atomic_load_n(&g_order, __ATOMIC_ACQUIRE) != 4U ||
        __atomic_load_n(&g_register_order, __ATOMIC_ACQUIRE) != 2U) {
        Fail("rtgum-lifecycle: event sequence incomplete");
        return;
    }
    unsigned long expected = 0UL;
    const unsigned long observed =
        __atomic_load_n(&g_native_function, __ATOMIC_ACQUIRE);
    if (g_host->find_export("libghostlab.so", "rtgum_lifecycle_native_value",
                            &expected) != 0 || expected == 0UL ||
        expected != observed) {
        Fail("rtgum-lifecycle: RegisterNatives function mismatch");
        return;
    }
    AttachedEnv attached{};
    if (!Attach(attached) || !g_probe_class) {
        Detach(attached);
        Fail("rtgum-lifecycle: app class unavailable");
        return;
    }
    jmethodID method = attached.env->GetStaticMethodID(g_probe_class,
                                                        "nativeValue", "()I");
    const jint value = method ? attached.env->CallStaticIntMethod(g_probe_class,
                                                                   method)
                              : 0;
    const bool java_ok = method && !attached.env->ExceptionCheck() &&
                         value == RTGUM_LIFECYCLE_NATIVE_MAGIC &&
                         __atomic_load_n(&g_native_hits,
                                         __ATOMIC_ACQUIRE) == 1U;
    if (attached.env->ExceptionCheck()) attached.env->ExceptionClear();
    const long reverted = g_native_hook != 0UL
                              ? g_host->hook_native_revert(g_native_hook)
                              : RTGUM_HOST_ERR_BADF;
    if (reverted == 0) {
        g_native_hook = 0UL;
        __atomic_store_n(&g_native_original, 0UL, __ATOMIC_RELEASE);
    }
    const jint value_after = method && reverted == 0
                                 ? attached.env->CallStaticIntMethod(g_probe_class,
                                                                    method)
                                 : 0;
    const bool restored = reverted == 0 && method &&
        !attached.env->ExceptionCheck() &&
        value_after == RTGUM_LIFECYCLE_NATIVE_MAGIC &&
        __atomic_load_n(&g_native_hits, __ATOMIC_ACQUIRE) == 1U;
    if (attached.env->ExceptionCheck()) attached.env->ExceptionClear();
    attached.env->DeleteGlobalRef(g_probe_class);
    g_probe_class = nullptr;
    Detach(attached);
    if (!java_ok || !restored) {
        Fail("rtgum-lifecycle: registered Java native trace failed");
        return;
    }
    RtGumInterceptorStats lifecycle{};
    lifecycle.version = 1UL;
    lifecycle.size = sizeof(lifecycle);
    RtGumInterceptorStats jni{};
    jni.version = 1UL;
    jni.size = sizeof(jni);
    RtGumInterceptorStats linker{};
    linker.version = 1UL;
    linker.size = sizeof(linker);
    if (g_host->interceptor_query(RTGUM_INTERCEPTOR_SO_LIFECYCLE,
                                  &lifecycle) != 0 ||
        g_host->interceptor_query(RTGUM_INTERCEPTOR_JNI_TRACE, &jni) != 0 ||
        g_host->interceptor_query(RTGUM_INTERCEPTOR_LINKER, &linker) != 0 ||
        lifecycle.initialized != 1U || lifecycle.rules != 1U ||
        lifecycle.matched < 2UL || lifecycle.callback_errors != 0UL ||
        jni.initialized != 1U || jni.rules != 1U || jni.matched < 2UL ||
        jni.callback_errors != 0UL || linker.initialized != 1U ||
        linker.rules != 1U) {
        Fail("rtgum-lifecycle: runtime statistics mismatch");
        return;
    }
    if (g_host->interceptor_unregister(g_jni_rule) != 0 ||
        g_host->interceptor_unregister(g_jni_rule) != 0 ||
        g_host->interceptor_unregister(g_lifecycle_rule) != 0 ||
        g_host->interceptor_unregister(g_lifecycle_rule) != 0) {
        Fail("rtgum-lifecycle: teardown failed");
        return;
    }
    g_jni_rule = 0UL;
    g_lifecycle_rule = 0UL;
    lifecycle = {};
    lifecycle.version = 1UL;
    lifecycle.size = sizeof(lifecycle);
    jni = {};
    jni.version = 1UL;
    jni.size = sizeof(jni);
    linker = {};
    linker.version = 1UL;
    linker.size = sizeof(linker);
    if (g_host->interceptor_query(RTGUM_INTERCEPTOR_SO_LIFECYCLE,
                                  &lifecycle) != 0 ||
        g_host->interceptor_query(RTGUM_INTERCEPTOR_JNI_TRACE, &jni) != 0 ||
        g_host->interceptor_query(RTGUM_INTERCEPTOR_LINKER, &linker) != 0 ||
        lifecycle.initialized != 0U || lifecycle.rules != 0U ||
        jni.initialized != 0U || jni.rules != 0U ||
        linker.initialized != 1U || linker.rules != 1U) {
        Fail("rtgum-lifecycle: base hooks remained active");
        return;
    }
    if (g_host->interceptor_unregister(g_linker_rule) != 0 ||
        g_host->interceptor_unregister(g_linker_rule) != 0) {
        Fail("rtgum-lifecycle: shared linker teardown failed");
        return;
    }
    g_linker_rule = 0UL;
    linker = {};
    linker.version = 1UL;
    linker.size = sizeof(linker);
    if (g_host->interceptor_query(RTGUM_INTERCEPTOR_LINKER, &linker) != 0 ||
        linker.initialized != 0U || linker.rules != 0U) {
        Fail("rtgum-lifecycle: shared linker hook remained active");
        return;
    }
    g_api->status(RTGUM_DAEMON_STATUS_EXTRA,
                  RTGUM_MODULE_EXTRA_LIFECYCLE_READY);
    g_api->log("rtgum-lifecycle: constructors=1 jni-onload=1 register-natives=1 function=matched native-trace=1 restored=1 shared-linker=1 teardown=1 PASS");
}

}  // namespace

extern "C" __attribute__((visibility("default"))) void ghostEntry(GhostApi *api)
{
    if (!api || api->version != RTGUM_GHOST_API_VERSION || !api->host) return;
    g_api = api;
    g_host = api->host;
    const unsigned long required = static_cast<unsigned long>(
        offsetof(HostApiV2, jni_trace_register) +
        sizeof(g_host->jni_trace_register));
    const unsigned long caps = RTGUM_HOST_CAP_FIND_EXPORT |
        RTGUM_HOST_CAP_DEFER | RTGUM_HOST_CAP_SHADOW_PAGE |
        RTGUM_HOST_CAP_LINKER_INTERCEPTOR | RTGUM_HOST_CAP_SO_LIFECYCLE |
        RTGUM_HOST_CAP_JNI_TRACE;
    if (g_host->version != RTGUM_HOST_API_V2_VERSION || g_host->size < required ||
        (g_host->capabilities & caps) != caps || !g_host->find_export ||
        !g_host->shadow_replace || !g_host->hook_native_revert ||
        !g_host->defer || !g_host->sleep_ms || !g_host->so_lifecycle_register ||
        !g_host->jni_trace_register || !g_host->linker_interceptor_register ||
        !g_host->interceptor_unregister || !g_host->interceptor_query) {
        Fail("rtgum-lifecycle: host ABI unavailable");
        return;
    }
    long status = g_host->so_lifecycle_register(
        "libghostlab.so", RTGUM_INTERCEPT_MATCH_SUBSTRING,
        RTGUM_SO_EVENT_CONSTRUCTORS | RTGUM_SO_EVENT_JNI_ONLOAD,
        LifecycleEvent, nullptr, &g_lifecycle_rule);
    if (status == 0)
        status = g_host->linker_interceptor_register(
            "__rtgum_lifecycle_never_matches__.so",
            RTGUM_INTERCEPT_MATCH_EXACT, KeepSharedLinkerAlive, nullptr,
            nullptr, &g_linker_rule);
    if (status == 0)
        status = g_host->jni_trace_register(
            "dev/rtgum/lab/LifecycleProbe", "nativeValue", "()I",
            RTGUM_INTERCEPT_MATCH_EXACT, JniRegistration, nullptr, &g_jni_rule);
    if (status != 0 || g_lifecycle_rule == 0UL || g_linker_rule == 0UL ||
        g_jni_rule == 0UL ||
        g_host->defer(RunAcceptance, nullptr) != 0) {
        if (g_jni_rule) (void)g_host->interceptor_unregister(g_jni_rule);
        if (g_lifecycle_rule)
            (void)g_host->interceptor_unregister(g_lifecycle_rule);
        if (g_linker_rule)
            (void)g_host->interceptor_unregister(g_linker_rule);
        g_jni_rule = 0UL;
        g_lifecycle_rule = 0UL;
        g_linker_rule = 0UL;
        Fail("rtgum-lifecycle: registration failed");
        return;
    }
    api->status(RTGUM_DAEMON_STATUS_EXTRA, RTGUM_MODULE_EXTRA_POLL_ARMED);
    api->log("rtgum-lifecycle: acceptance armed");
}

extern "C" __attribute__((visibility("default"))) void ghostModuleUnload(
    GhostApi *api)
{
    if (g_host && g_host->interceptor_unregister) {
        if (g_native_hook && g_host->hook_native_revert)
            (void)g_host->hook_native_revert(g_native_hook);
        if (g_jni_rule) (void)g_host->interceptor_unregister(g_jni_rule);
        if (g_lifecycle_rule)
            (void)g_host->interceptor_unregister(g_lifecycle_rule);
        if (g_linker_rule)
            (void)g_host->interceptor_unregister(g_linker_rule);
    }
    if (g_probe_class && g_host) {
        AttachedEnv attached{};
        if (Attach(attached)) {
            attached.env->DeleteGlobalRef(g_probe_class);
            Detach(attached);
        }
    }
    g_probe_class = nullptr;
    g_native_hook = 0UL;
    __atomic_store_n(&g_native_original, 0UL, __ATOMIC_RELEASE);
    g_jni_rule = 0UL;
    g_lifecycle_rule = 0UL;
    g_linker_rule = 0UL;
    if (api && api->log) api->log("rtgum-lifecycle: unload");
}
