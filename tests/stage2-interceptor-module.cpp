/* End-to-end Binder + linker Shadow-Page interceptor acceptance module. */

#include <rtgum/ghost_api.h>

#include <jni.h>
#include <stddef.h>

namespace {

GhostApi *g_api = nullptr;
const HostApiV2 *g_host = nullptr;
unsigned long g_binder_rule = 0UL;
unsigned long g_linker_rule = 0UL;
unsigned long g_linker_skip_rule = 0UL;
volatile unsigned long g_binder_before = 0UL;
volatile unsigned long g_binder_after = 0UL;
volatile unsigned long g_linker_before = 0UL;
volatile unsigned long g_linker_after = 0UL;

using GetCreatedJavaVMs = jint (*)(JavaVM **, jsize, jsize *);
using AndroidDlopenExt = void *(*)(const char *, int, const void *);
using Dlclose = int (*)(void *);

struct AttachedEnv final {
    JavaVM *vm;
    JNIEnv *env;
    bool attached_here;
};

void Fail(const char *message)
{
    if (g_api && g_api->status)
        g_api->status(RTGUM_DAEMON_STATUS_EXTRA,
                      RTGUM_MODULE_EXTRA_INTERCEPTORS_FAILED);
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

long BinderBefore(RtGumBinderCall *call, void *)
{
    if (!call || call->version != 1UL || !call->interface_token ||
        call->interface_token_length == 0UL)
        return RTGUM_HOST_ERR_INVAL;
    __atomic_add_fetch(&g_binder_before, 1UL, __ATOMIC_RELAXED);
    return RTGUM_INTERCEPT_CONTINUE;
}

long BinderAfter(RtGumBinderCall *call, void *)
{
    if (!call || call->version != 1UL) return RTGUM_HOST_ERR_INVAL;
    __atomic_add_fetch(&g_binder_after, 1UL, __ATOMIC_RELAXED);
    return RTGUM_INTERCEPT_CONTINUE;
}

long LinkerBefore(RtGumLinkerCall *call, void *)
{
    if (!call || call->version != 1UL || !call->filename)
        return RTGUM_HOST_ERR_INVAL;
    __atomic_add_fetch(&g_linker_before, 1UL, __ATOMIC_RELAXED);
    return RTGUM_INTERCEPT_CONTINUE;
}

long LinkerAfter(RtGumLinkerCall *call, void *)
{
    if (!call || call->version != 1UL || !call->result)
        return RTGUM_HOST_ERR_INVAL;
    __atomic_add_fetch(&g_linker_after, 1UL, __ATOMIC_RELAXED);
    return RTGUM_INTERCEPT_CONTINUE;
}

long LinkerSkip(RtGumLinkerCall *call, void *)
{
    if (!call || call->version != 1UL) return RTGUM_HOST_ERR_INVAL;
    call->result = reinterpret_cast<void *>(0x12345000UL);
    return RTGUM_INTERCEPT_SKIP_OR_OVERRIDE;
}

bool TriggerBinder(JNIEnv *env)
{
    jclass service_manager = env->FindClass("android/os/ServiceManager");
    jmethodID check_service = service_manager ? env->GetStaticMethodID(
        service_manager, "checkService", "(Ljava/lang/String;)Landroid/os/IBinder;")
        : nullptr;
    if (env->ExceptionCheck() || !service_manager || !check_service) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (service_manager) env->DeleteLocalRef(service_manager);
        return false;
    }
    const char *names[3] = {"rtgum.interceptor.missing.1",
                            "rtgum.interceptor.missing.2", "package"};
    for (unsigned int index = 0U; index < 3U; ++index) {
        jstring name = env->NewStringUTF(names[index]);
        jobject binder = name ? env->CallStaticObjectMethod(service_manager,
                                                             check_service, name)
                              : nullptr;
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (binder) env->DeleteLocalRef(binder);
        if (name) env->DeleteLocalRef(name);
    }
    env->DeleteLocalRef(service_manager);
    return __atomic_load_n(&g_binder_before, __ATOMIC_RELAXED) != 0UL &&
           __atomic_load_n(&g_binder_after, __ATOMIC_RELAXED) != 0UL;
}

void RunAcceptance(void *)
{
    RtGumInterceptorStats cold_binder{};
    cold_binder.version = 1UL;
    cold_binder.size = sizeof(cold_binder);
    RtGumInterceptorStats cold_linker{};
    cold_linker.version = 1UL;
    cold_linker.size = sizeof(cold_linker);
    if (g_host->interceptor_query(RTGUM_INTERCEPTOR_BINDER, &cold_binder) != 0 ||
        g_host->interceptor_query(RTGUM_INTERCEPTOR_LINKER, &cold_linker) != 0 ||
        cold_binder.initialized != 0U || cold_binder.rules != 0U ||
        cold_binder.logging_enabled != 0U || cold_linker.initialized != 0U ||
        cold_linker.rules != 0U) {
        Fail("rtgum-interceptors: bases were not lazy/default-off");
        return;
    }

    unsigned long dlopen_address = 0UL;
    unsigned long dlclose_address = 0UL;
    if (g_host->find_export("libdl.so", "android_dlopen_ext", &dlopen_address) != 0 ||
        dlopen_address == 0UL ||
        g_host->find_export("libdl.so", "dlclose", &dlclose_address) != 0 ||
        dlclose_address == 0UL) {
        Fail("rtgum-interceptors: loader exports unavailable");
        return;
    }

    long status = g_host->linker_interceptor_register(
        "libc.so", RTGUM_INTERCEPT_MATCH_SUBSTRING, LinkerBefore, LinkerAfter,
        nullptr, &g_linker_rule);
    if (status != 0 || g_linker_rule == 0UL) {
        Fail("rtgum-interceptors: linker register failed");
        return;
    }
    auto dlopen_ext = reinterpret_cast<AndroidDlopenExt>(dlopen_address);
    auto dlclose_fn = reinterpret_cast<Dlclose>(dlclose_address);
    void *libc = dlopen_ext("libc.so", 2 | 4 /* RTLD_NOW | RTLD_NOLOAD */, nullptr);
    if (libc) (void)dlclose_fn(libc);
    const unsigned long linker_before =
        __atomic_load_n(&g_linker_before, __ATOMIC_RELAXED);
    const unsigned long linker_after =
        __atomic_load_n(&g_linker_after, __ATOMIC_RELAXED);
    if (!libc || linker_before == 0UL || linker_before != linker_after) {
        Fail("rtgum-interceptors: linker callbacks did not pair");
        return;
    }
    status = g_host->linker_interceptor_register(
        "rtgum-never-load.so", RTGUM_INTERCEPT_MATCH_EXACT, LinkerSkip,
        nullptr, nullptr, &g_linker_skip_rule);
    if (status != 0 || g_linker_skip_rule == 0UL ||
        dlopen_ext("rtgum-never-load.so", 2 /* RTLD_NOW */, nullptr) !=
            reinterpret_cast<void *>(0x12345000UL)) {
        Fail("rtgum-interceptors: linker skip override failed");
        return;
    }

    status = g_host->binder_interceptor_register(
        "android.os.IServiceManager", RTGUM_INTERCEPT_MATCH_EXACT, BinderBefore,
        BinderAfter, nullptr, &g_binder_rule);
    if (status != 0 || g_binder_rule == 0UL) {
        Fail("rtgum-interceptors: binder register failed");
        return;
    }
    AttachedEnv attached{};
    if (!Attach(attached) || !TriggerBinder(attached.env)) {
        Detach(attached);
        Fail("rtgum-interceptors: binder callbacks did not pair");
        return;
    }
    Detach(attached);
    const unsigned long binder_before =
        __atomic_load_n(&g_binder_before, __ATOMIC_RELAXED);
    const unsigned long binder_after =
        __atomic_load_n(&g_binder_after, __ATOMIC_RELAXED);
    if (binder_before == 0UL || binder_before != binder_after) {
        Fail("rtgum-interceptors: binder before/after ordering mismatch");
        return;
    }

    RtGumInterceptorStats binder{};
    binder.version = 1UL;
    binder.size = sizeof(binder);
    RtGumInterceptorStats linker{};
    linker.version = 1UL;
    linker.size = sizeof(linker);
    if (g_host->interceptor_query(RTGUM_INTERCEPTOR_BINDER, &binder) != 0 ||
        g_host->interceptor_query(RTGUM_INTERCEPTOR_LINKER, &linker) != 0 ||
        binder.initialized != 1U || linker.initialized != 1U ||
        binder.matched == 0UL || linker.matched == 0UL ||
        binder.callback_errors != 0UL || linker.callback_errors != 0UL ||
        binder.logging_enabled != 0U) {
        Fail("rtgum-interceptors: runtime statistics mismatch");
        return;
    }

    if (g_host->binder_interceptor_set_logging(1U) != 0 ||
        g_host->interceptor_query(RTGUM_INTERCEPTOR_BINDER, &binder) != 0 ||
        binder.logging_enabled != 1U ||
        g_host->binder_interceptor_set_logging(0U) != 0 ||
        g_host->interceptor_query(RTGUM_INTERCEPTOR_BINDER, &binder) != 0 ||
        binder.logging_enabled != 0U) {
        Fail("rtgum-interceptors: binder logging switch mismatch");
        return;
    }

    if (g_host->interceptor_unregister(g_binder_rule) != 0 ||
        g_host->interceptor_unregister(g_binder_rule) != 0 ||
        g_host->interceptor_unregister(g_linker_skip_rule) != 0 ||
        g_host->interceptor_unregister(g_linker_skip_rule) != 0 ||
        g_host->interceptor_unregister(g_linker_rule) != 0 ||
        g_host->interceptor_unregister(g_linker_rule) != 0) {
        Fail("rtgum-interceptors: idempotent unregister failed");
        return;
    }
    binder = {};
    binder.version = 1UL;
    binder.size = sizeof(binder);
    linker = {};
    linker.version = 1UL;
    linker.size = sizeof(linker);
    if (g_host->interceptor_query(RTGUM_INTERCEPTOR_BINDER, &binder) != 0 ||
        g_host->interceptor_query(RTGUM_INTERCEPTOR_LINKER, &linker) != 0 ||
        binder.initialized != 0U || linker.initialized != 0U ||
        binder.rules != 0U || linker.rules != 0U) {
        Fail("rtgum-interceptors: base teardown mismatch");
        return;
    }
    g_binder_rule = 0UL;
    g_linker_rule = 0UL;
    g_linker_skip_rule = 0UL;
    g_api->status(RTGUM_DAEMON_STATUS_EXTRA,
                  RTGUM_MODULE_EXTRA_INTERCEPTORS_READY);
    g_api->log("rtgum-interceptors: binder=1 linker=1 lazy=1 log-default=0 shadow=1 PASS");
}

}  // namespace

extern "C" __attribute__((visibility("default"))) void ghostEntry(GhostApi *api)
{
    if (!api || api->version != RTGUM_GHOST_API_VERSION || !api->host) return;
    g_api = api;
    g_host = api->host;
    const unsigned long required = static_cast<unsigned long>(
        offsetof(HostApiV2, interceptor_query) + sizeof(g_host->interceptor_query));
    const unsigned long caps = RTGUM_HOST_CAP_FIND_EXPORT |
        RTGUM_HOST_CAP_DEFER | RTGUM_HOST_CAP_BINDER_INTERCEPTOR |
        RTGUM_HOST_CAP_LINKER_INTERCEPTOR | RTGUM_HOST_CAP_SHADOW_PAGE;
    if (g_host->version != RTGUM_HOST_API_V2_VERSION || g_host->size < required ||
        (g_host->capabilities & caps) != caps || !g_host->find_export ||
        !g_host->defer || !g_host->binder_interceptor_register ||
        !g_host->linker_interceptor_register || !g_host->interceptor_unregister ||
        !g_host->binder_interceptor_set_logging || !g_host->interceptor_query ||
        g_host->defer(RunAcceptance, nullptr) != 0) {
        Fail("rtgum-interceptors: host ABI unavailable");
        return;
    }
    api->status(RTGUM_DAEMON_STATUS_EXTRA, RTGUM_MODULE_EXTRA_POLL_ARMED);
    api->log("rtgum-interceptors: acceptance armed");
}

extern "C" __attribute__((visibility("default"))) void ghostModuleUnload(
    GhostApi *api)
{
    if (g_host && g_host->interceptor_unregister) {
        if (g_binder_rule) (void)g_host->interceptor_unregister(g_binder_rule);
        if (g_linker_skip_rule)
            (void)g_host->interceptor_unregister(g_linker_skip_rule);
        if (g_linker_rule) (void)g_host->interceptor_unregister(g_linker_rule);
    }
    g_binder_rule = 0UL;
    g_linker_rule = 0UL;
    g_linker_skip_rule = 0UL;
    if (api && api->log) api->log("rtgum-interceptors: unload");
}
