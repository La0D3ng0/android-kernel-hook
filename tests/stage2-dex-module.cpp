/*
 * End-to-end module for the Daemon-owned in-memory DEX runtime.
 *
 * The DEX bytes are embedded in this .ghm only as input. load_dex must copy
 * them to a separate RW ghost span before constructing a direct ByteBuffer.
 * The module exercises bootstrap isolation, app-parent delegation, duplicate
 * class lookup, explicit symbol-not-found, stale handles and idempotent unload.
 */

#include <rtgum/ghost_api.h>

#include <jni.h>
#include <stddef.h>

namespace {

#include "rtgum-dex-fixture.inc"

/* Kept in the module's writable image instead of the deferred pthread stack:
 * the large-span acceptance fixture can exceed 512 KiB. Its contents are
 * still destroyed immediately after load_dex returns. */
unsigned char g_disposable_source[kRtgumDexFixtureSize]{};

GhostApi *g_api = nullptr;
const HostApiV2 *g_host = nullptr;
unsigned long g_live_handle = 0;

using GetCreatedJavaVMs = jint (*)(JavaVM **, jsize, jsize *);

struct AttachedEnv final {
    JavaVM *vm;
    JNIEnv *env;
    bool attached_here;
};

void PublishFailure(const char *message)
{
    if (g_api && g_api->status)
        g_api->status(RTGUM_DAEMON_STATUS_EXTRA, RTGUM_MODULE_EXTRA_DEX_FAILED);
    if (g_api && g_api->log) g_api->log(message);
}

bool PackageReady()
{
    if (!g_api || !g_api->cmdline) return false;
    char cmdline[256];
    const long length = g_api->cmdline(cmdline, sizeof(cmdline));
    const char expected[] = "dev.rtgum.lab";
    if (length <= 0) return false;
    unsigned long index = 0;
    while (expected[index] != '\0' && cmdline[index] == expected[index]) ++index;
    return expected[index] == '\0' && cmdline[index] == '\0';
}

bool Attach(AttachedEnv &attached)
{
    attached = {};
    unsigned long address = 0;
    if (!g_host || !g_host->find_export ||
        g_host->find_export("libart.so", "JNI_GetCreatedJavaVMs", &address) != 0 ||
        address == 0)
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

bool ClearException(JNIEnv *env)
{
    if (!env || !env->ExceptionCheck()) return true;
    env->ExceptionClear();
    return false;
}

bool InvokeInt(JNIEnv *env, jclass klass, const char *name,
               const char *signature, jint expected)
{
    jmethodID method = env->GetStaticMethodID(klass, name, signature);
    if (!method || !ClearException(env)) return false;
    jint value = 0;
    if (signature[1] == 'I')
        value = env->CallStaticIntMethod(klass, method, 1, 2);
    else
        value = env->CallStaticIntMethod(klass, method);
    return ClearException(env) && value == expected;
}

bool LoadAndCheck(JNIEnv *env, unsigned int use_app_parent,
                  jint expected_app_visibility)
{
    /* Use a disposable source rather than the module's embedded .rodata.
     * Destroy it as soon as load_dex returns: every later lookup/invocation
     * therefore proves that the Daemon made its own ghost copy and that ART
     * no longer depends on the caller's input storage. */
    for (unsigned long index = 0; index < kRtgumDexFixtureSize; ++index)
        g_disposable_source[index] = kRtgumDexFixture[index];
    unsigned long handle = 0;
    long result = RTGUM_HOST_ERR_BUSY;
    for (unsigned int attempt = 0; attempt < 8000U; ++attempt) {
        result = g_host->load_dex(g_disposable_source, kRtgumDexFixtureSize,
                                  use_app_parent, &handle);
        if (result == 0) break;
        if (result != RTGUM_HOST_ERR_BUSY) return false;
        if (g_host->sleep_ms) (void)g_host->sleep_ms(5U);
    }
    if (result != 0 || handle == 0) return false;
    for (unsigned long index = 0; index < kRtgumDexFixtureSize; ++index)
        g_disposable_source[index] = 0;
    g_live_handle = handle;

    unsigned long first = 0;
    unsigned long second = 0;
    if (g_host->find_class_from_dex(handle, "dev/rtgum/dex/LoadedDexProbe",
                                    &first) != 0 || first == 0 ||
        g_host->find_class_from_dex(handle, "Ldev.rtgum.dex.LoadedDexProbe;",
                                    &second) != 0 || second != first) {
        return false;
    }
    unsigned long missing = 1;
    if (g_host->find_class_from_dex(handle, "dev/rtgum/dex/Missing", &missing) !=
            RTGUM_HOST_ERR_NOENT ||
        missing != 0 || env->ExceptionCheck()) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        return false;
    }

    auto klass = reinterpret_cast<jclass>(first);
    if (!InvokeInt(env, klass, "answer", "(II)I", 42) ||
        !InvokeInt(env, klass, "appVisible", "()I", expected_app_visibility))
        return false;

    if (g_host->unload_dex(handle) != 0 || g_host->unload_dex(handle) != 0)
        return false;
    g_live_handle = 0;
    unsigned long stale = 1;
    return g_host->find_class_from_dex(handle, "dev/rtgum/dex/LoadedDexProbe",
                                       &stale) == RTGUM_HOST_ERR_BADF &&
           stale == 0;
}

void RunDexAcceptance(void *)
{
    for (unsigned int attempt = 0; attempt < 5000U && !PackageReady(); ++attempt) {
        if (g_host && g_host->sleep_ms) (void)g_host->sleep_ms(2U);
    }
    if (!PackageReady()) {
        PublishFailure("rtgum-dex-module: package identity unavailable");
        return;
    }

    unsigned char invalid[112]{};
    unsigned long invalid_handle = 1;
    if (g_host->load_dex(invalid, sizeof(invalid), 0U, &invalid_handle) !=
            RTGUM_HOST_ERR_INVAL ||
        invalid_handle != 0) {
        PublishFailure("rtgum-dex-module: invalid image accepted");
        return;
    }

    AttachedEnv attached{};
    if (!Attach(attached)) {
        PublishFailure("rtgum-dex-module: JNI attach failed");
        return;
    }
    if (!LoadAndCheck(attached.env, 0U, -1)) {
        PublishFailure("rtgum-dex-module: isolated parent check failed");
        if (g_live_handle) (void)g_host->unload_dex(g_live_handle);
        g_live_handle = 0;
        Detach(attached);
        return;
    }
    if (!LoadAndCheck(attached.env, 1U, 3)) {
        PublishFailure("rtgum-dex-module: app parent check failed");
        if (g_live_handle) (void)g_host->unload_dex(g_live_handle);
        g_live_handle = 0;
        Detach(attached);
        return;
    }
    Detach(attached);
    g_api->status(RTGUM_DAEMON_STATUS_EXTRA, RTGUM_MODULE_EXTRA_DEX_READY);
    g_api->log(
        "rtgum-dex-module: source-decoupled=1 isolated=1 app-parent=1 unload=1 PASS");
}

}  // namespace

extern "C" __attribute__((visibility("default"))) void ghostEntry(GhostApi *api)
{
    if (!api || api->version != RTGUM_GHOST_API_VERSION || !api->host) return;
    g_api = api;
    g_host = api->host;
    const unsigned long required_size =
        static_cast<unsigned long>(offsetof(HostApiV2, unload_dex) +
                                   sizeof(g_host->unload_dex));
    if (g_host->version != RTGUM_HOST_API_V2_VERSION ||
        g_host->size < required_size ||
        (g_host->capabilities &
         (RTGUM_HOST_CAP_FIND_EXPORT | RTGUM_HOST_CAP_DEFER |
          RTGUM_HOST_CAP_LOAD_DEX)) !=
            (RTGUM_HOST_CAP_FIND_EXPORT | RTGUM_HOST_CAP_DEFER |
             RTGUM_HOST_CAP_LOAD_DEX) ||
        !g_host->find_export || !g_host->defer || !g_host->load_dex ||
        !g_host->find_class_from_dex || !g_host->unload_dex) {
        PublishFailure("rtgum-dex-module: host DEX ABI unavailable");
        return;
    }
    if (g_host->defer(RunDexAcceptance, nullptr) != 0) {
        PublishFailure("rtgum-dex-module: defer failed");
        return;
    }
    api->status(RTGUM_DAEMON_STATUS_EXTRA, RTGUM_MODULE_EXTRA_POLL_ARMED);
    api->log("rtgum-dex-module: acceptance armed");
}

extern "C" __attribute__((visibility("default"))) void ghostModuleUnload(GhostApi *api)
{
    if (g_host && g_host->unload_dex && g_live_handle != 0) {
        (void)g_host->unload_dex(g_live_handle);
        g_live_handle = 0;
    }
    if (api && api->log) api->log("rtgum-dex-module: unload");
}
