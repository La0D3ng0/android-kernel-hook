/*
 * Visible-path Java rewrite of the owned JNICode APK.
 * LSPlant owns ART-version adaptation. Inline hooks use HostApiV2's native
 * backend. libart symbols come from .dynsym and .symtab. This does not hide
 * mappings or guess ArtMethod field offsets.
 */

#include "rtgum/elf_symbols.hpp"
#include "rtgum/gtrace.hpp"
#include "rtgum/host_api_v2.h"
#include "rtgum/native_backend.hpp"

#include "art_hook/class_factory.h"
#include "art_hook/dex.h"
#include "art_hook/lsplant_backend.h"
#include "art_hook/status.h"
#include "art_hook/vm.h"

#include <android/api-level.h>
#include <android/log.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <fcntl.h>
#include <jni.h>
#include <memory>
#include <mutex>
#include <pthread.h>
#include <string>
#include <string_view>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace {

constexpr const char *kTag = "rtgum-m3";
constexpr unsigned int kMaxJavaHooks = 8U;
constexpr unsigned int kMaxDex = 4U;

void Log(const char *message)
{
    __android_log_print(ANDROID_LOG_INFO, kTag, "%s", message);
}

void CopyMessage(const std::string &message, char *output, std::size_t output_size)
{
    if (!output || output_size == 0) return;
    const std::size_t length =
        message.size() < output_size - 1U ? message.size() : output_size - 1U;
    std::memcpy(output, message.data(), length);
    output[length] = '\0';
}

int Fail(const art_hook::Status &status, char *output, std::size_t output_size)
{
    CopyMessage(status.ToString(), output, output_size);
    Log(status.ToString().c_str());
    return static_cast<int>(status.code());
}

int FailMessage(const char *message, char *output, std::size_t output_size)
{
    return Fail({art_hook::StatusCode::kPlatformError, message}, output, output_size);
}

long OpenRead(const char *path)
{
    return open(path, O_RDONLY | O_CLOEXEC);
}

long ReadFd(long fd, void *buffer, unsigned long size)
{
    const ssize_t count = read(static_cast<int>(fd), buffer, static_cast<size_t>(size));
    return count;
}

long CloseFd(long fd)
{
    return close(static_cast<int>(fd));
}

long MapAnonymous(unsigned long size, unsigned long protection)
{
    void *address = mmap(nullptr, static_cast<size_t>(size), static_cast<int>(protection),
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (address == MAP_FAILED) return -static_cast<long>(errno);
    return reinterpret_cast<long>(address);
}

long Protect(unsigned long address, unsigned long size, unsigned long protection)
{
    if (mprotect(reinterpret_cast<void *>(address), static_cast<size_t>(size),
                 static_cast<int>(protection)) != 0) {
        return -static_cast<long>(errno);
    }
    return 0;
}

long Unmap(unsigned long address, unsigned long size)
{
    return munmap(reinterpret_cast<void *>(address), static_cast<size_t>(size)) == 0
               ? 0
               : -static_cast<long>(errno);
}

void ClearCache(unsigned long address, unsigned long size)
{
    __builtin___clear_cache(reinterpret_cast<char *>(address),
                            reinterpret_cast<char *>(address + size));
}

rtgum::native::MemoryOps MakeOps()
{
    rtgum::native::MemoryOps ops{};
    ops.open_read = OpenRead;
    ops.read = ReadFd;
    ops.close = CloseFd;
    ops.mmap = MapAnonymous;
    ops.mprotect = Protect;
    ops.munmap = Unmap;
    ops.clear_cache = ClearCache;
    return ops;
}

struct MappedFile {
    const unsigned char *data = nullptr;
    unsigned long size = 0;
    void *map = nullptr;
    unsigned long map_size = 0;

    void Reset()
    {
        if (map && map != MAP_FAILED) {
            munmap(map, static_cast<size_t>(map_size));
        }
        data = nullptr;
        size = 0;
        map = nullptr;
        map_size = 0;
    }
};

bool MapPath(const char *path, MappedFile *out, std::string *error)
{
    const int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        *error = std::string("open(") + path + ") errno=" + std::to_string(errno);
        return false;
    }
    struct stat info {};
    if (fstat(fd, &info) != 0 || info.st_size <= 0) {
        const int saved = errno;
        close(fd);
        *error = std::string("fstat(") + path + ") errno=" + std::to_string(saved);
        return false;
    }
    const auto bytes = static_cast<unsigned long>(info.st_size);
    void *mapped = mmap(nullptr, static_cast<size_t>(bytes), PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (mapped == MAP_FAILED) {
        *error = std::string("mmap(") + path + ") errno=" + std::to_string(errno);
        return false;
    }
    out->Reset();
    out->map = mapped;
    out->map_size = bytes;
    out->data = static_cast<const unsigned char *>(mapped);
    out->size = bytes;
    return true;
}

bool ReadSelfMaps(std::string *maps, std::string *error)
{
    const int fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        *error = std::string("open(maps) errno=") + std::to_string(errno);
        return false;
    }
    maps->clear();
    char chunk[4096];
    for (;;) {
        const ssize_t count = read(fd, chunk, sizeof(chunk));
        if (count < 0) {
            const int saved = errno;
            close(fd);
            *error = std::string("read(maps) errno=") + std::to_string(saved);
            return false;
        }
        if (count == 0) break;
        maps->append(chunk, static_cast<std::size_t>(count));
    }
    close(fd);
    return true;
}

bool FindLibartPath(const std::string &maps, std::string *path)
{
    const char *line = maps.c_str();
    while (*line != '\0') {
        const char *newline = line;
        while (*newline != '\0' && *newline != '\n') ++newline;
        rtgum::native::MapsRegion region{};
        if (rtgum::native::ParseMapsRegion(line, newline, &region) &&
            rtgum::native::PathHasSoname(region.path, "libart.so")) {
            *path = region.path;
            return true;
        }
        line = (*newline == '\n') ? newline + 1 : newline;
    }
    return false;
}

struct JavaSlot {
    unsigned long handle = 0;
    unsigned int generation = 0;
    bool used = false;
    std::unique_ptr<art_hook::LsplantHook> hook;
    jobject backup = nullptr;
};

struct DexSlot {
    unsigned long handle = 0;
    unsigned int generation = 0;
    bool used = false;
    jobject loader = nullptr;
    jobject klass = nullptr;
};

struct State {
    std::recursive_mutex mutex;
    JavaVM *vm = nullptr;
    rtgum::native::Engine native;
    MappedFile art;
    unsigned long art_bias = 0;
    unsigned long art_min_vaddr = 0;
    std::unique_ptr<art_hook::LsplantBackend> lsplant;
    jobject hooker = nullptr;
    jobject callback = nullptr;
    jobject binder_hooker = nullptr;
    jobject binder_callback = nullptr;
    unsigned long binder_handle = 0;
    JavaSlot java_slots[kMaxJavaHooks]{};
    DexSlot dex_slots[kMaxDex]{};
    unsigned int next_generation = 1;
    unsigned int next_dex_generation = 1;
    unsigned long binder_calls = 0;
    bool native_ready = false;
    bool art_ready = false;
};

State g_state;

struct JavaPoller {
    char jni_class[128]{};
    char name[64]{};
    char signature[128]{};
    unsigned long handle = 0;
    long rc = RTGUM_HOST_ERR_BUSY;
    bool started = false;
    bool done = false;
};

JavaPoller g_poller;

bool CopyCString(char *destination, std::size_t capacity, const char *source)
{
    if (!destination || capacity == 0 || !source) return false;
    const std::size_t length = std::strlen(source);
    if (length + 1U > capacity) return false;
    std::memcpy(destination, source, length + 1U);
    return true;
}

bool CmdlineIsPackage()
{
    const int fd = open("/proc/self/cmdline", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    char buffer[256]{};
    const ssize_t count = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);
    if (count <= 0) return false;
    return std::strcmp(buffer, "com.laodeng.jnicode") == 0;
}

void *ResolveArt(std::string_view name)
{
    if (!g_state.art_ready || name.empty()) return nullptr;
    std::string owned(name);
    unsigned long vaddr = 0;
    if (rtgum::native::LookupSymbolInElfFile(g_state.art.data, g_state.art.size, owned.c_str(),
                                             &vaddr) != 0) {
        if (rtgum::native::LookupSymbolInElfSymtab(g_state.art.data, g_state.art.size,
                                                   owned.c_str(), &vaddr) != 0) {
            return nullptr;
        }
    }
    return reinterpret_cast<void *>(g_state.art_bias + (vaddr - g_state.art_min_vaddr));
}

void *ResolveArtPrefix(std::string_view prefix)
{
    if (!g_state.art_ready || prefix.empty()) return nullptr;
    std::string owned(prefix);
    unsigned long vaddr = 0;
    if (rtgum::native::LookupSymbolPrefixInElfSymtab(g_state.art.data, g_state.art.size,
                                                     owned.c_str(), &vaddr) != 0) {
        return nullptr;
    }
    return reinterpret_cast<void *>(g_state.art_bias + (vaddr - g_state.art_min_vaddr));
}

void *InlineHooker(void *target, void *replacement)
{
    if (!target || !replacement) return nullptr;
    unsigned long original = 0;
    unsigned long handle = 0;
    const long status = g_state.native.Replace(reinterpret_cast<unsigned long>(target),
                                               reinterpret_cast<unsigned long>(replacement),
                                               &original, &handle);
    if (status != 0) {
        __android_log_print(ANDROID_LOG_ERROR, kTag,
                            "inline hook %p -> %p failed rc=%ld step=%d", target, replacement,
                            status, g_state.native.last_step);
        return nullptr;
    }
    return reinterpret_cast<void *>(original);
}

bool InlineUnhooker(void *target)
{
    if (!target) return false;
    const long status = g_state.native.RevertByTarget(reinterpret_cast<unsigned long>(target));
    return status == 0 || status == RTGUM_HOST_ERR_NOENT;
}

art_hook::Status EnsureNativeEngine()
{
    if (g_state.native_ready) return art_hook::Status::Ok();
    g_state.native.ops = MakeOps();
    g_state.native.Reset();
    g_state.native_ready = true;
    return art_hook::Status::Ok();
}

art_hook::Status EnsureArtImage()
{
    if (g_state.art_ready) return art_hook::Status::Ok();
    std::string maps;
    std::string error;
    if (!ReadSelfMaps(&maps, &error)) {
        return {art_hook::StatusCode::kIoError, error};
    }
    std::string path;
    if (!FindLibartPath(maps, &path)) {
        return {art_hook::StatusCode::kNotFound, "libart.so is not mapped"};
    }
    unsigned long bias = 0;
    if (rtgum::native::FindSonameLoadBias(maps.c_str(), "libart.so", &bias) != 0) {
        return {art_hook::StatusCode::kNotFound, "libart.so load bias is missing"};
    }
    if (!MapPath(path.c_str(), &g_state.art, &error)) {
        return {art_hook::StatusCode::kIoError, error};
    }
    g_state.art_bias = bias;
    g_state.art_min_vaddr = rtgum::native::MinPtLoadVaddr(g_state.art.data, g_state.art.size);
    g_state.art_ready = true;
    return art_hook::Status::Ok();
}

JNIEnv *AttachEnv(JNIEnv *env)
{
    if (env != nullptr) {
        JavaVM *vm = nullptr;
        if (env->GetJavaVM(&vm) == JNI_OK) g_state.vm = vm;
        return env;
    }
    JavaVM *vm = g_state.vm;
    if (vm == nullptr) {
        using GetCreated = jint (*)(JavaVM **, jsize, jsize *);
        auto *get_created = reinterpret_cast<GetCreated>(dlsym(RTLD_DEFAULT, "JNI_GetCreatedJavaVMs"));
        if (get_created == nullptr) return nullptr;
        JavaVM *vms[1]{};
        jsize count = 0;
        if (get_created(vms, 1, &count) != JNI_OK || count <= 0 || vms[0] == nullptr) return nullptr;
        vm = vms[0];
        g_state.vm = vm;
    }
    JNIEnv *attached = nullptr;
    const jint got = vm->GetEnv(reinterpret_cast<void **>(&attached), JNI_VERSION_1_6);
    if (got == JNI_OK) return attached;
    if (vm->AttachCurrentThread(&attached, nullptr) == JNI_OK) return attached;
    return nullptr;
}

std::string JniToDotted(const char *jni_name)
{
    std::string dotted(jni_name ? jni_name : "");
    for (char &c : dotted) {
        if (c == '/') c = '.';
    }
    return dotted;
}

jobject AppClassLoader(JNIEnv *env)
{
    art_hook::Env wrapped(env);
    auto thread_class = wrapped.FindClass("android/app/ActivityThread");
    if (!thread_class.ok()) return nullptr;
    jclass klass = thread_class.value().get();

    jmethodID current_app = env->GetStaticMethodID(
        klass, "currentApplication", "()Landroid/app/Application;");
    if (current_app == nullptr) {
        env->ExceptionClear();
    } else {
        jobject app = env->CallStaticObjectMethod(klass, current_app);
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (app != nullptr) {
            jclass app_class = env->GetObjectClass(app);
            jmethodID get_loader =
                env->GetMethodID(app_class, "getClassLoader", "()Ljava/lang/ClassLoader;");
            if (get_loader != nullptr) {
                jobject loader = env->CallObjectMethod(app, get_loader);
                if (!env->ExceptionCheck() && loader != nullptr) return loader;
            }
            env->ExceptionClear();
        }
    }

    jmethodID current_thread = env->GetStaticMethodID(
        klass, "currentActivityThread", "()Landroid/app/ActivityThread;");
    if (current_thread == nullptr) {
        env->ExceptionClear();
        return nullptr;
    }
    jobject at = env->CallStaticObjectMethod(klass, current_thread);
    if (env->ExceptionCheck() || at == nullptr) {
        env->ExceptionClear();
        return nullptr;
    }
    jclass at_class = env->GetObjectClass(at);
    jfieldID bound_field = env->GetFieldID(
        at_class, "mBoundApplication", "Landroid/app/ActivityThread$AppBindData;");
    if (bound_field == nullptr) {
        env->ExceptionClear();
        return nullptr;
    }
    jobject bound = env->GetObjectField(at, bound_field);
    if (bound == nullptr) return nullptr;
    jclass bound_class = env->GetObjectClass(bound);
    jfieldID info_field = env->GetFieldID(bound_class, "info", "Landroid/app/LoadedApk;");
    if (info_field == nullptr) {
        env->ExceptionClear();
        return nullptr;
    }
    jobject loaded = env->GetObjectField(bound, info_field);
    if (loaded == nullptr) return nullptr;
    jclass loaded_class = env->GetObjectClass(loaded);
    jmethodID get_loader =
        env->GetMethodID(loaded_class, "getClassLoader", "()Ljava/lang/ClassLoader;");
    if (get_loader == nullptr) {
        env->ExceptionClear();
        return nullptr;
    }
    jobject loader = env->CallObjectMethod(loaded, get_loader);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        return nullptr;
    }
    return loader;
}

art_hook::Status FindAppClass(JNIEnv *env, const char *jni_name, jclass *out_class)
{
    jobject loader = AppClassLoader(env);
    if (loader == nullptr) {
        return {art_hook::StatusCode::kNotFound, "app ClassLoader is not ready"};
    }
    art_hook::Env wrapped(env);
    auto class_class = wrapped.FindClass("java/lang/Class");
    if (!class_class.ok()) return class_class.status();
    jmethodID for_name = env->GetStaticMethodID(
        class_class.value().get(), "forName",
        "(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;");
    if (for_name == nullptr) {
        return wrapped.ExceptionStatus("Class.forName");
    }
    const std::string dotted = JniToDotted(jni_name);
    jstring name = env->NewStringUTF(dotted.c_str());
    if (name == nullptr) {
        return wrapped.ExceptionStatus("NewStringUTF(class name)");
    }
    jobject klass = env->CallStaticObjectMethod(class_class.value().get(), for_name, name,
                                                JNI_FALSE, loader);
    env->DeleteLocalRef(name);
    if (env->ExceptionCheck() || klass == nullptr) {
        return wrapped.ExceptionStatus("Class.forName(app class)");
    }
    *out_class = static_cast<jclass>(klass);
    return art_hook::Status::Ok();
}

art_hook::Status EnsureLsplant(JNIEnv *env)
{
    if (g_state.lsplant) return art_hook::Status::Ok();
    JavaVM *vm = g_state.vm;
    if (vm == nullptr && env->GetJavaVM(&vm) != JNI_OK) {
        return {art_hook::StatusCode::kJniError, "JNIEnv::GetJavaVM failed"};
    }
    g_state.vm = vm;
    art_hook::LsplantBackendConfig config;
    config.inline_hooker = InlineHooker;
    config.inline_unhooker = InlineUnhooker;
    config.art_symbol_resolver = ResolveArt;
    config.art_symbol_prefix_resolver = ResolveArtPrefix;
    config.use_custom_arm64_bridge = true;
    auto backend = art_hook::LsplantBackend::Create(art_hook::Vm(vm), art_hook::Env(env), config);
    if (!backend.ok()) return backend.status();
    g_state.lsplant = std::move(backend).value();
    return art_hook::Status::Ok();
}

art_hook::Status EnsureHooker(JNIEnv *env)
{
    if (g_state.hooker && g_state.callback) return art_hook::Status::Ok();
    art_hook::Env wrapped(env);
    art_hook::DexClassSpec spec;
    spec.name = "Lrtgum/JniCodeOnCreateHook;";
    spec.methods.push_back({"callback",
                            "Ljava/lang/Object;",
                            {"[Ljava/lang/Object;"},
                            art_hook::kDexAccPublic | art_hook::kDexAccNative});
    art_hook::DexBuilder builder;
    auto dex = builder.Build(std::move(spec));
    if (!dex.ok()) return dex.status();

    jobject app_loader = AppClassLoader(env);
    if (app_loader == nullptr) {
        return {art_hook::StatusCode::kNotFound, "app ClassLoader is not ready"};
    }

    art_hook::ClassFactory factory(wrapped);
    auto dex_loader = factory.LoadDex(dex.value(), app_loader);
    if (!dex_loader.ok()) return dex_loader.status();
    auto hooker_class = factory.LoadClass(dex_loader.value().get(), "rtgum.JniCodeOnCreateHook");
    if (!hooker_class.ok()) return hooker_class.status();

    JNINativeMethod native_method{};
    native_method.name = const_cast<char *>("callback");
    native_method.signature = const_cast<char *>("([Ljava/lang/Object;)Ljava/lang/Object;");
    native_method.fnPtr = reinterpret_cast<void *>(+[](JNIEnv *jni, jobject, jobjectArray args)
                                                       -> jobject {
        if (!args) return nullptr;
        const jsize count = jni->GetArrayLength(args);
        jobject activity = count > 0 ? jni->GetObjectArrayElement(args, 0) : nullptr;
        jobject bundle = count > 1 ? jni->GetObjectArrayElement(args, 1) : nullptr;
        jobject backup = nullptr;
        {
            std::lock_guard lock(g_state.mutex);
            for (auto &slot : g_state.java_slots) {
                if (slot.used && slot.backup != nullptr) {
                    backup = slot.backup;
                    break;
                }
            }
        }
        if (backup != nullptr && activity != nullptr) {
            jclass method_class = jni->FindClass("java/lang/reflect/Method");
            jmethodID set_accessible =
                jni->GetMethodID(method_class, "setAccessible", "(Z)V");
            jni->CallVoidMethod(backup, set_accessible, JNI_TRUE);
            jmethodID invoke = jni->GetMethodID(
                method_class, "invoke",
                "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;");
            jclass object_class = jni->FindClass("java/lang/Object");
            jobjectArray invoke_args = jni->NewObjectArray(1, object_class, bundle);
            jni->CallObjectMethod(backup, invoke, activity, invoke_args);
            if (jni->ExceptionCheck()) {
                jni->ExceptionDescribe();
                jni->ExceptionClear();
            }
        }
        if (activity == nullptr) return nullptr;
        jclass id_class = jni->FindClass("com/laodeng/jnicode/R$id");
        if (id_class == nullptr) {
            jni->ExceptionClear();
            return nullptr;
        }
        jfieldID sample = jni->GetStaticFieldID(id_class, "sample_text", "I");
        if (sample == nullptr) {
            jni->ExceptionClear();
            return nullptr;
        }
        const jint view_id = jni->GetStaticIntField(id_class, sample);
        jclass activity_class = jni->FindClass("android/app/Activity");
        jmethodID find_view =
            jni->GetMethodID(activity_class, "findViewById", "(I)Landroid/view/View;");
        jobject view = jni->CallObjectMethod(activity, find_view, view_id);
        if (view == nullptr || jni->ExceptionCheck()) {
            jni->ExceptionClear();
            return nullptr;
        }
        jclass text_view = jni->FindClass("android/widget/TextView");
        jmethodID set_text =
            jni->GetMethodID(text_view, "setText", "(Ljava/lang/CharSequence;)V");
        jstring replacement = jni->NewStringUTF(RTGUM_JAVA_REPLACEMENT_TEXT);
        jni->CallVoidMethod(view, set_text, replacement);
        if (jni->ExceptionCheck()) {
            jni->ExceptionDescribe();
            jni->ExceptionClear();
        }
        return nullptr;
    });
    if (env->RegisterNatives(hooker_class.value().get(), &native_method, 1) != JNI_OK) {
        return wrapped.ExceptionStatus("RegisterNatives(callback)");
    }
    jmethodID constructor = env->GetMethodID(hooker_class.value().get(), "<init>", "()V");
    if (constructor == nullptr) {
        return wrapped.ExceptionStatus("JniCodeOnCreateHook.<init>");
    }
    jobject hooker = env->NewObject(hooker_class.value().get(), constructor);
    if (hooker == nullptr) {
        return wrapped.ExceptionStatus("new JniCodeOnCreateHook");
    }
    jmethodID callback_id = env->GetMethodID(hooker_class.value().get(), "callback",
                                             "([Ljava/lang/Object;)Ljava/lang/Object;");
    if (callback_id == nullptr) {
        return wrapped.ExceptionStatus("callback method id");
    }
    jobject callback =
        env->ToReflectedMethod(hooker_class.value().get(), callback_id, JNI_FALSE);
    if (callback == nullptr) {
        return wrapped.ExceptionStatus("ToReflectedMethod(callback)");
    }
    g_state.hooker = env->NewGlobalRef(hooker);
    g_state.callback = env->NewGlobalRef(callback);
    env->DeleteLocalRef(hooker);
    env->DeleteLocalRef(callback);
    if (g_state.hooker == nullptr || g_state.callback == nullptr) {
        return {art_hook::StatusCode::kResourceExhausted, "global ref for hooker failed"};
    }
    return art_hook::Status::Ok();
}

long HostStatus(const art_hook::Status &status)
{
    switch (status.code()) {
        case art_hook::StatusCode::kOk:
            return 0;
        case art_hook::StatusCode::kInvalidArgument:
            return RTGUM_HOST_ERR_INVAL;
        case art_hook::StatusCode::kNotFound:
            return RTGUM_HOST_ERR_NOENT;
        case art_hook::StatusCode::kUnsupported:
        case art_hook::StatusCode::kUnavailable:
            return RTGUM_HOST_ERR_NOTSUP;
        case art_hook::StatusCode::kResourceExhausted:
            return RTGUM_HOST_ERR_NOMEM;
        default:
            return RTGUM_HOST_ERR_NXIO;
    }
}

long JavaReplace(void *raw_env,
                 void *reflected_method,
                 void *hooker_object,
                 void *callback_method,
                 unsigned long *out_handle)
{
    std::lock_guard lock(g_state.mutex);
    if (!raw_env || !reflected_method || !hooker_object || !callback_method || !out_handle) {
        return RTGUM_HOST_ERR_INVAL;
    }
    if (!g_state.lsplant) return RTGUM_HOST_ERR_NOTSUP;
    JNIEnv *env = static_cast<JNIEnv *>(raw_env);
    int free_index = -1;
    for (unsigned int index = 0; index < kMaxJavaHooks; ++index) {
        if (!g_state.java_slots[index].used) {
            free_index = static_cast<int>(index);
            break;
        }
    }
    if (free_index < 0) return RTGUM_HOST_ERR_BUSY;
    auto hooked = g_state.lsplant->Hook(art_hook::Env(env), static_cast<jobject>(reflected_method),
                                        static_cast<jobject>(hooker_object),
                                        static_cast<jobject>(callback_method));
    if (!hooked.ok()) return RTGUM_HOST_ERR_NXIO;
    JavaSlot &slot = g_state.java_slots[static_cast<unsigned int>(free_index)];
    slot.hook = std::move(hooked).value();
    slot.backup = slot.hook->backup_method();
    slot.used = true;
    slot.generation = g_state.next_generation++;
    if (g_state.next_generation == 0U) g_state.next_generation = 1U;
    slot.handle = (static_cast<unsigned long>(slot.generation) << 8) |
                  (static_cast<unsigned long>(free_index) + 1UL);
    *out_handle = slot.handle;
    return 0;
}

long JavaRevert(unsigned long handle)
{
    std::lock_guard lock(g_state.mutex);
    if (handle == 0) return RTGUM_HOST_ERR_BADF;
    const unsigned int slot_id = static_cast<unsigned int>(handle & 0xffUL);
    if (slot_id == 0 || slot_id > kMaxJavaHooks) return RTGUM_HOST_ERR_BADF;
    JavaSlot &slot = g_state.java_slots[slot_id - 1U];
    if (!slot.used || slot.handle != handle) return RTGUM_HOST_ERR_BADF;
    const art_hook::Status status = slot.hook->Unhook();
    slot.hook.reset();
    slot.backup = nullptr;
    slot.used = false;
    slot.handle = 0;
    return status.ok() ? 0 : RTGUM_HOST_ERR_NXIO;
}

long InstallJavaMethod(JNIEnv *env,
                       const char *jni_class,
                       const char *name,
                       const char *signature,
                       unsigned long *out_handle)
{
    if (env->ExceptionCheck()) env->ExceptionClear();
    art_hook::Status status = EnsureNativeEngine();
    if (!status.ok()) return HostStatus(status);
    status = EnsureArtImage();
    if (!status.ok()) return HostStatus(status);
    status = EnsureLsplant(env);
    if (!status.ok()) return HostStatus(status);
    status = EnsureHooker(env);
    if (!status.ok()) return HostStatus(status);
    jclass klass = nullptr;
    status = FindAppClass(env, jni_class, &klass);
    if (!status.ok()) return HostStatus(status);
    jmethodID method = env->GetMethodID(klass, name, signature);
    if (method == nullptr) {
        env->ExceptionClear();
        return RTGUM_HOST_ERR_NOENT;
    }
    jobject reflected = env->ToReflectedMethod(klass, method, JNI_FALSE);
    if (reflected == nullptr) {
        env->ExceptionClear();
        return RTGUM_HOST_ERR_NXIO;
    }
    const long rc = JavaReplace(env, reflected, g_state.hooker, g_state.callback, out_handle);
    env->DeleteLocalRef(reflected);
    if (rc == 0) {
        Log("hook_java_method ok");
    } else {
        __android_log_print(ANDROID_LOG_ERROR, kTag, "hook_java_method rc=%ld", rc);
    }
    return rc;
}

void *JavaPollerMain(void *)
{
    Log("java poller start");
    for (unsigned int attempt = 0; attempt < 5000U; ++attempt) {
        if (CmdlineIsPackage()) break;
        usleep(2000);
    }
    if (!CmdlineIsPackage()) {
        Log("java poller waiting past zygote cmdline");
    } else {
        Log("java poller cmdline ready");
    }

    for (;;) {
        JNIEnv *env = AttachEnv(nullptr);
        if (env != nullptr) {
            if (env->ExceptionCheck()) env->ExceptionClear();
            jobject loader = AppClassLoader(env);
            if (loader != nullptr) {
                env->DeleteLocalRef(loader);
                Log("java poller app ready");
                std::lock_guard lock(g_state.mutex);
                unsigned long handle = 0;
                const long rc = InstallJavaMethod(env, g_poller.jni_class, g_poller.name,
                                                  g_poller.signature, &handle);
                if (rc == 0 ||
                    (rc != RTGUM_HOST_ERR_NOENT && rc != RTGUM_HOST_ERR_BUSY)) {
                    g_poller.handle = handle;
                    g_poller.rc = rc;
                    g_poller.done = true;
                    return nullptr;
                }
            }
        }
        usleep(2000);
    }
}

art_hook::Status EnsureBinderHooker(JNIEnv *env)
{
    if (g_state.binder_hooker && g_state.binder_callback) return art_hook::Status::Ok();
    art_hook::Env wrapped(env);
    art_hook::DexClassSpec spec;
    spec.name = "Lrtgum/BinderTransactHook;";
    spec.methods.push_back({"callback",
                            "Ljava/lang/Object;",
                            {"[Ljava/lang/Object;"},
                            art_hook::kDexAccPublic | art_hook::kDexAccNative});
    art_hook::DexBuilder builder;
    auto dex = builder.Build(std::move(spec));
    if (!dex.ok()) return dex.status();
    jobject app_loader = AppClassLoader(env);
    art_hook::ClassFactory factory(wrapped);
    auto dex_loader = factory.LoadDex(dex.value(), app_loader);
    if (!dex_loader.ok()) return dex_loader.status();
    auto hooker_class = factory.LoadClass(dex_loader.value().get(), "rtgum.BinderTransactHook");
    if (!hooker_class.ok()) return hooker_class.status();
    JNINativeMethod native_method{};
    native_method.name = const_cast<char *>("callback");
    native_method.signature = const_cast<char *>("([Ljava/lang/Object;)Ljava/lang/Object;");
    native_method.fnPtr = reinterpret_cast<void *>(+[](JNIEnv *jni, jobject, jobjectArray args)
                                                       -> jobject {
        jobject backup = nullptr;
        {
            std::lock_guard lock(g_state.mutex);
            ++g_state.binder_calls;
            const unsigned long handle = g_state.binder_handle;
            const unsigned int slot_id = static_cast<unsigned int>(handle & 0xffUL);
            if (slot_id != 0 && slot_id <= kMaxJavaHooks) {
                JavaSlot &slot = g_state.java_slots[slot_id - 1U];
                if (slot.used && slot.handle == handle) backup = slot.backup;
            }
        }
        if (!args || backup == nullptr) return nullptr;
        const jsize count = jni->GetArrayLength(args);
        jobject receiver = count > 0 ? jni->GetObjectArrayElement(args, 0) : nullptr;
        jclass method_class = jni->FindClass("java/lang/reflect/Method");
        jmethodID set_accessible = jni->GetMethodID(method_class, "setAccessible", "(Z)V");
        jni->CallVoidMethod(backup, set_accessible, JNI_TRUE);
        jmethodID invoke = jni->GetMethodID(
            method_class, "invoke", "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;");
        jclass object_class = jni->FindClass("java/lang/Object");
        const jsize rest = count > 1 ? count - 1 : 0;
        jobjectArray invoke_args = jni->NewObjectArray(rest, object_class, nullptr);
        for (jsize index = 0; index < rest; ++index) {
            jobject value = jni->GetObjectArrayElement(args, index + 1);
            jni->SetObjectArrayElement(invoke_args, index, value);
        }
        jobject result = jni->CallObjectMethod(backup, invoke, receiver, invoke_args);
        if (jni->ExceptionCheck()) {
            jni->ExceptionDescribe();
            jni->ExceptionClear();
            return nullptr;
        }
        return result;
    });
    if (env->RegisterNatives(hooker_class.value().get(), &native_method, 1) != JNI_OK) {
        return wrapped.ExceptionStatus("RegisterNatives(binder callback)");
    }
    jmethodID constructor = env->GetMethodID(hooker_class.value().get(), "<init>", "()V");
    if (constructor == nullptr) return wrapped.ExceptionStatus("BinderTransactHook.<init>");
    jobject hooker = env->NewObject(hooker_class.value().get(), constructor);
    if (hooker == nullptr) return wrapped.ExceptionStatus("new BinderTransactHook");
    jmethodID callback_id = env->GetMethodID(hooker_class.value().get(), "callback",
                                             "([Ljava/lang/Object;)Ljava/lang/Object;");
    jobject callback =
        env->ToReflectedMethod(hooker_class.value().get(), callback_id, JNI_FALSE);
    if (callback == nullptr) return wrapped.ExceptionStatus("ToReflectedMethod(binder)");
    g_state.binder_hooker = env->NewGlobalRef(hooker);
    g_state.binder_callback = env->NewGlobalRef(callback);
    env->DeleteLocalRef(hooker);
    env->DeleteLocalRef(callback);
    if (g_state.binder_hooker == nullptr || g_state.binder_callback == nullptr) {
        return {art_hook::StatusCode::kResourceExhausted, "binder hooker global ref failed"};
    }
    return art_hook::Status::Ok();
}

long LoadDexApi(const unsigned char *bytes,
                unsigned long size,
                unsigned int use_app_parent,
                unsigned long *out_handle)
{
    if (!bytes || size == 0 || !out_handle) return RTGUM_HOST_ERR_INVAL;
    *out_handle = 0;
    std::lock_guard lock(g_state.mutex);
    JNIEnv *env = AttachEnv(nullptr);
    if (env == nullptr) return RTGUM_HOST_ERR_NXIO;
    int free_index = -1;
    for (unsigned int index = 0; index < kMaxDex; ++index) {
        if (!g_state.dex_slots[index].used) {
            free_index = static_cast<int>(index);
            break;
        }
    }
    if (free_index < 0) return RTGUM_HOST_ERR_BUSY;
    std::vector<std::uint8_t> dex(bytes, bytes + size);
    art_hook::Env wrapped(env);
    art_hook::ClassFactory factory(wrapped);
    jobject parent = nullptr;
    if (use_app_parent != 0U) parent = AppClassLoader(env);
    auto loader = factory.LoadDex(dex, parent);
    if (!loader.ok()) return HostStatus(loader.status());
    jobject global = env->NewGlobalRef(loader.value().get());
    if (global == nullptr) return RTGUM_HOST_ERR_NOMEM;
    DexSlot &slot = g_state.dex_slots[static_cast<unsigned int>(free_index)];
    slot.used = true;
    slot.loader = global;
    slot.klass = nullptr;
    slot.generation = g_state.next_dex_generation++;
    if (g_state.next_dex_generation == 0U) g_state.next_dex_generation = 1U;
    slot.handle = (static_cast<unsigned long>(slot.generation) << 8) |
                  (static_cast<unsigned long>(free_index) + 1UL);
    *out_handle = slot.handle;
    Log("load_dex ok");
    return 0;
}

long FindClassFromDexApi(unsigned long handle, const char *jni_class, unsigned long *out_class)
{
    if (handle == 0 || !jni_class || !out_class) return RTGUM_HOST_ERR_INVAL;
    *out_class = 0;
    std::lock_guard lock(g_state.mutex);
    const unsigned int slot_id = static_cast<unsigned int>(handle & 0xffUL);
    if (slot_id == 0 || slot_id > kMaxDex) return RTGUM_HOST_ERR_BADF;
    DexSlot &slot = g_state.dex_slots[slot_id - 1U];
    if (!slot.used || slot.handle != handle || slot.loader == nullptr) return RTGUM_HOST_ERR_BADF;
    JNIEnv *env = AttachEnv(nullptr);
    if (env == nullptr) return RTGUM_HOST_ERR_NXIO;
    art_hook::Env wrapped(env);
    art_hook::ClassFactory factory(wrapped);
    auto klass = factory.LoadClass(slot.loader, jni_class);
    if (!klass.ok()) return HostStatus(klass.status());
    jobject global = env->NewGlobalRef(klass.value().get());
    if (global == nullptr) return RTGUM_HOST_ERR_NOMEM;
    if (slot.klass != nullptr) env->DeleteGlobalRef(slot.klass);
    slot.klass = global;
    *out_class = reinterpret_cast<unsigned long>(global);
    return 0;
}

long UnloadDexApi(unsigned long handle)
{
    if (handle == 0) return RTGUM_HOST_ERR_BADF;
    std::lock_guard lock(g_state.mutex);
    const unsigned int slot_id = static_cast<unsigned int>(handle & 0xffUL);
    if (slot_id == 0 || slot_id > kMaxDex) return RTGUM_HOST_ERR_BADF;
    DexSlot &slot = g_state.dex_slots[slot_id - 1U];
    if (!slot.used) return slot.handle == handle ? 0 : RTGUM_HOST_ERR_BADF;
    if (slot.handle != handle) return RTGUM_HOST_ERR_BADF;
    JNIEnv *env = AttachEnv(nullptr);
    if (env != nullptr) {
        if (slot.klass != nullptr) env->DeleteGlobalRef(slot.klass);
        if (slot.loader != nullptr) env->DeleteGlobalRef(slot.loader);
    }
    slot = DexSlot{};
    return 0;
}

long HookBinderApi(unsigned long *out_handle)
{
    if (!out_handle) return RTGUM_HOST_ERR_INVAL;
    *out_handle = 0;
    std::lock_guard lock(g_state.mutex);
    JNIEnv *env = AttachEnv(nullptr);
    if (env == nullptr) return RTGUM_HOST_ERR_NXIO;
    art_hook::Status status = EnsureNativeEngine();
    if (!status.ok()) return HostStatus(status);
    status = EnsureArtImage();
    if (!status.ok()) return HostStatus(status);
    status = EnsureLsplant(env);
    if (!status.ok()) return HostStatus(status);
    status = EnsureBinderHooker(env);
    if (!status.ok()) return HostStatus(status);
    jclass klass = env->FindClass(RTGUM_BINDER_CLASS);
    if (klass == nullptr) {
        env->ExceptionClear();
        return RTGUM_HOST_ERR_NOENT;
    }
    jmethodID method = env->GetMethodID(klass, RTGUM_BINDER_NAME, RTGUM_BINDER_SIG);
    if (method == nullptr) {
        env->ExceptionClear();
        return RTGUM_HOST_ERR_NOENT;
    }
    jobject reflected = env->ToReflectedMethod(klass, method, JNI_FALSE);
    if (reflected == nullptr) {
        env->ExceptionClear();
        return RTGUM_HOST_ERR_NXIO;
    }
    const long rc = JavaReplace(env, reflected, g_state.binder_hooker, g_state.binder_callback,
                                out_handle);
    env->DeleteLocalRef(reflected);
    if (rc == 0) {
        g_state.binder_handle = *out_handle;
        Log("hook_binder ok");
    }
    return rc;
}

long HostGtraceDecode(const unsigned char *code,
                      unsigned long size,
                      unsigned long pc,
                      char *out,
                      unsigned long capacity)
{
    return rtgum::native::GtraceDecode(code, size, pc, out, capacity);
}

long HostGtraceFormatPath(const RtGumGtraceStep *steps,
                          unsigned long count,
                          unsigned long image_start,
                          unsigned long image_end,
                          char *out,
                          unsigned long capacity)
{
    return rtgum::native::GtraceFormatPath(
        steps, count, image_start, image_end, out, capacity);
}

jstring DexProbeMessage(JNIEnv *env, jclass)
{
    return env->NewStringUTF(RTGUM_DEX_PROBE_TEXT);
}

long JavaMethod(void *raw_env,
                const char *jni_class,
                const char *name,
                const char *signature,
                unsigned long *out_handle)
{
    if (!jni_class || !name || !signature || !out_handle) return RTGUM_HOST_ERR_INVAL;
    std::lock_guard lock(g_state.mutex);
    if (raw_env != nullptr) {
        JNIEnv *env = AttachEnv(static_cast<JNIEnv *>(raw_env));
        if (env == nullptr) return RTGUM_HOST_ERR_NXIO;
        return InstallJavaMethod(env, jni_class, name, signature, out_handle);
    }
    if (g_poller.done) {
        if (g_poller.rc == 0) *out_handle = g_poller.handle;
        return g_poller.rc;
    }
    if (!g_poller.started) {
        if (!CopyCString(g_poller.jni_class, sizeof(g_poller.jni_class), jni_class) ||
            !CopyCString(g_poller.name, sizeof(g_poller.name), name) ||
            !CopyCString(g_poller.signature, sizeof(g_poller.signature), signature)) {
            return RTGUM_HOST_ERR_INVAL;
        }
        pthread_t thread {};
        g_poller.started = true;
        if (pthread_create(&thread, nullptr, JavaPollerMain, nullptr) != 0) {
            g_poller.started = false;
            Log("java poller pthread_create failed");
            return RTGUM_HOST_ERR_NXIO;
        }
        pthread_detach(thread);
    }
    return RTGUM_HOST_ERR_BUSY;
}

std::string FormatProbe()
{
    std::string text = "runtime=art";
    text += " api=";
    text += std::to_string(android_get_device_api_level());
    text += " arch=arm64";
    if (g_state.art_ready) {
        text += " art_bias=0x";
        char hex[32];
        std::snprintf(hex, sizeof(hex), "%lx", g_state.art_bias);
        text += hex;
        const char *names[] = {
            "_ZN3art9ArtMethod12PrettyMethodEb",
            "_ZN3art10ThreadList10SuspendAllEPKcb",
            "_ZN3art10ThreadList9ResumeAllEv",
            "_ZN3art11ClassLinker22FixupStaticTrampolinesENS_6HandleINS_6mirror5ClassEEE",
            "_ZN3art15GetMethodShortyEP7_JNIEnvP10_jmethodID",
            "_ZN3artL15GetMethodShortyEP7_JNIEnvP10_jmethodID",
        };
        unsigned int found = 0;
        for (const char *name : names) {
            if (ResolveArt(name) != nullptr) ++found;
        }
        unsigned long prefix = 0;
        const bool prefix_ok =
            rtgum::native::LookupSymbolPrefixInElfSymtab(
                g_state.art.data, g_state.art.size, "_ZN3art9ArtMethod", &prefix) == 0;
        text += " art_symbols=";
        text += std::to_string(found);
        text += "/6 prefix=";
        text += prefix_ok ? "1" : "0";
        text += " lsplant=";
        text += g_state.lsplant ? "1" : "0";
    }
    return text;
}

}  // namespace

extern "C" JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *)
{
    g_state.vm = vm;
    return JNI_VERSION_1_6;
}

extern "C" __attribute__((visibility("default"))) long
rtgum_host_bind_java(HostApiV2 *host)
{
    if (!host || host->version != RTGUM_HOST_API_V2_VERSION) return RTGUM_HOST_ERR_INVAL;
    const unsigned long java_end =
        static_cast<unsigned long>(offsetof(HostApiV2, hook_java_method) +
                                   sizeof(host->hook_java_method));
    if (host->size < java_end) return RTGUM_HOST_ERR_INVAL;
    host->hook_java_replace = JavaReplace;
    host->hook_java_revert = JavaRevert;
    host->hook_java_method = JavaMethod;
    host->capabilities |= RTGUM_HOST_CAP_JAVA_HOOK;
    if (host->size >= static_cast<unsigned long>(offsetof(HostApiV2, gtrace_decode) +
                                                 sizeof(host->gtrace_decode))) {
        /* The stage-2 Daemon owns its ghost-buffer DEX runtime. Keep those
         * callbacks when already present; this visible helper only supplies
         * the legacy standalone fallback used by its own host-binding test. */
        if (host->load_dex == nullptr) host->load_dex = LoadDexApi;
        if (host->find_class_from_dex == nullptr)
            host->find_class_from_dex = FindClassFromDexApi;
        if (host->unload_dex == nullptr) host->unload_dex = UnloadDexApi;
        /* A modern Daemon supplies the native Shadow-Page Binder runtime.
         * Never replace it with this legacy ArtMethod/LSPlant fixture. */
        if (host->hook_binder == nullptr &&
            (host->capabilities & RTGUM_HOST_CAP_BINDER_INTERCEPTOR) == 0UL)
            host->hook_binder = HookBinderApi;
        host->gtrace_decode = HostGtraceDecode;
        host->capabilities |= RTGUM_HOST_CAP_LOAD_DEX | RTGUM_HOST_CAP_BINDER |
                              RTGUM_HOST_CAP_GTRACE;
    }
    if (host->size >= static_cast<unsigned long>(
            offsetof(HostApiV2, gtrace_format_path) +
            sizeof(host->gtrace_format_path))) {
        host->gtrace_format_path = HostGtraceFormatPath;
        host->capabilities |= RTGUM_HOST_CAP_GTRACE_RUNTIME;
    }
    Log("host bind java");
    return 0;
}

extern "C" __attribute__((visibility("default"))) int
rtgum_jnicode_java_probe(JNIEnv *env, char *error, std::size_t error_size)
{
    std::lock_guard lock(g_state.mutex);
    art_hook::Status status = EnsureNativeEngine();
    if (!status.ok()) return Fail(status, error, error_size);
    status = EnsureArtImage();
    if (!status.ok()) return Fail(status, error, error_size);
    JNIEnv *attached = AttachEnv(env);
    if (attached != nullptr) {
        status = EnsureLsplant(attached);
        if (!status.ok()) {
            CopyMessage(FormatProbe() + " lsplant_error=" + status.ToString(), error, error_size);
            Log(error);
            return static_cast<int>(status.code());
        }
    }
    CopyMessage(FormatProbe(), error, error_size);
    Log(error);
    return 0;
}

extern "C" __attribute__((visibility("default"))) int
rtgum_jnicode_java_hook_install(JNIEnv *env, char *error, std::size_t error_size)
{
    Log("install: bind");
    HostApiV2 host{};
    host.version = RTGUM_HOST_API_V2_VERSION;
    host.size = sizeof(HostApiV2);
    if (rtgum_host_bind_java(&host) != 0 || host.hook_java_method == nullptr) {
        return FailMessage("host bind java failed", error, error_size);
    }
    Log("install: method");
    unsigned long handle = 0;
    const long rc = host.hook_java_method(env, RTGUM_JAVA_MAIN_CLASS, RTGUM_JAVA_ONCREATE_NAME,
                                          RTGUM_JAVA_ONCREATE_SIG, &handle);
    if (rc != 0) {
        return Fail({art_hook::StatusCode::kPlatformError,
                     std::string("hook_java_method rc=") + std::to_string(rc) + " " +
                         FormatProbe()},
                    error, error_size);
    }
    CopyMessage(std::string("java onCreate hooked handle=") + std::to_string(handle) + " " +
                    FormatProbe(),
                error, error_size);
    Log(error);
    return 0;
}

extern "C" __attribute__((visibility("default"))) int
rtgum_jnicode_java_hook_revert(char *error, std::size_t error_size)
{
    std::lock_guard lock(g_state.mutex);
    int failures = 0;
    for (auto &slot : g_state.java_slots) {
        if (!slot.used) continue;
        if (JavaRevert(slot.handle) != 0) ++failures;
    }
    if (failures != 0) {
        return FailMessage("java revert incomplete", error, error_size);
    }
    CopyMessage("java onCreate reverted", error, error_size);
    Log(error);
    return 0;
}

extern "C" __attribute__((visibility("default"))) int
rtgum_jnicode_loaddex_selftest(JNIEnv *env, char *error, std::size_t error_size)
{
    HostApiV2 host{};
    host.version = RTGUM_HOST_API_V2_VERSION;
    host.size = sizeof(HostApiV2);
    if (rtgum_host_bind_java(&host) != 0 || host.load_dex == nullptr) {
        return FailMessage("host bind load_dex failed", error, error_size);
    }
    JNIEnv *attached = AttachEnv(env);
    if (attached == nullptr) return FailMessage("loaddex attach failed", error, error_size);
    art_hook::DexClassSpec spec;
    spec.name = "Lcom/laodeng/jnicode/LoadedDexProbe;";
    spec.methods.push_back({RTGUM_DEX_PROBE_METHOD,
                            "Ljava/lang/String;",
                            {},
                            art_hook::kDexAccPublic | art_hook::kDexAccStatic |
                                art_hook::kDexAccNative});
    art_hook::DexBuilder builder;
    auto dex = builder.Build(std::move(spec));
    if (!dex.ok()) return Fail(dex.status(), error, error_size);
    unsigned long handle = 0;
    const long loaded = host.load_dex(dex.value().data(),
                                      static_cast<unsigned long>(dex.value().size()),
                                      1U,
                                      &handle);
    if (loaded != 0 || handle == 0) {
        return Fail({art_hook::StatusCode::kPlatformError,
                     std::string("load_dex rc=") + std::to_string(loaded)},
                    error, error_size);
    }
    unsigned long klass_word = 0;
    const long found =
        host.find_class_from_dex(handle, RTGUM_DEX_PROBE_CLASS, &klass_word);
    if (found != 0 || klass_word == 0) {
        host.unload_dex(handle);
        return Fail({art_hook::StatusCode::kPlatformError,
                     std::string("find_class_from_dex rc=") + std::to_string(found)},
                    error, error_size);
    }
    auto *klass = reinterpret_cast<jclass>(klass_word);
    JNINativeMethod native{};
    native.name = const_cast<char *>(RTGUM_DEX_PROBE_METHOD);
    native.signature = const_cast<char *>(RTGUM_DEX_PROBE_SIG);
    native.fnPtr = reinterpret_cast<void *>(DexProbeMessage);
    if (attached->RegisterNatives(klass, &native, 1) != JNI_OK) {
        host.unload_dex(handle);
        return FailMessage("RegisterNatives(LoadedDexProbe) failed", error, error_size);
    }
    jmethodID method = attached->GetStaticMethodID(klass, RTGUM_DEX_PROBE_METHOD,
                                                   RTGUM_DEX_PROBE_SIG);
    if (method == nullptr) {
        attached->ExceptionClear();
        host.unload_dex(handle);
        return FailMessage("LoadedDexProbe.message missing", error, error_size);
    }
    jstring text = static_cast<jstring>(attached->CallStaticObjectMethod(klass, method));
    if (text == nullptr || attached->ExceptionCheck()) {
        attached->ExceptionClear();
        host.unload_dex(handle);
        return FailMessage("LoadedDexProbe.message returned null", error, error_size);
    }
    const char *utf = attached->GetStringUTFChars(text, nullptr);
    const bool ok = utf != nullptr && std::strcmp(utf, RTGUM_DEX_PROBE_TEXT) == 0;
    if (utf) attached->ReleaseStringUTFChars(text, utf);
    const long unloaded = host.unload_dex(handle);
    if (!ok) return FailMessage("LoadedDexProbe text mismatch", error, error_size);
    if (unloaded != 0) return FailMessage("unload_dex failed", error, error_size);
    CopyMessage("loaddex=1 find_class=1 native=1 unload=1", error, error_size);
    Log(error);
    return 0;
}

extern "C" __attribute__((visibility("default"))) int
rtgum_jnicode_binder_selftest(JNIEnv *env, char *error, std::size_t error_size)
{
    HostApiV2 host{};
    host.version = RTGUM_HOST_API_V2_VERSION;
    host.size = sizeof(HostApiV2);
    if (rtgum_host_bind_java(&host) != 0 || host.hook_binder == nullptr) {
        return FailMessage("host bind binder failed", error, error_size);
    }
    JNIEnv *attached = AttachEnv(env);
    if (attached == nullptr) return FailMessage("binder attach failed", error, error_size);
    (void)attached;
    unsigned long handle = 0;
    const long rc = host.hook_binder(&handle);
    if (rc != 0 || handle == 0) {
        return Fail({art_hook::StatusCode::kPlatformError,
                     std::string("hook_binder rc=") + std::to_string(rc) + " " + FormatProbe()},
                    error, error_size);
    }
    const unsigned long before = g_state.binder_calls;
    jclass sm = attached->FindClass("android/os/ServiceManager");
    if (sm != nullptr) {
        jmethodID get_service = attached->GetStaticMethodID(
            sm, "getService", "(Ljava/lang/String;)Landroid/os/IBinder;");
        if (get_service != nullptr) {
            jstring name = attached->NewStringUTF("package");
            jobject binder = attached->CallStaticObjectMethod(sm, get_service, name);
            if (attached->ExceptionCheck()) attached->ExceptionClear();
            if (name) attached->DeleteLocalRef(name);
            if (binder) attached->DeleteLocalRef(binder);
        } else {
            attached->ExceptionClear();
        }
        attached->DeleteLocalRef(sm);
    } else {
        attached->ExceptionClear();
    }
    const unsigned long intercepted = g_state.binder_calls > before ? 1UL : 0UL;
    const long reverted = JavaRevert(handle);
    g_state.binder_handle = 0;
    if (reverted != 0) {
        return Fail({art_hook::StatusCode::kPlatformError,
                     std::string("binder revert rc=") + std::to_string(reverted)},
                    error, error_size);
    }
    CopyMessage(std::string("binder_hook=1 binder_intercept=") + std::to_string(intercepted) +
                    " binder_revert=1",
                error, error_size);
    Log(error);
    return 0;
}

extern "C" __attribute__((visibility("default"))) int
rtgum_jnicode_gtrace_selftest(char *error, std::size_t error_size)
{
    unsigned char code[24] = {
        0x3f, 0x23, 0x03, 0xd5, /* paciasp */
        0x1f, 0x20, 0x03, 0xd5, /* nop */
        0x00, 0x00, 0x00, 0x14, /* b #0 (self) is not junk; use b #4 */
        0x01, 0x00, 0x00, 0x14, /* b #4 junk */
        0xc0, 0x03, 0x5f, 0xd6, /* ret */
        0x1f, 0x20, 0x03, 0xd5,
    };
    /* bytes 8-11 were b #0; overwrite with a real add then junk b#4 then ret */
    code[8] = 0x00;
    code[9] = 0x00;
    code[10] = 0x00;
    code[11] = 0x91; /* add x0, x0, #0 */
    char text[256]{};
    const long rc = HostGtraceDecode(code, 20, 0x1000UL, text, sizeof(text));
    if (rc != 0 || std::strstr(text, "real=") == nullptr ||
        std::strstr(text, "junk=") == nullptr) {
        return FailMessage("gtrace decode failed", error, error_size);
    }
    CopyMessage(std::string("gtrace=1 ") + text, error, error_size);
    Log(error);
    return 0;
}
