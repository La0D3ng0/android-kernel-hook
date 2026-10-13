/*
 * Visible-path Native rewrite of the owned JNICode APK library.
 * Loads libjnicode.so through the system linker and uses HostApiV2.
 */

#include "rtgum/native_backend.hpp"

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <fcntl.h>
#include <jni.h>
#include <sys/mman.h>
#include <unistd.h>

namespace {

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

const char *g_last_utf = nullptr;
unsigned long g_original = 0;
unsigned long g_calls = 0;

jstring MockNewStringUTF(JNIEnv *, const char *utf)
{
    g_last_utf = utf;
    return reinterpret_cast<jstring>(static_cast<uintptr_t>(0xC0FFEEUL));
}

unsigned long HookedStringFromJni(void *env, unsigned long thiz)
{
    using Original = unsigned long (*)(void *, unsigned long);
    ++g_calls;
    (void)reinterpret_cast<Original>(g_original)(env, thiz);
    void **table = *reinterpret_cast<void ***>(env);
    using NewStringUTFFn = unsigned long (*)(void *, const char *);
    auto *new_string_utf = reinterpret_cast<NewStringUTFFn>(
        table[RTGUM_JNI_NEW_STRING_UTF_INDEX]);
    return new_string_utf(env, RTGUM_JNI_REPLACEMENT_TEXT);
}

int Fail(const char *message)
{
    std::fprintf(stderr, "%s\n", message);
    return 1;
}

}  // namespace

int main(int argc, char **argv)
{
    if (argc != 2) return Fail("usage: rtgum-jnicode-native-hook-test <libjnicode.so>");

    static_assert(offsetof(JNINativeInterface, NewStringUTF) ==
                      RTGUM_JNI_NEW_STRING_UTF_INDEX * sizeof(void *),
                  "JNI NewStringUTF index mismatch");

    void *library = dlopen(argv[1], RTLD_NOW);
    if (!library) {
        std::fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 1;
    }

    rtgum::native::Engine engine;
    engine.ops.open_read = OpenRead;
    engine.ops.read = ReadFd;
    engine.ops.close = CloseFd;
    engine.ops.mmap = MapAnonymous;
    engine.ops.mprotect = Protect;
    engine.ops.munmap = Unmap;
    engine.ops.clear_cache = ClearCache;

    unsigned long target = 0;
    const long found = engine.FindExport("libjnicode.so", RTGUM_JNI_STRING_FROM_JNI, &target);
    if (found != 0 || target == 0) return Fail("find_export failed");

    JNINativeInterface functions{};
    functions.NewStringUTF = MockNewStringUTF;
    JNIEnv env{};
    env.functions = &functions;

    using JniFn = unsigned long (*)(void *, unsigned long);
    auto original = reinterpret_cast<JniFn>(target);
    g_last_utf = nullptr;
    const unsigned long baseline = original(&env, 0);
    if (baseline != 0xC0FFEEUL || g_last_utf == nullptr ||
        std::strcmp(g_last_utf, RTGUM_JNI_ORIGINAL_TEXT) != 0) {
        std::fprintf(stderr, "baseline mismatch utf=%s\n", g_last_utf ? g_last_utf : "(null)");
        return 1;
    }

    unsigned long handle = 0;
    const long replaced = engine.Replace(target,
                                         reinterpret_cast<unsigned long>(HookedStringFromJni),
                                         &g_original,
                                         &handle);
    if (replaced != 0) {
        std::printf("replace failed result=%ld errno=%d target=0x%lx step=%d\n",
                    replaced, errno, target, engine.last_step);
        std::fflush(stdout);
        return 1;
    }

    g_last_utf = nullptr;
    g_calls = 0;
    const unsigned long hooked = original(&env, 0);
    if (g_calls != 1 || hooked != 0xC0FFEEUL ||
        std::strcmp(g_last_utf, RTGUM_JNI_REPLACEMENT_TEXT) != 0) {
        std::fprintf(stderr, "hooked mismatch calls=%lu utf=%s\n",
                     g_calls, g_last_utf ? g_last_utf : "(null)");
        engine.Revert(handle);
        return 1;
    }

    if (engine.Revert(handle) != 0) return Fail("revert failed");
    if (engine.Revert(handle) != 0) return Fail("idempotent revert failed");

    g_last_utf = nullptr;
    const unsigned long restored = original(&env, 0);
    if (restored != 0xC0FFEEUL || std::strcmp(g_last_utf, RTGUM_JNI_ORIGINAL_TEXT) != 0) {
        return Fail("restored value mismatch");
    }

    dlclose(library);
    std::puts("native original=Hello from C++ replacement=Hooked from JNI restored=1");
    std::puts("jnicode-native-hook PASS");
    return 0;
}
