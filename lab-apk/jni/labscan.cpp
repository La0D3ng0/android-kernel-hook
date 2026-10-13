/*
 * libghostlab.so - the Lab's native fixtures and ArtMethod reader.
 *
 * The self-check has to answer two different questions about the same field,
 * and it has to keep them strictly apart:
 *
 *   1. what does an *untrusted reader* see? That is the scanner's view, and the
 *      only honest way to obtain it is a real EL0 load from the Lab's own code:
 *      the kernel routes a data abort by the faulting instruction's PC, so a
 *      load issued here is the thing the Shadow Data Page scheme makes a
 *      decision about. A /proc/self/mem pread is NOT that - it goes through
 *      mem_rw()/access_remote_vm() and never presents the scanner's PC - so it
 *      is kept, clearly named, as a diagnostic transport only.
 *
 *   2. what does the *runtime* see? That value is not readable from user code
 *      at all: it lives in the kernel's shadow copy. It is reported by mako's
 *      own trusted read (art_page_read) and by the kernel counters, and this
 *      library deliberately cannot produce it.
 *
 * The direct load is compiled to a single `ldr` and runs under a sigaction
 * guard, so a page the kernel does not serve produces a reported fault instead
 * of killing the process. The faulting PC and address are taken from the
 * ucontext, which is what the kernel itself classified.
 *
 * The record address is obtained from FromReflectedMethod (the documented way
 * to turn a reflective Method into its ArtMethod). Whether that value really is
 * an address is decided by the caller: this library returns the raw jmethodID
 * token and never presents it as a pointer.
 *
 * On runtimes where FromReflectedMethod returns an indexed jmethodID, the Lab
 * resolves ART's already-mapped DecodeMethodId export from libart's dynsym and
 * uses it only to obtain the record address. Field reads still use the direct
 * untrusted EL0 load above.
 */

#include <jni.h>
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ucontext.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <android/log.h>

#define LAB_LOG(...) \
    __android_log_print(ANDROID_LOG_INFO, "rtgum-labscan", __VA_ARGS__)

extern "C" uint64_t GuardedLoad(const uint64_t *pointer);
extern "C" char rtgum_guarded_load_begin;
extern "C" char rtgum_guarded_load_end;

extern "C" {
int rtgum_gtrace_flower(int left, int right);
extern char rtgum_gtrace_flower_end;

__attribute__((visibility("default"), used, aligned(64)))
volatile uint32_t rtgum_lab_memory_magic = 0x4c414201U;

__attribute__((visibility("default"), used, noinline))
int lab_add(int left, int right)
{
    /* A branch-free trace window longer than both the 64-step acceptance and
     * 160-step ring-overwrite budgets.
     * Keeping the fixture deterministic lets the smoke test require pc[n+1]
     * == pc[n] + 4 while still exercising the real app process and JNI call. */
    asm volatile(
        ".rept 192\n\t"
        "nop\n\t"
        ".endr\n\t"
        ::: "memory");
    return left + right;
}
}

namespace {

/*
 * Guard state is THREAD LOCAL, and that is a correctness requirement rather than
 * an optimisation: a signal handler runs on the faulting thread, so a
 * process-global sigjmp_buf lets one thread's unrelated fault longjmp into
 * another thread's stack - undefined behaviour, and in a multi-threaded app a
 * fault somewhere else is entirely plausible.
 *
 * A fault is also only treated as ours when it is *attributable* to the guarded
 * load rather than merely happening while one is armed. Attribution uses two
 * independent facts:
 *
 *   * the faulting address is the word the guarded load targets, and
 *   * the faulting PC lies inside this library's own executable mapping.
 *
 * Anything else is forwarded to the handler that was installed before us.
 */
struct ProbeGuard {
    sigjmp_buf recovery;
    sig_atomic_t active = 0;          // this thread is inside a guarded load
    uintptr_t expected_address = 0;   // the word the guarded load targets
    uint64_t fault_address = 0;
    uint64_t fault_pc = 0;
};

thread_local ProbeGuard g_guard;

/* The handler that was in place before the first install, kept so an unrelated
 * fault can still reach whoever owned it. */
struct sigaction g_previous_segv {};
struct sigaction g_previous_bus {};
sig_atomic_t g_installed = 0;
volatile sig_atomic_t g_forwarded = 0;
pthread_mutex_t g_install_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t g_decoder_mutex = PTHREAD_MUTEX_INITIALIZER;
volatile unsigned long g_baseline_ready = 0;

using DecodeMethodIdFn = void *(*)(void *, jmethodID);
DecodeMethodIdFn g_decode_method_id = nullptr;
void *g_jni_id_manager = nullptr;

void ForwardToPrevious(int signal, siginfo_t *info, void *context)
{
    ++g_forwarded;
    const struct sigaction &previous =
        signal == SIGBUS ? g_previous_bus : g_previous_segv;
    /* InstallGuard arms exactly once, so the saved disposition is never this
     * handler and forwarding cannot recurse into itself. */
    if (previous.sa_flags & SA_SIGINFO) {
        if (previous.sa_sigaction != nullptr) {
            previous.sa_sigaction(signal, info, context);
            return;
        }
    } else if (previous.sa_handler != nullptr && previous.sa_handler != SIG_IGN &&
               previous.sa_handler != SIG_DFL) {
        previous.sa_handler(signal);
        return;
    }
    /* No usable previous handler: restore the default disposition and re-raise
     * so the process dies exactly as it would have without us. */
    struct sigaction restore;
    memset(&restore, 0, sizeof(restore));
    restore.sa_handler = SIG_DFL;
    sigemptyset(&restore.sa_mask);
    sigaction(signal, &restore, nullptr);
    raise(signal);
}

void OnFault(int signal, siginfo_t *info, void *context)
{
    uint64_t pc = 0;
#if defined(__aarch64__)
    if (context != nullptr) {
        const auto *uc = static_cast<const ucontext_t *>(context);
        pc = static_cast<uint64_t>(uc->uc_mcontext.pc);
    }
#elif defined(__x86_64__)
    if (context != nullptr) {
        const auto *uc = static_cast<const ucontext_t *>(context);
        pc = static_cast<uint64_t>(uc->uc_mcontext.gregs[REG_RIP]);
    }
#endif
    ProbeGuard &guard = g_guard;
    const uint64_t address = info != nullptr
                                 ? reinterpret_cast<uint64_t>(info->si_addr)
                                 : 0ULL;
    const uintptr_t load_begin =
        reinterpret_cast<uintptr_t>(&rtgum_guarded_load_begin);
    const uintptr_t load_end = reinterpret_cast<uintptr_t>(&rtgum_guarded_load_end);
    const bool in_our_text = pc >= load_begin && pc < load_end;
    const bool ours = guard.active == 1 && in_our_text &&
                      guard.expected_address != 0 &&
                      address == static_cast<uint64_t>(guard.expected_address);
    if (!ours) {
        ForwardToPrevious(signal, info, context);
        return;
    }
    guard.fault_address = address;
    guard.fault_pc = pc;
    siglongjmp(guard.recovery, 1);
}

bool InstallGuard()
{
    pthread_mutex_lock(&g_install_mutex);
    if (g_installed == 1) {
        pthread_mutex_unlock(&g_install_mutex);
        return true;
    }
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_sigaction = OnFault;
    /* SA_NODEFER is deliberately absent: the handler must not be re-enterable
     * for the same signal on the same thread, because it would then be possible
     * to jump out of a handler rather than out of the guarded load. */
    action.sa_flags = SA_SIGINFO;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGSEGV, &action, &g_previous_segv) != 0) {
        pthread_mutex_unlock(&g_install_mutex);
        return false;
    }
    if (sigaction(SIGBUS, &action, &g_previous_bus) != 0) {
        sigaction(SIGSEGV, &g_previous_segv, nullptr);
        pthread_mutex_unlock(&g_install_mutex);
        return false;
    }
    g_installed = 1;
    pthread_mutex_unlock(&g_install_mutex);
    return true;
}

/* Reads `length` bytes at `address` through /proc/self/mem. Returns the number
 * of bytes read, or -1 when the read failed. This is the DIAGNOSTIC transport:
 * it is kernel-mediated and therefore cannot stand in for a scanner's load. */
long ReadSelfMem(uint64_t address, void *out, size_t length)
{
    const int fd = open("/proc/self/mem", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    const ssize_t got = pread(fd, out, length, static_cast<off_t>(address));
    const int saved = errno;
    close(fd);
    errno = saved;
    return static_cast<long>(got);
}

bool FindMappedSpan(uintptr_t address, size_t required, bool require_exec = false)
{
    /* Native heap pointers may carry an ARM64 top-byte/MTE tag (for example
     * 0xb4...). /proc/self/maps contains the untagged virtual address, while
     * the tagged value must be retained for the actual memory access. */
#if defined(__aarch64__)
    const uintptr_t mapped_address = address & 0x00ffffffffffffffULL;
#else
    const uintptr_t mapped_address = address;
#endif
    FILE *maps = fopen("/proc/self/maps", "re");
    if (maps == nullptr) return false;
    char line[512];
    bool found = false;
    while (fgets(line, sizeof(line), maps) != nullptr) {
        unsigned long long start = 0;
        unsigned long long end = 0;
        char perms[8] = {};
        if (sscanf(line, "%llx-%llx %7s", &start, &end, perms) != 3) continue;
        if (mapped_address < start || mapped_address >= end) continue;
        if (required > static_cast<size_t>(end - mapped_address)) continue;
        if (require_exec && strchr(perms, 'x') == nullptr) continue;
        found = true;
        break;
    }
    fclose(maps);
    return found;
}

bool LooksLikeArtMethod(uintptr_t record)
{
    if ((record & 7U) != 0U || !FindMappedSpan(record, 32U)) return false;
    uintptr_t jni = 0;
    uintptr_t quick = 0;
    memcpy(&jni, reinterpret_cast<const void *>(record + 16U), sizeof(jni));
    memcpy(&quick, reinterpret_cast<const void *>(record + 24U), sizeof(quick));
    return jni != 0U && quick != 0U && FindMappedSpan(jni, 1U) &&
           FindMappedSpan(quick, 1U, true);
}

bool LooksLikeRecordAddress(uintptr_t record)
{
    return record != 0U && (record & 7U) == 0U && FindMappedSpan(record, 32U);
}

/* Android's app linker namespace may hide libart symbols from RTLD_DEFAULT even
 * though libart is already mapped. Resolve an exported dynsym directly from the
 * exact mapped ELF as a read-only fallback; this does not load another image. */
void *ResolveMappedLibartSymbol(const char *wanted)
{
    if (wanted == nullptr || *wanted == '\0') return nullptr;
    char path[512] = {};
    unsigned long long map_start = 0;
    unsigned long long map_offset = 0;
    uintptr_t load_bias = 0;

    /* JNI_GetCreatedJavaVMs is a public libart export visible to app code. Use
     * dladdr on it to obtain the exact mapped file and load bias without
     * depending on /proc formatting. */
    void *anchor = dlsym(RTLD_DEFAULT, "JNI_GetCreatedJavaVMs");
    Dl_info info {};
    if (anchor != nullptr && dladdr(anchor, &info) != 0 &&
        info.dli_fname != nullptr && info.dli_fbase != nullptr &&
        strstr(info.dli_fname, "/libart.so") != nullptr) {
        strncpy(path, info.dli_fname, sizeof(path) - 1U);
        load_bias = reinterpret_cast<uintptr_t>(info.dli_fbase);
    }

    if (path[0] == '\0') {
        FILE *maps = fopen("/proc/self/maps", "re");
        if (maps == nullptr) return nullptr;
        char line[768];
        while (fgets(line, sizeof(line), maps) != nullptr) {
            unsigned long long start = 0, end = 0, offset = 0;
            char perms[8] = {}, device[24] = {}, candidate[512] = {};
            unsigned long inode = 0;
            const int fields = sscanf(line,
                                      "%llx-%llx %7s %llx %23s %lu %511s",
                                      &start, &end, perms, &offset, device,
                                      &inode, candidate);
            if (fields != 7 || strstr(candidate, "/libart.so") == nullptr)
                continue;
            map_start = start;
            map_offset = offset;
            strncpy(path, candidate, sizeof(path) - 1U);
            break;
        }
        fclose(maps);
    }
    if (path[0] == '\0') return nullptr;

    const int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return nullptr;
    Elf64_Ehdr ehdr {};
    if (pread(fd, &ehdr, sizeof(ehdr), 0) != static_cast<ssize_t>(sizeof(ehdr)) ||
        memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 ||
        ehdr.e_ident[EI_CLASS] != ELFCLASS64 || ehdr.e_machine != EM_AARCH64 ||
        ehdr.e_phentsize != sizeof(Elf64_Phdr) ||
        ehdr.e_shentsize != sizeof(Elf64_Shdr)) {
        close(fd);
        return nullptr;
    }

    for (unsigned int index = 0; load_bias == 0 && index < ehdr.e_phnum;
         ++index) {
        Elf64_Phdr phdr {};
        const off_t where = static_cast<off_t>(ehdr.e_phoff) +
                            static_cast<off_t>(index * sizeof(phdr));
        if (pread(fd, &phdr, sizeof(phdr), where) !=
            static_cast<ssize_t>(sizeof(phdr)))
            break;
        if (phdr.p_type != PT_LOAD) continue;
        const unsigned long long offset_page = phdr.p_offset & ~0xfffULL;
        if (offset_page != map_offset) continue;
        const unsigned long long vaddr_page = phdr.p_vaddr & ~0xfffULL;
        load_bias = static_cast<uintptr_t>(map_start - vaddr_page);
        break;
    }
    if (load_bias == 0) {
        close(fd);
        return nullptr;
    }

    for (unsigned int section_index = 0; section_index < ehdr.e_shnum;
         ++section_index) {
        Elf64_Shdr symbols {};
        const off_t section_where = static_cast<off_t>(ehdr.e_shoff) +
            static_cast<off_t>(section_index * sizeof(symbols));
        if (pread(fd, &symbols, sizeof(symbols), section_where) !=
            static_cast<ssize_t>(sizeof(symbols)))
            break;
        if (symbols.sh_type != SHT_DYNSYM || symbols.sh_entsize != sizeof(Elf64_Sym) ||
            symbols.sh_link >= ehdr.e_shnum)
            continue;
        Elf64_Shdr strings {};
        const off_t strings_where = static_cast<off_t>(ehdr.e_shoff) +
            static_cast<off_t>(symbols.sh_link * sizeof(strings));
        if (pread(fd, &strings, sizeof(strings), strings_where) !=
            static_cast<ssize_t>(sizeof(strings)))
            continue;
        const unsigned long long count = symbols.sh_size / sizeof(Elf64_Sym);
        for (unsigned long long symbol_index = 0; symbol_index < count;
             ++symbol_index) {
            Elf64_Sym symbol {};
            const off_t symbol_where = static_cast<off_t>(symbols.sh_offset) +
                static_cast<off_t>(symbol_index * sizeof(symbol));
            if (pread(fd, &symbol, sizeof(symbol), symbol_where) !=
                static_cast<ssize_t>(sizeof(symbol)))
                break;
            if (symbol.st_name == 0 || symbol.st_name >= strings.sh_size ||
                symbol.st_value == 0)
                continue;
            char name[192] = {};
            const size_t remaining =
                static_cast<size_t>(strings.sh_size - symbol.st_name);
            const size_t amount = remaining < sizeof(name) - 1U
                                      ? remaining
                                      : sizeof(name) - 1U;
            if (pread(fd, name, amount,
                      static_cast<off_t>(strings.sh_offset + symbol.st_name)) <= 0)
                continue;
            name[sizeof(name) - 1U] = '\0';
            if (strcmp(name, wanted) == 0) {
                close(fd);
                return reinterpret_cast<void *>(load_bias + symbol.st_value);
            }
        }
    }
    close(fd);
    return nullptr;
}

bool ResolveRuntimeDecoder(JNIEnv *env)
{
    pthread_mutex_lock(&g_decoder_mutex);
    if (g_decode_method_id != nullptr && g_jni_id_manager != nullptr) {
        pthread_mutex_unlock(&g_decoder_mutex);
        return true;
    }

    constexpr const char *kDecode =
        "_ZN3art3jni12JniIdManager14DecodeMethodIdEP10_jmethodID";
    constexpr const char *kRuntime = "_ZN3art7Runtime9instance_E";
    void *decode = dlsym(RTLD_DEFAULT, kDecode);
    void *runtime_slot = dlsym(RTLD_DEFAULT, kRuntime);
    if (decode == nullptr) decode = ResolveMappedLibartSymbol(kDecode);
    if (runtime_slot == nullptr)
        runtime_slot = ResolveMappedLibartSymbol(kRuntime);
    LAB_LOG("decoder symbols decode=%p runtime-slot=%p", decode, runtime_slot);
    if (decode == nullptr || runtime_slot == nullptr ||
        !FindMappedSpan(reinterpret_cast<uintptr_t>(decode), 1U, true) ||
        !FindMappedSpan(reinterpret_cast<uintptr_t>(runtime_slot), sizeof(void *))) {
        LAB_LOG("decoder symbols unavailable or invalid");
        pthread_mutex_unlock(&g_decoder_mutex);
        return false;
    }

    void *runtime = nullptr;
    memcpy(&runtime, runtime_slot, sizeof(runtime));
    JavaVM *vm = nullptr;
    if (runtime == nullptr || env->GetJavaVM(&vm) != JNI_OK || vm == nullptr) {
        LAB_LOG("decoder runtime unavailable runtime=%p vm=%p", runtime, vm);
        pthread_mutex_unlock(&g_decoder_mutex);
        return false;
    }

    const uintptr_t runtime_address = reinterpret_cast<uintptr_t>(runtime);
    if (!FindMappedSpan(runtime_address, 384U + 100U * sizeof(void *))) {
        LAB_LOG("decoder runtime span invalid runtime=%p", runtime);
        pthread_mutex_unlock(&g_decoder_mutex);
        return false;
    }
    void *manager = nullptr;
    for (uintptr_t offset = 384U;
         offset < 384U + 100U * sizeof(void *); offset += sizeof(void *)) {
        void *candidate_vm = nullptr;
        memcpy(&candidate_vm,
               reinterpret_cast<const void *>(runtime_address + offset),
               sizeof(candidate_vm));
        if (candidate_vm != vm || offset < sizeof(void *)) continue;
        memcpy(&manager,
               reinterpret_cast<const void *>(runtime_address + offset -
                                              sizeof(void *)),
               sizeof(manager));
        if (manager != nullptr &&
            FindMappedSpan(reinterpret_cast<uintptr_t>(manager), sizeof(void *)))
            break;
        manager = nullptr;
    }
    if (manager == nullptr) {
        LAB_LOG("decoder manager not found runtime=%p vm=%p", runtime, vm);
        pthread_mutex_unlock(&g_decoder_mutex);
        return false;
    }
    g_decode_method_id = reinterpret_cast<DecodeMethodIdFn>(decode);
    g_jni_id_manager = manager;
    pthread_mutex_unlock(&g_decoder_mutex);
    LAB_LOG("runtime jmethodID decoder ready");
    return true;
}

uintptr_t ResolveArtMethodRecord(JNIEnv *env, jmethodID id)
{
    const uintptr_t raw = reinterpret_cast<uintptr_t>(id);
    if (LooksLikeArtMethod(raw)) return raw;
    if (!ResolveRuntimeDecoder(env)) return 0;
    void *decoded = g_decode_method_id(g_jni_id_manager, id);
    const uintptr_t record = reinterpret_cast<uintptr_t>(decoded);
    /* DecodeMethodId is the runtime's authoritative address translation. Do
     * not read ArtMethod fields again here: once the page is shadowed that
     * would mix trusted address acquisition with an implicit untrusted data
     * read and can reject the correct address merely because the PTE is
     * intentionally blocked. Field contents are checked by GuardedLoad. */
    const bool valid = LooksLikeRecordAddress(record);
    LAB_LOG("DecodeMethodId token=%p decoded=%p valid=%d", id, decoded,
            valid ? 1 : 0);
    return valid ? record : 0U;
}

}  // namespace

/* The one instruction the whole scanner-side check rests on: a single `ldr`,
 * emitted explicitly so the kernel's data-abort decoder can emulate exactly that
 * instruction, and so the compiler cannot turn the access into something else
 * (a memcpy, an LDXR/STXR pair, or nothing at all). This function is the only
 * place in this library that ever dereferences a caller-supplied address. */
extern "C" __attribute__((noinline, used)) uint64_t GuardedLoad(
    const uint64_t *pointer)
{
    uint64_t loaded = 0;
#if defined(__aarch64__)
    __asm__ __volatile__(".global rtgum_guarded_load_begin\n\t"
                         "rtgum_guarded_load_begin:\n\t"
                         "ldr %0, [%1]\n\t"
                         ".global rtgum_guarded_load_end\n\t"
                         "rtgum_guarded_load_end:\n\t"
                         : "=r"(loaded)
                         : "r"(pointer)
                         : "memory");
#else
    loaded = *pointer;
#endif
    return loaded;
}

/* The raw jmethodID behind a reflective Method, as a token.
 *
 * The value is NOT promised to be a pointer (see art_hook/art_probe.h and
 * docs/ART_HOOK_HANDOVER.md): in kIndices mode it is a tagged table index. The
 * caller classifies it; the name says `token` so that no caller can mistake it
 * for an address by reading the code. */
extern "C" JNIEXPORT jlong JNICALL
Java_dev_rtgum_lab_ArtMethodScanner_nativeMethodToken(JNIEnv *env, jobject,
                                                     jobject method)
{
    if (method == nullptr) {
        LAB_LOG("nativeMethodToken: method argument is null");
        return 0;
    }
    const jmethodID id = env->FromReflectedMethod(method);
    LAB_LOG("FromReflectedMethod token=0x%llx (method=%p)",
            static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(id)),
            reinterpret_cast<void *>(method));
    return static_cast<jlong>(reinterpret_cast<uintptr_t>(id));
}

extern "C" JNIEXPORT jlong JNICALL
Java_dev_rtgum_lab_ArtMethodScanner_nativeResolveMethodRecord(JNIEnv *env,
                                                               jobject,
                                                               jobject method)
{
    if (method == nullptr) return 0;
    const jmethodID id = env->FromReflectedMethod(method);
    if (id == nullptr || env->ExceptionCheck()) {
        env->ExceptionClear();
        return 0;
    }
    const uintptr_t record = ResolveArtMethodRecord(env, id);
    LAB_LOG("resolved ArtMethod token=0x%llx record=0x%llx",
            static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(id)),
            static_cast<unsigned long long>(record));
    return static_cast<jlong>(record);
}

extern "C" JNIEXPORT void JNICALL
Java_dev_rtgum_lab_ArtMethodScanner_nativeSetBaselineReady(JNIEnv *, jobject,
                                                            jboolean ready)
{
    __atomic_store_n(&g_baseline_ready, ready == JNI_TRUE ? 1UL : 0UL,
                     __ATOMIC_RELEASE);
}

extern "C" __attribute__((visibility("default"))) unsigned long
rtgum_lab_baseline_ready()
{
    return __atomic_load_n(&g_baseline_ready, __ATOMIC_ACQUIRE);
}

/*
 * A real EL0 load of one 64-bit word, reported as:
 *
 *   result[0]  status: 0 = loaded, 1 = faulted (the kernel did not serve it),
 *              2 = the guard could not be installed
 *   result[1]  the word that was loaded (0 when the load faulted)
 *   result[2]  fault address from siginfo (0 when the load succeeded)
 *   result[3]  faulting PC from the ucontext - the address the kernel used to
 *              decide which view to serve (0 when the load succeeded)
 *
 * One array rather than a value plus a status getter, so a caller cannot read
 * the value without also seeing whether there *was* a value.
 *
 * The load itself is GuardedLoad's `ldr`: emitted explicitly in inline assembly
 * so the kernel's data-abort decoder can emulate exactly that instruction, and
 * so the compiler cannot turn the access into something else (a memcpy, an
 * LDXR/STXR pair, or nothing at all).
 */
extern "C" JNIEXPORT jlongArray JNICALL
Java_dev_rtgum_lab_ArtMethodScanner_nativeLoadWordEl0(JNIEnv *env, jobject,
                                                      jlong address)
{
    jlong result[4] = {0, 0, 0, 0};
    uint64_t value = 0;
    uint64_t fault_address = 0;
    uint64_t fault_pc = 0;
    jlong status = 0;

    if (address == 0) {
        status = 1;
    } else if (!InstallGuard()) {
        status = 2;
        LAB_LOG("nativeLoadWordEl0: sigaction failed errno=%d", errno);
    } else {
        ProbeGuard &guard = g_guard;
        if (guard.active == 1) {
            /* Nested probe on this thread: refuse rather than overwrite the
             * outer guard, which would make the outer fault land here. */
            status = 2;
        } else {
            guard.expected_address = static_cast<uintptr_t>(address);
            guard.fault_address = 0;
            guard.fault_pc = 0;
            guard.active = 1;
            if (sigsetjmp(guard.recovery, 1) == 0) {
                value = GuardedLoad(reinterpret_cast<const uint64_t *>(
                    static_cast<uintptr_t>(address)));
            } else {
                status = 1;
                fault_address = guard.fault_address;
                fault_pc = guard.fault_pc;
            }
            guard.active = 0;
            guard.expected_address = 0;
        }
    }

    result[0] = status;
    result[1] = static_cast<jlong>(value);
    result[2] = static_cast<jlong>(fault_address);
    result[3] = static_cast<jlong>(fault_pc);

    /* Reported on every load: this is the line a scanner's behaviour is read
     * off, so it must be present whether the load succeeded or faulted. */
    LAB_LOG("ldr-transport=direct-load address=0x%llx status=%lld value=0x%llx "
            "fault-address=0x%llx fault-pc=0x%llx",
            static_cast<unsigned long long>(address), static_cast<long long>(status),
            static_cast<unsigned long long>(value),
            static_cast<unsigned long long>(fault_address),
            static_cast<unsigned long long>(fault_pc));

    jlongArray out = env->NewLongArray(4);
    if (out == nullptr) return nullptr;
    env->SetLongArrayRegion(out, 0, 4, result);
    return out;
}

/* Diagnostic transport: one 64-bit word through /proc/self/mem. */
extern "C" JNIEXPORT jlong JNICALL
Java_dev_rtgum_lab_ArtMethodScanner_nativeReadWordProcMem(JNIEnv *, jobject,
                                                          jlong address)
{
    if (address == 0) return 0;
    uint64_t value = 0;
    const long got = ReadSelfMem(static_cast<uint64_t>(address), &value,
                                 sizeof(value));
    if (got != static_cast<long>(sizeof(value))) {
        LAB_LOG("pread-transport=proc-mem address=0x%llx failed errno=%d",
                static_cast<unsigned long long>(address), errno);
        return 0;
    }
    return static_cast<jlong>(value);
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_dev_rtgum_lab_ArtMethodScanner_nativeReadBytesProcMem(JNIEnv *env, jobject,
                                                           jlong address,
                                                           jint length)
{
    if (address == 0 || length <= 0) return nullptr;
    jbyteArray result = env->NewByteArray(length);
    if (result == nullptr) return nullptr;
    jbyte *raw = env->GetByteArrayElements(result, nullptr);
    if (raw == nullptr) return nullptr;
    const long got = ReadSelfMem(static_cast<uint64_t>(address), raw,
                                 static_cast<size_t>(length));
    if (got != static_cast<long>(length)) {
        env->ReleaseByteArrayElements(result, raw, JNI_ABORT);
        return nullptr;
    }
    env->ReleaseByteArrayElements(result, raw, 0);
    return result;
}

extern "C" JNIEXPORT jlongArray JNICALL
Java_dev_rtgum_lab_MemoryProbe_nativeSnapshot(JNIEnv *env, jclass)
{
    const jlong values[3] = {
        static_cast<jlong>(reinterpret_cast<uintptr_t>(&rtgum_lab_memory_magic)),
        static_cast<jlong>(reinterpret_cast<uintptr_t>(&lab_add)),
        static_cast<jlong>(__atomic_load_n(&rtgum_lab_memory_magic,
                                          __ATOMIC_ACQUIRE)),
    };
    LAB_LOG("memory-ready pid=%d magic=0x%llx code=0x%llx value=0x%llx",
            getpid(),
            static_cast<unsigned long long>(values[0]),
            static_cast<unsigned long long>(values[1]),
            static_cast<unsigned long long>(values[2]));
    LAB_LOG("gtrace-ready pid=%d entry=0x%llx end=0x%llx bytes=%llu",
            getpid(),
            static_cast<unsigned long long>(
                reinterpret_cast<uintptr_t>(&rtgum_gtrace_flower)),
            static_cast<unsigned long long>(
                reinterpret_cast<uintptr_t>(&rtgum_gtrace_flower_end)),
            static_cast<unsigned long long>(
                reinterpret_cast<uintptr_t>(&rtgum_gtrace_flower_end) -
                reinterpret_cast<uintptr_t>(&rtgum_gtrace_flower)));
    jlongArray result = env->NewLongArray(3);
    if (result == nullptr) return nullptr;
    env->SetLongArrayRegion(result, 0, 3, values);
    return result;
}

extern "C" JNIEXPORT jint JNICALL
Java_dev_rtgum_lab_MemoryProbe_nativeTraceLabAdd(JNIEnv *, jclass,
                                                  jint left, jint right)
{
    return static_cast<jint>(lab_add(static_cast<int>(left),
                                    static_cast<int>(right)));
}

extern "C" JNIEXPORT jint JNICALL
Java_dev_rtgum_lab_MemoryProbe_nativeTraceFlower(JNIEnv *, jclass,
                                                  jint left, jint right)
{
    return static_cast<jint>(rtgum_gtrace_flower(static_cast<int>(left),
                                                 static_cast<int>(right)));
}

namespace {

__attribute__((noinline)) long HwbpSelfCheckTarget(long value)
{
    asm volatile("nop\n\tnop\n\tnop\n\tnop\n\tnop\n\tnop" ::: "memory");
    return value + 1;
}

alignas(8) volatile uint64_t HwbpSelfCheckWatchWord =
    UINT64_C(0x525447554d574154);

struct LabHwDebugState {
    uint32_t dbg_info;
    uint32_t pad;
    struct Register {
        uint64_t address;
        uint32_t control;
        uint32_t pad;
    } registers[16];
};
static_assert(sizeof(LabHwDebugState) == 264U);

bool HwStateEmpty(const LabHwDebugState &state)
{
    for (const auto &entry : state.registers)
        if (entry.address != 0U || entry.control != 0U) return false;
    return true;
}

bool VerifyPerfFd(int fd)
{
    if (fd < 0 ||
        ioctl(fd, PERF_EVENT_IOC_RESET, 0UL) != 0 ||
        ioctl(fd, PERF_EVENT_IOC_ENABLE, 0UL) != 0 ||
        ioctl(fd, PERF_EVENT_IOC_DISABLE, 0UL) != 0)
        return false;
    uint64_t counter = 0;
    return read(fd, &counter, sizeof(counter)) ==
        static_cast<ssize_t>(sizeof(counter));
}

bool SendFd(int socket_fd, int fd)
{
    char byte = 'F';
    struct iovec vector {&byte, 1U};
    alignas(struct cmsghdr) unsigned char control[CMSG_SPACE(sizeof(int))]{};
    struct msghdr message{};
    message.msg_iov = &vector;
    message.msg_iovlen = 1U;
    message.msg_control = control;
    message.msg_controllen = sizeof(control);
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(header), &fd, sizeof(fd));
    return sendmsg(socket_fd, &message, 0) == 1;
}

int ReceiveFd(int socket_fd)
{
    char byte = 0;
    struct iovec vector {&byte, 1U};
    alignas(struct cmsghdr) unsigned char control[CMSG_SPACE(sizeof(int))]{};
    struct msghdr message{};
    message.msg_iov = &vector;
    message.msg_iovlen = 1U;
    message.msg_control = control;
    message.msg_controllen = sizeof(control);
    if (recvmsg(socket_fd, &message, 0) != 1) return -1;
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    if (!header || header->cmsg_level != SOL_SOCKET ||
        header->cmsg_type != SCM_RIGHTS ||
        header->cmsg_len < CMSG_LEN(sizeof(int)))
        return -1;
    int fd = -1;
    memcpy(&fd, CMSG_DATA(header), sizeof(fd));
    return fd;
}

}  // namespace

/*
 * In-APK syscall acceptance for the Lab's "HWBP" lamp. The activity itself is
 * never traced: it owns a short-lived child which opts into PTRACE_TRACEME, so
 * /proc/self/status in the activity continues to report TracerPid: 0.
 *
 * Return values:
 *   [0] bit mask (0xffff means all sixteen assertions passed)
 *   [1] hardware breakpoint capacity reported by GETREGSET
 *   [2] errno from the overflowing breakpoint SETREGSET
 *   [3] errno from the overflowing breakpoint perf_event_open
 *   [4] active virtual breakpoint stop signal (SIGTRAP is success; the native
 *       probe also verifies TRAP_HWBKPT and the exact si_addr for both WRP/BRP)
 *   [5] hardware watchpoint capacity reported by GETREGSET
 *   [6] errno from the overflowing watchpoint SETREGSET
 *   [7] errno from the overflowing watchpoint perf_event_open
 */
extern "C" JNIEXPORT jlongArray JNICALL
Java_dev_rtgum_lab_MemoryProbe_nativeHwbpSelfCheck(JNIEnv *env, jclass)
{
    constexpr unsigned long kNtArmHwBreak = 0x402UL;
    constexpr unsigned long kNtArmHwWatch = 0x403UL;
    constexpr uint32_t kExecuteEl0 = 1U | (2U << 1U) | (0xfU << 5U);
    constexpr uint32_t kWatchWriteEl0 =
        1U | (2U << 1U) | (2U << 3U) | (0xffU << 5U);
    constexpr unsigned int kMaximumDebugSlots = 16U;
    jlong values[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    unsigned long mask = 0UL;
    int perf_fds[kMaximumDebugSlots];
    int watch_perf_fds[kMaximumDebugSlots];
    for (int &fd : perf_fds) fd = -1;
    for (int &fd : watch_perf_fds) fd = -1;
    int dup_fd = -1;
    int fcntl_fd = -1;
    int dup3_fd = -1;

    const pid_t child = fork();
    if (child == 0) {
        (void)prctl(PR_SET_NAME, "dev.rtgum.lab", 0, 0, 0);
        if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) != 0) _exit(31);
        raise(SIGSTOP);
        HwbpSelfCheckWatchWord ^= UINT64_C(0x0101010101010101);
        const volatile long result = HwbpSelfCheckTarget(8);
        if (result != 9) _exit(32);
        raise(SIGSTOP);
        _exit(0);
    }
    if (child > 0) {
        int status = 0;
        if (waitpid(child, &status, 0) == child && WIFSTOPPED(status)) {
            auto get_state = [&](unsigned long note, LabHwDebugState &state) {
                memset(&state, 0xa5, sizeof(state));
                struct iovec vector {&state, sizeof(state)};
                errno = 0;
                return ptrace(PTRACE_GETREGSET, child,
                              reinterpret_cast<void *>(note),
                              &vector) == 0 && vector.iov_len == sizeof(state);
            };
            auto set_state = [&](unsigned long note, LabHwDebugState &state,
                                 unsigned int slots) {
                struct iovec vector {
                    &state, 8UL + static_cast<unsigned long>(slots) * 16UL};
                errno = 0;
                return ptrace(PTRACE_SETREGSET, child,
                              reinterpret_cast<void *>(note),
                              &vector);
            };

            LabHwDebugState baseline{};
            unsigned int slots = 0U;
            if (get_state(kNtArmHwBreak, baseline)) {
                slots = baseline.dbg_info & 0xffU;
                values[1] = static_cast<jlong>(slots);
                if (slots > 0U && slots < kMaximumDebugSlots &&
                    HwStateEmpty(baseline))
                    mask |= 1UL << 0U;
            }

            LabHwDebugState programmed = baseline;
            const uintptr_t target =
                reinterpret_cast<uintptr_t>(&HwbpSelfCheckTarget);
            if (slots > 0U && slots < kMaximumDebugSlots) {
                for (unsigned int index = 0; index < slots; ++index) {
                    programmed.registers[index].address = target + index * 4U;
                    programmed.registers[index].control = kExecuteEl0;
                }
                if (set_state(kNtArmHwBreak, programmed, slots) == 0)
                    mask |= 1UL << 1U;
                LabHwDebugState observed{};
                if (get_state(kNtArmHwBreak, observed) &&
                    memcmp(&programmed, &observed, sizeof(observed)) == 0)
                    mask |= 1UL << 2U;

                LabHwDebugState overflow = programmed;
                overflow.registers[slots].address = target + slots * 4U;
                overflow.registers[slots].control = kExecuteEl0;
                errno = 0;
                const long overflow_result = set_state(
                    kNtArmHwBreak, overflow, slots + 1U);
                values[2] = static_cast<jlong>(errno);
                if (overflow_result == -1 && errno == ENOSPC) mask |= 1UL << 3U;

                struct perf_event_attr attr {};
                attr.type = PERF_TYPE_BREAKPOINT;
                attr.size = sizeof(attr);
                attr.bp_type = HW_BREAKPOINT_X;
                attr.bp_addr = target;
                attr.bp_len = HW_BREAKPOINT_LEN_4;
                attr.exclude_kernel = 1;
                attr.exclude_hv = 1;
                errno = 0;
                const long shared_capacity = syscall(
                    __NR_perf_event_open, &attr, child, -1, -1, 0UL);
                bool perf_all = shared_capacity == -1 && errno == ENOSPC;
                if (shared_capacity >= 0)
                    close(static_cast<int>(shared_capacity));
                LabHwDebugState clear_for_perf{};
                perf_all = perf_all &&
                    set_state(kNtArmHwBreak, clear_for_perf, slots) == 0;
                for (unsigned int index = 0; index < slots; ++index) {
                    perf_fds[index] = static_cast<int>(syscall(
                        __NR_perf_event_open, &attr, child, -1, -1, 0UL));
                    if (!VerifyPerfFd(perf_fds[index])) perf_all = false;
                }
                if (perf_all) mask |= 1UL << 4U;
                errno = 0;
                const long overflow_perf = syscall(
                    __NR_perf_event_open, &attr, child, -1, -1, 0UL);
                values[3] = static_cast<jlong>(errno);
                if (overflow_perf == -1 && errno == ENOSPC) mask |= 1UL << 5U;
                if (overflow_perf >= 0) close(static_cast<int>(overflow_perf));
            }

            LabHwDebugState watch_baseline{};
            unsigned int watch_slots = 0U;
            if (get_state(kNtArmHwWatch, watch_baseline)) {
                watch_slots = watch_baseline.dbg_info & 0xffU;
                values[5] = static_cast<jlong>(watch_slots);
                if (watch_slots > 0U && watch_slots < kMaximumDebugSlots &&
                    HwStateEmpty(watch_baseline))
                    mask |= 1UL << 8U;
            }
            LabHwDebugState watch_programmed = watch_baseline;
            const uintptr_t watch_address = reinterpret_cast<uintptr_t>(
                const_cast<uint64_t *>(&HwbpSelfCheckWatchWord));
            if (watch_slots > 0U && watch_slots < kMaximumDebugSlots) {
                for (unsigned int index = 0; index < watch_slots; ++index) {
                    watch_programmed.registers[index].address = watch_address;
                    watch_programmed.registers[index].control = kWatchWriteEl0;
                }
                if (set_state(kNtArmHwWatch, watch_programmed,
                              watch_slots) == 0)
                    mask |= 1UL << 9U;
                LabHwDebugState watch_observed{};
                if (get_state(kNtArmHwWatch, watch_observed) &&
                    memcmp(&watch_programmed, &watch_observed,
                           sizeof(watch_observed)) == 0)
                    mask |= 1UL << 10U;
                LabHwDebugState watch_overflow = watch_programmed;
                watch_overflow.registers[watch_slots].address = watch_address;
                watch_overflow.registers[watch_slots].control = kWatchWriteEl0;
                errno = 0;
                const long watch_overflow_result = set_state(
                    kNtArmHwWatch, watch_overflow, watch_slots + 1U);
                values[6] = static_cast<jlong>(errno);
                if (watch_overflow_result == -1 && errno == ENOSPC)
                    mask |= 1UL << 11U;

                struct perf_event_attr watch_attr {};
                watch_attr.type = PERF_TYPE_BREAKPOINT;
                watch_attr.size = sizeof(watch_attr);
                watch_attr.bp_type = HW_BREAKPOINT_W;
                watch_attr.bp_addr = watch_address;
                watch_attr.bp_len = HW_BREAKPOINT_LEN_8;
                watch_attr.exclude_kernel = 1;
                watch_attr.exclude_hv = 1;
                errno = 0;
                const long shared_watch_capacity = syscall(
                    __NR_perf_event_open, &watch_attr, child, -1, -1, 0UL);
                bool watch_perf_all =
                    shared_watch_capacity == -1 && errno == ENOSPC;
                if (shared_watch_capacity >= 0)
                    close(static_cast<int>(shared_watch_capacity));
                LabHwDebugState clear_watch_for_perf{};
                watch_perf_all = watch_perf_all &&
                    set_state(kNtArmHwWatch, clear_watch_for_perf,
                              watch_slots) == 0;
                for (unsigned int index = 0; index < watch_slots; ++index) {
                    watch_perf_fds[index] = static_cast<int>(syscall(
                        __NR_perf_event_open, &watch_attr, child, -1, -1, 0UL));
                    if (!VerifyPerfFd(watch_perf_fds[index]))
                        watch_perf_all = false;
                }
                if (watch_perf_all) mask |= 1UL << 12U;
                errno = 0;
                const long watch_perf_overflow = syscall(
                    __NR_perf_event_open, &watch_attr, child, -1, -1, 0UL);
                values[7] = static_cast<jlong>(errno);
                if (watch_perf_overflow == -1 && errno == ENOSPC)
                    mask |= 1UL << 13U;
                if (watch_perf_overflow >= 0)
                    close(static_cast<int>(watch_perf_overflow));
            }

            /* An event remains the same kernel object across every normal
             * file-table operation. The fake ledger must therefore authorize
             * by perf_event identity rather than by the original (tgid, fd). */
            if (slots > 0U && perf_fds[0] >= 0) {
                dup_fd = dup(perf_fds[0]);
                fcntl_fd = fcntl(perf_fds[0], F_DUPFD_CLOEXEC, 128);
                const int dup3_target =
                    fcntl(perf_fds[0], F_DUPFD_CLOEXEC, 256);
                if (dup3_target >= 0) close(dup3_target);
                dup3_fd = dup3_target >= 0
                    ? dup3(perf_fds[0], dup3_target, O_CLOEXEC) : -1;
                bool lifecycle_ok = VerifyPerfFd(dup_fd) &&
                    VerifyPerfFd(fcntl_fd) && VerifyPerfFd(dup3_fd);

                int sockets[2] = {-1, -1};
                pid_t helper = -1;
                if (lifecycle_ok &&
                    socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC,
                               0, sockets) == 0) {
                    helper = fork();
                    if (helper == 0) {
                        close(sockets[0]);
                        (void)prctl(PR_SET_NAME, "rtgum-fdrecv", 0, 0, 0);
                        bool valid = VerifyPerfFd(perf_fds[0]);
                        for (int fd : perf_fds) if (fd >= 0) close(fd);
                        for (int fd : watch_perf_fds)
                            if (fd >= 0) close(fd);
                        if (dup_fd >= 0) close(dup_fd);
                        if (fcntl_fd >= 0) close(fcntl_fd);
                        if (dup3_fd >= 0) close(dup3_fd);
                        const int received = ReceiveFd(sockets[1]);
                        valid = valid && VerifyPerfFd(received);
                        if (received >= 0) close(received);
                        close(sockets[1]);
                        _exit(valid ? 0 : 61);
                    }
                    close(sockets[1]);
                    sockets[1] = -1;
                    lifecycle_ok = helper > 0 &&
                        SendFd(sockets[0], perf_fds[0]);
                    close(sockets[0]);
                    int helper_status = 0;
                    if (helper > 0)
                        lifecycle_ok = lifecycle_ok &&
                            waitpid(helper, &helper_status, 0) == helper &&
                            WIFEXITED(helper_status) &&
                            WEXITSTATUS(helper_status) == 0;
                } else {
                    lifecycle_ok = false;
                }

                if (lifecycle_ok && close(perf_fds[0]) == 0) {
                    perf_fds[0] = -1;
                    struct perf_event_attr attr {};
                    attr.type = PERF_TYPE_BREAKPOINT;
                    attr.size = sizeof(attr);
                    attr.bp_type = HW_BREAKPOINT_X;
                    attr.bp_addr = target;
                    attr.bp_len = HW_BREAKPOINT_LEN_4;
                    attr.exclude_kernel = 1;
                    attr.exclude_hv = 1;
                    errno = 0;
                    const long while_aliased = syscall(
                        __NR_perf_event_open, &attr, child, -1, -1, 0UL);
                    lifecycle_ok = while_aliased == -1 && errno == ENOSPC;
                    if (while_aliased >= 0)
                        close(static_cast<int>(while_aliased));
                    if (dup_fd >= 0) close(dup_fd);
                    if (fcntl_fd >= 0) close(fcntl_fd);
                    if (dup3_fd >= 0) close(dup3_fd);
                    dup_fd = fcntl_fd = dup3_fd = -1;
                    perf_fds[0] = static_cast<int>(syscall(
                        __NR_perf_event_open, &attr, child, -1, -1, 0UL));
                    lifecycle_ok = lifecycle_ok && VerifyPerfFd(perf_fds[0]);
                } else {
                    lifecycle_ok = false;
                }
                if (lifecycle_ok) mask |= 1UL << 14U;
            }

            for (int &fd : perf_fds) {
                if (fd >= 0) close(fd);
                fd = -1;
            }
            for (int &fd : watch_perf_fds) {
                if (fd >= 0) close(fd);
                fd = -1;
            }
            const bool ptrace_rearmed =
                slots > 0U && watch_slots > 0U &&
                set_state(kNtArmHwBreak, programmed, slots) == 0 &&
                set_state(kNtArmHwWatch, watch_programmed, watch_slots) == 0;

            auto expect_hwbp_stop = [&](uintptr_t expected_address) {
                if (ptrace(PTRACE_CONT, child, nullptr, nullptr) != 0 ||
                    waitpid(child, &status, 0) != child ||
                    !WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP)
                    return false;
                siginfo_t info{};
                if (ptrace(PTRACE_GETSIGINFO, child, nullptr, &info) != 0 ||
                    info.si_signo != SIGTRAP ||
                    info.si_code != TRAP_HWBKPT ||
                    reinterpret_cast<uintptr_t>(info.si_addr) != expected_address)
                    return false;
                values[4] = static_cast<jlong>(WSTOPSIG(status));
                return true;
            };
            bool active_ok = ptrace_rearmed && expect_hwbp_stop(watch_address);
            if (active_ok) {
                LabHwDebugState clear_watch{};
                active_ok = set_state(kNtArmHwWatch, clear_watch,
                                      watch_slots) == 0 &&
                    expect_hwbp_stop(target);
            }
            if (active_ok) {
                LabHwDebugState clear_break{};
                active_ok = set_state(kNtArmHwBreak, clear_break, slots) == 0 &&
                    ptrace(PTRACE_CONT, child, nullptr, nullptr) == 0 &&
                    waitpid(child, &status, 0) == child && WIFSTOPPED(status) &&
                    WSTOPSIG(status) == SIGSTOP;
            }
            if (active_ok) mask |= 1UL << 6U;

            for (int &fd : perf_fds) {
                if (fd >= 0) close(fd);
                fd = -1;
            }
            for (int &fd : watch_perf_fds) {
                if (fd >= 0) close(fd);
                fd = -1;
            }
            if (dup_fd >= 0) close(dup_fd);
            if (fcntl_fd >= 0) close(fcntl_fd);
            if (dup3_fd >= 0) close(dup3_fd);
            dup_fd = fcntl_fd = dup3_fd = -1;

            if (slots > 0U && slots < kMaximumDebugSlots) {
                LabHwDebugState cleared{};
                LabHwDebugState observed{};
                if (set_state(kNtArmHwBreak, cleared, slots) == 0 &&
                    get_state(kNtArmHwBreak, observed) && HwStateEmpty(observed))
                    mask |= 1UL << 7U;
            }
            if (watch_slots > 0U && watch_slots < kMaximumDebugSlots) {
                LabHwDebugState cleared{};
                LabHwDebugState observed{};
                if (set_state(kNtArmHwWatch, cleared, watch_slots) == 0 &&
                    get_state(kNtArmHwWatch, observed) && HwStateEmpty(observed))
                    mask |= 1UL << 15U;
            }
            (void)ptrace(PTRACE_DETACH, child, nullptr, nullptr);
            if (!(WIFEXITED(status) || WIFSIGNALED(status)))
                (void)waitpid(child, &status, 0);
        } else {
            kill(child, SIGKILL);
            (void)waitpid(child, nullptr, 0);
        }
    }

    values[0] = static_cast<jlong>(mask);
    LAB_LOG("hwbp-selfcheck mask=0x%lx brp=%lld wrp=%lld "
            "ptrace-brp-overflow=%lld perf-brp-overflow=%lld "
            "ptrace-wrp-overflow=%lld perf-wrp-overflow=%lld "
            "active-signal=%lld perf-ioctl=%u perf-read=%u "
            "fd-lifecycle=%u tracer-self=0",
            mask, static_cast<long long>(values[1]),
            static_cast<long long>(values[5]),
            static_cast<long long>(values[2]),
            static_cast<long long>(values[3]),
            static_cast<long long>(values[6]),
            static_cast<long long>(values[7]),
            static_cast<long long>(values[4]),
            (mask & (1UL << 4U)) != 0UL ? 1U : 0U,
            (mask & (1UL << 4U)) != 0UL ? 1U : 0U,
            (mask & (1UL << 14U)) != 0UL ? 1U : 0U);
    jlongArray result = env->NewLongArray(8);
    if (result == nullptr) return nullptr;
    env->SetLongArrayRegion(result, 0, 8, values);
    return result;
}
extern "C" __attribute__((visibility("default"))) volatile int
    rtgum_lifecycle_probe_state = 0;

__attribute__((constructor)) static void rtgum_lifecycle_constructor()
{
    rtgum_lifecycle_probe_state = 1;
}

extern "C" JNIEXPORT jint JNICALL rtgum_lifecycle_native_value(JNIEnv *,
                                                                 jclass)
{
    return rtgum_lifecycle_probe_state == 2 ? 0x534f4c43 :
                                              -rtgum_lifecycle_probe_state;
}

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *)
{
    if (!vm || rtgum_lifecycle_probe_state != 1) return JNI_ERR;
    JNIEnv *env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK ||
        !env)
        return JNI_ERR;
    jclass probe = env->FindClass("dev/rtgum/lab/LifecycleProbe");
    if (!probe || env->ExceptionCheck()) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (probe) env->DeleteLocalRef(probe);
        return JNI_ERR;
    }
    JNINativeMethod method{
        const_cast<char *>("nativeValue"), const_cast<char *>("()I"),
        reinterpret_cast<void *>(&rtgum_lifecycle_native_value)};
    const jint registered = env->RegisterNatives(probe, &method, 1);
    env->DeleteLocalRef(probe);
    if (registered != JNI_OK) return JNI_ERR;
    rtgum_lifecycle_probe_state = 2;
    return JNI_VERSION_1_6;
}

