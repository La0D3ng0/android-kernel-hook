#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <cstddef>
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <linux/hw_breakpoint.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <string>
#include <thread>
#include <vector>
#include <sys/auxv.h>
#include <sys/epoll.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/ifunc.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__aarch64__)
#include <android/dlext.h>
#include <asm/hwcap.h>
#include <asm/mman.h>
#endif

#include <rtgum/kpm_supercall.h>
#include <rtgum/ghost_api.h>
#include <rtgum/gum_api.h>
#include <rtgum/gtrace.hpp>

#include "dbi/rtgum-dbi.h"
#include "dbi/rtgum-dbi-ehframe.h"
#include "dbi/rtgum-dbi-follow.h"
#include "vma/rtgum-vma.h"

extern "C" long rtgum_dbi_personality_frame(long (*target)(long), long value);
extern "C" volatile unsigned int rtgum_dbi_personality_hits;

namespace {

constexpr const char *kModuleName = "rtgum-stage1";
constexpr std::size_t kControlBufferSize = 2048;
constexpr std::size_t kVmaControlBufferSize = 512U * 1024U;
constexpr std::size_t kTraceControlBufferSize = 128U * 1024U;

rtgum::vma::PerPidCache g_vma_cache;
rtgum::vma::ElfCache g_vma_elf_cache;

long find_pid_by_cmdline(const char *prefix, bool exact = false);
long find_pid_by_comm(const char *name);
bool module_is_loaded(const char *key);
/* Leaves the Zygote Daemon linked and the target app running (see its
 * definition): the ART path needs the hook to stay observable. */
int command_mako_hold(const char *key, const char *package,
                      bool use_existing_manager_config = false);

sigjmp_buf g_xonly_read_jump;
volatile sig_atomic_t g_xonly_read_fault = 0;

void xonly_read_fault_handler(int signal, siginfo_t *, void *)
{
    g_xonly_read_fault = signal;
    siglongjmp(g_xonly_read_jump, 1);
}

// Returns 1 only when an EL0 data read faults after instruction fetch succeeds.
int probe_xonly_data_read(volatile const unsigned char *address)
{
    struct sigaction handler{};
    struct sigaction previous{};
    handler.sa_sigaction = xonly_read_fault_handler;
    handler.sa_flags = SA_SIGINFO;
    sigemptyset(&handler.sa_mask);
    if (sigaction(SIGSEGV, &handler, &previous) != 0) return -1;

    g_xonly_read_fault = 0;
    if (sigsetjmp(g_xonly_read_jump, 1) == 0) {
        const volatile unsigned char value = *address;
        (void)value;
    }
    const int fault = g_xonly_read_fault == SIGSEGV ? 1 : 0;
    if (sigaction(SIGSEGV, &previous, nullptr) != 0) return -1;
    return fault;
}

void usage(const char *program)
{
    std::fprintf(stderr,
                 "Usage: RTGUM_SUPERKEY=<key> RTGUM_SESSION_KEY=<key> %s <command> [argument]\n"
                 "Commands:\n"
                 "  ready                    check the KernelPatch supercall\n"
                 "  load <module.kpm>        load the stage-1 KPM\n"
                 "  ping                     perform a KPM control round-trip\n"
                 "  capabilities             report runtime kernel prerequisites\n"
                 "  session-pair <code>      consume the one-time debug pairing code\n"
                 "  session-manager          request a session as the signed Manager\n"
                 "  auth-status              report enrollment methods without secrets\n"
                 "  pid-probe <pid>          inspect a task name under RCU\n"
                 "  zygote-find <pid>        validate an arm64 Zygote PID in KPM\n"
                 "  zygote-test              remote DT_NEEDED+import resolution into Zygote\n"
                 "  stage2-test <package>    full Zygote hijack, fork inheritance, package\n"
                 "                           dispatch, hot reload end-to-end test\n"
                 "  daemon-shutdown <pid>    unload the active module in place\n"
                 "  mako-manager-test <pkg>  bootstrap using Manager-cached config\n"
                 "  zygote-dex-test          Daemon-owned ghost DEX loader acceptance\n"
                 "  zygote-interceptor-test  Binder token + linker dlopen Shadow hooks\n"
                 "  zygote-lifecycle-test    constructors + JNI_OnLoad/RegisterNatives trace\n"
                 "  zygote-gtrace-test       dynamic BR path + explicit junk-gap acceptance\n"
                 "  zygote-multitrace-test   independent asynchronous A/B trace handles\n"
                 "  gumlua-target-test <pkg> <component> <label> [quiet-seconds]\n"
                 "                           one-app Zygote/Gum/Lua distribution test\n"
                 "  symbol-target-test <pkg> <component> shared Hook/Trace ELF resolver test\n"
                  "  memory-read <pid> <va> [len]  GUP-read an authorized target\n"
                  "  memory-write <pid> <va> <hex> GUP-write an authorized target\n"
                  "  memory-status            report operations and mm-ref balance\n"
                  "  vma-dump <pid>           snapshot kernel VMAs without /proc/maps\n"
                  "  vma-symbolize <pid> <pc> <elf> resolve PC using VMA + disk ELF caches\n"
                  "  vma-proc-baseline <pid>  acceptance-only privileged /proc/maps baseline\n"
                  "  vma-test-ghost-alloc <pid> create one acceptance-only VMA-less page\n"
                  "  vma-test-ghost-free <pid> <va> remove that acceptance page\n"
                  "  trace-start <pid> <tid> <entry> <start> <end> <steps>\n"
                  "                           arm bounded kernel CPU single-step trace\n"
                  "  trace-status <handle>    report trace and affinity restoration state\n"
                  "  trace-read <handle> [n] batched destructive read (n <= 32)\n"
                  "  gtrace-read <handle> <pid> <start> <end> [n]\n"
                  "                           format CPU-SS records as executed path/edges/gaps\n"
                  "  trace-stop <handle>      stop at the next software-step boundary\n"
                  "  trace-clear <handle>     release completed session and entry HWBP\n"
                 "  shadow-hook-enable       install the code Shadow Hook backend\n"
                 "  shadow-preflight <pid> <va> validate pin/PTE/copy prerequisites\n"
                 "  shadow-prepare <pid> <va> pin and copy without changing the PTE\n"
                 "  shadow-install <pid> <va> install a code shadow page\n"
                 "  shadow-patch-code <pid> <va> <hex> patch the execution view\n"
                 "  shadow-release-page <pid> <va> release a code shadow page\n"
                 "  shadow-hook-status       report code Shadow Hook state\n"
                 "  stage2-bisect           stage2-test up to bootstrap, then stop (crash bisect)\n"
                 "  ghost-test               allocate, hide, execute, and free one ghost page\n"
                 "  ghost-race-test          protect and free Ghost pages concurrently\n"
                 "  hwbp-test                trace entry and return on the main thread\n"
                 "  hwbp-probe-test          register and clear without executing the target\n"
                 "  hwbp-replace-test        call the original through a closed gate\n"
                 "  hwbp-capacity-test       verify six slots, limit, and slot reuse\n"
                 "  antidbg-lab-test         ptrace/perf five-step fake-ledger acceptance\n"
                 "  shadowhook-lifecycle-test shared dispatcher and dormant-hook lifecycle\n"
                 "  antidbg-ebpf-probe       observe ptrace/perf syscalls with optional eBPF\n"
                 "  unload-guard-test        confirm live ghost state blocks KPM unload\n"
                 "  fork-test                verify explicit fork clone and exit cleanup\n"
                 "  linker-test              KPM-load and execute the test ET_DYN image\n"
                 "  needed-ifunc-test        resolve libc import and repair IFUNC in this process\n"
                 "  needed-version-reject-test  reject a mismatched GNU symbol version\n"
                 "  needed-maps-ambiguous-test  reject a duplicate libc map instance\n"
                 "  needed-file-mismatch-test  reject a changed provider build ID\n"
                 "  channel-test             verify authenticated membarrier channel\n"
                 "  real-so-test             load and call the supplied Android ET_DYN image\n"
                 "  control <command-string> send an unmodified control command\n"
                 "  list                     list loaded KPM names\n"
                 "  info                     show stage-1 KPM metadata\n"
                 "  dmesg                    elevate this process and read dmesg\n"
                 "  dmesg-w                  elevate and stream dmesg -w\n"
                 "  pstore-dump              elevate and dump /sys/fs/pstore (crash logs)\n"
                 "  unload                   unload the stage-1 KPM\n"
                 "  probe <module.kpm>       ready + load/reuse + ping + capabilities\n",
                 program);
}

const char *require_key()
{
    const char *key = std::getenv("RTGUM_SUPERKEY");
    if (!key || key[0] == '\0') {
        std::fprintf(stderr, "RTGUM_SUPERKEY is required\n");
        return nullptr;
    }
    if (strnlen(key, RTGUM_SUPERCALL_KEY_MAX_LEN) >= RTGUM_SUPERCALL_KEY_MAX_LEN) {
        std::fprintf(stderr, "RTGUM_SUPERKEY is too long\n");
        return nullptr;
    }
    return key;
}

int report_call_error(const char *operation, long result)
{
    if (result == -1)
        std::fprintf(stderr, "%s failed: errno=%d (%s)\n", operation, errno, std::strerror(errno));
    else
        std::fprintf(stderr, "%s failed: result=%ld\n", operation, result);
    return 1;
}

int command_ready(const char *key)
{
    const long hello = rtgum_sc_hello(key);
    if (hello != RTGUM_SUPERCALL_HELLO_MAGIC) return report_call_error("supercall hello", hello);
    std::printf("ready hello=0x%lx kpver=0x%x kver=0x%x\n",
                hello,
                rtgum_sc_kp_ver(key),
                rtgum_sc_k_ver(key));
    return 0;
}

int command_load(const char *key, const char *path)
{
    rtgum_kpm_load_result detail{};
    detail.magic = RTGUM_KPM_LOAD_RESULT_MAGIC;
    detail.size = sizeof(detail);
    const long result = rtgum_sc_kpm_load(key, path, "stage1-probe", &detail);
    if (result != 0) {
        if (detail.magic == RTGUM_KPM_LOAD_RESULT_MAGIC && detail.message[0] != '\0')
            std::fprintf(stderr, "KPM load detail: code=%d message=%s\n", detail.code, detail.message);
        return report_call_error("KPM load", result);
    }
    std::printf("loaded module=%s path=%s detail=%s\n",
                kModuleName,
                path,
                detail.message[0] ? detail.message : "not-reported");
    return 0;
}

int command_load_nohooks(const char *key, const char *path)
{
    rtgum_kpm_load_result detail{};
    detail.magic = RTGUM_KPM_LOAD_RESULT_MAGIC;
    detail.size = sizeof(detail);
    const long result = rtgum_sc_kpm_load(key, path, "nohooks", &detail);
    if (result != 0) {
        if (detail.magic == RTGUM_KPM_LOAD_RESULT_MAGIC && detail.message[0] != '\0')
            std::fprintf(stderr, "KPM load detail: code=%d message=%s\n", detail.code, detail.message);
        return report_call_error("KPM load (nohooks)", result);
    }
    std::printf("loaded-nohooks module=%s path=%s\n", kModuleName, path);
    return 0;
}

int command_load_args(const char *key, const char *path, const char *args)
{
    rtgum_kpm_load_result detail{};
    detail.magic = RTGUM_KPM_LOAD_RESULT_MAGIC;
    detail.size = sizeof(detail);
    const long result = rtgum_sc_kpm_load(key, path, args, &detail);
    if (result != 0) {
        if (detail.magic == RTGUM_KPM_LOAD_RESULT_MAGIC && detail.message[0] != '\0')
            std::fprintf(stderr, "KPM load detail: code=%d message=%s\n", detail.code, detail.message);
        return report_call_error("KPM load (args)", result);
    }
    std::printf("loaded module=%s args=%s\n", kModuleName, args);
    return 0;
}

int control_raw(const char *key,
                const char *command,
                char *response,
                std::size_t response_size)
{
    std::memset(response, 0, response_size);
    const long result =
        rtgum_sc_kpm_control(key, kModuleName, command, response, static_cast<long>(response_size));
    if (result != 0) return report_call_error("KPM control", result);
    if (response[0] == '\0') {
        std::fprintf(stderr, "KPM control returned an empty response\n");
        return 1;
    }
    return 0;
}

int control(const char *key, const char *command, char *response, std::size_t response_size)
{
    const char *session = std::getenv("RTGUM_SESSION_KEY");
    if (!session || session[0] == '\0')
        return control_raw(key, command, response, response_size);
    if (strnlen(session, 65) != 64) {
        std::fprintf(stderr, "RTGUM_SESSION_KEY must contain 64 hexadecimal characters\n");
        return 1;
    }
    char authenticated[1024];
    const int length = std::snprintf(
        authenticated, sizeof(authenticated), "auth %s %s", session, command);
    if (length < 0 || static_cast<std::size_t>(length) >= sizeof(authenticated)) {
        std::fprintf(stderr, "authenticated command is too long\n");
        return 1;
    }
    return control_raw(key, authenticated, response, response_size);
}

int command_session_enrollment(const char *key, const char *command)
{
    char response[kControlBufferSize];
    if (control_raw(key, command, response, sizeof(response)) != 0) return 1;
    std::puts(response);
    return std::strncmp(response, "ok ", 3) == 0 ||
                   std::strncmp(response, "ready=", 6) == 0
               ? 0
               : 1;
}

int command_control(const char *key, const char *command)
{
    char response[kControlBufferSize];
    if (control(key, command, response, sizeof(response)) != 0) return 1;
    std::puts(response);
    return 0;
}

int command_memory_read(const char *key, const char *pid, const char *address,
                        const char *length)
{
    char command[128];
    const int written = length
                            ? std::snprintf(command, sizeof(command),
                                            "mem-read %s %s %s", pid, address, length)
                            : std::snprintf(command, sizeof(command),
                                            "mem-read %s %s", pid, address);
    if (written < 0 || static_cast<std::size_t>(written) >= sizeof(command)) return 2;
    char response[kControlBufferSize];
    if (control(key, command, response, sizeof(response)) != 0) return 1;
    std::puts(response);
    return std::strncmp(response, "ok ", 3) == 0 ? 0 : 1;
}

int command_memory_write(const char *key, const char *pid, const char *address,
                          const char *hex)
{
    char command[1024];
    const int written = std::snprintf(command, sizeof(command),
                                      "mem-write %s %s %s", pid, address, hex);
    if (written < 0 || static_cast<std::size_t>(written) >= sizeof(command)) return 2;
    char response[kControlBufferSize];
    if (control(key, command, response, sizeof(response)) != 0) return 1;
    std::puts(response);
    return std::strncmp(response, "ok ", 3) == 0 ? 0 : 1;
}

int command_trace_start(const char *key, int argc, char **argv)
{
    if (argc != 8) return 2;
    char command[256];
    const int written = std::snprintf(
        command, sizeof(command), "trace-start %s %s %s %s %s %s",
        argv[2], argv[3], argv[4], argv[5], argv[6], argv[7]);
    if (written < 0 || static_cast<std::size_t>(written) >= sizeof(command)) return 2;
    char response[kControlBufferSize]{};
    if (control(key, command, response, sizeof(response)) != 0) return 1;
    std::puts(response);
    return std::strncmp(response, "ok ", 3) == 0 ? 0 : 1;
}

int command_trace_simple(const char *key, const char *operation, const char *handle)
{
    char command[96];
    const int written = std::snprintf(command, sizeof(command),
                                      "trace-%s %s", operation, handle);
    if (written < 0 || static_cast<std::size_t>(written) >= sizeof(command)) return 2;
    char response[kControlBufferSize]{};
    if (control(key, command, response, sizeof(response)) != 0) return 1;
    std::puts(response);
    return std::strncmp(response, "ok ", 3) == 0 ? 0 : 1;
}

int command_trace_read(const char *key, const char *handle, const char *maximum)
{
    char command[96];
    const int written = maximum
                            ? std::snprintf(command, sizeof(command),
                                            "trace-read %s %s", handle, maximum)
                            : std::snprintf(command, sizeof(command),
                                            "trace-read %s", handle);
    if (written < 0 || static_cast<std::size_t>(written) >= sizeof(command)) return 2;
    std::vector<char> response(kTraceControlBufferSize, '\0');
    if (control(key, command, response.data(), response.size()) != 0) return 1;
    std::fputs(response.data(), stdout);
    if (response[std::strlen(response.data()) - 1U] != '\n') std::fputc('\n', stdout);
    return std::strncmp(response.data(), "ok ", 3) == 0 ? 0 : 1;
}

bool parse_cli_unsigned(const char *text, unsigned long long &value)
{
    if (!text || *text == '\0' || *text == '-') return false;
    char *end = nullptr;
    errno = 0;
    value = std::strtoull(text, &end, 0);
    return errno == 0 && end != text && *end == '\0';
}

int command_gtrace_read(const char *key, int argc, char **argv)
{
    if (argc != 6 && argc != 7) return 2;
    unsigned long long handle = 0ULL;
    unsigned long long pid = 0ULL;
    unsigned long long image_start = 0ULL;
    unsigned long long image_end = 0ULL;
    unsigned long long maximum = 32ULL;
    if (!parse_cli_unsigned(argv[2], handle) || handle == 0ULL ||
        !parse_cli_unsigned(argv[3], pid) || pid == 0ULL || pid > 0x7fffffffULL ||
        !parse_cli_unsigned(argv[4], image_start) ||
        !parse_cli_unsigned(argv[5], image_end) || image_start == 0ULL ||
        image_end <= image_start || ((image_start | image_end) & 3ULL) != 0ULL ||
        (argc == 7 && !parse_cli_unsigned(argv[6], maximum)) ||
        maximum == 0ULL || maximum > 32ULL)
        return 2;

    char command[128];
    const int written = std::snprintf(command, sizeof(command),
                                      "trace-read %llu %llu", handle, maximum);
    if (written < 0 || static_cast<std::size_t>(written) >= sizeof(command)) return 2;
    std::vector<char> trace(kTraceControlBufferSize, '\0');
    if (control(key, command, trace.data(), trace.size()) != 0 ||
        std::strncmp(trace.data(), "ok ", 3) != 0) {
        std::fprintf(stderr, "GTrace CPU-SS read failed: %s\n", trace.data());
        return 1;
    }

    std::vector<RtGumGtraceStep> steps;
    const char *line = std::strchr(trace.data(), '\n');
    while (line && *line != '\0') {
        ++line;
        if (*line == '\0') break;
        const char *next = std::strchr(line, '\n');
        if (std::strncmp(line, "trace ", 6) == 0) {
            unsigned long long sequence = 0ULL;
            unsigned long long pc = 0ULL;
            unsigned long long landing = 0ULL;
            if (std::sscanf(line,
                            "trace seq=%llu pc=0x%llx timestamp=%*llu next=0x%llx",
                            &sequence, &pc, &landing) != 3 || sequence == 0ULL ||
                pc > ~0UL || landing > ~0UL) {
                std::fprintf(stderr, "Malformed CPU-SS trace record: %.*s\n",
                             next ? static_cast<int>(next - line) : 160, line);
                return 1;
            }

            char read_command[128];
            const int read_written = std::snprintf(
                read_command, sizeof(read_command), "mem-read %llu 0x%llx 4", pid, pc);
            if (read_written < 0 ||
                static_cast<std::size_t>(read_written) >= sizeof(read_command))
                return 2;
            char read_response[kControlBufferSize]{};
            if (control(key, read_command, read_response, sizeof(read_response)) != 0 ||
                std::strncmp(read_response, "ok ", 3) != 0) {
                std::fprintf(stderr,
                             "GTrace cannot read instruction at 0x%llx: %s\n",
                             pc, read_response);
                return 1;
            }
            const char *hex = std::strstr(read_response, "hex=");
            if (!hex) {
                std::fprintf(stderr, "GTrace memory reply lacks hex bytes: %s\n",
                             read_response);
                return 1;
            }
            hex += 4;
            unsigned int instruction = 0U;
            for (unsigned int byte = 0U; byte < 4U; ++byte) {
                unsigned int value = 0U;
                for (unsigned int nibble = 0U; nibble < 2U; ++nibble) {
                    const char ch = hex[byte * 2U + nibble];
                    unsigned int digit = 0U;
                    if (ch >= '0' && ch <= '9') digit = static_cast<unsigned int>(ch - '0');
                    else if (ch >= 'a' && ch <= 'f') digit = 10U + static_cast<unsigned int>(ch - 'a');
                    else if (ch >= 'A' && ch <= 'F') digit = 10U + static_cast<unsigned int>(ch - 'A');
                    else {
                        std::fprintf(stderr, "GTrace invalid instruction bytes: %s\n", hex);
                        return 1;
                    }
                    value = (value << 4U) | digit;
                }
                instruction |= value << (byte * 8U);
            }
            RtGumGtraceStep step{};
            step.sequence = sequence;
            step.pc = static_cast<unsigned long>(pc);
            step.next_pc = static_cast<unsigned long>(landing);
            step.instruction = instruction;
            step.flags = RTGUM_GTRACE_STEP_INSN_VALID |
                         RTGUM_GTRACE_STEP_NEXT_VALID |
                         RTGUM_GTRACE_STEP_DYNAMIC |
                         RTGUM_GTRACE_STEP_CPU_SINGLE_STEP;
            steps.push_back(step);
        }
        line = next;
    }
    if (steps.empty()) {
        std::fprintf(stderr, "GTrace CPU-SS batch contains no records\n");
        return 1;
    }

    std::vector<char> formatted(kTraceControlBufferSize, '\0');
    const long status = rtgum::native::GtraceFormatPath(
        steps.data(), static_cast<unsigned long>(steps.size()),
        static_cast<unsigned long>(image_start), static_cast<unsigned long>(image_end),
        formatted.data(), static_cast<unsigned long>(formatted.size()));
    if (status != 0L) {
        std::fprintf(stderr, "GTrace formatter failed: %ld\n", status);
        return 1;
    }
    std::fputs(formatted.data(), stdout);
    return 0;
}

bool fetch_vma_snapshot(const char *key,
                        long pid,
                        std::vector<char> &response,
                        std::string &error)
{
    char command[64];
    const int written = std::snprintf(command, sizeof(command), "vma-dump %ld", pid);
    if (written < 0 || static_cast<std::size_t>(written) >= sizeof(command)) {
        error = "VMA command formatting failed";
        return false;
    }
    response.assign(kVmaControlBufferSize, '\0');
    if (control(key, command, response.data(), response.size()) != 0) {
        error = "kernel VMA control request failed";
        return false;
    }
    if (std::strncmp(response.data(), "ok ", 3) != 0) {
        error = response.data();
        return false;
    }
    if (!g_vma_cache.update(response.data(), error)) return false;
    const rtgum::vma::Snapshot *snapshot = g_vma_cache.get(pid);
    if (!snapshot || snapshot->pid != pid) {
        error = "per-pid VMA cache did not retain the requested snapshot";
        return false;
    }
    return true;
}

int command_vma_dump(const char *key, const char *pid_text)
{
    unsigned long long parsed_pid = 0;
    if (!parse_cli_unsigned(pid_text, parsed_pid) || parsed_pid == 0 ||
        parsed_pid > 0x7fffffffULL) {
        std::fprintf(stderr, "vma-dump: invalid pid\n");
        return 2;
    }
    std::vector<char> response;
    std::string error;
    if (!fetch_vma_snapshot(key, static_cast<long>(parsed_pid), response, error)) {
        std::fprintf(stderr, "vma-dump failed: %s\n", error.c_str());
        return 1;
    }
    std::fputs(response.data(), stdout);
    return 0;
}

int hex_nibble(char value)
{
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

bool read_remote_for_symbolization(const char *key,
                                   long pid,
                                   unsigned long long address,
                                   std::size_t length,
                                   std::vector<unsigned char> &bytes,
                                   std::string &error)
{
    if (length == 0 || length > 384U) {
        error = "symbol identity read has an invalid length";
        return false;
    }
    char command[96];
    std::snprintf(command, sizeof(command), "mem-read %ld 0x%llx %zu",
                  pid, address, length);
    char response[kControlBufferSize]{};
    if (control(key, command, response, sizeof(response)) != 0 ||
        std::strncmp(response, "ok ", 3) != 0) {
        error = response[0] ? response : "kernel identity read failed";
        return false;
    }
    const char *hex = std::strstr(response, "hex=");
    if (!hex) {
        error = "kernel identity read omitted hex data";
        return false;
    }
    hex += 4;
    bytes.resize(length);
    for (std::size_t index = 0; index < length; ++index) {
        const int high = hex_nibble(hex[index * 2U]);
        const int low = hex_nibble(hex[index * 2U + 1U]);
        if (high < 0 || low < 0) {
            error = "kernel identity read returned malformed hex";
            return false;
        }
        bytes[index] = static_cast<unsigned char>((high << 4U) | low);
    }
    const char tail = hex[length * 2U];
    if (tail != '\0' && tail != ' ' && tail != '\n') {
        error = "kernel identity read returned an unexpected length";
        return false;
    }
    return true;
}

int command_vma_symbolize(const char *key,
                          const char *pid_text,
                          const char *pc_text,
                          const char *elf_path)
{
    unsigned long long parsed_pid = 0;
    unsigned long long pc = 0;
    if (!parse_cli_unsigned(pid_text, parsed_pid) || parsed_pid == 0 ||
        parsed_pid > 0x7fffffffULL || !parse_cli_unsigned(pc_text, pc) || pc == 0 ||
        !elf_path || elf_path[0] == '\0') {
        std::fprintf(stderr, "usage: vma-symbolize <pid> <pc> <disk-elf>\n");
        return 2;
    }

    std::vector<char> response;
    std::string error;
    const long pid = static_cast<long>(parsed_pid);
    if (!fetch_vma_snapshot(key, pid, response, error)) {
        std::fprintf(stderr, "VMA cache refresh failed: %s\n", error.c_str());
        return 1;
    }
    const rtgum::vma::Snapshot *snapshot = g_vma_cache.get(pid);
    bool elf_cache_hit = false;
    const rtgum::vma::ElfImage *image =
        g_vma_elf_cache.get(elf_path, elf_cache_hit, error);
    if (!image) {
        std::fprintf(stderr, "ELF cache load failed: %s\n", error.c_str());
        return 1;
    }
    rtgum::vma::Symbolized symbolized;
    if (!image->symbolize(*snapshot, pc, symbolized, error)) {
        std::fprintf(stderr, "symbolization failed: %s\n", error.c_str());
        return 1;
    }

    /* A basename and matching segment geometry alone can collide. Confirm the
     * selected load bias by comparing the mapped ELF header through the new
     * kernel memory transport; this still does not touch /proc or ptrace. */
    std::size_t prefix_length = 0;
    const unsigned char *prefix = image->header_prefix(prefix_length);
    std::vector<unsigned char> remote;
    if (!read_remote_for_symbolization(key, pid, symbolized.load_bias,
                                       prefix_length, remote, error) ||
        remote.size() != prefix_length ||
        std::memcmp(prefix, remote.data(), prefix_length) != 0) {
        std::fprintf(stderr, "ELF identity validation failed: %s\n",
                     error.empty() ? "mapped header differs from disk ELF" : error.c_str());
        return 1;
    }

    std::printf(
        "ok pid=%ld pc=0x%llx vma=0x%llx-0x%llx load-bias=0x%llx "
        "module=%s symbol=%s offset=0x%llx result=%s!%s+0x%llx "
        "vma-cache=per-pid elf-cache=%s identity=elf-header ghost=excluded-vmaless\n",
        pid,
        pc,
        static_cast<unsigned long long>(symbolized.vma.start),
        static_cast<unsigned long long>(symbolized.vma.end),
        static_cast<unsigned long long>(symbolized.load_bias),
        symbolized.module.c_str(),
        symbolized.symbol.c_str(),
        static_cast<unsigned long long>(symbolized.offset),
        symbolized.module.c_str(),
        symbolized.symbol.c_str(),
        static_cast<unsigned long long>(symbolized.offset),
        elf_cache_hit ? "hit" : "miss");
    return 0;
}

int command_vma_test_ghost(const char *key,
                           const char *operation,
                           const char *pid,
                           const char *address)
{
    char command[128];
    const int written = address
                            ? std::snprintf(command, sizeof(command),
                                            "vma-test-ghost-%s %s %s",
                                            operation, pid, address)
                            : std::snprintf(command, sizeof(command),
                                            "vma-test-ghost-%s %s",
                                            operation, pid);
    if (written < 0 || static_cast<std::size_t>(written) >= sizeof(command)) return 2;
    return command_control(key, command);
}

/* This is deliberately separate from vma-dump and vma-symbolize. Production
 * VMA discovery never opens procfs; the smoke test needs an independent view
 * with which to compare the kernel walk on Android builds where shell is not
 * permitted to read another process' maps. */
int command_vma_proc_baseline(const char *key, const char *pid_text)
{
    unsigned long long parsed_pid = 0;
    if (!parse_cli_unsigned(pid_text, parsed_pid) || parsed_pid == 0 ||
        parsed_pid > 0x7fffffffULL) {
        std::fprintf(stderr, "vma-proc-baseline: invalid pid\n");
        return 2;
    }

    rtgum_su_profile profile{};
    profile.uid = static_cast<std::uint32_t>(getuid());
    profile.to_uid = 0;
    const long elevated = rtgum_sc_su(key, &profile);
    if (elevated != 0)
        return report_call_error("temporary SuperCall elevation", elevated);
    if (getuid() != 0) {
        std::fprintf(stderr,
                     "SuperCall elevation returned success but uid is not zero\n");
        return 1;
    }

    char path[64];
    const int path_length = std::snprintf(path, sizeof(path), "/proc/%llu/maps",
                                          parsed_pid);
    if (path_length < 0 || static_cast<std::size_t>(path_length) >= sizeof(path))
        return 2;
    const int input = open(path, O_RDONLY | O_CLOEXEC);
    if (input < 0) {
        std::fprintf(stderr, "open %s failed: %s\n", path, std::strerror(errno));
        return 1;
    }

    char buffer[16384];
    int result = 0;
    for (;;) {
        const ssize_t received = read(input, buffer, sizeof(buffer));
        if (received == 0) break;
        if (received < 0) {
            if (errno == EINTR) continue;
            std::fprintf(stderr, "read %s failed: %s\n", path, std::strerror(errno));
            result = 1;
            break;
        }
        ssize_t sent = 0;
        while (sent < received) {
            const ssize_t written = write(STDOUT_FILENO, buffer + sent,
                                          static_cast<std::size_t>(received - sent));
            if (written < 0 && errno == EINTR) continue;
            if (written <= 0) {
                std::fprintf(stderr, "write VMA baseline failed: %s\n",
                             std::strerror(errno));
                result = 1;
                break;
            }
            sent += written;
        }
        if (result != 0) break;
    }
    if (close(input) != 0 && result == 0) {
        std::fprintf(stderr, "close %s failed: %s\n", path, std::strerror(errno));
        result = 1;
    }
    return result;
}

int command_ping(const char *key)
{
    char response[kControlBufferSize];
    if (control(key, "ping", response, sizeof(response)) != 0) return 1;
    if (std::strncmp(response, "pong ", 5) != 0) {
        std::fprintf(stderr, "unexpected ping response: %s\n", response);
        return 1;
    }
    std::printf("syscall-roundtrip %s\n", response);
    return 0;
}

bool range_file_contains(const char *path,
                         std::uintptr_t address,
                         char *matched,
                         std::size_t matched_size)
{
    FILE *file = std::fopen(path, "r");
    char line[512];
    if (!file) return false;
    while (std::fgets(line, sizeof(line), file)) {
        unsigned long start = 0;
        unsigned long end = 0;
        if (std::sscanf(line, "%lx-%lx", &start, &end) == 2 && address >= start &&
            address < end) {
            std::snprintf(matched, matched_size, "%s", line);
            matched[std::strcspn(matched, "\r\n")] = '\0';
            std::fclose(file);
            return true;
        }
    }
    std::fclose(file);
    return false;
}

bool response_hex_field(const char *response,
                        const char *field,
                        unsigned long &value)
{
    value = 0UL;
    if (!response || !field) return false;
    const char *cursor = std::strstr(response, field);
    if (!cursor) return false;
    cursor += std::strlen(field);
    if (cursor[0] != '0' || (cursor[1] != 'x' && cursor[1] != 'X')) return false;
    char *end = nullptr;
    errno = 0;
    const unsigned long parsed = std::strtoul(cursor, &end, 16);
    if (errno != 0 || end == cursor || (*end != '\0' && *end != ' ')) return false;
    value = parsed;
    return true;
}

/* Read /proc/<pid>/maps in userspace (the only access path that works for
 * cross-process maps on this device) into a VMA-less ghost buffer that the
 * KPM can then parse in kernel. The buffer never shows up in maps. */
bool read_maps_into_ghost(const char *key,
                          long pid,
                          unsigned long &buffer_address,
                          unsigned long &maps_length)
{
    buffer_address = 0;
    maps_length = 0;
    /* Snapshot first, then allocate only as many ghost pages as needed.
     * A fixed 512 KiB ghost request can fail to fit in a process's current
     * PMD window even when its maps file is much smaller. */
    constexpr std::size_t kMaxMapsBytes = 1024U * 1024U;
    std::string maps(kMaxMapsBytes, '\0');
    char path[64];
    std::snprintf(path, sizeof(path), "/proc/%ld/maps", pid);
    bool snapshot_ready = false;
    for (unsigned int attempt = 0; attempt < 3U; ++attempt) {
        maps_length = 0UL;
        FILE *file = std::fopen(path, "r");
        if (file) {
            maps_length = std::fread(&maps[0], 1, maps.size() - 1U, file);
            const bool complete = std::ferror(file) == 0 &&
                (maps_length < maps.size() - 1U || std::fgetc(file) == EOF);
            const bool read_error = std::ferror(file) != 0;
            std::fclose(file);
            snapshot_ready = maps_length != 0UL && complete && !read_error &&
                             maps[maps_length - 1UL] == '\n';
            if (snapshot_ready) break;
        }
        usleep(50000);
    }
    if (!snapshot_ready) {
        std::fprintf(stderr, "maps snapshot incomplete pid=%ld bytes=%lu after-retries=3\n",
                     pid, maps_length);
        return false;
    }
    char command[512];
    char response[kControlBufferSize];
    std::snprintf(command, sizeof(command), "ghost-alloc %lu 3", maps_length + 1UL);
    unsigned long address = 0;
    unsigned long size = 0;
    bool allocated = false;
    for (unsigned int attempt = 0; attempt < 3U; ++attempt) {
        address = 0UL;
        size = 0UL;
        if (control(key, command, response, sizeof(response)) == 0 &&
            std::sscanf(response, "ok address=0x%lx size=%lu", &address, &size) == 2 &&
            address != 0UL && size > maps_length) {
            allocated = true;
            break;
        }
        if (address != 0) {
            std::snprintf(command, sizeof(command), "ghost-free 0x%lx", address);
            control(key, command, response, sizeof(response));
            std::snprintf(command, sizeof(command), "ghost-alloc %lu 3",
                          maps_length + 1UL);
        }
        usleep(50000);
    }
    if (!allocated) {
        std::fprintf(stderr, "maps ghost allocation failed after-retries=3: %s\n",
                     response);
        return false;
    }
    auto *mapping = reinterpret_cast<unsigned char *>(address);
    std::memcpy(mapping, maps.data(), maps_length);
    mapping[maps_length] = '\0';
    buffer_address = address;
    return true;
}

void free_ghost_buffer(const char *key, unsigned long address)
{
    char command[512];
    char response[kControlBufferSize];
    std::snprintf(command, sizeof(command), "ghost-free 0x%lx", address);
    control(key, command, response, sizeof(response));
}

struct LinkMapSearch final {
    const char *needle;
    bool found;
};

int find_link_map_entry(dl_phdr_info *info, std::size_t, void *opaque)
{
    auto *search = static_cast<LinkMapSearch *>(opaque);
    if (info && info->dlpi_name && std::strstr(info->dlpi_name, search->needle)) {
        search->found = true;
        return 1;
    }
    return 0;
}

int ghost_cleanup(const char *key, unsigned long address)
{
    char command[96];
    char response[kControlBufferSize];
    std::snprintf(command, sizeof(command), "ghost-free 0x%lx", address);
    if (control(key, command, response, sizeof(response)) != 0) return 1;
    if (std::strncmp(response, "ok ", 3) != 0) {
        std::fprintf(stderr, "ghost cleanup failed: %s\n", response);
        return 1;
    }
    return 0;
}

int command_channel_test()
{
    const char *session = std::getenv("RTGUM_SESSION_KEY");
    if (!session || strnlen(session, 65) != 64) return 2;
    const auto hex = [](char digit) -> int {
        if (digit >= '0' && digit <= '9') return digit - '0';
        if (digit >= 'a' && digit <= 'f') return digit - 'a' + 10;
        if (digit >= 'A' && digit <= 'F') return digit - 'A' + 10;
        return -1;
    };
    unsigned long words[4]{};
    for (unsigned int index = 0; index < 32U; ++index) {
        const int high = hex(session[index * 2U]);
        const int low = hex(session[index * 2U + 1U]);
        if (high < 0 || low < 0) return 2;
        words[index / 8U] |= static_cast<unsigned long>((high << 4U) | low)
                             << ((index % 8U) * 8U);
    }
    errno = 0;
    const long unauthenticated = syscall(RTGUM_DAEMON_SYSCALL,
                                         RTGUM_DAEMON_OP_CALIBRATE,
                                         0L, 0L, 0L, 0L, 0L);
    const int unauthenticated_errno = errno;
    errno = 0;
    const long authenticated = syscall(RTGUM_DAEMON_SYSCALL,
                                       RTGUM_DAEMON_OP_CALIBRATE,
                                       0L,
                                       words[0], words[1], words[2], words[3]);
    const int authenticated_errno = errno;
    if (unauthenticated < 0L || unauthenticated_errno != 0 ||
        authenticated != 0L || authenticated_errno != 0) {
        std::fprintf(stderr,
                     "channel ABI failed unauth=%ld errno=%d auth=%ld errno=%d\n",
                     unauthenticated, unauthenticated_errno,
                     authenticated, authenticated_errno);
        return 1;
    }
    std::printf("channel-auth=1 unauth-passthrough=%ld stage2-channel-test PASS\n",
                unauthenticated);
    return 0;
}

int command_hijack_self_test(const char *key)
{
    char response[kControlBufferSize]{};
    if (control(key, "hijack-self-test", response, sizeof(response)) != 0) return 1;
    unsigned long trampoline = 0;
    unsigned long context = 0;
    if (std::sscanf(response, "ok trampoline=0x%lx ctx=0x%lx armed=1",
                    &trampoline, &context) != 2 || trampoline == 0 || context == 0) {
        std::fprintf(stderr, "self-test was not armed: %s\n", response);
        return 1;
    }
    const volatile unsigned long *marker =
        reinterpret_cast<volatile unsigned long *>(context + 0x180UL);
    const unsigned long observed = *marker;
    char command[96];
    std::snprintf(command, sizeof(command), "ghost-free 0x%lx", trampoline);
    char cleanup[kControlBufferSize]{};
    const int cleanup_status = control(key, command, cleanup, sizeof(cleanup));
    if (cleanup_status != 0 || std::strncmp(cleanup, "ok ", 3) != 0) {
        std::fprintf(stderr, "self-test cleanup failed: %s\n", cleanup);
        return 1;
    }
    if (observed != 0x5a3UL) {
        std::fprintf(stderr, "self-test marker mismatch: 0x%lx\n", observed);
        return 1;
    }
    std::puts("trampoline-executed=1 restored=1 cleaned=1 stage2-hijack-self-test PASS");
    return 0;
}

int command_taskwork_selftest(const char *key)
{
    char response[kControlBufferSize]{};
    if (control(key, "taskwork-self-test", response, sizeof(response)) != 0) return 1;
    unsigned long trampoline = 0;
    unsigned long context = 0;
    if (std::sscanf(response, "ok trampoline=0x%lx ctx=0x%lx armed=1 taskwork=1",
                    &trampoline, &context) != 2 || trampoline == 0 || context == 0) {
        std::fprintf(stderr, "taskwork self-test was not armed: %s\n", response);
        return 1;
    }
    /* The task_work callback runs when THIS ioctl returns to user: the stub
     * executes right after the control call above completes. */
    const volatile unsigned long *marker =
        reinterpret_cast<volatile unsigned long *>(context + 0x180UL);
    const unsigned long observed = *marker;
    char command[96];
    std::snprintf(command, sizeof(command), "ghost-free 0x%lx", trampoline);
    char cleanup[kControlBufferSize]{};
    const int cleanup_status = control(key, command, cleanup, sizeof(cleanup));
    if (cleanup_status != 0 || std::strncmp(cleanup, "ok ", 3) != 0) {
        std::fprintf(stderr, "taskwork self-test cleanup failed: %s\n", cleanup);
        return 1;
    }
    if (observed != 0x5a3UL) {
        std::fprintf(stderr, "taskwork marker mismatch: 0x%lx\n", observed);
        return 1;
    }
    std::puts("taskwork-delivered=1 trampoline-executed=1 restored=1 cleaned=1 stage2-taskwork-self-test PASS");
    return 0;
}

/* ============ Shadow Hook lab acceptance ============ */

namespace {

constexpr const char *kShadowLabLib =
    "/data/local/tmp/rtgum-stage1-pixel8/librtgum-lab.so";
/* mov x0, #42 (MOVZ x0, #0x2a); ret */
constexpr const char *kShadowReplacePatch = "400580d2c0035fd6";

struct ShadowLabHandles {
    void *lib = nullptr;
    long (*lab_add)(long, long) = nullptr;
    long (*lab_listen)(long, long) = nullptr;
};

/* The no-op user gate for INTERCEPT / BEFORE_AFTER. Lives in the ctl's own
 * text (a page separate from the shadowed lab page, as the KPM requires).
 * Entered with x0 = the on-stack register context; ends with brk #0x5758. */
extern "C" __attribute__((naked, noinline)) void shadow_lab_gate()
{
    __asm__ volatile("brk #0x5758" ::: "memory");
}

int shadow_lab_control(const char *key, const char *command, char *response,
                       std::size_t response_size)
{
    if (control(key, command, response, response_size) != 0) {
        std::fprintf(stderr, "shadow-lab control failed: %s => %s\n", command, response);
        return -1;
    }
    if (std::strncmp(response, "ok ", 3) != 0) {
        std::fprintf(stderr, "shadow-lab control rejected: %s => %s\n", command, response);
        return -1;
    }
    return 0;
}

int shadow_lab_load(ShadowLabHandles &handles)
{
    handles.lib = dlopen(kShadowLabLib, RTLD_NOW | RTLD_LOCAL);
    if (!handles.lib) {
        std::fprintf(stderr, "shadow-lab dlopen failed: %s\n", dlerror());
        return -1;
    }
    handles.lab_add =
        reinterpret_cast<long (*)(long, long)>(dlsym(handles.lib, "lab_add"));
    handles.lab_listen =
        reinterpret_cast<long (*)(long, long)>(dlsym(handles.lib, "lab_listen"));
    if (!handles.lab_add || !handles.lab_listen) {
        std::fprintf(stderr, "shadow-lab dlsym failed\n");
        return -1;
    }
    return 0;
}

/* Read the first bytes of a function the "clean" way: a direct memcpy goes
 * through the fault path (which flips the PTE and serves the original), and
 * process_vm_readv goes through GUP (which gets the original via the
 * follow_page_pte hiding). Both must return the original prologue. */
int shadow_lab_read_probe(unsigned long address, const unsigned char *expected,
                          unsigned long length, bool use_gup, const char *label)
{
    unsigned char buffer[16]{};
    if (use_gup) {
        struct iovec local{};
        struct iovec remote{};
        local.iov_base = buffer;
        local.iov_len = length;
        remote.iov_base = reinterpret_cast<void *>(address);
        remote.iov_len = length;
        const ssize_t copied =
            process_vm_readv(getpid(), &local, 1, &remote, 1, 0);
        if (copied != static_cast<ssize_t>(length)) {
            std::fprintf(stderr, "shadow-lab %s process_vm_readv copied %zd\n",
                         label, copied);
            return -1;
        }
    } else {
        std::memcpy(buffer, reinterpret_cast<const void *>(address), length);
    }
    if (std::memcmp(buffer, expected, length) != 0) {
        std::fprintf(stderr,
                     "shadow-lab %s saw tampered bytes: %02x%02x%02x%02x...\n",
                     label, buffer[0], buffer[1], buffer[2], buffer[3]);
        return -1;
    }
    return 0;
}

/* Drains the LISTEN event ring and verifies a PRE/POST pair with the same
 * sequence. */
int shadow_lab_drain_events(const char *key, long pid, unsigned long site,
                            unsigned int rounds, unsigned int *pre_count,
                            unsigned int *post_count, bool *saw_pair)
{
    char command[96];
    char response[kControlBufferSize]{};
    for (unsigned int round = 0; round < rounds; ++round) {
        std::snprintf(command, sizeof(command), "shadow-events %ld 0x%lx 16",
                      pid, site);
        if (control(key, command, response, sizeof(response)) != 0) return -1;
        for (const char *line = std::strstr(response, "ev"); line != nullptr;) {
            unsigned int event_index = 0;
            unsigned int phase = 0;
            unsigned long long sequence = 0;
            unsigned long long site_va = 0;
            unsigned long long tid = 0;
            unsigned long long pc = 0;
            unsigned long long x0_value = 0;
            unsigned long long x1_value = 0;
            unsigned long long x2_value = 0;
            unsigned long long sp_value = 0;
            const int matched = std::sscanf(
                line,
                "ev%u phase=%u seq=%llu site=0x%llx tid=%llu pc=0x%llx "
                "x0=0x%llx x1=0x%llx x2=0x%llx sp=0x%llx",
                &event_index, &phase, &sequence, &site_va, &tid, &pc,
                &x0_value, &x1_value, &x2_value, &sp_value);
            if (matched < 10) break;
            if (phase == 1U) {
                ++*pre_count;
            } else if (phase == 2U) {
                ++*post_count;
                *saw_pair = true;
            }
            const char *next = std::strchr(line, '\n');
            if (!next) break;
            line = next + 1;
        }
    }
    return 0;
}

/* Isolation: the BRK + legacy single-step path (no XOL) on lab_listen. */
int command_shadow_brk_test(const char *key)
{
    char command[128];
    char response[kControlBufferSize]{};
    const long pid = static_cast<long>(getpid());
    signal(SIGSEGV, SIG_DFL);
    if (shadow_lab_control(key, "hook-shadow-hook", response, sizeof(response)) != 0)
        return 1;
    ShadowLabHandles lab{};
    if (shadow_lab_load(lab) != 0) return 1;
    const unsigned long listen_va = reinterpret_cast<unsigned long>(
        reinterpret_cast<void *>(lab.lab_listen));
    /* Fault the text page in before the shadow install: the KPM requires a
     * live PTE to snapshot the original PFN. */
    (void)*reinterpret_cast<const volatile unsigned char *>(listen_va);
    std::snprintf(command, sizeof(command), "shadow-install %ld 0x%lx", pid, listen_va);
    if (shadow_lab_control(key, command, response, sizeof(response)) != 0) return 1;
    std::puts("brk-test installed");
    std::fflush(stdout);
    std::snprintf(command, sizeof(command), "shadow-set-bp %ld 0x%lx 0 0 0",
                  pid, listen_va);
    if (shadow_lab_control(key, command, response, sizeof(response)) != 0) return 1;
    std::puts("brk-test armed");
    std::fflush(stdout);
    const long result = lab.lab_listen(1, 2);
    std::printf("brk-test call result=%ld\n", result);
    std::fflush(stdout);
    if (result != 3) {
        std::fprintf(stderr, "brk-test result mismatch\n");
        return 1;
    }
    std::snprintf(command, sizeof(command), "shadow-release %ld 0x%lx", pid, listen_va);
    if (shadow_lab_control(key, command, response, sizeof(response)) != 0) return 1;
    std::puts("brk=1 step=1 stage2-shadow-brk PASS");
    return 0;
}

} // namespace

int command_shadow_lab_test(const char *key)
{
    char command[128];
    char response[kControlBufferSize]{};
    const long pid = static_cast<long>(getpid());

    /* The ctl installs a SIGSEGV longjmp handler for the x-only read probes;
     * any shadow fault that escapes the KPM would longjmp to a stale buffer
     * and spin. The lab runs with the default disposition so an escaping
     * fault crashes loudly instead. */
    signal(SIGSEGV, SIG_DFL);

    if (shadow_lab_control(key, "hook-shadow-hook", response, sizeof(response)) != 0)
        return 1;

    ShadowLabHandles lab{};
    if (shadow_lab_load(lab) != 0) return 1;
    const unsigned long add_va = reinterpret_cast<unsigned long>(
        reinterpret_cast<void *>(lab.lab_add));
    const unsigned long listen_va = reinterpret_cast<unsigned long>(
        reinterpret_cast<void *>(lab.lab_listen));
    std::printf("shadow-lab add=0x%lx listen=0x%lx\n", add_va, listen_va);
    std::fflush(stdout);

    /* 1. Baseline: unhooked arithmetic. */
    if (lab.lab_add(1, 2) != 3 || lab.lab_listen(1, 2) != 3) {
        std::fprintf(stderr, "shadow-lab baseline arithmetic failed\n");
        return 1;
    }
    std::puts("shadow-lab baseline=3");
    std::fflush(stdout);

    /* 2. Capture the original prologue before any shadow exists. */
    unsigned char original[8]{};
    std::memcpy(original, reinterpret_cast<const void *>(add_va), sizeof(original));

    /* 3. Install the shadow page over lab_add. Fault the page in first so
     * the KPM can snapshot the original PFN. */
    (void)*reinterpret_cast<const volatile unsigned char *>(add_va);
    std::snprintf(command, sizeof(command), "shadow-install %ld 0x%lx", pid, add_va);
    if (shadow_lab_control(key, command, response, sizeof(response)) != 0) return 1;
    std::printf("shadow-lab installed: %s\n", response);
    std::fflush(stdout);

    /* 4. Read hiding: direct read (fault flip) and GUP read both see the
     * original prologue while execution still runs the shadow content. */
    if (shadow_lab_read_probe(add_va, original, 8, false, "direct-read") != 0) return 1;
    std::puts("shadow-lab read-hiding=1");
    std::fflush(stdout);
    if (shadow_lab_read_probe(add_va, original, 8, true, "gup-read") != 0) return 1;
    std::puts("shadow-lab gup-hiding=1");
    std::fflush(stdout);

    /* 5. REPLACE: patch the shadow page with mov x0,#42; ret. */
    std::snprintf(command, sizeof(command), "shadow-code-patch %ld 0x%lx %s",
                  pid, add_va, kShadowReplacePatch);
    if (shadow_lab_control(key, command, response, sizeof(response)) != 0) return 1;
    std::puts("shadow-lab patched");
    std::fflush(stdout);
    if (lab.lab_add(1, 2) != 42) {
        std::fprintf(stderr, "shadow-lab REPLACE did not return 42\n");
        return 1;
    }
    std::puts("shadow-lab replace=42");
    std::fflush(stdout);

    /* 6. The reads still see the clean prologue after the patch. */
    if (shadow_lab_read_probe(add_va, original, 8, false, "post-patch-read") != 0) return 1;
    if (shadow_lab_read_probe(add_va, original, 8, true, "post-patch-gup") != 0) return 1;
    std::puts("shadow-lab patched-read-hiding=1");
    std::fflush(stdout);

    /* 7. LISTEN: XOL slot with the original first instruction, then hit
     * lab_listen (no patch) and verify PRE/POST snapshots + the unchanged
     * result. */
    const long xol_length = static_cast<long>(sysconf(_SC_PAGESIZE));
    std::puts("shadow-lab xol-mmapping");
    std::fflush(stdout);
    void *xol = mmap(nullptr, static_cast<std::size_t>(xol_length),
                     PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (xol == MAP_FAILED) {
        std::fprintf(stderr, "shadow-lab xol mmap failed\n");
        return 1;
    }
    std::puts("shadow-lab xol-mapped");
    std::fflush(stdout);
    std::memcpy(xol, reinterpret_cast<const void *>(listen_va), 4);
    if (mprotect(xol, static_cast<std::size_t>(xol_length), PROT_READ | PROT_EXEC) != 0) {
        std::fprintf(stderr, "shadow-lab xol mprotect failed\n");
        return 1;
    }
    __builtin___clear_cache(static_cast<char *>(xol),
                            static_cast<char *>(xol) + 4);
    std::puts("shadow-lab xol-ready");
    std::fflush(stdout);
    std::snprintf(command, sizeof(command), "shadow-set-bp %ld 0x%lx 1 0 0x%lx",
                  pid, listen_va, reinterpret_cast<unsigned long>(xol));
    if (shadow_lab_control(key, command, response, sizeof(response)) != 0) return 1;
    std::puts("shadow-lab listen-armed");
    std::fflush(stdout);
    if (lab.lab_listen(1, 2) != 3) {
        std::fprintf(stderr, "shadow-lab LISTEN changed the result\n");
        return 1;
    }
    std::puts("shadow-lab listen-called");
    std::fflush(stdout);
    unsigned int pre = 0;
    unsigned int post = 0;
    bool pair = false;
    if (shadow_lab_drain_events(key, pid, listen_va, 1, &pre, &post, &pair) != 0)
        return 1;
    if (pre == 0 || post == 0 || !pair) {
        std::fprintf(stderr, "shadow-lab LISTEN events missing pre=%u post=%u\n",
                     pre, post);
        return 1;
    }
    std::printf("shadow-lab listen pre=%u post=%u result=3\n", pre, post);
    std::fflush(stdout);

    /* 8. INTERCEPT + BEFORE_AFTER: the no-op gate leaves the registers
     * untouched, so the arithmetic must still return 3 through the XOL +
     * the callback rendezvous. */
    const unsigned long gate_va = reinterpret_cast<unsigned long>(
        reinterpret_cast<void *>(&shadow_lab_gate));
    for (unsigned int mode = 2U; mode <= 3U; ++mode) {
        std::snprintf(command, sizeof(command), "shadow-set-bp %ld 0x%lx %u 0x%lx 0x%lx",
                      pid, listen_va, mode, gate_va,
                      reinterpret_cast<unsigned long>(xol));
        if (shadow_lab_control(key, command, response, sizeof(response)) != 0) return 1;
        const long mode_result = lab.lab_listen(1, 2);
        if (mode_result != 3) {
            std::fprintf(stderr, "shadow-lab mode %u changed the result: %ld\n",
                         mode, mode_result);
            return 1;
        }
        std::printf("shadow-lab mode%u=3\n", mode);
        std::fflush(stdout);
    }

    /* 9. Stress: 1000 alternating executions and clean reads across TWO
     * threads (the callback/pending pools must not cross contexts); no
     * missed switches, no deadlock, no wrong TLB leftovers. */
    std::atomic<long> stress_failures{0};
    auto stress_worker = [&]() {
        for (unsigned int round = 0; round < 500U; ++round) {
            if (lab.lab_add(1, 2) != 42) stress_failures.fetch_add(1);
            if (lab.lab_listen(1, 2) != 3) stress_failures.fetch_add(1);
        }
    };
    std::thread worker_a(stress_worker);
    std::thread worker_b(stress_worker);
    worker_a.join();
    worker_b.join();
    if (stress_failures.load() != 0) {
        std::fprintf(stderr, "shadow-lab stress mismatches: %ld\n",
                     stress_failures.load());
        return 1;
    }
    if (shadow_lab_read_probe(add_va, original, 8, false, "stress-read") != 0)
        return 1;
    std::printf("shadow-lab stress=1000 threaded=2\n");
    std::fflush(stdout);

    /* 9. Release both sites and prove the arithmetic is restored. The two
     * sites share one page, so the second release legitimately finds the
     * page already gone (code -2) and is accepted. */
    std::snprintf(command, sizeof(command), "shadow-release %ld 0x%lx", pid, add_va);
    if (shadow_lab_control(key, command, response, sizeof(response)) != 0) return 1;
    std::snprintf(command, sizeof(command), "shadow-release %ld 0x%lx", pid, listen_va);
    if (control(key, command, response, sizeof(response)) != 0) return 1;
    if (std::strncmp(response, "ok ", 3) != 0 &&
        std::strstr(response, "code=-2") == nullptr) {
        std::fprintf(stderr, "shadow-lab second release rejected: %s\n", response);
        return 1;
    }
    if (lab.lab_add(1, 2) != 3) {
        std::fprintf(stderr, "shadow-lab restore failed\n");
        return 1;
    }
    std::puts("shadow-lab restored=3");
    std::fflush(stdout);

    if (shadow_lab_control(key, "shadowhook-status", response, sizeof(response)) != 0)
        return 1;
    std::printf("shadow-lab status: %s\n", response);
    std::puts("replace=42 read-hiding=1 listen=1 stress=1000 stage2-shadow-lab PASS");
    return 0;
}

int command_hook_probe()
{
    errno = 0;
    const int poll_result = poll(nullptr, 0, 0);
    const int poll_errno = errno;
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd < 0) return 1;
    epoll_event event{};
    errno = 0;
    const int epoll_result = epoll_wait(epoll_fd, &event, 1, 0);
    const int epoll_errno = errno;
    close(epoll_fd);
    if (poll_result != 0 || poll_errno != 0 ||
        epoll_result != 0 || epoll_errno != 0) return 1;
    std::puts("poll=0 epoll=0 stage2-hook-probe PASS");
    return 0;
}

int command_comm_probe()
{
    if (prctl(PR_SET_NAME, "rtgum-comm-probe", 0, 0, 0) != 0) return 1;
    std::puts("stage2-comm-probe PASS");
    return 0;
}

int command_stage2_sandbox_test(const char *key)
{
    rtgum_su_profile profile{};
    profile.uid = static_cast<std::uint32_t>(getuid());
    profile.to_uid = 0;
    if (rtgum_sc_su(key, &profile) != 0 || getuid() != 0) return 1;

    char command[512];
    char response[kControlBufferSize]{};
    constexpr const char *daemon =
        "/data/local/tmp/rtgum-stage1-pixel8/rtgum-stage2-daemon.so";
    std::snprintf(command, sizeof(command),
                  "link %s rtgum_stage2_daemon_dispatch", daemon);
    if (control(key, command, response, sizeof(response)) != 0) return 1;
    unsigned long base = 0;
    unsigned long size = 0;
    if (std::sscanf(response, "ok base=0x%lx entry=0x%*lx size=%lu",
                    &base, &size) != 2 || base == 0 || size == 0) {
        std::fprintf(stderr, "sandbox link failed: %s\n", response);
        return 1;
    }
    auto cleanup = [&]() {
        std::snprintf(command, sizeof(command), "sandbox-unlink 0x%lx", base);
        return control(key, command, response, sizeof(response)) == 0 &&
               std::strcmp(response, "ok sandbox-unlinked=1") == 0;
    };
    auto fail = [&](const char *reason) {
        std::fprintf(stderr, "%s: %s\n", reason, response);
        if (!cleanup()) std::fprintf(stderr, "sandbox cleanup failed: %s\n", response);
        return 1;
    };

    unsigned long maps_address = 0;
    unsigned long maps_length = 0;
    if (!read_maps_into_ghost(key, getpid(), maps_address, maps_length))
        return fail("sandbox maps staging failed");
    std::snprintf(command, sizeof(command), "resolve-current 0x%lx 0x%lx %lu",
                  base, maps_address, maps_length);
    const bool resolved = control(key, command, response, sizeof(response)) == 0 &&
                          std::strncmp(response, "ok base=", 8) == 0;
    free_ghost_buffer(key, maps_address);
    if (!resolved) return fail("sandbox NEEDED/IFUNC resolution failed");

    if (control(key, "hook-sysni", response, sizeof(response)) != 0 ||
        std::strcmp(response, "ok sysni_hook=1") != 0)
        return fail("sandbox channel hook failed");
    if (control(key, "hook-poll", response, sizeof(response)) != 0 ||
        std::strcmp(response, "ok poll_hook=1") != 0)
        return fail("sandbox poll hook failed");

    std::snprintf(command, sizeof(command), "sandbox-bootstrap 0x%lx 0x%lx 0x%lx",
                  base, getauxval(AT_HWCAP), getauxval(AT_HWCAP2));
    if (control(key, command, response, sizeof(response)) != 0 ||
        std::strncmp(response, "ok pid=", 7) != 0)
        return fail("sandbox bootstrap failed");

    if (poll(nullptr, 0, 0) != 0) return fail("sandbox poll failed");
    std::snprintf(command, sizeof(command), "daemon-status %ld",
                  static_cast<long>(getpid()));
    if (control(key, command, response, sizeof(response)) != 0)
        return fail("sandbox status query failed");
    unsigned long phase = 0;
    unsigned long modules = 0;
    unsigned long extra = 0;
    unsigned long magic = 0;
    unsigned long api = 0;
    if (std::sscanf(response,
                    "ok pid=%*ld phase=%lu modules=%lu extra=%lu magic=0x%lx module_base=0x%*lx api=0x%lx",
                    &phase, &modules, &extra, &magic, &api) != 5 ||
        phase != RTGUM_DAEMON_PHASE_INIT || modules != 0 || extra != 0 ||
        magic != RTGUM_DAEMON_MAGIC || api == 0)
        return fail("sandbox INIT or IFUNC status mismatch");

    if (!cleanup()) {
        std::fprintf(stderr, "sandbox cleanup failed: %s\n", response);
        return 1;
    }
    if (control(key, "capabilities", response, sizeof(response)) != 0 ||
        !std::strstr(response, "active=0 busy=0 images=0 daemon=0")) {
        std::fprintf(stderr, "sandbox residual state: %s\n", response);
        return 1;
    }
    std::puts("needed=1 provider-ifunc=1 local-ifunc=1 daemon-init=1 cleaned=1 stage2-sandbox-bootstrap PASS");
    return 0;
}

bool file_contains(const char *path, const char *needle)
{
    FILE *file = std::fopen(path, "r");
    if (!file) return false;
    const std::size_t needle_length = std::strlen(needle);
    char window[512];
    std::size_t filled = 0;
    bool found = false;
    while (!found) {
        const std::size_t count =
            std::fread(window + filled, 1, sizeof(window) - filled - 1, file);
        if (count == 0) break;
        filled += count;
        window[filled] = '\0';
        if (std::strstr(window, needle)) {
            found = true;
            break;
        }
        if (filled > needle_length) {
            std::memmove(window, window + (filled - needle_length), needle_length);
            filled = needle_length;
        }
    }
    std::fclose(file);
    return found;
}

bool ui_dump_contains(const char *needle)
{
    std::system("rm -f /data/local/tmp/rtgum-jnicode-ui.xml");
    if (std::system("uiautomator dump /data/local/tmp/rtgum-jnicode-ui.xml >/dev/null 2>&1") != 0) {
        return false;
    }
    return file_contains("/data/local/tmp/rtgum-jnicode-ui.xml", needle);
}

int copy_regular_file(const char *source, const char *destination)
{
    const int in = open(source, O_RDONLY | O_CLOEXEC);
    if (in < 0) return -1;
    const int out = open(destination, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0755);
    if (out < 0) {
        close(in);
        return -1;
    }
    char buffer[8192];
    for (;;) {
        const ssize_t count = read(in, buffer, sizeof(buffer));
        if (count < 0) {
            close(in);
            close(out);
            return -1;
        }
        if (count == 0) break;
        ssize_t offset = 0;
        while (offset < count) {
            const ssize_t written =
                write(out, buffer + offset, static_cast<size_t>(count - offset));
            if (written <= 0) {
                close(in);
                close(out);
                return -1;
            }
            offset += written;
        }
    }
    close(in);
    close(out);
    return 0;
}

int stage_java_helper()
{
    const char *package_dir = "/data/data/com.laodeng.jnicode";
    const char *cache_dir = "/data/data/com.laodeng.jnicode/code_cache";
    struct stat info {};
    if (stat(package_dir, &info) != 0) return -1;
    if (mkdir(cache_dir, 0755) != 0 && errno != EEXIST) return -1;
    if (copy_regular_file(RTGUM_JAVA_HELPER_STAGING_PATH, RTGUM_JAVA_HELPER_APP_PATH) != 0)
        return -1;
    if (chown(cache_dir, info.st_uid, info.st_gid) != 0) return -1;
    if (chown(RTGUM_JAVA_HELPER_APP_PATH, info.st_uid, info.st_gid) != 0) return -1;
    chmod(RTGUM_JAVA_HELPER_APP_PATH, 0755);
    std::system("chcon --reference=/data/data/com.laodeng.jnicode "
                "/data/data/com.laodeng.jnicode/code_cache >/dev/null 2>&1");
    std::system("chcon --reference=/data/data/com.laodeng.jnicode/code_cache "
                "/data/data/com.laodeng.jnicode/code_cache/librtgum-jnicode-java-hook.so "
                ">/dev/null 2>&1");
    return 0;
}

/* Stages a backend library into the target app's own code_cache (the only
 * directory the app's linker is allowed to dlopen from). Runs as root in
 * the elevated ctl. Returns the app-side path in "out". */
int stage_into_app_cache(const char *package, const char *staging_path,
                         char *out, std::size_t out_capacity)
{
    if (!package || !staging_path || !out || out_capacity < 192) return -1;
    char package_dir[128];
    char cache_dir[160];
    char app_path[192];
    std::snprintf(package_dir, sizeof(package_dir), "/data/data/%s", package);
    std::snprintf(cache_dir, sizeof(cache_dir), "/data/data/%s/code_cache", package);
    const char *base_name = std::strrchr(staging_path, '/');
    base_name = base_name ? base_name + 1 : staging_path;
    std::snprintf(app_path, sizeof(app_path), "/data/data/%s/code_cache/%s",
                  package, base_name);
    struct stat info {};
    if (stat(package_dir, &info) != 0) return -1;
    if (mkdir(cache_dir, 0755) != 0 && errno != EEXIST) return -1;
    if (copy_regular_file(staging_path, app_path) != 0) return -1;
    if (chown(cache_dir, info.st_uid, info.st_gid) != 0) return -1;
    if (chown(app_path, info.st_uid, info.st_gid) != 0) return -1;
    chmod(app_path, 0755);
    char chcon_command[256];
    std::snprintf(chcon_command, sizeof(chcon_command),
                  "chcon --reference=%s %s >/dev/null 2>&1", package_dir, cache_dir);
    std::system(chcon_command);
    std::snprintf(chcon_command, sizeof(chcon_command),
                  "chcon --reference=%s %s >/dev/null 2>&1", cache_dir, app_path);
    std::system(chcon_command);
    std::snprintf(out, out_capacity, "%s", app_path);
    return 0;
}

int command_zygote_init_test(const char *key, int scenario,
                             const char *target_package = nullptr,
                             const char *target_launch = nullptr)
{
    rtgum_su_profile profile{};
    profile.uid = static_cast<std::uint32_t>(getuid());
    profile.to_uid = 0;
    if (rtgum_sc_su(key, &profile) != 0 || getuid() != 0) {
        std::fprintf(stderr, "Zygote su failed\n");
        return 1;
    }

    const long expected_pid = find_pid_by_cmdline("zygote64", true);
    if (expected_pid <= 0) {
        std::fprintf(stderr, "zygote64 pid not found\n");
        return 1;
    }
    char command[512];
    char response[kControlBufferSize]{};
    std::snprintf(command, sizeof(command), "zygote-find %ld", expected_pid);
    long pid = -1;
    char name[32]{};
    char abi[16]{};
    if (control(key, command, response, sizeof(response)) != 0 ||
        std::sscanf(response, "ok pid=%ld name=%31s abi=%15s",
                    &pid, name, abi) != 3 || pid != expected_pid ||
        std::strcmp(name, "zygote64") != 0 || std::strcmp(abi, "arm64") != 0) {
        std::fprintf(stderr, "Zygote find failed: %s\n", response);
        return 1;
    }

    constexpr const char *daemon =
        "/data/local/tmp/rtgum-stage1-pixel8/rtgum-stage2-daemon.so";
    std::snprintf(command, sizeof(command),
                  "zygote-link %ld %s rtgum_stage2_daemon_dispatch", pid, daemon);
    if (control(key, command, response, sizeof(response)) != 0) {
        std::fprintf(stderr, "Zygote link failed: %s\n", response);
        return 1;
    }
    unsigned long base = 0;
    unsigned long size = 0;
    unsigned int needed = 0;
    unsigned int imports = 0;
    unsigned int ifuncs = 0;
    if (std::sscanf(response,
                    "ok pid=%*ld name=zygote64 base=0x%lx entry=0x%*lx size=%lu relocations=%*u needed=%u imports=%u ifuncs=%u",
                    &base, &size, &needed, &imports, &ifuncs) != 5 ||
        base == 0 || size == 0 || needed != 1U || imports == 0U) {
        std::fprintf(stderr, "Zygote link parse failed: %s\n", response);
        return 1;
    }
    auto cleanup = [&]() {
        std::snprintf(command, sizeof(command), "zygote-unlink %ld 0x%lx", pid, base);
        return control(key, command, response, sizeof(response)) == 0 &&
               std::strncmp(response, "ok pid=", 7) == 0;
    };
    auto stop_inherited = [&]() {
        std::system("am force-stop com.laodeng.jnicode >/dev/null 2>&1");
        std::system("am force-stop com.android.settings >/dev/null 2>&1");
        std::system("am force-stop com.google.android.apps.pixel.dcservice >/dev/null 2>&1");
        std::system("am force-stop com.google.android.settings.intelligence >/dev/null 2>&1");
        std::system("am force-stop com.android.providers.calendar >/dev/null 2>&1");
        std::system("am force-stop dev.rtgum.lab >/dev/null 2>&1");
    };
    auto fail = [&](const char *reason) {
        std::fprintf(stderr, "%s: %s\n", reason, response);
        if (scenario != 0) {
            stop_inherited();
        }
        if (!cleanup()) std::fprintf(stderr, "Zygote cleanup deferred: %s\n", response);
        return 1;
    };

    unsigned long maps_address = 0;
    unsigned long maps_length = 0;
    if (!read_maps_into_ghost(key, pid, maps_address, maps_length))
        return fail("Zygote maps staging failed");
    std::snprintf(command, sizeof(command), "zygote-resolve %ld 0x%lx 0x%lx %lu",
                  pid, base, maps_address, maps_length);
    unsigned int resolved_needed = 0;
    unsigned int resolved_imports = 0;
    unsigned int deferred_ifuncs = 0;
    const bool resolved = control(key, command, response, sizeof(response)) == 0 &&
        std::sscanf(response,
                    "ok pid=%*ld base=0x%*lx needed=%u imports=%u ifuncs=%u resolved=1",
                    &resolved_needed, &resolved_imports, &deferred_ifuncs) == 3;
    free_ghost_buffer(key, maps_address);
    if (!resolved || resolved_needed != needed ||
        resolved_imports + deferred_ifuncs != imports)
        return fail("Zygote NEEDED/IFUNC resolution failed");

    if (control(key, "hook-sysni", response, sizeof(response)) != 0 ||
        std::strcmp(response, "ok sysni_hook=1") != 0)
        return fail("Zygote channel hook failed");
    if (control(key, "hook-poll", response, sizeof(response)) != 0 ||
        std::strcmp(response, "ok poll_hook=1") != 0)
        return fail("Zygote poll hook failed");
    std::snprintf(command, sizeof(command),
                  "zygote-bootstrap %ld 0x%lx 0x%lx 0x%lx", pid, base,
                  getauxval(AT_HWCAP), getauxval(AT_HWCAP2));
    unsigned int ifunc_slots = 0;
    if (control(key, command, response, sizeof(response)) != 0 ||
        std::sscanf(response,
                    "ok pid=%*ld base=0x%*lx trampoline=0x%*lx ctx=0x%*lx dispatch=0x%*lx status=0x%*lx fixup=%*lu ifunc_slots=%u dispatched=1",
                    &ifunc_slots) != 1 || ifunc_slots < deferred_ifuncs + ifuncs)
        return fail("Zygote bootstrap failed");
    std::printf("zygote-init armed pid=%ld base=0x%lx ifunc_slots=%u\n",
                pid, base, ifunc_slots);
    std::fflush(stdout);

    bool initialized = false;
    for (int attempt = 0; attempt < 200; ++attempt) {
        /* Zygote may already be asleep in poll when the hook is installed.
         * Launching a child supplies the poll return needed to dispatch and
         * a subsequent return confirms the trampoline has left the stack. */
        if (attempt % 12 == 0 && attempt < 60) {
            std::system("am force-stop com.android.settings >/dev/null 2>&1");
            if (std::system("am start -a android.settings.SETTINGS >/dev/null 2>&1") != 0)
                return fail("Settings wake-up for Zygote INIT failed");
        }
        std::snprintf(command, sizeof(command), "daemon-status %ld", pid);
        if (control(key, command, response, sizeof(response)) == 0 &&
            std::strstr(response, "phase=1 ") &&
            std::strstr(response, "magic=0x4441454d4f4e3230 ") &&
            std::strstr(response, "quiescent=1")) {
            initialized = true;
            break;
        }
        usleep(250000);
    }
    if (!initialized) {
        char counters[kControlBufferSize]{};
        if (control(key, "hook-counters", counters, sizeof(counters)) == 0)
            std::fprintf(stderr, "Zygote hook counters: %s\n", counters);
        return fail("Zygote INIT did not become quiescent");
    }
    /* The INIT wait loop's asynchronous force-stop/start pairs can land
     * AFTER the loop breaks (am returns before the kill completes). Settle
     * here so a late kill cannot strike the package process mid-dispatch or
     * mid-reload. */
    std::system("am force-stop com.android.settings >/dev/null 2>&1");
    usleep(600000);
    unsigned long zygote_phase = 0UL;
    unsigned long zygote_modules = 0UL;
    unsigned long zygote_extra = 0UL;
    unsigned long zygote_magic = 0UL;
    unsigned long zygote_module_base = 0UL;
    unsigned long zygote_api = 0UL;
    bool zygote_private_baseline = false;
    if (scenario != 0 && scenario != 8) {
        std::snprintf(command, sizeof(command), "daemon-status %ld", pid);
        if (control(key, command, response, sizeof(response)) != 0 ||
            std::sscanf(response,
                        "ok pid=%*ld phase=%lu modules=%lu extra=%lu magic=0x%lx module_base=0x%lx api=0x%lx",
                        &zygote_phase, &zygote_modules, &zygote_extra,
                        &zygote_magic, &zygote_module_base,
                        &zygote_api) != 6 ||
            zygote_phase != RTGUM_DAEMON_PHASE_INIT ||
            zygote_modules != 0UL || zygote_extra != 0UL ||
            zygote_magic != RTGUM_DAEMON_MAGIC || zygote_api == 0UL)
            return fail("Zygote private-state baseline is invalid");
        zygote_private_baseline = true;
    }
    if (scenario == 8) {
        const long zygote_pid = pid;
        stop_inherited();
        if (!cleanup()) return fail("daemon replace clear failed");
        std::snprintf(command, sizeof(command),
                      "zygote-link %ld %s rtgum_stage2_daemon_dispatch", pid, daemon);
        if (control(key, command, response, sizeof(response)) != 0)
            return fail("daemon replace re-link failed");
        unsigned int relink_needed = 0;
        unsigned int relink_imports = 0;
        unsigned int relink_ifuncs = 0;
        if (std::sscanf(response,
                        "ok pid=%*ld name=zygote64 base=0x%lx entry=0x%*lx size=%lu relocations=%*u needed=%u imports=%u ifuncs=%u",
                        &base, &size, &relink_needed, &relink_imports, &relink_ifuncs) != 5 ||
            base == 0 || size == 0 || relink_needed != 1U)
            return fail("daemon replace re-link parse failed");
        if (!read_maps_into_ghost(key, pid, maps_address, maps_length))
            return fail("daemon replace maps staging failed");
        std::snprintf(command, sizeof(command), "zygote-resolve %ld 0x%lx 0x%lx %lu",
                      pid, base, maps_address, maps_length);
        resolved_needed = 0;
        resolved_imports = 0;
        deferred_ifuncs = 0;
        const bool replaced = control(key, command, response, sizeof(response)) == 0 &&
            std::sscanf(response,
                        "ok pid=%*ld base=0x%*lx needed=%u imports=%u ifuncs=%u resolved=1",
                        &resolved_needed, &resolved_imports, &deferred_ifuncs) == 3;
        free_ghost_buffer(key, maps_address);
        if (!replaced || resolved_needed != relink_needed)
            return fail("daemon replace resolve failed");
        std::snprintf(command, sizeof(command),
                      "zygote-bootstrap %ld 0x%lx 0x%lx 0x%lx", pid, base,
                      getauxval(AT_HWCAP), getauxval(AT_HWCAP2));
        ifunc_slots = 0;
        if (control(key, command, response, sizeof(response)) != 0 ||
            std::sscanf(response,
                        "ok pid=%*ld base=0x%*lx trampoline=0x%*lx ctx=0x%*lx dispatch=0x%*lx status=0x%*lx fixup=%*lu ifunc_slots=%u dispatched=1",
                        &ifunc_slots) != 1)
            return fail("daemon replace bootstrap failed");
        bool reentered = false;
        for (int attempt = 0; attempt < 200; ++attempt) {
            if (attempt % 12 == 0 && attempt < 60) {
                std::system("am force-stop com.android.settings >/dev/null 2>&1");
                if (std::system("am start -a android.settings.SETTINGS >/dev/null 2>&1") != 0)
                    return fail("Settings wake-up for daemon replace failed");
            }
            std::snprintf(command, sizeof(command), "daemon-status %ld", pid);
            if (control(key, command, response, sizeof(response)) == 0 &&
                std::strstr(response, "phase=1 ") &&
                std::strstr(response, "magic=0x4441454d4f4e3230 ") &&
                std::strstr(response, "quiescent=1")) {
                reentered = true;
                break;
            }
            usleep(250000);
        }
        if (!reentered) return fail("daemon replace did not re-enter INIT");
        const long pid_after = find_pid_by_cmdline("zygote64", true);
        if (pid_after != zygote_pid) return fail("Zygote PID changed during daemon replace");
        stop_inherited();
        if (!cleanup()) return fail("daemon replace final unlink failed");
        std::puts("zygote-init=1 daemon-clear=1 daemon-reenter=1 zygote-pid-stable=1 cleaned=1 stage2-zygote-daemon-replace PASS");
        return 0;
    }
    if (scenario >= 2) {
        const bool jnicode = scenario == 4;
        const bool jnicode_java = scenario == 5;
        const bool jnicode_badver = scenario == 6;
        const bool jnicode_nosym = scenario == 7;
        const bool jnicode_mako = scenario == 9;
        const bool symbol_test = scenario == 10;
        const bool dex_test = scenario == 11;
        const bool interceptor_test = scenario == 12;
        const bool lifecycle_test = scenario == 13;
        const bool gtrace_test = scenario == 14;
        const bool multi_trace_test = scenario == 15;
        /* Scenario 9 runs the acceptance fixture, not the JNICode app: the
         * module hooks LabTarget.add(II)I and rewrites its result, which is what
         * makes the lab's ArtMethod self-check conclusive (a hidden rewrite needs
         * a live hook to be hidden from). `mako-target-test <pkg> <comp>` picks
         * the package; without it the scenario falls back to the JNICode app. */
        const bool lab_mako = jnicode_mako &&
                              (target_package == nullptr ||
                               std::strstr(target_package, "rtgum.lab") != nullptr);
        const bool jnicode_any =
            jnicode || jnicode_java || jnicode_badver || jnicode_nosym || jnicode_mako;
        const bool jnicode_success = jnicode || jnicode_java;
        unsigned long shadow_access_baseline = 0UL;
        const char *package = multi_trace_test
            ? (target_package ? target_package : "dev.rtgum.lab")
            : gtrace_test
            ? (target_package ? target_package : "dev.rtgum.lab")
            : lifecycle_test
            ? (target_package ? target_package : "dev.rtgum.lab")
            : interceptor_test
            ? (target_package ? target_package : "dev.rtgum.lab")
            : dex_test
            ? (target_package ? target_package : "dev.rtgum.lab")
            : symbol_test
            ? (target_package ? target_package : "dev.rtgum.lab")
            : jnicode_any
            ? (jnicode_mako && target_package != nullptr ? target_package
                                                         : "com.laodeng.jnicode")
            : "com.android.settings";
        const char *module = multi_trace_test
            ? "/data/local/tmp/rtgum-stage1-pixel8/rtgum-stage2-multitrace.ghm"
            : gtrace_test
            ? "/data/local/tmp/rtgum-stage1-pixel8/rtgum-stage2-gtrace.ghm"
            : lifecycle_test
            ? "/data/local/tmp/rtgum-stage1-pixel8/rtgum-stage2-lifecycle.ghm"
            : interceptor_test
            ? "/data/local/tmp/rtgum-stage1-pixel8/rtgum-stage2-interceptors.ghm"
            : dex_test
            ? "/data/local/tmp/rtgum-stage1-pixel8/rtgum-stage2-dex.ghm"
            : symbol_test
            ? "/data/local/tmp/rtgum-stage1-pixel8/rtgum-stage2-symbol.ghm"
            : jnicode_java
            ? "/data/local/tmp/rtgum-stage1-pixel8/rtgum-stage2-jnicode-java.ghm"
            : jnicode_mako
                  ? (lab_mako
                         ? "/data/local/tmp/rtgum-stage1-pixel8/rtgum-stage2-lab-mako.ghm"
                         : "/data/local/tmp/rtgum-stage1-pixel8/rtgum-stage2-jnicode-mako.ghm")
                  : jnicode_badver
                        ? "/data/local/tmp/rtgum-stage1-pixel8/rtgum-stage2-jnicode-badver.ghm"
                        : jnicode_nosym
                              ? "/data/local/tmp/rtgum-stage1-pixel8/rtgum-stage2-jnicode-nosym.ghm"
                              : jnicode
                                    ? "/data/local/tmp/rtgum-stage1-pixel8/rtgum-stage2-jnicode.ghm"
                                    : "/data/local/tmp/rtgum-stage1-pixel8/rtgum-stage2-module.ghm";
        constexpr const char *mako_library =
            "/data/local/tmp/rtgum-stage1-pixel8/libmako-ghost.so";
        char launch_command[256];
        char stop_command[256];
        if ((jnicode_mako || symbol_test || dex_test || interceptor_test ||
             lifecycle_test || gtrace_test || multi_trace_test) &&
            target_package != nullptr &&
            target_launch != nullptr) {
            std::snprintf(launch_command, sizeof(launch_command),
                          "am start -n %s -f 0x10008000 >/dev/null 2>&1",
                          target_launch);
            std::snprintf(stop_command, sizeof(stop_command),
                          "am force-stop %s >/dev/null 2>&1", target_package);
        } else {
            std::snprintf(launch_command, sizeof(launch_command), "%s",
                          jnicode_any
                              ? "am start -n com.laodeng.jnicode/.MainActivity -f 0x10008000 >/dev/null 2>&1"
                              : "am start -a android.settings.SETTINGS >/dev/null 2>&1");
            std::snprintf(stop_command, sizeof(stop_command), "%s",
                          jnicode_any
                              ? "am force-stop com.laodeng.jnicode >/dev/null 2>&1"
                              : "am force-stop com.android.settings >/dev/null 2>&1");
        }
        const char *launch = launch_command;
        const char *stop = stop_command;
        char extra_token[32];
        if (multi_trace_test) {
            std::snprintf(extra_token, sizeof(extra_token), "extra=%lu ",
                          RTGUM_MODULE_EXTRA_MULTI_TRACE_READY);
        } else if (gtrace_test) {
            std::snprintf(extra_token, sizeof(extra_token), "extra=%lu ",
                          RTGUM_MODULE_EXTRA_GTRACE_READY);
        } else if (lifecycle_test) {
            std::snprintf(extra_token, sizeof(extra_token), "extra=%lu ",
                          RTGUM_MODULE_EXTRA_LIFECYCLE_READY);
        } else if (interceptor_test) {
            std::snprintf(extra_token, sizeof(extra_token), "extra=%lu ",
                          RTGUM_MODULE_EXTRA_INTERCEPTORS_READY);
        } else if (dex_test) {
            std::snprintf(extra_token, sizeof(extra_token), "extra=%lu ",
                          RTGUM_MODULE_EXTRA_DEX_READY);
        } else if (symbol_test) {
            std::snprintf(extra_token, sizeof(extra_token), "extra=%lu ",
                          RTGUM_MODULE_EXTRA_SYMBOLS_READY);
        } else if (jnicode_badver) {
            std::snprintf(extra_token, sizeof(extra_token), "extra=%lu ",
                          RTGUM_MODULE_EXTRA_HOST_UNAVAILABLE);
        } else if (jnicode_nosym) {
            std::snprintf(extra_token, sizeof(extra_token), "extra=%lu ",
                          RTGUM_MODULE_EXTRA_LOOKUP_FAILED);
        } else if (jnicode_any) {
            std::snprintf(extra_token, sizeof(extra_token), "extra=%lu ",
                          RTGUM_MODULE_EXTRA_REPLACED);
        } else {
            std::snprintf(extra_token, sizeof(extra_token), "extra=1 ");
        }
        if (jnicode_java && stage_java_helper() != 0)
            return fail("JNICode Java helper could not be staged into code_cache");
        if (symbol_test) {
            char staged_elf[192];
            constexpr const char *lab_elf =
                "/data/local/tmp/rtgum-stage1-pixel8/libghostlab.so";
            if (stage_into_app_cache(package, lab_elf, staged_elf,
                                     sizeof(staged_elf)) != 0)
                return fail("Lab ELF could not be staged into code_cache");
        }
        constexpr const char *gum_library =
            "/data/local/tmp/rtgum-stage1-pixel8/librtgum-gum-ghost.so";
        if (control(key, "hook-comm", response, sizeof(response)) != 0 ||
            std::strcmp(response, "ok comm_hook=1") != 0)
            return fail("package comm hook failed");
        if (scenario == 3 &&
            (control(key, "hook-epoll", response, sizeof(response)) != 0 ||
             std::strcmp(response, "ok epoll_hook=1") != 0))
            return fail("Settings epoll hook failed");
        if (jnicode_mako &&
            (control(key, "hook-art-shadow", response, sizeof(response)) != 0 ||
             std::strcmp(response, "ok art_shadow=1") != 0))
            return fail("ART shadow data page hooks failed");
        if (jnicode_mako) {
            char baseline_status[1024]{};
            unsigned long baseline_emulated = 0UL;
            unsigned long baseline_served = 0UL;
            if (control(key, "shadow-status", baseline_status,
                        sizeof(baseline_status)) != 0 ||
                std::sscanf(
                    baseline_status,
                    "ok pages=%*u stale=%*u trusts=%*u emulated=%lu served=%lu",
                    &baseline_emulated, &baseline_served) != 2)
                return fail("ART shadow baseline counters unavailable");
            shadow_access_baseline = baseline_emulated + baseline_served;
        }
        if (gtrace_test || multi_trace_test) {
            std::snprintf(command, sizeof(command),
                          "daemon-config %ld %s %s - %s", pid, package, module,
                          gum_library);
        } else if (jnicode_mako) {
            /* Manager switch: the mako path is pushed into the KPM cache at
             * config time; the Daemon lazily links it on its first artHook. */
            std::snprintf(command, sizeof(command),
                          "daemon-config %ld %s %s %s", pid, package, module,
                          mako_library);
        } else {
            std::snprintf(command, sizeof(command),
                          "daemon-config %ld %s %s", pid, package, module);
        }
        if (control(key, command, response, sizeof(response)) != 0 ||
            std::strncmp(response, "ok ", 3) != 0)
            return fail("package configuration failed");
        std::system(stop);
        if (jnicode_any) {
            std::system("input keyevent KEYCODE_WAKEUP >/dev/null 2>&1");
            std::system("wm dismiss-keyguard >/dev/null 2>&1");
        }
        if (std::system(launch) != 0)
            return fail("package launch failed");
        long settings_pid = -1;
        const int pid_attempts =
            (jnicode_java || jnicode_mako || symbol_test || dex_test ||
             interceptor_test || lifecycle_test || gtrace_test ||
             multi_trace_test) ? 300 : 80;
        for (int attempt = 0; attempt < pid_attempts && settings_pid <= 0; ++attempt) {
            settings_pid = find_pid_by_cmdline(package, true);
            if (settings_pid <= 0 && jnicode_any)
                settings_pid = find_pid_by_comm("laodeng.jnicode");
            if (settings_pid <= 0) usleep(100000);
        }
        if (settings_pid <= 0) return fail("package process is absent");
        bool dispatched = false;
        for (int attempt = 0;
              attempt < (jnicode_mako
                             ? 900
                             : ((jnicode_any || symbol_test || dex_test ||
                                 interceptor_test || lifecycle_test || gtrace_test ||
                                 multi_trace_test)
                                    ? 400 : 200));
             ++attempt) {
            std::snprintf(command, sizeof(command), "daemon-status %ld", settings_pid);
            const bool status_ok =
                control(key, command, response, sizeof(response)) == 0;
            /* Mako publishes ARMED=4 and may advance to its first-call marker
             * before this process gets scheduled again. Both 42 (Lab return
             * rewrite) and 257 (Activity.onCreate entered) are later success
             * states, so waiting only for the transient 4 creates a false
             * timeout after a demonstrably successful hook. */
            const bool mako_advanced =
                jnicode_mako &&
                ((lab_mako && std::strstr(response, "extra=42 ")) ||
                 (!lab_mako && std::strstr(response, "extra=257 ")));
            if (status_ok &&
                std::strstr(response, "phase=3 modules=1 ") &&
                (std::strstr(response, extra_token) || mako_advanced) &&
                std::strstr(response, "magic=0x4441454d4f4e3230 ")) {
                dispatched = true;
                break;
            }
            usleep(100000);
        }
        if (!dispatched) return fail("package ghostEntry did not complete");
        if (gtrace_test) {
            constexpr const char *evidence =
                "/data/local/tmp/rtgum-stage1-pixel8/rtgum-gtrace-dmesg.log";
            std::system("dmesg > /data/local/tmp/rtgum-stage1-pixel8/rtgum-gtrace-dmesg.log 2>/dev/null");
            if (!file_contains(evidence,
                               "kind=br branch=indirect reg=x16") ||
                !file_contains(evidence, "target-scope=internal") ||
                !file_contains(evidence,
                               "bytes=12 direction=forward candidate-junk=1") ||
                !file_contains(evidence,
                               "gtrace-summary executed=5 branches=2 indirect=2 internal-targets=1 gaps=1 skipped-bytes=12 losses=0 mismatches=0 unreadable=0") ||
                !file_contains(evidence,
                               "rtgum-gtrace: result=42 executed=5 junk-executed=0") ||
                !file_contains(evidence, "rtgum-gtrace: PASS"))
                return fail("GTrace path evidence is incomplete");
        }
        if (multi_trace_test) {
            constexpr const char *evidence =
                "/data/local/tmp/rtgum-stage1-pixel8/rtgum-multitrace-dmesg.log";
            std::system("dmesg > /data/local/tmp/rtgum-stage1-pixel8/rtgum-multitrace-dmesg.log 2>/dev/null");
            if (!file_contains(evidence,
                               "rtgum-multitrace: callbacks A/B=2/3") ||
                !file_contains(evidence,
                               "rtgum-multitrace: steps A/B=6/9") ||
                !file_contains(evidence,
                               "rtgum-multitrace: per-handle config isolated") ||
                !file_contains(evidence,
                               "rtgum-multitrace: relocated prologue coverage complete") ||
                !file_contains(evidence,
                               "rtgum-multitrace: query-stop race safe") ||
                !file_contains(evidence, "rtgum-multitrace: PASS"))
                return fail("Multi-trace handle evidence is incomplete");
        }
        if (symbol_test) {
            std::system("dmesg > /data/local/tmp/rtgum-stage1-pixel8/rtgum-symbol-dmesg.log 2>/dev/null");
            if (!file_contains(
                    "/data/local/tmp/rtgum-stage1-pixel8/rtgum-symbol-dmesg.log",
                    "libghostlab.so!lab_add+0x0") ||
                !file_contains(
                    "/data/local/tmp/rtgum-stage1-pixel8/rtgum-symbol-dmesg.log",
                    "rtgum-symbol: symbol not found") ||
                !file_contains(
                    "/data/local/tmp/rtgum-stage1-pixel8/rtgum-symbol-dmesg.log",
                    "rtgum-symbol: ghost .symtab resolved") ||
                !file_contains(
                    "/data/local/tmp/rtgum-stage1-pixel8/rtgum-symbol-dmesg.log",
                    "rtgum-symbol: disk .symtab fallback resolved"))
                return fail("symbol resolver evidence is incomplete");
        }
        if (jnicode_any && !jnicode_mako) {
            std::system("input keyevent KEYCODE_WAKEUP >/dev/null 2>&1");
            std::system("wm dismiss-keyguard >/dev/null 2>&1");
            std::system("am start -n com.laodeng.jnicode/.MainActivity "
                        "-f 0x10008000 >/dev/null 2>&1");
            if (jnicode_success) {
                /* onCreate often paints the original text before the poller
                 * installs the rewrite. Recreate the activity in the same process. */
                const char *hooked_text =
                    jnicode_java ? RTGUM_JAVA_REPLACEMENT_TEXT : RTGUM_JNI_REPLACEMENT_TEXT;
                bool hooked_ui = false;
                for (int attempt = 0; attempt < 40; ++attempt) {
                    if (ui_dump_contains(hooked_text)) {
                        hooked_ui = true;
                        break;
                    }
                    usleep(200000);
                }
                if (!hooked_ui) {
                    if (file_contains("/data/local/tmp/rtgum-jnicode-ui.xml",
                                      RTGUM_JNI_ORIGINAL_TEXT))
                        std::fprintf(stderr, "JNICode UI still shows the original text\n");
                    else
                        std::fprintf(stderr, "JNICode UI dump did not contain the expected text\n");
                    return fail(jnicode_java
                                    ? "JNICode UI did not show the Java replacement"
                                    : "JNICode UI did not show the native replacement");
                }
            } else {
                bool original_ui = false;
                for (int attempt = 0; attempt < 40; ++attempt) {
                    std::system("rm -f /data/local/tmp/rtgum-jnicode-ui.xml");
                    if (std::system("uiautomator dump /data/local/tmp/rtgum-jnicode-ui.xml "
                                    ">/dev/null 2>&1") == 0 &&
                        file_contains("/data/local/tmp/rtgum-jnicode-ui.xml",
                                      RTGUM_JNI_ORIGINAL_TEXT) &&
                        !file_contains("/data/local/tmp/rtgum-jnicode-ui.xml",
                                       RTGUM_JNI_REPLACEMENT_TEXT) &&
                        !file_contains("/data/local/tmp/rtgum-jnicode-ui.xml",
                                       RTGUM_JAVA_REPLACEMENT_TEXT)) {
                        original_ui = true;
                        break;
                    }
                    usleep(200000);
                }
                if (!original_ui)
                    return fail("JNICode UI changed after a failed module");
            }
        }
        if (jnicode_mako) {
            /* The module must report the hook it installed. For the lab fixture
             * that report IS the rewritten return value (42), so this asserts
             * the acceptance behaviour itself rather than a generic "armed"
             * marker; for the JNICode app it is the onCreate counter (0x101). */
            const char *expected_extra = lab_mako ? "extra=42 " : "extra=257 ";
            bool create_entered = false;
            for (int attempt = 0; attempt < 400; ++attempt) {
                std::snprintf(command, sizeof(command), "daemon-status %ld", settings_pid);
                if (control(key, command, response, sizeof(response)) == 0 &&
                    std::strstr(response, expected_extra) != nullptr) {
                    create_entered = true;
                    break;
                }
                /* The activity may not have been created yet; relaunch the
                 * component to force one. */
                if (attempt % 40 == 20) std::system(launch);
                usleep(100000);
            }
            if (!create_entered)
                return fail("onCreate did not fire through the mako hook");
            /* The shadow counters must have moved: onCreate dispatches through
             * the tampered entry point (trusted ART reads), while mako's own
             * scanner-view self-check read the clean original page. */
            char shadow_status[1024];
            unsigned long shadow_pages = 0;
            unsigned long shadow_emulated = 0;
            unsigned long shadow_served = 0;
            unsigned long shadow_traps = 0;
            bool shadow_ok = false;
            for (int attempt = 0; attempt < 100; ++attempt) {
                if (control(key, "shadow-status", shadow_status, sizeof(shadow_status)) == 0 &&
                    std::sscanf(shadow_status,
                                "ok pages=%lu stale=%*u trusts=%*u emulated=%lu served=%lu traps=%lu",
                                &shadow_pages, &shadow_emulated, &shadow_served,
                                &shadow_traps) == 4 &&
                    (!lab_mako || shadow_pages >= 1UL) &&
                    shadow_emulated + shadow_served > shadow_access_baseline) {
                    shadow_ok = true;
                    break;
                }
                usleep(200000);
            }
            std::fprintf(stderr, "mako shadow counters: %s\n", shadow_status);
            if (!shadow_ok)
                return fail("mako shadow data page counters did not advance");
            std::printf("jnicode-mako=1 pages=%lu emulated=%lu served=%lu traps=%lu ",
                        shadow_pages, shadow_emulated, shadow_served, shadow_traps);
        }
        if (scenario == 3) {
            constexpr const char *module2 =
                "/data/local/tmp/rtgum-stage1-pixel8/rtgum-stage2-module2.ghm";
            std::snprintf(command, sizeof(command),
                          "daemon-reload %ld com.android.settings %s",
                          settings_pid, module2);
            if (control(key, command, response, sizeof(response)) != 0 ||
                std::strncmp(response, "ok ", 3) != 0)
                return fail("Settings hot reload could not be armed");
            /* A pending epoll hook runs on the next entry to the wait. Keep
             * Settings foreground and wake its looper without exiting it. */
            if (std::system("am start -a android.settings.SETTINGS >/dev/null 2>&1") != 0)
                return fail("Settings reload wake-up failed");
            bool reloaded = false;
            for (int attempt = 0; attempt < 120; ++attempt) {
                if (find_pid_by_cmdline("com.android.settings", true) != settings_pid)
                    return fail("Settings PID changed during hot reload");
                std::snprintf(command, sizeof(command), "daemon-status %ld", settings_pid);
                if (control(key, command, response, sizeof(response)) == 0 &&
                    std::strstr(response, "phase=4 modules=1 extra=2 ") &&
                    std::strstr(response, "magic=0x4441454d4f4e3230 ")) {
                    reloaded = true;
                    break;
                }
                if (attempt % 5 == 0)
                    std::system("input tap 400 600 >/dev/null 2>&1");
                usleep(100000);
            }
            if (!reloaded) return fail("Settings hot reload did not complete");
        }
        std::system(stop);
        std::system("am force-stop com.android.settings >/dev/null 2>&1");
        stop_inherited();
        for (int attempt = 0; attempt < 80; ++attempt) {
            if (find_pid_by_cmdline(package, true) <= 0) break;
            usleep(100000);
        }
    } else if (scenario == 1) {
        /* INIT deliberately force-stops Settings once it has quiesced.  Start
         * a fresh child here instead of depending on a pending ActivityManager
         * launch from the wake-up loop. */
        if (std::system("am start -a android.settings.SETTINGS >/dev/null 2>&1") != 0)
            return fail("Settings child launch failed");
        long settings_pid = -1;
        for (int attempt = 0; attempt < 120 && settings_pid <= 0; ++attempt) {
            settings_pid = find_pid_by_cmdline("com.android.settings", true);
            if (settings_pid <= 0) usleep(100000);
        }
        if (settings_pid <= 0) return fail("Settings child is absent");
        std::snprintf(command, sizeof(command), "daemon-status %ld", settings_pid);
        if (control(key, command, response, sizeof(response)) != 0 ||
            !std::strstr(response, "phase=1 ") ||
            !std::strstr(response, "magic=0x4441454d4f4e3230 "))
            return fail("Settings did not inherit the Daemon image");
        std::system("am force-stop com.android.settings >/dev/null 2>&1");
        bool exited = false;
        for (int attempt = 0; attempt < 80; ++attempt) {
            if (find_pid_by_cmdline("com.android.settings", true) <= 0) {
                exited = true;
                break;
            }
            usleep(100000);
        }
        if (!exited) return fail("Settings child did not exit");
    }
    if (zygote_private_baseline) {
        unsigned long phase_after = 0UL;
        unsigned long modules_after = 0UL;
        unsigned long extra_after = 0UL;
        unsigned long magic_after = 0UL;
        unsigned long module_base_after = 0UL;
        unsigned long api_after = 0UL;
        std::snprintf(command, sizeof(command), "daemon-status %ld", pid);
        if (control(key, command, response, sizeof(response)) != 0 ||
            std::sscanf(response,
                        "ok pid=%*ld phase=%lu modules=%lu extra=%lu magic=0x%lx module_base=0x%lx api=0x%lx",
                        &phase_after, &modules_after, &extra_after,
                        &magic_after, &module_base_after, &api_after) != 6 ||
            phase_after != zygote_phase || modules_after != zygote_modules ||
            extra_after != zygote_extra || magic_after != zygote_magic ||
            module_base_after != zygote_module_base || api_after != zygote_api)
            return fail("child Daemon state polluted the Zygote mapping");
    }
    if (!cleanup()) {
        std::fprintf(stderr, "Zygote cleanup failed: %s\n", response);
        return 1;
    }
    bool cleared = false;
    for (int attempt = 0; attempt < 80; ++attempt) {
        if (control(key, "capabilities", response, sizeof(response)) == 0 &&
            std::strstr(response, "active=0 busy=0 images=0 daemon=0")) {
            cleared = true;
            break;
        }
        if (attempt % 8 == 0) {
            stop_inherited();
        }
        usleep(100000);
    }
    if (!cleared) {
        std::fprintf(stderr, "Zygote residual state: %s\n", response);
        return 1;
    }
    if (scenario == 4 || scenario == 5 || scenario == 6 || scenario == 7) {
        const char *hooked_text =
            scenario == 5 ? RTGUM_JAVA_REPLACEMENT_TEXT : RTGUM_JNI_REPLACEMENT_TEXT;
        std::system("am force-stop com.laodeng.jnicode >/dev/null 2>&1");
        if (std::system("am start -n com.laodeng.jnicode/.MainActivity >/dev/null 2>&1") != 0)
            return 1;
        bool restored = false;
        for (int attempt = 0; attempt < 40; ++attempt) {
            if (ui_dump_contains(RTGUM_JNI_ORIGINAL_TEXT) &&
                !ui_dump_contains(hooked_text) &&
                !ui_dump_contains(RTGUM_JNI_REPLACEMENT_TEXT) &&
                !ui_dump_contains(RTGUM_JAVA_REPLACEMENT_TEXT)) {
                restored = true;
                break;
            }
            usleep(200000);
        }
        std::system("am force-stop com.laodeng.jnicode >/dev/null 2>&1");
        std::system("rm -f /data/local/tmp/rtgum-jnicode-ui.xml");
        if (!restored) {
            std::fprintf(stderr, "JNICode UI did not restore the original string\n");
            return 1;
        }
    }
    if (scenario == 3)
        std::puts("package-dispatch=1 hot-reload=1 child-cleaned=1 stage2-zygote-reload PASS");
    else if (scenario == 4)
        std::puts("zygote-init=1 package-dispatch=1 native-hook=1 restored=1 child-cleaned=1 stage2-zygote-jnicode PASS");
    else if (scenario == 5)
        std::puts("zygote-init=1 package-dispatch=1 java-hook=1 restored=1 child-cleaned=1 stage2-zygote-jnicode-java PASS");
    else if (scenario == 6)
        std::puts("zygote-init=1 package-dispatch=1 module-error=1 original-ui=1 child-cleaned=1 stage2-zygote-jnicode-badver PASS");
    else if (scenario == 7)
        std::puts("zygote-init=1 package-dispatch=1 module-error=1 original-ui=1 child-cleaned=1 stage2-zygote-jnicode-nosym PASS");
    else if (scenario == 9)
        std::puts("stage2-zygote-jnicode-mako PASS");
    else if (scenario == 10)
        std::puts("hook-symbol=1 trace-symbol=libghostlab.so!lab_add+0x0 ghost-symtab=1 disk-symtab=1 missing=ENOENT stage2-symbol-resolver PASS");
    else if (scenario == 11)
        std::puts("ghost-buffer=1 source-decoupled=1 isolated-parent=1 app-parent=1 find-class=1 unload=1 stale-handle=1 stage2-dex-loader PASS");
    else if (scenario == 12)
        std::puts("binder-client=1 token-dispatch=1 linker-internal=1 before-after=1 lazy=1 log-default-off=1 shadow=1 child-cleaned=1 stage2-interceptors PASS");
    else if (scenario == 13)
        std::puts("constructors-before-after=1 jni-onload-before-after=1 register-natives=1 function-match=1 native-trace=1 restored=1 hidden-symtab=1 teardown=1 child-cleaned=1 stage2-so-lifecycle PASS");
    else if (scenario == 14)
        std::puts("dynamic=1 br-followed=1 internal-target=1 explicit-gap=1 junk-executed=0 result=42 child-cleaned=1 stage2-gtrace PASS");
    else if (scenario == 15)
        std::puts("handles=2 config-isolated=1 interleaved=1 writer-routed=1 prologue-full=1 query-stop-race=1 stop-one-keeps-other=1 stale-rejected=1 child-cleaned=1 stage2-multitrace PASS");
    else if (scenario == 2)
        std::puts("zygote-init=1 package-dispatch=1 ghost-entry=1 zygote-parent-isolated=1 child-cleaned=1 stage2-zygote-package PASS");
    else if (scenario == 1)
        std::puts("zygote-init=1 fork-inherit=1 zygote-parent-isolated=1 child-cleaned=1 stage2-zygote-fork PASS");
    else
        std::puts("zygote-init=1 ifunc-fixup=1 poll-resume=1 cleaned=1 stage2-zygote-init PASS");
    return 0;
}

/* Three third-party apps (com.imusic.iting, com.threegene.yeemiao,
 * com.funshion.video.mobile): in-kernel Zygote discovery, task_work_add
 * INIT delivery (poll-hook fallback), package dispatch by truncated comm,
 * and a Gum Lua module hooking libc.so!getpid in every target. */
int command_gumlua_targets_test(const char *key, bool dbi_mode = false,
                                 bool stalker_mode = false,
                                 const char *single_package = nullptr,
                                 const char *single_component = nullptr,
                                 const char *single_label = nullptr,
                                 unsigned int quiet_seconds = 0U)
{
    rtgum_su_profile profile{};
    profile.uid = static_cast<std::uint32_t>(getuid());
    profile.to_uid = 0;
    if (rtgum_sc_su(key, &profile) != 0 || getuid() != 0) {
        std::fprintf(stderr, "GumLua su failed\n");
        return 1;
    }

    char command[512];
    char response[kControlBufferSize]{};
    const char *daemon = "/data/local/tmp/rtgum-stage1-pixel8/rtgum-stage2-daemon.so";
    const char *module = stalker_mode
                             ? "/data/local/tmp/rtgum-stage1-pixel8/rtgum-stage2-dbi-stalker.ghm"
                             : dbi_mode
                                   ? "/data/local/tmp/rtgum-stage1-pixel8/rtgum-stage2-dbi.ghm"
                                   : "/data/local/tmp/rtgum-stage1-pixel8/rtgum-stage2-gumlua.ghm";
    const char *gum = "/data/local/tmp/rtgum-stage1-pixel8/librtgum-gum-ghost.so";
    const char *lua_helper = "/data/local/tmp/rtgum-stage1-pixel8/librtgum-lua-helper.so";

    struct Target {
        const char *package;
        const char *component;
        const char *label;
    };
    const bool single_target = single_package != nullptr ||
                               single_component != nullptr || single_label != nullptr;
    auto valid_package = [](const char *value) {
        if (!value || std::strlen(value) < 3U || std::strlen(value) > 127U ||
            !std::strchr(value, '.'))
            return false;
        for (const char *cursor = value; *cursor != '\0'; ++cursor) {
            if ((*cursor < 'a' || *cursor > 'z') &&
                (*cursor < 'A' || *cursor > 'Z') &&
                (*cursor < '0' || *cursor > '9') && *cursor != '.' &&
                *cursor != '_')
                return false;
        }
        return true;
    };
    auto valid_component = [](const char *value) {
        if (!value || std::strlen(value) < 3U || std::strlen(value) > 255U ||
            !std::strchr(value, '/'))
            return false;
        for (const char *cursor = value; *cursor != '\0'; ++cursor) {
            if ((*cursor < 'a' || *cursor > 'z') &&
                (*cursor < 'A' || *cursor > 'Z') &&
                (*cursor < '0' || *cursor > '9') && *cursor != '.' &&
                *cursor != '_' && *cursor != '$' && *cursor != '/')
                return false;
        }
        return true;
    };
    auto valid_label = [](const char *value) {
        if (!value || value[0] == '\0' || std::strlen(value) > 63U) return false;
        for (const char *cursor = value; *cursor != '\0'; ++cursor) {
            if ((*cursor < 'a' || *cursor > 'z') &&
                (*cursor < 'A' || *cursor > 'Z') &&
                (*cursor < '0' || *cursor > '9') && *cursor != '_' &&
                *cursor != '-')
                return false;
        }
        return true;
    };
    if (single_target &&
        (!valid_package(single_package) || !valid_component(single_component) ||
         !valid_label(single_label) || dbi_mode || stalker_mode)) {
        std::fprintf(stderr,
                     "gumlua-target-test requires safe package, component, and label arguments\n");
        return 2;
    }
    std::vector<Target> targets;
    if (single_target) {
        targets.push_back({single_package, single_component, single_label});
    } else {
        targets.push_back({"com.imusic.iting",
                           "com.imusic.iting/.LoadingActivity", "imusic"});
        targets.push_back({
            "com.threegene.yeemiao",
            "com.threegene.yeemiao/com.threegene.module.splash.ui.SplashActivity",
            "yeemiao"});
        targets.push_back({"com.funshion.video.mobile",
                           "com.funshion.video.mobile/.MainActivity", "funshion"});
    }

    /* 1. Zygote discovery: the KPM scans the pid space in-kernel; /proc is
     * the ground truth for the cross-check. */
    const long expected_pid = find_pid_by_cmdline("zygote64", true);
    if (expected_pid <= 0) {
        std::fprintf(stderr, "zygote64 pid not found\n");
        return 1;
    }
    if (control(key, "zygote-discover", response, sizeof(response)) != 0) {
        std::fprintf(stderr, "zygote-discover failed: %s\n", response);
        return 1;
    }
    unsigned long discovered_pid = 0;
    unsigned long discovered_flags = 0;
    unsigned int discovered_candidates = 0;
    if (std::sscanf(response,
                    "ok pid=%lu flags=0x%lx is_64=%*u candidates=%u",
                    &discovered_pid,
                    &discovered_flags,
                    &discovered_candidates) != 3 ||
        discovered_candidates == 0) {
        std::fprintf(stderr, "zygote-discover parse failed: %s\n", response);
        return 1;
    }
    if (static_cast<long>(discovered_pid) != expected_pid) {
        std::fprintf(stderr,
                     "zygote-discover mismatch: kernel=%lu proc=%ld\n",
                     discovered_pid,
                     expected_pid);
        return 1;
    }
    const long pid = expected_pid;
    std::printf("zygote-discovered pid=%lu flags=0x%lx candidates=%u\n",
                discovered_pid,
                discovered_flags,
                discovered_candidates);
    std::fflush(stdout);

    auto stop_inherited = [&]() {
        std::system("am force-stop com.laodeng.jnicode >/dev/null 2>&1");
        std::system("am force-stop com.android.settings >/dev/null 2>&1");
        std::system("am force-stop com.google.android.apps.pixel.dcservice >/dev/null 2>&1");
        std::system("am force-stop com.google.android.settings.intelligence >/dev/null 2>&1");
        for (const Target &target : targets) {
            char stop_command[192];
            std::snprintf(stop_command, sizeof(stop_command),
                          "am force-stop %s >/dev/null 2>&1", target.package);
            std::system(stop_command);
        }
    };
    auto fail = [&](const char *reason) {
        std::fprintf(stderr, "%s: %s\n", reason, response);
        stop_inherited();
        return 1;
    };

    /* 2. Link, resolve, hooks, bootstrap. */
    std::snprintf(command,
                  sizeof(command),
                  "zygote-link %ld %s rtgum_stage2_daemon_dispatch",
                  pid,
                  daemon);
    unsigned long base = 0;
    unsigned long size = 0;
    unsigned int needed = 0;
    unsigned int imports = 0;
    unsigned int ifuncs = 0;
    if (control(key, command, response, sizeof(response)) != 0 ||
        std::sscanf(response,
                    "ok pid=%*ld name=zygote64 base=0x%lx entry=0x%*lx size=%lu relocations=%*u needed=%u imports=%u ifuncs=%u",
                    &base,
                    &size,
                    &needed,
                    &imports,
                    &ifuncs) != 5 ||
        base == 0 || size == 0 || needed != 1U || imports == 0U)
        return fail("Zygote link failed");

    unsigned long maps_address = 0;
    unsigned long maps_length = 0;
    if (!read_maps_into_ghost(key, pid, maps_address, maps_length))
        return fail("Zygote maps staging failed");
    std::snprintf(command,
                  sizeof(command),
                  "zygote-resolve %ld 0x%lx 0x%lx %lu",
                  pid,
                  base,
                  maps_address,
                  maps_length);
    unsigned int resolved_needed = 0;
    unsigned int resolved_imports = 0;
    unsigned int deferred_ifuncs = 0;
    const bool resolved = control(key, command, response, sizeof(response)) == 0 &&
        std::sscanf(response,
                    "ok pid=%*ld base=0x%*lx needed=%u imports=%u ifuncs=%u resolved=1",
                    &resolved_needed,
                    &resolved_imports,
                    &deferred_ifuncs) == 3;
    free_ghost_buffer(key, maps_address);
    if (!resolved || resolved_needed != needed ||
        resolved_imports + deferred_ifuncs != imports)
        return fail("Zygote resolution failed");

    if (control(key, "hook-sysni", response, sizeof(response)) != 0 ||
        std::strcmp(response, "ok sysni_hook=1") != 0)
        return fail("Zygote channel hook failed");
    if (control(key, "hook-poll", response, sizeof(response)) != 0 ||
        std::strcmp(response, "ok poll_hook=1") != 0)
        return fail("Zygote poll hook failed");
    std::snprintf(command,
                  sizeof(command),
                  "zygote-bootstrap %ld 0x%lx 0x%lx 0x%lx",
                  pid,
                  base,
                  getauxval(AT_HWCAP),
                  getauxval(AT_HWCAP2));
    unsigned int ifunc_slots = 0;
    if (control(key, command, response, sizeof(response)) != 0 ||
        std::sscanf(response,
                    "ok pid=%*ld base=0x%*lx trampoline=0x%*lx ctx=0x%*lx dispatch=0x%*lx status=0x%*lx fixup=%*lu ifunc_slots=%u dispatched=1",
                    &ifunc_slots) != 1)
        return fail("Zygote bootstrap failed");
    std::printf("zygote-bootstrap armed pid=%ld base=0x%lx ifunc_slots=%u\n",
                pid,
                base,
                ifunc_slots);
    std::fflush(stdout);

    /* 3. INIT delivery: task_work_add first (no wake-ups needed), with the
     * Settings poll wake-up as the fallback. */
    bool taskwork_armed = false;
    std::snprintf(command, sizeof(command), "zygote-taskwork %ld", pid);
    if (control(key, command, response, sizeof(response)) == 0 &&
        std::strstr(response, "armed=1 taskwork=1") != nullptr) {
        taskwork_armed = true;
        std::printf("zygote-taskwork armed: %s\n", response);
        std::fflush(stdout);
    }
    bool initialized = false;
    for (int attempt = 0; attempt < 300; ++attempt) {
        /* Settings launches serve both delivery paths: they wake the poll
         * hook's dispatch AND nudge the task_work return-to-user. Running
         * them regardless of the taskwork arm keeps INIT delivery robust
         * when the zygote is busy at arm time. */
        if (attempt % 12 == 0 && attempt < 60) {
            std::system("am force-stop com.android.settings >/dev/null 2>&1");
            if (std::system("am start -a android.settings.SETTINGS >/dev/null 2>&1") != 0)
                return fail("Settings wake-up for Zygote INIT failed");
        }
        std::snprintf(command, sizeof(command), "daemon-status %ld", pid);
        if (control(key, command, response, sizeof(response)) == 0 &&
            std::strstr(response, "phase=1 ") &&
            std::strstr(response, "magic=0x4441454d4f4e3230 ") &&
            std::strstr(response, "quiescent=1")) {
            initialized = true;
            break;
        }
        usleep(250000);
    }
    if (!initialized) return fail("Zygote INIT did not complete");
    std::printf("zygote-init=1 taskwork=%u\n", taskwork_armed ? 1U : 0U);
    std::fflush(stdout);

    /* 4. Comm hook + the three package configs (mako empty, gum backend). */
    if (control(key, "hook-comm", response, sizeof(response)) != 0 ||
        std::strcmp(response, "ok comm_hook=1") != 0)
        return fail("package comm hook failed");
    for (const Target &target : targets) {
        std::snprintf(command,
                      sizeof(command),
                      "daemon-config %ld %s %s - %s %s",
                      pid,
                      target.package,
                      module,
                      gum,
                      lua_helper);
        if (control(key, command, response, sizeof(response)) != 0 ||
            std::strncmp(response, "ok ", 3) != 0)
            return fail("package configuration failed");
        std::printf("configured package=%s\n", target.package);
        std::fflush(stdout);
    }

    /* 5. Launch each target, wait for the Gum Lua module, prove the open()
     * hook through the KPM crashlog breadcrumbs. */
    for (const Target &target : targets) {
        /* Gum and Lua bytes were cached by daemon-config.  The child asks KPM
         * to link those bytes directly into VMA-less memory; no app-private
         * staging file or platform dlopen is involved. */
        std::system("input keyevent KEYCODE_WAKEUP >/dev/null 2>&1");
        std::system("wm dismiss-keyguard >/dev/null 2>&1");
        char stop_command[128];
        char launch_command[256];
        std::snprintf(stop_command,
                      sizeof(stop_command),
                      "am force-stop %s >/dev/null 2>&1",
                      target.package);
        std::snprintf(launch_command,
                      sizeof(launch_command),
                      "am start -n %s -f 0x10008000 >/dev/null 2>&1",
                      target.component);
        if (control(key, "crashlog-clear", response, sizeof(response)) != 0)
            return fail("crashlog clear failed");
        std::system(stop_command);
        std::system(launch_command);
        long target_pid = -1;
        /* These apps cold-start slowly (10s+); relaunch periodically in case
         * the first activity instance finished before the process settled.
         * The packaged launcher component is preferred, but a device that
         * renames its entry activity (or a build whose component string went
         * stale) is handled by resolving the launcher dynamically. */
        char resolved_component[256];
        resolved_component[0] = '\0';
        for (int attempt = 0; attempt < 900 && target_pid <= 0; ++attempt) {
            target_pid = find_pid_by_cmdline(target.package, true);
            if (target_pid <= 0) {
                if (attempt == 150 || attempt == 450) {
                    if (resolved_component[0] == '\0') {
                        char query[256];
                        std::snprintf(query, sizeof(query),
                                      "cmd package resolve-activity --brief "
                                      "-c android.intent.category.LAUNCHER %s "
                                      "2>/dev/null | tail -n 1",
                                      target.package);
                        FILE *pipe = popen(query, "r");
                        if (pipe != nullptr) {
                            if (fgets(resolved_component,
                                      sizeof(resolved_component), pipe) != nullptr) {
                                char *newline = std::strchr(resolved_component, '\n');
                                if (newline) *newline = '\0';
                            }
                            pclose(pipe);
                        }
                        if (std::strchr(resolved_component, '/') != nullptr) {
                            std::printf("resolved-component=%s package=%s\n",
                                        resolved_component, target.package);
                            std::fflush(stdout);
                        } else {
                            resolved_component[0] = '\0';
                        }
                    }
                    if (resolved_component[0] != '\0') {
                        char retry_command[420];
                        std::snprintf(retry_command, sizeof(retry_command),
                                      "am start -n %s -f 0x10008000 >/dev/null 2>&1",
                                      resolved_component);
                        std::system(retry_command);
                    } else {
                        std::system(launch_command);
                    }
                } else if (attempt % 50 == 25) {
                    std::system(launch_command);
                }
                usleep(100000);
            }
        }
        if (target_pid <= 0) return fail("package process is absent");
        /* The module reports completion through the daemon's extra status
         * word: 512 = gumlua armed, 0x210 = in-app DBI clone executed. */
        const unsigned long expected_extra = stalker_mode ? 0x220UL :
                                             dbi_mode ? 0x210UL : 512UL;
        char extra_field[32];
        std::snprintf(extra_field, sizeof(extra_field), "extra=%lu ", expected_extra);
        bool dispatched = false;
        for (int attempt = 0; attempt < 1200; ++attempt) {
            /* A launcher process can finish just after the first pidof.
             * Follow its replacement instead of polling a dead PID for two
             * minutes and reporting a false injection failure. */
            if (attempt % 5 == 0) {
                const long current_pid = find_pid_by_cmdline(target.package, true);
                if (current_pid > 0 && current_pid != target_pid) {
                    target_pid = current_pid;
                    std::printf("target=%s replacement-pid=%ld\n",
                                target.label, target_pid);
                    std::fflush(stdout);
                } else if (current_pid <= 0 && attempt % 50 == 0) {
                    std::system(launch_command);
                }
            }
            std::snprintf(command, sizeof(command), "daemon-status %ld", target_pid);
            if (control(key, command, response, sizeof(response)) == 0 &&
                std::strstr(response, "phase=3 modules=1 ") &&
                std::strstr(response, extra_field) &&
                std::strstr(response, "magic=0x4441454d4f4e3230 ")) {
                dispatched = true;
                break;
            }
            usleep(100000);
        }
        if (!dispatched) {
            return fail(dbi_mode ? "in-app DBI module did not report armed"
                                 : "gumlua ghostEntry did not complete");
        }
        if (dbi_mode) {
            /* The module logs its evidence through the KPM printk channel. */
            std::system("dmesg > /data/local/tmp/rtgum-stage1-pixel8/rtgum-dbi-dmesg.log 2>/dev/null");
            const bool executed = file_contains(
                "/data/local/tmp/rtgum-stage1-pixel8/rtgum-dbi-dmesg.log",
                "rtgum-dbi-module: in-app clone executed and matched");
            const bool allocated = file_contains(
                "/data/local/tmp/rtgum-stage1-pixel8/rtgum-dbi-dmesg.log",
                "rtgum-dbi-module: ghost clone at 0x");
            const bool stalker_completed = !stalker_mode || file_contains(
                "/data/local/tmp/rtgum-stage1-pixel8/rtgum-dbi-dmesg.log",
                "rtgum-dbi-module: stalker completed");
            std::system(stop_command);
            std::printf("target=%s in-app-dbi-armed=1 ghost-clone=%u executed=%u "
                        "stalker=%u pid=%ld\n",
                        target.label, allocated ? 1U : 0U, executed ? 1U : 0U,
                        stalker_completed ? 1U : 0U, target_pid);
            std::fflush(stdout);
            if (!allocated || !executed || !stalker_completed)
                return fail("in-app DBI evidence missing from the kernel log");
            bool dbi_exited = false;
            for (int attempt = 0; attempt < 80; ++attempt) {
                if (find_pid_by_cmdline(target.package, true) <= 0) {
                    dbi_exited = true;
                    break;
                }
                usleep(100000);
            }
            if (!dbi_exited) return fail("package process survived force-stop");
            continue;
        }
        /* The fixture uses low-frequency getpid and performs one deterministic
         * call from Lua after the hook is armed. Evidence uses HostApiV2::log
         * and the authenticated KPM channel. Some
         * protected apps replace their launcher process while Gum is binding;
         * retain every observed PID so a hit from a short-lived replacement is
         * not lost merely because pidof already points at its successor. Only
         * relaunch when the package is actually absent: repeated am start calls
         * while a process is alive can create the very replacement race this
         * acceptance test is intended to observe. */
        bool hook_fired = false;
        bool lua_leave_fired = false;
        bool ordinary_memory_ok = false;
        long hit_pid = -1;
        long candidate_pids[32]{};
        unsigned int candidate_count = 0;
        auto remember_pid = [&](long candidate) {
            if (candidate <= 0) return;
            for (unsigned int i = 0; i < candidate_count; ++i) {
                if (candidate_pids[i] == candidate) return;
            }
            if (candidate_count < sizeof(candidate_pids) / sizeof(candidate_pids[0]))
                candidate_pids[candidate_count++] = candidate;
        };
        remember_pid(target_pid);
        for (int attempt = 0; attempt < 200; ++attempt) {
            const long current_pid = find_pid_by_cmdline(target.package, true);
            if (current_pid > 0) {
                const unsigned int before = candidate_count;
                remember_pid(current_pid);
                if (candidate_count != before) {
                    std::printf("target=%s hook-window-pid=%ld\n",
                                target.label, current_pid);
                    std::fflush(stdout);
                }
            } else if (attempt % 10 == 0) {
                std::system(launch_command);
            }
            std::system("dmesg > /data/local/tmp/rtgum-stage1-pixel8/rtgum-gum-dmesg.log "
                        "2>/dev/null");
            for (unsigned int i = 0; i < candidate_count; ++i) {
                char hit_marker[160];
                char leave_marker[160];
                char memory_marker[160];
                char ghost_memory_marker[160];
                std::snprintf(hit_marker,
                              sizeof(hit_marker),
                              "rtgum-daemon[%ld]: gum-lua getpid hit=1 lua-enter=1",
                              candidate_pids[i]);
                std::snprintf(leave_marker,
                              sizeof(leave_marker),
                              "rtgum-daemon[%ld]: gum-lua getpid leave=1 lua-leave=1",
                              candidate_pids[i]);
                std::snprintf(memory_marker,
                              sizeof(memory_marker),
                              "rtgum-daemon[%ld]: gum-lua ordinary-memory=1",
                              candidate_pids[i]);
                std::snprintf(ghost_memory_marker,
                              sizeof(ghost_memory_marker),
                              "rtgum-daemon[%ld]: gum-lua ghost-memory=1",
                              candidate_pids[i]);
                const bool enter_seen = file_contains(
                    "/data/local/tmp/rtgum-stage1-pixel8/rtgum-gum-dmesg.log",
                    hit_marker);
                const bool leave_seen = file_contains(
                    "/data/local/tmp/rtgum-stage1-pixel8/rtgum-gum-dmesg.log",
                    leave_marker);
                const bool memory_seen = file_contains(
                    "/data/local/tmp/rtgum-stage1-pixel8/rtgum-gum-dmesg.log",
                    memory_marker) && file_contains(
                    "/data/local/tmp/rtgum-stage1-pixel8/rtgum-gum-dmesg.log",
                    ghost_memory_marker);
                if (enter_seen && leave_seen && memory_seen) {
                    hit_pid = candidate_pids[i];
                    hook_fired = true;
                    lua_leave_fired = true;
                    ordinary_memory_ok = true;
                    break;
                }
            }
            if (hook_fired) break;
            usleep(200000);
        }
        if (hit_pid > 0) target_pid = hit_pid;
        std::printf("target=%s gumlua-armed=1 hook-fired=%u lua-callback=%u memory-io=%u pid=%ld\n",
                    target.label,
                    hook_fired ? 1U : 0U,
                    lua_leave_fired ? 1U : 0U,
                    ordinary_memory_ok ? 1U : 0U,
                    target_pid);
        std::fflush(stdout);
        if (!hook_fired || !lua_leave_fired || !ordinary_memory_ok)
            return fail("gum-lua getpid callbacks or guarded memory roundtrip failed");
        /* The status words are written by the backend only after successful
         * private linking/binding.  Check the exact runtime addresses in both
         * procfs views, and also reject any named platform-loader residue. */
        std::snprintf(command, sizeof(command), "daemon-status %ld", target_pid);
        unsigned long gum_base = 0UL;
        unsigned long lua_base = 0UL;
        unsigned long backend_flags = 0UL;
        if (control(key, command, response, sizeof(response)) != 0 ||
            !response_hex_field(response, "gum_base=", gum_base) ||
            !response_hex_field(response, "lua_base=", lua_base) ||
            !response_hex_field(response, "backend_flags=", backend_flags) ||
            gum_base == 0UL || lua_base == 0UL ||
            (backend_flags & (RTGUM_DAEMON_BACKEND_GUM_GHOST |
                              RTGUM_DAEMON_BACKEND_LUA_GHOST |
                              RTGUM_DAEMON_BACKEND_GUM_ALLOCATIONS_GHOST)) !=
                (RTGUM_DAEMON_BACKEND_GUM_GHOST |
                 RTGUM_DAEMON_BACKEND_LUA_GHOST |
                 RTGUM_DAEMON_BACKEND_GUM_ALLOCATIONS_GHOST))
            return fail("Gum/Lua ghost backend status is incomplete");
        char maps_path[64];
        char smaps_path[64];
        std::snprintf(maps_path, sizeof(maps_path), "/proc/%ld/maps", target_pid);
        std::snprintf(smaps_path, sizeof(smaps_path), "/proc/%ld/smaps", target_pid);
        char matched[512]{};
        const bool gum_in_maps = range_file_contains(
            maps_path, static_cast<std::uintptr_t>(gum_base), matched, sizeof(matched));
        const bool lua_in_maps = range_file_contains(
            maps_path, static_cast<std::uintptr_t>(lua_base), matched, sizeof(matched));
        const bool gum_in_smaps = range_file_contains(
            smaps_path, static_cast<std::uintptr_t>(gum_base), matched, sizeof(matched));
        const bool lua_in_smaps = range_file_contains(
            smaps_path, static_cast<std::uintptr_t>(lua_base), matched, sizeof(matched));
        const bool named_residue =
            file_contains(maps_path, "librtgum-gum-ghost.so") ||
            file_contains(maps_path, "librtgum-lua-helper.so") ||
            file_contains(smaps_path, "librtgum-gum-ghost.so") ||
            file_contains(smaps_path, "librtgum-lua-helper.so");
        if (gum_in_maps || lua_in_maps || gum_in_smaps || lua_in_smaps ||
            named_residue)
            return fail("Gum/Lua backend leaked into maps or smaps");
        std::printf("target=%s backends-vmaless=1 gum-base=0x%lx lua-base=0x%lx "
                    "maps-hidden=1 smaps-hidden=1 pid=%ld\n",
                    target.label, gum_base, lua_base, target_pid);
        std::fflush(stdout);
        if (single_target && quiet_seconds != 0U) {
            bool survived = true;
            for (unsigned int tick = 0; tick < quiet_seconds * 4U; ++tick) {
                const long current_pid = find_pid_by_cmdline(target.package, true);
                if (current_pid != target_pid) {
                    survived = false;
                    break;
                }
                if (tick % 4U == 0U) {
                    std::snprintf(command, sizeof(command), "daemon-status %ld",
                                  target_pid);
                    if (control(key, command, response, sizeof(response)) != 0 ||
                        !std::strstr(response, "phase=3 modules=1 ") ||
                        !std::strstr(response, "extra=512 ")) {
                        survived = false;
                        break;
                    }
                }
                usleep(250000);
            }
            std::printf("target=%s hook-survived=%u quiet-seconds=%u pid=%ld\n",
                        target.label, survived ? 1U : 0U, quiet_seconds,
                        target_pid);
            std::fflush(stdout);
            if (!survived) return fail("Gum Lua hook did not survive the quiet window");
        }
        std::system(stop_command);
        bool exited = false;
        for (int attempt = 0; attempt < 80; ++attempt) {
            if (find_pid_by_cmdline(target.package, true) <= 0) {
                exited = true;
                break;
            }
            usleep(100000);
        }
        if (!exited) return fail("target did not exit");
    }

    /* 6. Cleanup: unlink the daemon, restore, verify no residual state. */
    std::snprintf(command, sizeof(command), "zygote-unlink %ld 0x%lx", pid, base);
    if (control(key, command, response, sizeof(response)) != 0 ||
        std::strncmp(response, "ok ", 3) != 0)
        return fail("zygote unlink failed");
    bool cleared = false;
    for (int attempt = 0; attempt < 120; ++attempt) {
        if (control(key, "capabilities", response, sizeof(response)) == 0 &&
            std::strstr(response, "active=0 busy=0 images=0 daemon=0")) {
            cleared = true;
            break;
        }
        if (attempt % 8 == 0) stop_inherited();
        usleep(100000);
    }
    if (!cleared) return fail("residual state after unlink");
    if (single_target) {
        std::printf("zygote-discover=1 taskwork-init=1 target=%s hook-fired=1 "
                    "child-cleaned=1 stage2-single-app-gumlua PASS\n",
                    single_label);
    } else {
        std::puts(stalker_mode
                      ? "zygote-discover=1 taskwork-init=1 imusic=1 yeemiao=1 funshion=1 "
                        "in-app-dbi=1 stalker=1 child-cleaned=1 stage2-three-apps-dbi-stalker PASS"
                      : dbi_mode
                      ? "zygote-discover=1 taskwork-init=1 imusic=1 yeemiao=1 funshion=1 "
                        "in-app-dbi=1 child-cleaned=1 stage2-three-apps-dbi PASS"
                      : "zygote-discover=1 taskwork-init=1 imusic=1 yeemiao=1 funshion=1 "
                        "hook-fired=1 child-cleaned=1 stage2-three-apps-gumlua PASS");
    }
    return 0;
}

/* Shadow Data Page self-test: real EL0 reads through the blocked PTE.
 * direct_read_word faults (untrusted PC) and must see the ORIGINAL value via
 * DABT emulation; the q-register variant exercises the single-step serve
 * path. After registering this function's page as trusted, the same reads
 * must see the tampered shadow value. */
__attribute__((noinline)) unsigned long long shadow_direct_read_word(
    volatile unsigned long long *slot)
{
    unsigned long long value = 0;
    asm volatile("ldr %0, [%1]" : "=r"(value) : "r"(slot));
    return value;
}

__attribute__((noinline)) void shadow_direct_read_q(
    volatile unsigned long long *slot)
{
    asm volatile("ldr q0, [%0]" : : "r"(slot) : "v0", "memory");
}

int command_shadow_selftest(const char *key)
{
    char response[kControlBufferSize]{};
    char command[128];
    std::printf("step1-hook-art-shadow\n");
    std::fflush(stdout);
    /* Ensure the DABT hooks are live. */
    if (control(key, "hook-art-shadow", response, sizeof(response)) != 0 ||
        std::strcmp(response, "ok art_shadow=1") != 0) {
        std::fprintf(stderr, "shadow selftest: hook-art-shadow failed: %s\n", response);
        return 1;
    }
    if (control(key, "shadow-trust-clear", response, sizeof(response)) != 0) {
        std::fprintf(stderr, "shadow selftest: trust clear failed\n");
        return 1;
    }
    std::printf("step2-ghost-alloc\n");
    std::fflush(stdout);
    /* Allocate a RW page and write a known pattern. */
    unsigned long page = 0;
    if (control(key, "ghost-alloc 4096 3", response, sizeof(response)) != 0 ||
        std::sscanf(response, "ok address=0x%lx", &page) != 1 || page == 0) {
        std::fprintf(stderr, "shadow selftest: ghost-alloc failed: %s\n", response);
        return 1;
    }
    auto *words = reinterpret_cast<volatile unsigned long long *>(page);
    words[0] = 0x1111111122222222ULL;
    words[1] = 0x3333333344444444ULL;
    std::printf("step3-register page=0x%lx\n", page);
    std::fflush(stdout);
    std::snprintf(command, sizeof(command), "shadow-register 0x%lx", page);
    if (control(key, command, response, sizeof(response)) != 0 ||
        std::strncmp(response, "ok page=", 8) != 0) {
        std::fprintf(stderr, "shadow selftest: register failed: %s\n", response);
        return 1;
    }
    std::printf("step4-patch\n");
    std::fflush(stdout);
    constexpr unsigned long long kPatch = 0xdeadbeefcafef00dULL;
    std::snprintf(command, sizeof(command), "shadow-patch 0x%lx 0x8 0x%llx", page, kPatch);
    if (control(key, command, response, sizeof(response)) != 0 ||
        std::strncmp(response, "ok page=", 8) != 0) {
        std::fprintf(stderr, "shadow selftest: patch failed: %s\n", response);
        return 1;
    }
    std::printf("step5-shadow-read\n");
    std::fflush(stdout);
    unsigned long trusted_word = 0;
    std::snprintf(command, sizeof(command), "shadow-read 0x%lx 0x8", page);
    if (control(key, command, response, sizeof(response)) != 0 ||
        std::sscanf(response, "ok page=0x%*lx offset=0x%*lx value=0x%lx",
                    &trusted_word) != 1 ||
        trusted_word != static_cast<unsigned long>(kPatch)) {
        std::fprintf(stderr, "shadow selftest: shadow-read mismatch: %s\n", response);
        return 1;
    }
    std::printf("step6-untrusted-read-word0\n");
    std::fflush(stdout);
    /* Untrusted EL0 reads (DABT emulation): the ORIGINAL values. */
    const unsigned long long first = shadow_direct_read_word(&words[0]);
    std::printf("step7-untrusted-read-word1\n");
    std::fflush(stdout);
    const unsigned long long second = shadow_direct_read_word(&words[1]);
    if (first != 0x1111111122222222ULL || second != 0x3333333344444444ULL) {
        std::fprintf(stderr, "shadow selftest: untrusted read saw 0x%llx / 0x%llx\n",
                     static_cast<unsigned long long>(first),
                     static_cast<unsigned long long>(second));
        return 1;
    }
    std::printf("step8-untrusted-q-read\n");
    std::fflush(stdout);
    /* Untrusted SIMD read (single-step serve path). */
    shadow_direct_read_q(&words[0]);
    std::printf("step9-trust-add\n");
    std::fflush(stdout);
    /* Trust this function's page: the same reads must now see the shadow. */
    const unsigned long self_page =
        reinterpret_cast<unsigned long>(&shadow_direct_read_word) & ~0xfffUL;
    std::snprintf(command, sizeof(command), "shadow-trust-add 0x%lx 0x%lx",
                  self_page, self_page + 0x1000UL);
    if (control(key, command, response, sizeof(response)) != 0 ||
        std::strncmp(response, "ok start=", 9) != 0) {
        std::fprintf(stderr, "shadow selftest: trust add failed: %s\n", response);
        return 1;
    }
    std::printf("step10-trusted-read\n");
    std::fflush(stdout);
    const unsigned long long tampered = shadow_direct_read_word(&words[1]);
    std::printf("step11-trusted-q-read\n");
    std::fflush(stdout);
    shadow_direct_read_q(&words[0]);
    if (tampered != kPatch) {
        std::fprintf(stderr, "shadow selftest: trusted read saw 0x%llx\n",
                     static_cast<unsigned long long>(tampered));
        return 1;
    }
    std::printf("step12-status\n");
    std::fflush(stdout);
    if (control(key, "shadow-status", response, sizeof(response)) != 0) return 1;
    std::fprintf(stderr, "shadow selftest counters: %s\n", response);
    unsigned long emulated = 0;
    unsigned long served = 0;
    unsigned long traps = 0;
    if (std::sscanf(response,
                    "ok pages=%*u trusts=%*u emulated=%lu served=%lu traps=%lu",
                    &emulated, &served, &traps) != 3 ||
        emulated == 0UL || served == 0UL || traps == 0UL) {
        std::fprintf(stderr, "shadow selftest: counters did not advance (%s)\n", response);
        return 1;
    }
    std::printf("step13-cleanup\n");
    std::fflush(stdout);
    control(key, "shadow-trust-clear", response, sizeof(response));
    std::snprintf(command, sizeof(command), "shadow-unregister 0x%lx", page);
    control(key, command, response, sizeof(response));
    std::snprintf(command, sizeof(command), "ghost-free 0x%lx", page);
    control(key, command, response, sizeof(response));
    std::puts("shadow-selftest emulated=1 served=1 traps=1 scanner-view=1 trusted-view=1 PASS");
    return 0;
}

int command_unload_guard_test(const char *key)
{
    char response[kControlBufferSize]{};
    if (control(key, "ghost-alloc 4096 3", response, sizeof(response)) != 0) return 1;
    unsigned long address = 0;
    unsigned long size = 0;
    if (std::sscanf(response, "ok address=0x%lx size=%lu", &address, &size) != 2 ||
        address == 0 || size != 4096UL)
        return 1;

    errno = 0;
    const long unload_result = rtgum_sc_kpm_unload(key, kModuleName);
    const int unload_errno = errno;
    const bool refused = unload_result == -EBUSY ||
                         (unload_result == -1 && unload_errno == EBUSY);
    if (!refused || !module_is_loaded(key)) {
        std::fprintf(stderr,
                     "live-state unload guard failed: result=%ld errno=%d\n",
                     unload_result,
                     unload_errno);
        if (module_is_loaded(key)) ghost_cleanup(key, address);
        return 1;
    }
    if (ghost_cleanup(key, address) != 0) return 1;
    if (control(key, "capabilities", response, sizeof(response)) != 0 ||
        std::strstr(response, "active=0 busy=0 images=0 daemon=0") == nullptr)
        return 1;
    std::puts("stage1-unload-guard-test PASS");
    return 0;
}

int command_ghost_test(const char *key)
{
    constexpr unsigned long page_size = 4096UL;
    char response[kControlBufferSize];
    char command[96];
    char matched[512]{};
    unsigned long address = 0;
    unsigned long size = 0;
    unsigned long protection = 0;
    long kernel_pid = -1;

    if (control(key, "ghost-alloc 4096 3", response, sizeof(response)) != 0) return 1;
    if (std::sscanf(response,
                    "ok address=0x%lx size=%lu prot=%lu pid=%ld",
                    &address,
                    &size,
                    &protection,
                    &kernel_pid) != 4 ||
        size != page_size || protection != 3UL || kernel_pid != static_cast<long>(getpid())) {
        std::fprintf(stderr, "unexpected ghost allocation response: %s\n", response);
        if (address != 0) ghost_cleanup(key, address);
        return 1;
    }

    auto fail = [&](const char *message) {
        std::fprintf(stderr, "%s\n", message);
        ghost_cleanup(key, address);
        return 1;
    };

    if (range_file_contains("/proc/self/maps", address, matched, sizeof(matched))) {
        std::fprintf(stderr, "ghost address leaked through maps: %s\n", matched);
        return fail("ghost visibility check failed");
    }
    if (range_file_contains("/proc/self/smaps", address, matched, sizeof(matched))) {
        std::fprintf(stderr, "ghost address leaked through smaps: %s\n", matched);
        return fail("ghost visibility check failed");
    }

    unsigned char residency = 0;
    errno = 0;
    if (mincore(reinterpret_cast<void *>(address), page_size, &residency) == 0 || errno != ENOMEM)
        return fail("mincore did not reject the VMA-less address with ENOMEM");

    errno = 0;
    void *collision = mmap(reinterpret_cast<void *>(address),
                           page_size,
                           PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                           -1,
                           0);
    if (collision != MAP_FAILED) {
        munmap(collision, page_size);
        return fail("MAP_FIXED unexpectedly replaced the ghost mapping");
    }
    if (errno != ENOMEM) return fail("ghost mmap collision did not fail with ENOMEM");

    auto *bytes = reinterpret_cast<volatile unsigned char *>(address);
    for (unsigned long index = 0; index < page_size; ++index)
        bytes[index] = static_cast<unsigned char>((index * 17U) ^ 0xa5U);
    for (unsigned long index = 0; index < page_size; ++index) {
        if (bytes[index] != static_cast<unsigned char>((index * 17U) ^ 0xa5U))
            return fail("ghost read/write verification failed");
    }

    auto *instructions = reinterpret_cast<volatile std::uint32_t *>(address);
    instructions[0] = 0x52824680U; // mov w0, #0x1234
    instructions[1] = 0xd65f03c0U; // ret

    std::snprintf(command, sizeof(command), "ghost-protect 0x%lx 5", address);
    if (control(key, command, response, sizeof(response)) != 0 ||
        std::strncmp(response, "ok ", 3) != 0)
        return fail("RW to RX transition failed");

    using TestFunction = int (*)();
    auto test_function = reinterpret_cast<TestFunction>(address);
    if (test_function() != 0x1234) return fail("execution from ghost RX memory failed");

    if (control(key, "capabilities", response, sizeof(response)) != 0)
        return fail("capabilities query failed before execute-only test");
    const bool epan_enabled = std::strstr(response, " epan=1 ") != nullptr;
    if (epan_enabled) {
        std::snprintf(command, sizeof(command), "ghost-protect 0x%lx 4", address);
        if (control(key, command, response, sizeof(response)) != 0 ||
            std::strncmp(response, "ok ", 3) != 0)
            return fail("RX to execute-only transition failed");
        if (test_function() != 0x1234) return fail("execution from ghost X-only memory failed");
        if (probe_xonly_data_read(bytes) != 1)
            return fail("EL0 data read from ghost X-only memory did not fault with SIGSEGV");
    } else {
        std::snprintf(command, sizeof(command), "ghost-protect 0x%lx 4", address);
        if (control(key, command, response, sizeof(response)) != 0 ||
            std::strcmp(response, "error=ghost-protect-failed code=-95") != 0)
            return fail("X-only transition was not rejected without active EPAN");
        if (test_function() != 0x1234)
            return fail("rejected X-only transition damaged the RX mapping");
    }

    if (ghost_cleanup(key, address) != 0) return 1;
    std::printf("ghost-allocation verified address=0x%lx size=%lu pid=%ld\n",
                address,
                size,
                kernel_pid);
    if (epan_enabled)
        std::puts("maps-hidden=1 smaps-hidden=1 mincore-hidden=1 mmap-collision-blocked=1 rw=1 rx-exec=1 xonly-exec=1 xonly-read-fault=1 freed=1");
    else
        std::puts("maps-hidden=1 smaps-hidden=1 mincore-hidden=1 mmap-collision-blocked=1 rw=1 rx-exec=1 xonly-rejected=1 reason=epan-disabled freed=1");
    std::puts("stage1-ghost-test PASS");
    return 0;
}

/* Ghost memory stress acceptance: a resident executable ghost region must
 * survive a wall of NATURAL (non-MAP_FIXED) mmaps. When the kernel's hole
 * search would land on the ghost VA the mmap_region guard fails it closed
 * with -ENOMEM, so the ghost bytes are never silently overwritten. A forked
 * child then allocates and exits to prove the mm_users accounting stays
 * balanced (no leak blocks the exit_mmap teardown or the next run). */
int command_ghost_stress_lab_test(const char *key)
{
    constexpr unsigned long page_size = 4096UL;
    constexpr unsigned long kStressBlocks = 200U;
    constexpr unsigned long kStressBlockSize = 64UL * 1024UL;
    char response[kControlBufferSize];
    char command[96];
    char matched[512]{};
    unsigned long address = 0;
    unsigned long size = 0;
    unsigned long protection = 0;
    long kernel_pid = -1;

    if (control(key, "ghost-alloc 4096 3", response, sizeof(response)) != 0) return 1;
    if (std::sscanf(response,
                    "ok address=0x%lx size=%lu prot=%lu pid=%ld",
                    &address,
                    &size,
                    &protection,
                    &kernel_pid) != 4 ||
        size != page_size || protection != 3UL || kernel_pid != static_cast<long>(getpid())) {
        std::fprintf(stderr, "unexpected ghost allocation response: %s\n", response);
        return 1;
    }
    auto fail = [&](const char *message) {
        std::fprintf(stderr, "%s\n", message);
        ghost_cleanup(key, address);
        return 1;
    };

    /* Install a marker function in the ghost page. */
    auto *instructions = reinterpret_cast<volatile std::uint32_t *>(address);
    instructions[0] = 0x52824680U; // mov w0, #0x1234
    instructions[1] = 0xd65f03c0U; // ret
    std::snprintf(command, sizeof(command), "ghost-protect 0x%lx 5", address);
    if (control(key, command, response, sizeof(response)) != 0 ||
        std::strncmp(response, "ok ", 3) != 0)
        return fail("RW to RX transition failed");
    using TestFunction = int (*)();
    auto test_function = reinterpret_cast<TestFunction>(address);
    if (test_function() != 0x1234) return fail("baseline ghost execution failed");

    /* The stress wall: fill the address space with natural mmaps. Whenever
     * the kernel's candidate range would overlap the ghost VA the guard
     * rejects it (-ENOMEM); count those rejections as the fail-closed
     * evidence and keep going. */
    void *blocks[kStressBlocks]{};
    unsigned int blocks_held = 0;
    unsigned int guard_rejections = 0;
    unsigned int guard_failures = 0;
    for (unsigned int index = 0; index < kStressBlocks; ++index) {
        errno = 0;
        void *block = mmap(nullptr, kStressBlockSize, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (block == MAP_FAILED) {
            if (errno == ENOMEM) {
                ++guard_rejections;
                continue;
            }
            ++guard_failures;
            break;
        }
        /* A successful natural mmap must never overlap the ghost VA: the
         * guard fails such requests closed, so a silent overlap here is a
         * genuine corruption. */
        const unsigned long block_start = reinterpret_cast<unsigned long>(block);
        if (block_start < address + page_size && address < block_start + kStressBlockSize) {
            std::fprintf(stderr, "natural mmap silently overlapped the ghost VA\n");
            return fail("natural mmap overlap");
        }
        volatile unsigned char *fill =
            reinterpret_cast<volatile unsigned char *>(block);
        fill[0] = 0xaa;
        fill[kStressBlockSize - 1] = 0xbb;
        blocks[blocks_held++] = block;
    }
    /* The ghost must still execute after the wall. */
    if (test_function() != 0x1234) return fail("ghost execution corrupted by stress mmaps");
    for (unsigned int index = 0; index < blocks_held; ++index)
        munmap(blocks[index], kStressBlockSize);
    std::printf("ghost-stress blocks-held=%u guard-rejections=%u guard-failures=%u\n",
                blocks_held, guard_rejections, guard_failures);

    /* Restart/leak check: a forked child allocates a ghost page and exits.
     * A leaked mm_users reference would keep the child out of exit_mmap and
     * the waitpid would time out. */
    const pid_t child = fork();
    if (child == 0) {
        char child_response[kControlBufferSize];
        if (control(key, "ghost-alloc 4096 3", child_response, sizeof(child_response)) != 0)
            _exit(2);
        unsigned long child_address = 0;
        if (std::sscanf(child_response, "ok address=0x%lx", &child_address) != 1 ||
            child_address == 0)
            _exit(3);
        volatile unsigned char *probe =
            reinterpret_cast<volatile unsigned char *>(child_address);
        probe[0] = 0x5a;
        if (probe[0] != 0x5a) _exit(4);
        ghost_cleanup(key, child_address);
        _exit(0);
    }
    if (child < 0) return fail("fork failed");
    int child_status = -1;
    bool child_exited = false;
    for (unsigned int attempt = 0; attempt < 100U; ++attempt) {
        const pid_t waited = waitpid(child, &child_status, WNOHANG);
        if (waited == child) {
            child_exited = true;
            break;
        }
        if (waited < 0) break;
        usleep(20000);
    }
    if (!child_exited) {
        kill(child, SIGKILL);
        waitpid(child, nullptr, 0);
        return fail("forked ghost owner did not exit (mm_users leak suspected)");
    }
    if (!WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0)
        return fail("forked ghost owner exited abnormally");

    if (ghost_cleanup(key, address) != 0) return 1;
    if (range_file_contains("/proc/self/maps", address, matched, sizeof(matched))) {
        std::fprintf(stderr, "ghost address leaked through maps after cleanup: %s\n", matched);
        return 1;
    }
    std::puts("maps-hidden=1 mincore-hidden=1 stress-survived=1 fail-closed=1 fork-exit=1 restartable=1 stage1-ghost-stress-lab PASS");
    return 0;
}

struct GhostRaceContext final {
    const char *key;
    unsigned long address;
    std::atomic<unsigned int> ready{0};
    std::atomic<bool> start{false};
    std::atomic<unsigned int> successful{0};
    std::atomic<unsigned int> failed{0};
};

void *ghost_protection_worker(void *opaque)
{
    auto &context = *static_cast<GhostRaceContext *>(opaque);
    context.ready.fetch_add(1, std::memory_order_release);
    while (!context.start.load(std::memory_order_acquire)) sched_yield();
    for (unsigned int attempt = 0; attempt < 64U; ++attempt) {
        char command[96];
        char response[kControlBufferSize];
        const unsigned int protection = (attempt & 1U) != 0U ? 3U : 5U;
        std::snprintf(command, sizeof(command), "ghost-protect 0x%lx %u",
                      context.address, protection);
        if (control(context.key, command, response, sizeof(response)) != 0) {
            context.failed.fetch_add(1, std::memory_order_relaxed);
            break;
        }
        if (std::strncmp(response, "ok ", 3) == 0) {
            context.successful.fetch_add(1, std::memory_order_relaxed);
        } else if (std::strcmp(response, "error=ghost-protect-failed code=-2") == 0) {
            break;
        } else {
            std::fprintf(stderr, "unexpected concurrent protection result: %s\n", response);
            context.failed.fetch_add(1, std::memory_order_relaxed);
            break;
        }
    }
    return nullptr;
}

int command_ghost_race_test(const char *key)
{
    constexpr unsigned int workers = 4U;
    constexpr unsigned int rounds = 12U;
    unsigned int successful = 0;
    for (unsigned int round = 0; round < rounds; ++round) {
        char response[kControlBufferSize];
        if (control(key, "ghost-alloc 4096 3", response, sizeof(response)) != 0)
            return 1;
        unsigned long address = 0;
        unsigned long size = 0;
        if (std::sscanf(response, "ok address=0x%lx size=%lu", &address, &size) != 2 ||
            address == 0 || size != 4096UL) {
            if (address != 0) ghost_cleanup(key, address);
            return 1;
        }
        GhostRaceContext context{key, address};
        pthread_t threads[workers]{};
        unsigned int created = 0;
        for (; created < workers; ++created) {
            if (pthread_create(&threads[created], nullptr,
                               &ghost_protection_worker, &context) != 0)
                break;
        }
        while (context.ready.load(std::memory_order_acquire) != created)
            sched_yield();
        context.start.store(true, std::memory_order_release);
        usleep(1000);
        const int free_result = ghost_cleanup(key, address);
        for (unsigned int index = 0; index < created; ++index)
            pthread_join(threads[index], nullptr);
        successful += context.successful.load(std::memory_order_relaxed);
        if (created != workers || free_result != 0 ||
            context.failed.load(std::memory_order_relaxed) != 0U)
            return 1;
    }
    if (successful == 0U) return 1;
    std::printf("concurrent-protect-free rounds=%u workers=%u successful-protects=%u\n",
                rounds, workers, successful);
    std::puts("stage1-ghost-race-test PASS");
    return 0;
}

#if defined(__aarch64__)
__attribute__((noinline)) int hwbp_target(int first, int second)
{
    volatile int sum = first + second;
    asm volatile("" ::: "memory");
    return sum;
}

#define HWBP_CAPACITY_TARGET(number)                         \
    __attribute__((noinline)) int hwbp_capacity_target##number() \
    {                                                       \
        volatile int value = number;                        \
        return value;                                       \
    }
HWBP_CAPACITY_TARGET(1)
HWBP_CAPACITY_TARGET(2)
HWBP_CAPACITY_TARGET(3)
HWBP_CAPACITY_TARGET(4)
HWBP_CAPACITY_TARGET(5)
HWBP_CAPACITY_TARGET(6)
#undef HWBP_CAPACITY_TARGET

struct HwbpWorkerContext final {
    const char *key;
    std::atomic<unsigned int> rejected{0};
};

void *hwbp_other_thread(void *opaque)
{
    auto &context = *static_cast<HwbpWorkerContext *>(opaque);
    char command[128];
    char response[kControlBufferSize];
    std::snprintf(command, sizeof(command), "hwbp-set 0x%lx 0",
                  reinterpret_cast<unsigned long>(&hwbp_target));
    if (control(context.key, command, response, sizeof(response)) == 0 &&
        std::strncmp(response, "error=hwbp-set-failed code=-22",
                     std::strlen("error=hwbp-set-failed code=-22")) == 0)
        context.rejected.store(1U, std::memory_order_release);
    volatile int observed = hwbp_target(1, 2);
    (void)observed;
    return nullptr;
}

const char *g_hwbp_replacement_key = nullptr;
unsigned long g_hwbp_replacement_handle = 0;
std::atomic<unsigned int> g_hwbp_replacement_error{0};

__attribute__((noinline)) int hwbp_replacement(int first, int second)
{
    char command[96];
    char response[kControlBufferSize];
    std::snprintf(command, sizeof(command), "hwbp-gate-close %lu",
                  g_hwbp_replacement_handle);
    if (control(g_hwbp_replacement_key, command, response, sizeof(response)) != 0 ||
        std::strncmp(response, "ok ", 3) != 0) {
        g_hwbp_replacement_error.store(1U, std::memory_order_release);
        return -900;
    }
    const int original = hwbp_target(first, second);
    std::snprintf(command, sizeof(command), "hwbp-gate-open %lu",
                  g_hwbp_replacement_handle);
    if (control(g_hwbp_replacement_key, command, response, sizeof(response)) != 0 ||
        std::strncmp(response, "ok ", 3) != 0) {
        g_hwbp_replacement_error.store(2U, std::memory_order_release);
        return -901;
    }
    return original + 4;
}
#endif

int command_hwbp_test(const char *key)
{
#if !defined(__aarch64__)
    (void)key;
    return 1;
#else
    char command[128];
    char response[kControlBufferSize];
    std::snprintf(command, sizeof(command), "hwbp-set 0x%lx 0",
                  reinterpret_cast<unsigned long>(&hwbp_target));
    if (control(key, command, response, sizeof(response)) != 0) return 1;
    unsigned long handle = 0;
    unsigned int slots = 0;
    long tid = -1;
    if (std::sscanf(response, "ok handle=%lu slots=%u tid=%ld",
                    &handle, &slots, &tid) != 3 ||
        handle == 0 || slots != 6U || tid != static_cast<long>(getpid())) {
        std::fprintf(stderr, "HWBP registration failed: %s\n", response);
        return 1;
    }
    auto clear = [&]() {
        std::snprintf(command, sizeof(command), "hwbp-clear %lu", handle);
        return control(key, command, response, sizeof(response)) == 0 &&
               std::strncmp(response, "ok ", 3) == 0;
    };
    volatile int first_result = hwbp_target(7, 11);
    if (first_result != 18) {
        clear();
        return 1;
    }
    std::snprintf(command, sizeof(command), "hwbp-snapshot %lu", handle);
    if (control(key, command, response, sizeof(response)) != 0 ||
        std::strstr(response, "entry=1 return=1") == nullptr ||
        std::strstr(response, "x0=0x7 x1=0xb") == nullptr ||
        std::strstr(response, "ret=0x12") == nullptr) {
        std::fprintf(stderr, "HWBP entry/return snapshot failed: %s\n", response);
        clear();
        return 1;
    }
    HwbpWorkerContext worker_context{key};
    pthread_t worker{};
    if (pthread_create(&worker, nullptr, &hwbp_other_thread, &worker_context) != 0) {
        clear();
        return 1;
    }
    pthread_join(worker, nullptr);
    if (worker_context.rejected.load(std::memory_order_acquire) != 1U ||
        control(key, command, response, sizeof(response)) != 0 ||
        std::strstr(response, "entry=1 return=1") == nullptr) {
        std::fprintf(stderr, "subthread hit a main-thread breakpoint: %s\n", response);
        clear();
        return 1;
    }
    volatile int second_result = hwbp_target(3, 5);
    if (second_result != 8 ||
        control(key, command, response, sizeof(response)) != 0 ||
        std::strstr(response, "entry=2 return=2") == nullptr ||
        std::strstr(response, "ret=0x8") == nullptr) {
        std::fprintf(stderr, "HWBP did not rearm at entry: %s\n", response);
        clear();
        return 1;
    }
    if (!clear()) return 1;
    std::puts("tid-bound=1 subthread-registration-rejected=1 entry=2 return=2 subthread-hits=0 rearmed=1 cleared=1");
    std::puts("stage1-hwbp-test PASS");
    return 0;
#endif
}

int command_hwbp_probe_test(const char *key)
{
#if !defined(__aarch64__)
    (void)key;
    return 1;
#else
    char command[128];
    char response[kControlBufferSize];
    std::snprintf(command, sizeof(command), "hwbp-set 0x%lx 0",
                  reinterpret_cast<unsigned long>(&hwbp_target));
    if (control(key, command, response, sizeof(response)) != 0) return 1;
    unsigned long handle = 0;
    if (std::sscanf(response, "ok handle=%lu", &handle) != 1 || handle == 0) {
        std::fprintf(stderr, "HWBP probe registration failed: %s\n", response);
        return 1;
    }
    std::snprintf(command, sizeof(command), "hwbp-clear %lu", handle);
    if (control(key, command, response, sizeof(response)) != 0 ||
        std::strncmp(response, "ok ", 3) != 0)
        return 1;
    std::puts("stage1-hwbp-probe-test PASS");
    return 0;
#endif
}

int command_hwbp_replace_test(const char *key)
{
#if !defined(__aarch64__)
    (void)key;
    return 1;
#else
    char command[128];
    char response[kControlBufferSize];
    g_hwbp_replacement_key = key;
    g_hwbp_replacement_error.store(0U, std::memory_order_release);
    std::snprintf(command, sizeof(command), "hwbp-set 0x%lx 0x%lx",
                  reinterpret_cast<unsigned long>(&hwbp_target),
                  reinterpret_cast<unsigned long>(&hwbp_replacement));
    if (control(key, command, response, sizeof(response)) != 0) return 1;
    unsigned long handle = 0;
    if (std::sscanf(response, "ok handle=%lu", &handle) != 1 || handle == 0) {
        std::fprintf(stderr, "HWBP replacement registration failed: %s\n", response);
        return 1;
    }
    g_hwbp_replacement_handle = handle;
    const volatile int result = hwbp_target(9, 4);
    std::snprintf(command, sizeof(command), "hwbp-snapshot %lu", handle);
    const bool snapshot_ok = control(key, command, response, sizeof(response)) == 0 &&
                             std::strstr(response, "entry=1 return=1") != nullptr &&
                             std::strstr(response, "x0=0x9 x1=0x4") != nullptr &&
                             std::strstr(response, "ret=0x11") != nullptr;
    const unsigned int replacement_error =
        g_hwbp_replacement_error.load(std::memory_order_acquire);
    std::snprintf(command, sizeof(command), "hwbp-clear %lu", handle);
    const bool cleared = control(key, command, response, sizeof(response)) == 0 &&
                         std::strncmp(response, "ok ", 3) == 0;
    g_hwbp_replacement_handle = 0;
    g_hwbp_replacement_key = nullptr;
    if (result != 17 || !snapshot_ok || replacement_error != 0U || !cleared) {
        std::fprintf(stderr,
                     "HWBP replacement failed result=%d error=%u snapshot=%d cleared=%d response=%s\n",
                     static_cast<int>(result), replacement_error,
                     snapshot_ok ? 1 : 0, cleared ? 1 : 0, response);
        return 1;
    }
    std::puts("replacement=1 gate-close=1 original-call=1 gate-open=1 return=17 cleared=1");
    std::puts("stage1-hwbp-replace-test PASS");
    return 0;
#endif
}

/* Minimal worker bisect: a worker thread arms the HWBP on the ctl's own
 * hwbp_target (no lab .so, no remote attach) and hits it. */
struct HwbpWorkerBisectContext {
    const char *key;
    std::atomic<int> arm_status{-1};
    std::atomic<int> call_status{-1};
    std::atomic<int> snapshot_status{-1};
    std::atomic<unsigned long> handle{0};
    std::atomic<bool> hit_ready{false};
    std::atomic<bool> go{false};
    std::atomic<bool> done{false};
    std::atomic<bool> clear_ok{false};
    char snapshot_text[kControlBufferSize]{};
    char arm_reply[kControlBufferSize]{};
};

void *hwbp_worker_bisect(void *opaque)
{
    auto &context = *static_cast<HwbpWorkerBisectContext *>(opaque);
    char command[128];
    char response[kControlBufferSize];
    std::snprintf(command, sizeof(command), "hwbp-set 0x%lx 0",
                  reinterpret_cast<unsigned long>(&hwbp_target));
    context.arm_status.store(
        control(context.key, command, response, sizeof(response)) != 0 ? 1 : 0,
        std::memory_order_release);
    unsigned long handle = 0;
    if (context.arm_status.load(std::memory_order_relaxed) == 0)
        std::sscanf(response, "ok handle=%lu", &handle);
    context.handle.store(handle, std::memory_order_release);
    std::snprintf(context.arm_reply, sizeof(context.arm_reply), "%s", response);
    context.hit_ready.store(true, std::memory_order_release);
    while (!context.go.load(std::memory_order_acquire)) sched_yield();
    const volatile int result = hwbp_target(5, 6);
    context.call_status.store(result == 11 ? 0 : 1, std::memory_order_release);
    /* The non-remote rule's snapshot is owner-only: snapshot from the
     * worker itself before releasing. */
    std::snprintf(command, sizeof(command), "hwbp-snapshot %lu", handle);
    const int snap = control(context.key, command, response, sizeof(response));
    std::snprintf(context.snapshot_text, sizeof(context.snapshot_text), "%s",
                  response);
    context.snapshot_status.store(snap, std::memory_order_release);
    context.done.store(true, std::memory_order_release);
    while (!context.clear_ok.load(std::memory_order_acquire)) sched_yield();
    std::snprintf(command, sizeof(command), "hwbp-clear %lu", handle);
    control(context.key, command, response, sizeof(response));
    return nullptr;
}

int command_hwbp_worker_bisect(const char *key)
{
#if !defined(__aarch64__)
    (void)key;
    return 1;
#else
    HwbpWorkerBisectContext context{};
    context.key = key;
    pthread_t worker{};
    if (pthread_create(&worker, nullptr, &hwbp_worker_bisect, &context) != 0) {
        std::fprintf(stderr, "worker create failed\n");
        return 1;
    }
    while (!context.hit_ready.load(std::memory_order_acquire)) sched_yield();
    const pid_t worker_tid = 0; /* self-arm variant; tid unused here */
    (void)worker_tid;
    context.go.store(true, std::memory_order_release);
    while (!context.done.load(std::memory_order_acquire)) sched_yield();
    std::printf("bisect arm=%d call=%d snapshot=%d: %s | arm-reply=%s\n",
                context.arm_status.load(), context.call_status.load(),
                context.snapshot_status.load(), context.snapshot_text,
                context.arm_reply);
    std::fflush(stdout);
    context.clear_ok.store(true, std::memory_order_release);
    pthread_join(worker, nullptr);
    return 0;
#endif
}

/* HWBP Lab acceptance: entry args + the return value on the MAIN thread AND
 * a WORKER thread (per-TID attach), the byte integrity of the target, the
 * ptrace debug-register view (the fake empty ledger), and the slot count. */
struct HwbpLabWorkerContext {
    const char *key;
    pid_t tid = 0;
    std::atomic<bool> attach_ready{false};
    std::atomic<bool> go{false};
    std::atomic<unsigned int> call_failed{0};
    std::atomic<bool> done{false};
    std::atomic<bool> snapshot_ok{false};
    long (*lab_add)(long, long) = nullptr;
};

void *hwbp_lab_worker(void *opaque)
{
    auto &context = *static_cast<HwbpLabWorkerContext *>(opaque);
    context.tid = static_cast<pid_t>(gettid());
    context.attach_ready.store(true, std::memory_order_release);
    while (!context.go.load(std::memory_order_acquire)) sched_yield();
    if (context.lab_add(1, 2) != 3)
        context.call_failed.store(1U, std::memory_order_release);
    context.done.store(true, std::memory_order_release);
    /* The TID-bound rule is torn down by do_exit when this thread returns;
     * stay alive until the parent has captured the snapshot. */
    while (!context.snapshot_ok.load(std::memory_order_acquire)) sched_yield();
    return nullptr;
}

/* Remote-attach variant: the parent arms the worker's TID, the worker hits
 * the target, the parent snapshots (remote rules allow the cross-thread
 * snapshot). */
struct HwbpRemoteBisectContext {
    const char *key;
    pid_t tid = 0;
    std::atomic<bool> tid_ready{false};
    std::atomic<bool> go{false};
    std::atomic<int> call_status{-1};
    std::atomic<bool> done{false};
    std::atomic<bool> clear_ok{false};
};

void *hwbp_remote_bisect_worker(void *opaque)
{
    auto &context = *static_cast<HwbpRemoteBisectContext *>(opaque);
    context.tid = static_cast<pid_t>(gettid());
    context.tid_ready.store(true, std::memory_order_release);
    while (!context.go.load(std::memory_order_acquire)) sched_yield();
    const volatile int result = hwbp_target(7, 8);
    context.call_status.store(result == 15 ? 0 : 1, std::memory_order_release);
    context.done.store(true, std::memory_order_release);
    while (!context.clear_ok.load(std::memory_order_acquire)) sched_yield();
    return nullptr;
}

int command_hwbp_remote_bisect(const char *key)
{
#if !defined(__aarch64__)
    (void)key;
    return 1;
#else
    HwbpRemoteBisectContext context{};
    context.key = key;
    pthread_t worker{};
    if (pthread_create(&worker, nullptr, &hwbp_remote_bisect_worker, &context) != 0) {
        std::fprintf(stderr, "worker create failed\n");
        return 1;
    }
    while (!context.tid_ready.load(std::memory_order_acquire)) sched_yield();
    char command[128];
    char response[kControlBufferSize];
    std::snprintf(command, sizeof(command), "hwbp-attach %ld 0x%lx",
                  static_cast<long>(context.tid),
                  reinterpret_cast<unsigned long>(&hwbp_target));
    if (control(key, command, response, sizeof(response)) != 0) {
        std::fprintf(stderr, "remote attach failed\n");
        return 1;
    }
    unsigned long handle = 0;
    std::sscanf(response, "ok handle=%lu", &handle);
    std::printf("remote-bisect attach: %s\n", response);
    std::fflush(stdout);
    context.go.store(true, std::memory_order_release);
    while (!context.done.load(std::memory_order_acquire)) sched_yield();
    std::snprintf(command, sizeof(command), "hwbp-snapshot %lu", handle);
    control(key, command, response, sizeof(response));
    std::printf("remote-bisect call=%d snapshot: %s\n",
                context.call_status.load(), response);
    std::fflush(stdout);
    std::snprintf(command, sizeof(command), "hwbp-clear %lu", handle);
    control(key, command, response, sizeof(response));
    context.clear_ok.store(true, std::memory_order_release);
    pthread_join(worker, nullptr);
    return 0;
#endif
}

int command_hwbp_lab_test(const char *key)
{
#if !defined(__aarch64__)
    (void)key;
    return 1;
#else
    char command[160];
    char response[kControlBufferSize];
    signal(SIGSEGV, SIG_DFL);
    signal(SIGTRAP, SIG_DFL);

    void *lab_lib = dlopen("/data/local/tmp/rtgum-stage1-pixel8/librtgum-lab.so",
                           RTLD_NOW | RTLD_LOCAL);
    if (!lab_lib) {
        std::fprintf(stderr, "hwbp-lab dlopen failed: %s\n", dlerror());
        return 1;
    }
    auto *lab_add = reinterpret_cast<long (*)(long, long)>(dlsym(lab_lib, "lab_add"));
    if (!lab_add) {
        std::fprintf(stderr, "hwbp-lab dlsym failed\n");
        return 1;
    }
    (void)lab_add(1, 2); /* fault the text page in */

    unsigned char prologue[8]{};
    std::memcpy(prologue, reinterpret_cast<const void *>(lab_add), sizeof(prologue));

    /* 1. Main thread: ENTRY/RETURN state machine on lab_add(1,2)==3. */
    std::snprintf(command, sizeof(command), "hwbp-set 0x%lx 0",
                  reinterpret_cast<unsigned long>(lab_add));
    if (control(key, command, response, sizeof(response)) != 0) return 1;
    unsigned long main_handle = 0;
    if (std::sscanf(response, "ok handle=%lu", &main_handle) != 1 || main_handle == 0) {
        std::fprintf(stderr, "hwbp-lab main registration failed: %s\n", response);
        return 1;
    }
    if (lab_add(1, 2) != 3) {
        std::fprintf(stderr, "hwbp-lab main call result changed\n");
        return 1;
    }
    std::snprintf(command, sizeof(command), "hwbp-snapshot %lu", main_handle);
    if (control(key, command, response, sizeof(response)) != 0 ||
        std::strstr(response, "entry=1 return=1") == nullptr ||
        std::strstr(response, "x0=0x1 x1=0x2") == nullptr ||
        std::strstr(response, "ret=0x3") == nullptr) {
        std::fprintf(stderr, "hwbp-lab main snapshot failed: %s\n", response);
        return 1;
    }
    std::puts("hwbp-lab main entry=1 return=1 x0=1 x1=2 ret=3");
    std::fflush(stdout);

    /* 2. Worker thread: the per-TID attach for the same address. */
    HwbpLabWorkerContext worker_context{};
    worker_context.key = key;
    worker_context.lab_add = lab_add;
    pthread_t worker{};
    const int create_result =
        pthread_create(&worker, nullptr, &hwbp_lab_worker, &worker_context);
    if (create_result != 0) {
        std::fprintf(stderr, "hwbp-lab worker create failed: %d (%s)\n",
                     create_result, std::strerror(create_result));
        return 1;
    }
    while (!worker_context.attach_ready.load(std::memory_order_acquire)) sched_yield();
    std::snprintf(command, sizeof(command), "hwbp-attach %ld 0x%lx",
                  static_cast<long>(worker_context.tid),
                  reinterpret_cast<unsigned long>(lab_add));
    if (control(key, command, response, sizeof(response)) != 0) {
        std::fprintf(stderr, "hwbp-lab worker attach failed: %s\n", response);
        return 1;
    }
    std::puts("hwbp-lab worker-attached");
    std::fflush(stdout);
    unsigned long worker_handle = 0;
    if (std::sscanf(response, "ok handle=%lu", &worker_handle) != 1 || worker_handle == 0)
        return 1;
    worker_context.go.store(true, std::memory_order_release);
    while (!worker_context.done.load(std::memory_order_acquire)) sched_yield();
    std::puts("hwbp-lab worker-joined");
    std::fflush(stdout);
    std::snprintf(command, sizeof(command), "hwbp-snapshot %lu", worker_handle);
    const bool worker_snapshot_ok =
        control(key, command, response, sizeof(response)) == 0 &&
        std::strstr(response, "entry=1 return=1") != nullptr &&
        std::strstr(response, "ret=0x3") != nullptr;
    worker_context.snapshot_ok.store(true, std::memory_order_release);
    pthread_join(worker, nullptr);
    if (worker_context.call_failed.load(std::memory_order_acquire) != 0U) {
        std::fprintf(stderr, "hwbp-lab worker call failed\n");
        return 1;
    }
    if (!worker_snapshot_ok) {
        std::fprintf(stderr, "hwbp-lab worker snapshot failed: %s\n", response);
        return 1;
    }
    std::puts("hwbp-lab worker entry=1 return=1 ret=3");
    std::fflush(stdout);

    /* 3. Byte integrity after the armed/unarmed cycles. */
    unsigned char after[8]{};
    std::memcpy(after, reinterpret_cast<const void *>(lab_add), sizeof(after));
    if (std::memcmp(prologue, after, sizeof(after)) != 0) {
        std::fprintf(stderr, "hwbp-lab target bytes changed\n");
        return 1;
    }
    std::puts("hwbp-lab bytes-unchanged=1");
    std::fflush(stdout);

    /* 4. The fake ledger: a traced child arms the HWBP; the parent reads
     * the child's NT_ARM_HW_BREAK regset BEFORE and AFTER the arming. The
     * perf-bypass bookkeeping must be IDENTICAL in both reads ("same as
     * unarmed"), so the armed breakpoint leaves no trace in the kernel's
     * debug-register ledger. */
    {
        struct UserHwBreakState {
            unsigned int dbg_info;
            unsigned int pad;
            unsigned int ctrl[16];
            unsigned long address[16];
        };
        const pid_t child = fork();
        if (child == 0) {
            if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) != 0) _exit(2);
            raise(SIGSTOP); /* the baseline read */
            char child_response[kControlBufferSize];
            std::snprintf(command, sizeof(command), "hwbp-set 0x%lx 0",
                          reinterpret_cast<unsigned long>(lab_add));
            if (control(key, command, child_response, sizeof(child_response)) != 0)
                _exit(3);
            (void)lab_add(1, 2);
            raise(SIGSTOP); /* the armed read */
            _exit(0);
        }
        if (child < 0) return 1;
        int status = 0;
        if (waitpid(child, &status, 0) != child || !WIFSTOPPED(status)) return 1;
        auto read_state = [&](UserHwBreakState &state) {
            for (unsigned int attempt = 0; attempt < 400U; ++attempt) {
                struct iovec iov{&state, sizeof(state)};
                const long read_result =
                    ptrace(PTRACE_GETREGSET, child,
                           reinterpret_cast<void *>(static_cast<long>(0x402)), &iov);
                if (read_result == 0) return true;
                usleep(10000);
            }
            return false;
        };
        UserHwBreakState baseline{};
        if (!read_state(baseline)) {
            kill(child, SIGKILL);
            waitpid(child, nullptr, 0);
            std::fprintf(stderr, "hwbp-lab baseline ledger read failed\n");
            return 1;
        }
        if (ptrace(PTRACE_CONT, child, nullptr, nullptr) != 0) return 1;
        if (waitpid(child, &status, 0) != child || !WIFSTOPPED(status)) return 1;
        UserHwBreakState armed{};
        if (!read_state(armed)) return 1;
        ptrace(PTRACE_DETACH, child, nullptr, nullptr);
        kill(child, SIGKILL);
        waitpid(child, nullptr, 0);
        if (std::memcmp(&baseline, &armed, sizeof(baseline)) != 0) {
            std::fprintf(stderr,
                         "hwbp-lab ledger differs when armed: info 0x%x->0x%x\n",
                         baseline.dbg_info, armed.dbg_info);
            return 1;
        }
    }
    std::puts("hwbp-lab fake-ledger-empty=1");
    std::fflush(stdout);

    std::snprintf(command, sizeof(command), "hwbp-clear %lu", main_handle);
    control(key, command, response, sizeof(response));
    std::snprintf(command, sizeof(command), "hwbp-clear %lu", worker_handle);
    control(key, command, response, sizeof(response));
    std::puts("main-hit=1 worker-hit=1 bytes-unchanged=1 fake-ledger=1 stage1-hwbp-lab PASS");
    return 0;
#endif
}

struct BpfProbeResult final {
    const char *stage = "none";
    int error = 0;
    std::uint64_t observed = 0;
};

static bpf_insn make_bpf_insn(std::uint8_t code, std::uint8_t destination,
                              std::uint8_t source, std::int16_t offset,
                              std::int32_t immediate)
{
    bpf_insn instruction{};
    instruction.code = code;
    instruction.dst_reg = destination;
    instruction.src_reg = source;
    instruction.off = offset;
    instruction.imm = immediate;
    return instruction;
}

static int bpf_command(enum bpf_cmd command, union bpf_attr &attributes)
{
    return static_cast<int>(syscall(__NR_bpf, command, &attributes,
                                    sizeof(attributes)));
}

/* Optional comparison only. The raw tracepoint observes ptrace and
 * perf_event_open entries but never changes their arguments or return values;
 * the KPM ledger remains the sole enforcement/virtualization path. */
static BpfProbeResult run_antidbg_ebpf_observer()
{
    BpfProbeResult result{};
    union bpf_attr map_attributes{};
    map_attributes.map_type = BPF_MAP_TYPE_ARRAY;
    map_attributes.key_size = sizeof(std::uint32_t);
    map_attributes.value_size = sizeof(std::uint64_t);
    map_attributes.max_entries = 1U;
    const int map_fd = bpf_command(BPF_MAP_CREATE, map_attributes);
    if (map_fd < 0) {
        result.stage = "map-create";
        result.error = errno;
        return result;
    }

    bpf_insn instructions[] = {
        /* raw_syscalls:sys_enter args[1] is the syscall number. */
        make_bpf_insn(BPF_LDX | BPF_DW | BPF_MEM, BPF_REG_2, BPF_REG_1,
                      8, 0),
        make_bpf_insn(BPF_JMP | BPF_JEQ | BPF_K, BPF_REG_2, 0,
                      1, __NR_ptrace),
        make_bpf_insn(BPF_JMP | BPF_JNE | BPF_K, BPF_REG_2, 0,
                      10, __NR_perf_event_open),
        make_bpf_insn(BPF_ST | BPF_W | BPF_MEM, BPF_REG_10, 0,
                      -4, 0),
        make_bpf_insn(BPF_LD | BPF_DW | BPF_IMM, BPF_REG_1,
                      BPF_PSEUDO_MAP_FD, 0, map_fd),
        make_bpf_insn(0, 0, 0, 0, 0),
        make_bpf_insn(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_2,
                      BPF_REG_10, 0, 0),
        make_bpf_insn(BPF_ALU64 | BPF_ADD | BPF_K, BPF_REG_2,
                      0, 0, -4),
        make_bpf_insn(BPF_JMP | BPF_CALL, 0, 0, 0,
                      BPF_FUNC_map_lookup_elem),
        make_bpf_insn(BPF_JMP | BPF_JEQ | BPF_K, BPF_REG_0, 0,
                      3, 0),
        make_bpf_insn(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_1,
                      0, 0, 1),
        make_bpf_insn(BPF_STX | BPF_DW | BPF_XADD, BPF_REG_0,
                      BPF_REG_1, 0, 0),
        make_bpf_insn(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_0,
                      0, 0, 0),
        make_bpf_insn(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
    };
    static const char license[] = "GPL";
    char verifier_log[4096]{};
    union bpf_attr program_attributes{};
    program_attributes.prog_type = BPF_PROG_TYPE_RAW_TRACEPOINT;
    program_attributes.insn_cnt = static_cast<std::uint32_t>(
        sizeof(instructions) / sizeof(instructions[0]));
    program_attributes.insns = reinterpret_cast<std::uint64_t>(instructions);
    program_attributes.license = reinterpret_cast<std::uint64_t>(license);
    program_attributes.log_buf = reinterpret_cast<std::uint64_t>(verifier_log);
    program_attributes.log_size = sizeof(verifier_log);
    program_attributes.log_level = 1U;
    const int program_fd = bpf_command(BPF_PROG_LOAD, program_attributes);
    if (program_fd < 0) {
        result.stage = "prog-load";
        result.error = errno;
        close(map_fd);
        return result;
    }

    static const char tracepoint_name[] = "sys_enter";
    union bpf_attr attach_attributes{};
    attach_attributes.raw_tracepoint.name =
        reinterpret_cast<std::uint64_t>(tracepoint_name);
    attach_attributes.raw_tracepoint.prog_fd = program_fd;
    const int link_fd = bpf_command(
        BPF_RAW_TRACEPOINT_OPEN, attach_attributes);
    if (link_fd < 0) {
        result.stage = "raw-tracepoint-open";
        result.error = errno;
        close(program_fd);
        close(map_fd);
        return result;
    }

    (void)syscall(__NR_ptrace, PTRACE_PEEKDATA, -1L, 0UL, 0UL);
    (void)syscall(__NR_perf_event_open, nullptr, 0, -1, -1, 0UL);
    std::uint32_t key = 0U;
    std::uint64_t value = 0U;
    union bpf_attr lookup_attributes{};
    lookup_attributes.map_fd = map_fd;
    lookup_attributes.key = reinterpret_cast<std::uint64_t>(&key);
    lookup_attributes.value = reinterpret_cast<std::uint64_t>(&value);
    if (bpf_command(BPF_MAP_LOOKUP_ELEM, lookup_attributes) != 0) {
        result.stage = "map-lookup";
        result.error = errno;
    } else if (value < 2U) {
        result.stage = "observation";
        result.error = EIO;
        result.observed = value;
    } else {
        result.stage = "observed";
        result.observed = value;
    }
    close(link_fd);
    close(program_fd);
    close(map_fd);
    return result;
}

int command_antidbg_ebpf_probe(const char *key)
{
#if !defined(__aarch64__)
    (void)key;
    std::puts("ebpf-compare role=observe-only status=unsupported-arch");
    return 0;
#else
    rtgum_su_profile profile{};
    profile.uid = static_cast<std::uint32_t>(getuid());
    profile.to_uid = 0;
    const long elevated = rtgum_sc_su(key, &profile);
    if (elevated != 0 || getuid() != 0) {
        const int error = elevated < 0 ? static_cast<int>(-elevated) : EPERM;
        std::printf("ebpf-compare role=observe-only primary=kernel-ledger "
                    "status=unavailable stage=elevate errno=%d\n", error);
        return 0;
    }
    const BpfProbeResult result = run_antidbg_ebpf_observer();
    if (std::strcmp(result.stage, "observed") == 0) {
        std::printf("ebpf-compare role=observe-only primary=kernel-ledger "
                    "status=observed ptrace-perf-events=%llu\n",
                    static_cast<unsigned long long>(result.observed));
    } else {
        std::printf("ebpf-compare role=observe-only primary=kernel-ledger "
                    "status=unavailable stage=%s errno=%d observed=%llu\n",
                    result.stage, result.error,
                    static_cast<unsigned long long>(result.observed));
    }
    return 0;
#endif
}

/*
 * Anti-debug acceptance uses an owned, traced child whose comm is authorized
 * through the same daemon-config field emitted by the Manager. The separate
 * APK half of the smoke keeps exercising the built-in Lab grant. The activity
 * itself is never attached, so its TracerPid remains zero. The child checks:
 *
 *   - GETREGSET sees an empty ledger while a real KPM HWBP is armed;
 *   - six SETREGSET entries round-trip byte-for-byte and the seventh is
 *     rejected with ENOSPC without programming a physical comparator;
 *   - six perf breakpoint opens return ordinary FDs backed by SW_DUMMY and
 *     the seventh is rejected with ENOSPC;
 *   - touching the virtual watchpoint and executing the virtual breakpoint
 *     produce real SIGTRAP/TRAP_HWBKPT stops with the expected si_addr;
 *   - the independently armed KPM breakpoint still records entry and return.
 */
#if defined(__GNUC__)
__attribute__((noinline))
#endif
long antidbg_fake_target(long value)
{
    asm volatile("nop\n\tnop\n\tnop" ::: "memory");
    return value + 1;
}

#if defined(__GNUC__)
__attribute__((noinline))
#endif
long antidbg_modified_target(long value)
{
    asm volatile("nop\n\tnop\n\tnop" ::: "memory");
    return value + 2;
}

#if defined(__GNUC__)
__attribute__((noinline))
#endif
long antidbg_real_target(long left, long right)
{
    asm volatile("nop\n\tnop\n\tnop" ::: "memory");
    return left + right;
}

alignas(8) volatile std::uint64_t antidbg_fake_watch_word =
    UINT64_C(0x525447554d574154);

volatile sig_atomic_t antidbg_inherit_signal_hits = 0;
volatile sig_atomic_t antidbg_inherit_signal_code = 0;
volatile sig_atomic_t antidbg_inherit_signal_type = 0;
volatile sig_atomic_t antidbg_inherit_disable_result = -1;
alignas(8) volatile std::uint64_t antidbg_inherit_signal_address = 0;
alignas(8) volatile std::uint64_t antidbg_inherit_signal_data = 0;

void antidbg_inherit_signal_handler(int signal, siginfo_t *info, void *)
{
    if (signal != SIGTRAP || !info) return;
    antidbg_inherit_signal_code = info->si_code;
    antidbg_inherit_signal_type =
        static_cast<sig_atomic_t>(info->si_perf_type);
    antidbg_inherit_signal_address = reinterpret_cast<std::uint64_t>(
        info->si_addr);
    antidbg_inherit_signal_data = static_cast<std::uint64_t>(
        info->si_perf_data);
    /* PERF_ATTR_FLAG_SIGTRAP is synchronous and an execute breakpoint stops
     * before the watched instruction. Native perf users must disable or move
     * the event before returning, otherwise the same PC is expected to trap
     * again. Use the syscall directly so this handler also verifies that the
     * virtual task-wide disable path is safe in signal context. */
    if (antidbg_inherit_signal_hits == 0)
        antidbg_inherit_disable_result = static_cast<sig_atomic_t>(
            syscall(__NR_prctl, PR_TASK_PERF_EVENTS_DISABLE,
                    0UL, 0UL, 0UL, 0UL));
    ++antidbg_inherit_signal_hits;
}

int command_antidbg_lab_test(const char *key)
{
#if !defined(__aarch64__)
    (void)key;
    std::puts("antidbg skipped=1 (not arm64)");
    return 0;
#else
    constexpr unsigned long kNtArmHwBreak = 0x402UL;
    constexpr unsigned long kNtArmHwWatch = 0x403UL;
    struct UserHwDebugState {
        unsigned int dbg_info;
        unsigned int pad;
        struct Register {
            unsigned long address;
            unsigned int control;
            unsigned int pad;
        } registers[16];
    };
    static_assert(sizeof(UserHwDebugState) == 264UL);
    constexpr unsigned int kMaximumDebugSlots = 16U;

    char response[kControlBufferSize]{};
    char command[160]{};
    if (control(key, "hook-antidbg", response, sizeof(response)) != 0 ||
        std::strstr(response, "ok antidbg=1") == nullptr) {
        std::fprintf(stderr, "anti-debug hook install failed: %s\n", response);
        return 1;
    }
    constexpr const char *kManagerProbePackage = "dev.rtgum.probe";
    constexpr const char *kManagerProbeConfig =
        "daemon-config 1 dev.rtgum.probe "
        "/data/local/tmp/rtgum-stage1-pixel8/rtgum-stage1.kpm - - - - antidbg";
    if (control(key, kManagerProbeConfig, response, sizeof(response)) != 0 ||
        std::strstr(response, "anti-debug=1") == nullptr) {
        std::fprintf(stderr, "anti-debug Manager policy failed: %s\n", response);
        return 1;
    }
    char original_comm[16]{};
    if (prctl(PR_GET_NAME, original_comm, 0, 0, 0) != 0 ||
        prctl(PR_SET_NAME, kManagerProbePackage, 0, 0, 0) != 0) {
        std::perror("antidbg Manager caller name");
        (void)control(key, "daemon-config-clear 1", response, sizeof(response));
        return 1;
    }
    std::snprintf(command, sizeof(command), "antidbg-policy %d", getpid());
    if (control(key, command, response, sizeof(response)) != 0 ||
        std::strstr(response, "policy=denied") == nullptr) {
        std::fprintf(stderr, "comm-only anti-debug policy was not denied: %s\n",
                     response);
        (void)prctl(PR_SET_NAME, original_comm, 0, 0, 0);
        (void)control(key, "daemon-config-clear 1", response, sizeof(response));
        return 1;
    }
    /* A configured package name and spoofed comm are deliberately
     * insufficient. Exercise the real syscall while the explicit grant is
     * absent and prove the KPM neither allocates a fake event nor a ledger.
     * The underlying kernel may allow or deny the disabled native probe; both
     * are valid pass-through outcomes. */
    struct perf_event_attr denied_attr {};
    denied_attr.type = PERF_TYPE_BREAKPOINT;
    denied_attr.size = sizeof(denied_attr);
    denied_attr.bp_type = HW_BREAKPOINT_X;
    denied_attr.bp_addr =
        reinterpret_cast<unsigned long>(&antidbg_fake_target);
    denied_attr.bp_len = HW_BREAKPOINT_LEN_4;
    denied_attr.disabled = 1;
    denied_attr.exclude_kernel = 1;
    denied_attr.exclude_hv = 1;
    const long denied_fd = syscall(__NR_perf_event_open, &denied_attr,
                                   0, -1, -1, 0UL);
    if (denied_fd >= 0) close(static_cast<int>(denied_fd));
    if (control(key, "antidbg-status", response, sizeof(response)) != 0 ||
        std::strstr(response, "perf_open=0") == nullptr ||
        std::strstr(response, "perf=0") == nullptr ||
        std::strstr(response, "ledgers=0") == nullptr) {
        std::fprintf(stderr,
                     "unauthorized anti-debug syscall was virtualized: %s\n",
                     response);
        (void)prctl(PR_SET_NAME, original_comm, 0, 0, 0);
        (void)control(key, "daemon-config-clear 1", response, sizeof(response));
        return 1;
    }
    std::snprintf(command, sizeof(command), "antidbg-authorize %d", getpid());
    if (control(key, command, response, sizeof(response)) != 0 ||
        std::strstr(response, "policy=manager") == nullptr ||
        std::strstr(response, "grants=1") == nullptr) {
        std::fprintf(stderr, "explicit Manager anti-debug grant failed: %s\n",
                     response);
        (void)prctl(PR_SET_NAME, original_comm, 0, 0, 0);
        (void)control(key, "daemon-config-clear 1", response, sizeof(response));
        return 1;
    }
    std::snprintf(command, sizeof(command), "antidbg-policy %d", getpid());
    if (control(key, command, response, sizeof(response)) != 0 ||
        std::strstr(response, "policy=manager") == nullptr) {
        std::fprintf(stderr, "explicit Manager policy lookup failed: %s\n",
                     response);
        (void)prctl(PR_SET_NAME, original_comm, 0, 0, 0);
        (void)control(key, "daemon-config-clear 1", response, sizeof(response));
        return 1;
    }

    const pid_t child = fork();
    if (child < 0) {
        std::perror("antidbg fork");
        (void)prctl(PR_SET_NAME, original_comm, 0, 0, 0);
        (void)control(key, "daemon-config-clear 1", response, sizeof(response));
        return 1;
    }
    if (child == 0) {
        /* Deliberately do not match the configured package: this proves the
         * caller TGID authorization covers renamed helper children/threads. */
        if (prctl(PR_SET_NAME, "rtgum-worker", 0, 0, 0) != 0) _exit(20);
        if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) != 0) _exit(21);
        raise(SIGSTOP);
        antidbg_fake_watch_word ^= UINT64_C(0x0101010101010101);
        const volatile long fake_result = antidbg_fake_target(8);
        const volatile long real_result = antidbg_real_target(11, 7);
        if (fake_result != 9 || real_result != 18) _exit(22);
        /* The parent first validates the ptrace ledger, then installs active
         * perf BRP/WRP events. Three further rounds cover enabled, disabled,
         * and reset+re-enabled event state without changing the child code. */
        raise(SIGSTOP);
        for (unsigned int round = 0; round < 3U; ++round) {
            antidbg_fake_watch_word ^=
                UINT64_C(0x1010101010101010) + round;
            const volatile long perf_fake = antidbg_fake_target(8);
            const volatile long perf_real = antidbg_real_target(11, 7);
            if (perf_fake != 9 || perf_real != 18) _exit(23);
            raise(SIGSTOP);
        }
        _exit(0);
    }

    unsigned long hwbp_handle = 0UL;
    int perf_fds[kMaximumDebugSlots];
    int watch_perf_fds[kMaximumDebugSlots];
    for (int &fd : perf_fds) fd = -1;
    for (int &fd : watch_perf_fds) fd = -1;
    int dup_fd = -1;
    int fcntl_fd = -1;
    int dup3_fd = -1;
    bool child_reaped = false;
    auto cleanup = [&]() {
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
        if (hwbp_handle != 0UL) {
            std::snprintf(command, sizeof(command), "hwbp-clear %lu", hwbp_handle);
            (void)control(key, command, response, sizeof(response));
            hwbp_handle = 0UL;
        }
        if (!child_reaped) {
            int observed_status = 0;
            const pid_t observed = waitpid(child, &observed_status, WNOHANG);
            if (observed == 0) {
                (void)ptrace(PTRACE_DETACH, child, nullptr, nullptr);
                (void)kill(child, SIGKILL);
                (void)waitpid(child, nullptr, 0);
            }
            child_reaped = observed == child || observed == 0;
        }
        (void)prctl(PR_SET_NAME, original_comm, 0, 0, 0);
        (void)control(key, "daemon-config-clear 1", response, sizeof(response));
    };

    int status = 0;
    if (waitpid(child, &status, 0) != child || !WIFSTOPPED(status) ||
        WSTOPSIG(status) != SIGSTOP) {
        std::fprintf(stderr, "antidbg initial stop failed status=0x%x\n", status);
        cleanup();
        return 1;
    }

    std::snprintf(command, sizeof(command), "hwbp-attach %ld 0x%lx",
                  static_cast<long>(child),
                  reinterpret_cast<unsigned long>(&antidbg_real_target));
    if (control(key, command, response, sizeof(response)) != 0 ||
        std::sscanf(response, "ok handle=%lu", &hwbp_handle) != 1 ||
        hwbp_handle == 0UL) {
        std::fprintf(stderr, "antidbg real HWBP attach failed: %s\n", response);
        cleanup();
        return 1;
    }

    auto get_state = [&](unsigned long note, UserHwDebugState &state) {
        std::memset(&state, 0xa5, sizeof(state));
        struct iovec vector{&state, sizeof(state)};
        errno = 0;
        const long result = ptrace(
            PTRACE_GETREGSET, child,
            reinterpret_cast<void *>(note), &vector);
        return result == 0 && vector.iov_len == sizeof(state);
    };
    auto set_state = [&](unsigned long note, UserHwDebugState &state,
                         unsigned int slots) {
        struct iovec vector{
            &state, 8UL + static_cast<unsigned long>(slots) * 16UL};
        errno = 0;
        return ptrace(PTRACE_SETREGSET, child,
                      reinterpret_cast<void *>(note), &vector);
    };
    auto state_empty = [](const UserHwDebugState &state) {
        for (const auto &entry : state.registers)
            if (entry.address != 0UL || entry.control != 0U) return false;
        return true;
    };

    UserHwDebugState baseline{};
    if (!get_state(kNtArmHwBreak, baseline)) {
        std::fprintf(stderr, "antidbg GETREGSET baseline failed errno=%d\n", errno);
        cleanup();
        return 1;
    }
    const unsigned int slots = baseline.dbg_info & 0xffU;
    if (slots == 0U || slots > kMaximumDebugSlots) {
        std::fprintf(stderr, "antidbg invalid BRP slots=%u info=0x%x\n",
                     slots, baseline.dbg_info);
        cleanup();
        return 1;
    }
    for (const auto &entry : baseline.registers) {
        if (entry.address != 0UL || entry.control != 0U) {
            std::fprintf(stderr, "antidbg baseline ledger was not empty\n");
            cleanup();
            return 1;
        }
    }

    constexpr unsigned int kExecuteEl0 = 1U | (2U << 1U) | (0xfU << 5U);
    const unsigned long fake_address =
        reinterpret_cast<unsigned long>(&antidbg_fake_target);
    UserHwDebugState roundtrip{};

    /* Native arm64 regset handling aligns the value register and shifts the
     * supplied BAS by the low address bits, truncating it to eight bits. */
    UserHwDebugState shifted_break = baseline;
    shifted_break.registers[0].address = fake_address + 1UL;
    shifted_break.registers[0].control = kExecuteEl0;
    constexpr unsigned int kShiftedExecuteEl0 =
        1U | (2U << 1U) | (0x1eU << 5U);
    if (set_state(kNtArmHwBreak, shifted_break, 1U) != 0 ||
        !get_state(kNtArmHwBreak, roundtrip) ||
        roundtrip.registers[0].address != (fake_address & ~3UL) ||
        roundtrip.registers[0].control != kShiftedExecuteEl0) {
        std::fprintf(stderr,
                     "antidbg shifted execute regset mismatch addr=0x%lx ctrl=0x%x errno=%d\n",
                     roundtrip.registers[0].address,
                     roundtrip.registers[0].control, errno);
        cleanup();
        return 1;
    }
    UserHwDebugState shifted_break_clear{};
    if (set_state(kNtArmHwBreak, shifted_break_clear, slots) != 0) {
        std::fprintf(stderr,
                     "antidbg shifted execute clear failed errno=%d\n", errno);
        cleanup();
        return 1;
    }

    /* Kernel regset edge semantics: resource/pad/reserved bits are ignored,
     * privilege is derived from the user address, and a torn address record is
     * rejected. These details are common detector fingerprints. */
    UserHwDebugState header_only{};
    header_only.dbg_info = 0xffffffffU;
    header_only.pad = 0xffffffffU;
    struct iovec header_vector{&header_only, 8U};
    errno = 0;
    if (ptrace(PTRACE_SETREGSET, child,
               reinterpret_cast<void *>(kNtArmHwBreak),
               &header_vector) != 0 || !get_state(kNtArmHwBreak, roundtrip) ||
        !state_empty(roundtrip)) {
        std::fprintf(stderr,
                     "antidbg ignored-header semantics failed errno=%d\n", errno);
        cleanup();
        return 1;
    }
    UserHwDebugState noisy = baseline;
    noisy.dbg_info = 0xffffffffU;
    noisy.pad = 0xffffffffU;
    noisy.registers[0].address = fake_address;
    noisy.registers[0].control =
        1U | (3U << 1U) | (0xfU << 5U) | 0xfff00000U;
    noisy.registers[0].pad = 0xffffffffU;
    if (set_state(kNtArmHwBreak, noisy, 1U) != 0 ||
        !get_state(kNtArmHwBreak, roundtrip) ||
        roundtrip.dbg_info != baseline.dbg_info || roundtrip.pad != 0U ||
        roundtrip.registers[0].address != fake_address ||
        roundtrip.registers[0].control != kExecuteEl0 ||
        roundtrip.registers[0].pad != 0U) {
        std::fprintf(stderr,
                     "antidbg canonical regset roundtrip failed errno=%d\n",
                     errno);
        cleanup();
        return 1;
    }
    UserHwDebugState edge_clear{};
    if (set_state(kNtArmHwBreak, edge_clear, slots) != 0 ||
        !get_state(kNtArmHwBreak, roundtrip) || !state_empty(roundtrip)) {
        std::fprintf(stderr, "antidbg edge ledger clear failed errno=%d\n", errno);
        cleanup();
        return 1;
    }
    UserHwDebugState invalid_control = baseline;
    invalid_control.registers[0].address = fake_address;
    invalid_control.registers[0].control =
        1U | (2U << 1U) | (2U << 3U) | (0xfU << 5U);
    errno = 0;
    if (set_state(kNtArmHwBreak, invalid_control, 1U) != -1 ||
        errno != EINVAL) {
        std::fprintf(stderr,
                     "antidbg invalid control was not rejected errno=%d\n",
                     errno);
        cleanup();
        return 1;
    }
    UserHwDebugState torn_address = baseline;
    struct iovec torn_vector{&torn_address, 12U};
    errno = 0;
    if (ptrace(PTRACE_SETREGSET, child,
               reinterpret_cast<void *>(kNtArmHwBreak),
               &torn_vector) != -1 || errno != EINVAL) {
        std::fprintf(stderr,
                     "antidbg torn regset was not rejected errno=%d\n", errno);
        cleanup();
        return 1;
    }

    UserHwDebugState programmed = baseline;
    for (unsigned int index = 0; index < slots; ++index) {
        programmed.registers[index].address = fake_address + index * 4UL;
        programmed.registers[index].control = kExecuteEl0;
    }
    if (set_state(kNtArmHwBreak, programmed, slots) != 0) {
        std::fprintf(stderr, "antidbg SETREGSET six failed errno=%d\n", errno);
        cleanup();
        return 1;
    }
    if (!get_state(kNtArmHwBreak, roundtrip) ||
        std::memcmp(&programmed, &roundtrip, sizeof(programmed)) != 0) {
        std::fprintf(stderr, "antidbg ptrace read/write consistency failed errno=%d\n",
                     errno);
        cleanup();
        return 1;
    }

    if (slots >= kMaximumDebugSlots) {
        std::fprintf(stderr, "antidbg cannot encode BRP overflow slots=%u\n", slots);
        cleanup();
        return 1;
    }
    UserHwDebugState overflow = programmed;
    overflow.registers[slots].address = fake_address + slots * 4UL;
    overflow.registers[slots].control = kExecuteEl0;
    errno = 0;
    if (set_state(kNtArmHwBreak, overflow, slots + 1U) != -1 ||
        errno != ENOSPC) {
        std::fprintf(stderr,
                     "antidbg ptrace seventh mismatch result/errno=%d expected=%d\n",
                     errno, ENOSPC);
        cleanup();
        return 1;
    }

    UserHwDebugState watch_baseline{};
    if (!get_state(kNtArmHwWatch, watch_baseline)) {
        std::fprintf(stderr, "antidbg watch GETREGSET baseline failed errno=%d\n",
                     errno);
        cleanup();
        return 1;
    }
    const unsigned int watch_slots = watch_baseline.dbg_info & 0xffU;
    if (watch_slots == 0U || watch_slots >= kMaximumDebugSlots) {
        std::fprintf(stderr, "antidbg invalid WRP slots=%u info=0x%x\n",
                     watch_slots, watch_baseline.dbg_info);
        cleanup();
        return 1;
    }
    for (const auto &entry : watch_baseline.registers) {
        if (entry.address != 0UL || entry.control != 0U) {
            std::fprintf(stderr, "antidbg watch baseline ledger was not empty\n");
            cleanup();
            return 1;
        }
    }
    constexpr unsigned int kWatchWriteEl0 =
        1U | (2U << 1U) | (2U << 3U) | (0xffU << 5U);
    const unsigned long watch_address = reinterpret_cast<unsigned long>(
        const_cast<std::uint64_t *>(&antidbg_fake_watch_word));
    UserHwDebugState watch_roundtrip{};
    UserHwDebugState shifted_watch = watch_baseline;
    shifted_watch.registers[0].address = watch_address + 1UL;
    shifted_watch.registers[0].control = kWatchWriteEl0;
    constexpr unsigned int kShiftedWatchWriteEl0 =
        1U | (2U << 1U) | (2U << 3U) | (0xfeU << 5U);
    if (set_state(kNtArmHwWatch, shifted_watch, 1U) != 0 ||
        !get_state(kNtArmHwWatch, watch_roundtrip) ||
        watch_roundtrip.registers[0].address != (watch_address & ~7UL) ||
        watch_roundtrip.registers[0].control != kShiftedWatchWriteEl0) {
        std::fprintf(stderr,
                     "antidbg shifted watch regset mismatch addr=0x%lx ctrl=0x%x errno=%d\n",
                     watch_roundtrip.registers[0].address,
                     watch_roundtrip.registers[0].control, errno);
        cleanup();
        return 1;
    }
    UserHwDebugState shifted_watch_clear{};
    if (set_state(kNtArmHwWatch, shifted_watch_clear, watch_slots) != 0) {
        std::fprintf(stderr,
                     "antidbg shifted watch clear failed errno=%d\n", errno);
        cleanup();
        return 1;
    }
    UserHwDebugState watch_programmed = watch_baseline;
    for (unsigned int index = 0; index < watch_slots; ++index) {
        watch_programmed.registers[index].address = watch_address;
        watch_programmed.registers[index].control = kWatchWriteEl0;
    }
    if (set_state(kNtArmHwWatch, watch_programmed, watch_slots) != 0) {
        std::fprintf(stderr, "antidbg watch SETREGSET failed errno=%d\n", errno);
        cleanup();
        return 1;
    }
    if (!get_state(kNtArmHwWatch, watch_roundtrip) ||
        std::memcmp(&watch_programmed, &watch_roundtrip,
                    sizeof(watch_programmed)) != 0) {
        std::fprintf(stderr,
                     "antidbg watch read/write consistency failed errno=%d\n",
                     errno);
        cleanup();
        return 1;
    }
    UserHwDebugState watch_overflow = watch_programmed;
    watch_overflow.registers[watch_slots].address = watch_address;
    watch_overflow.registers[watch_slots].control = kWatchWriteEl0;
    errno = 0;
    if (set_state(kNtArmHwWatch, watch_overflow, watch_slots + 1U) != -1 ||
        errno != ENOSPC) {
        std::fprintf(stderr,
                     "antidbg watch overflow mismatch errno=%d expected=%d\n",
                     errno, ENOSPC);
        cleanup();
        return 1;
    }

    struct perf_event_attr attr {};
    attr.type = PERF_TYPE_BREAKPOINT;
    attr.size = sizeof(attr);
    attr.bp_type = HW_BREAKPOINT_X;
    attr.bp_addr = fake_address;
    attr.bp_len = HW_BREAKPOINT_LEN_4;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;

    /* Conversion to SW_DUMMY must not erase breakpoint-specific validation.
     * sigtrap requires remove_on_exec, while branch-stack sampling is not
     * supported by the hardware-breakpoint PMU. */
    struct perf_event_attr invalid_sigtrap_attr = attr;
    invalid_sigtrap_attr.sigtrap = 1;
    invalid_sigtrap_attr.sample_period = 1;
    errno = 0;
    const long invalid_sigtrap_fd = syscall(
        __NR_perf_event_open, &invalid_sigtrap_attr, child, -1, -1, 0UL);
    const int invalid_sigtrap_errno = errno;
    if (invalid_sigtrap_fd >= 0) close(static_cast<int>(invalid_sigtrap_fd));
    struct perf_event_attr branch_stack_attr = attr;
    branch_stack_attr.sample_type = PERF_SAMPLE_BRANCH_STACK;
    errno = 0;
    const long branch_stack_fd = syscall(
        __NR_perf_event_open, &branch_stack_attr, child, -1, -1, 0UL);
    const int branch_stack_errno = errno;
    if (branch_stack_fd >= 0) close(static_cast<int>(branch_stack_fd));
    if (invalid_sigtrap_fd != -1 || invalid_sigtrap_errno != EINVAL ||
        branch_stack_fd != -1 || branch_stack_errno != EINVAL) {
        std::fprintf(stderr,
                     "antidbg perf attr validation mismatch sigtrap-fd=%ld sigtrap-errno=%d branch-fd=%ld branch-errno=%d\n",
                     invalid_sigtrap_fd, invalid_sigtrap_errno,
                     branch_stack_fd, branch_stack_errno);
        cleanup();
        return 1;
    }

    errno = 0;
    const long shared_break_capacity = syscall(
        __NR_perf_event_open, &attr, child, -1, -1, 0UL);
    if (shared_break_capacity != -1 || errno != ENOSPC) {
        if (shared_break_capacity >= 0)
            close(static_cast<int>(shared_break_capacity));
        std::fprintf(stderr,
                     "antidbg ptrace/perf BRP capacity was not shared fd=%ld errno=%d\n",
                     shared_break_capacity, errno);
        cleanup();
        return 1;
    }
    UserHwDebugState perf_break_clear{};
    if (set_state(kNtArmHwBreak, perf_break_clear, slots) != 0) {
        std::fprintf(stderr,
                     "antidbg BRP clear before perf test failed errno=%d\n", errno);
        cleanup();
        return 1;
    }
    struct perf_event_attr unaligned_break_attr = attr;
    unaligned_break_attr.disabled = 1;
    unaligned_break_attr.bp_addr = fake_address + 1UL;
    const int unaligned_break_fd = static_cast<int>(syscall(
        __NR_perf_event_open, &unaligned_break_attr, child, -1, -1, 0UL));
    const int unaligned_break_close = unaligned_break_fd >= 0
        ? close(unaligned_break_fd) : -1;
    if (unaligned_break_fd < 0 || unaligned_break_close != 0) {
        std::fprintf(stderr,
                     "antidbg ARM64 unaligned execute canonicalization failed fd=%d close=%d errno=%d\n",
                     unaligned_break_fd, unaligned_break_close, errno);
        cleanup();
        return 1;
    }
    auto verify_perf_fd = [](int fd) {
        if (fd < 0 ||
            ioctl(fd, PERF_EVENT_IOC_RESET, 0UL) != 0 ||
            ioctl(fd, PERF_EVENT_IOC_ENABLE, 0UL) != 0 ||
            ioctl(fd, PERF_EVENT_IOC_DISABLE, 0UL) != 0)
            return false;
        std::uint64_t counter = 0;
        return read(fd, &counter, sizeof(counter)) ==
            static_cast<ssize_t>(sizeof(counter));
    };
    for (unsigned int index = 0; index < slots; ++index) {
        errno = 0;
        perf_fds[index] = static_cast<int>(syscall(
            __NR_perf_event_open, &attr, child, -1, -1, 0UL));
        if (perf_fds[index] < 0) {
            std::fprintf(stderr, "antidbg perf slot %u failed errno=%d\n",
                         index, errno);
            cleanup();
            return 1;
        }
        if (!verify_perf_fd(perf_fds[index])) {
            std::fprintf(stderr,
                         "antidbg perf slot %u is not a real perf fd errno=%d\n",
                         index, errno);
            cleanup();
            return 1;
        }
    }
    errno = 0;
    const long seventh_perf = syscall(
        __NR_perf_event_open, &attr, child, -1, -1, 0UL);
    if (seventh_perf != -1 || errno != ENOSPC) {
        std::fprintf(stderr,
                     "antidbg perf seventh mismatch fd=%ld errno=%d\n",
                     seventh_perf, errno);
        if (seventh_perf >= 0) close(static_cast<int>(seventh_perf));
        cleanup();
        return 1;
    }

    struct perf_event_attr watch_attr = attr;
    watch_attr.bp_type = HW_BREAKPOINT_W;
    watch_attr.bp_addr = watch_address;
    watch_attr.bp_len = HW_BREAKPOINT_LEN_8;
    errno = 0;
    const long shared_watch_capacity = syscall(
        __NR_perf_event_open, &watch_attr, child, -1, -1, 0UL);
    if (shared_watch_capacity != -1 || errno != ENOSPC) {
        if (shared_watch_capacity >= 0)
            close(static_cast<int>(shared_watch_capacity));
        std::fprintf(stderr,
                     "antidbg ptrace/perf WRP capacity was not shared fd=%ld errno=%d\n",
                     shared_watch_capacity, errno);
        cleanup();
        return 1;
    }
    UserHwDebugState perf_watch_clear{};
    if (set_state(kNtArmHwWatch, perf_watch_clear, watch_slots) != 0) {
        std::fprintf(stderr,
                     "antidbg WRP clear before perf test failed errno=%d\n", errno);
        cleanup();
        return 1;
    }
    struct perf_event_attr crossing_watch_attr = watch_attr;
    crossing_watch_attr.disabled = 1;
    crossing_watch_attr.bp_addr = watch_address + 1UL;
    crossing_watch_attr.bp_len = HW_BREAKPOINT_LEN_8;
    const int crossing_watch_fd = static_cast<int>(syscall(
        __NR_perf_event_open, &crossing_watch_attr, child, -1, -1, 0UL));
    const int crossing_watch_close = crossing_watch_fd >= 0
        ? close(crossing_watch_fd) : -1;
    if (crossing_watch_fd < 0 || crossing_watch_close != 0) {
        std::fprintf(stderr,
                     "antidbg ARM64 crossing watch canonicalization failed fd=%d close=%d errno=%d\n",
                     crossing_watch_fd, crossing_watch_close, errno);
        cleanup();
        return 1;
    }
    for (unsigned int index = 0; index < watch_slots; ++index) {
        watch_perf_fds[index] = static_cast<int>(syscall(
            __NR_perf_event_open, &watch_attr, child, -1, -1, 0UL));
        if (!verify_perf_fd(watch_perf_fds[index])) {
            std::fprintf(stderr,
                         "antidbg perf watch slot %u failed errno=%d\n",
                         index, errno);
            cleanup();
            return 1;
        }
    }
    errno = 0;
    const long overflow_watch_perf = syscall(
        __NR_perf_event_open, &watch_attr, child, -1, -1, 0UL);
    if (overflow_watch_perf != -1 || errno != ENOSPC) {
        std::fprintf(stderr,
                     "antidbg perf watch overflow fd=%ld errno=%d\n",
                     overflow_watch_perf, errno);
        if (overflow_watch_perf >= 0)
            close(static_cast<int>(overflow_watch_perf));
        cleanup();
        return 1;
    }

    /* Bind access control to the perf_event object, then prove every ordinary
     * file-table lifetime operation keeps working. This covers aliasing in one
     * process, fork inheritance, and an FD received through SCM_RIGHTS. */
    auto send_fd = [](int socket_fd, int fd) {
        char byte = 'F';
        struct iovec vector{&byte, 1U};
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
        std::memcpy(CMSG_DATA(header), &fd, sizeof(fd));
        return sendmsg(socket_fd, &message, 0) == 1;
    };
    auto receive_fd = [](int socket_fd) {
        char byte = 0;
        struct iovec vector{&byte, 1U};
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
        std::memcpy(&fd, CMSG_DATA(header), sizeof(fd));
        return fd;
    };

    dup_fd = dup(perf_fds[0]);
    fcntl_fd = fcntl(perf_fds[0], F_DUPFD_CLOEXEC, 128);
    const int dup3_target = fcntl(perf_fds[0], F_DUPFD_CLOEXEC, 256);
    if (dup3_target >= 0) close(dup3_target);
    dup3_fd = dup3_target >= 0
        ? dup3(perf_fds[0], dup3_target, O_CLOEXEC) : -1;
    if (!verify_perf_fd(dup_fd) || !verify_perf_fd(fcntl_fd) ||
        !verify_perf_fd(dup3_fd)) {
        std::fprintf(stderr, "antidbg perf fd alias verification failed errno=%d\n",
                     errno);
        cleanup();
        return 1;
    }

    int sockets[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, sockets) != 0) {
        std::fprintf(stderr, "antidbg socketpair failed errno=%d\n", errno);
        cleanup();
        return 1;
    }
    const pid_t fd_helper = fork();
    if (fd_helper == 0) {
        close(sockets[0]);
        (void)prctl(PR_SET_NAME, "rtgum-fdrecv", 0, 0, 0);
        bool valid = verify_perf_fd(perf_fds[0]);
        for (int fd : perf_fds) if (fd >= 0) close(fd);
        for (int fd : watch_perf_fds) if (fd >= 0) close(fd);
        if (dup_fd >= 0) close(dup_fd);
        if (fcntl_fd >= 0) close(fcntl_fd);
        if (dup3_fd >= 0) close(dup3_fd);
        const int received = receive_fd(sockets[1]);
        valid = valid && verify_perf_fd(received);
        if (received >= 0) close(received);
        close(sockets[1]);
        _exit(valid ? 0 : 61);
    }
    close(sockets[1]);
    sockets[1] = -1;
    if (fd_helper < 0 || !send_fd(sockets[0], perf_fds[0])) {
        if (fd_helper > 0) kill(fd_helper, SIGKILL);
        close(sockets[0]);
        if (fd_helper > 0) (void)waitpid(fd_helper, nullptr, 0);
        std::fprintf(stderr, "antidbg SCM_RIGHTS send failed errno=%d\n", errno);
        cleanup();
        return 1;
    }
    close(sockets[0]);
    int helper_status = 0;
    if (waitpid(fd_helper, &helper_status, 0) != fd_helper ||
        !WIFEXITED(helper_status) || WEXITSTATUS(helper_status) != 0) {
        std::fprintf(stderr, "antidbg inherited/SCM fd helper failed status=0x%x\n",
                     helper_status);
        cleanup();
        return 1;
    }

    if (close(perf_fds[0]) != 0) {
        std::fprintf(stderr, "antidbg original perf close failed errno=%d\n", errno);
        perf_fds[0] = -1;
        cleanup();
        return 1;
    }
    perf_fds[0] = -1;
    errno = 0;
    const long alias_capacity = syscall(
        __NR_perf_event_open, &attr, child, -1, -1, 0UL);
    if (alias_capacity != -1 || errno != ENOSPC) {
        if (alias_capacity >= 0) close(static_cast<int>(alias_capacity));
        std::fprintf(stderr,
                     "antidbg aliases did not retain capacity fd=%ld errno=%d\n",
                     alias_capacity, errno);
        cleanup();
        return 1;
    }
    close(dup_fd);
    close(fcntl_fd);
    close(dup3_fd);
    dup_fd = fcntl_fd = dup3_fd = -1;
    perf_fds[0] = static_cast<int>(syscall(
        __NR_perf_event_open, &attr, child, -1, -1, 0UL));
    if (!verify_perf_fd(perf_fds[0])) {
        std::fprintf(stderr,
                     "antidbg capacity was not released after last alias errno=%d\n",
                     errno);
        cleanup();
        return 1;
    }

    /* Real ptrace and perf HWBP objects share the target task's comparator
     * pool. Close the perf half before re-arming the ptrace half for the
     * active-trigger check. */
    for (int &fd : perf_fds) {
        if (fd >= 0) close(fd);
        fd = -1;
    }
    for (int &fd : watch_perf_fds) {
        if (fd >= 0) close(fd);
        fd = -1;
    }
    if (set_state(kNtArmHwBreak, programmed, slots) != 0 ||
        set_state(kNtArmHwWatch, watch_programmed, watch_slots) != 0) {
        std::fprintf(stderr,
                     "antidbg ptrace re-arm after perf test failed errno=%d\n",
                     errno);
        cleanup();
        return 1;
    }

    auto expect_hwbp_stop = [&](unsigned long expected_address,
                                const char *label) {
        if (ptrace(PTRACE_CONT, child, nullptr, nullptr) != 0 ||
            waitpid(child, &status, 0) != child || !WIFSTOPPED(status) ||
            WSTOPSIG(status) != SIGTRAP) {
            std::fprintf(stderr,
                         "antidbg %s trigger stop failed status=0x%x errno=%d\n",
                         label, status, errno);
            return false;
        }
        siginfo_t info{};
        errno = 0;
        if (ptrace(PTRACE_GETSIGINFO, child, nullptr, &info) != 0 ||
            info.si_signo != SIGTRAP || info.si_code != TRAP_HWBKPT ||
            reinterpret_cast<unsigned long>(info.si_addr) != expected_address) {
            std::fprintf(stderr,
                         "antidbg %s siginfo mismatch signo=%d code=%d addr=%p expected=0x%lx errno=%d\n",
                         label, info.si_signo, info.si_code, info.si_addr,
                         expected_address, errno);
            return false;
        }
        return true;
    };

    if (!expect_hwbp_stop(watch_address, "watch")) {
        cleanup();
        return 1;
    }
    UserHwDebugState active_watch_clear{};
    if (set_state(kNtArmHwWatch, active_watch_clear, watch_slots) != 0) {
        std::fprintf(stderr,
                     "antidbg active watch clear failed errno=%d\n", errno);
        cleanup();
        return 1;
    }
    if (!expect_hwbp_stop(fake_address, "break")) {
        cleanup();
        return 1;
    }
    UserHwDebugState active_break_clear{};
    if (set_state(kNtArmHwBreak, active_break_clear, slots) != 0) {
        std::fprintf(stderr,
                     "antidbg active break clear failed errno=%d\n", errno);
        cleanup();
        return 1;
    }
    if (ptrace(PTRACE_CONT, child, nullptr, nullptr) != 0 ||
        waitpid(child, &status, 0) != child || !WIFSTOPPED(status) ||
        WSTOPSIG(status) != SIGSTOP) {
        std::fprintf(stderr,
                     "antidbg post-trigger rendezvous failed status=0x%x errno=%d\n",
                     status, errno);
        cleanup();
        return 1;
    }

    std::snprintf(command, sizeof(command), "hwbp-snapshot %lu", hwbp_handle);
    if (control(key, command, response, sizeof(response)) != 0 ||
        std::strstr(response, "entry=1 return=1") == nullptr ||
        std::strstr(response, "x0=0xb x1=0x7") == nullptr ||
        std::strstr(response, "ret=0x12") == nullptr) {
        std::fprintf(stderr, "antidbg real HWBP was lost: %s\n", response);
        cleanup();
        return 1;
    }

    /* Active perf semantics. The KPM keeps these as ordinary SW_DUMMY file
     * objects, but feeds a real breakpoint hit into perf_bp_event(). This must
     * preserve count, disable/reset/enable, and synchronous TRAP_PERF fields. */
    constexpr std::uint64_t kBreakSigData = UINT64_C(0x5254474252500001);
    constexpr std::uint64_t kWatchSigData = UINT64_C(0x5254475752500002);
    struct perf_event_attr active_break = attr;
    active_break.disabled = 1;
    active_break.remove_on_exec = 1;
    active_break.sigtrap = 1;
    active_break.sample_period = 1;
    active_break.sig_data = kBreakSigData;
    struct perf_event_attr active_watch = watch_attr;
    active_watch.disabled = 1;
    active_watch.remove_on_exec = 1;
    active_watch.sigtrap = 1;
    active_watch.sample_period = 1;
    active_watch.sig_data = kWatchSigData;

    perf_fds[0] = static_cast<int>(syscall(
        __NR_perf_event_open, &active_break, child, -1, -1, 0UL));
    watch_perf_fds[0] = static_cast<int>(syscall(
        __NR_perf_event_open, &active_watch, child, -1, -1, 0UL));
    if (perf_fds[0] < 0 || watch_perf_fds[0] < 0 ||
        ioctl(perf_fds[0], PERF_EVENT_IOC_RESET, 0UL) != 0 ||
        ioctl(watch_perf_fds[0], PERF_EVENT_IOC_RESET, 0UL) != 0 ||
        ioctl(perf_fds[0], PERF_EVENT_IOC_ENABLE, 0UL) != 0 ||
        ioctl(watch_perf_fds[0], PERF_EVENT_IOC_ENABLE, 0UL) != 0) {
        std::fprintf(stderr,
                     "antidbg active perf setup failed brk-fd=%d watch-fd=%d errno=%d\n",
                     perf_fds[0], watch_perf_fds[0], errno);
        cleanup();
        return 1;
    }

    auto read_perf_count = [](int fd, std::uint64_t &value) {
        value = 0;
        return fd >= 0 && read(fd, &value, sizeof(value)) ==
            static_cast<ssize_t>(sizeof(value));
    };
    auto expect_perf_stop = [&](unsigned long expected_address,
                                std::uint64_t expected_data,
                                const char *label) {
        if (ptrace(PTRACE_CONT, child, nullptr, nullptr) != 0 ||
            waitpid(child, &status, 0) != child || !WIFSTOPPED(status) ||
            WSTOPSIG(status) != SIGTRAP) {
            char diagnostic[kControlBufferSize]{};
            if (control(key, "antidbg-status", diagnostic,
                        sizeof(diagnostic)) == 0)
                std::fprintf(stderr, "antidbg perf diagnostic status: %s\n",
                             diagnostic);
            if (control(key, "antidbg-physical", diagnostic,
                        sizeof(diagnostic)) == 0)
                std::fprintf(stderr, "antidbg perf diagnostic physical: %s\n",
                             diagnostic);
            std::fprintf(stderr,
                         "antidbg perf %s stop failed status=0x%x errno=%d\n",
                         label, status, errno);
            return false;
        }
        siginfo_t info{};
        if (ptrace(PTRACE_GETSIGINFO, child, nullptr, &info) != 0 ||
            info.si_signo != SIGTRAP || info.si_code != TRAP_PERF ||
            reinterpret_cast<unsigned long>(info.si_addr) != expected_address ||
            static_cast<unsigned int>(info.si_perf_type) != PERF_TYPE_BREAKPOINT ||
            static_cast<std::uint64_t>(info.si_perf_data) != expected_data) {
            std::fprintf(stderr,
                         "antidbg perf %s siginfo mismatch signo=%d code=%d addr=%p type=%u data=0x%llx expected-addr=0x%lx expected-data=0x%llx errno=%d\n",
                         label, info.si_signo, info.si_code, info.si_addr,
                         static_cast<unsigned int>(info.si_perf_type),
                         static_cast<unsigned long long>(info.si_perf_data),
                         expected_address,
                         static_cast<unsigned long long>(expected_data), errno);
            return false;
        }
        return true;
    };
    auto expect_round_rendezvous = [&](const char *label) {
        if (ptrace(PTRACE_CONT, child, nullptr, nullptr) != 0 ||
            waitpid(child, &status, 0) != child || !WIFSTOPPED(status) ||
            WSTOPSIG(status) != SIGSTOP) {
            std::fprintf(stderr,
                         "antidbg perf %s rendezvous failed status=0x%x errno=%d\n",
                         label, status, errno);
            return false;
        }
        return true;
    };

    if (!expect_perf_stop(watch_address, kWatchSigData, "watch-enabled") ||
        !expect_perf_stop(fake_address, kBreakSigData, "break-enabled") ||
        !expect_round_rendezvous("enabled")) {
        cleanup();
        return 1;
    }
    std::uint64_t break_count = 0;
    std::uint64_t watch_count = 0;
    if (!read_perf_count(perf_fds[0], break_count) ||
        !read_perf_count(watch_perf_fds[0], watch_count) ||
        break_count != 1U || watch_count != 1U) {
        std::fprintf(stderr,
                     "antidbg active perf count mismatch enabled brk=%llu watch=%llu errno=%d\n",
                     static_cast<unsigned long long>(break_count),
                     static_cast<unsigned long long>(watch_count), errno);
        cleanup();
        return 1;
    }

    if (ioctl(perf_fds[0], PERF_EVENT_IOC_DISABLE, 0UL) != 0 ||
        ioctl(watch_perf_fds[0], PERF_EVENT_IOC_DISABLE, 0UL) != 0 ||
        !expect_round_rendezvous("disabled") ||
        !read_perf_count(perf_fds[0], break_count) ||
        !read_perf_count(watch_perf_fds[0], watch_count) ||
        break_count != 1U || watch_count != 1U) {
        std::fprintf(stderr,
                     "antidbg disabled perf semantics failed brk=%llu watch=%llu status=0x%x errno=%d\n",
                     static_cast<unsigned long long>(break_count),
                     static_cast<unsigned long long>(watch_count), status, errno);
        cleanup();
        return 1;
    }

    if (ioctl(perf_fds[0], PERF_EVENT_IOC_RESET, 0UL) != 0 ||
        ioctl(watch_perf_fds[0], PERF_EVENT_IOC_RESET, 0UL) != 0 ||
        ioctl(perf_fds[0], PERF_EVENT_IOC_ENABLE, 0UL) != 0 ||
        ioctl(watch_perf_fds[0], PERF_EVENT_IOC_ENABLE, 0UL) != 0 ||
        !expect_perf_stop(watch_address, kWatchSigData, "watch-reenabled") ||
        !expect_perf_stop(fake_address, kBreakSigData, "break-reenabled") ||
        !expect_round_rendezvous("reenabled") ||
        !read_perf_count(perf_fds[0], break_count) ||
        !read_perf_count(watch_perf_fds[0], watch_count) ||
        break_count != 1U || watch_count != 1U) {
        std::fprintf(stderr,
                     "antidbg reset/re-enable perf semantics failed brk=%llu watch=%llu status=0x%x errno=%d\n",
                     static_cast<unsigned long long>(break_count),
                     static_cast<unsigned long long>(watch_count), status, errno);
        cleanup();
        return 1;
    }

    std::snprintf(command, sizeof(command), "hwbp-snapshot %lu", hwbp_handle);
    if (control(key, command, response, sizeof(response)) != 0 ||
        std::strstr(response, "entry=4 return=4") == nullptr) {
        std::fprintf(stderr,
                     "antidbg real HWBP did not coexist with active perf: %s\n",
                     response);
        cleanup();
        return 1;
    }

    for (int &fd : perf_fds) {
        if (fd < 0) continue;
        if (close(fd) != 0) {
            std::fprintf(stderr, "antidbg fake perf close failed errno=%d\n", errno);
            fd = -1;
            cleanup();
            return 1;
        }
        fd = -1;
    }
    for (int &fd : watch_perf_fds) {
        if (fd < 0) continue;
        if (close(fd) != 0) {
            std::fprintf(stderr,
                         "antidbg fake watch perf close failed errno=%d\n", errno);
            fd = -1;
            cleanup();
            return 1;
        }
        fd = -1;
    }
    UserHwDebugState cleared{};
    if (set_state(kNtArmHwBreak, cleared, slots) != 0 ||
        !get_state(kNtArmHwBreak, roundtrip)) {
        std::fprintf(stderr, "antidbg ledger clear failed errno=%d\n", errno);
        cleanup();
        return 1;
    }
    for (const auto &entry : roundtrip.registers) {
        if (entry.address != 0UL || entry.control != 0U) {
            std::fprintf(stderr, "antidbg cleared ledger retained a register\n");
            cleanup();
            return 1;
        }
    }
    UserHwDebugState watch_cleared{};
    if (set_state(kNtArmHwWatch, watch_cleared, watch_slots) != 0 ||
        !get_state(kNtArmHwWatch, watch_roundtrip)) {
        std::fprintf(stderr, "antidbg watch ledger clear failed errno=%d\n",
                     errno);
        cleanup();
        return 1;
    }
    for (const auto &entry : watch_roundtrip.registers) {
        if (entry.address != 0UL || entry.control != 0U) {
            std::fprintf(stderr,
                         "antidbg cleared watch ledger retained a register\n");
            cleanup();
            return 1;
        }
    }

    std::snprintf(command, sizeof(command), "hwbp-clear %lu", hwbp_handle);
    if (control(key, command, response, sizeof(response)) != 0 ||
        std::strstr(response, "cleared=1") == nullptr) {
        std::fprintf(stderr, "antidbg real HWBP clear failed: %s\n", response);
        cleanup();
        return 1;
    }
    hwbp_handle = 0UL;
    if (ptrace(PTRACE_DETACH, child, nullptr, nullptr) != 0 ||
        waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0) {
        std::fprintf(stderr, "antidbg child completion failed status=0x%x errno=%d\n",
                     status, errno);
        cleanup();
        return 1;
    }
    child_reaped = true;

    /* Task-wide PR_TASK_PERF_EVENTS_{ENABLE,DISABLE} reaches the kernel's
     * internal _perf_event_* helpers rather than the fd ioctl path.  A detector
     * can use this to spot a virtual ledger whose state only follows ioctl.
     * Exercise the real prctl ABI, inspect the physical image while enabled,
     * then prove both the generic perf-fd metadata and final disable state. */
    struct perf_event_attr task_toggle_attr = attr;
    task_toggle_attr.disabled = 1;
    const int task_toggle_fd = static_cast<int>(syscall(
        __NR_perf_event_open, &task_toggle_attr, 0, -1, -1, 0UL));
    std::uint64_t task_toggle_id = 0;
    char task_fd_path[64]{};
    char task_fd_link[128]{};
    std::snprintf(task_fd_path, sizeof(task_fd_path),
                  "/proc/self/fd/%d", task_toggle_fd);
    const ssize_t task_link_length = task_toggle_fd >= 0
        ? readlink(task_fd_path, task_fd_link, sizeof(task_fd_link) - 1U)
        : -1;
    if (task_link_length > 0)
        task_fd_link[static_cast<std::size_t>(task_link_length)] = '\0';
    struct stat task_fd_stat {};
    struct pollfd task_poll {task_toggle_fd, POLLIN, 0};
    const int task_poll_result = task_toggle_fd >= 0
        ? poll(&task_poll, 1, 0) : -1;
    const long perf_page_size = sysconf(_SC_PAGESIZE);
    void *perf_metadata = task_toggle_fd >= 0 && perf_page_size > 0
        ? mmap(nullptr, static_cast<std::size_t>(perf_page_size),
               PROT_READ | PROT_WRITE, MAP_SHARED, task_toggle_fd, 0)
        : MAP_FAILED;
    const bool perf_mmap_ok = perf_metadata != MAP_FAILED;
    volatile std::uint32_t perf_mmap_version = perf_mmap_ok
        ? static_cast<volatile struct perf_event_mmap_page *>(
              perf_metadata)->version : UINT32_MAX;
    (void)perf_mmap_version;
    const int perf_munmap = perf_mmap_ok
        ? munmap(perf_metadata, static_cast<std::size_t>(perf_page_size)) : -1;
    char perf_filter[] = "filter 0/0@0";
    errno = 0;
    const int perf_filter_result = task_toggle_fd >= 0
        ? ioctl(task_toggle_fd, PERF_EVENT_IOC_SET_FILTER, perf_filter) : 0;
    const int perf_filter_errno = errno;
    errno = 0;
    const int perf_bpf_result = task_toggle_fd >= 0
        ? ioctl(task_toggle_fd, PERF_EVENT_IOC_SET_BPF, -1L) : 0;
    const int perf_bpf_errno = errno;
    struct PerfBpfQuery final {
        std::uint32_t ids_len;
        std::uint32_t prog_cnt;
        std::uint32_t ids[4];
    } perf_bpf_query{4U, 0U, {0U, 0U, 0U, 0U}};
    errno = 0;
    const int perf_query_result = task_toggle_fd >= 0
        ? ioctl(task_toggle_fd, PERF_EVENT_IOC_QUERY_BPF, &perf_bpf_query) : 0;
    const int perf_query_errno = errno;
    errno = 0;
    const int perf_output_result = task_toggle_fd >= 0
        ? ioctl(task_toggle_fd, PERF_EVENT_IOC_SET_OUTPUT, -1L) : 0;
    const int perf_output_errno = errno;
    errno = 0;
    const int perf_pause_result = task_toggle_fd >= 0
        ? ioctl(task_toggle_fd, PERF_EVENT_IOC_PAUSE_OUTPUT, 1UL) : 0;
    const int perf_pause_errno = errno;
    const bool perf_surface_ok = perf_mmap_ok && perf_munmap == 0 &&
        perf_filter_result == -1 && perf_filter_errno == EINVAL &&
        perf_bpf_result == -1 && perf_bpf_errno == EBADF &&
        perf_query_result == -1 && perf_query_errno == EINVAL &&
        perf_output_result == 0 && perf_output_errno == 0 &&
        perf_pause_result == -1 && perf_pause_errno == EINVAL;
    if (task_toggle_fd < 0 || !verify_perf_fd(task_toggle_fd) ||
        ioctl(task_toggle_fd, PERF_EVENT_IOC_ID, &task_toggle_id) != 0 ||
        task_toggle_id == 0U || task_link_length <= 0 ||
        std::strstr(task_fd_link, "anon_inode:[perf_event]") == nullptr ||
        fstat(task_toggle_fd, &task_fd_stat) != 0 ||
        fcntl(task_toggle_fd, F_GETFL) < 0 ||
        fcntl(task_toggle_fd, F_GETFD) < 0 || task_poll_result < 0 ||
        (task_poll.revents & POLLNVAL) != 0 || !perf_surface_ok ||
        prctl(PR_TASK_PERF_EVENTS_ENABLE, 0, 0, 0, 0) != 0 ||
        control(key, "antidbg-physical", response, sizeof(response)) != 0 ||
        std::strstr(response, "antidbg-records=1") == nullptr ||
        std::strstr(response, "antidbg-enabled=1") == nullptr ||
        prctl(PR_TASK_PERF_EVENTS_DISABLE, 0, 0, 0, 0) != 0 ||
        control(key, "antidbg-physical", response, sizeof(response)) != 0 ||
        std::strstr(response, "antidbg-records=0") == nullptr ||
        std::strstr(response, "antidbg-enabled=0") == nullptr ||
        close(task_toggle_fd) != 0) {
        if (task_toggle_fd >= 0) close(task_toggle_fd);
        std::fprintf(stderr,
                     "antidbg task-wide perf/fd metadata failed: %s id=%llu link=%s poll=%d revents=0x%x mmap=%u/%d filter=%d/%d bpf=%d/%d query=%d/%d output=%d/%d pause=%d/%d errno=%d\n",
                     response,
                     static_cast<unsigned long long>(task_toggle_id),
                     task_fd_link, task_poll_result,
                     static_cast<unsigned int>(task_poll.revents),
                     perf_mmap_ok ? 1U : 0U, perf_munmap,
                     perf_filter_result, perf_filter_errno,
                     perf_bpf_result, perf_bpf_errno,
                     perf_query_result, perf_query_errno,
                     perf_output_result, perf_output_errno,
                     perf_pause_result, perf_pause_errno, errno);
        cleanup();
        return 1;
    }

    /* exclude_user still consumes a logical slot, but a user address must not
     * arm an EL0 comparator or increment the counter. */
    constexpr std::uint64_t kExcludeUserSigData =
        UINT64_C(0x5254474558550003);
    struct sigaction exclude_action {};
    struct sigaction exclude_previous {};
    exclude_action.sa_sigaction = antidbg_inherit_signal_handler;
    exclude_action.sa_flags = SA_SIGINFO;
    sigemptyset(&exclude_action.sa_mask);
    struct perf_event_attr exclude_user_attr = attr;
    exclude_user_attr.disabled = 0;
    exclude_user_attr.exclude_user = 1;
    exclude_user_attr.remove_on_exec = 1;
    exclude_user_attr.sigtrap = 1;
    exclude_user_attr.sample_period = 1;
    exclude_user_attr.sig_data = kExcludeUserSigData;
    antidbg_inherit_signal_hits = 0;
    antidbg_inherit_disable_result = -1;
    const bool exclude_signal_installed =
        sigaction(SIGTRAP, &exclude_action, &exclude_previous) == 0;
    const int exclude_user_fd = exclude_signal_installed
        ? static_cast<int>(syscall(__NR_perf_event_open,
                                   &exclude_user_attr, 0, -1, -1, 0UL))
        : -1;
    const bool exclude_physical_empty = exclude_user_fd >= 0 &&
        control(key, "antidbg-physical", response, sizeof(response)) == 0 &&
        std::strstr(response, "antidbg-records=0") != nullptr &&
        std::strstr(response, "antidbg-enabled=0") != nullptr;
    const int exclude_result = exclude_physical_empty
        ? static_cast<int>(antidbg_fake_target(8)) : -1;
    std::uint64_t exclude_count = UINT64_MAX;
    const bool exclude_read = exclude_user_fd >= 0 &&
        read(exclude_user_fd, &exclude_count, sizeof(exclude_count)) ==
            static_cast<ssize_t>(sizeof(exclude_count));
    const int exclude_close = exclude_user_fd >= 0
        ? close(exclude_user_fd) : -1;
    const int exclude_restore = exclude_signal_installed
        ? sigaction(SIGTRAP, &exclude_previous, nullptr) : -1;
    if (!exclude_physical_empty || exclude_result != 9 || !exclude_read ||
        exclude_count != 0 || antidbg_inherit_signal_hits != 0 ||
        exclude_close != 0 || exclude_restore != 0 ||
        control(key, "antidbg-status", response, sizeof(response)) != 0 ||
        std::strstr(response, "perf=0") == nullptr) {
        if (exclude_user_fd >= 0 && exclude_close != 0) close(exclude_user_fd);
        if (exclude_signal_installed)
            (void)sigaction(SIGTRAP, &exclude_previous, nullptr);
        std::fprintf(stderr,
                     "antidbg exclude-user semantics failed: %s fd=%d result=%d count=%llu hits=%d errno=%d\n",
                     response, exclude_user_fd, exclude_result,
                     static_cast<unsigned long long>(exclude_count),
                     static_cast<int>(antidbg_inherit_signal_hits), errno);
        cleanup();
        return 1;
    }

    /* PERF_IOC_FLAG_GROUP must reach every fake event through the kernel's
     * own group walk. Verify physical state 0 -> 2 -> 0. */
    struct perf_event_attr group_leader_attr = attr;
    group_leader_attr.disabled = 1;
    struct perf_event_attr group_member_attr = group_leader_attr;
    group_member_attr.bp_addr = fake_address + 4UL;
    const int group_leader_fd = static_cast<int>(syscall(
        __NR_perf_event_open, &group_leader_attr, 0, -1, -1, 0UL));
    const int group_member_fd = group_leader_fd >= 0
        ? static_cast<int>(syscall(__NR_perf_event_open, &group_member_attr,
                                   0, -1, group_leader_fd, 0UL))
        : -1;
    const bool group_enabled = group_member_fd >= 0 &&
        ioctl(group_leader_fd, PERF_EVENT_IOC_ENABLE,
              PERF_IOC_FLAG_GROUP) == 0 &&
        control(key, "antidbg-physical", response, sizeof(response)) == 0 &&
        std::strstr(response, "antidbg-records=2") != nullptr &&
        std::strstr(response, "antidbg-enabled=2") != nullptr;
    const bool group_disabled = group_enabled &&
        ioctl(group_leader_fd, PERF_EVENT_IOC_DISABLE,
              PERF_IOC_FLAG_GROUP) == 0 &&
        control(key, "antidbg-physical", response, sizeof(response)) == 0 &&
        std::strstr(response, "antidbg-records=0") != nullptr &&
        std::strstr(response, "antidbg-enabled=0") != nullptr;
    const int group_member_close = group_member_fd >= 0
        ? close(group_member_fd) : -1;
    const int group_leader_close = group_leader_fd >= 0
        ? close(group_leader_fd) : -1;
    if (!group_disabled || group_member_close != 0 ||
        group_leader_close != 0 ||
        control(key, "antidbg-status", response, sizeof(response)) != 0 ||
        std::strstr(response, "perf=0") == nullptr) {
        if (group_member_fd >= 0 && group_member_close != 0)
            close(group_member_fd);
        if (group_leader_fd >= 0 && group_leader_close != 0)
            close(group_leader_fd);
        std::fprintf(stderr,
                     "antidbg perf group semantics failed: %s leader=%d member=%d enabled=%u disabled=%u errno=%d\n",
                     response, group_leader_fd, group_member_fd,
                     group_enabled ? 1U : 0U, group_disabled ? 1U : 0U,
                     errno);
        cleanup();
        return 1;
    }

    /* Mixed groups are a separate fingerprint from an all-breakpoint group:
     * exercise both directions so the virtual member follows a real software
     * leader and a real software member follows a virtual leader. */
    unsigned int mixed_group_perf_events = 0U;
    unsigned int mixed_group_perf_reads = 0U;
    struct perf_event_attr software_group_attr {};
    software_group_attr.type = PERF_TYPE_SOFTWARE;
    software_group_attr.size = sizeof(software_group_attr);
    software_group_attr.config = PERF_COUNT_SW_DUMMY;
    software_group_attr.disabled = 1;
    software_group_attr.exclude_kernel = 1;
    software_group_attr.exclude_hv = 1;
    struct perf_event_attr mixed_break_attr = group_leader_attr;
    mixed_break_attr.bp_addr = fake_address;

    const int real_group_leader = static_cast<int>(syscall(
        __NR_perf_event_open, &software_group_attr, 0, -1, -1, 0UL));
    const int fake_group_member = real_group_leader >= 0
        ? static_cast<int>(syscall(__NR_perf_event_open, &mixed_break_attr,
                                   0, -1, real_group_leader, 0UL))
        : -1;
    if (fake_group_member >= 0) ++mixed_group_perf_events;
    const bool mixed_real_leader_enabled = fake_group_member >= 0 &&
        ioctl(real_group_leader, PERF_EVENT_IOC_ENABLE,
              PERF_IOC_FLAG_GROUP) == 0 &&
        control(key, "antidbg-physical", response, sizeof(response)) == 0 &&
        std::strstr(response, "antidbg-records=1") != nullptr &&
        std::strstr(response, "antidbg-enabled=1") != nullptr;
    const int mixed_real_leader_result = mixed_real_leader_enabled
        ? static_cast<int>(antidbg_fake_target(8)) : -1;
    std::uint64_t mixed_real_leader_count = UINT64_MAX;
    const bool mixed_real_leader_read = fake_group_member >= 0 &&
        read(fake_group_member, &mixed_real_leader_count,
             sizeof(mixed_real_leader_count)) ==
            static_cast<ssize_t>(sizeof(mixed_real_leader_count));
    if (mixed_real_leader_read) ++mixed_group_perf_reads;
    const bool mixed_real_leader_disabled = mixed_real_leader_read &&
        ioctl(real_group_leader, PERF_EVENT_IOC_DISABLE,
              PERF_IOC_FLAG_GROUP) == 0 &&
        control(key, "antidbg-physical", response, sizeof(response)) == 0 &&
        std::strstr(response, "antidbg-records=0") != nullptr &&
        std::strstr(response, "monitor-owned=0") != nullptr;
    const int fake_group_member_close = fake_group_member >= 0
        ? close(fake_group_member) : -1;
    const int real_group_leader_close = real_group_leader >= 0
        ? close(real_group_leader) : -1;

    const int fake_mixed_leader = static_cast<int>(syscall(
        __NR_perf_event_open, &mixed_break_attr, 0, -1, -1, 0UL));
    if (fake_mixed_leader >= 0) ++mixed_group_perf_events;
    const int real_group_member = fake_mixed_leader >= 0
        ? static_cast<int>(syscall(__NR_perf_event_open, &software_group_attr,
                                   0, -1, fake_mixed_leader, 0UL))
        : -1;
    const bool mixed_fake_leader_enabled = real_group_member >= 0 &&
        ioctl(fake_mixed_leader, PERF_EVENT_IOC_ENABLE,
              PERF_IOC_FLAG_GROUP) == 0 &&
        control(key, "antidbg-physical", response, sizeof(response)) == 0 &&
        std::strstr(response, "antidbg-records=1") != nullptr &&
        std::strstr(response, "antidbg-enabled=1") != nullptr;
    const int mixed_fake_leader_result = mixed_fake_leader_enabled
        ? static_cast<int>(antidbg_fake_target(8)) : -1;
    std::uint64_t mixed_fake_leader_count = UINT64_MAX;
    const bool mixed_fake_leader_read = fake_mixed_leader >= 0 &&
        read(fake_mixed_leader, &mixed_fake_leader_count,
             sizeof(mixed_fake_leader_count)) ==
            static_cast<ssize_t>(sizeof(mixed_fake_leader_count));
    if (mixed_fake_leader_read) ++mixed_group_perf_reads;
    const bool mixed_fake_leader_disabled = mixed_fake_leader_read &&
        ioctl(fake_mixed_leader, PERF_EVENT_IOC_DISABLE,
              PERF_IOC_FLAG_GROUP) == 0 &&
        control(key, "antidbg-physical", response, sizeof(response)) == 0 &&
        std::strstr(response, "antidbg-records=0") != nullptr &&
        std::strstr(response, "monitor-owned=0") != nullptr;
    const int real_group_member_close = real_group_member >= 0
        ? close(real_group_member) : -1;
    const int fake_mixed_leader_close = fake_mixed_leader >= 0
        ? close(fake_mixed_leader) : -1;
    const bool mixed_groups_ok = mixed_real_leader_enabled &&
        mixed_real_leader_result == 9 && mixed_real_leader_count == 1U &&
        mixed_real_leader_disabled && fake_group_member_close == 0 &&
        real_group_leader_close == 0 && mixed_fake_leader_enabled &&
        mixed_fake_leader_result == 9 && mixed_fake_leader_count == 1U &&
        mixed_fake_leader_disabled && real_group_member_close == 0 &&
        fake_mixed_leader_close == 0 && mixed_group_perf_events == 2U &&
        mixed_group_perf_reads == 2U &&
        control(key, "antidbg-status", response, sizeof(response)) == 0 &&
        std::strstr(response, "perf=0") != nullptr;
    if (!mixed_groups_ok) {
        if (fake_group_member >= 0 && fake_group_member_close != 0)
            close(fake_group_member);
        if (real_group_leader >= 0 && real_group_leader_close != 0)
            close(real_group_leader);
        if (real_group_member >= 0 && real_group_member_close != 0)
            close(real_group_member);
        if (fake_mixed_leader >= 0 && fake_mixed_leader_close != 0)
            close(fake_mixed_leader);
        std::fprintf(stderr,
                     "antidbg mixed group failed: %s fds=%d/%d/%d/%d enabled=%u/%u result=%d/%d count=%llu/%llu disabled=%u/%u closes=%d/%d/%d/%d errno=%d\n",
                     response, real_group_leader, fake_group_member,
                     fake_mixed_leader, real_group_member,
                     mixed_real_leader_enabled ? 1U : 0U,
                     mixed_fake_leader_enabled ? 1U : 0U,
                     mixed_real_leader_result, mixed_fake_leader_result,
                     static_cast<unsigned long long>(mixed_real_leader_count),
                     static_cast<unsigned long long>(mixed_fake_leader_count),
                     mixed_real_leader_disabled ? 1U : 0U,
                     mixed_fake_leader_disabled ? 1U : 0U,
                     fake_group_member_close, real_group_leader_close,
                     real_group_member_close, fake_mixed_leader_close, errno);
        cleanup();
        return 1;
    }

    /* A virtual sigtrap must follow the backing event's overflow cadence,
     * including a period changed through PERF_EVENT_IOC_PERIOD. */
    constexpr std::uint64_t kPeriodSigData =
        UINT64_C(0x5254475045520004);
    struct sigaction period_action {};
    struct sigaction period_previous {};
    period_action.sa_sigaction = antidbg_inherit_signal_handler;
    period_action.sa_flags = SA_SIGINFO;
    sigemptyset(&period_action.sa_mask);
    struct perf_event_attr period_attr = attr;
    period_attr.disabled = 0;
    period_attr.remove_on_exec = 1;
    period_attr.sigtrap = 1;
    period_attr.sample_period = 4;
    period_attr.sig_data = kPeriodSigData;
    antidbg_inherit_signal_hits = 0;
    antidbg_inherit_disable_result = -1;
    antidbg_inherit_signal_code = 0;
    antidbg_inherit_signal_type = 0;
    antidbg_inherit_signal_address = 0;
    antidbg_inherit_signal_data = 0;
    const bool period_signal_installed =
        sigaction(SIGTRAP, &period_action, &period_previous) == 0;
    const int period_fd = period_signal_installed
        ? static_cast<int>(syscall(__NR_perf_event_open, &period_attr,
                                   0, -1, -1, 0UL))
        : -1;
    std::uint64_t period_value = 2U;
    const bool period_changed = period_fd >= 0 &&
        ioctl(period_fd, PERF_EVENT_IOC_PERIOD, &period_value) == 0;
    const int period_first = period_changed
        ? static_cast<int>(antidbg_fake_target(8)) : -1;
    /* _perf_event_period() resets period_left to zero. The next event is an
     * immediate overflow; the following interval uses the new value. Our
     * handler disables the event at that first overflow. */
    const bool period_first_signalled = period_first == 9 &&
        antidbg_inherit_signal_hits == 1;
    const int period_second = period_first_signalled
        ? static_cast<int>(antidbg_fake_target(8)) : -1;
    std::uint64_t period_count = UINT64_MAX;
    const bool period_read = period_fd >= 0 &&
        read(period_fd, &period_count, sizeof(period_count)) ==
            static_cast<ssize_t>(sizeof(period_count));
    const int period_close = period_fd >= 0 ? close(period_fd) : -1;
    const int period_restore = period_signal_installed
        ? sigaction(SIGTRAP, &period_previous, nullptr) : -1;
    const bool period_signal_ok =
        antidbg_inherit_signal_hits == 1 &&
        antidbg_inherit_disable_result == 0 &&
        antidbg_inherit_signal_code == TRAP_PERF &&
        antidbg_inherit_signal_type == PERF_TYPE_BREAKPOINT &&
        antidbg_inherit_signal_address == fake_address &&
        antidbg_inherit_signal_data == kPeriodSigData;
    if (!period_changed || !period_first_signalled || period_second != 9 ||
        !period_read || period_count != 1U || !period_signal_ok ||
        period_close != 0 || period_restore != 0 ||
        control(key, "antidbg-status", response, sizeof(response)) != 0 ||
        std::strstr(response, "perf=0") == nullptr) {
        if (period_fd >= 0 && period_close != 0) close(period_fd);
        if (period_signal_installed)
            (void)sigaction(SIGTRAP, &period_previous, nullptr);
        std::fprintf(stderr,
                     "antidbg period/sigtrap semantics failed: %s changed=%u first=%d second=%d count=%llu hits=%d disable=%d code=%d type=%d addr=0x%llx data=0x%llx errno=%d\n",
                     response, period_changed ? 1U : 0U, period_first,
                     period_second,
                     static_cast<unsigned long long>(period_count),
                     static_cast<int>(antidbg_inherit_signal_hits),
                     static_cast<int>(antidbg_inherit_disable_result),
                     static_cast<int>(antidbg_inherit_signal_code),
                     static_cast<int>(antidbg_inherit_signal_type),
                     static_cast<unsigned long long>(
                         antidbg_inherit_signal_address),
                     static_cast<unsigned long long>(
                         antidbg_inherit_signal_data), errno);
        cleanup();
        return 1;
    }

    /* REFRESH(1) permits exactly one overflow, then disables the event from
     * irq-work. The virtual comparator must disappear before a second call. */
    struct perf_event_attr refresh_attr = attr;
    refresh_attr.disabled = 1;
    refresh_attr.sample_period = 1;
    const int refresh_fd = static_cast<int>(syscall(
        __NR_perf_event_open, &refresh_attr, 0, -1, -1, 0UL));
    const bool refresh_started = refresh_fd >= 0 &&
        ioctl(refresh_fd, PERF_EVENT_IOC_REFRESH, 1UL) == 0;
    const int refresh_first = refresh_started
        ? static_cast<int>(antidbg_fake_target(8)) : -1;
    const int refresh_second = refresh_first == 9
        ? static_cast<int>(antidbg_fake_target(8)) : -1;
    std::uint64_t refresh_count = UINT64_MAX;
    const bool refresh_read = refresh_fd >= 0 &&
        read(refresh_fd, &refresh_count, sizeof(refresh_count)) ==
            static_cast<ssize_t>(sizeof(refresh_count));
    const bool refresh_physical_empty =
        control(key, "antidbg-physical", response, sizeof(response)) == 0 &&
        std::strstr(response, "antidbg-records=0") != nullptr &&
        std::strstr(response, "antidbg-enabled=0") != nullptr;
    const int refresh_close = refresh_fd >= 0 ? close(refresh_fd) : -1;
    if (!refresh_started || refresh_first != 9 || refresh_second != 9 ||
        !refresh_read || refresh_count != 1U || !refresh_physical_empty ||
        refresh_close != 0 ||
        control(key, "antidbg-status", response, sizeof(response)) != 0 ||
        std::strstr(response, "perf=0") == nullptr) {
        if (refresh_fd >= 0 && refresh_close != 0) close(refresh_fd);
        std::fprintf(stderr,
                     "antidbg refresh limit failed: %s started=%u first=%d second=%d count=%llu physical=%u errno=%d\n",
                     response, refresh_started ? 1U : 0U, refresh_first,
                     refresh_second,
                     static_cast<unsigned long long>(refresh_count),
                     refresh_physical_empty ? 1U : 0U, errno);
        cleanup();
        return 1;
    }

    /* A real breakpoint fd supports MODIFY_ATTRIBUTES.  SW_DUMMY does not, so
     * this is an important type-fingerprint check: move a disabled comparator
     * to a second function, enable it through the new attr, and reject a change
     * to an immutable exclusion bit exactly like native breakpoint perf. */
    struct perf_event_attr modify_attr = attr;
    modify_attr.disabled = 1;
    const int modify_fd = static_cast<int>(syscall(
        __NR_perf_event_open, &modify_attr, 0, -1, -1, 0UL));
    struct perf_event_attr moved_attr = modify_attr;
    moved_attr.disabled = 0;
    moved_attr.bp_addr = reinterpret_cast<unsigned long>(
        &antidbg_modified_target);
    const bool modify_moved = modify_fd >= 0 &&
        ioctl(modify_fd, PERF_EVENT_IOC_MODIFY_ATTRIBUTES, &moved_attr) == 0;
    char modify_armed_status[kControlBufferSize]{};
    const bool modify_armed = modify_moved &&
        control(key, "antidbg-physical", modify_armed_status,
                sizeof(modify_armed_status)) == 0 &&
        std::strstr(modify_armed_status, "antidbg-records=1") != nullptr &&
        std::strstr(modify_armed_status, "antidbg-enabled=1") != nullptr;
    const int modify_old_result = modify_moved
        ? static_cast<int>(antidbg_fake_target(8)) : -1;
    const int modify_new_result = modify_moved
        ? static_cast<int>(antidbg_modified_target(8)) : -1;
    std::uint64_t modify_count = UINT64_MAX;
    const bool modify_read = modify_fd >= 0 &&
        read(modify_fd, &modify_count, sizeof(modify_count)) ==
            static_cast<ssize_t>(sizeof(modify_count));
    struct perf_event_attr invalid_modify_attr = moved_attr;
    invalid_modify_attr.exclude_kernel = 0;
    errno = 0;
    const int invalid_modify_result = modify_fd >= 0
        ? ioctl(modify_fd, PERF_EVENT_IOC_MODIFY_ATTRIBUTES,
                &invalid_modify_attr) : 0;
    const int invalid_modify_errno = errno;
    const bool modify_disabled = modify_fd >= 0 &&
        ioctl(modify_fd, PERF_EVENT_IOC_DISABLE, 0UL) == 0;
    const int modify_close = modify_fd >= 0 ? close(modify_fd) : -1;
    const bool modify_physical_empty =
        control(key, "antidbg-physical", response, sizeof(response)) == 0 &&
        std::strstr(response, "antidbg-records=0") != nullptr &&
        std::strstr(response, "antidbg-enabled=0") != nullptr;
    if (!modify_moved || !modify_armed || modify_old_result != 9 ||
        modify_new_result != 10 ||
        !modify_read || modify_count != 1U || invalid_modify_result != -1 ||
        invalid_modify_errno != EINVAL || !modify_disabled ||
        modify_close != 0 || !modify_physical_empty ||
        control(key, "antidbg-status", response, sizeof(response)) != 0 ||
        std::strstr(response, "perf=0") == nullptr ||
        std::strstr(response, "perf-modify=1") == nullptr ||
        std::strstr(response, "perf-modify-reject=1") == nullptr) {
        if (modify_fd >= 0 && modify_close != 0) close(modify_fd);
        std::fprintf(stderr,
                     "antidbg modify-attributes failed: %s armed=[%s] moved=%u armed-ok=%u old=%d new=%d read=%u count=%llu invalid=%d/%d disabled=%u physical=%u errno=%d\n",
                     response, modify_armed_status,
                     modify_moved ? 1U : 0U, modify_armed ? 1U : 0U,
                     modify_old_result,
                     modify_new_result, modify_read ? 1U : 0U,
                     static_cast<unsigned long long>(modify_count),
                     invalid_modify_result, invalid_modify_errno,
                     modify_disabled ? 1U : 0U,
                     modify_physical_empty ? 1U : 0U, errno);
        cleanup();
        return 1;
    }

    /* pid + explicit CPU events are only active while the target task runs on
     * that logical CPU.  The backing SW_DUMMY fd already lets perf validate
     * the pid/cpu pair; this probe verifies that the virtual comparator obeys
     * the same scheduling domain across two real migrations. */
    unsigned int cpu_specific_perf_events = 0U;
    unsigned int cpu_specific_perf_reads = 0U;
    cpu_set_t original_affinity{};
    const bool affinity_read =
        sched_getaffinity(0, sizeof(original_affinity), &original_affinity) == 0;
    int affinity_cpus[2] = {-1, -1};
    if (affinity_read) {
        for (int cpu = 0; cpu < CPU_SETSIZE && affinity_cpus[1] < 0; ++cpu) {
            if (!CPU_ISSET(cpu, &original_affinity)) continue;
            if (affinity_cpus[0] < 0)
                affinity_cpus[0] = cpu;
            else
                affinity_cpus[1] = cpu;
        }
    }
    if (!affinity_read || affinity_cpus[1] < 0) {
        std::fprintf(stderr,
                     "antidbg explicit-CPU test requires two allowed CPUs errno=%d\n",
                     errno);
        cleanup();
        return 1;
    }
    auto pin_to_cpu = [](int cpu) {
        cpu_set_t mask{};
        CPU_ZERO(&mask);
        CPU_SET(cpu, &mask);
        return sched_setaffinity(0, sizeof(mask), &mask) == 0 &&
            sched_yield() == 0;
    };
    bool cpu_binding_ok = pin_to_cpu(affinity_cpus[0]);
    struct perf_event_attr cpu_attr = attr;
    cpu_attr.disabled = 0;
    const int cpu_fd = cpu_binding_ok
        ? static_cast<int>(syscall(__NR_perf_event_open, &cpu_attr, 0,
                                   affinity_cpus[1], -1, 0UL))
        : -1;
    if (cpu_fd >= 0) cpu_specific_perf_events = 1U;
    auto read_cpu_count = [&](std::uint64_t &value) {
        if (cpu_fd < 0) return false;
        const ssize_t amount = read(cpu_fd, &value, sizeof(value));
        if (amount == static_cast<ssize_t>(sizeof(value))) {
            ++cpu_specific_perf_reads;
            return true;
        }
        return false;
    };
    std::uint64_t cpu_count_before = UINT64_MAX;
    std::uint64_t cpu_count_on_target = UINT64_MAX;
    std::uint64_t cpu_count_after = UINT64_MAX;
    const bool cpu_source_empty = cpu_fd >= 0 &&
        read_cpu_count(cpu_count_before) && cpu_count_before == 0U &&
        control(key, "antidbg-physical", response, sizeof(response)) == 0 &&
        std::strstr(response, "antidbg-records=0") != nullptr &&
        std::strstr(response, "antidbg-enabled=0") != nullptr;
    const bool cpu_target_armed = cpu_source_empty &&
        pin_to_cpu(affinity_cpus[1]) &&
        control(key, "antidbg-physical", response, sizeof(response)) == 0 &&
        std::strstr(response, "antidbg-records=1") != nullptr &&
        std::strstr(response, "antidbg-enabled=1") != nullptr;
    const int cpu_target_result = cpu_target_armed
        ? static_cast<int>(antidbg_fake_target(8)) : -1;
    const bool cpu_target_hit = cpu_target_result == 9 &&
        read_cpu_count(cpu_count_on_target) && cpu_count_on_target == 1U;
    const bool cpu_source_restored = cpu_target_hit &&
        pin_to_cpu(affinity_cpus[0]) &&
        control(key, "antidbg-physical", response, sizeof(response)) == 0 &&
        std::strstr(response, "antidbg-records=0") != nullptr &&
        std::strstr(response, "antidbg-enabled=0") != nullptr;
    const int cpu_source_result = cpu_source_restored
        ? static_cast<int>(antidbg_fake_target(8)) : -1;
    const bool cpu_source_did_not_hit = cpu_source_result == 9 &&
        read_cpu_count(cpu_count_after) && cpu_count_after == 1U;
    const int cpu_close = cpu_fd >= 0 ? close(cpu_fd) : -1;
    const int affinity_restore = sched_setaffinity(
        0, sizeof(original_affinity), &original_affinity);
    cpu_binding_ok = cpu_source_did_not_hit && cpu_close == 0 &&
        affinity_restore == 0 &&
        control(key, "antidbg-status", response, sizeof(response)) == 0 &&
        std::strstr(response, "perf=0") != nullptr &&
        control(key, "antidbg-physical", response, sizeof(response)) == 0 &&
        std::strstr(response, "antidbg-records=0") != nullptr &&
        std::strstr(response, "untracked-brk=0") != nullptr &&
        std::strstr(response, "monitor-owned=0") != nullptr &&
        std::strstr(response, "mdscr-ss=0") != nullptr;
    if (!cpu_binding_ok) {
        if (cpu_fd >= 0 && cpu_close != 0) close(cpu_fd);
        (void)sched_setaffinity(0, sizeof(original_affinity),
                                &original_affinity);
        std::fprintf(stderr,
                     "antidbg explicit-CPU binding failed: %s cpus=%d/%d fd=%d counts=%llu/%llu/%llu reads=%u target=%d source=%d close=%d restore=%d errno=%d\n",
                     response, affinity_cpus[0], affinity_cpus[1], cpu_fd,
                     static_cast<unsigned long long>(cpu_count_before),
                     static_cast<unsigned long long>(cpu_count_on_target),
                     static_cast<unsigned long long>(cpu_count_after),
                     cpu_specific_perf_reads, cpu_target_result,
                     cpu_source_result, cpu_close, affinity_restore, errno);
        cleanup();
        return 1;
    }

    /* Capacity is per overlapping CPU domain.  Six events on CPU A and six
     * on CPU B are simultaneously valid on this device; a seventh on A and an
     * any-CPU event must both observe the native -ENOSPC boundary. */
    unsigned int cpu_capacity_perf_events = 0U;
    int cpu_capacity_fds[2][kMaximumDebugSlots];
    for (auto &domain : cpu_capacity_fds)
        for (int &fd : domain) fd = -1;
    struct perf_event_attr cpu_capacity_attr = attr;
    cpu_capacity_attr.disabled = 1;
    bool cpu_capacity_ok = true;
    for (unsigned int domain = 0U; domain < 2U && cpu_capacity_ok; ++domain) {
        for (unsigned int index = 0U; index < slots; ++index) {
            cpu_capacity_attr.bp_addr = fake_address + index * 4UL;
            const int fd = static_cast<int>(syscall(
                __NR_perf_event_open, &cpu_capacity_attr, 0,
                affinity_cpus[domain], -1, 0UL));
            cpu_capacity_fds[domain][index] = fd;
            if (fd < 0) {
                cpu_capacity_ok = false;
                break;
            }
            ++cpu_capacity_perf_events;
        }
    }
    cpu_capacity_attr.bp_addr = fake_address + slots * 4UL;
    errno = 0;
    const int cpu_same_overflow = cpu_capacity_ok
        ? static_cast<int>(syscall(__NR_perf_event_open, &cpu_capacity_attr, 0,
                                   affinity_cpus[0], -1, 0UL))
        : -2;
    const int cpu_same_overflow_errno = errno;
    errno = 0;
    const int cpu_any_overflow = cpu_capacity_ok
        ? static_cast<int>(syscall(__NR_perf_event_open, &cpu_capacity_attr, 0,
                                   -1, -1, 0UL))
        : -2;
    const int cpu_any_overflow_errno = errno;
    errno = 0;
    const int cpu_wildcard_overlap = cpu_capacity_ok
        ? static_cast<int>(syscall(__NR_perf_event_open, &cpu_capacity_attr,
                                   -1, affinity_cpus[0], -1, 0UL))
        : -2;
    const int cpu_wildcard_overlap_errno = errno;
    if (cpu_same_overflow >= 0) close(cpu_same_overflow);
    if (cpu_any_overflow >= 0) close(cpu_any_overflow);
    if (cpu_wildcard_overlap >= 0) close(cpu_wildcard_overlap);
    for (auto &domain : cpu_capacity_fds)
        for (int &fd : domain) {
            if (fd >= 0 && close(fd) != 0) cpu_capacity_ok = false;
            fd = -1;
        }
    cpu_capacity_ok = cpu_capacity_ok &&
        cpu_same_overflow == -1 && cpu_same_overflow_errno == ENOSPC &&
        cpu_any_overflow == -1 && cpu_any_overflow_errno == ENOSPC &&
        cpu_wildcard_overlap == -1 &&
        cpu_wildcard_overlap_errno == ENOSPC &&
        cpu_capacity_perf_events == slots * 2U &&
        control(key, "antidbg-status", response, sizeof(response)) == 0 &&
        std::strstr(response, "perf=0") != nullptr &&
        control(key, "antidbg-physical", response, sizeof(response)) == 0 &&
        std::strstr(response, "antidbg-records=0") != nullptr &&
        std::strstr(response, "monitor-owned=0") != nullptr &&
        std::strstr(response, "mdscr-ss=0") != nullptr;
    errno = 0;
    const int invalid_negative_cpu = static_cast<int>(syscall(
        __NR_perf_event_open, &cpu_capacity_attr, 0, -2, -1, 0UL));
    const int invalid_negative_errno = errno;
    if (invalid_negative_cpu >= 0) close(invalid_negative_cpu);
    errno = 0;
    const int invalid_large_cpu = static_cast<int>(syscall(
        __NR_perf_event_open, &cpu_capacity_attr, 0, CPU_SETSIZE, -1, 0UL));
    const int invalid_large_errno = errno;
    if (invalid_large_cpu >= 0) close(invalid_large_cpu);
    cpu_capacity_ok = cpu_capacity_ok &&
        invalid_negative_cpu == -1 && invalid_negative_errno == EINVAL &&
        invalid_large_cpu == -1 && invalid_large_errno == EINVAL;
    if (!cpu_capacity_ok) {
        std::fprintf(stderr,
                     "antidbg CPU-domain capacity failed: %s opened=%u expected=%u same=%d/%d any=%d/%d wildcard=%d/%d invalid=%d/%d large=%d/%d errno=%d\n",
                     response, cpu_capacity_perf_events, slots * 2U,
                     cpu_same_overflow, cpu_same_overflow_errno,
                     cpu_any_overflow, cpu_any_overflow_errno,
                     cpu_wildcard_overlap, cpu_wildcard_overlap_errno,
                     invalid_negative_cpu, invalid_negative_errno,
                     invalid_large_cpu, invalid_large_errno, errno);
        cleanup();
        return 1;
    }
    std::puts("antidbg-phase=cpu-capacity-pass");

    /* Privileged detectors can request pid=-1,cpu=N and observe every task on
     * one CPU.  Fill two independent CPU-wide ledgers, prove overlap rejects a
     * task event in either direction, then exercise one live wildcard from a
     * forked process which has no Manager grant of its own. */
    unsigned int system_wide_perf_events = 0U;
    unsigned int system_wide_perf_reads = 0U;
    unsigned int system_wide_perf_writes = 0U;
    int system_wide_capacity_fds[2][kMaximumDebugSlots];
    for (auto &domain : system_wide_capacity_fds)
        for (int &fd : domain) fd = -1;
    struct perf_event_attr system_wide_capacity_attr = attr;
    system_wide_capacity_attr.disabled = 1;
    bool system_wide_capacity_ok = true;
    std::puts("antidbg-phase=systemwide-capacity-begin");
    for (unsigned int domain = 0U;
         domain < 2U && system_wide_capacity_ok; ++domain) {
        for (unsigned int index = 0U; index < slots; ++index) {
            system_wide_capacity_attr.bp_addr = fake_address + index * 4UL;
            const int fd = static_cast<int>(syscall(
                __NR_perf_event_open, &system_wide_capacity_attr, -1,
                affinity_cpus[domain], -1, 0UL));
            system_wide_capacity_fds[domain][index] = fd;
            if (fd < 0) {
                system_wide_capacity_ok = false;
                break;
            }
            ++system_wide_perf_events;
        }
    }
    system_wide_capacity_attr.bp_addr = fake_address + slots * 4UL;
    errno = 0;
    const int system_wide_same_overflow = system_wide_capacity_ok
        ? static_cast<int>(syscall(__NR_perf_event_open,
                                   &system_wide_capacity_attr, -1,
                                   affinity_cpus[0], -1, 0UL))
        : -2;
    const int system_wide_same_errno = errno;
    errno = 0;
    const int system_wide_task_a = system_wide_capacity_ok
        ? static_cast<int>(syscall(__NR_perf_event_open,
                                   &system_wide_capacity_attr, 0,
                                   affinity_cpus[0], -1, 0UL))
        : -2;
    const int system_wide_task_a_errno = errno;
    errno = 0;
    const int system_wide_task_b = system_wide_capacity_ok
        ? static_cast<int>(syscall(__NR_perf_event_open,
                                   &system_wide_capacity_attr, 0,
                                   affinity_cpus[1], -1, 0UL))
        : -2;
    const int system_wide_task_b_errno = errno;
    errno = 0;
    const int system_wide_task_any = system_wide_capacity_ok
        ? static_cast<int>(syscall(__NR_perf_event_open,
                                   &system_wide_capacity_attr, 0, -1, -1,
                                   0UL))
        : -2;
    const int system_wide_task_any_errno = errno;
    if (system_wide_same_overflow >= 0) close(system_wide_same_overflow);
    if (system_wide_task_a >= 0) close(system_wide_task_a);
    if (system_wide_task_b >= 0) close(system_wide_task_b);
    if (system_wide_task_any >= 0) close(system_wide_task_any);
    for (auto &domain : system_wide_capacity_fds)
        for (int &fd : domain) {
            if (fd >= 0 && close(fd) != 0) system_wide_capacity_ok = false;
            fd = -1;
        }
    system_wide_capacity_ok = system_wide_capacity_ok &&
        system_wide_same_overflow == -1 &&
        system_wide_same_errno == ENOSPC &&
        system_wide_task_a == -1 && system_wide_task_a_errno == ENOSPC &&
        system_wide_task_b == -1 && system_wide_task_b_errno == ENOSPC &&
        system_wide_task_any == -1 && system_wide_task_any_errno == ENOSPC &&
        system_wide_perf_events == slots * 2U &&
        control(key, "antidbg-status", response, sizeof(response)) == 0 &&
        std::strstr(response, "perf=0") != nullptr &&
        std::strstr(response, "perf-systemwide=0") != nullptr &&
        control(key, "antidbg-physical", response, sizeof(response)) == 0 &&
        std::strstr(response, "antidbg-records=0") != nullptr &&
        std::strstr(response, "monitor-owned=0") != nullptr &&
        std::strstr(response, "mdscr-ss=0") != nullptr;
    if (!system_wide_capacity_ok) {
        std::fprintf(stderr,
                     "antidbg system-wide CPU capacity failed: %s opened=%u expected=%u wildcard=%d/%d task-a=%d/%d task-b=%d/%d task-any=%d/%d errno=%d\n",
                     response, system_wide_perf_events, slots * 2U,
                     system_wide_same_overflow, system_wide_same_errno,
                     system_wide_task_a, system_wide_task_a_errno,
                     system_wide_task_b, system_wide_task_b_errno,
                     system_wide_task_any, system_wide_task_any_errno, errno);
        cleanup();
        return 1;
    }
    std::puts("antidbg-phase=systemwide-capacity-pass");

    bool system_wide_runtime_ok = pin_to_cpu(affinity_cpus[0]);
    struct perf_event_attr system_wide_attr = attr;
    system_wide_attr.disabled = 0;
    system_wide_attr.bp_addr = fake_address;
    const int system_wide_fd = system_wide_runtime_ok
        ? static_cast<int>(syscall(__NR_perf_event_open, &system_wide_attr,
                                   -1, affinity_cpus[1], -1, 0UL))
        : -1;
    std::printf("antidbg-phase=systemwide-open fd=%d cpus=%d/%d\n",
                system_wide_fd, affinity_cpus[0], affinity_cpus[1]);
    if (system_wide_fd >= 0) ++system_wide_perf_events;
    auto read_system_wide_count = [&](std::uint64_t &value) {
        if (system_wide_fd < 0) return false;
        const ssize_t amount = read(system_wide_fd, &value, sizeof(value));
        if (amount != static_cast<ssize_t>(sizeof(value))) return false;
        ++system_wide_perf_reads;
        return true;
    };
    std::uint64_t system_wide_source_count = UINT64_MAX;
    std::uint64_t system_wide_child_count = UINT64_MAX;
    std::uint64_t system_wide_target_count = UINT64_MAX;
    std::uint64_t system_wide_final_count = UINT64_MAX;
    /* An allowed CPU can be offline/idle at open time on Pixel.  The virtual
     * CPU ledger must exist immediately, while the physical comparator is
     * allowed to appear only when a task is next scheduled on that CPU. */
    const bool system_wide_armed = system_wide_fd >= 0 &&
        control(key, "antidbg-status", response, sizeof(response)) == 0 &&
        std::strstr(response, "perf=1") != nullptr &&
        std::strstr(response, "perf-systemwide=1") != nullptr;
    const int system_wide_source_result = system_wide_armed
        ? static_cast<int>(antidbg_fake_target(8)) : -1;
    const bool system_wide_source_quiet = system_wide_source_result == 9 &&
        read_system_wide_count(system_wide_source_count) &&
        system_wide_source_count == 0U;
    std::printf("antidbg-phase=systemwide-source quiet=%u count=%llu\n",
                system_wide_source_quiet ? 1U : 0U,
                static_cast<unsigned long long>(system_wide_source_count));
    const pid_t system_wide_child = system_wide_source_quiet ? fork() : -1;
    if (system_wide_child == 0) {
        if (!pin_to_cpu(affinity_cpus[1])) _exit(90);
        const volatile long result = antidbg_fake_target(8);
        _exit(result == 9 ? 0 : 91);
    }
    int system_wide_child_status = 0;
    const bool system_wide_child_hit = system_wide_child > 0 &&
        waitpid(system_wide_child, &system_wide_child_status, 0) ==
            system_wide_child &&
        WIFEXITED(system_wide_child_status) &&
        WEXITSTATUS(system_wide_child_status) == 0 &&
        read_system_wide_count(system_wide_child_count) &&
        system_wide_child_count == 1U;
    std::printf("antidbg-phase=systemwide-child hit=%u count=%llu\n",
                system_wide_child_hit ? 1U : 0U,
                static_cast<unsigned long long>(system_wide_child_count));
    const bool system_wide_target_armed = system_wide_child_hit &&
        pin_to_cpu(affinity_cpus[1]);
    const int system_wide_target_result = system_wide_target_armed
        ? static_cast<int>(antidbg_fake_target(8)) : -1;
    const bool system_wide_target_hit = system_wide_target_result == 9 &&
        read_system_wide_count(system_wide_target_count) &&
        system_wide_target_count == 2U;
    std::printf("antidbg-phase=systemwide-target hit=%u count=%llu\n",
                system_wide_target_hit ? 1U : 0U,
                static_cast<unsigned long long>(system_wide_target_count));
    const bool system_wide_source_restored = system_wide_target_hit &&
        pin_to_cpu(affinity_cpus[0]);
    const int system_wide_final_result = system_wide_source_restored
        ? static_cast<int>(antidbg_fake_target(8)) : -1;
    const bool system_wide_final_quiet = system_wide_final_result == 9 &&
        read_system_wide_count(system_wide_final_count) &&
        system_wide_final_count == 2U;
    std::printf("antidbg-phase=systemwide-final quiet=%u count=%llu\n",
                system_wide_final_quiet ? 1U : 0U,
                static_cast<unsigned long long>(system_wide_final_count));
    const bool system_wide_disabled = system_wide_fd >= 0 &&
        ioctl(system_wide_fd, PERF_EVENT_IOC_DISABLE, 0UL) == 0;
    std::printf("antidbg-phase=systemwide-disable ok=%u\n",
                system_wide_disabled ? 1U : 0U);
    if (system_wide_disabled) ++system_wide_perf_writes;
    const bool system_wide_physical_empty = system_wide_disabled &&
        control(key, "antidbg-physical", response, sizeof(response)) == 0 &&
        std::strstr(response, "antidbg-records=0") != nullptr &&
        std::strstr(response, "antidbg-enabled=0") != nullptr &&
        std::strstr(response, "monitor-owned=0") != nullptr &&
        std::strstr(response, "mdscr-ss=0") != nullptr;
    const int system_wide_close = system_wide_fd >= 0
        ? close(system_wide_fd) : -1;
    const int system_wide_affinity_restore = sched_setaffinity(
        0, sizeof(original_affinity), &original_affinity);
    system_wide_runtime_ok = system_wide_source_quiet &&
        system_wide_child_hit && system_wide_target_hit &&
        system_wide_final_quiet && system_wide_physical_empty &&
        system_wide_close == 0 && system_wide_affinity_restore == 0 &&
        system_wide_perf_events == slots * 2U + 1U &&
        system_wide_perf_reads == 4U && system_wide_perf_writes == 1U &&
        control(key, "antidbg-status", response, sizeof(response)) == 0 &&
        std::strstr(response, "perf=0") != nullptr &&
        std::strstr(response, "perf-systemwide=0") != nullptr;
    if (!system_wide_runtime_ok) {
        if (system_wide_child > 0 && !WIFEXITED(system_wide_child_status) &&
            !WIFSIGNALED(system_wide_child_status)) {
            (void)kill(system_wide_child, SIGKILL);
            (void)waitpid(system_wide_child, nullptr, 0);
        }
        if (system_wide_fd >= 0 && system_wide_close != 0)
            close(system_wide_fd);
        (void)sched_setaffinity(0, sizeof(original_affinity),
                                &original_affinity);
        std::fprintf(stderr,
                     "antidbg system-wide runtime failed: %s cpus=%d/%d fd=%d armed=%u source=%d/%llu child=%ld status=0x%x count=%llu target=%d/%llu final=%d/%llu reads=%u writes=%u close=%d restore=%d errno=%d\n",
                     response, affinity_cpus[0], affinity_cpus[1],
                     system_wide_fd, system_wide_armed ? 1U : 0U,
                     system_wide_source_result,
                     static_cast<unsigned long long>(system_wide_source_count),
                     static_cast<long>(system_wide_child),
                     system_wide_child_status,
                     static_cast<unsigned long long>(system_wide_child_count),
                     system_wide_target_result,
                     static_cast<unsigned long long>(system_wide_target_count),
                     system_wide_final_result,
                     static_cast<unsigned long long>(system_wide_final_count),
                     system_wide_perf_reads, system_wide_perf_writes,
                     system_wide_close, system_wide_affinity_restore, errno);
        cleanup();
        return 1;
    }

    /* Exercise the privileged-detector shape in a distinct TGID/mm.  A root
     * helper is explicitly granted by the Manager, then opens pid=-1,cpu=N
     * events from its own address space.  The first round proves that wildcard
     * capacity is global per CPU (one slot owned by this process plus the
     * remaining slots owned by the helper).  The second round proves that the
     * helper-owned event observes another process on the selected CPU.  Finally
     * revoke the helper while its fd is alive: the existing fd retains normal
     * perf lifetime, while a new open must pass through the native kernel and
     * must not enter the virtual ledger. */
    struct RootDetectorReport final {
        unsigned int phase = 0U;
        int result = -1;
        int saved_errno = 0;
        std::uint64_t count = UINT64_MAX;
    };
    int root_command_pipe[2] = {-1, -1};
    int root_report_pipe[2] = {-1, -1};
    if (pipe2(root_command_pipe, O_CLOEXEC) != 0 ||
        pipe2(root_report_pipe, O_CLOEXEC) != 0) {
        std::perror("antidbg root-detector pipe");
        for (int fd : root_command_pipe) if (fd >= 0) close(fd);
        for (int fd : root_report_pipe) if (fd >= 0) close(fd);
        cleanup();
        return 1;
    }
    const pid_t root_detector = fork();
    if (root_detector == 0) {
        close(root_command_pipe[1]);
        close(root_report_pipe[0]);
        auto send_report = [&](const RootDetectorReport &report) {
            ssize_t amount = -1;
            do {
                amount = write(root_report_pipe[1], &report, sizeof(report));
            } while (amount < 0 && errno == EINTR);
            return amount == static_cast<ssize_t>(sizeof(report));
        };
        auto receive_command = [&]() {
            char command_byte = 0;
            ssize_t amount = -1;
            do {
                amount = read(root_command_pipe[0], &command_byte,
                              sizeof(command_byte));
            } while (amount < 0 && errno == EINTR);
            return amount == 1 ? command_byte : '\0';
        };
        rtgum_su_profile root_profile{};
        root_profile.uid = static_cast<std::uint32_t>(getuid());
        root_profile.to_uid = 0U;
        const long elevate_status = rtgum_sc_su(key, &root_profile);
        const int root_identity = elevate_status == 0 && getuid() == 0 &&
                geteuid() == 0
            ? 0 : static_cast<int>(geteuid());
        if (prctl(PR_SET_NAME, kManagerProbePackage, 0, 0, 0) != 0 ||
            !send_report({1U, root_identity,
                          static_cast<int>(elevate_status), 0U}))
            _exit(100);
        if (receive_command() != 'C' || !pin_to_cpu(affinity_cpus[0]))
            _exit(101);

        struct perf_event_attr capacity_attr = attr;
        capacity_attr.disabled = 1;
        int capacity_fds[kMaximumDebugSlots];
        for (int &fd : capacity_fds) fd = -1;
        unsigned int capacity_opened = 0U;
        for (; capacity_opened + 1U < slots; ++capacity_opened) {
            capacity_attr.bp_addr = fake_address +
                static_cast<unsigned long>(capacity_opened + 1U) * 4UL;
            const int fd = static_cast<int>(syscall(
                __NR_perf_event_open, &capacity_attr, -1,
                affinity_cpus[1], -1, 0UL));
            capacity_fds[capacity_opened] = fd;
            if (fd < 0) break;
        }
        capacity_attr.bp_addr = fake_address +
            static_cast<unsigned long>(slots) * 4UL;
        errno = 0;
        const int overflow_fd = static_cast<int>(syscall(
            __NR_perf_event_open, &capacity_attr, -1,
            affinity_cpus[1], -1, 0UL));
        const int overflow_errno = errno;
        if (overflow_fd >= 0) close(overflow_fd);
        for (int fd : capacity_fds) if (fd >= 0) close(fd);
        if (!send_report({2U, static_cast<int>(capacity_opened),
                          overflow_errno,
                          overflow_fd < 0 ? UINT64_C(0) : UINT64_C(1)}))
            _exit(102);

        if (receive_command() != 'A') _exit(103);
        struct perf_event_attr active_attr = attr;
        active_attr.disabled = 0;
        active_attr.bp_addr = fake_address;
        errno = 0;
        const int active_fd = static_cast<int>(syscall(
            __NR_perf_event_open, &active_attr, -1,
            affinity_cpus[1], -1, 0UL));
        const int active_errno = errno;
        std::uint64_t before_count = UINT64_MAX;
        const bool before_read = active_fd >= 0 &&
            read(active_fd, &before_count, sizeof(before_count)) ==
                static_cast<ssize_t>(sizeof(before_count));
        if (!send_report({3U, active_fd >= 0 && before_read ? 0 : -1,
                          active_errno, before_count}))
            _exit(104);

        if (receive_command() != 'H') _exit(105);
        std::uint64_t after_count = UINT64_MAX;
        const bool after_read = active_fd >= 0 &&
            read(active_fd, &after_count, sizeof(after_count)) ==
                static_cast<ssize_t>(sizeof(after_count));
        if (!send_report({4U, after_read ? 0 : -1, errno, after_count}))
            _exit(106);

        if (receive_command() != 'U') _exit(107);
        struct perf_event_attr unauthorized_attr = attr;
        unauthorized_attr.disabled = 1;
        unauthorized_attr.bp_addr = fake_address + 4UL;
        errno = 0;
        const int unauthorized_fd = static_cast<int>(syscall(
            __NR_perf_event_open, &unauthorized_attr, -1,
            affinity_cpus[1], -1, 0UL));
        const int unauthorized_errno = errno;
        if (unauthorized_fd >= 0) close(unauthorized_fd);
        std::uint64_t retained_count = UINT64_MAX;
        const bool retained_read = active_fd >= 0 &&
            read(active_fd, &retained_count, sizeof(retained_count)) ==
                static_cast<ssize_t>(sizeof(retained_count));
        if (active_fd >= 0) close(active_fd);
        if (!send_report({5U, unauthorized_fd, unauthorized_errno,
                          retained_read ? retained_count : UINT64_MAX}))
            _exit(108);
        close(root_command_pipe[0]);
        close(root_report_pipe[1]);
        _exit(retained_read && retained_count == 1U ? 0 : 109);
    }
    close(root_command_pipe[0]);
    root_command_pipe[0] = -1;
    close(root_report_pipe[1]);
    root_report_pipe[1] = -1;
    auto root_write_command = [&](char value) {
        ssize_t amount = -1;
        do {
            amount = write(root_command_pipe[1], &value, sizeof(value));
        } while (amount < 0 && errno == EINTR);
        return amount == 1;
    };
    auto root_read_report = [&](RootDetectorReport &report) {
        struct pollfd descriptor{root_report_pipe[0], POLLIN, 0};
        const int ready = poll(&descriptor, 1, 10000);
        if (ready != 1 || (descriptor.revents & (POLLIN | POLLHUP)) == 0)
            return false;
        ssize_t amount = -1;
        do {
            amount = read(root_report_pipe[0], &report, sizeof(report));
        } while (amount < 0 && errno == EINTR);
        return amount == static_cast<ssize_t>(sizeof(report));
    };
    bool root_detector_reaped = false;
    auto root_detector_cleanup = [&]() {
        if (root_command_pipe[1] >= 0) close(root_command_pipe[1]);
        if (root_report_pipe[0] >= 0) close(root_report_pipe[0]);
        root_command_pipe[1] = root_report_pipe[0] = -1;
        if (root_detector > 0 && !root_detector_reaped) {
            (void)kill(root_detector, SIGKILL);
            (void)waitpid(root_detector, nullptr, 0);
            root_detector_reaped = true;
        }
    };
    RootDetectorReport root_report{};
    if (root_detector <= 0 || !root_read_report(root_report) ||
        root_report.phase != 1U || root_report.result != 0) {
        std::fprintf(stderr,
                     "antidbg root-detector did not start as root pid=%ld phase=%u euid=%d errno=%d\n",
                     static_cast<long>(root_detector), root_report.phase,
                     root_report.result, root_report.saved_errno);
        root_detector_cleanup();
        cleanup();
        return 1;
    }
    std::snprintf(command, sizeof(command), "antidbg-authorize %ld",
                  static_cast<long>(root_detector));
    if (control(key, command, response, sizeof(response)) != 0 ||
        std::strstr(response, "policy=manager") == nullptr ||
        std::strstr(response, "grants=2") == nullptr) {
        std::fprintf(stderr, "root-detector Manager grant failed: %s\n",
                     response);
        root_detector_cleanup();
        cleanup();
        return 1;
    }
    std::snprintf(command, sizeof(command), "antidbg-policy %ld",
                  static_cast<long>(root_detector));
    if (control(key, command, response, sizeof(response)) != 0 ||
        std::strstr(response, "policy=manager") == nullptr) {
        std::fprintf(stderr, "root-detector policy lookup failed: %s\n",
                     response);
        root_detector_cleanup();
        cleanup();
        return 1;
    }

    struct perf_event_attr shared_capacity_attr = attr;
    shared_capacity_attr.disabled = 1;
    shared_capacity_attr.bp_addr = fake_address;
    const int shared_capacity_fd = static_cast<int>(syscall(
        __NR_perf_event_open, &shared_capacity_attr, -1,
        affinity_cpus[1], -1, 0UL));
    if (shared_capacity_fd < 0 || !root_write_command('C') ||
        !root_read_report(root_report) || root_report.phase != 2U ||
        root_report.result != static_cast<int>(slots - 1U) ||
        root_report.saved_errno != ENOSPC || root_report.count != 0U) {
        std::fprintf(stderr,
                     "root-detector shared wildcard capacity failed fd=%d phase=%u opened=%d expected=%u overflow-errno=%d marker=%llu\n",
                     shared_capacity_fd, root_report.phase, root_report.result,
                     slots - 1U, root_report.saved_errno,
                     static_cast<unsigned long long>(root_report.count));
        if (shared_capacity_fd >= 0) close(shared_capacity_fd);
        root_detector_cleanup();
        cleanup();
        return 1;
    }
    close(shared_capacity_fd);
    system_wide_perf_events += slots;

    if (!root_write_command('A') || !root_read_report(root_report) ||
        root_report.phase != 3U || root_report.result != 0 ||
        root_report.count != 0U) {
        std::fprintf(stderr,
                     "root-detector wildcard open failed phase=%u result=%d errno=%d count=%llu\n",
                     root_report.phase, root_report.result,
                     root_report.saved_errno,
                     static_cast<unsigned long long>(root_report.count));
        root_detector_cleanup();
        cleanup();
        return 1;
    }
    ++system_wide_perf_events;
    ++system_wide_perf_reads;
    const bool root_target_pinned = pin_to_cpu(affinity_cpus[1]);
    const int root_target_result = root_target_pinned
        ? static_cast<int>(antidbg_fake_target(8)) : -1;
    const int root_affinity_restore = sched_setaffinity(
        0, sizeof(original_affinity), &original_affinity);
    if (!root_write_command('H') || !root_read_report(root_report) ||
        root_report.phase != 4U || root_report.result != 0 ||
        root_report.count != 1U || root_target_result != 9 ||
        root_affinity_restore != 0) {
        std::fprintf(stderr,
                     "root-detector cross-process wildcard hit failed phase=%u result=%d count=%llu target=%d restore=%d\n",
                     root_report.phase, root_report.result,
                     static_cast<unsigned long long>(root_report.count),
                     root_target_result, root_affinity_restore);
        root_detector_cleanup();
        cleanup();
        return 1;
    }
    ++system_wide_perf_reads;

    std::snprintf(command, sizeof(command), "antidbg-revoke %ld",
                  static_cast<long>(root_detector));
    if (control(key, command, response, sizeof(response)) != 0 ||
        std::strstr(response, "revoked=1") == nullptr ||
        std::strstr(response, "grants=1") == nullptr) {
        std::fprintf(stderr, "root-detector revoke failed: %s\n", response);
        root_detector_cleanup();
        cleanup();
        return 1;
    }
    std::snprintf(command, sizeof(command), "antidbg-policy %ld",
                  static_cast<long>(root_detector));
    if (control(key, command, response, sizeof(response)) != 0 ||
        std::strstr(response, "policy=denied") == nullptr ||
        !root_write_command('U') || !root_read_report(root_report) ||
        root_report.phase != 5U || root_report.count != 1U) {
        std::fprintf(stderr,
                     "root-detector revoke/pass-through failed response=%s phase=%u native-fd=%d native-errno=%d retained=%llu\n",
                     response, root_report.phase, root_report.result,
                     root_report.saved_errno,
                     static_cast<unsigned long long>(root_report.count));
        root_detector_cleanup();
        cleanup();
        return 1;
    }
    ++system_wide_perf_reads;
    int root_detector_status = 0;
    const pid_t root_wait = waitpid(root_detector, &root_detector_status, 0);
    root_detector_reaped = root_wait == root_detector;
    if (!root_detector_reaped || !WIFEXITED(root_detector_status) ||
        WEXITSTATUS(root_detector_status) != 0 ||
        control(key, "antidbg-status", response, sizeof(response)) != 0 ||
        std::strstr(response, "perf-systemwide=0") == nullptr ||
        std::strstr(response, "manager-grants=1") == nullptr ||
        std::strstr(response, "grant-mm-get=2") == nullptr ||
        std::strstr(response, "grant-mm-put=1") == nullptr) {
        std::fprintf(stderr,
                     "root-detector wildcard cleanup failed wait=%ld status=0x%x response=%s\n",
                     static_cast<long>(root_wait), root_detector_status,
                     response);
        root_detector_cleanup();
        cleanup();
        return 1;
    }
    root_detector_cleanup();
    std::printf("antidbg-phase=root-detector-wildcard-pass pid=%ld cpus=%d/%d shared-capacity=%u hit=1 revoke=1 native-open=%d/%d\n",
                static_cast<long>(root_detector), affinity_cpus[0],
                affinity_cpus[1], slots, root_report.result,
                root_report.saved_errno);

    /* A perf fd is allowed to outlive its monitored task. Keep the inert
     * kernel event usable while the virtual target identity is marked dead,
     * and prove the exit hook removed every CPU-local comparator before the
     * final file reference is closed. */
    int exit_pipe[2] = {-1, -1};
    if (pipe2(exit_pipe, O_CLOEXEC) != 0) {
        std::fprintf(stderr, "antidbg target-exit pipe failed errno=%d\n", errno);
        cleanup();
        return 1;
    }
    const pid_t perf_exit_child = fork();
    if (perf_exit_child == 0) {
        close(exit_pipe[1]);
        (void)prctl(PR_SET_NAME, "rtgum-perfexit", 0, 0, 0);
        char release = 0;
        ssize_t amount = -1;
        do {
            amount = read(exit_pipe[0], &release, sizeof(release));
        } while (amount < 0 && errno == EINTR);
        close(exit_pipe[0]);
        _exit(amount == 1 ? 0 : 81);
    }
    close(exit_pipe[0]);
    exit_pipe[0] = -1;
    struct perf_event_attr exit_attr = attr;
    exit_attr.disabled = 1;
    const int target_exit_fd = perf_exit_child > 0
        ? static_cast<int>(syscall(__NR_perf_event_open, &exit_attr,
                                   perf_exit_child, -1, -1, 0UL))
        : -1;
    char release = 'X';
    const bool released = perf_exit_child > 0 && target_exit_fd >= 0 &&
        write(exit_pipe[1], &release, sizeof(release)) == 1;
    close(exit_pipe[1]);
    exit_pipe[1] = -1;
    int perf_exit_status = 0;
    const bool target_exited = released &&
        waitpid(perf_exit_child, &perf_exit_status, 0) == perf_exit_child &&
        WIFEXITED(perf_exit_status) && WEXITSTATUS(perf_exit_status) == 0;
    if (!target_exited || !verify_perf_fd(target_exit_fd)) {
        if (target_exit_fd >= 0) close(target_exit_fd);
        if (perf_exit_child > 0 && !target_exited) {
            (void)kill(perf_exit_child, SIGKILL);
            (void)waitpid(perf_exit_child, nullptr, 0);
        }
        std::fprintf(stderr,
                     "antidbg target-exit fd lifetime failed fd=%d status=0x%x errno=%d\n",
                     target_exit_fd, perf_exit_status, errno);
        cleanup();
        return 1;
    }
    if (control(key, "antidbg-status", response, sizeof(response)) != 0 ||
        std::strstr(response, "perf=1") == nullptr ||
        control(key, "antidbg-physical", response, sizeof(response)) != 0 ||
        std::strstr(response, "antidbg-records=0") == nullptr ||
        std::strstr(response, "untracked-brk=0") == nullptr ||
        std::strstr(response, "untracked-watch=0") == nullptr ||
        std::strstr(response, "monitor-owned=0") == nullptr ||
        std::strstr(response, "mdscr-ss=0") == nullptr) {
        close(target_exit_fd);
        std::fprintf(stderr,
                     "antidbg target-exit physical cleanup failed: %s\n",
                     response);
        cleanup();
        return 1;
    }
    if (close(target_exit_fd) != 0 ||
        control(key, "antidbg-status", response, sizeof(response)) != 0 ||
        std::strstr(response, "perf=0") == nullptr) {
        std::fprintf(stderr,
                     "antidbg target-exit final fd release failed: %s errno=%d\n",
                     response, errno);
        cleanup();
        return 1;
    }

    /* Exercise perf's event inheritance rather than merely inheriting the fd
     * table. The child owns a distinct kernel perf_event and therefore needs
     * its own virtual ledger entry; child exit must free only that entry while
     * the parent's event remains usable. */
    struct perf_event_attr inherit_attr = attr;
    inherit_attr.disabled = 1;
    inherit_attr.inherit = 1;
    const int inherit_fd = static_cast<int>(syscall(
        __NR_perf_event_open, &inherit_attr, 0, -1, -1, 0UL));
    int inherit_pipe[2] = {-1, -1};
    if (inherit_fd < 0 || !verify_perf_fd(inherit_fd) ||
        pipe2(inherit_pipe, O_CLOEXEC) != 0) {
        if (inherit_fd >= 0) close(inherit_fd);
        std::fprintf(stderr,
                     "antidbg inherited-event setup failed fd=%d errno=%d\n",
                     inherit_fd, errno);
        cleanup();
        return 1;
    }
    const pid_t inherit_child = fork();
    if (inherit_child == 0) {
        close(inherit_pipe[1]);
        (void)prctl(PR_SET_NAME, "rtgum-inherit", 0, 0, 0);
        char release_child = 0;
        ssize_t amount = -1;
        do {
            amount = read(inherit_pipe[0], &release_child,
                          sizeof(release_child));
        } while (amount < 0 && errno == EINTR);
        close(inherit_pipe[0]);
        _exit(amount == 1 ? 0 : 84);
    }
    close(inherit_pipe[0]);
    inherit_pipe[0] = -1;
    const bool inherit_registered = inherit_child > 0 &&
        control(key, "antidbg-status", response, sizeof(response)) == 0 &&
        std::strstr(response, "perf=2") != nullptr &&
        std::strstr(response, "perf-inherit=1") != nullptr;
    char release_child = 'I';
    const bool inherit_released = inherit_child > 0 &&
        write(inherit_pipe[1], &release_child, sizeof(release_child)) == 1;
    close(inherit_pipe[1]);
    inherit_pipe[1] = -1;
    int inherit_status = 0;
    const bool inherit_reaped = inherit_child > 0 &&
        waitpid(inherit_child, &inherit_status, 0) == inherit_child;
    const bool inherit_child_ok = inherit_reaped && WIFEXITED(inherit_status) &&
        WEXITSTATUS(inherit_status) == 0;
    const bool inherit_parent_remains = inherit_child_ok &&
        control(key, "antidbg-status", response, sizeof(response)) == 0 &&
        std::strstr(response, "perf=1") != nullptr &&
        std::strstr(response, "perf-inherit=1") != nullptr &&
        std::strstr(response, "perf-inherit-bind=1") != nullptr &&
        std::strstr(response, "perf-inherit-exit=1") != nullptr;
    const bool inherit_ok = inherit_registered && inherit_released &&
        inherit_parent_remains;
    if (!inherit_ok || close(inherit_fd) != 0 ||
        control(key, "antidbg-status", response, sizeof(response)) != 0 ||
        std::strstr(response, "perf=0") == nullptr) {
        if (!inherit_reaped && inherit_child > 0) {
            (void)kill(inherit_child, SIGKILL);
            (void)waitpid(inherit_child, nullptr, 0);
        }
        if (!inherit_ok) close(inherit_fd);
        std::fprintf(stderr,
                     "antidbg inherited-event lifecycle failed: %s status=0x%x errno=%d\n",
                     response, inherit_status, errno);
        cleanup();
        return 1;
    }

    /* Now exercise the behavioral half of inheritance.  The parent owns an
     * enabled sigtrap breakpoint, fork creates a distinct child perf_event,
     * and the child must receive the same breakpoint ABI after its deferred
     * task/TID binding on first schedule. */
    constexpr std::uint64_t kInheritSigData =
        UINT64_C(0x525447494e480002);
    struct sigaction inherit_action {};
    struct sigaction inherit_previous {};
    inherit_action.sa_sigaction = antidbg_inherit_signal_handler;
    inherit_action.sa_flags = SA_SIGINFO;
    sigemptyset(&inherit_action.sa_mask);
    struct perf_event_attr active_inherit_attr = attr;
    active_inherit_attr.disabled = 0;
    active_inherit_attr.inherit = 1;
    active_inherit_attr.remove_on_exec = 1;
    active_inherit_attr.sigtrap = 1;
    active_inherit_attr.sample_period = 1;
    active_inherit_attr.sig_data = kInheritSigData;
    auto status_value = [](const char *text, const char *field,
                           unsigned long &value) {
        if (!text || !field || !*field) return false;
        char needle[64]{};
        if (std::snprintf(needle, sizeof(needle), "%s=", field) <= 0)
            return false;
        const char *cursor = text;
        while ((cursor = std::strstr(cursor, needle)) != nullptr) {
            if (cursor == text || cursor[-1] == ' ') {
                char *end = nullptr;
                errno = 0;
                const unsigned long parsed = std::strtoul(
                    cursor + std::strlen(needle), &end, 0);
                if (errno == 0 && end && end != cursor + std::strlen(needle)) {
                    value = parsed;
                    return true;
                }
            }
            cursor += std::strlen(needle);
        }
        return false;
    };
    char active_diag_before[kControlBufferSize]{};
    char active_diag_after[kControlBufferSize]{};
    char active_inherit_diag[kControlBufferSize]{};
    unsigned long active_open_before = 0;
    unsigned long active_perf_before = 0;
    const bool active_baseline_ok =
        control(key, "antidbg-status", response, sizeof(response)) == 0 &&
        status_value(response, "perf_open", active_open_before) &&
        status_value(response, "perf", active_perf_before) &&
        control(key, "antidbg-perf-diag", active_diag_before,
                sizeof(active_diag_before)) == 0 &&
        control(key, "antidbg-inherit-diag", active_inherit_diag,
                sizeof(active_inherit_diag)) == 0;
    int active_inherit_pipe[2] = {-1, -1};
    int active_start_pipe[2] = {-1, -1};
    const bool active_signal_installed =
        sigaction(SIGTRAP, &inherit_action, &inherit_previous) == 0;
    const int active_inherit_fd = active_baseline_ok && active_signal_installed
        ? static_cast<int>(syscall(__NR_perf_event_open,
                                   &active_inherit_attr, 0, -1, -1, 0UL))
        : -1;
    unsigned long active_open_after = 0;
    unsigned long active_perf_after = 0;
    const bool active_virtualized = active_inherit_fd >= 0 &&
        control(key, "antidbg-status", response, sizeof(response)) == 0 &&
        status_value(response, "perf_open", active_open_after) &&
        status_value(response, "perf", active_perf_after) &&
        control(key, "antidbg-perf-diag", active_diag_after,
                sizeof(active_diag_after)) == 0 &&
        active_open_after == active_open_before + 1UL &&
        active_perf_after == active_perf_before + 1UL &&
        std::strstr(active_diag_after, "stage-name=converted") != nullptr;
    if (!active_virtualized) {
        const int saved_errno = errno;
        if (active_inherit_fd >= 0) close(active_inherit_fd);
        if (active_signal_installed)
            (void)sigaction(SIGTRAP, &inherit_previous, nullptr);
        std::fprintf(stderr,
                     "antidbg active inherited event was not virtualized: fd=%d baseline=%u signal=%u open=%lu->%lu perf=%lu->%lu before=[%s] after=[%s] status=[%s] errno=%d\n",
                     active_inherit_fd, active_baseline_ok ? 1U : 0U,
                     active_signal_installed ? 1U : 0U,
                     active_open_before, active_open_after,
                     active_perf_before, active_perf_after,
                     active_diag_before, active_diag_after, response,
                     saved_errno);
        cleanup();
        return 1;
    }
    const bool active_pipe_ok = active_inherit_fd >= 0 &&
        pipe2(active_inherit_pipe, O_CLOEXEC) == 0 &&
        pipe2(active_start_pipe, O_CLOEXEC) == 0;
    struct ActiveInheritReport final {
        int result;
        int hits;
        int code;
        int type;
        int disable_result;
        int reserved;
        std::uint64_t address;
        std::uint64_t data;
    } active_report{};
    const pid_t active_inherit_child = active_pipe_ok ? fork() : -1;
    if (active_inherit_child == 0) {
        close(active_inherit_pipe[0]);
        close(active_start_pipe[1]);
        char start = 0;
        ssize_t start_read = -1;
        do {
            start_read = read(active_start_pipe[0], &start, sizeof(start));
        } while (start_read < 0 && errno == EINTR);
        close(active_start_pipe[0]);
        if (start_read != 1 || start != 'G') _exit(86);
        antidbg_inherit_signal_hits = 0;
        antidbg_inherit_signal_code = 0;
        antidbg_inherit_signal_type = 0;
        antidbg_inherit_disable_result = -1;
        antidbg_inherit_signal_address = 0;
        antidbg_inherit_signal_data = 0;
        active_report.result = static_cast<int>(antidbg_fake_target(8));
        active_report.hits = antidbg_inherit_signal_hits;
        active_report.code = antidbg_inherit_signal_code;
        active_report.type = antidbg_inherit_signal_type;
        active_report.disable_result = antidbg_inherit_disable_result;
        active_report.address = antidbg_inherit_signal_address;
        active_report.data = antidbg_inherit_signal_data;
        const ssize_t written = write(active_inherit_pipe[1], &active_report,
                                      sizeof(active_report));
        close(active_inherit_pipe[1]);
        _exit(written == static_cast<ssize_t>(sizeof(active_report)) ? 0 : 85);
    }
    if (active_inherit_pipe[1] >= 0) close(active_inherit_pipe[1]);
    active_inherit_pipe[1] = -1;
    if (active_start_pipe[0] >= 0) close(active_start_pipe[0]);
    active_start_pipe[0] = -1;
    bool active_child_registered = false;
    if (active_inherit_child > 0) {
        for (unsigned int attempt = 0; attempt < 100U; ++attempt) {
            unsigned long active_perf_slots = 0;
            if (control(key, "antidbg-status", response, sizeof(response)) == 0 &&
                status_value(response, "perf", active_perf_slots) &&
                active_perf_slots == active_perf_before + 2UL &&
                std::strstr(response, "perf-inherit=2") != nullptr &&
                std::strstr(response, "perf-inherit-bind=2") != nullptr &&
                control(key, "antidbg-inherit-diag", active_inherit_diag,
                        sizeof(active_inherit_diag)) == 0 &&
                std::strstr(active_inherit_diag,
                            "stage-name=created") != nullptr) {
                active_child_registered = true;
                break;
            }
            usleep(10000);
        }
    }
    const char active_start = 'G';
    const bool active_child_released = active_child_registered &&
        active_start_pipe[1] >= 0 &&
        write(active_start_pipe[1], &active_start, sizeof(active_start)) == 1;
    if (active_start_pipe[1] >= 0) close(active_start_pipe[1]);
    active_start_pipe[1] = -1;
    ssize_t active_read = -1;
    if (active_child_released && active_inherit_child > 0) {
        do {
            active_read = read(active_inherit_pipe[0], &active_report,
                               sizeof(active_report));
        } while (active_read < 0 && errno == EINTR);
    }
    if (active_inherit_pipe[0] >= 0) close(active_inherit_pipe[0]);
    active_inherit_pipe[0] = -1;
    int active_inherit_status = 0;
    const bool active_inherit_reaped = active_inherit_child > 0 &&
        waitpid(active_inherit_child, &active_inherit_status, 0) ==
            active_inherit_child;
    const bool active_inherit_ok = active_pipe_ok && active_child_registered &&
        active_child_released && active_inherit_reaped &&
        WIFEXITED(active_inherit_status) &&
        WEXITSTATUS(active_inherit_status) == 0 &&
        active_read == static_cast<ssize_t>(sizeof(active_report)) &&
        active_report.result == 9 && active_report.hits == 1 &&
        active_report.disable_result == 0 &&
        active_report.code == TRAP_PERF &&
        active_report.type == PERF_TYPE_BREAKPOINT &&
        active_report.address == fake_address &&
        active_report.data == kInheritSigData;
    const int active_close = active_inherit_fd >= 0
        ? close(active_inherit_fd) : -1;
    const int restore_signal = active_signal_installed
        ? sigaction(SIGTRAP, &inherit_previous, nullptr) : -1;
    const bool active_post_status_ok =
        control(key, "antidbg-status", response, sizeof(response)) == 0;
    (void)control(key, "antidbg-inherit-diag", active_inherit_diag,
                  sizeof(active_inherit_diag));
    if (!active_inherit_ok || active_close != 0 || restore_signal != 0 ||
        !active_post_status_ok ||
        std::strstr(response, "perf=0") == nullptr ||
        std::strstr(response, "perf-inherit=2") == nullptr ||
        std::strstr(response, "perf-inherit-bind=2") == nullptr ||
        std::strstr(response, "perf-inherit-exit=2") == nullptr) {
        if (!active_inherit_reaped && active_inherit_child > 0) {
            (void)kill(active_inherit_child, SIGKILL);
            (void)waitpid(active_inherit_child, nullptr, 0);
        }
        if (active_inherit_fd >= 0 && active_close != 0)
            close(active_inherit_fd);
        (void)sigaction(SIGTRAP, &inherit_previous, nullptr);
        std::fprintf(stderr,
                     "antidbg active inherited event failed: %s inherit=[%s] registered=%u released=%u status=0x%x read=%zd result=%d hits=%d disable=%d code=%d type=%d addr=0x%llx data=0x%llx errno=%d\n",
                     response, active_inherit_diag,
                     active_child_registered ? 1U : 0U,
                     active_child_released ? 1U : 0U,
                     active_inherit_status, active_read,
                     active_report.result, active_report.hits,
                     active_report.disable_result,
                     active_report.code, active_report.type,
                     static_cast<unsigned long long>(active_report.address),
                     static_cast<unsigned long long>(active_report.data), errno);
        cleanup();
        return 1;
    }

    /* inherit_thread is a distinct ABI promise: the event follows CLONE_THREAD
     * children but must not follow an ordinary fork.  The backing SW_DUMMY
     * event performs the kernel's clone_flags filtering; this test proves the
     * virtual ledger observes exactly the same inherited-event set. */
    struct perf_event_attr inherit_thread_attr = attr;
    inherit_thread_attr.disabled = 1;
    inherit_thread_attr.inherit = 1;
    inherit_thread_attr.inherit_thread = 1;
    const int inherit_thread_fd = static_cast<int>(syscall(
        __NR_perf_event_open, &inherit_thread_attr, 0, -1, -1, 0UL));
    if (inherit_thread_fd < 0 || !verify_perf_fd(inherit_thread_fd)) {
        if (inherit_thread_fd >= 0) close(inherit_thread_fd);
        std::fprintf(stderr,
                     "antidbg inherit-thread root setup failed fd=%d errno=%d\n",
                     inherit_thread_fd, errno);
        cleanup();
        return 1;
    }

    const pid_t inherit_thread_fork = fork();
    if (inherit_thread_fork == 0) _exit(0);
    int inherit_thread_fork_status = 0;
    const bool fork_not_inherited = inherit_thread_fork > 0 &&
        waitpid(inherit_thread_fork, &inherit_thread_fork_status, 0) ==
            inherit_thread_fork &&
        WIFEXITED(inherit_thread_fork_status) &&
        WEXITSTATUS(inherit_thread_fork_status) == 0 &&
        control(key, "antidbg-status", response, sizeof(response)) == 0 &&
        std::strstr(response, "perf=1") != nullptr &&
        std::strstr(response, "perf-inherit=2") != nullptr &&
        std::strstr(response, "perf-inherit-exit=2") != nullptr;

    struct InheritThreadContext final {
        int ready_write;
        int release_read;
    } inherit_thread_context{};
    int inherit_thread_ready[2] = {-1, -1};
    int inherit_thread_release[2] = {-1, -1};
    pthread_t inherit_thread{};
    bool inherit_thread_created = false;
    if (fork_not_inherited &&
        pipe2(inherit_thread_ready, O_CLOEXEC) == 0 &&
        pipe2(inherit_thread_release, O_CLOEXEC) == 0) {
        inherit_thread_context.ready_write = inherit_thread_ready[1];
        inherit_thread_context.release_read = inherit_thread_release[0];
        inherit_thread_created = pthread_create(
            &inherit_thread, nullptr,
            [](void *opaque) -> void * {
                auto *context = static_cast<InheritThreadContext *>(opaque);
                const char ready = 'R';
                char release = 0;
                (void)write(context->ready_write, &ready, sizeof(ready));
                ssize_t amount = -1;
                do {
                    amount = read(context->release_read, &release,
                                  sizeof(release));
                } while (amount < 0 && errno == EINTR);
                return reinterpret_cast<void *>(
                    static_cast<uintptr_t>(amount == 1 ? 0U : 1U));
            },
            &inherit_thread_context) == 0;
    }
    char inherit_thread_ready_byte = 0;
    const bool thread_inherited = inherit_thread_created &&
        read(inherit_thread_ready[0], &inherit_thread_ready_byte,
             sizeof(inherit_thread_ready_byte)) == 1 &&
        inherit_thread_ready_byte == 'R' &&
        control(key, "antidbg-status", response, sizeof(response)) == 0 &&
        std::strstr(response, "perf=2") != nullptr &&
        std::strstr(response, "perf-inherit=3") != nullptr &&
        std::strstr(response, "perf-inherit-bind=3") != nullptr;
    const char release_inherit_thread = 'X';
    const bool thread_released = inherit_thread_created &&
        write(inherit_thread_release[1], &release_inherit_thread,
              sizeof(release_inherit_thread)) == 1;
    void *inherit_thread_result = reinterpret_cast<void *>(1UL);
    const bool thread_joined = inherit_thread_created &&
        pthread_join(inherit_thread, &inherit_thread_result) == 0 &&
        inherit_thread_result == nullptr;
    const bool thread_retired = thread_joined &&
        control(key, "antidbg-status", response, sizeof(response)) == 0 &&
        std::strstr(response, "perf=1") != nullptr &&
        std::strstr(response, "perf-inherit=3") != nullptr &&
        std::strstr(response, "perf-inherit-bind=3") != nullptr &&
        std::strstr(response, "perf-inherit-exit=3") != nullptr;
    for (int &fd : inherit_thread_ready) {
        if (fd >= 0) close(fd);
        fd = -1;
    }
    for (int &fd : inherit_thread_release) {
        if (fd >= 0) close(fd);
        fd = -1;
    }
    const int inherit_thread_close = close(inherit_thread_fd);
    const bool inherit_thread_clean = inherit_thread_close == 0 &&
        control(key, "antidbg-status", response, sizeof(response)) == 0 &&
        std::strstr(response, "perf=0") != nullptr;
    if (!fork_not_inherited || !thread_inherited || !thread_released ||
        !thread_retired || !inherit_thread_clean) {
        if (inherit_thread_created && !thread_joined) {
            const char release = 'K';
            if (inherit_thread_release[1] >= 0)
                (void)write(inherit_thread_release[1], &release,
                            sizeof(release));
            (void)pthread_join(inherit_thread, nullptr);
        }
        if (inherit_thread_ready[0] >= 0) close(inherit_thread_ready[0]);
        if (inherit_thread_ready[1] >= 0) close(inherit_thread_ready[1]);
        if (inherit_thread_release[0] >= 0) close(inherit_thread_release[0]);
        if (inherit_thread_release[1] >= 0) close(inherit_thread_release[1]);
        std::fprintf(stderr,
                     "antidbg inherit-thread semantics failed: %s fork=%u thread=%u release=%u join=%u retire=%u clean=%u errno=%d\n",
                     response, fork_not_inherited ? 1U : 0U,
                     thread_inherited ? 1U : 0U,
                     thread_released ? 1U : 0U,
                     thread_joined ? 1U : 0U,
                     thread_retired ? 1U : 0U,
                     inherit_thread_clean ? 1U : 0U, errno);
        cleanup();
        return 1;
    }

    /* Detach is not the only ptrace ledger terminator. Program a stopped
     * tracee and kill it without DETACH; do_exit/flush must erase the virtual
     * state and all physical bindings before the PID can be reused. */
    const pid_t ptrace_exit_child = fork();
    if (ptrace_exit_child == 0) {
        (void)prctl(PR_SET_NAME, "rtgum-ptexit", 0, 0, 0);
        if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) != 0) _exit(82);
        raise(SIGSTOP);
        _exit(83);
    }
    int ptrace_exit_status = 0;
    bool ptrace_exit_ok = ptrace_exit_child > 0 &&
        waitpid(ptrace_exit_child, &ptrace_exit_status, 0) ==
            ptrace_exit_child &&
        WIFSTOPPED(ptrace_exit_status) && WSTOPSIG(ptrace_exit_status) == SIGSTOP;
    if (ptrace_exit_ok) {
        UserHwDebugState exit_state{};
        exit_state.registers[0].address = fake_address;
        exit_state.registers[0].control = kExecuteEl0;
        struct iovec exit_vector{&exit_state, 24U};
        ptrace_exit_ok = ptrace(PTRACE_SETREGSET, ptrace_exit_child,
                                reinterpret_cast<void *>(kNtArmHwBreak),
                                &exit_vector) == 0 &&
            ptrace(PTRACE_KILL, ptrace_exit_child, nullptr, nullptr) == 0 &&
            waitpid(ptrace_exit_child, &ptrace_exit_status, 0) ==
                ptrace_exit_child && WIFSIGNALED(ptrace_exit_status);
    }
    if (!ptrace_exit_ok ||
        control(key, "antidbg-status", response, sizeof(response)) != 0 ||
        std::strstr(response, "ledgers=0") == nullptr ||
        control(key, "antidbg-physical", response, sizeof(response)) != 0 ||
        std::strstr(response, "antidbg-records=0") == nullptr ||
        std::strstr(response, "untracked-brk=0") == nullptr) {
        if (ptrace_exit_child > 0 &&
            !(WIFEXITED(ptrace_exit_status) || WIFSIGNALED(ptrace_exit_status))) {
            (void)kill(ptrace_exit_child, SIGKILL);
            (void)waitpid(ptrace_exit_child, nullptr, 0);
        }
        std::fprintf(stderr,
                     "antidbg ptrace target-exit cleanup failed: %s status=0x%x errno=%d\n",
                     response, ptrace_exit_status, errno);
        cleanup();
        return 1;
    }

    /* disabled+enable_on_exec must transition both the real SW_DUMMY event and
     * the virtual comparator at exec.  Transfer an fd alias to the parent so
     * the post-exec event can be queried and disabled while the tracee is held
     * at PTRACE_EVENT_EXEC. */
    int enable_exec_sockets[2] = {-1, -1};
    const bool enable_exec_socket_ok =
        socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0,
                   enable_exec_sockets) == 0;
    const pid_t enable_exec_child = enable_exec_socket_ok ? fork() : -1;
    if (enable_exec_child == 0) {
        close(enable_exec_sockets[0]);
        (void)prctl(PR_SET_NAME, "dev.rtgum.lab", 0, 0, 0);
        struct perf_event_attr enable_exec_attr = attr;
        enable_exec_attr.disabled = 1;
        enable_exec_attr.enable_on_exec = 1;
        const int enable_exec_fd = static_cast<int>(syscall(
            __NR_perf_event_open, &enable_exec_attr, 0, -1, -1, 0UL));
        if (enable_exec_fd < 0 ||
            !send_fd(enable_exec_sockets[1], enable_exec_fd))
            _exit(74);
        close(enable_exec_sockets[1]);
        (void)prctl(PR_SET_NAME, "rtgum-exec-enable", 0, 0, 0);
        if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) != 0) _exit(75);
        raise(SIGSTOP);
        execl("/system/bin/sleep", "sleep", "1",
              static_cast<char *>(nullptr));
        _exit(76);
    }
    if (enable_exec_sockets[1] >= 0) close(enable_exec_sockets[1]);
    enable_exec_sockets[1] = -1;
    const int enable_exec_alias = enable_exec_child > 0
        ? receive_fd(enable_exec_sockets[0]) : -1;
    if (enable_exec_sockets[0] >= 0) close(enable_exec_sockets[0]);
    enable_exec_sockets[0] = -1;
    int enable_exec_status = 0;
    bool enable_exec_ok = enable_exec_child > 0 && enable_exec_alias >= 0 &&
        verify_perf_fd(enable_exec_alias) &&
        waitpid(enable_exec_child, &enable_exec_status, 0) ==
            enable_exec_child &&
        WIFSTOPPED(enable_exec_status) &&
        WSTOPSIG(enable_exec_status) == SIGSTOP &&
        ptrace(PTRACE_SETOPTIONS, enable_exec_child, nullptr,
               reinterpret_cast<void *>(PTRACE_O_TRACEEXEC)) == 0 &&
        ptrace(PTRACE_CONT, enable_exec_child, nullptr, nullptr) == 0 &&
        waitpid(enable_exec_child, &enable_exec_status, 0) ==
            enable_exec_child &&
        WIFSTOPPED(enable_exec_status) &&
        WSTOPSIG(enable_exec_status) == SIGTRAP &&
        (static_cast<unsigned int>(enable_exec_status) >> 16U) ==
            PTRACE_EVENT_EXEC &&
        control(key, "antidbg-status", response, sizeof(response)) == 0 &&
        std::strstr(response, "perf=1") != nullptr &&
        std::strstr(response, "perf-exec-enable=1") != nullptr;
    const bool enable_exec_disabled = enable_exec_ok &&
        ioctl(enable_exec_alias, PERF_EVENT_IOC_DISABLE, 0UL) == 0 &&
        control(key, "antidbg-physical", response, sizeof(response)) == 0 &&
        std::strstr(response, "antidbg-records=0") != nullptr &&
        std::strstr(response, "antidbg-enabled=0") != nullptr;
    if (enable_exec_alias >= 0) close(enable_exec_alias);
    if (enable_exec_child > 0) {
        if (WIFSTOPPED(enable_exec_status))
            (void)ptrace(PTRACE_DETACH, enable_exec_child, nullptr, nullptr);
        if (!WIFEXITED(enable_exec_status) && !WIFSIGNALED(enable_exec_status))
            (void)waitpid(enable_exec_child, &enable_exec_status, 0);
    }
    const bool enable_exec_clean = enable_exec_disabled &&
        control(key, "antidbg-status", response, sizeof(response)) == 0 &&
        std::strstr(response, "perf=0") != nullptr;
    if (!enable_exec_clean) {
        if (enable_exec_child > 0 &&
            !(WIFEXITED(enable_exec_status) || WIFSIGNALED(enable_exec_status))) {
            (void)kill(enable_exec_child, SIGKILL);
            (void)waitpid(enable_exec_child, nullptr, 0);
        }
        if (enable_exec_sockets[0] >= 0) close(enable_exec_sockets[0]);
        if (enable_exec_sockets[1] >= 0) close(enable_exec_sockets[1]);
        std::fprintf(stderr,
                     "antidbg enable-on-exec failed: %s transition=%u disabled=%u status=0x%x errno=%d\n",
                     response, enable_exec_ok ? 1U : 0U,
                     enable_exec_disabled ? 1U : 0U,
                     enable_exec_status, errno);
        cleanup();
        return 1;
    }

    /* execve() flushes ptrace state and removes perf events carrying
     * remove_on_exec from the task context. The perf fd remains alive in
     * PERF_EVENT_STATE_EXIT, so the virtual slot must retain fd identity while
     * permanently retiring its old-address comparator. */
    const pid_t exec_child = fork();
    if (exec_child == 0) {
        (void)prctl(PR_SET_NAME, "dev.rtgum.lab", 0, 0, 0);
        struct perf_event_attr exec_attr = attr;
        exec_attr.disabled = 0;
        exec_attr.remove_on_exec = 1;
        const int exec_perf_fd = static_cast<int>(syscall(
            __NR_perf_event_open, &exec_attr, 0, -1, -1, 0UL));
        if (exec_perf_fd < 0) _exit(73);
        (void)prctl(PR_SET_NAME, "rtgum-execprobe", 0, 0, 0);
        if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) != 0) _exit(71);
        raise(SIGSTOP);
        execl("/system/bin/sleep", "sleep", "1",
              static_cast<char *>(nullptr));
        _exit(72);
    }
    int exec_status = 0;
    bool exec_perf_retired = false;
    bool exec_flush_ok = exec_child > 0 &&
        waitpid(exec_child, &exec_status, 0) == exec_child &&
        WIFSTOPPED(exec_status) && WSTOPSIG(exec_status) == SIGSTOP;
    if (exec_flush_ok) {
        UserHwDebugState exec_state{};
        exec_state.registers[0].address = fake_address;
        exec_state.registers[0].control = kExecuteEl0;
        struct iovec vector{&exec_state, 24U};
        exec_flush_ok = ptrace(PTRACE_SETREGSET, exec_child,
                               reinterpret_cast<void *>(kNtArmHwBreak),
                               &vector) == 0 &&
            ptrace(PTRACE_SETOPTIONS, exec_child, nullptr,
                   reinterpret_cast<void *>(PTRACE_O_TRACEEXEC)) == 0 &&
            ptrace(PTRACE_CONT, exec_child, nullptr, nullptr) == 0 &&
            waitpid(exec_child, &exec_status, 0) == exec_child &&
            WIFSTOPPED(exec_status) && WSTOPSIG(exec_status) == SIGTRAP &&
            (static_cast<unsigned int>(exec_status) >> 16U) ==
                PTRACE_EVENT_EXEC;
        if (exec_flush_ok) {
            std::memset(&exec_state, 0xa5, sizeof(exec_state));
            vector = {&exec_state, sizeof(exec_state)};
            exec_flush_ok = ptrace(
                PTRACE_GETREGSET, exec_child,
                reinterpret_cast<void *>(kNtArmHwBreak), &vector) == 0 &&
                state_empty(exec_state);
        }
        if (exec_flush_ok) {
            exec_perf_retired =
                control(key, "antidbg-status", response,
                        sizeof(response)) == 0 &&
                std::strstr(response, "perf=1") != nullptr &&
                std::strstr(response, "perf-exec-retire=1") != nullptr &&
                control(key, "antidbg-physical", response,
                        sizeof(response)) == 0 &&
                std::strstr(response, "antidbg-records=0") != nullptr &&
                std::strstr(response, "antidbg-enabled=0") != nullptr;
            exec_flush_ok = exec_perf_retired;
        }
    }
    if (exec_child > 0) {
        if (WIFSTOPPED(exec_status))
            (void)ptrace(PTRACE_DETACH, exec_child, nullptr, nullptr);
        if (!WIFEXITED(exec_status) && !WIFSIGNALED(exec_status))
            (void)waitpid(exec_child, &exec_status, 0);
    }
    if (!exec_flush_ok) {
        if (exec_child > 0) {
            kill(exec_child, SIGKILL);
            (void)waitpid(exec_child, nullptr, 0);
        }
        std::fprintf(stderr,
                     "antidbg exec flush/remove-on-exec failed: %s retired=%u status=0x%x errno=%d\n",
                     response, exec_perf_retired ? 1U : 0U, exec_status,
                     errno);
        (void)prctl(PR_SET_NAME, original_comm, 0, 0, 0);
        (void)control(key, "daemon-config-clear 1", response,
                      sizeof(response));
        return 1;
    }
    (void)prctl(PR_SET_NAME, original_comm, 0, 0, 0);

    /* do_exit hooks run concurrently across CPUs. Release a synchronized wave
     * of worker threads and then require a clean physical audit; this guards
     * against synchronous cross-CPU cleanup cycles that only surface later as
     * an EHLD watchdog reboot. */
    constexpr unsigned int kExitStormThreads = 16U;
    std::atomic<bool> exit_storm_release{false};
    pthread_t exit_storm_threads[kExitStormThreads]{};
    unsigned int exit_storm_created = 0U;
    for (; exit_storm_created < kExitStormThreads; ++exit_storm_created) {
        if (pthread_create(
                &exit_storm_threads[exit_storm_created], nullptr,
                [](void *opaque) -> void * {
                    auto *release = static_cast<std::atomic<bool> *>(opaque);
                    while (!release->load(std::memory_order_acquire))
                        sched_yield();
                    return nullptr;
                },
                &exit_storm_release) != 0)
            break;
    }
    exit_storm_release.store(true, std::memory_order_release);
    bool exit_storm_joined = exit_storm_created == kExitStormThreads;
    for (unsigned int index = 0; index < exit_storm_created; ++index)
        if (pthread_join(exit_storm_threads[index], nullptr) != 0)
            exit_storm_joined = false;
    const bool exit_storm_clean = exit_storm_joined &&
        control(key, "antidbg-physical", response, sizeof(response)) == 0 &&
        std::strstr(response, "antidbg-records=0") != nullptr &&
        std::strstr(response, "antidbg-enabled=0") != nullptr &&
        std::strstr(response, "antidbg-steps=0") != nullptr;
    if (!exit_storm_clean) {
        std::fprintf(stderr,
                     "antidbg concurrent-exit cleanup failed: %s created=%u joined=%u errno=%d\n",
                     response, exit_storm_created,
                     exit_storm_joined ? 1U : 0U, errno);
        (void)control(key, "daemon-config-clear 1", response,
                      sizeof(response));
        return 1;
    }

    if (control(key, "daemon-config-clear 1", response, sizeof(response)) != 0 ||
        std::strstr(response, "entries=0") == nullptr) {
        std::fprintf(stderr, "anti-debug Manager policy cleanup failed: %s\n",
                     response);
        return 1;
    }
    std::snprintf(command, sizeof(command), "antidbg-policy %d", getpid());
    if (control(key, command, response, sizeof(response)) != 0 ||
        std::strstr(response, "policy=denied") == nullptr) {
        std::fprintf(stderr, "Manager anti-debug grant survived config clear: %s\n",
                     response);
        return 1;
    }

    /* The fixed tail covers lifecycle/alias probes, exclude-user, the
     * two-event group, period, refresh, inherit-thread, enable-on-exec and
     * remove-on-exec. Three inherited events have no user-visible fd but do
     * pass through the perf security free hook at task exit. */
    const unsigned int perf_events = slots + watch_slots + 18U +
        cpu_specific_perf_events + cpu_capacity_perf_events +
        mixed_group_perf_events + system_wide_perf_events;
    const unsigned int perf_frees = perf_events + 3U;
    /* A pid=-1,cpu=N event passes both PERF_SECURITY_OPEN and
     * PERF_SECURITY_CPU.  Task events only pass the former. */
    const unsigned int perf_lsm_opens =
        perf_events + system_wide_perf_events;
    const unsigned int extra_fd_checks = 11U;
    const unsigned int perf_fd_surface_writes = 5U;
    const unsigned int perf_fd_surface_reads = 1U;
    const unsigned int mixed_group_writes = 2U;
    const unsigned int expected_writes = 3U *
        (slots + watch_slots + extra_fd_checks) + 19U +
        perf_fd_surface_writes + mixed_group_writes +
        system_wide_perf_writes;
    const unsigned int expected_reads =
        slots + watch_slots + extra_fd_checks + 10U +
        cpu_specific_perf_reads + mixed_group_perf_reads +
        perf_fd_surface_reads + system_wide_perf_reads;
    char expected_system_wide_open[64]{};
    char expected_open[64]{};
    char expected_alloc[64]{};
    char expected_free[64]{};
    char expected_write[64]{};
    char expected_read[64]{};
    char expected_auth[64]{};
    std::snprintf(expected_open, sizeof(expected_open),
                  "perf_lsm_open=%u", perf_lsm_opens);
    std::snprintf(expected_alloc, sizeof(expected_alloc),
                  "perf_alloc=%u", perf_events);
    std::snprintf(expected_free, sizeof(expected_free),
                  "perf_free=%u", perf_frees);
    std::snprintf(expected_write, sizeof(expected_write),
                  "perf_lsm_write=%u", expected_writes);
    std::snprintf(expected_read, sizeof(expected_read),
                  "perf_lsm_read=%u", expected_reads);
    std::snprintf(expected_auth, sizeof(expected_auth),
                  "event_auth=%u", expected_writes + expected_reads);
    std::snprintf(expected_system_wide_open,
                  sizeof(expected_system_wide_open),
                  "perf-systemwide-open=%u", system_wide_perf_events);
    const bool final_status_ok =
        control(key, "antidbg-status", response, sizeof(response)) == 0;
    const char *targeted_sync_field = final_status_ok
        ? std::strstr(response, "perf-targeted-sync=") : nullptr;
    const unsigned long targeted_syncs = targeted_sync_field
        ? std::strtoul(targeted_sync_field +
                           std::strlen("perf-targeted-sync="),
                       nullptr, 10)
        : 0UL;
    if (!final_status_ok ||
        std::strstr(response, "antidbg=1") == nullptr ||
        std::strstr(response, "kernel=") == nullptr ||
        std::strstr(response, "compat=") == nullptr ||
        std::strstr(response, "ledgers=0") == nullptr ||
        std::strstr(response, "perf=0") == nullptr ||
        std::strstr(response, "perf-systemwide=0") == nullptr ||
        std::strstr(response, "active-steps=0") == nullptr ||
        std::strstr(response, "physical-bindings=0") == nullptr ||
        std::strstr(response, "scheduler-work=0") == nullptr ||
        std::strstr(response, "manager-grants=0") == nullptr ||
        std::strstr(response, "grant-add=2") == nullptr ||
        std::strstr(response, "grant-revoke=2") == nullptr ||
        std::strstr(response, "grant-mm-get=2") == nullptr ||
        std::strstr(response, "grant-mm-put=2") == nullptr ||
        std::strstr(response, "step-dispatch=1") == nullptr ||
        std::strstr(response, "ptrace_flush=") == nullptr ||
        std::strstr(response, expected_open) == nullptr ||
        std::strstr(response, expected_alloc) == nullptr ||
        std::strstr(response, expected_free) == nullptr ||
        std::strstr(response, expected_write) == nullptr ||
        std::strstr(response, expected_read) == nullptr ||
        std::strstr(response, expected_auth) == nullptr ||
        std::strstr(response, "active-trigger=1") == nullptr ||
        std::strstr(response, "active-brk=1") == nullptr ||
        std::strstr(response, "active-watch=1") == nullptr ||
        std::strstr(response, "perf-brk=12") == nullptr ||
        std::strstr(response, "perf-watch=2") == nullptr ||
        std::strstr(response, expected_system_wide_open) == nullptr ||
        std::strstr(response, "perf-systemwide-hit=3") == nullptr ||
        std::strstr(response, "perf-clear-broadcast=0") == nullptr ||
        /* Wildcard and task-scoped events now share precise CPU rendezvous.
         * The exact count varies with migrations; at least the wildcard open
         * must be observed and no operation may fall back to a deferred CPU. */
        targeted_syncs == 0UL ||
        std::strstr(response, "perf-targeted-deferred=0") == nullptr ||
        std::strstr(response, "perf-scheduler-deferred=") == nullptr ||
        std::strstr(response, "perf-rearm=14") == nullptr ||
        std::strstr(response, "perf-step-deferred=0") == nullptr ||
        std::strstr(response, "perf-step-disable-rearm=") == nullptr ||
        std::strstr(response, "perf-step-switch-rearm=") == nullptr ||
        std::strstr(response, "perf-step-forward=14") == nullptr ||
        std::strstr(response, "perf-sigtrap-fix=6") == nullptr ||
        std::strstr(response, "perf-overflow-disable=1") == nullptr ||
        std::strstr(response, "perf-exec-retire=1") == nullptr ||
        std::strstr(response, "perf-exec-enable=1") == nullptr ||
        std::strstr(response, "perf-modify=1") == nullptr ||
        std::strstr(response, "perf-modify-reject=1") == nullptr ||
        std::strstr(response, "perf-inherit=3") == nullptr ||
        std::strstr(response, "perf-inherit-bind=3") == nullptr ||
        std::strstr(response, "perf-inherit-exit=3") == nullptr ||
        std::strstr(response, "perf-task-enable=1") == nullptr ||
        std::strstr(response, "perf-task-disable=3") == nullptr ||
        std::strstr(response, "perf-enable=") == nullptr ||
        std::strstr(response, "perf-disable=") == nullptr ||
        std::strstr(response, "switch-lock-miss=0") == nullptr ||
        std::strstr(response, "perf-physical-program=") == nullptr ||
        std::strstr(response, "perf_fallback=0") == nullptr ||
        std::strstr(response, "copy_fail=0") == nullptr) {
        std::fprintf(stderr, "antidbg cleanup/status failed: %s\n", response);
        return 1;
    }
    std::printf("anti-debug status: %s\n", response);
    if (control(key, "antidbg-physical", response, sizeof(response)) != 0 ||
        std::strstr(response, "hwbp-records=0") == nullptr ||
        std::strstr(response, "hwbp-enabled=0") == nullptr ||
        std::strstr(response, "hwbp-mismatch=0") == nullptr ||
        std::strstr(response, "antidbg-records=0") == nullptr ||
        std::strstr(response, "antidbg-enabled=0") == nullptr ||
        std::strstr(response, "antidbg-mismatch=0") == nullptr ||
        std::strstr(response, "antidbg-steps=0") == nullptr ||
        std::strstr(response, "untracked-brk=0") == nullptr ||
        std::strstr(response, "untracked-watch=0") == nullptr ||
        std::strstr(response, "monitor-owned=0") == nullptr ||
        std::strstr(response, "mdscr-ss=0") == nullptr) {
        std::fprintf(stderr, "anti-debug physical cleanup failed: %s\n",
                     response);
        return 1;
    }
    std::printf("anti-debug physical: %s\n", response);

    /* The software-step hook is shared by ART shadow, Shadow Hook, CPU trace,
     * and AntiDebug. Exercise real control-plane transitions so an ART unhook
     * cannot silently remove AntiDebug's one-shot dispatcher. */
    if (control(key, "hook-art-shadow-dbg", response, sizeof(response)) != 0 ||
        std::strstr(response, "ok art_shadow_dbg=1") == nullptr ||
        control(key, "shadow-status", response, sizeof(response)) != 0 ||
        std::strstr(response, "dbg-hook=1") == nullptr ||
        std::strstr(response, "dbg-owners=0x5") == nullptr) {
        std::fprintf(stderr, "shared step dispatcher retain failed: %s\n",
                     response);
        return 1;
    }
    if (control(key, "unhook-art-shadow", response, sizeof(response)) != 0 ||
        std::strstr(response, "ok art_shadow=0") == nullptr ||
        control(key, "antidbg-status", response, sizeof(response)) != 0 ||
        std::strstr(response, "antidbg=1") == nullptr ||
        std::strstr(response, "active-steps=0") == nullptr ||
        std::strstr(response, "step-dispatch=1") == nullptr ||
        std::strstr(response, "dbg-owners=0x4") == nullptr) {
        std::fprintf(stderr, "ART unhook removed AntiDebug dispatcher: %s\n",
                     response);
        return 1;
    }
    if (control(key, "unhook-antidbg", response, sizeof(response)) != 0 ||
        std::strstr(response, "ok antidbg=0") == nullptr ||
        control(key, "shadow-status", response, sizeof(response)) != 0 ||
        std::strstr(response, "dbg-hook=0") == nullptr ||
        std::strstr(response, "dbg-owners=0x0") == nullptr) {
        std::fprintf(stderr, "shared step dispatcher final release failed: %s\n",
                     response);
        return 1;
    }
    if (control(key, "hook-antidbg", response, sizeof(response)) != 0 ||
        std::strstr(response, "ok antidbg=1") == nullptr ||
        control(key, "antidbg-status", response, sizeof(response)) != 0 ||
        std::strstr(response, "active-steps=0") == nullptr ||
        std::strstr(response, "step-dispatch=1") == nullptr ||
        std::strstr(response, "dbg-owners=0x4") == nullptr) {
        std::fprintf(stderr, "AntiDebug dispatcher reinstall failed: %s\n",
                     response);
        return 1;
    }
    std::printf("anti-debug step-dispatch lifecycle: %s\n", response);
    std::printf("manager-scope=1 caller-tgid-scope=1 root-detector-tgid-scope=1 unauthorized-pass-through=1 brp-slots=%u wrp-slots=%u ptrace-rw=1 ptrace-overflow=-ENOSPC shared-capacity=1 regset-ignore=1 regset-canonical=1 regset-arm64-shift=1 invalid-control=-EINVAL torn-address=-EINVAL perf-rw=1 perf-overflow=-ENOSPC perf-attr-validation=1 perf-arm64-canonicalization=1 perf-active-count=1 perf-disable=1 perf-reset-enable=1 perf-siginfo=TRAP_PERF perf-type=BREAKPOINT perf-sig-data=1 perf-period=1 perf-refresh-limit=1 perf-modify-attributes=1 perf-modify-reject=EINVAL perf-cpu-binding=1 perf-cpu-capacity=1 perf-cpu-invalid-errno=1 perf-systemwide=1 perf-systemwide-cross-process=1 perf-systemwide-capacity=1 perf-systemwide-multi-owner=1 perf-systemwide-revoke-lifetime=1 perf-step-rearm=1 perf-step-forward=1 task-wide-toggle=1 perf-fd-metadata=1 perf-fd-surfaces=1 exclude-user=1 perf-group-toggle=1 perf-mixed-groups=1 dup=1 dup3=1 fcntl-dup=1 fd-fork-inherit=1 perf-event-inherit=1 active-perf-inherit=1 inherit-thread=1 scm-rights=1 alias-capacity=1 target-exit-fd=1 ptrace-exit-cleanup=1 concurrent-exit-cleanup=1 exec-flush=1 enable-on-exec=1 remove-on-exec=1 active-fake-trap=2 siginfo=TRAP_HWBKPT real-hwbp-entry=4 real-hwbp-return=4 cleanup=1\n",
                slots, watch_slots);
    std::puts("stage1-antidbg-lab-test PASS");
    return 0;
#endif
}

int command_shadowhook_lifecycle_test(const char *key)
{
    char response[kControlBufferSize]{};
    auto require = [&](const char *command, const char *needle,
                       const char *stage) {
        if (control(key, command, response, sizeof(response)) == 0 &&
            std::strstr(response, needle) != nullptr)
            return true;
        std::fprintf(stderr, "shadow lifecycle %s failed: %s\n", stage,
                     response);
        return false;
    };

    if (!require("hook-antidbg", "ok antidbg=1", "anti install") ||
        !require("hook-shadow-hook", "ok shadowhook=1", "initial install") ||
        !require("shadow-status", "dbg-owners=0x6", "shared owner retain") ||
        !require("unhook-shadow-hook", "physical=dormant", "deactivate") ||
        !require("antidbg-status", "dbg-owners=0x4", "anti owner survive") ||
        !require("hook-shadow-hook", "ok shadowhook=1", "re-enable") ||
        !require("shadow-status", "dbg-owners=0x6", "owner re-retain") ||
        !require("unhook-shadow-hook", "physical=dormant", "second deactivate") ||
        !require("unhook-antidbg", "ok antidbg=0", "anti release") ||
        !require("shadow-status", "dbg-owners=0x0", "final owner release") ||
        !require("antidbg-physical", "untracked-watch=0", "physical audit"))
        return 1;

    if (std::strstr(response, "hwbp-records=0") == nullptr ||
        std::strstr(response, "antidbg-records=0") == nullptr ||
        std::strstr(response, "untracked-brk=0") == nullptr) {
        std::fprintf(stderr, "shadow lifecycle physical residue: %s\n", response);
        return 1;
    }
    std::puts("stage1-shadowhook-lifecycle PASS");
    return 0;
}

/* DBI acceptance: clone lab_flower to a far page through the relocator and
 * prove (1) the relocated execution matches the original register end state,
 * (2) the offset_map maps clone PCs back to the original instruction index,
 * (3) the expanded literal pool stays inside the reserved capacity. */
/* Per-APK DBI acceptance: read the target process's real code bytes through
 * the KPM's cross-process page-table read, relocate them, execute the clone
 * here and compare the behaviour with the same function locally (same libc
 * build). Proves the relocator works on real application code. */
int command_dbi_apk_test(const char *key, long pid, unsigned long va,
                         const char *symbol_name, unsigned long request_length)
{
#if !defined(__aarch64__)
    (void)key; (void)pid; (void)va; (void)symbol_name; (void)request_length;
    return 1;
#else
    const bool self_contained =
        symbol_name != nullptr && std::strstr(symbol_name, "bsearch") != nullptr;
    char command[128];
    char response[kControlBufferSize];
    std::snprintf(command, sizeof(command), "read-user %ld 0x%lx %lu", pid, va,
                  request_length);
    if (control(key, command, response, sizeof(response)) != 0) return 1;
    const char *hex = std::strstr(response, "hex=");
    if (!hex) {
        std::fprintf(stderr, "dbi-apk read-user rejected: %s\n", response);
        return 1;
    }
    const char *bytes_field = std::strstr(response, "bytes=");
    const unsigned long reported =
        bytes_field ? std::strtoul(bytes_field + 6, nullptr, 10) : 0;
    if (reported != request_length) {
        std::fprintf(stderr, "dbi-apk read-user returned %lu bytes, want %lu\n",
                     reported, request_length);
        return 1;
    }
    hex += 4;
    unsigned char code[192];
    size_t code_length = 0;
    for (const char *p = hex; p[0] && p[1] && code_length < sizeof(code) &&
                            code_length < request_length; p += 2) {
        auto nibble = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        const int high = nibble(p[0]);
        const int low = nibble(p[1]);
        if (high < 0 || low < 0) break;
        code[code_length++] = static_cast<unsigned char>((high << 4) | low);
    }
    if (code_length < 16) {
        std::fprintf(stderr, "dbi-apk short read: %zu bytes\n", code_length);
        return 1;
    }

    /* Identity check: the remote bytes must match the local mapping of the
     * same function before any relocation claim is made. */
    auto *local_function = reinterpret_cast<unsigned char *>(
        dlsym(RTLD_DEFAULT, symbol_name));
    if (!local_function) {
        std::fprintf(stderr, "dbi-apk local %s missing\n", symbol_name);
        return 1;
    }
    if (std::memcmp(code, local_function, code_length) != 0) {
        std::fprintf(stderr,
                     "dbi-apk remote bytes differ from the local libc mapping\n");
        return 1;
    }

    void *clone = mmap(nullptr, 4096, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (clone == MAP_FAILED) {
        std::fprintf(stderr, "dbi-apk clone mmap failed\n");
        return 1;
    }
    /* The bytes are the app's real code, verified byte-identical to the
     * LOCAL mapping above; the relocation base is therefore the local VA, so
     * the rewritten PC-relative targets resolve inside this address space. */
    const unsigned long local_va = reinterpret_cast<unsigned long>(local_function);
    static uint8_t apk_code[4096];
    static rtgum_dbi::OffsetMapEntry apk_map[192];
    static rtgum_dbi::BranchTraceEntry apk_trace[192];
    static rtgum_dbi::LiteralRange apk_literals[192];
    rtgum_dbi::RelocationResult result = rtgum_dbi::make_result(
        apk_code, sizeof(apk_code), apk_map, 192, apk_trace, 192,
        apk_literals, 192);
    if (!rtgum_dbi::Relocator::relocate(code, code_length, local_va,
                                        reinterpret_cast<unsigned long>(clone),
                                        result) ||
        result.code_size > sizeof(apk_code)) {
        std::fprintf(stderr, "dbi-apk relocation failed overflow=%d\n",
                     result.overflow ? 1 : 0);
        return 1;
    }
    std::memcpy(clone, result.code, result.code_size);
    __builtin___clear_cache(reinterpret_cast<char *>(clone),
                            reinterpret_cast<char *>(clone) + result.code_size);
    if (mprotect(clone, 4096, PROT_READ | PROT_EXEC) != 0) {
        std::fprintf(stderr, "dbi-apk mprotect failed\n");
        return 1;
    }

    /* Differential: run the same call through the original and the clone.
     * A self-contained leaf function (strlen) exercises the clone's own
     * intra-block branches; a libc stub (epoll_wait) exercises the exit
     * path. */
    struct epoll_event events[4]{};
    long original_result = 0;
    long clone_result = 0;
    int original_errno = 0;
    int clone_errno = 0;
    if (self_contained) {
        /* bsearch is a real FUNC with its own loop and an indirect call to
         * the comparator, so the clone must run its own control flow. */
        auto *original_bsearch = reinterpret_cast<void *(*)(const void *, const void *,
                                                            size_t, size_t,
                                                            int (*)(const void *,
                                                                    const void *))>(
            dlsym(RTLD_DEFAULT, "bsearch"));
        auto *clone_bsearch = reinterpret_cast<void *(*)(const void *, const void *,
                                                         size_t, size_t,
                                                         int (*)(const void *,
                                                                 const void *))>(clone);
        if (!original_bsearch) {
            std::fprintf(stderr, "dbi-apk local bsearch missing\n");
            return 1;
        }
        auto compare_ints = [](const void *left, const void *right) -> int {
            const int a = *static_cast<const int *>(left);
            const int b = *static_cast<const int *>(right);
            return a < b ? -1 : (a > b ? 1 : 0);
        };
        static const int kSorted[] = {1, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37};
        const size_t count = sizeof(kSorted) / sizeof(kSorted[0]);
        const int probes[] = {1, 17, 37, 4, 100};
        for (int key : probes) {
            const void *expected = original_bsearch(&key, kSorted, count,
                                                    sizeof(int), compare_ints);
            const void *actual = clone_bsearch(&key, kSorted, count, sizeof(int),
                                               compare_ints);
            original_result += expected ? static_cast<long>(
                                    (static_cast<const int *>(expected) - kSorted) + 1)
                                        : 0;
            clone_result += actual ? static_cast<long>(
                                    (static_cast<const int *>(actual) - kSorted) + 1)
                                   : 0;
            if (expected != actual) {
                std::fprintf(stderr, "dbi-apk bsearch clone diverged for %d\n", key);
                return 1;
            }
        }
    } else {
        auto *local_epoll_wait = reinterpret_cast<int (*)(int, void *, int, int)>(
            dlsym(RTLD_DEFAULT, "epoll_wait"));
        auto *clone_entry = reinterpret_cast<int (*)(int, void *, int, int)>(clone);
        errno = 0;
        original_result = local_epoll_wait ? local_epoll_wait(-1, events, 4, 0) : -98;
        original_errno = errno;
        errno = 0;
        clone_result = clone_entry(-1, events, 4, 0);
        clone_errno = errno;
    }

    /* Runtime coverage: how much of this block really executes inside the
     * clone. A leaf-heavy libc stub tail-branches out early, so the number is
     * reported instead of being claimed as full coverage. */
    unsigned int coverage_steps = 0;
    unsigned int coverage_in_clone = 0;
    unsigned long coverage_landing = 0;
    {
        struct UserPtRegs {
            unsigned long regs[31];
            unsigned long sp;
            unsigned long pc;
            unsigned long pstate;
        };
        const unsigned long clone_begin = reinterpret_cast<unsigned long>(clone);
        const unsigned long clone_end = clone_begin + result.placeholder_index;
        const pid_t child = fork();
        if (child == 0) {
            if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) != 0) _exit(2);
            raise(SIGSTOP);
            if (self_contained) {
                auto *clone_bsearch =
                    reinterpret_cast<void *(*)(const void *, const void *, size_t,
                                               size_t,
                                               int (*)(const void *, const void *))>(clone);
                auto compare_ints = [](const void *left, const void *right) -> int {
                    const int a = *static_cast<const int *>(left);
                    const int b = *static_cast<const int *>(right);
                    return a < b ? -1 : (a > b ? 1 : 0);
                };
                static const int kSorted[] = {1, 3, 5, 7, 11, 13, 17, 19, 23, 29,
                                              31, 37};
                const int coverage_key = 23;
                volatile void *rc = clone_bsearch(&coverage_key, kSorted, 12,
                                                  sizeof(int), compare_ints);
                (void)rc;
            } else {
                auto *clone_entry =
                    reinterpret_cast<int (*)(int, void *, int, int)>(clone);
                volatile int rc = clone_entry(-1, events, 4, 0);
                (void)rc;
            }
            _exit(0);
        }
        if (child > 0) {
            int status = 0;
            if (waitpid(child, &status, 0) == child && WIFSTOPPED(status)) {
                unsigned long previous = 0;
                while (coverage_steps < 2048U) {
                    if (ptrace(PTRACE_SINGLESTEP, child, nullptr, nullptr) != 0) break;
                    if (waitpid(child, &status, 0) != child) break;
                    if (WIFEXITED(status) || WIFSIGNALED(status)) break;
                    UserPtRegs regs{};
                    struct iovec iov{&regs, sizeof(regs)};
                    if (ptrace(PTRACE_GETREGSET, child,
                               reinterpret_cast<void *>(static_cast<long>(1)),
                               &iov) != 0)
                        break;
                    ++coverage_steps;
                    if (regs.pc >= clone_begin && regs.pc < clone_end) {
                        ++coverage_in_clone;
                    } else if (previous >= clone_begin && previous < clone_end &&
                               coverage_landing == 0) {
                        coverage_landing = regs.pc;
                    }
                    previous = regs.pc;
                }
                ptrace(PTRACE_DETACH, child, nullptr, nullptr);
            }
            kill(child, SIGKILL);
            waitpid(child, nullptr, 0);
        }
    }

    std::printf("dbi-apk symbol=%s pid=%ld app-va=0x%lx local-va=0x%lx bytes=%zu "
                "identity=1 cloned=%zu literals=%u expanded=%u result=%ld/%ld "
                "errno=%d/%d steps=%u in-clone=%u landing=0x%lx "
                "scope=remote-read+ctl-differential\n",
                symbol_name, pid, va, local_va, code_length, result.code_size,
                result.literal_count, result.expanded_branches, original_result,
                clone_result, original_errno, clone_errno, coverage_steps,
                coverage_in_clone, coverage_landing);
    std::fflush(stdout);
    if (original_result != clone_result || original_errno != clone_errno) {
        std::fprintf(stderr, "dbi-apk clone diverged from the local function\n");
        return 1;
    }
    if (coverage_in_clone == 0) {
        std::fprintf(stderr, "dbi-apk the clone never executed a single step\n");
        return 1;
    }
    if (self_contained && coverage_in_clone < 20U) {
        std::fprintf(stderr,
                     "dbi-apk self-contained block only executed %u clone steps\n",
                     coverage_in_clone);
        return 1;
    }
    std::puts("stage1-dbi-apk PASS");
    return 0;
#endif
}

/* LDR (literal) subtype matrix: every supported subtype is executed from a
 * near clone (in-range re-encode) and a far clone (absolute rewrite), and the
 * refused subtypes must report their reason instead of silently changing
 * width, signedness or prefetch semantics. */
/* Concurrency check for the remote read path.
 *
 * Three regions are exercised at once:
 *   A  stable pattern pages (never unmapped)  -> every read must return the
 *      pattern exactly, byte for byte;
 *   B  pages that a background thread keeps dropping with MADV_DONTNEED and
 *      re-faulting -> a read may fail explicitly, and when it succeeds every
 *      byte must be either the pattern byte or zero (a freshly faulted anon
 *      page), never unrelated memory;
 *   C  pages that are munmap()ed and re-mmap()ed with MAP_FIXED in a loop ->
 *      same rule as B, plus an explicit error is acceptable at any time.
 * Any "ok" reply whose bytes break these rules fails the test, as does a
 * crash: the point is that a lost race must never be reported as success.
 * A remote thread is used so the churn happens on the same mm the reader
 * inspects (fork would copy the page tables). */
int command_read_user_race_test(const char *key)
{
#if !defined(__aarch64__)
    (void)key;
    return 1;
#else
    constexpr size_t kPageSize = 4096UL;
    constexpr size_t kPagesPerRegion = 4UL;
    constexpr unsigned int kAttempts = 200U;
    const size_t region = kPagesPerRegion * kPageSize;
    auto pattern_at = [](unsigned long offset) -> unsigned char {
        return static_cast<unsigned char>((offset * 7UL + 1UL) & 0xffUL);
    };
    auto map_region = [&](void *hint) -> unsigned char * {
        return static_cast<unsigned char *>(
            mmap(hint, region, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS | (hint ? MAP_FIXED : 0), -1, 0));
    };
    unsigned char *stable = map_region(nullptr);
    unsigned char *dropped = map_region(nullptr);
    unsigned char *remapped = map_region(nullptr);
    if (stable == MAP_FAILED || dropped == MAP_FAILED || remapped == MAP_FAILED) {
        std::fprintf(stderr, "read-user-race mmap failed\n");
        return 1;
    }
    auto fill = [&](unsigned char *target) {
        for (size_t i = 0; i < region; ++i) target[i] = pattern_at(i);
    };
    fill(stable);
    fill(dropped);
    fill(remapped);

    struct Churn {
        unsigned char *dropped;
        unsigned char *remapped;
        size_t region;
        volatile int stop;
    };
    Churn churn{dropped, remapped, region, 0};
    pthread_t worker{};
    const int created = pthread_create(
        &worker, nullptr,
        [](void *argument) -> void * {
            auto *context = static_cast<Churn *>(argument);
            unsigned int round = 0;
            while (context->stop == 0) {
                /* Drop every other page of the "dropped" region. */
                for (size_t offset = 0; offset < context->region;
                     offset += 2UL * kPageSize)
                    madvise(context->dropped + offset, kPageSize, MADV_DONTNEED);
                for (size_t offset = 0; offset < context->region;
                     offset += kPageSize)
                    context->dropped[offset] = static_cast<unsigned char>(
                        (offset * 7UL + 1UL) & 0xffUL);
                /* Unmap and re-map the whole "remapped" region in place. */
                munmap(context->remapped, context->region);
                void *again = mmap(context->remapped, context->region,
                                   PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
                if (again != MAP_FAILED) {
                    auto *bytes = static_cast<unsigned char *>(again);
                    for (size_t offset = 0; offset < context->region;
                         offset += kPageSize)
                        bytes[offset] = static_cast<unsigned char>(
                            (offset * 7UL + 1UL) & 0xffUL);
                }
                ++round;
                if ((round & 3U) == 0U) sched_yield();
            }
            return nullptr;
        },
        &churn);
    if (created != 0) {
        std::fprintf(stderr, "read-user-race thread create failed\n");
        return 1;
    }

    char command[160];
    char response[kControlBufferSize];
    unsigned int stable_ok = 0;
    unsigned int stable_bad = 0;
    unsigned int churned_ok = 0;
    unsigned int churned_refused = 0;
    unsigned int churned_bad = 0;
    unsigned int unexpected = 0;
    auto parse_hex = [](const char *hex, unsigned char *out, size_t capacity) -> size_t {
        size_t count = 0;
        for (const char *p = hex; p[0] && p[1] && count < capacity; p += 2) {
            auto nibble = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            const int high = nibble(p[0]);
            const int low = nibble(p[1]);
            if (high < 0 || low < 0) break;
            out[count++] = static_cast<unsigned char>((high << 4) | low);
        }
        return count;
    };
    auto read_at = [&](unsigned long target, unsigned char *out, size_t &got,
                       bool &is_error) -> void {
        got = 0;
        is_error = false;
        std::snprintf(command, sizeof(command), "read-user %ld 0x%lx 192",
                      static_cast<long>(getpid()), target);
        if (control(key, command, response, sizeof(response)) != 0) {
            is_error = true;
            return;
        }
        const char *hex = std::strstr(response, "hex=");
        if (hex == nullptr) {
            is_error = true;
            return;
        }
        got = parse_hex(hex + 4, out, 192);
    };

    /* Offset 0 keeps the 192-byte window inside one page for the stable check
     * so its expectation is exact; the churned reads cross a page boundary. */
    for (unsigned int attempt = 0; attempt < kAttempts; ++attempt) {
        unsigned char bytes[192];
        size_t got = 0;
        bool is_error = false;

        read_at(reinterpret_cast<unsigned long>(stable) + kPageSize - 64UL, bytes, got,
                is_error);
        if (is_error) {
            ++stable_bad;
        } else if (got == 192U) {
            bool matches = true;
            for (size_t i = 0; i < got; ++i) {
                const unsigned long offset = kPageSize - 64UL + i;
                if (bytes[i] != pattern_at(offset)) matches = false;
            }
            if (matches) ++stable_ok; else ++stable_bad;
        } else {
            ++stable_bad;
        }

        read_at(reinterpret_cast<unsigned long>(dropped) + kPageSize - 64UL, bytes,
                got, is_error);
        if (is_error) {
            ++churned_refused;
        } else if (got == 192U) {
            bool plausible = true;
            for (size_t i = 0; i < got; ++i) {
                const unsigned long offset = kPageSize - 64UL + i;
                const unsigned char expected = pattern_at(offset);
                if (bytes[i] != expected && bytes[i] != 0x00U) plausible = false;
            }
            if (plausible) ++churned_ok; else ++churned_bad;
        } else {
            ++unexpected;
        }

        read_at(reinterpret_cast<unsigned long>(remapped) + kPageSize - 64UL, bytes,
                got, is_error);
        if (is_error) {
            ++churned_refused;
        } else if (got == 192U) {
            bool plausible = true;
            for (size_t i = 0; i < got; ++i) {
                const unsigned long offset = kPageSize - 64UL + i;
                const unsigned char expected = pattern_at(offset & (kPageSize - 1UL));
                if (bytes[i] != expected && bytes[i] != 0x00U) plausible = false;
            }
            if (plausible) ++churned_ok; else ++churned_bad;
        } else {
            ++unexpected;
        }
    }
    churn.stop = 1;
    pthread_join(worker, nullptr);

    std::printf("read-user-race attempts=%u stable-ok=%u stable-bad=%u "
                "churned-ok=%u churned-refused=%u churned-bad=%u unexpected=%u\n",
                kAttempts, stable_ok, stable_bad, churned_ok, churned_refused,
                churned_bad, unexpected);
    std::fflush(stdout);
    if (stable_bad != 0 || churned_bad != 0 || unexpected != 0 ||
        stable_ok != kAttempts) {
        std::fprintf(stderr,
                     "read-user-race contract violated (stable=%u/%u bad=%u,%u)\n",
                     stable_ok, kAttempts, stable_bad, churned_bad);
        return 1;
    }
    std::puts("read-user-concurrent=no-crash bytes-verified=1 munmap-covered=1");
    std::puts("stage1-read-user-race PASS");
    return 0;
#endif
}

/* Register terminal-state capture: both the original function and the clone
 * are called through this one trampoline, so the captured x0..x30 + sp are
 * directly comparable. x20 (the output pointer) is stored first, before it is
 * used as the base for the remaining stores. */
struct RegSnapshot {
    unsigned long x[31];
    unsigned long sp;
};
extern "C" void rtgum_capture_call(long (*fn)(long, long), long a, long b,
                                   RegSnapshot *out);
__asm__(
    ".text\n"
    ".global rtgum_capture_call\n"
    ".type rtgum_capture_call, %function\n"
    "rtgum_capture_call:\n"
    "    stp x29, x30, [sp, #-16]!\n"
    "    mov x29, sp\n"
    "    stp x19, x20, [sp, #-16]!\n"
    "    stp x21, x22, [sp, #-16]!\n"
    "    stp x23, x24, [sp, #-16]!\n"
    "    stp x25, x26, [sp, #-16]!\n"
    "    stp x27, x28, [sp, #-16]!\n"
    "    mov x19, x0\n"
    "    mov x20, x3\n"
    "    mov x0, x1\n"
    "    mov x1, x2\n"
    "    blr x19\n"
    "    str x20, [x20, #160]\n"
    "    stp x0, x1, [x20, #0]\n"
    "    stp x2, x3, [x20, #16]\n"
    "    stp x4, x5, [x20, #32]\n"
    "    stp x6, x7, [x20, #48]\n"
    "    stp x8, x9, [x20, #64]\n"
    "    stp x10, x11, [x20, #80]\n"
    "    stp x12, x13, [x20, #96]\n"
    "    stp x14, x15, [x20, #112]\n"
    "    stp x16, x17, [x20, #128]\n"
    "    stp x18, x19, [x20, #144]\n"
    "    str x21, [x20, #168]\n"
    "    stp x22, x23, [x20, #176]\n"
    "    stp x24, x25, [x20, #192]\n"
    "    stp x26, x27, [x20, #208]\n"
    "    stp x28, x29, [x20, #224]\n"
    "    str x30, [x20, #240]\n"
    "    mov x9, sp\n"
    "    str x9, [x20, #248]\n"
    "    ldp x19, x20, [sp], #16\n"
    "    ldp x21, x22, [sp], #16\n"
    "    ldp x23, x24, [sp], #16\n"
    "    ldp x25, x26, [sp], #16\n"
    "    ldp x27, x28, [sp], #16\n"
    "    ldp x29, x30, [sp], #16\n"
    "    ret\n"
    ".previous\n");
/* Unwinder interaction fixture: a frame that throws and a caller that catches.
 * Relocating the throwing frame and raising through the clone tells us whether
 * the platform unwinder can walk a frame whose PC lies outside any registered
 * module range (it looks FDEs up by PC via dl_iterate_phdr / .eh_frame_hdr). */
static long lab_thrower(long x)
{
    if (x != 0) throw std::runtime_error("rtgum-dbi-boom");
    return 42;
}
static long lab_catcher(long x)
{
    try {
        return lab_thrower(x);
    } catch (const std::exception &) {
        return -1;
    }
}

static __attribute__((noinline)) long dbi_blr_target(long value)
{
    return value + 7;
}

extern "C" __attribute__((naked, noinline)) long
dbi_blr_fixture(long, long (*)(long))
{
    __asm__ volatile(
        "stp x29, x30, [sp, #-16]!\n"
        "blr x1\n"
        "ldp x29, x30, [sp], #16\n"
        "ret\n");
}

extern "C" __attribute__((naked, noinline)) long
dbi_tail_target(long, long (*)(long))
{
    __asm__ volatile("br x1\n");
}

extern "C" __attribute__((naked, noinline)) long
dbi_tail_caller(long, long (*)(long))
{
    __asm__ volatile(
        "stp x29, x30, [sp, #-16]!\n"
        "bl dbi_tail_target\n"
        "ldp x29, x30, [sp], #16\n"
        "ret\n");
}

static volatile sig_atomic_t g_dbi_stalker_signal_hits = 0;
static volatile sig_atomic_t g_dbi_stalker_altstack_hits = 0;
static volatile sig_atomic_t g_dbi_stalker_in_signal = 0;
static volatile sig_atomic_t g_dbi_stalker_inner_enters = 0;
static volatile sig_atomic_t g_dbi_stalker_inner_leaves = 0;
static volatile sig_atomic_t g_dbi_stalker_inner_errors = 0;
static volatile long g_dbi_stalker_handler_result = 0;
static std::uintptr_t g_dbi_stalker_altstack_low = 0;
static std::uintptr_t g_dbi_stalker_altstack_high = 0;

static void dbi_stalker_inner_enter(RtGumInvocation *invocation, void *)
{
    if (g_dbi_stalker_in_signal == 0) return;
    ++g_dbi_stalker_inner_enters;
    if (invocation->args[0] != 2) ++g_dbi_stalker_inner_errors;
}

static void dbi_stalker_inner_leave(RtGumInvocation *invocation, void *)
{
    if (g_dbi_stalker_in_signal == 0) return;
    ++g_dbi_stalker_inner_leaves;
    if (invocation->return_value != 9) ++g_dbi_stalker_inner_errors;
}

static void dbi_stalker_signal_handler(int)
{
    volatile char stack_marker = 0;
    const auto stack_address = reinterpret_cast<std::uintptr_t>(&stack_marker);
    if (stack_address >= g_dbi_stalker_altstack_low &&
        stack_address < g_dbi_stalker_altstack_high)
        ++g_dbi_stalker_altstack_hits;
    g_dbi_stalker_in_signal = 1;
    g_dbi_stalker_handler_result = dbi_blr_fixture(2, &dbi_blr_target);
    g_dbi_stalker_in_signal = 0;
    ++g_dbi_stalker_signal_hits;
}

static __attribute__((noinline)) long dbi_blr_signal_target(long value)
{
    raise(SIGUSR1);
    return value + 7;
}

static __attribute__((noinline)) long dbi_stalker_throw_target(long)
{
    throw std::runtime_error("stalker-unwind");
}

static sigjmp_buf g_dbi_stalker_jump;

static __attribute__((noinline)) long dbi_stalker_jump_target(long)
{
    siglongjmp(g_dbi_stalker_jump, 1);
    __builtin_unreachable();
}

static __attribute__((noinline)) long dbi_stalker_unwind_call(
    long value, long (*target)(long))
{
    volatile long increment = 1;
    return target(value) + increment;
}

static int dbi_stalker_count_phdr(dl_phdr_info *, std::size_t, void *opaque)
{
    ++*static_cast<unsigned int *>(opaque);
    return 0;
}

struct DbiModuleSpan {
    unsigned long base = 0;
    std::size_t size = 0;
};

static int dbi_stalker_module_span(dl_phdr_info *info, std::size_t,
                                   void *opaque)
{
    auto *span = static_cast<DbiModuleSpan *>(opaque);
    if (static_cast<unsigned long>(info->dlpi_addr) != span->base)
        return 0;
    const std::size_t page_size = static_cast<std::size_t>(
        sysconf(_SC_PAGESIZE));
    if (page_size == 0 || (page_size & (page_size - 1U)) != 0)
        return 1;
    unsigned long end = 0;
    for (ElfW(Half) i = 0; i < info->dlpi_phnum; ++i) {
        const auto &segment = info->dlpi_phdr[i];
        if (segment.p_type != PT_LOAD ||
            segment.p_vaddr > ~0UL - segment.p_memsz)
            continue;
        const unsigned long segment_end =
            segment.p_vaddr + segment.p_memsz;
        if (segment_end > end) end = segment_end;
    }
    if (end <= ~0UL - (page_size - 1U))
        span->size = static_cast<std::size_t>(
            (end + page_size - 1U) & ~(page_size - 1U));
    return 1;
}

extern "C" __attribute__((naked, noinline)) long
dbi_pac_call(long, long (*)(long), long)
{
    __asm__ volatile(
        ".arch_extension pauth\n"
        "stp x29, x30, [sp, #-32]!\n"
        "mov x29, sp\n"
        "str x2, [sp, #16]\n"
        "mov x16, x1\n"
        "mov x17, sp\n"
        "pacia x16, x17\n"
        "ldr x2, [sp, #16]\n"
        "cbz x2, 1f\n"
        /* Corrupt a PAC bit, keeping the address bits unchanged. XPACI
         * would erase this error, making it a useful anti-bypass fixture. */
        "mov x15, #1\n"
        "lsl x15, x15, #48\n"
        "eor x16, x16, x15\n"
        "1: blraa x16, x17\n"
        "ldp x29, x30, [sp], #32\n"
        "ret\n");
}

extern "C" __attribute__((naked, noinline)) long dbi_bti_call(void *)
{
    __asm__ volatile(
        "stp x29, x30, [sp, #-16]!\n"
        "blr x0\n"
        "ldp x29, x30, [sp], #16\n"
        "ret\n");
}

extern "C" __attribute__((naked, noinline)) long
dbi_pac_return_fixture(long, long)
{
    __asm__ volatile(
        ".arch_extension pauth\n"
        "paciasp\n"
        "cbz x1, 1f\n"
        "mov x15, #1\n"
        "lsl x15, x15, #48\n"
        "eor x30, x30, x15\n"
        "1: add x0, x0, #7\n"
        "retaa\n");
}

extern "C" __attribute__((naked, noinline)) long
dbi_pac_b_call(long, long (*)(long), long)
{
    __asm__ volatile(
        ".arch_extension pauth\n"
        "stp x29, x30, [sp, #-32]!\n"
        "mov x29, sp\n"
        "str x2, [sp, #16]\n"
        "mov x16, x1\n"
        "mov x17, sp\n"
        "pacib x16, x17\n"
        "ldr x2, [sp, #16]\n"
        "cbz x2, 1f\n"
        "mov x15, #1\n"
        "lsl x15, x15, #48\n"
        "eor x16, x16, x15\n"
        "1: blrab x16, x17\n"
        "ldp x29, x30, [sp], #32\n"
        "ret\n");
}

extern "C" __attribute__((naked, noinline)) long
dbi_pac_b_return_fixture(long, long)
{
    __asm__ volatile(
        ".arch_extension pauth\n"
        "pacibsp\n"
        "cbz x1, 1f\n"
        "mov x15, #1\n"
        "lsl x15, x15, #48\n"
        "eor x30, x30, x15\n"
        "1: add x0, x0, #7\n"
        "retab\n");
}

static __attribute__((noinline)) bool dbi_pac_auth_matches_strip(
    unsigned long address)
{
    unsigned long modifier = 0x12345678UL;
    __asm__ volatile(".arch_extension pauth\n\tpacia %0, %1"
                     : "+r"(address) : "r"(modifier));
    unsigned long authenticated = address;
    unsigned long stripped = address;
    __asm__ volatile(".arch_extension pauth\n\tautia %0, %1"
                     : "+r"(authenticated) : "r"(modifier));
    __asm__ volatile(".arch_extension pauth\n\txpaci %0"
                     : "+r"(stripped));
    return authenticated == stripped;
}

int g_dbi_hardening_signal_fd = -1;

void dbi_hardening_signal_handler(int signo, siginfo_t *info, void *)
{
    const int evidence[2] = {signo, info ? info->si_code : 0};
    if (g_dbi_hardening_signal_fd >= 0)
        (void)write(g_dbi_hardening_signal_fd, evidence, sizeof(evidence));
    _exit(0);
}

struct DbiHardwareFault {
    bool observed;
    int signal;
    int code;
};

DbiHardwareFault dbi_observe_hardware_fault(bool pac, void *bti_target,
                                           bool pac_return = false,
                                           bool key_b = false)
{
    int channel[2] = {-1, -1};
    if (pipe(channel) != 0) return {};
    const pid_t child = fork();
    if (child == 0) {
        close(channel[0]);
        g_dbi_hardening_signal_fd = channel[1];
        struct sigaction action{};
        action.sa_sigaction = dbi_hardening_signal_handler;
        action.sa_flags = SA_SIGINFO;
        sigemptyset(&action.sa_mask);
        if (sigaction(SIGILL, &action, nullptr) != 0) _exit(10);
        if (pac && pac_return)
            (void)(key_b ? dbi_pac_b_return_fixture(35, 1)
                         : dbi_pac_return_fixture(35, 1));
        else if (pac)
            (void)(key_b ? dbi_pac_b_call(35, &dbi_blr_target, 1)
                         : dbi_pac_call(35, &dbi_blr_target, 1));
        else
            (void)dbi_bti_call(bti_target);
        _exit(11); // the hardware unexpectedly accepted the bad target
    }
    close(channel[1]);
    int evidence[2]{};
    const ssize_t got = read(channel[0], evidence, sizeof(evidence));
    close(channel[0]);
    int status = 0;
    const bool waited = child > 0 && waitpid(child, &status, 0) == child;
    return {waited && WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
                got == static_cast<ssize_t>(sizeof(evidence)),
            evidence[0], evidence[1]};
}
/* _Unwind_Find_FDE is exported by some versions of bionic only, so it is not
 * declared here: the lab resolves it with dlsym. Its return value is used only
 * to answer "does this PC now have a frame, and is it the copy we registered?".
 * It is deliberately NOT used to derive the CIE offset: on this target the
 * loader rewrites the .eh_frame_hdr lookup table in place, so a record reached
 * through the unwinder does not sit at the same offset inside .eh_frame as the
 * on-disk section, and offset arithmetic against the section base silently
 * lands a few bytes off. The linear scan reads the section itself and is
 * therefore the authority on offsets. */
struct UnwindFindFdeBases {
    void *tbase;
    void *dbase;
    void *func;
};
using UnwindFindFdeFn = const void *(*)(const void *, UnwindFindFdeBases *);
// The control tool statically links its C++ unwinder. dlsym(RTLD_DEFAULT, ...)
// resolves bionic's different copy, whose dynamic FDE cache is unrelated to
// the __register_frame linked into this executable.
extern "C" const void *_Unwind_Find_FDE(const void *, UnwindFindFdeBases *);

/* Resolved once per process: a lazy PLT call would fault in the dynamic linker
 * on a libc that does not export the symbol at all. */
static UnwindFindFdeFn g_unwind_find_fde = nullptr;
static bool g_unwind_find_resolved = false;
/* What the unwinder last reported, kept for diagnostics. */
static const void *g_unwind_fde = nullptr;

static UnwindFindFdeFn unwind_find_symbol()
{
    if (!g_unwind_find_resolved) {
        g_unwind_find_resolved = true;
        g_unwind_find_fde = reinterpret_cast<UnwindFindFdeFn>(
            dlsym(RTLD_DEFAULT, "_Unwind_Find_FDE"));
    }
    return g_unwind_find_fde;
}

/* Cross-checks the header's own resolution against the unwinder's, using the
 * source PC of a function whose FDE the unwinder is known to find. Both sides
 * are printed as offsets from the section the header resolved, together with the
 * raw bytes each side sees, so a disagreement points at the byte rather than at
 * a theory about the layout. */
static void diagnose_frame_offsets(uint64_t source_pc,
                                   const rtgum_dbi::EhModule &module,
                                   const rtgum_dbi::FdeLocation &location)
{
    UnwindFindFdeFn find = unwind_find_symbol();
    const uint8_t *section = module.eh_frame;
    std::printf("dbi-ehframe-offsets section=0x%lx scan-fde=+0x%llx scan-cie=+0x%llx "
                "section-head=%02x%02x%02x%02x\n",
                static_cast<unsigned long>(reinterpret_cast<uintptr_t>(section)),
                static_cast<unsigned long long>(location.fde_offset),
                static_cast<unsigned long long>(location.cie_offset),
                section[0], section[1], section[2], section[3]);
    if (find == nullptr) {
        std::printf("dbi-ehframe-offsets unwinder=absent\n");
        return;
    }
    UnwindFindFdeBases bases{};
    const void *fde = find(reinterpret_cast<const void *>(source_pc), &bases);
    g_unwind_fde = fde;
    if (fde == nullptr) {
        std::printf("dbi-ehframe-offsets unwinder=none\n");
        return;
    }
    const uint8_t *record = static_cast<const uint8_t *>(fde);
    const uint8_t *cie = record + 4U - rtgum_dbi::detail::read_u32(record, 4);
    std::printf("dbi-ehframe-offsets unwinder-fde=+0x%llx unwinder-cie=+0x%llx "
                "record=%02x%02x%02x%02x%02x%02x%02x%02x\n",
                static_cast<unsigned long long>(
                    reinterpret_cast<uint64_t>(record) -
                    reinterpret_cast<uint64_t>(section)),
                static_cast<unsigned long long>(
                    reinterpret_cast<uint64_t>(cie) -
                    reinterpret_cast<uint64_t>(section)),
                record[0], record[1], record[2], record[3], record[4], record[5],
                record[6], record[7]);
    if (location.cie_offset != 0U) {
        const uint8_t *scan_cie = section + location.cie_offset;
        std::printf("dbi-ehframe-offsets scan-cie-bytes=%02x%02x%02x%02x%02x%02x%02x%02x "
                    "unwinder-cie-bytes=%02x%02x%02x%02x%02x%02x%02x%02x\n",
                    scan_cie[0], scan_cie[1], scan_cie[2], scan_cie[3], scan_cie[4],
                    scan_cie[5], scan_cie[6], scan_cie[7],
                    cie[0], cie[1], cie[2], cie[3], cie[4], cie[5], cie[6], cie[7]);
    }
    std::fflush(stdout);
}

int command_dbi_ldr_test(const char *key)
{
#if !defined(__aarch64__)
    (void)key;
    return 1;
#else
    (void)key;
    constexpr uint32_t kRet = 0xd65f03c0U;
    const unsigned long page_size = 0x1000UL;
    /* Reserve enough room to host the fixture plus clones at +/-1MB, so the
     * exact reach boundaries can be probed without fighting the process's
     * own mappings. */
    const unsigned long reserve = 6UL * 1024UL * 1024UL;
    void *reservation = mmap(nullptr, reserve, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (reservation == MAP_FAILED) {
        std::fprintf(stderr, "dbi-ldr reservation mmap failed\n");
        return 1;
    }
    void *block = reinterpret_cast<void *>(
        reinterpret_cast<unsigned long>(reservation) + 2UL * 1024UL * 1024UL);
    const unsigned long base = reinterpret_cast<unsigned long>(block);
    /* The far clone must sit outside the +/-1MB literal reach, otherwise the
     * in-range re-encode hides the absolute-rewrite path entirely. */
    void *far = MAP_FAILED;
    const unsigned long far_offsets[] = {0x10000000UL, 0x20000000UL, 0x40000000UL,
                                         0x80000000UL, 0x100000000UL};
    for (unsigned long offset : far_offsets) {
        void *candidate = mmap(reinterpret_cast<void *>((base + offset) & ~0xfffUL),
                               page_size, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                               -1, 0);
        if (candidate != MAP_FAILED) {
            far = candidate;
            break;
        }
    }
    if (far == MAP_FAILED) {
        /* Last resort: a natural mapping, as long as it is clearly outside the
         * +/-1MB literal reach (asserted below). */
        far = mmap(nullptr, page_size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (far == MAP_FAILED) {
            std::fprintf(stderr, "dbi-ldr far mmap failed\n");
            return 1;
        }
    }
    std::printf("dbi-ldr base=0x%lx far=0x%lx distance-mb=%lu\n", base,
                reinterpret_cast<unsigned long>(far),
                (reinterpret_cast<unsigned long>(far) - base) >> 20);
    std::fflush(stdout);

    struct Case {
        const char *name;
        uint32_t load;       // the literal-load instruction under test
        uint64_t literal;    // the 8-byte literal it reads
        bool supported;      // must relocate and execute identically
        rtgum_dbi::RejectReason reason;
    };
    // imm19 = 2 -> the literal sits 8 bytes ahead (directly after [load; ret]).
    auto literal_load = [](uint32_t opcode_base, uint32_t rt) {
        return opcode_base | rt | (2U << 5U);
    };
    const Case cases[] = {
        {"ldr-x", literal_load(0x58000000U, 0), 0x1122334455667788ULL, true,
         rtgum_dbi::RejectReason::None},
        {"ldr-w", literal_load(0x18000000U, 0), 0xffffffff80000001ULL, true,
         rtgum_dbi::RejectReason::None},
        {"ldrsw", literal_load(0x98000000U, 0), 0xffffffff80000001ULL, true,
         rtgum_dbi::RejectReason::None},
        {"prfm", literal_load(0xd8000000U, 0), 0x1122334455667788ULL, false,
         rtgum_dbi::RejectReason::LdrLiteralPrfm},
        {"simd", literal_load(0x5c000000U, 0), 0x1122334455667788ULL, false,
         rtgum_dbi::RejectReason::LdrLiteralSimd},
        {"xzr", literal_load(0x58000000U, 31), 0x1122334455667788ULL, false,
         rtgum_dbi::RejectReason::LdrLiteralZeroRegister},
    };
    unsigned int passed = 0;
    unsigned int rejected = 0;
    for (const Case &item : cases) {
        if (mprotect(reinterpret_cast<void *>(base), page_size,
                     PROT_READ | PROT_WRITE) != 0) {
            std::fprintf(stderr, "dbi-ldr base write-enable failed\n");
            return 1;
        }
        auto *words = reinterpret_cast<uint32_t *>(base);
        words[0] = item.load;
        words[1] = kRet;
        *reinterpret_cast<uint64_t *>(base + 8) = item.literal;
        __builtin___clear_cache(reinterpret_cast<char *>(base),
                                reinterpret_cast<char *>(base) + 16);
        if (mprotect(reinterpret_cast<void *>(base), page_size,
                     PROT_READ | PROT_EXEC) != 0) {
            std::fprintf(stderr, "dbi-ldr mprotect failed\n");
            return 1;
        }
        auto *original = reinterpret_cast<unsigned long (*)(void)>(base);
        std::printf("dbi-ldr %s: calling original\n", item.name);
        std::fflush(stdout);
        const unsigned long expected = original();
        std::printf("dbi-ldr %s: original=0x%lx\n", item.name, expected);
        std::fflush(stdout);

        auto relocate_into = [&](unsigned long target, const char *label,
                                 rtgum_dbi::RelocationResult &result,
                                 unsigned long &observed) -> int {
            static uint8_t code[4096];
            static rtgum_dbi::OffsetMapEntry map[16];
            static rtgum_dbi::BranchTraceEntry trace[16];
            static rtgum_dbi::LiteralRange literals[16];
            result = rtgum_dbi::make_result(code, sizeof(code), map, 16, trace, 16,
                                            literals, 16);
            if (!rtgum_dbi::Relocator::relocate(
                    reinterpret_cast<const void *>(base), 8UL, base, target,
                    result)) {
                std::printf("dbi-ldr %s %s relocate=rejected reason=%u opcode=0x%08x "
                            "subtype=%u src=0x%lx literal=0x%llx clone=0x%lx delta=%lld\n",
                            item.name, label,
                            static_cast<unsigned>(result.reject.reason),
                            result.reject.opcode,
                            static_cast<unsigned>(result.reject.subtype),
                            static_cast<unsigned long>(result.reject.source_pc),
                            static_cast<unsigned long long>(result.reject.target),
                            static_cast<unsigned long>(result.reject.clone_pc),
                            static_cast<long long>(result.reject.delta));
                return 1;
            }
            if (result.literal_size != result.literal_count) {
                std::fprintf(stderr, "dbi-ldr %s %s: incomplete literal metadata\n",
                             item.name, label);
                return -1;
            }
            mprotect(reinterpret_cast<void *>(target), page_size,
                     PROT_READ | PROT_WRITE);
            std::memcpy(reinterpret_cast<void *>(target), result.code,
                        result.code_size);
            __builtin___clear_cache(reinterpret_cast<char *>(target),
                                    reinterpret_cast<char *>(target) +
                                        result.code_size);
            if (mprotect(reinterpret_cast<void *>(target), page_size,
                         PROT_READ | PROT_EXEC) != 0)
                return -1;
            auto *relocated =
                reinterpret_cast<unsigned long (*)(void)>(target);
            observed = relocated();
            return 0;
        };

        if (!item.supported) {
            rtgum_dbi::RelocationResult result{};
            unsigned long observed = 0;
            const int status = relocate_into(
                reinterpret_cast<unsigned long>(far), "far", result, observed);
            if (status != 1 || result.reject.reason != item.reason) {
                std::fprintf(stderr,
                             "dbi-ldr %s: expected rejection reason %u\n",
                             item.name, static_cast<unsigned>(item.reason));
                return 1;
            }
            ++rejected;
            continue;
        }

        rtgum_dbi::RelocationResult near_result{};
        rtgum_dbi::RelocationResult far_result{};
        unsigned long near_value = 0;
        unsigned long far_value = 0;
        const unsigned long near_target = base + page_size; /* within +1MB */
        if (relocate_into(near_target, "near", near_result, near_value) != 0 ||
            relocate_into(reinterpret_cast<unsigned long>(far), "far",
                          far_result, far_value) != 0) {
            std::fprintf(stderr, "dbi-ldr %s: relocation failed\n", item.name);
            return 1;
        }
        std::printf("dbi-ldr %s expected=0x%lx near=0x%lx far=0x%lx "
                    "near-expanded=%u far-expanded=%u\n",
                    item.name, expected, near_value, far_value,
                    near_result.expanded_branches, far_result.expanded_branches);
        if (expected != near_value || expected != far_value) {
            std::fprintf(stderr, "dbi-ldr %s: value mismatch\n", item.name);
            return 1;
        }
        ++passed;
    }
    /* Exact reach boundaries: the literal sits at base+8, so the in-range
     * window is (base+8) +/- 1MB. Both sides are probed at page granularity
     * and the emitted size tells which path was taken (8 bytes = re-encoded
     * in place, 28 bytes = absolute rewrite), so the boundary itself is
     * verified rather than assumed. */
    {
        if (mprotect(reinterpret_cast<void *>(base), page_size,
                     PROT_READ | PROT_WRITE) != 0)
            return 1;
        auto *words = reinterpret_cast<uint32_t *>(base);
        words[0] = literal_load(0x58000000U, 0);
        words[1] = kRet;
        *reinterpret_cast<uint64_t *>(base + 8) = 0x1122334455667788ULL;
        __builtin___clear_cache(reinterpret_cast<char *>(base),
                                reinterpret_cast<char *>(base) + 16);
        if (mprotect(reinterpret_cast<void *>(base), page_size,
                     PROT_READ | PROT_EXEC) != 0)
            return 1;
        const unsigned long expected =
            reinterpret_cast<unsigned long (*)(void)>(base)();
        struct Edge {
            const char *label;
            unsigned long offset;
            bool expect_rewrite;
        };
        const Edge edges[] = {
            {"in-range-just-below", 0x100000UL - page_size, false},
            {"out-of-range-just-above", 0x100000UL + page_size, true},
        };
        for (const Edge &edge : edges) {
            const unsigned long site = (base + edge.offset + page_size - 1UL) &
                                       ~(page_size - 1UL);
            void *page = reinterpret_cast<void *>(site); /* inside our reservation */
            if (site < reinterpret_cast<unsigned long>(reservation) + 2UL * page_size ||
                site + page_size >
                    reinterpret_cast<unsigned long>(reservation) + reserve) {
                std::printf("dbi-ldr edge %s: site 0x%lx outside reservation\n",
                            edge.label, site);
                continue;
            }
            static uint8_t edge_code[4096];
            static rtgum_dbi::OffsetMapEntry edge_map[16];
            static rtgum_dbi::BranchTraceEntry edge_trace[16];
            static rtgum_dbi::LiteralRange edge_literals[16];
            rtgum_dbi::RelocationResult result = rtgum_dbi::make_result(
                edge_code, sizeof(edge_code), edge_map, 16, edge_trace, 16,
                edge_literals, 16);
            if (!rtgum_dbi::Relocator::relocate(
                    reinterpret_cast<const void *>(base), 8UL, base, site,
                    result)) {
                std::fprintf(stderr, "dbi-ldr edge %s: relocate failed\n",
                             edge.label);
                return 1;
            }
            if (result.literal_size != result.literal_count) {
                std::fprintf(stderr, "dbi-ldr edge %s: incomplete literal metadata\n",
                             edge.label);
                return 1;
            }
            std::memcpy(page, result.code, result.code_size);
            __builtin___clear_cache(reinterpret_cast<char *>(site),
                                    reinterpret_cast<char *>(site) +
                                        result.code_size);
            if (mprotect(reinterpret_cast<void *>(site), page_size,
                         PROT_READ | PROT_EXEC) != 0)
                return 1;
            const unsigned long observed =
                reinterpret_cast<unsigned long (*)(void)>(site)();
            const bool rewrote = result.code_size > 8UL;
            const long long delta =
                static_cast<long long>(site) - static_cast<long long>(base + 8UL);
            std::printf("dbi-ldr edge %s literal-to-clone=%lld bytes=%zu "
                        "rewrite=%d expected-rewrite=%d value=0x%lx\n",
                        edge.label, delta, result.code_size, rewrote ? 1 : 0,
                        edge.expect_rewrite ? 1 : 0, observed);
            std::fflush(stdout);
            if (observed != expected || rewrote != edge.expect_rewrite) {
                std::fprintf(stderr, "dbi-ldr edge %s: boundary decision wrong\n",
                             edge.label);
                return 1;
            }
        }
    }

    std::printf("dbi-ldr executed=%u rejected=%u\n", passed, rejected);
    std::fflush(stdout);
    if (passed != 3U || rejected != 3U) {
        std::fprintf(stderr, "dbi-ldr matrix incomplete\n");
        return 1;
    }
    std::puts("ldr-literal-subtypes=1 range-boundaries=1 reject-reasons=1");
    std::puts("stage1-dbi-ldr PASS");
    return 0;
#endif
}

int command_dbi_hardening_test()
{
#if !defined(__aarch64__)
    return 1;
#else
    const unsigned long hwcap = getauxval(AT_HWCAP);
    const unsigned long hwcap2 = getauxval(AT_HWCAP2);
    const bool pac_present = (hwcap & HWCAP_PACA) != 0;
    const bool bti_present = (hwcap2 & HWCAP2_BTI) != 0;
    if (!pac_present || !bti_present) {
        std::printf("dbi-hardening pac-hw=%d bti-hw=%d unsupported\n",
                    pac_present ? 1 : 0, bti_present ? 1 : 0);
        return 1;
    }

    const long pac_positive = dbi_pac_call(35, &dbi_blr_target, 0);
    const DbiHardwareFault pac_fault = dbi_observe_hardware_fault(true, nullptr);

    const long page_size = sysconf(_SC_PAGESIZE);
    if (page_size < 4096) return 1;
    void *pages = mmap(nullptr, static_cast<size_t>(page_size) * 2U,
                       PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
                       -1, 0);
    if (pages == MAP_FAILED) return 1;
    auto *valid = static_cast<uint32_t *>(pages);
    auto *invalid = reinterpret_cast<uint32_t *>(
        static_cast<uint8_t *>(pages) + page_size);
    valid[0] = 0xd503245fU;  // BTI c
    invalid[0] = 0xd503201fU; // NOP is not a guarded call landing
    valid[1] = invalid[1] = 0xd2800540U; // mov x0, #42
    valid[2] = invalid[2] = 0xd65f03c0U; // ret
    __builtin___clear_cache(static_cast<char *>(pages),
                            static_cast<char *>(pages) + page_size * 2U);
    if (mprotect(pages, static_cast<size_t>(page_size) * 2U,
                 PROT_READ | PROT_EXEC | PROT_BTI) != 0) {
        std::printf("dbi-hardening PROT_BTI mprotect errno=%d\n", errno);
        munmap(pages, static_cast<size_t>(page_size) * 2U);
        return 1;
    }
    const pid_t bti_good_child = fork();
    if (bti_good_child == 0)
        _exit(dbi_bti_call(valid) == 42 ? 0 : 6);
    int bti_good_status = 0;
    if (bti_good_child <= 0 ||
        waitpid(bti_good_child, &bti_good_status, 0) != bti_good_child) {
        munmap(pages, static_cast<size_t>(page_size) * 2U);
        return 1;
    }
    const DbiHardwareFault bti_fault = dbi_observe_hardware_fault(false, invalid);
    const bool bti_good = WIFEXITED(bti_good_status) &&
        WEXITSTATUS(bti_good_status) == 0;
    munmap(pages, static_cast<size_t>(page_size) * 2U);
    std::printf("dbi-hardening pac-positive=%ld pac-negative-signal=%d "
                "pac-code=%d bti-positive=%d bti-negative-signal=%d bti-code=%d\n",
                pac_positive, pac_fault.signal, pac_fault.code,
                bti_good ? 1 : 0, bti_fault.signal, bti_fault.code);
    if (pac_positive != 42 || !pac_fault.observed ||
        pac_fault.signal != SIGILL || pac_fault.code != ILL_ILLOPN ||
        !bti_good || !bti_fault.observed || bti_fault.signal != SIGILL ||
        bti_fault.code != ILL_ILLOPC)
        return 1;
    std::puts("stage1-dbi-hardening PASS");
    return 0;
#endif
}

int command_dbi_stalker_lab(bool exercise_unwind = false,
                            bool exercise_phdr = false)
{
#if !defined(__aarch64__)
    return 1;
#else
    const pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        void *image = dlopen(
            "/data/local/tmp/rtgum-stage1-pixel8/librtgum-gum-ghost.so",
            RTLD_NOW | RTLD_LOCAL);
        if (!image) {
            std::fprintf(stderr, "dbi-stalker dlopen: %s\n", dlerror());
            _exit(2);
        }
        auto *entry = reinterpret_cast<RtGumEntry>(dlsym(image, "rtgum_gum_entry"));
        RtGumHost host{};
        RtGumApi api{};
        host.version = RTGUM_GUM_API_VERSION;
        if (!entry || entry(&host, &api) != 0 ||
            !api.stalker_start || !api.stalker_invalidate ||
            !api.stalker_stop) {
            std::fprintf(stderr, "dbi-stalker bind failed\n");
            _exit(3);
        }
        if (exercise_unwind || exercise_phdr) {
            using DbiPhdrIterator = int (*)(
                int (*)(dl_phdr_info *, std::size_t, void *), void *);
            auto *phdr_iterator = exercise_phdr
                ? reinterpret_cast<DbiPhdrIterator>(
                    dlsym(RTLD_DEFAULT, "dl_iterate_phdr")) : nullptr;
            if (exercise_unwind) {
                bool native_caught = false;
                try {
                    dbi_stalker_unwind_call(1, &dbi_stalker_throw_target);
                } catch (const std::runtime_error &) {
                    native_caught = true;
                }
                std::fprintf(stderr, "dbi-stalker-unwind native-caught=%d\n",
                             native_caught ? 1 : 0);
                if (!native_caught) _exit(5);
            }
            RtGumStalkerStats unwind_stats{};
            const long unwind_started = api.stalker_start(
                &unwind_stats,
                reinterpret_cast<unsigned long>(&dbi_stalker_unwind_call), 64UL);
            if (exercise_phdr) {
                unsigned int plt_count = 0;
                unsigned int pointer_count = 0;
                unsigned int dynamic_count = 0;
                unsigned int postload_count = 0;
                unsigned int worker_count = 0;
                unsigned int postworker_count = 0;
                unsigned int replacement_count = 0;
                unsigned int native_replacement_count = 0;
                unsigned int postreplacement_count = 0;
                RtGumStalkerStats reload_stats{};
                long reload_stopped = -1;
                long reload_started = -1;
                void *dynamic_fixture = nullptr;
                void *worker_fixture = nullptr;
                void *replacement_fixture = nullptr;
                void *reserved_area = MAP_FAILED;
                DbiModuleSpan dynamic_span{};
                bool base_reused = false;
                if (unwind_started == 0) {
                    dl_iterate_phdr(&dbi_stalker_count_phdr, &plt_count);
                    if (phdr_iterator != nullptr)
                        phdr_iterator(&dbi_stalker_count_phdr,
                                      &pointer_count);
                    dynamic_fixture = dlopen(
                        "/data/local/tmp/rtgum-stage1-pixel8/"
                        "librtgum-dbi-dynamic-phdr.so",
                        RTLD_NOW | RTLD_LOCAL);
                    std::fprintf(stderr, "dbi-stalker-phdr dynamic-loaded=%d\n",
                                 dynamic_fixture != nullptr ? 1 : 0);
                    if (dynamic_fixture != nullptr) {
                        using DynamicPhdrProbe = unsigned int (*)();
                        auto *probe = reinterpret_cast<DynamicPhdrProbe>(
                            dlsym(dynamic_fixture, "rtgum_dynamic_phdr_probe"));
                        std::fprintf(stderr, "dbi-stalker-phdr dynamic-probe=%d\n",
                                     probe != nullptr ? 1 : 0);
                        if (probe != nullptr) {
                            dynamic_count = probe();
                            Dl_info module_info{};
                            if (dladdr(reinterpret_cast<void *>(probe),
                                       &module_info) != 0) {
                                dynamic_span.base = reinterpret_cast<
                                    unsigned long>(module_info.dli_fbase);
                                dl_iterate_phdr(&dbi_stalker_module_span,
                                                &dynamic_span);
                            }
                        }
                        dl_iterate_phdr(&dbi_stalker_count_phdr,
                                        &postload_count);
                    }
                    std::thread loader([&worker_fixture] {
                        worker_fixture = dlopen(
                            "/data/local/tmp/rtgum-stage1-pixel8/"
                            "librtgum-dbi-dynamic-phdr-worker.so",
                            RTLD_NOW | RTLD_LOCAL);
                    });
                    loader.join();
                    if (worker_fixture != nullptr) {
                        using DynamicPhdrProbe = unsigned int (*)();
                        auto *probe = reinterpret_cast<DynamicPhdrProbe>(
                            dlsym(worker_fixture, "rtgum_dynamic_phdr_probe"));
                        if (probe != nullptr) worker_count = probe();
                        dl_iterate_phdr(&dbi_stalker_count_phdr,
                                        &postworker_count);
                    }
                    if (dynamic_fixture != nullptr &&
                        dynamic_span.base != 0 &&
                        dynamic_span.size != 0 &&
                        dynamic_span.size <= (1U << 20U)) {
                        /* Gum exclusions and compiled call transfers belong
                         * to one module generation. Retire that session
                         * before dlclose can reuse its PLT addresses. */
                        reload_stopped = api.stalker_stop();
                        if (reload_stopped != 0) _exit(5);
                        dlclose(dynamic_fixture);
                        dynamic_fixture = nullptr;
                        reserved_area = mmap(
                            reinterpret_cast<void *>(dynamic_span.base),
                            dynamic_span.size, PROT_NONE,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                            -1, 0);
                        if (reserved_area ==
                            reinterpret_cast<void *>(dynamic_span.base)) {
                            android_dlextinfo ext{};
                            ext.flags = ANDROID_DLEXT_RESERVED_ADDRESS;
                            ext.reserved_addr = reserved_area;
                            ext.reserved_size = dynamic_span.size;
                            replacement_fixture = android_dlopen_ext(
                                "/data/local/tmp/rtgum-stage1-pixel8/"
                                "librtgum-dbi-dynamic-phdr-replacement.so",
                                RTLD_NOW | RTLD_LOCAL, &ext);
                            if (replacement_fixture != nullptr) {
                                using DynamicPhdrProbe = unsigned int (*)();
                                auto *probe = reinterpret_cast<DynamicPhdrProbe>(
                                    dlsym(replacement_fixture,
                                          "rtgum_dynamic_phdr_probe"));
                                Dl_info replacement_info{};
                                if (probe != nullptr &&
                                    dladdr(reinterpret_cast<void *>(probe),
                                           &replacement_info) != 0) {
                                    base_reused = replacement_info.dli_fbase ==
                                        reserved_area;
                                    native_replacement_count = probe();
                                    reload_started = api.stalker_start(
                                        &reload_stats,
                                        reinterpret_cast<unsigned long>(
                                            &dbi_stalker_unwind_call), 64UL);
                                    if (reload_started == 0)
                                        replacement_count = probe();
                                    dl_iterate_phdr(&dbi_stalker_count_phdr,
                                                    &postreplacement_count);
                                }
                            }
                        }
                    }
                }
                const long unwind_stopped = reload_started == 0
                    ? api.stalker_stop()
                    : reload_stopped != 0 && unwind_started == 0
                        ? api.stalker_stop() : -1;
                if (replacement_fixture != nullptr)
                    dlclose(replacement_fixture);
                if (reserved_area != MAP_FAILED)
                    munmap(reserved_area, dynamic_span.size);
                if (worker_fixture != nullptr) dlclose(worker_fixture);
                if (dynamic_fixture != nullptr) dlclose(dynamic_fixture);
                std::fprintf(stderr,
                             "dbi-stalker-phdr start=%ld plt=%u ptr=%u "
                             "dynamic=%u postload=%u worker=%u "
                             "postworker=%u reload-stop=%ld reload-start=%ld "
                             "reused=%d native-replacement=%u replacement=%u "
                             "postreplacement=%u reload-blocks=%lu stop=%ld\n",
                             unwind_started, plt_count, pointer_count,
                             dynamic_count, postload_count, worker_count,
                             postworker_count, reload_stopped, reload_started,
                             base_reused ? 1 : 0,
                             native_replacement_count, replacement_count,
                             postreplacement_count,
                             reload_stats.blocks,
                             unwind_stopped);
                _exit(unwind_started == 0 && plt_count > 0 &&
                       pointer_count == plt_count &&
                       dynamic_count == postload_count &&
                       dynamic_count > plt_count &&
                       worker_count == postworker_count &&
                       worker_count > dynamic_count &&
                       reload_stopped == 0 && reload_started == 0 &&
                       base_reused &&
                       native_replacement_count ==
                           postreplacement_count + 1000U &&
                       replacement_count == postreplacement_count + 1000U &&
                       reload_stats.blocks > 0 &&
                       unwind_stopped == 0 ? 0 : 5);
            }
            long unwind_first = -1;
            long unwind_after = -1;
            bool unwind_caught = false;
            if (unwind_started == 0) {
                unwind_first = dbi_stalker_unwind_call(5, &dbi_blr_target);
                try {
                    dbi_stalker_unwind_call(1, &dbi_stalker_throw_target);
                } catch (const std::runtime_error &) {
                    unwind_caught = true;
                }
                unwind_after = dbi_stalker_unwind_call(7, &dbi_blr_target);
            }
            const long unwind_stopped = unwind_started == 0
                ? api.stalker_stop() : -1;
            std::printf("dbi-stalker-unwind start=%ld first=%ld caught=%d "
                        "after=%ld stop=%ld matched=%lu mismatched=%lu "
                        "unpaired=%lu unwound=%lu overflow=%lu remaining=%lu\n",
                        unwind_started, unwind_first, unwind_caught ? 1 : 0,
                        unwind_after, unwind_stopped,
                        unwind_stats.matched_returns,
                        unwind_stats.mismatched_returns,
                        unwind_stats.unpaired_returns,
                        unwind_stats.unwound_frames,
                        unwind_stats.shadow_overflow,
                        unwind_stats.shadow_remaining);
            const bool resumed_pass = unwind_started == 0 &&
                unwind_first == 13 && unwind_caught && unwind_after == 15 &&
                unwind_stopped == 0 &&
                unwind_stats.matched_returns >= 2 &&
                unwind_stats.mismatched_returns == 0 &&
                unwind_stats.unpaired_returns == 0 &&
                unwind_stats.unwound_frames >= 1 &&
                unwind_stats.shadow_remaining == 0;
            RtGumStalkerStats direct_stats{};
            const long direct_started = api.stalker_start(
                &direct_stats,
                reinterpret_cast<unsigned long>(&dbi_stalker_unwind_call), 64UL);
            bool direct_caught = false;
            if (direct_started == 0) {
                try {
                    dbi_stalker_unwind_call(1, &dbi_stalker_throw_target);
                } catch (const std::runtime_error &) {
                    direct_caught = true;
                }
            }
            const long direct_stopped = direct_started == 0
                ? api.stalker_stop() : -1;
            std::printf("dbi-stalker-unwind direct-stop start=%ld caught=%d "
                        "stop=%ld unwound=%lu remaining=%lu\n",
                        direct_started, direct_caught ? 1 : 0,
                        direct_stopped, direct_stats.unwound_frames,
                        direct_stats.shadow_remaining);
            RtGumStalkerStats jump_stats{};
            const long jump_started = api.stalker_start(
                &jump_stats,
                reinterpret_cast<unsigned long>(&dbi_stalker_unwind_call), 64UL);
            volatile int jumped = 0;
            if (jump_started == 0) {
                if (sigsetjmp(g_dbi_stalker_jump, 1) == 0)
                    dbi_stalker_unwind_call(1, &dbi_stalker_jump_target);
                else
                    jumped = 1;
            }
            const long jump_after = jump_started == 0 && jumped == 1
                ? dbi_stalker_unwind_call(9, &dbi_blr_target) : -1;
            const long jump_stopped = jump_started == 0
                ? api.stalker_stop() : -1;
            std::printf("dbi-stalker-unwind longjmp start=%ld jumped=%d "
                        "after=%ld stop=%ld matched=%lu unwound=%lu "
                        "remaining=%lu\n",
                        jump_started, static_cast<int>(jumped), jump_after,
                        jump_stopped, jump_stats.matched_returns,
                        jump_stats.unwound_frames,
                        jump_stats.shadow_remaining);
            const unsigned int native_personality_before =
                rtgum_dbi_personality_hits;
            bool native_personality_caught = false;
            try {
                rtgum_dbi_personality_frame(&dbi_stalker_throw_target, 1);
            } catch (const std::runtime_error &) {
                native_personality_caught = true;
            }
            const unsigned int native_personality_calls =
                rtgum_dbi_personality_hits - native_personality_before;
            RtGumStalkerStats personality_stats{};
            const long personality_started = api.stalker_start(
                &personality_stats,
                reinterpret_cast<unsigned long>(&rtgum_dbi_personality_frame),
                32UL);
            long personality_first = -1;
            long personality_after = -1;
            bool personality_caught = false;
            const unsigned int personality_before = rtgum_dbi_personality_hits;
            if (personality_started == 0) {
                personality_first = rtgum_dbi_personality_frame(
                    &dbi_blr_target, 5);
                try {
                    rtgum_dbi_personality_frame(
                        &dbi_stalker_throw_target, 1);
                } catch (const std::runtime_error &) {
                    personality_caught = true;
                }
                personality_after = rtgum_dbi_personality_frame(
                    &dbi_blr_target, 7);
            }
            const long personality_stopped = personality_started == 0
                ? api.stalker_stop() : -1;
            const unsigned int personality_calls =
                rtgum_dbi_personality_hits - personality_before;
            std::printf("dbi-stalker-unwind custom-personality "
                        "native-caught=%d native-calls=%u start=%ld "
                        "first=%ld caught=%d calls=%u after=%ld stop=%ld "
                        "matched=%lu mismatched=%lu unpaired=%lu "
                        "unwound=%lu remaining=%lu\n",
                        native_personality_caught ? 1 : 0,
                        native_personality_calls, personality_started,
                        personality_first, personality_caught ? 1 : 0,
                        personality_calls, personality_after,
                        personality_stopped,
                        personality_stats.matched_returns,
                        personality_stats.mismatched_returns,
                        personality_stats.unpaired_returns,
                        personality_stats.unwound_frames,
                        personality_stats.shadow_remaining);
            std::fflush(stdout);
            _exit(resumed_pass && direct_started == 0 && direct_caught &&
                   direct_stopped == 0 &&
                   direct_stats.unwound_frames >= 1 &&
                   direct_stats.shadow_remaining == 0 &&
                   jump_started == 0 && jumped == 1 && jump_after == 17 &&
                   jump_stopped == 0 && jump_stats.matched_returns >= 1 &&
                   jump_stats.mismatched_returns == 0 &&
                   jump_stats.unpaired_returns == 0 &&
                   jump_stats.unwound_frames >= 1 &&
                   jump_stats.shadow_remaining == 0 &&
                   native_personality_caught && native_personality_calls >= 2 &&
                   personality_started == 0 && personality_first == 12 &&
                   personality_caught && personality_calls >= 2 &&
                   personality_after == 14 && personality_stopped == 0 &&
                   personality_stats.matched_returns >= 2 &&
                   personality_stats.mismatched_returns == 0 &&
                   personality_stats.unpaired_returns == 0 &&
                   personality_stats.unwound_frames >= 1 &&
                   personality_stats.shadow_remaining == 0 ? 0 : 5);
        }
        struct sigaction action{};
        action.sa_handler = dbi_stalker_signal_handler;
        sigemptyset(&action.sa_mask);
        if (sigaction(SIGUSR1, &action, nullptr) != 0) _exit(3);
        /* Stalker resumes at the interrupted native continuation after a
         * signal. Observe the handler's known inner target independently;
         * activating Stalker in the handler rewrites its return path. */
        unsigned long signal_inner_handle = 0;
        const long signal_inner_attached = api.intercept_attach_address(
            reinterpret_cast<unsigned long>(&dbi_blr_target),
            dbi_stalker_inner_enter, dbi_stalker_inner_leave, nullptr,
            &signal_inner_handle);
        if (signal_inner_attached != 0) _exit(3);
        RtGumStalkerStats stats{};
        const long started = api.stalker_start(
            &stats, reinterpret_cast<unsigned long>(&dbi_blr_fixture), 16UL);
        if (started != 0) {
            std::fprintf(stderr, "dbi-stalker start=%ld\n", started);
            _exit(4);
        }
        const long first = dbi_blr_fixture(5, &dbi_blr_target);
        const long invalidated = api.stalker_invalidate(
            reinterpret_cast<unsigned long>(&dbi_blr_fixture));
        const long second = dbi_blr_fixture(9, &dbi_blr_target);
        const long signaled = dbi_blr_fixture(3, &dbi_blr_signal_target);
        const sig_atomic_t normal_signal_hits = g_dbi_stalker_signal_hits;
        constexpr std::size_t kAltStackSize = 64U * 1024U;
        void *alt_stack_memory = std::malloc(kAltStackSize);
        if (alt_stack_memory == nullptr) _exit(3);
        stack_t alt_stack{};
        stack_t previous_alt_stack{};
        alt_stack.ss_sp = alt_stack_memory;
        alt_stack.ss_size = kAltStackSize;
        if (sigaltstack(&alt_stack, &previous_alt_stack) != 0) _exit(3);
        g_dbi_stalker_altstack_low =
            reinterpret_cast<std::uintptr_t>(alt_stack_memory);
        g_dbi_stalker_altstack_high =
            g_dbi_stalker_altstack_low + kAltStackSize;
        action.sa_flags = SA_ONSTACK;
        if (sigaction(SIGUSR1, &action, nullptr) != 0) _exit(3);
        const long alt_signaled = dbi_blr_fixture(4, &dbi_blr_signal_target);
        const sig_atomic_t altstack_hits = g_dbi_stalker_altstack_hits;
        const long stopped = api.stalker_stop();
        const long signal_inner_detached =
            api.intercept_revert(signal_inner_handle);
        action.sa_flags = 0;
        sigaction(SIGUSR1, &action, nullptr);
        sigaltstack(&previous_alt_stack, nullptr);
        g_dbi_stalker_altstack_low = 0;
        g_dbi_stalker_altstack_high = 0;
        std::free(alt_stack_memory);
        std::printf("dbi-stalker blocks=%lu calls=%lu returns=%lu "
                    "compiled=%lu shadow-matched=%lu shadow-mismatched=%lu "
                    "shadow-unpaired=%lu shadow-unwound=%lu shadow-overflow=%lu "
                    "shadow-remaining=%lu "
                    "first=%ld second=%ld signaled=%ld alt-signaled=%ld "
                    "signal-hits=%d altstack-hits=%d handler-result=%ld "
                    "inner-enter=%d inner-leave=%d inner-errors=%d "
                    "inner-attach=%ld inner-detach=%ld invalidate=%ld stop=%ld\n",
                    stats.blocks, stats.calls, stats.returns, stats.compiled,
                    stats.matched_returns, stats.mismatched_returns,
                    stats.unpaired_returns, stats.unwound_frames,
                    stats.shadow_overflow, stats.shadow_remaining,
                    first, second, signaled, alt_signaled,
                    static_cast<int>(g_dbi_stalker_signal_hits),
                    static_cast<int>(altstack_hits),
                    static_cast<long>(g_dbi_stalker_handler_result),
                    static_cast<int>(g_dbi_stalker_inner_enters),
                    static_cast<int>(g_dbi_stalker_inner_leaves),
                    static_cast<int>(g_dbi_stalker_inner_errors),
                    signal_inner_attached, signal_inner_detached,
                    invalidated, stopped);
        for (unsigned long index = 0; index < stats.mismatch_samples_used;
             ++index) {
            const auto &sample = stats.mismatch_samples[index];
            std::printf("dbi-stalker mismatch[%lu] call+%03x ret+%03x "
                        "expected+%03x actual+%03x depth=%d/%d\n",
                        index, sample.call_offset, sample.ret_offset,
                        sample.expected_offset, sample.actual_offset,
                        sample.call_depth, sample.ret_depth);
        }
        RtGumStalkerStats tail_stats{};
        const long tail_started = api.stalker_start(
            &tail_stats, reinterpret_cast<unsigned long>(&dbi_tail_caller),
            16UL);
        const long tailed = tail_started == 0
            ? dbi_tail_caller(4, &dbi_blr_target) : -1;
        const long tail_stopped = tail_started == 0 ? api.stalker_stop() : -1;
        std::printf("dbi-stalker tail-start=%ld value=%ld stop=%ld "
                    "matched=%lu mismatched=%lu unpaired=%lu overflow=%lu "
                    "remaining=%lu\n",
                    tail_started, tailed, tail_stopped,
                    tail_stats.matched_returns, tail_stats.mismatched_returns,
                    tail_stats.unpaired_returns, tail_stats.shadow_overflow,
                    tail_stats.shadow_remaining);
        std::fflush(stdout);
        _exit(first == 12 && second == 16 && signaled == 10 &&
              normal_signal_hits == 1 && alt_signaled == 11 &&
              g_dbi_stalker_signal_hits == 2 && altstack_hits == 1 &&
              g_dbi_stalker_handler_result == 9 && invalidated == 0 &&
              g_dbi_stalker_inner_enters == 2 &&
              g_dbi_stalker_inner_leaves == 2 &&
              g_dbi_stalker_inner_errors == 0 &&
              signal_inner_detached == 0 &&
              stopped == 0 && stats.blocks > 0 && stats.calls > 0 &&
              stats.returns > 0 && stats.matched_returns >= 4 &&
              stats.mismatched_returns == 0 &&
              stats.unpaired_returns == 0 &&
              stats.shadow_overflow == 0 &&
              stats.shadow_remaining == 0 && tail_started == 0 &&
              tailed == 11 && tail_stopped == 0 &&
              tail_stats.matched_returns == 1 &&
              tail_stats.mismatched_returns == 0 &&
              tail_stats.unpaired_returns == 0 &&
              tail_stats.shadow_overflow == 0 &&
              tail_stats.shadow_remaining == 0 ? 0 : 5);
    }
    int status = 0;
    if (waitpid(child, &status, 0) != child) return 1;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        std::fprintf(stderr, "%s child signal=%d exit=%d\n",
                     exercise_phdr ? "dbi-stalker-phdr" :
                     exercise_unwind ? "dbi-stalker-unwind" : "dbi-stalker",
                     WIFSIGNALED(status) ? WTERMSIG(status) : 0,
                     WIFEXITED(status) ? WEXITSTATUS(status) : -1);
        return 1;
    }
    std::puts(exercise_phdr ? "stage1-dbi-stalker-phdr PASS" :
              exercise_unwind ? "stage1-dbi-stalker-unwind PASS" :
                                "stage1-dbi-stalker PASS");
    return 0;
#endif
}

DbiHardwareFault dbi_observe_stalker_b_fault(bool pac_return)
{
    int channel[2] = {-1, -1};
    if (pipe(channel) != 0) return {};
    const pid_t child = fork();
    if (child == 0) {
        close(channel[0]);
        g_dbi_hardening_signal_fd = channel[1];
        struct sigaction action{};
        action.sa_sigaction = dbi_hardening_signal_handler;
        action.sa_flags = SA_SIGINFO;
        sigemptyset(&action.sa_mask);
        if (sigaction(SIGILL, &action, nullptr) != 0 ||
            sigaction(SIGSEGV, &action, nullptr) != 0 ||
            sigaction(SIGTRAP, &action, nullptr) != 0)
            _exit(30);
        void *image = dlopen(
            "/data/local/tmp/rtgum-stage1-pixel8/librtgum-gum-ghost.so",
            RTLD_NOW | RTLD_LOCAL);
        if (!image) _exit(31);
        auto *entry = reinterpret_cast<RtGumEntry>(
            dlsym(image, "rtgum_gum_entry"));
        RtGumHost host{};
        RtGumApi api{};
        host.version = RTGUM_GUM_API_VERSION;
        if (!entry || entry(&host, &api) != 0 || !api.stalker_start)
            _exit(32);
        RtGumStalkerStats stats{};
        const unsigned long watched = pac_return
            ? reinterpret_cast<unsigned long>(&dbi_pac_b_return_fixture)
            : reinterpret_cast<unsigned long>(&dbi_pac_b_call);
        if (api.stalker_start(&stats, watched, pac_return ? 28UL : 64UL) != 0)
            _exit(33);
        if (pac_return) {
            if (dbi_pac_b_return_fixture(35, 0) != 42) _exit(34);
            (void)dbi_pac_b_return_fixture(35, 1);
        } else {
            if (dbi_pac_b_call(35, &dbi_blr_target, 0) != 42) _exit(34);
            (void)dbi_pac_b_call(35, &dbi_blr_target, 1);
        }
        _exit(35);
    }
    close(channel[1]);
    int evidence[2]{};
    const ssize_t got = read(channel[0], evidence, sizeof(evidence));
    close(channel[0]);
    int status = 0;
    const bool waited = child > 0 && waitpid(child, &status, 0) == child;
    if (!(waited && WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
          got == static_cast<ssize_t>(sizeof(evidence)))) {
        std::printf("dbi-stalker-pac-b-%s child-exit=%d child-signal=%d\n",
                    pac_return ? "return" : "call",
                    waited && WIFEXITED(status) ? WEXITSTATUS(status) : -1,
                    waited && WIFSIGNALED(status) ? WTERMSIG(status) : 0);
        return {};
    }
    return {true, evidence[0], evidence[1]};
}

int command_dbi_stalker_pac_test()
{
#if !defined(__aarch64__)
    return 1;
#else
    const unsigned long target = reinterpret_cast<unsigned long>(&dbi_blr_target);
    const bool auth_valid = dbi_pac_auth_matches_strip(target);
    std::printf("dbi-stalker-pac auth-valid=%d\n", auth_valid ? 1 : 0);
    if (!auth_valid) return 1;
    const DbiHardwareFault native = dbi_observe_hardware_fault(true, nullptr);
    std::printf("dbi-stalker-pac native-signal=%d native-code=%d native-observed=%d\n",
                native.signal, native.code, native.observed ? 1 : 0);
    if (!native.observed || native.signal != SIGILL ||
        native.code != ILL_ILLOPN)
        return 1;
    int channel[2] = {-1, -1};
    if (pipe(channel) != 0) return 1;
    const pid_t child = fork();
    if (child == 0) {
        close(channel[0]);
        g_dbi_hardening_signal_fd = channel[1];
        struct sigaction action{};
        action.sa_sigaction = dbi_hardening_signal_handler;
        action.sa_flags = SA_SIGINFO;
        sigemptyset(&action.sa_mask);
        if (sigaction(SIGILL, &action, nullptr) != 0 ||
            sigaction(SIGSEGV, &action, nullptr) != 0 ||
            sigaction(SIGTRAP, &action, nullptr) != 0)
            _exit(10);
        void *image = dlopen(
            "/data/local/tmp/rtgum-stage1-pixel8/librtgum-gum-ghost.so",
            RTLD_NOW | RTLD_LOCAL);
        if (!image) _exit(11);
        auto *entry = reinterpret_cast<RtGumEntry>(
            dlsym(image, "rtgum_gum_entry"));
        RtGumHost host{};
        RtGumApi api{};
        host.version = RTGUM_GUM_API_VERSION;
        if (!entry || entry(&host, &api) != 0 || !api.stalker_start)
            _exit(12);
        RtGumStalkerStats stats{};
        const long started = api.stalker_start(&stats,
            reinterpret_cast<unsigned long>(&dbi_pac_call), 64UL);
        if (started != 0) _exit(13);
        if (dbi_pac_call(35, &dbi_blr_target, 0) != 42)
            _exit(14);
        (void)dbi_pac_call(35, &dbi_blr_target, 1);
        _exit(15); /* authentication was bypassed */
    }
    close(channel[1]);
    int evidence[2]{};
    const ssize_t got = read(channel[0], evidence, sizeof(evidence));
    close(channel[0]);
    int status = 0;
    const bool waited = child > 0 && waitpid(child, &status, 0) == child;
    const int exit_code = waited && WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    const int terminated_signal = waited && WIFSIGNALED(status)
        ? WTERMSIG(status) : 0;
    std::printf("dbi-stalker-pac signal=%d code=%d observed=%d exit=%d "
                "terminated-signal=%d\n",
                evidence[0], evidence[1],
                got == static_cast<ssize_t>(sizeof(evidence)) ? 1 : 0,
                exit_code, terminated_signal);
    if (got != static_cast<ssize_t>(sizeof(evidence)) ||
        evidence[0] != SIGILL || evidence[1] != ILL_ILLOPN ||
        exit_code != 0)
        return 1;
    const DbiHardwareFault native_return =
        dbi_observe_hardware_fault(true, nullptr, true);
    std::printf("dbi-stalker-pac-return native-signal=%d native-code=%d "
                "native-observed=%d\n", native_return.signal,
                native_return.code, native_return.observed ? 1 : 0);
    if (!native_return.observed || native_return.signal != SIGILL ||
        native_return.code != ILL_ILLOPN)
        return 1;
    int return_channel[2] = {-1, -1};
    if (pipe(return_channel) != 0) return 1;
    const pid_t return_child = fork();
    if (return_child == 0) {
        close(return_channel[0]);
        g_dbi_hardening_signal_fd = return_channel[1];
        struct sigaction action{};
        action.sa_sigaction = dbi_hardening_signal_handler;
        action.sa_flags = SA_SIGINFO;
        sigemptyset(&action.sa_mask);
        if (sigaction(SIGILL, &action, nullptr) != 0 ||
            sigaction(SIGSEGV, &action, nullptr) != 0 ||
            sigaction(SIGTRAP, &action, nullptr) != 0)
            _exit(20);
        void *image = dlopen(
            "/data/local/tmp/rtgum-stage1-pixel8/librtgum-gum-ghost.so",
            RTLD_NOW | RTLD_LOCAL);
        if (!image) _exit(21);
        auto *entry = reinterpret_cast<RtGumEntry>(
            dlsym(image, "rtgum_gum_entry"));
        RtGumHost host{};
        RtGumApi api{};
        host.version = RTGUM_GUM_API_VERSION;
        if (!entry || entry(&host, &api) != 0 || !api.stalker_start)
            _exit(22);
        RtGumStalkerStats stats{};
        if (api.stalker_start(&stats,
                reinterpret_cast<unsigned long>(&dbi_pac_return_fixture),
                28UL) != 0)
            _exit(23);
        if (dbi_pac_return_fixture(35, 0) != 42) _exit(24);
        (void)dbi_pac_return_fixture(35, 1);
        _exit(25); /* authenticated return was bypassed */
    }
    close(return_channel[1]);
    int return_evidence[2]{};
    const ssize_t return_got = read(return_channel[0], return_evidence,
                                    sizeof(return_evidence));
    close(return_channel[0]);
    int return_status = 0;
    const bool return_waited = return_child > 0 &&
        waitpid(return_child, &return_status, 0) == return_child;
    const int return_exit = return_waited && WIFEXITED(return_status)
        ? WEXITSTATUS(return_status) : -1;
    const int return_term_signal = return_waited && WIFSIGNALED(return_status)
        ? WTERMSIG(return_status) : 0;
    std::printf("dbi-stalker-pac-return signal=%d code=%d observed=%d "
                "exit=%d terminated-signal=%d\n", return_evidence[0],
                return_evidence[1],
                return_got == static_cast<ssize_t>(sizeof(return_evidence)) ? 1 : 0,
                return_exit, return_term_signal);
    if (return_got != static_cast<ssize_t>(sizeof(return_evidence)) ||
        return_evidence[0] != SIGILL ||
        return_evidence[1] != ILL_ILLOPN || return_exit != 0)
        return 1;
    for (const bool pac_return : {false, true}) {
        const DbiHardwareFault native_b = dbi_observe_hardware_fault(
            true, nullptr, pac_return, true);
        const DbiHardwareFault stalker_b =
            dbi_observe_stalker_b_fault(pac_return);
        std::printf("dbi-stalker-pac-b-%s native=%d/%d/%d stalker=%d/%d/%d\n",
                    pac_return ? "return" : "call",
                    native_b.signal, native_b.code,
                    native_b.observed ? 1 : 0,
                    stalker_b.signal, stalker_b.code,
                    stalker_b.observed ? 1 : 0);
        if (!native_b.observed || native_b.signal != SIGILL ||
            native_b.code != ILL_ILLOPN || !stalker_b.observed ||
            stalker_b.signal != SIGILL || stalker_b.code != ILL_ILLOPN)
            return 1;
    }
    std::puts("stage1-dbi-stalker-pac PASS");
    return 0;
#endif
}

int command_dbi_stalker_bti_test()
{
#if !defined(__aarch64__)
    return 1;
#else
    if ((getauxval(AT_HWCAP2) & HWCAP2_BTI) == 0) return 1;
    const long page_size = sysconf(_SC_PAGESIZE);
    if (page_size < 4096) return 1;
    void *pages = mmap(nullptr, static_cast<size_t>(page_size) * 2U,
                       PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
                       -1, 0);
    if (pages == MAP_FAILED) return 1;
    auto *valid = static_cast<uint32_t *>(pages);
    auto *invalid = reinterpret_cast<uint32_t *>(
        static_cast<uint8_t *>(pages) + page_size);
    valid[0] = 0xd503245fU;  /* BTI c */
    invalid[0] = 0xd503201fU; /* NOP */
    valid[1] = invalid[1] = 0xd2800540U; /* mov x0, #42 */
    valid[2] = invalid[2] = 0xd65f03c0U; /* ret */
    __builtin___clear_cache(static_cast<char *>(pages),
                            static_cast<char *>(pages) + page_size * 2U);
    if (mprotect(pages, static_cast<size_t>(page_size) * 2U,
                 PROT_READ | PROT_EXEC | PROT_BTI) != 0)
        return 1;
    if (dbi_bti_call(valid) != 42) return 1;
    const DbiHardwareFault native = dbi_observe_hardware_fault(false, invalid);
    int channel[2] = {-1, -1};
    if (pipe(channel) != 0) return 1;
    const pid_t child = fork();
    if (child == 0) {
        close(channel[0]);
        g_dbi_hardening_signal_fd = channel[1];
        struct sigaction action{};
        action.sa_sigaction = dbi_hardening_signal_handler;
        action.sa_flags = SA_SIGINFO;
        sigemptyset(&action.sa_mask);
        if (sigaction(SIGILL, &action, nullptr) != 0 ||
            sigaction(SIGSEGV, &action, nullptr) != 0 ||
            sigaction(SIGTRAP, &action, nullptr) != 0)
            _exit(40);
        void *image = dlopen(
            "/data/local/tmp/rtgum-stage1-pixel8/librtgum-gum-ghost.so",
            RTLD_NOW | RTLD_LOCAL);
        if (!image) _exit(41);
        auto *entry = reinterpret_cast<RtGumEntry>(
            dlsym(image, "rtgum_gum_entry"));
        RtGumHost host{};
        RtGumApi api{};
        host.version = RTGUM_GUM_API_VERSION;
        if (!entry || entry(&host, &api) != 0 || !api.stalker_start)
            _exit(42);
        RtGumStalkerStats stats{};
        if (api.stalker_start(&stats,
                reinterpret_cast<unsigned long>(&dbi_bti_call), 16UL) != 0)
            _exit(43);
        if (dbi_bti_call(valid) != 42) _exit(44);
        (void)dbi_bti_call(invalid);
        _exit(45); /* a guarded bad landing was accepted */
    }
    close(channel[1]);
    int evidence[2]{};
    const ssize_t got = read(channel[0], evidence, sizeof(evidence));
    close(channel[0]);
    int status = 0;
    const bool waited = child > 0 && waitpid(child, &status, 0) == child;
    const int exit_code = waited && WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    std::printf("dbi-stalker-bti native=%d/%d/%d stalker=%d/%d/%d exit=%d\n",
                native.signal, native.code, native.observed ? 1 : 0,
                evidence[0], evidence[1],
                got == static_cast<ssize_t>(sizeof(evidence)) ? 1 : 0,
                exit_code);
    munmap(pages, static_cast<size_t>(page_size) * 2U);
    if (!native.observed || native.signal != SIGILL ||
        native.code != ILL_ILLOPC ||
        got != static_cast<ssize_t>(sizeof(evidence)) ||
        evidence[0] != SIGILL || evidence[1] != ILL_ILLOPC ||
        exit_code != 0)
        return 1;
    std::puts("stage1-dbi-stalker-bti PASS");
    return 0;
#endif
}

#if defined(__aarch64__)
bool dbi_test_custom_personality_clone()
{
    const unsigned long source =
        reinterpret_cast<unsigned long>(&rtgum_dbi_personality_frame);
    rtgum_dbi::EhModule module{};
    rtgum_dbi::FdeLocation location{};
    if (!rtgum_dbi::find_module_for_address(source, &module) ||
        rtgum_dbi::detail::find_fde(module, source, &location) !=
            rtgum_dbi::FdeStatus::Ok ||
        location.initial_location != source ||
        location.address_range == 0 || location.address_range > 256U)
        return false;

    constexpr unsigned long kStep = 16UL * 1024UL * 1024UL;
    void *region = MAP_FAILED;
    const unsigned long source_page = source & ~0xfffUL;
    for (unsigned i = 1; i <= 64 && region == MAP_FAILED; ++i) {
        const unsigned long distance = static_cast<unsigned long>(i) * kStep;
        const unsigned long candidate[2] = {
            source_page <= ~0UL - distance ? source_page + distance : 0,
            source_page >= distance ? source_page - distance : 0,
        };
        for (unsigned side = 0; side < 2 && region == MAP_FAILED; ++side) {
            if (candidate[side] == 0) continue;
            region = mmap(reinterpret_cast<void *>(candidate[side]), 8192,
                          PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                          -1, 0);
        }
    }
    if (region == MAP_FAILED) return false;
    const unsigned long clone = reinterpret_cast<unsigned long>(region);
    auto *frame = reinterpret_cast<uint8_t *>(region) + 4096U;
    uint8_t code[1024]{};
    rtgum_dbi::OffsetMapEntry map[64]{};
    rtgum_dbi::BranchTraceEntry trace[64]{};
    rtgum_dbi::LiteralRange literals[64]{};
    auto relocation = rtgum_dbi::make_result(
        code, sizeof(code), map, 64, trace, 64, literals, 64);
    const bool relocated = rtgum_dbi::Relocator::relocate(
        reinterpret_cast<const uint8_t *>(source),
        static_cast<size_t>(location.address_range), source, clone, relocation);
    rtgum_dbi::CloneFdeResult cloned_frame{};
    if (relocated) {
        std::memcpy(region, relocation.code, relocation.code_size);
        __builtin___clear_cache(reinterpret_cast<char *>(region),
            reinterpret_cast<char *>(region) + relocation.code_size);
        cloned_frame = rtgum_dbi::build_clone_fde_span(
            module, location, clone,
            static_cast<uint32_t>(relocation.code_size), frame, 4096,
            relocation.map, relocation.map_size);
    }
    const bool built = relocated &&
        cloned_frame.status == rtgum_dbi::FdeStatus::Ok &&
        mprotect(region, 4096, PROT_READ | PROT_EXEC) == 0;
    int child_status = -1;
    if (built) {
        const pid_t child = fork();
        if (child == 0) {
            rtgum_dbi::register_clone_fde_span(cloned_frame);
            UnwindFindFdeBases bases{};
            const bool located =
                _Unwind_Find_FDE(region, &bases) == cloned_frame.clone_fde;
            const unsigned int before = rtgum_dbi_personality_hits;
            bool caught = false;
            try {
                auto *invoke = reinterpret_cast<long (*)(long (*)(long), long)>(
                    region);
                invoke(&dbi_stalker_throw_target, 1);
            } catch (const std::runtime_error &) {
                caught = true;
            }
            const unsigned int calls = rtgum_dbi_personality_hits - before;
            rtgum_dbi::unregister_clone_fde_span(cloned_frame);
            _exit(located && caught && calls >= 2 ? 0 : 5);
        }
        if (child > 0 && waitpid(child, &child_status, 0) != child)
            child_status = -1;
    }
    std::printf("dbi-personality-clone source-size=%llu clone-size=%zu "
                "fde-status=%u child-exit=%d child-signal=%d\n",
                static_cast<unsigned long long>(location.address_range),
                relocated ? relocation.code_size : 0U,
                static_cast<unsigned>(cloned_frame.status),
                child_status >= 0 && WIFEXITED(child_status)
                    ? WEXITSTATUS(child_status) : -1,
                child_status >= 0 && WIFSIGNALED(child_status)
                    ? WTERMSIG(child_status) : 0);
    munmap(region, 8192);
    return built && child_status >= 0 && WIFEXITED(child_status) &&
        WEXITSTATUS(child_status) == 0;
}
#endif

int command_dbi_lab_test(const char *key)
{
#if !defined(__aarch64__)
    (void)key;
    return 1;
#else
    (void)key;
    signal(SIGSEGV, SIG_DFL);
    signal(SIGBUS, SIG_DFL);
    void *lib = dlopen("/data/local/tmp/rtgum-stage1-pixel8/librtgum-lab.so",
                       RTLD_NOW | RTLD_LOCAL);
    if (!lib) {
        std::fprintf(stderr, "dbi-lab dlopen failed: %s\n", dlerror());
        return 1;
    }
    auto *flower = reinterpret_cast<long (*)(long, long)>(dlsym(lib, "lab_flower"));
    if (!flower) {
        std::fprintf(stderr, "dbi-lab dlsym failed\n");
        return 1;
    }

    const long in_a[3] = {2, 3, 100};
    const long in_b[3] = {2, 4, 3};
    long baseline[3]{};
    for (int i = 0; i < 3; ++i) baseline[i] = flower(in_a[i], in_b[i]);

    const unsigned long src = reinterpret_cast<unsigned long>(flower);
    const size_t room = 4096UL - (src & 0xfffUL);
    size_t bytes = room < 256UL ? room : 256UL;
    bytes &= ~3UL;

    constexpr size_t capacity = 4096UL;
    constexpr size_t kCapacity = capacity;
    constexpr size_t kMaxInstructions = 64UL;
    /* The clone mapping holds the code page and, right after it, the
     * dispatcher record area: ADR reach is +/-1MB, so co-locating them keeps
     * the stubs' site references in range. */
    const unsigned long far_address = (src + 0x40000000UL) & ~0xfffUL;
    void *clone = mmap(reinterpret_cast<void *>(far_address), 8192,
                       PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (clone == MAP_FAILED) {
        clone = mmap(nullptr, 8192, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    }
    if (clone == MAP_FAILED) {
        std::fprintf(stderr, "dbi-lab clone mmap failed\n");
        return 1;
    }
    auto *records = reinterpret_cast<rtgum_dbi::SiteRecord *>(
        reinterpret_cast<unsigned long>(clone) + 4096UL);
    for (unsigned int i = 0; i < 16U; ++i) records[i] = rtgum_dbi::SiteRecord{};

    static uint8_t lab_code[kCapacity];
    static rtgum_dbi::OffsetMapEntry lab_map[kMaxInstructions];
    static rtgum_dbi::BranchTraceEntry lab_trace[kMaxInstructions];
    static rtgum_dbi::LiteralRange lab_literals[kMaxInstructions];
    rtgum_dbi::RelocationResult result = rtgum_dbi::make_result(
        lab_code, sizeof(lab_code), lab_map, kMaxInstructions, lab_trace,
        kMaxInstructions, lab_literals, kMaxInstructions);
    const char *dispatch_mode = std::getenv("RTGUM_DBI_DISPATCH");
    result.dispatcher.enabled = dispatch_mode != nullptr;
    result.dispatcher.mode = 0U;
    if (dispatch_mode != nullptr) {
        if (std::strcmp(dispatch_mode, "br") == 0) result.dispatcher.mode = 1U;
        else if (std::strcmp(dispatch_mode, "ret") == 0) result.dispatcher.mode = 2U;
        else result.dispatcher.mode = 3U;
    }
    result.dispatcher.record_base = reinterpret_cast<unsigned long>(records);
    result.dispatcher.record_stride = sizeof(rtgum_dbi::SiteRecord);
    result.dispatcher.max_sites = 16U;    if (!rtgum_dbi::Relocator::relocate(reinterpret_cast<const void *>(src), bytes,
                                        src, reinterpret_cast<unsigned long>(clone),
                                        result)) {
        std::fprintf(stderr, "dbi-lab relocation failed overflow=%d unsupported=%d\n",
                     result.overflow ? 1 : 0, result.unsupported ? 1 : 0);
        return 1;
    }
    if (result.code_size > capacity) {
        std::fprintf(stderr, "dbi-lab literal pool exceeded capacity\n");
        return 1;
    }
    std::memcpy(clone, result.code, result.code_size);
    __builtin___clear_cache(reinterpret_cast<char *>(clone),
                            reinterpret_cast<char *>(clone) + result.code_size);
    if (mprotect(clone, 4096, PROT_READ | PROT_EXEC) != 0) {
        std::fprintf(stderr, "dbi-lab mprotect failed\n");
        return 1;
    }

    if (std::getenv("RTGUM_DBI_DUMP") != nullptr) {
        std::printf("dbi-lab src=0x%lx clone=0x%lx bytes=%zu insns=%u "
                    "cloned=%zu literals=%u expanded=%u unsupported=%d oor=%d\n",
                    src, reinterpret_cast<unsigned long>(clone), bytes,
                    result.input_instructions, result.code_size,
                    result.literal_count, result.expanded_branches,
                    result.unsupported ? 1 : 0, result.out_of_range ? 1 : 0);
        const unsigned int *words = reinterpret_cast<const unsigned int *>(src);
        for (size_t i = 0; i < bytes / 4U; ++i)
            std::printf("dbi-dump orig[%zu] 0x%08x\n", i, words[i]);
        const unsigned int *clone_words =
            reinterpret_cast<const unsigned int *>(result.code);
        for (size_t i = 0; i < result.code_size / 4U; ++i)
            std::printf("dbi-dump clone[%zu] 0x%08x\n", i, clone_words[i]);
        for (size_t i = 0; i < result.map_size; ++i)
            std::printf("dbi-dump map orig=%u clone-off=%u\n",
                        result.map[i].orig_index, result.map[i].clone_offset);
        std::fflush(stdout);
    }

    /* Diagnostic: report the faulting PC and the surrounding clone words so a
     * dispatcher stub failure points at the exact instruction. */
    static unsigned long g_clone_begin = 0;
    static unsigned long g_clone_end = 0;
    struct SigCtx { unsigned long pc; unsigned long sp; };
    static SigCtx g_fault{};
    struct sigaction fault_action{};
    fault_action.sa_flags = SA_SIGINFO;
    fault_action.sa_sigaction = [](int, siginfo_t *, void *context) {
        auto *uc = static_cast<ucontext_t *>(context);
        g_fault.pc = static_cast<unsigned long>(uc->uc_mcontext.pc);
        g_fault.sp = static_cast<unsigned long>(uc->uc_mcontext.sp);
        char text[256];
        int length = std::snprintf(text, sizeof(text),
                                   "DBI-FAULT pc=0x%lx sp=0x%lx clone=[0x%lx,0x%lx)\n",
                                   g_fault.pc, g_fault.sp, g_clone_begin, g_clone_end);
        ssize_t ignored = write(2, text, static_cast<size_t>(length));
        (void)ignored;
        if (g_fault.pc >= g_clone_begin && g_fault.pc + 32 < g_clone_end) {
            const unsigned long offset = g_fault.pc - g_clone_begin;
            const unsigned long start = offset >= 32 ? offset - 32 : 0;
            for (unsigned long at = start; at < offset + 32; at += 4) {
                const uint32_t word = *reinterpret_cast<const uint32_t *>(
                    g_clone_begin + at);
                length = std::snprintf(text, sizeof(text),
                                       "DBI-FAULT clone[%lu] 0x%08x%s\n", at / 4U,
                                       word, at == offset ? "  <== fault" : "");
                ignored = write(2, text, static_cast<size_t>(length));
                (void)ignored;
            }
        }
        _exit(3);
    };
    sigaction(SIGILL, &fault_action, nullptr);
    sigaction(SIGSEGV, &fault_action, nullptr);
    g_clone_begin = reinterpret_cast<unsigned long>(clone);
    g_clone_end = g_clone_begin + result.placeholder_index;
    static long (*g_clone_for_signal)(long, long) = nullptr;
    static volatile long g_handler_calls = 0;
    struct sigaction user_action{};
    user_action.sa_flags = 0;
    user_action.sa_handler = [](int) {
        if (g_clone_for_signal != nullptr) {
            volatile long nested = g_clone_for_signal(1, 2);
            (void)nested;
        }
        ++g_handler_calls;
    };
    sigaction(SIGUSR1, &user_action, nullptr);
    auto *clone_flower = reinterpret_cast<long (*)(long, long)>(clone);
    g_clone_for_signal = clone_flower;
    long relocated[3]{};
    for (int i = 0; i < 3; ++i) {
        std::printf("dbi-lab calling clone %d\n", i);
        std::fflush(stdout);
        relocated[i] = clone_flower(in_a[i], in_b[i]);
        std::printf("dbi-lab clone %d returned %ld\n", i, relocated[i]);
        std::fflush(stdout);
    }

    int mismatch = 0;
    for (int i = 0; i < 3; ++i)
        if (relocated[i] != baseline[i]) mismatch = 1;

    /* Register terminal state: the same trampoline calls the original and the
     * clone with identical inputs, so every register and SP must match. x16
     * and x17 are the ABI's intra-procedure scratch registers (IP0/IP1): a
     * relocated far-jump legitimately uses them where the original did not, so
     * they are reported separately instead of failing the comparison. */
    /* Register terminal state, measured with ptrace instead of a hand-written
     * trampoline: the child calls the original, traps with brk, calls the
     * clone, traps again; the parent reads the full regset at each trap, i.e.
     * exactly where each call returned. x30 is excluded (the two call sites
     * have different return addresses) and x16/x17 are ABI scratch. */
    {
        struct ChildRegs {
            unsigned long regs[31];
            unsigned long sp;
            unsigned long pc;
            unsigned long pstate;
        };
        const pid_t reg_child = fork();
        if (reg_child == 0) {
            if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) != 0) _exit(2);
            raise(SIGSTOP);
            volatile long first = flower(2, 2);
            (void)first;
            __asm__ volatile("brk #0x4d42" ::: "memory");
            volatile long second = clone_flower(2, 2);
            (void)second;
            __asm__ volatile("brk #0x4d42" ::: "memory");
            _exit(0);
        }
        if (reg_child < 0) {
            std::fprintf(stderr, "dbi-lab register comparison fork failed\n");
            return 1;
        }
        ChildRegs states[2]{};
        unsigned int captured = 0;
        int reg_status = 0;
        if (waitpid(reg_child, &reg_status, 0) == reg_child &&
            WIFSTOPPED(reg_status)) {
            while (captured < 2U) {
                if (ptrace(PTRACE_CONT, reg_child, nullptr, nullptr) != 0) break;
                if (waitpid(reg_child, &reg_status, 0) != reg_child) break;
                if (!WIFSTOPPED(reg_status)) break;
                ChildRegs sample{};
                struct iovec iov{&sample, sizeof(sample)};
                if (ptrace(PTRACE_GETREGSET, reg_child,
                           reinterpret_cast<void *>(static_cast<long>(1)),
                           &iov) != 0)
                    break;
                states[captured++] = sample;
            }
            ptrace(PTRACE_DETACH, reg_child, nullptr, nullptr);
        }
        kill(reg_child, SIGKILL);
        waitpid(reg_child, nullptr, 0);
        unsigned int terminal_mismatch = 0;
        unsigned int scratch_differ = 0;
        unsigned int first_register = 0;
        if (captured == 2U) {
            for (unsigned int reg = 0; reg < 31U; ++reg) {
                if (reg == 30U) continue; /* return address of a call site */
                if (states[0].regs[reg] == states[1].regs[reg]) continue;
                if (reg == 16U || reg == 17U) {
                    ++scratch_differ;
                    continue;
                }
                ++terminal_mismatch;
                if (first_register == 0U) first_register = reg;
            }
            if (states[0].sp != states[1].sp) ++terminal_mismatch;
        }
        std::printf("dbi-lab register-terminal-state captured=%u mismatches=%u "
                    "first-x%u scratch-differ=%u (x30/x16/x17 excluded)\n",
                    captured, terminal_mismatch, first_register, scratch_differ);
        std::fflush(stdout);
        if (captured != 2U) {
            std::fprintf(stderr, "dbi-lab register comparison could not sample\n");
            return 1;
        }
        if (terminal_mismatch != 0) {
            std::fprintf(stderr, "dbi-lab register terminal state differs\n");
            return 1;
        }
    }

    int map_bad = 0;
    for (size_t i = 0; i < result.map_size; ++i) {
        const rtgum_dbi::OffsetMapEntry &entry = result.map[i];
        uint32_t index = 0;
        if (!rtgum_dbi::Relocator::original_index_for(result, entry.clone_offset,
                                                      index) ||
            index != entry.orig_index)
            map_bad = 1;
    }

    const unsigned long distance =
        src > reinterpret_cast<unsigned long>(clone)
            ? (src - reinterpret_cast<unsigned long>(clone))
            : (reinterpret_cast<unsigned long>(clone) - src);
    std::printf("dbi-lab src=0x%lx clone=0x%lx distance-mb=%lu insns=%u "
                "cloned-bytes=%zu literals=%u expanded=%u overflow=%d "
                "unsupported=%d out-of-range=%d\n",
                src, reinterpret_cast<unsigned long>(clone), distance >> 20,
                result.input_instructions, result.code_size,
                result.literal_count, result.expanded_branches,
                result.overflow ? 1 : 0, result.unsupported ? 1 : 0,
                result.out_of_range ? 1 : 0);

    /* Static layout assertion: every intra-block branch target must land
     * inside the clone block (via offset_map), never back in the source. */
    unsigned int intra_block = 0;
    unsigned int escaped = 0;
    unsigned int introduced_indirect = 0;
    for (size_t i = 0; i < result.trace_size; ++i) {
        const rtgum_dbi::BranchTraceEntry &entry = result.trace[i];
        if (entry.introduced_indirect) ++introduced_indirect;
        if (entry.runtime_target || !entry.intra_block) continue;
        ++intra_block;
        uint32_t clone_offset = 0;
        if (!rtgum_dbi::Relocator::clone_offset_for(
                result, static_cast<uint32_t>((entry.target - src) / 4U),
                clone_offset)) {
            ++escaped;
        }
    }
    std::printf("dbi-lab intra-block-branches=%u unresolved=%u block-bytes=%u "
                "introduced-indirect=%u\n",
                intra_block, escaped, result.placeholder_index,
                introduced_indirect);
    if (escaped != 0) {
        std::fprintf(stderr, "dbi-lab intra-block branch was not remapped\n");
        return 1;
    }
    std::printf("dbi-lab baseline=%ld,%ld,%ld relocated=%ld,%ld,%ld "
                "mismatch=%d map-bad=%d\n",
                baseline[0], baseline[1], baseline[2],
                relocated[0], relocated[1], relocated[2], mismatch, map_bad);
    std::fflush(stdout);
    if (std::getenv("RTGUM_DBI_DUMP") != nullptr) {
        const unsigned int *words = reinterpret_cast<const unsigned int *>(src);
        for (size_t i = 0; i < bytes / 4U; ++i)
            std::printf("dbi-dump orig[%zu] 0x%08x\n", i, words[i]);
        const unsigned int *clone_words =
            reinterpret_cast<const unsigned int *>(result.code);
        for (size_t i = 0; i < result.code_size / 4U; ++i)
            std::printf("dbi-dump clone[%zu] 0x%08x\n", i, clone_words[i]);
        for (size_t i = 0; i < result.map_size; ++i)
            std::printf("dbi-dump map orig=%u clone-off=%u\n",
                        result.map[i].orig_index, result.map[i].clone_offset);
        std::fflush(stdout);
    }
    unsigned int kinds[12] = {0};
    for (size_t i = 0; i < result.trace_size; ++i)
        kinds[static_cast<unsigned>(result.trace[i].kind)]++;
    std::printf("dbi-lab trace branches=%zu b=%u bcond=%u cbz=%u tbz=%u adr=%u "
                "adrp=%u ldrlit=%u br=%u pac=%u ret=%u\n",
                result.trace_size, kinds[1], kinds[2], kinds[3], kinds[4],
                kinds[5], kinds[6], kinds[7], kinds[8], kinds[9], kinds[10]);
    for (size_t i = 0; i < result.trace_size && i < 10; ++i) {
        const rtgum_dbi::BranchTraceEntry &entry = result.trace[i];
        std::printf("dbi-lab trace[%zu] kind=%u orig=+0x%x target=0x%llx\n",
                    i, static_cast<unsigned>(entry.kind), entry.orig_index * 4U,
                    static_cast<unsigned long long>(entry.target));
    }
    std::fflush(stdout);

    if (mismatch != 0) {
        std::fprintf(stderr, "dbi-lab relocated result differs from baseline\n");
        return 1;
    }
    if (map_bad != 0) {
        std::fprintf(stderr, "dbi-lab offset_map reverse lookup failed\n");
        return 1;
    }
    std::puts("relocated-match=1 offset-map=1 literal-pool-in-bounds=1 lab-no-crash=1");

    /* The real-SO case: relocate the device libc's own epoll_wait prologue
     * and prove the clone behaves identically to the original call. */
    auto *real_epoll_wait = reinterpret_cast<int (*)(int, void *, int, int)>(
        dlsym(RTLD_DEFAULT, "epoll_wait"));
    if (!real_epoll_wait) {
        std::fprintf(stderr, "dbi-lab epoll_wait lookup failed\n");
        return 1;
    }
    const unsigned long real_src = reinterpret_cast<unsigned long>(real_epoll_wait);
    const size_t real_room = 4096UL - (real_src & 0xfffUL);
    size_t real_bytes = real_room < 64UL ? real_room : 64UL;
    real_bytes &= ~3UL;
    void *real_clone = mmap(nullptr, 4096, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (real_clone == MAP_FAILED) {
        std::fprintf(stderr, "dbi-lab real clone mmap failed\n");
        return 1;
    }
    /* The real-SO case gets its own storage: the freestanding core writes
     * into caller buffers, so sharing them would clobber the lab's
     * offset_map that the runtime coverage check below still needs. */
    static uint8_t real_code[kCapacity];
    static rtgum_dbi::OffsetMapEntry real_map[kMaxInstructions];
    static rtgum_dbi::BranchTraceEntry real_trace[kMaxInstructions];
    static rtgum_dbi::LiteralRange real_literals[kMaxInstructions];
    rtgum_dbi::RelocationResult real_result = rtgum_dbi::make_result(
        real_code, sizeof(real_code), real_map, kMaxInstructions, real_trace,
        kMaxInstructions, real_literals, kMaxInstructions);
    if (!rtgum_dbi::Relocator::relocate(
            reinterpret_cast<const void *>(real_src), real_bytes, real_src,
            reinterpret_cast<unsigned long>(real_clone), real_result)) {
        std::fprintf(stderr, "dbi-lab real relocation failed overflow=%d\n",
                     real_result.overflow ? 1 : 0);
        return 1;
    }
    std::memcpy(real_clone, real_result.code, real_result.code_size);
    __builtin___clear_cache(reinterpret_cast<char *>(real_clone),
                            reinterpret_cast<char *>(real_clone) +
                                real_result.code_size);
    if (mprotect(real_clone, 4096, PROT_READ | PROT_EXEC) != 0) {
        std::fprintf(stderr, "dbi-lab real mprotect failed\n");
        return 1;
    }
    auto *clone_epoll_wait =
        reinterpret_cast<int (*)(int, void *, int, int)>(real_clone);
    struct epoll_event events[4]{};
    errno = 0;
    const int original_bad = real_epoll_wait(-1, events, 4, 0);
    const int original_bad_errno = errno;
    errno = 0;
    const int clone_bad = clone_epoll_wait(-1, events, 4, 0);
    const int clone_bad_errno = errno;
    const int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    int original_ok = -99;
    int clone_ok = -99;
    if (epoll_fd >= 0) {
        errno = 0;
        original_ok = real_epoll_wait(epoll_fd, events, 4, 0);
        const int original_ok_errno = errno;
        errno = 0;
        clone_ok = clone_epoll_wait(epoll_fd, events, 4, 0);
        const int clone_ok_errno = errno;
        close(epoll_fd);
        if (original_ok != clone_ok || original_ok_errno != clone_ok_errno) {
            std::fprintf(stderr, "dbi-lab real clone diverged: %d/%d vs %d/%d\n",
                         original_ok, original_ok_errno, clone_ok, clone_ok_errno);
            return 1;
        }
    }
    std::printf("dbi-lab real=libc!epoll_wait bytes=%zu cloned=%zu literals=%u "
                "expanded=%u bad-fd=%d/%d errno=%d/%d timeout0=%d/%d\n",
                real_bytes, real_result.code_size, real_result.literal_count,
                real_result.expanded_branches, original_bad, clone_bad,
                original_bad_errno, clone_bad_errno, original_ok, clone_ok);
    if (original_bad != clone_bad || original_bad_errno != clone_bad_errno) {
        std::fprintf(stderr, "dbi-lab real clone bad-fd path diverged\n");
        return 1;
    }
    std::puts("real-so-relocated=1 behavior-identical=1");

    /* Runtime coverage: single-step the clone in a traced child and prove
     * the executed PCs live inside the clone block (the intra-block branches
     * really go to the clone) and capture the indirect br's real landing. */
    if (std::getenv("RTGUM_DBI_NO_TRACE") == nullptr) {
        struct UserPtRegs {
            unsigned long regs[31];
            unsigned long sp;
            unsigned long pc;
            unsigned long pstate;
        };
        const unsigned long clone_begin = reinterpret_cast<unsigned long>(clone);
        const unsigned long clone_end = clone_begin + result.placeholder_index;
        const pid_t child = fork();
        if (child == 0) {
            if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) != 0) _exit(2);
            raise(SIGSTOP);
            volatile long first = clone_flower(2, 2);
            volatile long second = clone_flower(3, 4);
            (void)first;
            (void)second;
            _exit(0);
        }
        if (child < 0) {
            std::fprintf(stderr, "dbi-lab trace fork failed\n");
            return 1;
        }
        int status = 0;
        if (waitpid(child, &status, 0) != child || !WIFSTOPPED(status)) return 1;
        unsigned int steps = 0;
        unsigned int in_clone = 0;
        unsigned int escaped_pc = 0;
        unsigned int signal_stops = 0;
        unsigned int observed_origins[512];
        unsigned int observed_count = 0;
        static unsigned long observed_pcs[4096];
        unsigned int observed_pc_count = 0;
        unsigned long br_landing = 0;
        unsigned long previous_pc = 0;

        /* Indirect-branch events are paired: (pre-step PC, decoded class,
         * target register value, pre-decode orig index, post-step PC, TID).
         * A landing only counts when the instruction that was single-stepped
         * really is a BR/BLR/PAC branch of this clone. */
        struct IndirectEvent {
            unsigned long pre_pc;
            unsigned long register_value;
            unsigned long landing;
            uint32_t orig_index;
            unsigned int tid;
            bool links;
        };
        IndirectEvent indirect_events[16];
        unsigned int indirect_count = 0;

        auto read_regs = [&](UserPtRegs &out) -> bool {
            struct iovec iov{&out, sizeof(out)};
            return ptrace(PTRACE_GETREGSET, child,
                          reinterpret_cast<void *>(static_cast<long>(1)),
                          &iov) == 0;
        };
        /* Decode only the register-indirect classes: those are copied
         * verbatim, so the word at the clone PC is the instruction. */
        auto decode_indirect = [&](unsigned long pc, uint8_t &reg, bool &links,
                                   bool &pac) -> bool {
            if (pc < clone_begin || pc + 4U > clone_end) return false;
            const uint32_t word = *reinterpret_cast<const uint32_t *>(pc);
            pac = false;
            if ((word & 0xfffffc1fU) == 0xd61f0000U ||
                (word & 0xfffffc1fU) == 0xd63f0000U) {
                reg = static_cast<uint8_t>((word >> 5U) & 0x1fU);
                links = (word & 0xfffffc1fU) == 0xd63f0000U;
                return true;
            }
            if ((word & 0xfefff800U) == 0xd61f0800U ||
                (word & 0xfefff800U) == 0xd63f0800U) {
                reg = static_cast<uint8_t>((word >> 5U) & 0x1fU);
                links = (word & 0xfefff800U) == 0xd63f0800U;
                pac = true;
                return true;
            }
            return false;
        };

        UserPtRegs regs{};
        if (!read_regs(regs)) return 1;
        while (steps < 4096U) {
            const unsigned long pre_pc = regs.pc;
            uint8_t pending_register = 0xffU;
            bool pending_links = false;
            bool pending_pac = false;
            const bool pending_indirect =
                decode_indirect(pre_pc, pending_register, pending_links, pending_pac);
            const unsigned long pending_value =
                (pending_indirect && pending_register < 31U)
                    ? regs.regs[pending_register]
                    : 0UL;
            uint32_t pending_orig = 0xffffffffU;
            if (pre_pc >= clone_begin && pre_pc < clone_end) {
                uint32_t mapped = 0;
                if (rtgum_dbi::Relocator::original_index_for(
                        result, static_cast<uint32_t>(pre_pc - clone_begin), mapped))
                    pending_orig = mapped;
            }

            if (ptrace(PTRACE_SINGLESTEP, child, nullptr, nullptr) != 0) break;
            const pid_t stopped_pid = waitpid(child, &status, 0);
            if (stopped_pid != child) break;
            if (WIFEXITED(status) || WIFSIGNALED(status)) break;
            /* A single-step stop is SIGTRAP; anything else is a signal
             * delivery stop and is accounted separately. */
            if (WSTOPSIG(status) != SIGTRAP) ++signal_stops;
            if (!read_regs(regs)) break;
            ++steps;
            const unsigned long pc = regs.pc;
            if (observed_pc_count < 4096U) observed_pcs[observed_pc_count++] = pc;
            if (pc >= clone_begin && pc < clone_end) {
                ++in_clone;
                uint32_t orig = 0;
                if (rtgum_dbi::Relocator::original_index_for(
                        result, static_cast<uint32_t>(pc - clone_begin), orig) &&
                    observed_count < 512U)
                    observed_origins[observed_count++] = orig;
            } else if (previous_pc >= clone_begin && previous_pc < clone_end) {
                /* The first step that leaves the clone: only a real indirect
                 * branch of this block may claim the landing. */
                if (br_landing == 0) br_landing = pc;
                ++escaped_pc;
            }
            if (pending_indirect && pc != pre_pc + 4U &&
                indirect_count < 16U) {
                indirect_events[indirect_count].pre_pc = pre_pc;
                indirect_events[indirect_count].register_value = pending_value;
                indirect_events[indirect_count].landing = pc;
                indirect_events[indirect_count].orig_index = pending_orig;
                indirect_events[indirect_count].tid =
                    static_cast<unsigned int>(stopped_pid);
                indirect_events[indirect_count].links = pending_links;
                ++indirect_count;
            }
            previous_pc = pre_pc;
        }
        ptrace(PTRACE_DETACH, child, nullptr, nullptr);
        kill(child, SIGKILL);
        waitpid(child, nullptr, 0);

        /* Coverage: the clone's own ADRP/BR must have executed. */
        bool saw_adrp = false;
        bool saw_br = false;
        const rtgum_dbi::OffsetMapEntry *adrp_map = nullptr;
        const rtgum_dbi::OffsetMapEntry *br_map = nullptr;
        for (size_t i = 0; i < result.trace_size; ++i) {
            if (result.trace[i].kind == rtgum_dbi::InstrKind::Adrp && !adrp_map) {
                uint32_t off = 0;
                if (rtgum_dbi::Relocator::clone_offset_for(
                        result, result.trace[i].orig_index, off)) {
                    adrp_map = &result.map[result.trace[i].orig_index];
                }
            }
            if (result.trace[i].kind == rtgum_dbi::InstrKind::Br && !br_map) {
                uint32_t off = 0;
                if (rtgum_dbi::Relocator::clone_offset_for(
                        result, result.trace[i].orig_index, off)) {
                    br_map = &result.map[result.trace[i].orig_index];
                }
            }
        }
        for (unsigned int i = 0; i < observed_count; ++i) {
            if (adrp_map && observed_origins[i] == adrp_map->orig_index) saw_adrp = true;
            if (br_map && observed_origins[i] == br_map->orig_index) saw_br = true;
        }
        /* Every indirect event must be self-consistent: the landing equals the
         * value the target register held before the step. */
        unsigned int verified_landings = 0;
        unsigned int landing_mismatch = 0;
        for (unsigned int i = 0; i < indirect_count; ++i) {
            const IndirectEvent &event = indirect_events[i];
            const char *name = event.links ? "blr" : "br";
            std::printf("dbi-lab indirect[%u] %s pre=0x%lx reg-value=0x%lx "
                        "landing=0x%lx orig=%u tid=%u %s\n",
                        i, name, event.pre_pc, event.register_value,
                        event.landing, event.orig_index, event.tid,
                        event.landing == event.register_value ? "match" : "MISMATCH");
            if (event.landing != 0 && event.landing == event.register_value)
                ++verified_landings;
            else
                ++landing_mismatch;
        }
        std::printf("dbi-lab trace-steps=%u in-clone=%u escaped=%u signal-stops=%u "
                    "clone-pc-coverage=%s adrp-executed=%d br-executed=%d "
                    "indirect-events=%u verified-landings=%u br-landing=0x%lx\n",
                    steps, in_clone, escaped_pc, signal_stops,
                    in_clone > 0 ? "yes" : "no", saw_adrp ? 1 : 0, saw_br ? 1 : 0,
                    indirect_count, verified_landings, br_landing);
        std::fflush(stdout);
        if (in_clone == 0 || !saw_adrp || !saw_br) {
            std::fprintf(stderr,
                         "dbi-lab clone PC coverage incomplete (in-clone=%u adrp=%d br=%d)\n",
                         in_clone, saw_adrp ? 1 : 0, saw_br ? 1 : 0);
            std::fprintf(stderr, "dbi-lab adrp-index=%u br-index=%u observed=%u:",
                         adrp_map ? adrp_map->orig_index : 0xffffffffU,
                         br_map ? br_map->orig_index : 0xffffffffU,
                         observed_count);
            for (unsigned int i = 0; i < observed_count && i < 40U; ++i)
                std::fprintf(stderr, " %u", observed_origins[i]);
            std::fprintf(stderr, "\n");
            return 1;
        }
        /* The runtime follow must be observed on the real indirect branch,
         * not merely inferred from a return value. */
        if (indirect_count == 0 || verified_landings == 0 || landing_mismatch != 0) {
            std::fprintf(stderr,
                         "dbi-lab indirect follow unverified (events=%u verified=%u mismatch=%u)\n",
                         indirect_count, verified_landings, landing_mismatch);
            return 1;
        }
        /* Cross-check the two independent mechanisms: the dispatcher stubs
         * recorded the runtime targets inside the clone, and the single-step
         * trace observed them from outside. They must agree, every site must
         * have executed, and RET sites must return to a statically known call
         * continuation. */
        const bool dispatcher_on = result.dispatcher.mode != 0U;
        unsigned int sites_exercised = 0;
        unsigned int site_mismatch = 0;
        unsigned int br_verified = 0;
        unsigned int ret_verified = 0;
        for (size_t i = 0; i < result.trace_size; ++i) {
            const rtgum_dbi::BranchTraceEntry &entry = result.trace[i];
            if (entry.site_index == 0xffffU || !entry.runtime_target) continue;
            const rtgum_dbi::SiteRecord &record = records[entry.site_index];
            std::printf("dbi-follow site=%u orig=%u kind=%u hits=%llu target=0x%llx "
                        "expected-return=0x%llx\n",
                        static_cast<unsigned>(entry.site_index), entry.orig_index,
                        static_cast<unsigned>(entry.kind),
                        static_cast<unsigned long long>(record.hits),
                        static_cast<unsigned long long>(record.target),
                        static_cast<unsigned long long>(record.expected_return));
            if (record.hits == 0) continue; /* unexecuted sites are legitimate */
            if (record.target == 0) {
                ++site_mismatch;
                continue;
            }
            ++sites_exercised;
            if (entry.kind == rtgum_dbi::InstrKind::Ret) {
                /* A RET must continue at a real instruction of this block:
                 * confirm the range first, then map, and let the mapper itself
                 * reject literals, misaligned offsets and out-of-code bytes. */
                if (record.target < clone_begin || record.target >= clone_end) {
                    ++site_mismatch;
                    continue;
                }
                uint32_t back = 0;
                if (rtgum_dbi::Relocator::original_index_for(
                        result, static_cast<uint32_t>(record.target - clone_begin),
                        back))
                    ++ret_verified;
                else
                    ++site_mismatch;
                continue;
            }
            /* The observed landing of the same source instruction must match
             * the recorded target. */
            bool matched = false;
            for (unsigned int e = 0; e < indirect_count; ++e) {
                if (indirect_events[e].landing == record.target) matched = true;
            }
            if (matched) ++br_verified;
            if (!matched) {
                ++site_mismatch;
                std::fprintf(stderr,
                             "dbi-follow site=%u recorded target does not match "
                             "the single-step landing\n",
                             static_cast<unsigned>(entry.site_index));
            }
            if (!clone_offset_is_literal(result, entry.orig_index * 4U) &&
                entry.kind == rtgum_dbi::InstrKind::Ret &&
                record.target < clone_begin) {
                /* A RET whose target lies outside the clone must be a real
                 * continuation (the caller), never a literal. */
            }
        }
        std::printf("dbi-follow sites=%u exercised=%u mismatch=%u literals=%zu\n",
                    static_cast<unsigned>(result.site_count), sites_exercised,
                    site_mismatch, result.literal_size);
        std::fflush(stdout);
        const bool need_br = dispatcher_on && (result.dispatcher.mode & 1U) != 0U;
        const bool need_ret = dispatcher_on && (result.dispatcher.mode & 2U) != 0U;
        if (dispatcher_on &&
            (result.site_count == 0 || sites_exercised == 0 || site_mismatch != 0 ||
             (need_br && br_verified == 0) || (need_ret && ret_verified == 0))) {
            std::fprintf(stderr, "dbi-follow dispatcher verification failed\n");
            return 1;
        }
        /* Explicit path: collapse the executed clone PCs into the sequence of
         * original instruction indices, which is the trace the acceptance
         * asks for ("trace 能还原 lab_flower 的真实路径"). */
        {
            char path[512];
            unsigned long cursor = 0;
            unsigned int last = 0xffffffffU;
            for (unsigned int i = 0; i < observed_count && cursor < sizeof(path) - 8U; ++i) {
                if (observed_origins[i] == last) continue;
                last = observed_origins[i];
                cursor += static_cast<unsigned long>(
                    std::snprintf(path + cursor, sizeof(path) - cursor, "%s%u",
                                  cursor == 0 ? "" : ",", last));
            }
            path[cursor < sizeof(path) ? cursor : sizeof(path) - 1U] = '\0';
            std::printf("dbi-path(orig-indices)=%s\n", path);
            std::fflush(stdout);
        }        /* Per-thread follower + target cache, driven with the data this run
     * actually produced: every direct BL in the block pushes its clone-side
     * continuation on the shadow stack, every recorded RET target pops it, and
     * the BR target goes through the cache (miss -> insert -> hit, then a
     * version bump must invalidate it). */
    {
        using namespace rtgum_dbi;
        ThreadState state{};
        state.address_space = static_cast<uint64_t>(getpid());
        state.code_version = 1U;
        Follower follower(state);
        TargetCache cache;
        cache.reset();
        FollowStats stats{};
        unsigned int shadow_mismatch = 0;
        unsigned int returns_checked = 0;
        /* Pseudo-source: replay the recorded single-step PC sequence. Sites are
         * classified by DECODING the clone word at each PC (not by looking up
         * a folded index, which repeats for expansion-internal PCs), and the
         * continuation is the next recorded PC. */
        unsigned int call_sites = 0;
        for (unsigned int i = 0; i + 1U < observed_pc_count; ++i) {
            const unsigned long here = observed_pcs[i];
            const unsigned long next = observed_pcs[i + 1];
            if (here < clone_begin || here + 4U > clone_end) continue;
            const uint32_t word = *reinterpret_cast<const uint32_t *>(here);
            if ((word & 0xfc000000U) == 0x94000000U ||
                (word & 0xfffffc1fU) == 0xd63f0000U) {
                /* The continuation is the instruction AFTER the whole emitted
                 * call sequence, i.e. the clone offset of the next source
                 * instruction -- not the next single-step PC, which is the
                 * callee's entry. */
                const uint32_t offset = static_cast<uint32_t>(here - clone_begin);
                unsigned long continuation = here + 4U;
                for (size_t slot = 0; slot < result.map_size; ++slot) {
                    if (result.map[slot].clone_offset > offset && slot != 0) {
                        continuation = clone_begin + result.map[slot].clone_offset;
                        break;
                    }
                }
                ++call_sites;
                if (follower.on_call(continuation) != FollowStatus::Ok)
                    ++shadow_mismatch;
                continue;
            }
            if ((word & 0xfffffc1fU) == 0xd65f0000U) {
                ++returns_checked;
                if (follower.on_return(next, stats) != FollowStatus::Ok)
                    ++shadow_mismatch;
            }
        }
        /* Exercise the target cache from the independently observed single-step
         * landing. Dispatcher records do not exist when RTGUM_DBI_DISPATCH is
         * off, so using SiteRecord here silently skipped the cache test in the
         * default lab mode. Pick one verified non-link BR event, then prove the
         * miss -> insert -> hit path and that a code-version invalidation both
         * removes the old entry and leaves the new version unresolved. */
        unsigned int cache_ok = 0;
        unsigned int cache_invalidated = 0;
        const IndirectEvent *cache_event = nullptr;
        for (unsigned int i = 0; i < indirect_count; ++i) {
            const IndirectEvent &event = indirect_events[i];
            if (!event.links && event.landing != 0 &&
                event.landing == event.register_value) {
                cache_event = &event;
                break;
            }
        }
        if (cache_event != nullptr) {
            BlockKey key{};
            key.address_space = static_cast<uint64_t>(getpid());
            key.target = cache_event->landing;
            key.code_version = 1U;
            key.kind = BranchClass::Branch;
            uint64_t clone_entry = 0;
            const LandingEvidence unguarded{true, false, false, false, 0};
            const FollowStatus first =
                follower.on_indirect(key, cache, clone_entry, stats, 0, &unguarded);
            cache.insert(key, 0x1000U);
            const FollowStatus second =
                follower.on_indirect(key, cache, clone_entry, stats, 0, &unguarded);
            if (first == FollowStatus::CacheMiss && second == FollowStatus::Ok &&
                clone_entry == 0x1000U)
                ++cache_ok;

            cache.invalidate_except(2U);
            ++stats.invalidations;
            uint64_t removed_entry = 0;
            const FollowStatus removed = cache.lookup(key, removed_entry);
            state.code_version = 2U;
            key.code_version = 2U;
            const FollowStatus third =
                follower.on_indirect(key, cache, clone_entry, stats, 0, &unguarded);
            if (removed == FollowStatus::CacheMiss &&
                third == FollowStatus::CacheMiss)
                ++cache_invalidated;
        }
        /* Non-local control flow matrix: tail call, signal checkpoint, a legal
         * longjmp-style unwind and one genuine mismatch. Statuses are asserted
         * exactly, so a legitimate unwind that gets reported as an error -- or
         * an error that gets swallowed as an unwind -- fails the run. */
        {
            unsigned int nlc_failures = 0;
            ThreadState s2{};
            s2.address_space = 1U;
            s2.code_version = 1U;
            Follower f2(s2);
            FollowStats st2{};
            f2.on_call(0x100U);
            f2.on_call(0x200U);
            f2.on_call(0x300U);
            if (f2.depth() != 3U) ++nlc_failures;
            if (f2.on_return(0x300U, st2) != FollowStatus::Ok) ++nlc_failures; /* normal */
            if (f2.depth() != 2U) ++nlc_failures;
            /* A plain RET cannot skip frames even if an outer address matches. */
            if (f2.on_return(0x100U, st2) != FollowStatus::ReturnMismatch)
                ++nlc_failures;
            /* A verified longjmp can name its destination frame. */
            if (f2.on_nonlocal_return(0x100U, 1U, st2) != FollowStatus::Ok)
                ++nlc_failures;
            if (st2.unwinds != 1U || f2.depth() != 0U) ++nlc_failures;
            f2.on_call(0x100U);
            f2.on_call(0x200U);
            if (f2.on_nonlocal_return(0x100U, 2U, st2) !=
                FollowStatus::ReturnMismatch)
                ++nlc_failures;
            const SignalCheckpoint saved = f2.checkpoint();
            if (f2.on_return(0x200U, st2) != FollowStatus::Ok) ++nlc_failures;
            f2.on_call(0x400U);            /* handler body */
            if (f2.on_return(0x400U, st2) != FollowStatus::Ok) ++nlc_failures;
            s2.code_version = 2U;
            if (f2.restore_checkpoint(saved, st2) !=
                FollowStatus::InvalidCheckpoint) ++nlc_failures;
            s2.code_version = 1U;
            if (f2.restore_checkpoint(saved, st2) != FollowStatus::Ok ||
                f2.depth() != 2U || st2.signal_frames != 1U) ++nlc_failures;
            f2.on_tail_call(0x500U, st2);  /* tail call keeps caller's return */
            if (f2.depth() != 2U || st2.tail_calls != 1U) ++nlc_failures;
            if (f2.on_return(0x200U, st2) != FollowStatus::Ok) ++nlc_failures;
            TargetCache call_cache;
            call_cache.reset();
            BlockKey call_key{1U, 0x600U, 1U, BranchClass::Call};
            call_cache.insert(call_key, 0x700U);
            uint64_t callee_clone = 0;
            const LandingEvidence unguarded{true, false, false, true, 0};
            if (f2.on_indirect(call_key, call_cache, callee_clone, st2) !=
                FollowStatus::LandingUnverified)
                ++nlc_failures;
            if (f2.on_indirect(call_key, call_cache, callee_clone, st2,
                               0, &unguarded) !=
                FollowStatus::MissingContinuation || f2.depth() != 1U)
                ++nlc_failures;
            if (f2.on_indirect(call_key, call_cache, callee_clone, st2,
                               0x800U, &unguarded) != FollowStatus::Ok ||
                callee_clone != 0x700U || f2.depth() != 2U ||
                f2.on_return(0x800U, st2) != FollowStatus::Ok)
                ++nlc_failures;
            const LandingEvidence wrong_pad{true, true, false, true, 0xd503201fU};
            if (f2.on_indirect(call_key, call_cache, callee_clone, st2,
                               0x800U, &wrong_pad) != FollowStatus::InvalidLanding)
                ++nlc_failures;
            const LandingEvidence bti_call{true, true, false, true, 0xd503245fU};
            if (f2.on_indirect(call_key, call_cache, callee_clone, st2,
                               0x800U, &bti_call) != FollowStatus::Ok ||
                f2.on_return(0x800U, st2) != FollowStatus::Ok)
                ++nlc_failures;
            BlockKey pac_key{1U, 0x610U, 1U, BranchClass::Pac};
            call_cache.insert(pac_key, 0x710U);
            const LandingEvidence unauthenticated{true, false, false, true, 0};
            if (f2.on_indirect(pac_key, call_cache, callee_clone, st2,
                               0x810U, &unauthenticated) !=
                FollowStatus::AuthenticationUnverified)
                ++nlc_failures;
            const LandingEvidence authenticated{true, false, true, true, 0};
            if (f2.on_indirect(pac_key, call_cache, callee_clone, st2,
                               0x810U, &authenticated) != FollowStatus::Ok ||
                f2.on_return(0x810U, st2) != FollowStatus::Ok)
                ++nlc_failures;
            /* A target matching no live frame is still an error. */
            if (f2.on_return(0xdeadU, st2) != FollowStatus::ReturnMismatch)
                ++nlc_failures;
            BlockKey ret_key{1U, 0x100U, 1U, BranchClass::Return};
            call_cache.insert(ret_key, 0x900U);
            if (f2.on_indirect(ret_key, call_cache, callee_clone, st2) !=
                FollowStatus::Ok || f2.depth() != 0U)
                ++nlc_failures;
            /* Real signal delivery into a running clone: the child is
         * single-stepped, and the moment its PC is inside the clone the parent
         * injects SIGUSR1. The handler calls the clone again, so the follower
         * sees call/return activity inside the handler; the checkpoint rule
         * must leave the interrupted frame intact. */
        {
            const pid_t sig_child = fork();
            if (sig_child == 0) {
                if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) != 0) _exit(2);
                raise(SIGSTOP);
                volatile long value = clone_flower(2, 2);
                _exit(value == 56 ? 0 : 9);
            }
            if (sig_child > 0) {
                int sig_status = 0;
                bool injected = false;
                unsigned int sig_steps = 0;
                if (waitpid(sig_child, &sig_status, 0) == sig_child &&
                    WIFSTOPPED(sig_status)) {
                    ptrace(PTRACE_SINGLESTEP, sig_child, nullptr, nullptr); if (false) {
                        /* continue below with whatever we have */
                    }
                    while (sig_steps < 4096U) {
                        if (waitpid(sig_child, &sig_status, 0) != sig_child) break;
                        if (WIFEXITED(sig_status) || WIFSIGNALED(sig_status)) break;
                        UserPtRegs child_regs{};
                        struct iovec child_iov{&child_regs, sizeof(child_regs)};
                        if (ptrace(PTRACE_GETREGSET, sig_child,
                                   reinterpret_cast<void *>(static_cast<long>(1)),
                                   &child_iov) != 0)
                            break;
                        const unsigned long child_pc = child_regs.pc;
                        ++sig_steps;
                        int deliver = 0;
                        if (!injected && child_pc >= clone_begin &&
                            child_pc < clone_end) {
                            injected = true;
                            deliver = SIGUSR1;
                        }
                        if (ptrace(PTRACE_SINGLESTEP, sig_child, nullptr, deliver) != 0)
                            break;
                    }
                    ptrace(PTRACE_DETACH, sig_child, nullptr, nullptr);
                }
                int child_result = 0;
                waitpid(sig_child, &child_result, 0);
                const bool exited_ok =
                    WIFEXITED(child_result) && WEXITSTATUS(child_result) == 0;
                std::printf("dbi-follow-signal injected=%d steps=%u child-ok=%d\n",
                            injected ? 1 : 0, sig_steps, exited_ok ? 1 : 0);
                std::fflush(stdout);
                if (!injected || !exited_ok) {
                    std::fprintf(stderr, "dbi-follow-signal verification failed\n");
                    return 1;
                }
            }
        }        /* Does a C++ exception unwind through a relocated frame? Run it in a
         * child so a failed phase-2 (std::terminate) cannot take the test down
         * with it; the parent reports the observed outcome.
         *
         * The relocated frame has no entry in any module's .eh_frame, so the
         * unwinder cannot look it up by PC and phase 1 never finds a landing
         * pad. The fix is to clone the covering FDE too: build_clone_fde copies
         * [CIE..FDE] and rewrites its pcrel fields for the clone address, and
         * __register_frame puts the copy into the dynamic table the unwinder
         * searches first. */
        {
            unsigned char thrower_code[256];
            unsigned long thrower_len = 256UL;
            /* Keep the copy inside one page so the source is always readable. */
            const unsigned long thrower_src =
                reinterpret_cast<unsigned long>(&lab_thrower);
            thrower_len = 0x1000UL - (thrower_src & 0xfffUL);
            if (thrower_len > sizeof(thrower_code)) thrower_len = sizeof(thrower_code);
            rtgum_dbi::EhModule thrower_module{};
            rtgum_dbi::FdeLocation thrower_fde{};
            if (!rtgum_dbi::find_module_for_address(thrower_src, &thrower_module) ||
                rtgum_dbi::detail::find_fde(thrower_module, thrower_src,
                                             &thrower_fde) != rtgum_dbi::FdeStatus::Ok ||
                thrower_fde.initial_location != thrower_src ||
                thrower_fde.address_range > thrower_len) {
                std::fprintf(stderr, "dbi-unwind source function frame unavailable\n");
                return 1;
            }
            thrower_len = static_cast<unsigned long>(thrower_fde.address_range);
            std::memcpy(thrower_code, reinterpret_cast<const void *>(thrower_src),
                        thrower_len);
            void *unwind_clone = MAP_FAILED;
            /* The frame data must live close enough to the clone that its PC
             * fields can be encoded as a signed 32-bit PC-relative delta, and it
             * must outlive the clone. A static buffer in .bss is typically tens
             * of gigabytes away on a 39-bit address space, which no such field
             * can reach, so the descriptors are placed on the page right after
             * the clone and registered from there. */
            constexpr size_t kFrameCapacity = 4096;
            uint8_t *unwind_frame = nullptr;
            void *unwind_region = mmap(nullptr, 8192, PROT_READ | PROT_WRITE,
                                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (unwind_region != MAP_FAILED) {
                unwind_clone = unwind_region;
                unwind_frame = reinterpret_cast<uint8_t *>(unwind_region) + kFrameCapacity;
            }
            int observed_signal = 0;
            int observed_caught = 0;
            /* Frame-data diagnostics: the FDE resolution, whether the lookup
             * really returned the copy, and the delta the rewrite had to fit. */
            int fde_ok = 0;
            int fde_found = 0;
            int fde_locate_ok = 0;
            int fde_matches = 0;
            int fde_absent = 0;
            unsigned int clone_status = 0;
            unsigned int clone_descriptors = 0;
            unsigned int clone_needed = 0;
            unsigned int clone_input_cie = 0;
            unsigned int clone_input_fde = 0;
            unsigned int clone_input_reloc = 0;
            unsigned long long clone_input_base = 0;
            unsigned long long clone_input_send = 0;
            unsigned long fde_src = 0;
            unsigned long fde_range = 0;
            unsigned long fde_initial = 0;
            long long fde_delta = 0;
            rtgum_dbi::CloneFdeResult child_frame{};

            if (unwind_clone != MAP_FAILED) {
                static uint8_t unwind_code[4096];
                static rtgum_dbi::OffsetMapEntry unwind_map[64];
                static rtgum_dbi::BranchTraceEntry unwind_trace[64];
                static rtgum_dbi::LiteralRange unwind_literals[64];
                rtgum_dbi::RelocationResult unwind_result = rtgum_dbi::make_result(
                    unwind_code, sizeof(unwind_code), unwind_map, 64, unwind_trace,
                    64, unwind_literals, 64);
                if (rtgum_dbi::Relocator::relocate(
                        thrower_code, thrower_len, thrower_src,
                        reinterpret_cast<unsigned long>(unwind_clone),
                        unwind_result)) {
                    std::memcpy(unwind_clone, unwind_result.code,
                                unwind_result.code_size);
                    __builtin___clear_cache(
                        reinterpret_cast<char *>(unwind_clone),
                        reinterpret_cast<char *>(unwind_clone) +
                            unwind_result.code_size);
                    mprotect(unwind_clone, 4096, PROT_READ | PROT_EXEC);
                    /* Self-check the frame clone before trusting it: the copy
                     * must decode back to the clone PC, and the unwinder must
                     * report the copy itself for a PC inside the clone. */
                    rtgum_dbi::EhModule frame_module{};
                    rtgum_dbi::FdeLocation frame_location{};
                    rtgum_dbi::ModuleStatus module_status =
                        rtgum_dbi::ModuleStatus::NoCoveringSegment;
                    const bool module_found = rtgum_dbi::find_module_for_address(
                        thrower_src, &frame_module, &module_status);
                    rtgum_dbi::detail::FdeProbe fde_probe{};
                    const rtgum_dbi::FdeStatus fde_status =
                        rtgum_dbi::find_fde_for_range_with(
                            &rtgum_dbi::detail::find_fde, thrower_src,
                            &frame_module, &frame_location, &fde_probe);
                    /* Independent cross-check: what does the unwinder itself
                     * say about the original PC? If it cannot find an FDE for
                     * the unrelocated function either, the resolver is wrong
                     * rather than the registration.
                     *
                     * The resolver is loaded through dlsym on purpose: a lazy
                     * PLT call would fault in the dynamic linker on a machine
                     * where libc does not export the symbol. The bases argument
                     * must be real storage: libunwind writes through it before
                     * it has found anything. */
                    /* Independent cross-check: what does the unwinder itself
                     * say about the original PC? If it cannot find an FDE for
                     * the unrelocated function either, the resolver is wrong
                     * rather than the registration. The bases argument must be
                     * real storage: libunwind writes through it before it has
                     * found anything, and a null pointer faults inside libc. */
                    UnwindFindFdeFn find_fde_symbol = unwind_find_symbol();
                    UnwindFindFdeBases orig_bases{};
                    UnwindFindFdeBases clone_bases{};
                    const bool orig_unwind_fde =
                        find_fde_symbol != nullptr &&
                        find_fde_symbol(reinterpret_cast<const void *>(thrower_src),
                                        &orig_bases) != nullptr;
                    diagnose_frame_offsets(thrower_src, frame_module, frame_location);
                    std::printf("dbi-ehframe-module found=%d status=%u base=0x%lx "
                                "eh-size=0x%llx unwinder-finds-original=%d "
                                "fde-status=%u entries=%u exit=%u cand=%u rejected=%u "
                                "fail=%u cie-off=0x%x cie-len=0x%x "
                                "bad='%c'@0x%x cursor=0x%x end=0x%x "
                                "cie=0x%x letters=%02x%02x%02x%02x "
                                "last-off=0x%x last-cand=0x%x total=0x%x "
                                "p0=0x%x[%02x%02x%02x%02x%02x%02x%02x%02x] "
                                "p1=0x%x[%02x%02x%02x%02x%02x%02x%02x%02x] "
                                "clone-fail=%u need=%u cap=%u\n",
                                module_found ? 1 : 0,
                                static_cast<unsigned>(module_status),
                                static_cast<unsigned long>(frame_module.base),
                                static_cast<unsigned long long>(frame_module.eh_frame_size),
                                orig_unwind_fde ? 1 : 0,
                                static_cast<unsigned>(fde_status),
                                fde_probe.entries, fde_probe.exit_code,
                                fde_probe.candidates, fde_probe.rejected,
                                static_cast<unsigned>(fde_probe.fail_stage),
                                fde_probe.cie_offset, fde_probe.cie_length,
                                fde_probe.fail_byte >= 0x20U && fde_probe.fail_byte < 0x7fU
                                    ? static_cast<char>(fde_probe.fail_byte)
                                    : '?',
                                fde_probe.fail_at, fde_probe.fail_cursor,
                                fde_probe.fail_end, fde_probe.fail_cie,
                                fde_probe.fail_letters[0], fde_probe.fail_letters[1],
                                fde_probe.fail_letters[2], fde_probe.fail_letters[3],
                                fde_probe.last_offset, fde_probe.last_candidate_offset,
                                fde_probe.total_dbg,
                                fde_probe.probe_offsets[0],
                                fde_probe.probe_bytes[0][0], fde_probe.probe_bytes[0][1],
                                fde_probe.probe_bytes[0][2], fde_probe.probe_bytes[0][3],
                                fde_probe.probe_bytes[0][4], fde_probe.probe_bytes[0][5],
                                fde_probe.probe_bytes[0][6], fde_probe.probe_bytes[0][7],
                                fde_probe.probe_offsets[1],
                                fde_probe.probe_bytes[1][0], fde_probe.probe_bytes[1][1],
                                fde_probe.probe_bytes[1][2], fde_probe.probe_bytes[1][3],
                                fde_probe.probe_bytes[1][4], fde_probe.probe_bytes[1][5],
                                fde_probe.probe_bytes[1][6], fde_probe.probe_bytes[1][7],
                                fde_probe.clone_fail, fde_probe.clone_needed,
                                fde_probe.clone_capacity);
                    std::fflush(stdout);
                    fde_found = fde_status == rtgum_dbi::FdeStatus::Ok ? 1 : 0;
                    if (fde_found) {
                        fde_src = frame_location.initial_location;
                        fde_range = frame_location.address_range;
                        /* Verify that the source FDE found by our section scan
                         * agrees with bionic's static lookup. This says nothing
                         * about the separate dynamic FDE cache linked into the
                         * executable; the clone probe below tests that cache. */
                        void *real_fde = const_cast<uint8_t *>(
                            frame_module.eh_frame + frame_location.fde_offset);
                        const void *real_lookup =
                            find_fde_symbol != nullptr
                                ? find_fde_symbol(
                                      reinterpret_cast<const void *>(thrower_src),
                                      &orig_bases)
                                : nullptr;
                        std::printf("dbi-ehframe-static-probe real-fde=0x%lx lookup=0x%lx "
                                    "same=%d\n",
                                    static_cast<unsigned long>(reinterpret_cast<
                                        uintptr_t>(real_fde)),
                                    static_cast<unsigned long>(reinterpret_cast<
                                        uintptr_t>(real_lookup)),
                                    real_lookup == real_fde ? 1 : 0);
                        std::fflush(stdout);
                        rtgum_dbi::CloneFdeResult clone_frame =
                            rtgum_dbi::build_clone_fde_span(
                                frame_module, frame_location,
                                reinterpret_cast<unsigned long>(unwind_clone),
                                static_cast<uint32_t>(unwind_result.code_size),
                                unwind_frame, kFrameCapacity,
                                unwind_result.map, unwind_result.map_size);
                        fde_ok = clone_frame.status == rtgum_dbi::FdeStatus::Ok ? 1 : 0;
                        clone_status = static_cast<unsigned>(clone_frame.status);
                        clone_descriptors = clone_frame.descriptor_count;
                        clone_needed = clone_frame.clone_size;
                        clone_input_cie = clone_frame.input_cie_size;
                        clone_input_fde = clone_frame.input_fde_size;
                        clone_input_reloc = clone_frame.input_relocated_size;
                        clone_input_base = clone_frame.input_clone_base;
                        clone_input_send = clone_frame.input_source_end;
                        fde_delta = static_cast<long long>(clone_frame.delta);
                        if (fde_ok) {
                            child_frame = clone_frame;
                            rtgum_dbi::register_clone_fde_span(clone_frame);
                            const void *linked_lookup =
                                _Unwind_Find_FDE(unwind_clone, &clone_bases);
                            const void *bionic_lookup =
                                find_fde_symbol != nullptr
                                    ? find_fde_symbol(unwind_clone, &clone_bases)
                                    : nullptr;
                            std::printf("dbi-ehframe-lookup handle=0x%lx "
                                        "linked-lookup=0x%lx bionic-lookup=0x%lx "
                                        "clone-pc=0x%lx personality-rebased=%d "
                                        "lsda-rebased=%d\n",
                                        static_cast<unsigned long>(reinterpret_cast<
                                            uintptr_t>(clone_frame.clone_fde)),
                                        static_cast<unsigned long>(reinterpret_cast<
                                            uintptr_t>(linked_lookup)),
                                        static_cast<unsigned long>(reinterpret_cast<
                                            uintptr_t>(bionic_lookup)),
                                        static_cast<unsigned long>(reinterpret_cast<
                                            uintptr_t>(unwind_clone)),
                                        clone_frame.personality_rewritten ? 1 : 0,
                                        clone_frame.lsda_rewritten ? 1 : 0);
                            std::fflush(stdout);
                            fde_locate_ok = linked_lookup == clone_frame.clone_fde ? 1 : 0;
                            rtgum_dbi::unregister_clone_fde_span(clone_frame);
                            /* Decode what we wrote: the copy must describe the
                             * clone, not the original PC. */
                            const unsigned long clone_field =
                                reinterpret_cast<unsigned long>(unwind_frame) +
                                clone_frame.cie_bytes + 8UL;
                            const long offset =
                                *reinterpret_cast<const int32_t *>(clone_field);
                            fde_initial =
                                static_cast<unsigned long>(static_cast<long long>(clone_field) +
                                                           offset);
                            fde_absent = orig_unwind_fde ? 0 : 1;
                            fde_matches =
                                fde_initial == reinterpret_cast<unsigned long>(unwind_clone)
                                    ? 1
                                    : 0;
                        }
                    }
                    const pid_t unwind_child = fork();
                    if (unwind_child == 0) {
                        /* Register inside the child. The frame data is private
                         * to this process, so building it before the fork and
                         * registering after keeps the vfork-style sharing in
                         * bionic's fork out of the picture entirely. */
                        if (fde_ok) {
                            /* Register the finished list inside the child: the
                             * frame data is private to this process, and doing
                             * it after the fork keeps it out of bionic's
                             * fork-time sharing. */
                            rtgum_dbi::register_clone_fde_span(child_frame);
                        }
                        auto *clone_thrower =
                            reinterpret_cast<long (*)(long)>(unwind_clone);
                        long value = 7;
                        try {
                            value = clone_thrower(1);
                        } catch (const std::exception &) {
                            value = -1;
                        }
                        if (fde_ok) rtgum_dbi::unregister_clone_fde_span(child_frame);
                        _exit(value == -1 ? 0 : 1);
                    }
                    int unwind_status = 0;
                    waitpid(unwind_child, &unwind_status, 0);
                    if (WIFSIGNALED(unwind_status)) observed_signal = WTERMSIG(unwind_status);
                    else if (WIFEXITED(unwind_status)) observed_caught = WEXITSTATUS(unwind_status) == 0 ? 1 : 0;
                }
            }
            std::printf("dbi-ehframe found=%d ok=%d clone-status=%u descriptors=%u "
                        "need=%u cie=%u fde=%u reloc=%u src=0x%lx range=0x%lx base=0x%llx send=0x%llx "
                        "delta=%lld clone-initial=0x%lx matches=%d locate-ok=%d "
                        "absent-without=%d\n",
                        fde_found, fde_ok, static_cast<unsigned>(clone_status),
                        clone_descriptors, clone_needed, clone_input_cie,
                        clone_input_fde, clone_input_reloc, fde_src, fde_range, clone_input_base, clone_input_send,
                        fde_delta, fde_initial, fde_matches, fde_locate_ok,
                        fde_absent);
            std::printf("dbi-unwind original=%ld clone-caught=%d clone-signal=%d\n",
                        lab_catcher(1), observed_caught, observed_signal);
            std::fflush(stdout);
            if (fde_found == 0 || fde_ok == 0 || fde_matches == 0) {
                std::fprintf(stderr, "dbi-ehframe construction failed\n");
                return 1;
            }
            if (observed_caught != 1 || observed_signal != 0 || fde_locate_ok == 0) {
                std::fprintf(stderr,
                             "dbi-unwind FAIL: clone-caught=%d signal=%d locate-ok=%d\n",
                             observed_caught, observed_signal, fde_locate_ok);
                return 1;
            }
        }        std::printf("dbi-follow-nlc failures=%u unwinds=%llu tail-calls=%llu "
                        "signal-frames=%llu depth=%u\n",
                        nlc_failures,
                        static_cast<unsigned long long>(st2.unwinds),
                        static_cast<unsigned long long>(st2.tail_calls),
                        static_cast<unsigned long long>(st2.signal_frames),
                        f2.depth());
            std::fflush(stdout);
            if (nlc_failures != 0) {
                std::fprintf(stderr, "dbi-follow-nlc verification failed\n");
                return 1;
            }
        }        std::printf("dbi-follow-thread depth=%u call-sites=%u returns-checked=%u shadow-mismatch=%u "
                    "cache-ok=%u cache-invalidated=%u hits=%llu misses=%llu\n",
                    follower.depth(), call_sites, returns_checked, shadow_mismatch, cache_ok,
                    cache_invalidated,
                    static_cast<unsigned long long>(stats.cache_hits),
                    static_cast<unsigned long long>(stats.cache_misses));
        std::fflush(stdout);
        if (shadow_mismatch != 0 || cache_ok == 0 || cache_invalidated == 0) {
            std::fprintf(stderr, "dbi-follow-thread verification failed\n");
            return 1;
        }
    }    std::puts(dispatcher_on
                      ? "clone-pc-coverage=1 indirect-target-verified=1 dispatcher-verified=1"
                      : "clone-pc-coverage=1 indirect-target-verified=1 dispatcher=off");
    } else {
        std::puts("clone-pc-coverage=skipped runtime-br-landing-recorded=skipped");
    }
    /* Force a record address outside ADR reach. BLR returns to the inserted
     * literal-skip branch, so test both the return PC and the emitted data. */
    {
        void *call_clone = mmap(nullptr, 4096, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (call_clone == MAP_FAILED) return 1;
        static rtgum_dbi::SiteRecord call_records[2];
        call_records[0] = rtgum_dbi::SiteRecord{};
        call_records[1] = rtgum_dbi::SiteRecord{};
        uint8_t call_code[512]{};
        rtgum_dbi::OffsetMapEntry call_map[4]{};
        rtgum_dbi::BranchTraceEntry call_trace[4]{};
        rtgum_dbi::LiteralRange call_literals[4]{};
        rtgum_dbi::RelocationResult call_result = rtgum_dbi::make_result(
            call_code, sizeof(call_code), call_map, 4, call_trace, 4,
            call_literals, 4);
        call_result.dispatcher.enabled = true;
        call_result.dispatcher.mode = 3U;
        call_result.dispatcher.record_base =
            reinterpret_cast<uint64_t>(call_records);
        call_result.dispatcher.record_stride = sizeof(rtgum_dbi::SiteRecord);
        call_result.dispatcher.max_sites = 2U;
        const uint64_t source_pc = reinterpret_cast<uint64_t>(&dbi_blr_fixture);
        const uint64_t clone_pc = reinterpret_cast<uint64_t>(call_clone);
        const uint64_t record_pc = reinterpret_cast<uint64_t>(call_records);
        const uint64_t distance = record_pc > clone_pc ? record_pc - clone_pc
                                                      : clone_pc - record_pc;
        const bool relocated = distance > 0x100000U &&
            rtgum_dbi::Relocator::relocate(
                reinterpret_cast<const void *>(source_pc), 16U, source_pc,
                clone_pc, call_result);
        if (!relocated || call_result.site_count != 2U ||
            call_result.literal_size != 2U) {
            std::fprintf(stderr,
                         "dbi-blr-far-record relocation failed distance=%llu "
                         "sites=%u literals=%zu reason=%u\n",
                         static_cast<unsigned long long>(distance),
                         call_result.site_count, call_result.literal_size,
                         static_cast<unsigned>(call_result.reject.reason));
            munmap(call_clone, 4096);
            return 1;
        }
        std::memcpy(call_clone, call_result.code, call_result.code_size);
        __builtin___clear_cache(reinterpret_cast<char *>(call_clone),
                                reinterpret_cast<char *>(call_clone) +
                                    call_result.code_size);
        if (mprotect(call_clone, 4096, PROT_READ | PROT_EXEC) != 0) {
            munmap(call_clone, 4096);
            return 1;
        }
        const pid_t call_child = fork();
        if (call_child == 0) {
            using Call = long (*)(long, long (*)(long));
            const long original = dbi_blr_fixture(5, &dbi_blr_target);
            const long clone_value = reinterpret_cast<Call>(call_clone)(
                5, &dbi_blr_target);
            const uint64_t continuation = call_records[0].expected_return;
            const bool continuation_in_clone =
                continuation >= clone_pc &&
                continuation + 4U <= clone_pc + call_result.code_size;
            const bool good = original == 12 && clone_value == original &&
                call_records[0].hits == 1U &&
                call_records[0].target ==
                    reinterpret_cast<uint64_t>(&dbi_blr_target) &&
                call_records[1].hits == 1U && continuation_in_clone &&
                *reinterpret_cast<const uint32_t *>(continuation) ==
                    rtgum_dbi::detail::b_imm(12U);
            _exit(good ? 0 : 1);
        }
        int call_status = 0;
        if (call_child > 0) waitpid(call_child, &call_status, 0);
        const bool call_ok = call_child > 0 && WIFEXITED(call_status) &&
                             WEXITSTATUS(call_status) == 0;
        std::printf("dbi-blr-far-record distance-mb=%llu literals=%zu "
                    "child-ok=%d\n",
                    static_cast<unsigned long long>(distance >> 20U),
                    call_result.literal_size, call_ok ? 1 : 0);
        munmap(call_clone, 4096);
        if (!call_ok) return 1;
    }
    {
        const uint32_t unknown[] = {
            0xffffffffU, // unallocated
            0xd5080000U, // unsupported system instruction
            0x1e202800U, // SIMD/FP encoding outside the freestanding subset
        };
        unsigned int rejected = 0;
        for (uint32_t word : unknown) {
            uint8_t output[64]{};
            rtgum_dbi::OffsetMapEntry map[2]{};
            rtgum_dbi::BranchTraceEntry trace[2]{};
            rtgum_dbi::LiteralRange literals[2]{};
            auto check = rtgum_dbi::make_result(output, sizeof(output), map, 2,
                                                trace, 2, literals, 2);
            if (!rtgum_dbi::Relocator::relocate(&word, sizeof(word), 0x10000U,
                                                0x20000U, check) &&
                check.unsupported &&
                check.reject.reason == rtgum_dbi::RejectReason::UnknownEncoding &&
                check.reject.opcode == word)
                ++rejected;
        }
        uint32_t auth_return = 0xd65f0bffU;
        uint8_t output[64]{};
        rtgum_dbi::OffsetMapEntry map[2]{};
        rtgum_dbi::BranchTraceEntry trace[2]{};
        rtgum_dbi::LiteralRange literals[2]{};
        auto check = rtgum_dbi::make_result(output, sizeof(output), map, 2,
                                            trace, 2, literals, 2);
        const bool pac_return = rtgum_dbi::Relocator::relocate(
            &auth_return, sizeof(auth_return), 0x10000U, 0x20000U, check) &&
            check.trace_size == 1U &&
            check.trace[0].kind == rtgum_dbi::InstrKind::PacReturn;
        std::printf("dbi-strict unknown-rejected=%u/3 pac-return-traced=%u\n",
                    rejected, pac_return ? 1U : 0U);
        if (rejected != 3U || !pac_return) return 1;
    }
    if (!dbi_test_custom_personality_clone()) return 1;
    std::puts("stage1-dbi-lab PASS");
    return 0;
#endif
}

int command_hwbp_capacity_test(const char *key)
{
#if !defined(__aarch64__)
    (void)key;
    return 1;
#else
    const unsigned long addresses[] = {
        reinterpret_cast<unsigned long>(&hwbp_target),
        reinterpret_cast<unsigned long>(&hwbp_capacity_target1),
        reinterpret_cast<unsigned long>(&hwbp_capacity_target2),
        reinterpret_cast<unsigned long>(&hwbp_capacity_target3),
        reinterpret_cast<unsigned long>(&hwbp_capacity_target4),
        reinterpret_cast<unsigned long>(&hwbp_capacity_target5),
        reinterpret_cast<unsigned long>(&hwbp_capacity_target6),
    };
    unsigned long handles[6]{};
    char command[128];
    char response[kControlBufferSize];
    auto clear = [&](unsigned int index) {
        if (handles[index] == 0UL) return true;
        std::snprintf(command, sizeof(command), "hwbp-clear %lu", handles[index]);
        const bool ok = control(key, command, response, sizeof(response)) == 0 &&
                        std::strncmp(response, "ok ", 3) == 0;
        handles[index] = 0;
        return ok;
    };
    bool success = true;
    for (unsigned int index = 0; index < 6U; ++index) {
        std::snprintf(command, sizeof(command), "hwbp-set 0x%lx 0", addresses[index]);
        if (control(key, command, response, sizeof(response)) != 0 ||
            std::sscanf(response, "ok handle=%lu", &handles[index]) != 1 ||
            handles[index] == 0UL) {
            std::fprintf(stderr, "HWBP slot %u registration failed: %s\n", index, response);
            success = false;
            break;
        }
    }
    if (success) {
        std::snprintf(command, sizeof(command), "hwbp-set 0x%lx 0", addresses[6]);
        const bool sent = control(key, command, response, sizeof(response)) == 0;
        const bool at_capacity = sent &&
            std::strncmp(response, "error=hwbp-set-failed code=-28",
                         std::strlen("error=hwbp-set-failed code=-28")) == 0;
        if (!at_capacity) {
            std::fprintf(stderr, "seventh HWBP did not fail at capacity: %s\n", response);
            unsigned long extra = 0;
            if (std::sscanf(response, "ok handle=%lu", &extra) == 1 && extra != 0UL) {
                std::snprintf(command, sizeof(command), "hwbp-clear %lu", extra);
                control(key, command, response, sizeof(response));
            }
            success = false;
        }
    }
    if (success && !clear(2U)) success = false;
    if (success) {
        std::snprintf(command, sizeof(command), "hwbp-set 0x%lx 0", addresses[6]);
        if (control(key, command, response, sizeof(response)) != 0 ||
            std::sscanf(response, "ok handle=%lu", &handles[2]) != 1 ||
            handles[2] == 0UL) {
            std::fprintf(stderr, "HWBP slot reuse failed: %s\n", response);
            success = false;
        }
    }
    for (unsigned int index = 0; index < 6U; ++index)
        if (!clear(index)) success = false;
    if (!success) return 1;
    std::puts("slots=6 seventh=-ENOSPC reused=1 cleared=6");
    std::puts("stage1-hwbp-capacity-test PASS");
    return 0;
#endif
}

int verify_art_shadow_fork(const char *key)
{
    char response[kControlBufferSize]{};
    char command[128]{};
    if (control(key, "hook-art-shadow", response, sizeof(response)) != 0 ||
        std::strstr(response, "ok art_shadow=1") == nullptr) {
        std::fprintf(stderr, "fork ART shadow hook install failed: %s\n", response);
        return 1;
    }
    void *mapping = mmap(nullptr, 8192, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) {
        std::perror("fork ART shadow mmap");
        return 1;
    }
    const unsigned long inherited = reinterpret_cast<unsigned long>(mapping);
    const unsigned long local_only = inherited + 4096UL;
    constexpr unsigned long kOriginal = 0x1122334455667788UL;
    constexpr unsigned long kParentPatch = 0x8877665544332211UL;
    constexpr unsigned long kChildPatch = 0xa5a55a5af0f00f0fUL;
    constexpr unsigned long kLocalOriginal = 0x0102030405060708UL;
    constexpr unsigned long kLocalPatch = 0x8070605040302010UL;
    *reinterpret_cast<volatile unsigned long *>(inherited) = kOriginal;
    *reinterpret_cast<volatile unsigned long *>(local_only) = kLocalOriginal;

    const auto request = [&](const char *text, const char *needle) {
        return control(key, text, response, sizeof(response)) == 0 &&
               std::strstr(response, needle) != nullptr;
    };
    std::snprintf(command, sizeof(command), "shadow-register 0x%lx", inherited);
    bool inherited_registered = request(command, "ok page=");
    std::snprintf(command, sizeof(command), "shadow-register 0x%lx", local_only);
    bool local_registered = request(command, "ok page=");
    if (!inherited_registered || !local_registered) {
        std::fprintf(stderr, "fork ART shadow register failed: %s\n", response);
        if (inherited_registered) {
            std::snprintf(command, sizeof(command),
                          "shadow-unregister 0x%lx", inherited);
            (void)control(key, command, response, sizeof(response));
        }
        if (local_registered) {
            std::snprintf(command, sizeof(command),
                          "shadow-unregister 0x%lx", local_only);
            (void)control(key, command, response, sizeof(response));
        }
        munmap(mapping, 8192);
        return 1;
    }
    struct ArtChildReport {
        unsigned long inherited_before;
        unsigned long inherited_after;
        unsigned long direct_inherited;
        unsigned long direct_local;
        unsigned int local_registry_absent;
    } report{};
    std::snprintf(command, sizeof(command),
                  "shadow-patch 0x%lx 0 0x%lx", inherited, kParentPatch);
    if (!request(command, "ok page=")) goto fail;
    std::snprintf(command, sizeof(command),
                  "shadow-patch 0x%lx 0 0x%lx", local_only, kLocalPatch);
    if (!request(command, "ok page=")) goto fail;
    std::snprintf(command, sizeof(command),
                  "art-shadow-fork-policy 0x%lx 1", inherited);
    if (!request(command, "fork=1")) goto fail;

    int report_pipe[2];
    if (pipe(report_pipe) != 0) goto fail;
    {
        const pid_t child = fork();
        if (child < 0) {
            close(report_pipe[0]);
            close(report_pipe[1]);
            goto fail;
        }
        if (child == 0) {
            close(report_pipe[0]);
            int status = 0;
            unsigned long page = 0;
            unsigned long offset = 0;
            std::snprintf(command, sizeof(command),
                          "shadow-read 0x%lx 0", inherited);
            if (control(key, command, response, sizeof(response)) != 0 ||
                std::sscanf(response,
                            "ok page=0x%lx offset=0x%lx value=0x%lx",
                            &page, &offset, &report.inherited_before) != 3 ||
                report.inherited_before != kParentPatch)
                status = 41;
            std::snprintf(command, sizeof(command),
                          "shadow-patch 0x%lx 0 0x%lx", inherited,
                          kChildPatch);
            if (status == 0 &&
                (control(key, command, response, sizeof(response)) != 0 ||
                 std::strstr(response, "ok page=") == nullptr))
                status = 42;
            std::snprintf(command, sizeof(command),
                          "shadow-read 0x%lx 0", inherited);
            if (status == 0 &&
                (control(key, command, response, sizeof(response)) != 0 ||
                 std::sscanf(response,
                             "ok page=0x%lx offset=0x%lx value=0x%lx",
                             &page, &offset, &report.inherited_after) != 3 ||
                 report.inherited_after != kChildPatch))
                status = 43;
            report.direct_inherited =
                *reinterpret_cast<volatile unsigned long *>(inherited);
            report.direct_local =
                *reinterpret_cast<volatile unsigned long *>(local_only);
            std::snprintf(command, sizeof(command),
                          "shadow-read 0x%lx 0", local_only);
            if (control(key, command, response, sizeof(response)) == 0 &&
                std::strcmp(response,
                            "error=shadow-read-failed code=-2") == 0)
                report.local_registry_absent = 1U;
            else if (status == 0)
                status = 44;
            if (status == 0 &&
                (report.direct_inherited != kOriginal ||
                 report.direct_local != kLocalOriginal))
                status = 45;
            if (write(report_pipe[1], &report, sizeof(report)) !=
                static_cast<ssize_t>(sizeof(report)))
                status = 46;
            close(report_pipe[1]);
            _exit(status);
        }
        close(report_pipe[1]);
        const ssize_t bytes = read(report_pipe[0], &report, sizeof(report));
        close(report_pipe[0]);
        int child_status = 0;
        if (waitpid(child, &child_status, 0) != child ||
            bytes != static_cast<ssize_t>(sizeof(report)) ||
            !WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0) {
            std::fprintf(stderr,
                         "fork ART shadow child failed status=%d bytes=%zd\n",
                         child_status, bytes);
            goto fail;
        }
    }

    {
        unsigned long page = 0;
        unsigned long offset = 0;
        unsigned long parent_shadow = 0;
        std::snprintf(command, sizeof(command),
                      "shadow-read 0x%lx 0", inherited);
        if (control(key, command, response, sizeof(response)) != 0 ||
            std::sscanf(response,
                        "ok page=0x%lx offset=0x%lx value=0x%lx",
                        &page, &offset, &parent_shadow) != 3 ||
            parent_shadow != kParentPatch ||
            *reinterpret_cast<volatile unsigned long *>(inherited) != kOriginal ||
            report.inherited_before != kParentPatch ||
            report.inherited_after != kChildPatch ||
            report.local_registry_absent != 1U) {
            std::fprintf(stderr, "fork ART shadow parent isolation failed\n");
            goto fail;
        }
    }

    std::snprintf(command, sizeof(command),
                  "shadow-unregister 0x%lx", inherited);
    if (!request(command, "unregistered")) goto fail;
    inherited_registered = false;
    std::snprintf(command, sizeof(command),
                  "shadow-unregister 0x%lx", local_only);
    if (!request(command, "unregistered")) goto fail;
    local_registered = false;
    munmap(mapping, 8192);
    (void)control(key, "unhook-art-shadow", response, sizeof(response));
    std::puts("art-shadow-fork propagate=1 private-shadow=1 unmarked-clean=1 parent-isolated=1");
    return 0;

fail:
    if (inherited_registered) {
        std::snprintf(command, sizeof(command),
                      "shadow-unregister 0x%lx", inherited);
        (void)control(key, command, response, sizeof(response));
    }
    if (local_registered) {
        std::snprintf(command, sizeof(command),
                      "shadow-unregister 0x%lx", local_only);
        (void)control(key, command, response, sizeof(response));
    }
    munmap(mapping, 8192);
    (void)control(key, "unhook-art-shadow", response, sizeof(response));
    return 1;
}

#if defined(__aarch64__)
using ForkCodeFunction = long (*)();

struct CodeShadowForkRaceContext final {
    ForkCodeFunction inherited = nullptr;
    ForkCodeFunction local_only = nullptr;
    std::atomic<bool> *go = nullptr;
    std::atomic<unsigned int> *failures = nullptr;
};

void *code_shadow_fork_race_worker(void *opaque)
{
    auto &context = *static_cast<CodeShadowForkRaceContext *>(opaque);
    while (!context.go->load(std::memory_order_acquire)) sched_yield();
    const pid_t child = fork();
    if (child == 0) {
        const long inherited = context.inherited();
        const long local_only = context.local_only();
        _exit(inherited == 42L && local_only == 5L ? 0 : 61);
    }
    int status = 0;
    if (child < 0 || waitpid(child, &status, 0) != child ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        context.failures->fetch_add(1U, std::memory_order_relaxed);
    return nullptr;
}
#endif

int verify_code_shadow_fork(const char *key)
{
#if !defined(__aarch64__)
    (void)key;
    return 1;
#else
    char response[kControlBufferSize]{};
    char command[160]{};
    const long pid = static_cast<long>(getpid());
    void *mapping = mmap(nullptr, 8192U, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) return 1;
    const unsigned long inherited = reinterpret_cast<unsigned long>(mapping);
    const unsigned long local_only = inherited + 4096UL;
    auto *first = reinterpret_cast<std::uint32_t *>(inherited);
    auto *second = reinterpret_cast<std::uint32_t *>(local_only);
    /* mov x0,#3/5; ret */
    first[0] = 0xd2800060U;
    first[1] = 0xd65f03c0U;
    second[0] = 0xd28000a0U;
    second[1] = 0xd65f03c0U;
    __builtin___clear_cache(reinterpret_cast<char *>(mapping),
                            reinterpret_cast<char *>(mapping) + 8192U);
    if (mprotect(mapping, 8192U, PROT_READ | PROT_EXEC) != 0) {
        munmap(mapping, 8192U);
        return 1;
    }
    auto inherited_fn = reinterpret_cast<ForkCodeFunction>(inherited);
    auto local_fn = reinterpret_cast<ForkCodeFunction>(local_only);
    unsigned char inherited_original[8]{};
    unsigned char local_original[8]{};
    std::memcpy(inherited_original, reinterpret_cast<void *>(inherited), 8U);
    std::memcpy(local_original, reinterpret_cast<void *>(local_only), 8U);
    bool hook_enabled = false;
    bool inherited_installed = false;
    bool local_installed = false;
    const auto request = [&](const char *text, const char *needle) {
        return control(key, text, response, sizeof(response)) == 0 &&
               std::strstr(response, needle) != nullptr;
    };
    const auto cleanup = [&]() {
        if (inherited_installed) {
            std::snprintf(command, sizeof(command),
                          "shadow-release %ld 0x%lx", pid, inherited);
            (void)control(key, command, response, sizeof(response));
        }
        if (local_installed) {
            std::snprintf(command, sizeof(command),
                          "shadow-release %ld 0x%lx", pid, local_only);
            (void)control(key, command, response, sizeof(response));
        }
        if (hook_enabled)
            (void)control(key, "unhook-shadow-hook", response, sizeof(response));
        munmap(mapping, 8192U);
    };
    if (inherited_fn() != 3L || local_fn() != 5L ||
        !request("hook-shadow-hook", "ok shadowhook=1")) {
        cleanup();
        return 1;
    }
    hook_enabled = true;
    std::snprintf(command, sizeof(command), "shadow-install %ld 0x%lx",
                  pid, inherited);
    inherited_installed = request(command, "state=shadow-x");
    std::snprintf(command, sizeof(command), "shadow-install %ld 0x%lx",
                  pid, local_only);
    local_installed = request(command, "state=shadow-x");
    if (!inherited_installed || !local_installed) {
        std::fprintf(stderr, "code-shadow fork install failed: %s\n", response);
        cleanup();
        return 1;
    }
    std::snprintf(command, sizeof(command),
                  "shadow-code-patch %ld 0x%lx %s", pid, inherited,
                  kShadowReplacePatch);
    if (!request(command, "ok pid=")) {
        cleanup();
        return 1;
    }
    std::snprintf(command, sizeof(command),
                  "shadow-code-patch %ld 0x%lx 600580d2c0035fd6", pid,
                  local_only);
    if (!request(command, "ok pid=")) {
        cleanup();
        return 1;
    }
    std::snprintf(command, sizeof(command),
                  "shadow-fork-policy %ld 0x%lx 1", pid, inherited);
    if (!request(command, "fork=1") || inherited_fn() != 42L ||
        local_fn() != 43L) {
        cleanup();
        return 1;
    }

    const auto fork_info = [&](long target_pid, unsigned long address,
                               unsigned long &shadow_pfn,
                               unsigned long &original_pfn,
                               unsigned int &propagate) {
        unsigned long reported_pid = 0UL;
        unsigned long reported_va = 0UL;
        std::snprintf(command, sizeof(command),
                      "shadow-fork-info %ld 0x%lx", target_pid, address);
        return control(key, command, response, sizeof(response)) == 0 &&
               std::sscanf(response,
                           "ok pid=%lu va=0x%lx shadow-pfn=0x%lx original-pfn=0x%lx fork=%u",
                           &reported_pid, &reported_va, &shadow_pfn,
                           &original_pfn, &propagate) == 5 &&
               reported_pid == static_cast<unsigned long>(target_pid) &&
               reported_va == (address & ~4095UL);
    };
    unsigned long parent_shadow_pfn = 0UL;
    unsigned long parent_original_pfn = 0UL;
    unsigned int parent_propagate = 0U;
    if (!fork_info(pid, inherited, parent_shadow_pfn, parent_original_pfn,
                   parent_propagate) || parent_propagate != 1U) {
        cleanup();
        return 1;
    }

    struct CodeShadowChildReport final {
        long inherited_before = 0;
        long inherited_after = 0;
        long local_result = 0;
        unsigned long shadow_pfn = 0UL;
        unsigned long original_pfn = 0UL;
        unsigned int unmarked_absent = 0U;
        unsigned int clean_reads = 0U;
    } report{};
    int report_pipe[2] = {-1, -1};
    if (pipe(report_pipe) != 0) {
        cleanup();
        return 1;
    }
    const pid_t child = fork();
    if (child == 0) {
        close(report_pipe[0]);
        int status = 0;
        unsigned int propagate = 0U;
        report.inherited_before = inherited_fn();
        report.local_result = local_fn();
        if (report.inherited_before != 42L || report.local_result != 5L)
            status = 62;
        if (status == 0 &&
            (!fork_info(static_cast<long>(getpid()), inherited,
                        report.shadow_pfn, report.original_pfn, propagate) ||
             propagate != 1U || report.shadow_pfn == parent_shadow_pfn))
            status = 63;
        std::snprintf(command, sizeof(command),
                      "shadow-fork-info %ld 0x%lx",
                      static_cast<long>(getpid()), local_only);
        if (control(key, command, response, sizeof(response)) == 0 &&
            std::strcmp(response,
                        "error=shadow-fork-info-failed code=-2") == 0)
            report.unmarked_absent = 1U;
        else if (status == 0)
            status = 64;
        std::snprintf(command, sizeof(command),
                      "shadow-code-patch %ld 0x%lx 800580d2c0035fd6",
                      static_cast<long>(getpid()), inherited);
        if (status == 0 && !request(command, "ok pid=")) status = 65;
        report.inherited_after = inherited_fn();
        if (status == 0 && report.inherited_after != 44L) status = 66;
        unsigned char inherited_read[8]{};
        unsigned char local_read[8]{};
        std::memcpy(inherited_read, reinterpret_cast<void *>(inherited), 8U);
        std::memcpy(local_read, reinterpret_cast<void *>(local_only), 8U);
        if (std::memcmp(inherited_read, inherited_original, 8U) == 0 &&
            std::memcmp(local_read, local_original, 8U) == 0)
            report.clean_reads = 1U;
        else if (status == 0)
            status = 67;
        if (write(report_pipe[1], &report, sizeof(report)) !=
            static_cast<ssize_t>(sizeof(report)))
            status = 68;
        close(report_pipe[1]);
        _exit(status);
    }
    close(report_pipe[1]);
    const ssize_t report_size = child > 0
        ? read(report_pipe[0], &report, sizeof(report)) : -1;
    close(report_pipe[0]);
    int child_status = 0;
    if (child < 0 || waitpid(child, &child_status, 0) != child ||
        report_size != static_cast<ssize_t>(sizeof(report)) ||
        !WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0 ||
        report.unmarked_absent != 1U || report.clean_reads != 1U ||
        inherited_fn() != 42L || local_fn() != 43L) {
        std::fprintf(stderr,
                     "code-shadow fork child failed status=%d report=%zd reply=%s\n",
                     child_status, report_size, response);
        cleanup();
        return 1;
    }

    /* Exercise overlapping copy_mm calls from different parent threads.  The
     * unmarked page must be clean in every child while the marked page remains
     * hooked, and the parent must still have both of its own patches. */
    constexpr unsigned int kRaceThreads = 4U;
    pthread_t threads[kRaceThreads]{};
    std::atomic<bool> go{false};
    std::atomic<unsigned int> failures{0U};
    CodeShadowForkRaceContext race{
        inherited_fn, local_fn, &go, &failures};
    unsigned int created = 0U;
    for (; created < kRaceThreads; ++created) {
        if (pthread_create(&threads[created], nullptr,
                           &code_shadow_fork_race_worker, &race) != 0)
            break;
    }
    if (created != kRaceThreads) failures.fetch_add(1U);
    go.store(true, std::memory_order_release);
    for (unsigned int index = 0U; index < created; ++index)
        pthread_join(threads[index], nullptr);
    if (failures.load(std::memory_order_acquire) != 0U ||
        inherited_fn() != 42L || local_fn() != 43L ||
        control(key, "shadowhook-status", response, sizeof(response)) != 0 ||
        std::strstr(response, "fork-pause-failures=0") == nullptr) {
        std::fprintf(stderr, "code-shadow concurrent fork failed: %s\n", response);
        cleanup();
        return 1;
    }
    cleanup();
    std::printf("code-shadow-fork private-pfn=1 child-repatch-isolated=1 unmarked-clean=1 clean-read=1 concurrent=%u\n",
                kRaceThreads);
    return 0;
#endif
}

#if defined(__aarch64__)
struct HwbpForkWorkerContext final {
    int first = 0;
    int second = 0;
    int observed = 0;
    std::atomic<bool> *go = nullptr;
};

void *hwbp_fork_worker(void *opaque)
{
    auto &context = *static_cast<HwbpForkWorkerContext *>(opaque);
    while (context.go && !context.go->load(std::memory_order_acquire))
        sched_yield();
    context.observed = hwbp_target(context.first, context.second);
    return nullptr;
}
#endif

int verify_hwbp_fork(const char *key)
{
#if !defined(__aarch64__)
    (void)key;
    return 1;
#else
    char response[kControlBufferSize]{};
    char command[160]{};
    unsigned long inherited_handle = 0UL;
    unsigned long local_handle = 0UL;
    const unsigned long inherited_entry =
        reinterpret_cast<unsigned long>(&hwbp_target);
    const unsigned long local_entry =
        reinterpret_cast<unsigned long>(&hwbp_capacity_target1);
    const auto arm = [&](unsigned long entry, unsigned long &handle) {
        std::snprintf(command, sizeof(command), "hwbp-set 0x%lx 0", entry);
        return control(key, command, response, sizeof(response)) == 0 &&
               std::sscanf(response, "ok handle=%lu", &handle) == 1 &&
               handle != 0UL;
    };
    const auto clear = [&](unsigned long handle) {
        if (handle == 0UL) return true;
        std::snprintf(command, sizeof(command), "hwbp-clear %lu", handle);
        return control(key, command, response, sizeof(response)) == 0 &&
               std::strstr(response, "cleared=1") != nullptr;
    };
    const auto cleanup = [&]() {
        const bool first = clear(inherited_handle);
        const bool second = clear(local_handle);
        return first && second;
    };
    if (!arm(inherited_entry, inherited_handle) ||
        !arm(local_entry, local_handle)) {
        cleanup();
        return 1;
    }
    std::snprintf(command, sizeof(command), "hwbp-fork-policy %lu 1 1",
                  inherited_handle);
    if (control(key, command, response, sizeof(response)) != 0 ||
        std::strstr(response, "fork=1 scope=tgid") == nullptr) {
        cleanup();
        return 1;
    }

    struct HwbpForkReport final {
        unsigned long handle = 0UL;
        unsigned int unmarked_absent = 0U;
        unsigned int thread_hit = 0U;
        char snapshot[256]{};
    } report{};
    int report_pipe[2] = {-1, -1};
    if (pipe(report_pipe) != 0) {
        cleanup();
        return 1;
    }
    const pid_t child = fork();
    if (child == 0) {
        close(report_pipe[0]);
        int status = 0;
        std::snprintf(command, sizeof(command), "hwbp-find-current 0x%lx",
                      inherited_entry);
        if (control(key, command, response, sizeof(response)) != 0 ||
            std::sscanf(response, "ok handle=%lu", &report.handle) != 1 ||
            report.handle == 0UL ||
            std::strstr(response, "fork=1 scope=tgid") == nullptr)
            status = 71;
        std::snprintf(command, sizeof(command), "hwbp-find-current 0x%lx",
                      local_entry);
        if (control(key, command, response, sizeof(response)) == 0 &&
            std::strcmp(response,
                        "error=hwbp-find-current-failed code=-2") == 0)
            report.unmarked_absent = 1U;
        else if (status == 0)
            status = 72;
        if (status == 0 && hwbp_target(10, 20) != 30) status = 73;
        constexpr unsigned int kConcurrentThreads = 4U;
        std::atomic<bool> go{false};
        HwbpForkWorkerContext worker_context[kConcurrentThreads]{};
        pthread_t workers[kConcurrentThreads]{};
        unsigned int created = 0U;
        if (status == 0) {
            for (; created < kConcurrentThreads; ++created) {
                worker_context[created].first = static_cast<int>(created + 2U);
                worker_context[created].second = static_cast<int>(created + 3U);
                worker_context[created].go = &go;
                if (pthread_create(&workers[created], nullptr,
                                   &hwbp_fork_worker,
                                   &worker_context[created]) != 0) {
                    status = 74;
                    break;
                }
            }
        }
        go.store(true, std::memory_order_release);
        for (unsigned int index = 0U; index < created; ++index)
            pthread_join(workers[index], nullptr);
        if (status == 0) {
            unsigned int hits = 0U;
            for (unsigned int index = 0U; index < kConcurrentThreads; ++index)
                if (worker_context[index].observed ==
                    worker_context[index].first + worker_context[index].second)
                    ++hits;
            report.thread_hit = hits;
            if (report.thread_hit != kConcurrentThreads) status = 75;
        }
        std::snprintf(command, sizeof(command), "hwbp-snapshot %lu",
                      report.handle);
        if (status == 0 &&
            (control(key, command, report.snapshot,
                     sizeof(report.snapshot)) != 0 ||
             std::strstr(report.snapshot, "entry=5 return=5") == nullptr))
            status = 76;
        if (write(report_pipe[1], &report, sizeof(report)) !=
            static_cast<ssize_t>(sizeof(report)))
            status = 77;
        close(report_pipe[1]);
        _exit(status);
    }
    close(report_pipe[1]);
    const ssize_t report_size = child > 0
        ? read(report_pipe[0], &report, sizeof(report)) : -1;
    close(report_pipe[0]);
    int child_status = 0;
    if (child < 0 || waitpid(child, &child_status, 0) != child ||
        report_size != static_cast<ssize_t>(sizeof(report)) ||
        !WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0 ||
        report.unmarked_absent != 1U || report.thread_hit != 4U) {
        std::fprintf(stderr,
                     "HWBP fork child failed status=%d bytes=%zd snapshot=%s\n",
                     child_status, report_size, report.snapshot);
        cleanup();
        return 1;
    }
    std::snprintf(command, sizeof(command), "hwbp-snapshot %lu",
                  inherited_handle);
    if (control(key, command, response, sizeof(response)) != 0 ||
        std::strstr(response, "entry=0 return=0") == nullptr ||
        control(key, "capabilities", response, sizeof(response)) != 0 ||
        std::strstr(response, "hwbp_active=2") == nullptr) {
        std::fprintf(stderr, "HWBP child polluted parent: %s\n", response);
        cleanup();
        return 1;
    }
    if (hwbp_target(3, 4) != 7) {
        cleanup();
        return 1;
    }
    HwbpForkWorkerContext parent_worker_context{6, 7, 0};
    pthread_t parent_worker{};
    if (pthread_create(&parent_worker, nullptr, &hwbp_fork_worker,
                       &parent_worker_context) != 0) {
        cleanup();
        return 1;
    }
    pthread_join(parent_worker, nullptr);
    std::snprintf(command, sizeof(command), "hwbp-snapshot %lu",
                  inherited_handle);
    if (parent_worker_context.observed != 13 ||
        control(key, command, response, sizeof(response)) != 0 ||
        std::strstr(response, "entry=2 return=2") == nullptr) {
        std::fprintf(stderr, "HWBP tgid thread inheritance failed: %s\n",
                     response);
        cleanup();
        return 1;
    }
    if (hwbp_capacity_target1() != 1) {
        cleanup();
        return 1;
    }
    std::snprintf(command, sizeof(command), "hwbp-snapshot %lu", local_handle);
    if (control(key, command, response, sizeof(response)) != 0 ||
        std::strstr(response, "entry=1 return=1") == nullptr) {
        cleanup();
        return 1;
    }

    /* A propagated rule and the marked Ghost mappings enter the child old mm,
     * then execve must retire both before the replacement image runs. */
    const pid_t exec_child = fork();
    if (exec_child == 0) {
        execl("/system/bin/true", "true", static_cast<char *>(nullptr));
        execl("/system/bin/toybox", "toybox", "true",
              static_cast<char *>(nullptr));
        _exit(127);
    }
    int exec_status = 0;
    if (exec_child < 0 || waitpid(exec_child, &exec_status, 0) != exec_child ||
        !WIFEXITED(exec_status) || WEXITSTATUS(exec_status) != 0 ||
        control(key, "capabilities", response, sizeof(response)) != 0 ||
        std::strstr(response, "active=3") == nullptr ||
        std::strstr(response, "hwbp_active=2") == nullptr) {
        std::fprintf(stderr, "fork exec cleanup failed status=%d: %s\n",
                     exec_status, response);
        cleanup();
        return 1;
    }
    if (!cleanup()) return 1;
    std::puts("hwbp-fork cloned-hit=1 tgid-thread=1 tgid-concurrent=4 unmarked-absent=1 parent-isolated=1 exec-cleanup=1");
    return 0;
#endif
}

int command_fork_test(const char *key)
{
    char response[kControlBufferSize];
    char command[128];
    unsigned long executable = 0;
    unsigned long private_data = 0;
    unsigned long unmarked = 0;
    unsigned long size = 0;
    unsigned long protection = 0;
    long kernel_pid = -1;

    const auto allocate = [&](unsigned long &address) {
        if (control(key, "ghost-alloc 4096 3", response, sizeof(response)) != 0)
            return false;
        return std::sscanf(response,
                           "ok address=0x%lx size=%lu prot=%lu pid=%ld",
                           &address, &size, &protection, &kernel_pid) == 4 &&
               address != 0 && size == 4096 && protection == 3;
    };
    const auto cleanup = [&]() {
        int result = 0;
        if (executable != 0) result |= ghost_cleanup(key, executable);
        if (private_data != 0) result |= ghost_cleanup(key, private_data);
        if (unmarked != 0) result |= ghost_cleanup(key, unmarked);
        return result;
    };
    const auto set_policy = [&](unsigned long address) {
        std::snprintf(command, sizeof(command),
                      "ghost-fork-policy 0x%lx 1", address);
        return control(key, command, response, sizeof(response)) == 0 &&
               std::strstr(response, "fork=1") != nullptr;
    };
    const auto fork_info = [&](unsigned long address, unsigned long &pfn) {
        unsigned long reported = 0;
        unsigned int propagate = 0;
        long pid = -1;
        std::snprintf(command, sizeof(command),
                      "ghost-fork-info 0x%lx", address);
        if (control(key, command, response, sizeof(response)) != 0 ||
            std::sscanf(response,
                        "ok address=0x%*lx pfn=0x%lx fork=%u pid=%ld",
                        &reported, &propagate, &pid) != 3 ||
            reported == 0 || propagate != 1U)
            return false;
        pfn = reported;
        return true;
    };

    if (!allocate(executable) || !allocate(private_data) || !allocate(unmarked)) {
        std::fprintf(stderr, "fork-test allocation failed: %s\n", response);
        cleanup();
        return 1;
    }

    auto *instructions = reinterpret_cast<volatile std::uint32_t *>(executable);
    instructions[0] = 0x52824680U;
    instructions[1] = 0xd65f03c0U;
    constexpr unsigned long long kParentMagic = 0x504152454e543031ULL;
    constexpr unsigned long long kChildMagic = 0x4348494c44303121ULL;
    constexpr unsigned long long kUnmarkedMagic = 0x554e4d41524b4544ULL;
    *reinterpret_cast<volatile unsigned long long *>(private_data) = kParentMagic;
    *reinterpret_cast<volatile unsigned long long *>(unmarked) = kUnmarkedMagic;
    if (!set_policy(executable) || !set_policy(private_data)) {
        cleanup();
        return 1;
    }
    std::snprintf(command, sizeof(command), "ghost-protect 0x%lx 5", executable);
    if (control(key, command, response, sizeof(response)) != 0 ||
        std::strncmp(response, "ok ", 3) != 0) {
        cleanup();
        return 1;
    }

    unsigned long parent_exec_pfn = 0;
    unsigned long parent_data_pfn = 0;
    if (!fork_info(executable, parent_exec_pfn) ||
        !fork_info(private_data, parent_data_pfn)) {
        std::fprintf(stderr, "parent fork metadata unavailable: %s\n", response);
        cleanup();
        return 1;
    }

    using TestFunction = int (*)();
    auto test_function = reinterpret_cast<TestFunction>(executable);
    struct ChildReport {
        unsigned long exec_pfn;
        unsigned long data_pfn;
        unsigned long long before;
        unsigned long long after;
        unsigned int unmarked_absent;
    } report{};
    int report_pipe[2] = {-1, -1};
    if (pipe(report_pipe) != 0) {
        std::perror("fork report pipe");
        cleanup();
        return 1;
    }
    const pid_t child = fork();
    if (child < 0) {
        std::fprintf(stderr, "fork failed: %s\n", std::strerror(errno));
        close(report_pipe[0]);
        close(report_pipe[1]);
        cleanup();
        return 1;
    }
    if (child == 0) {
        close(report_pipe[0]);
        char matched[512]{};
        unsigned char residency = 0;
        int status = 0;
        if (range_file_contains("/proc/self/maps", executable, matched,
                                sizeof(matched))) status = 21;
        errno = 0;
        if (status == 0 &&
            (mincore(reinterpret_cast<void *>(executable), size, &residency) == 0 ||
             errno != ENOMEM))
            status = 22;
        if (status == 0 && test_function() != 0x1234) status = 23;
        if (status == 0 && !fork_info(executable, report.exec_pfn)) status = 24;
        if (status == 0 && !fork_info(private_data, report.data_pfn)) status = 25;
        report.before = *reinterpret_cast<volatile unsigned long long *>(private_data);
        if (status == 0 && report.before != kParentMagic) status = 26;
        *reinterpret_cast<volatile unsigned long long *>(private_data) = kChildMagic;
        report.after = *reinterpret_cast<volatile unsigned long long *>(private_data);
        if (status == 0 && report.after != kChildMagic) status = 27;
        std::snprintf(command, sizeof(command),
                      "ghost-fork-info 0x%lx", unmarked);
        if (control(key, command, response, sizeof(response)) == 0 &&
            std::strcmp(response,
                        "error=ghost-fork-info-failed code=-2") == 0)
            report.unmarked_absent = 1U;
        else if (status == 0)
            status = 28;
        if (status == 0 &&
            (report.exec_pfn == parent_exec_pfn ||
             report.data_pfn == parent_data_pfn))
            status = 29;
        if (write(report_pipe[1], &report, sizeof(report)) !=
            static_cast<ssize_t>(sizeof(report)))
            status = 30;
        close(report_pipe[1]);
        _exit(status);
    }
    close(report_pipe[1]);
    const ssize_t report_bytes = read(report_pipe[0], &report, sizeof(report));
    close(report_pipe[0]);

    int child_status = 0;
    if (waitpid(child, &child_status, 0) != child) {
        std::fprintf(stderr, "waitpid failed: %s\n", std::strerror(errno));
        cleanup();
        return 1;
    }
    if (report_bytes != static_cast<ssize_t>(sizeof(report)) ||
        !WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0) {
        std::fprintf(stderr,
                     "fork child failed: raw-status=%d exited=%d code=%d report=%zd\n",
                     child_status,
                     WIFEXITED(child_status) ? 1 : 0,
                     WIFEXITED(child_status) ? WEXITSTATUS(child_status) : -1,
                     report_bytes);
        cleanup();
        return 1;
    }
    if (test_function() != 0x1234 ||
        *reinterpret_cast<volatile unsigned long long *>(private_data) !=
            kParentMagic ||
        report.before != kParentMagic || report.after != kChildMagic ||
        report.unmarked_absent != 1U ||
        report.exec_pfn == parent_exec_pfn ||
        report.data_pfn == parent_data_pfn) {
        std::fprintf(stderr, "parent/child ghost isolation failed\n");
        cleanup();
        return 1;
    }
    if (control(key, "capabilities", response, sizeof(response)) != 0 ||
        std::strstr(response, "active=3") == nullptr) {
        std::fprintf(stderr, "child exit cleanup count mismatch: %s\n", response);
        cleanup();
        return 1;
    }
    if (control(key, "fork-status", response, sizeof(response)) != 0 ||
        std::strstr(response, "ghost-private=1") == nullptr ||
        std::strstr(response, "rolled-back=0") == nullptr) {
        std::fprintf(stderr, "fork transaction status mismatch: %s\n", response);
        cleanup();
        return 1;
    }
    if (verify_art_shadow_fork(key) != 0) {
        cleanup();
        return 1;
    }
    if (verify_code_shadow_fork(key) != 0) {
        cleanup();
        return 1;
    }
    if (verify_hwbp_fork(key) != 0) {
        cleanup();
        return 1;
    }
    unsigned long long hwbp_sync_queued = 0ULL;
    unsigned long long hwbp_sync_run = 0ULL;
    unsigned long long hwbp_sync_fail = 0ULL;
    if (control(key, "fork-status", response, sizeof(response)) != 0) {
        std::fprintf(stderr, "HWBP first-resume status failed: %s\n", response);
        cleanup();
        return 1;
    }
    const char *hwbp_sync = std::strstr(response, "hwbp-sync-queued=");
    if (!hwbp_sync ||
        std::sscanf(hwbp_sync,
                    "hwbp-sync-queued=%llu hwbp-sync-run=%llu hwbp-sync-fail=%llu",
                    &hwbp_sync_queued, &hwbp_sync_run,
                    &hwbp_sync_fail) != 3 ||
        hwbp_sync_queued == 0ULL || hwbp_sync_run != hwbp_sync_queued ||
        hwbp_sync_fail != 0ULL) {
        std::fprintf(stderr, "HWBP first-resume sync failed: %s\n", response);
        cleanup();
        return 1;
    }
    unsigned long long hwbp_thread_queued = 0ULL;
    unsigned long long hwbp_thread_run = 0ULL;
    unsigned long long hwbp_thread_fail = 0ULL;
    const char *hwbp_thread = std::strstr(response, "hwbp-thread-queued=");
    if (!hwbp_thread ||
        std::sscanf(hwbp_thread,
                    "hwbp-thread-queued=%llu hwbp-thread-run=%llu hwbp-thread-fail=%llu",
                    &hwbp_thread_queued, &hwbp_thread_run,
                    &hwbp_thread_fail) != 3 ||
        hwbp_thread_queued == 0ULL ||
        hwbp_thread_run != hwbp_thread_queued ||
        hwbp_thread_fail != 0ULL ||
        std::strstr(response, "hwbp-thread-states=0") == nullptr) {
        std::fprintf(stderr, "HWBP thread first-resume sync failed: %s\n",
                     response);
        cleanup();
        return 1;
    }
    if (cleanup() != 0) return 1;

    std::printf("fork-clone verified parent=%ld child=%ld exec=0x%lx data=0x%lx parent-pfn=0x%lx/0x%lx child-pfn=0x%lx/0x%lx\n",
                static_cast<long>(getpid()),
                static_cast<long>(child),
                executable, private_data, parent_exec_pfn, parent_data_pfn,
                report.exec_pfn, report.data_pfn);
    std::puts("child-maps-hidden=1 child-mincore-hidden=1 child-exec=1 private-pfn=1 child-write-isolated=1 unmarked-absent=1 art-shadow-inherit=1 art-shadow-private=1 code-shadow-inherit=1 code-shadow-private=1 hwbp-inherit=1 hwbp-first-resume=1 tgid-thread=1 exec-cleanup=1 exit-cleanup=1 parent-exec=1 freed=1");
    std::puts("stage1-fork-test PASS");
    return 0;
}

int linker_cleanup(const char *key, unsigned long base)
{
    char command[96];
    char response[kControlBufferSize];
    std::snprintf(command, sizeof(command), "unlink 0x%lx", base);
    if (control(key, command, response, sizeof(response)) != 0) return 1;
    if (std::strncmp(response, "ok ", 3) != 0) {
        std::fprintf(stderr, "custom Linker cleanup failed: %s\n", response);
        return 1;
    }
    return 0;
}

struct alignas(8) Arm64BootstrapImage final {
    std::uint32_t instructions[6];
    std::uint64_t target;
};

static_assert(offsetof(Arm64BootstrapImage, target) == 24U,
              "ARM64 bootstrap literal must start at byte 24");
static_assert(sizeof(Arm64BootstrapImage) == 32U, "unexpected ARM64 bootstrap size");

bool invoke_arm64_bootstrap(unsigned long target,
                            unsigned long argument,
                            unsigned long &result)
{
    result = 0;
#if defined(__aarch64__)
    constexpr std::uint32_t instructions[] = {
        0xa9bf7bfdU, // stp x29, x30, [sp, #-16]!
        0x910003fdU, // mov x29, sp
        0x58000090U, // ldr x16, #16 (literal at byte 24)
        0xd63f0200U, // blr x16
        0xa8c17bfdU, // ldp x29, x30, [sp], #16
        0xd65f03c0U, // ret
    };
    Arm64BootstrapImage image{};
    std::memcpy(image.instructions, instructions, sizeof(instructions));
    image.target = static_cast<std::uint64_t>(target);

    void *memory = mmap(nullptr,
                        4096,
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS,
                        -1,
                        0);
    if (memory == MAP_FAILED) {
        std::fprintf(stderr, "bootstrap mmap failed: %s\n", std::strerror(errno));
        return false;
    }
    std::memcpy(memory, &image, sizeof(image));
    if (mprotect(memory, 4096, PROT_READ | PROT_EXEC) != 0) {
        std::fprintf(stderr, "bootstrap mprotect failed: %s\n", std::strerror(errno));
        munmap(memory, 4096);
        return false;
    }
    auto *begin = static_cast<char *>(memory);
    __builtin___clear_cache(begin, begin + sizeof(image));
    using Bootstrap = unsigned long (*)(unsigned long);
    result = reinterpret_cast<Bootstrap>(memory)(argument);
    if (munmap(memory, 4096) != 0) {
        std::fprintf(stderr, "bootstrap munmap failed: %s\n", std::strerror(errno));
        return false;
    }
    return true;
#else
    (void)target;
    (void)argument;
    std::fprintf(stderr, "ARM64 bootstrap is only available on AArch64\n");
    return false;
#endif
}

unsigned long call_arm64_ifunc_resolver(unsigned long resolver)
{
    /* Android arm64 API 30+ passes HWCAP and __ifunc_arg_t even when an
     * image-local resolver ignores both arguments. */
    __ifunc_arg_t argument{};
    argument._size = sizeof(argument);
    argument._hwcap = getauxval(AT_HWCAP);
    argument._hwcap2 = getauxval(AT_HWCAP2);
    using Resolver = void *(*)(std::uint64_t, __ifunc_arg_t *);
    return reinterpret_cast<unsigned long>(
        reinterpret_cast<Resolver>(resolver)(argument._hwcap | _IFUNC_ARG_HWCAP,
                                             &argument));
}

struct SharedLibraries final {
    void *handles[32]{};
    char names[32][192]{};
    unsigned int count = 0;
};

void close_shared_libraries(SharedLibraries &libraries)
{
    while (libraries.count != 0U) {
        --libraries.count;
        dlclose(libraries.handles[libraries.count]);
        libraries.handles[libraries.count] = nullptr;
        libraries.names[libraries.count][0] = '\0';
    }
}

bool elf_file_range_valid(std::uint64_t offset,
                          std::uint64_t length,
                          std::uint64_t file_size)
{
    return offset <= file_size && length <= file_size - offset;
}

const unsigned char *elf_virtual_to_file(const unsigned char *file,
                                         std::uint64_t file_size,
                                         const Elf64_Phdr *programs,
                                         unsigned int program_count,
                                         std::uint64_t address,
                                         std::uint64_t length)
{
    for (unsigned int index = 0; index < program_count; ++index) {
        const Elf64_Phdr &program = programs[index];
        if (program.p_type != PT_LOAD || address < program.p_vaddr) continue;
        const std::uint64_t delta = address - program.p_vaddr;
        if (delta <= program.p_filesz && length <= program.p_filesz - delta &&
            elf_file_range_valid(program.p_offset + delta, length, file_size))
            return file + program.p_offset + delta;
    }
    return nullptr;
}

bool preload_needed_libraries(const char *path,
                              SharedLibraries &libraries,
                              unsigned int &loaded)
{
    loaded = 0;
    const int descriptor = open(path, O_RDONLY | O_CLOEXEC);
    if (descriptor < 0) {
        std::fprintf(stderr, "cannot open ELF for DT_NEEDED preflight: %s\n", std::strerror(errno));
        return false;
    }
    struct stat metadata {};
    if (fstat(descriptor, &metadata) != 0 || metadata.st_size <= 0 ||
        static_cast<unsigned long long>(metadata.st_size) > 16ULL * 1024ULL * 1024ULL) {
        std::fprintf(stderr, "invalid ELF size during DT_NEEDED preflight\n");
        close(descriptor);
        return false;
    }
    const auto file_size = static_cast<std::uint64_t>(metadata.st_size);
    void *mapping = mmap(nullptr,
                         static_cast<std::size_t>(file_size),
                         PROT_READ,
                         MAP_PRIVATE,
                         descriptor,
                         0);
    if (mapping == MAP_FAILED) {
        std::fprintf(stderr, "ELF preflight mmap failed: %s\n", std::strerror(errno));
        close(descriptor);
        return false;
    }
    const auto finish_file = [&]() {
        munmap(mapping, static_cast<std::size_t>(file_size));
        close(descriptor);
    };
    const auto *file = static_cast<const unsigned char *>(mapping);
    if (!elf_file_range_valid(0, sizeof(Elf64_Ehdr), file_size)) {
        finish_file();
        return false;
    }
    const auto *header = reinterpret_cast<const Elf64_Ehdr *>(file);
    if (std::memcmp(header->e_ident, ELFMAG, SELFMAG) != 0 ||
        header->e_ident[EI_CLASS] != ELFCLASS64 ||
        header->e_ident[EI_DATA] != ELFDATA2LSB || header->e_type != ET_DYN ||
        header->e_machine != EM_AARCH64 || header->e_phentsize != sizeof(Elf64_Phdr) ||
        header->e_phnum == 0U ||
        !elf_file_range_valid(header->e_phoff,
                              static_cast<std::uint64_t>(header->e_phnum) * sizeof(Elf64_Phdr),
                              file_size)) {
        std::fprintf(stderr, "invalid AArch64 ET_DYN during DT_NEEDED preflight\n");
        finish_file();
        return false;
    }
    const auto *programs = reinterpret_cast<const Elf64_Phdr *>(file + header->e_phoff);
    const Elf64_Phdr *dynamic_program = nullptr;
    for (unsigned int index = 0; index < header->e_phnum; ++index) {
        if (programs[index].p_type == PT_DYNAMIC) dynamic_program = &programs[index];
    }
    if (!dynamic_program ||
        !elf_file_range_valid(dynamic_program->p_offset, dynamic_program->p_filesz, file_size) ||
        dynamic_program->p_filesz < sizeof(Elf64_Dyn)) {
        std::fprintf(stderr, "ELF has no valid PT_DYNAMIC segment\n");
        finish_file();
        return false;
    }

    std::uint64_t string_address = 0;
    std::uint64_t string_size = 0;
    std::uint64_t needed_offsets[32]{};
    unsigned int needed_count = 0;
    const auto *dynamic = reinterpret_cast<const Elf64_Dyn *>(file + dynamic_program->p_offset);
    const std::uint64_t dynamic_count = dynamic_program->p_filesz / sizeof(Elf64_Dyn);
    for (std::uint64_t index = 0; index < dynamic_count; ++index) {
        if (dynamic[index].d_tag == DT_NULL) break;
        if (dynamic[index].d_tag == DT_STRTAB)
            string_address = dynamic[index].d_un.d_ptr;
        else if (dynamic[index].d_tag == DT_STRSZ)
            string_size = dynamic[index].d_un.d_val;
        else if (dynamic[index].d_tag == DT_NEEDED) {
            if (needed_count >= 32U) {
                std::fprintf(stderr, "too many DT_NEEDED entries\n");
                finish_file();
                return false;
            }
            needed_offsets[needed_count++] = dynamic[index].d_un.d_val;
        }
    }
    const unsigned char *strings = string_address != 0U && string_size != 0U
                                       ? elf_virtual_to_file(file,
                                                             file_size,
                                                             programs,
                                                             header->e_phnum,
                                                             string_address,
                                                             string_size)
                                       : nullptr;
    if (!strings && needed_count != 0U) {
        std::fprintf(stderr, "ELF has no valid dynamic string table\n");
        finish_file();
        return false;
    }

    for (unsigned int index = 0; index < needed_count; ++index) {
        const std::uint64_t offset = needed_offsets[index];
        if (offset >= string_size) {
            std::fprintf(stderr, "invalid DT_NEEDED string offset\n");
            finish_file();
            close_shared_libraries(libraries);
            return false;
        }
        const char *name = reinterpret_cast<const char *>(strings + offset);
        const std::size_t available = static_cast<std::size_t>(string_size - offset);
        const std::size_t length = strnlen(name, available);
        if (length == 0U || length == available || length >= sizeof(libraries.names[0])) {
            std::fprintf(stderr, "invalid DT_NEEDED library name\n");
            finish_file();
            close_shared_libraries(libraries);
            return false;
        }
        for (std::size_t character = 0; character < length; ++character) {
            const unsigned char value = static_cast<unsigned char>(name[character]);
            if (value <= 0x20U || value == 0x7fU || value == '/' || value == '\\') {
                std::fprintf(stderr, "unsafe DT_NEEDED library name\n");
                finish_file();
                close_shared_libraries(libraries);
                return false;
            }
        }
        dlerror();
        void *handle = dlopen(name, RTLD_NOW | RTLD_LOCAL);
        if (!handle) {
            const char *error = dlerror();
            std::fprintf(stderr,
                         "required DT_NEEDED library is unavailable (%s): %s\n",
                         name,
                         error ? error : "unknown error");
            finish_file();
            close_shared_libraries(libraries);
            return false;
        }
        libraries.handles[libraries.count] = handle;
        std::snprintf(libraries.names[libraries.count],
                      sizeof(libraries.names[libraries.count]),
                      "%s",
                      name);
        ++libraries.count;
        ++loaded;
    }
    finish_file();
    return true;
}

bool register_needed_libraries(const char *key,
                               unsigned long base,
                               unsigned int pending,
                               SharedLibraries &libraries,
                               unsigned int &registered)
{
    registered = 0;
    char command[512];
    char response[kControlBufferSize];
    while (registered < pending) {
        unsigned int token = 0;
        char name[192]{};
        std::snprintf(command, sizeof(command), "needed-next 0x%lx", base);
        if (control(key, command, response, sizeof(response)) != 0 ||
            std::sscanf(response,
                        "ok base=0x%*lx token=%u name=%191s",
                        &token,
                        name) != 2 ||
            token == 0U) {
            std::fprintf(stderr, "DT_NEEDED enumeration failed: %s\n", response);
            return false;
        }
        bool preloaded = false;
        for (unsigned int index = 0; index < libraries.count; ++index) {
            if (std::strcmp(libraries.names[index], name) == 0) {
                preloaded = true;
                break;
            }
        }
        if (!preloaded) {
            std::fprintf(stderr, "KPM reported an un-preloaded DT_NEEDED library: %s\n", name);
            return false;
        }

        std::snprintf(command,
                      sizeof(command),
                      "needed-commit 0x%lx %u",
                      base,
                      token);
        unsigned int remaining = 0;
        unsigned int ready = 0;
        if (control(key, command, response, sizeof(response)) != 0 ||
            std::sscanf(response,
                        "ok base=0x%*lx remaining=%u ready=%u",
                        &remaining,
                        &ready) != 2 ||
            ready > 1U) {
            std::fprintf(stderr, "DT_NEEDED commit failed for %s: %s\n", name, response);
            return false;
        }
        std::printf("registered-needed name=%s remaining=%u\n", name, remaining);
        ++registered;
    }
    return true;
}

void *resolve_external_symbol(const SharedLibraries &libraries, const char *name)
{
    dlerror();
    void *address = dlsym(RTLD_DEFAULT, name);
    if (address) return address;
    for (unsigned int index = 0; index < libraries.count; ++index) {
        dlerror();
        address = dlsym(libraries.handles[index], name);
        if (address) return address;
    }
    return nullptr;
}

bool repair_imports(const char *key,
                    unsigned long base,
                    unsigned int pending,
                    const SharedLibraries &libraries,
                    unsigned int &repaired)
{
    repaired = 0;
    char command[512];
    char response[kControlBufferSize];
    while (repaired < pending) {
        unsigned int token = 0;
        unsigned int weak = 0;
        char name[192]{};
        std::snprintf(command, sizeof(command), "import-next 0x%lx", base);
        if (control(key, command, response, sizeof(response)) != 0 ||
            std::sscanf(response,
                        "ok base=0x%*lx token=%u weak=%u name=%191s",
                        &token,
                        &weak,
                        name) != 3 ||
            token == 0U || weak > 1U) {
            std::fprintf(stderr, "external import enumeration failed: %s\n", response);
            return false;
        }

        void *resolved = resolve_external_symbol(libraries, name);
        if (!resolved && weak == 0U) {
            std::fprintf(stderr, "required external import is unavailable: %s\n", name);
            return false;
        }
        const auto target = reinterpret_cast<unsigned long>(resolved);
        std::snprintf(command,
                      sizeof(command),
                      "import-commit 0x%lx %u 0x%lx",
                      base,
                      token,
                      target);
        unsigned int remaining = 0;
        unsigned int ready = 0;
        if (control(key, command, response, sizeof(response)) != 0 ||
            std::sscanf(response,
                        "ok base=0x%*lx remaining=%u ready=%u",
                        &remaining,
                        &ready) != 2 ||
            ready > 1U) {
            std::fprintf(stderr, "external import commit failed for %s: %s\n", name, response);
            return false;
        }
        std::printf("resolved-import name=%s weak=%u target=0x%lx remaining=%u\n",
                    name,
                    weak,
                    target,
                    remaining);
        ++repaired;
    }
    return true;
}

int command_linker_test(const char *key)
{
    constexpr const char *payload = "/data/local/tmp/rtgum-stage1-pixel8/rtgum-stage1-payload.so";
    char command[512];
    char response[kControlBufferSize];
    char matched[512]{};
    unsigned long base = 0;
    unsigned long entry = 0;
    unsigned long size = 0;
    unsigned int relocations = 0;
    unsigned int needed = 0;
    unsigned int imports = 0;
    unsigned int pending = 0;
    unsigned int ready = 0;

    std::snprintf(command, sizeof(command), "link %s ghost_linker_probe", payload);
    if (control(key, command, response, sizeof(response)) != 0) return 1;
    if (std::sscanf(response,
                    "ok base=0x%lx entry=0x%lx size=%lu relocations=%u needed_pending=%u imports_pending=%u ifunc_pending=%u ready=%u",
                    &base,
                    &entry,
                    &size,
                    &relocations,
                    &needed,
                    &imports,
                    &pending,
                    &ready) != 8 ||
        needed != 0U || imports != 0U ||
        base == 0 || size == 0 || (pending == 0U && (entry < base || entry >= base + size)) ||
        (pending != 0U && (entry != 0 || ready != 0U)) ||
        (pending == 0U && ready != 1U)) {
        std::fprintf(stderr, "unexpected linker response: %s\n", response);
        if (base != 0) linker_cleanup(key, base);
        return 1;
    }

    auto fail = [&](const char *message) {
        std::fprintf(stderr, "%s\n", message);
        linker_cleanup(key, base);
        return 1;
    };

    if (range_file_contains("/proc/self/maps", base, matched, sizeof(matched)) ||
        range_file_contains("/proc/self/smaps", base, matched, sizeof(matched))) {
        std::fprintf(stderr, "custom-linked image leaked through procfs: %s\n", matched);
        return fail("custom Linker procfs visibility check failed");
    }
    unsigned char residency = 0;
    errno = 0;
    if (mincore(reinterpret_cast<void *>(base), size, &residency) == 0 || errno != ENOMEM) {
        std::fprintf(stderr, "custom-linked image is visible to mincore\n");
        return fail("custom Linker mincore visibility check failed");
    }
    LinkMapSearch link_map_search{"rtgum-stage1-payload.so", false};
    dl_iterate_phdr(&find_link_map_entry, &link_map_search);
    if (link_map_search.found)
        return fail("custom-linked image unexpectedly appeared in dl_iterate_phdr");

    std::snprintf(command, sizeof(command), "lookup 0x%lx ghost_linker_probe", base);
    if (pending != 0U &&
        (control(key, command, response, sizeof(response)) != 0 ||
         std::strcmp(response, "error=lookup-failed code=-16") != 0))
        return fail("private symbol lookup did not block entry before IFUNC repair");

    unsigned int repaired = 0;
    while (pending != 0U) {
        unsigned int token = 0;
        unsigned long resolver = 0;
        std::snprintf(command, sizeof(command), "ifunc-next 0x%lx", base);
        if (control(key, command, response, sizeof(response)) != 0 ||
            std::sscanf(response,
                        "ok base=0x%*lx token=%u resolver=0x%lx",
                        &token,
                        &resolver) != 2 ||
            token == 0 || resolver < base || resolver >= base + size)
            return fail("IFUNC resolver enumeration failed");

        const unsigned long target = call_arm64_ifunc_resolver(resolver);
        if (target < base || target >= base + size)
            return fail("IFUNC resolver returned an out-of-image target");

        std::snprintf(command,
                      sizeof(command),
                      "ifunc-commit 0x%lx %u 0x%lx",
                      base,
                      token,
                      target);
        unsigned int commit_ready = 0;
        if (control(key, command, response, sizeof(response)) != 0 ||
            std::sscanf(response,
                        "ok base=0x%*lx remaining=%u ready=%u",
                        &pending,
                        &commit_ready) != 2 ||
            commit_ready != (pending == 0U ? 1U : 0U))
            return fail("IFUNC resolver commit failed");
        ++repaired;
    }
    if (ready != 0U || repaired == 0U)
        return fail("test image did not exercise deferred IFUNC repair");

    auto lookup = [&](const char *symbol, unsigned long &address, unsigned int &type) {
        unsigned long symbol_size = 0;
        std::snprintf(command, sizeof(command), "lookup 0x%lx %s", base, symbol);
        if (control(key, command, response, sizeof(response)) != 0) return false;
        return std::sscanf(response,
                           "ok base=0x%*lx address=0x%lx size=%lu type=%u",
                           &address,
                           &symbol_size,
                           &type) == 3 &&
               address >= base && address < base + size;
    };

    unsigned long normal_entry = 0;
    unsigned long ifunc_entry = 0;
    unsigned long relocation_entry = 0;
    unsigned long irelative_entry = 0;
    unsigned int normal_type = 0;
    unsigned int ifunc_type = 0;
    unsigned int relocation_type = 0;
    unsigned int irelative_type = 0;
    if (!lookup("ghost_linker_probe", normal_entry, normal_type) ||
        !lookup("ghost_ifunc_probe", ifunc_entry, ifunc_type) ||
        !lookup("ghost_ifunc_relocation_probe", relocation_entry, relocation_type) ||
        !lookup("ghost_irelative_relocation_probe", irelative_entry, irelative_type) ||
        (entry != 0 && normal_entry != entry) || ifunc_type != 10U)
        return fail("private dynamic-symbol lookup failed");

    using ProbeFunction = int (*)(int);
    auto ifunc_probe = reinterpret_cast<ProbeFunction>(ifunc_entry);
    auto relocation_probe = reinterpret_cast<ProbeFunction>(relocation_entry);
    auto irelative_probe = reinterpret_cast<ProbeFunction>(irelative_entry);
    const int argument = 7;
    unsigned long bootstrap_result = 0;
    if (!invoke_arm64_bootstrap(normal_entry,
                                static_cast<unsigned long>(argument),
                                bootstrap_result))
        return fail("ARM64 bootstrap invocation failed");
    const int result = static_cast<int>(bootstrap_result);
    const int ifunc_result = ifunc_probe(argument);
    const int relocation_result = relocation_probe(argument);
    const int irelative_result = irelative_probe(argument);
    if (result != argument + 0x1234 || ifunc_result != argument + 0x2345 ||
        relocation_result != argument + 0x2345 || irelative_result != argument + 0x2345) {
        std::fprintf(stderr,
                     "custom-linked functions returned normal=0x%x ifunc=0x%x relocated=0x%x irelative=0x%x\n",
                     result,
                     ifunc_result,
                     relocation_result,
                     irelative_result);
        return fail("custom-linked function result mismatch");
    }

    /* Linker images are deliberately non-inheritable until the owner opts in
     * (the Zygote bootstrap does this automatically for the Daemon). */
    std::snprintf(command, sizeof(command), "link-fork-policy 0x%lx 1", base);
    if (control(key, command, response, sizeof(response)) != 0 ||
        std::strstr(response, "fork=1") == nullptr)
        return fail("custom Linker fork policy could not be enabled");

    const pid_t child = fork();
    if (child < 0) return fail("custom Linker fork failed");
    if (child == 0) {
        unsigned long child_entry = 0;
        unsigned int child_type = 0;
        char child_match[512]{};
        int status = 0;
        if (!lookup("ghost_ifunc_probe", child_entry, child_type) || child_type != 10U)
            status = 31;
        if (status == 0 &&
            range_file_contains("/proc/self/maps", base, child_match, sizeof(child_match)))
            status = 32;
        if (status == 0 &&
            reinterpret_cast<ProbeFunction>(child_entry)(argument) != argument + 0x2345)
            status = 33;
        _exit(status);
    }
    int child_status = 0;
    if (waitpid(child, &child_status, 0) != child || !WIFEXITED(child_status) ||
        WEXITSTATUS(child_status) != 0)
        return fail("forked custom Linker image or private symbol table failed");
    if (control(key, "capabilities", response, sizeof(response)) != 0 ||
        std::strstr(response, "active=1") == nullptr ||
        std::strstr(response, "busy=1") == nullptr ||
        std::strstr(response, "images=1") == nullptr)
        return fail("forked custom Linker image cleanup count mismatch");

    if (linker_cleanup(key, base) != 0) return 1;

    std::printf("custom-linker verified base=0x%lx entry=0x%lx size=%lu relocations=%u ifunc_repaired=%u result=0x%x\n",
                base,
                normal_entry,
                size,
                relocations,
                repaired,
                result);
    std::puts("pt-load=1 rela=1 ifunc=1 irelative=1 private-dynsym=1 arm64-bootstrap=1 bootstrap-wx=1 fork-registry=1 link-map-hidden=1 maps-hidden=1 smaps-hidden=1 mincore-hidden=1 execute=1 unlinked=1");
    std::puts("stage1-linker-test PASS");
    return 0;
}

int command_real_so_test(const char *key)
{
    constexpr const char *payload =
        "/data/local/tmp/rtgum-stage1-pixel8/libAdaptivePerformanceThermalHeadroom.so";
    constexpr const char *soname = "libAdaptivePerformanceThermalHeadroom.so";
    constexpr const char *export_name =
        "Unity_AdaptivePerformance_ThermalHeadroom_GetPluginCallback";
    char command[512];
    char response[kControlBufferSize];
    char matched[512]{};
    unsigned long base = 0;
    unsigned long entry = 0;
    unsigned long size = 0;
    unsigned int relocations = 0;
    unsigned int needed = 0;
    unsigned int imports = 0;
    unsigned int ifuncs = 0;
    unsigned int ready = 0;
    SharedLibraries libraries{};
    unsigned int preloaded_needed = 0;
    if (!preload_needed_libraries(payload, libraries, preloaded_needed)) return 1;

    std::snprintf(command, sizeof(command), "link %s %s", payload, export_name);
    if (control(key, command, response, sizeof(response)) != 0) {
        close_shared_libraries(libraries);
        return 1;
    }
    if (std::sscanf(response,
                    "ok base=0x%lx entry=0x%lx size=%lu relocations=%u needed_pending=%u imports_pending=%u ifunc_pending=%u ready=%u",
                    &base,
                    &entry,
                    &size,
                    &relocations,
                    &needed,
                    &imports,
                    &ifuncs,
                    &ready) != 8 ||
        base == 0 || size == 0 || needed == 0U || needed != preloaded_needed ||
        imports == 0U || entry != 0 || ready != 0U) {
        std::fprintf(stderr, "unexpected real-SO linker response: %s\n", response);
        if (base != 0) linker_cleanup(key, base);
        close_shared_libraries(libraries);
        return 1;
    }

    auto fail = [&](const char *message) {
        std::fprintf(stderr, "%s\n", message);
        linker_cleanup(key, base);
        close_shared_libraries(libraries);
        return 1;
    };

    if (range_file_contains("/proc/self/maps", base, matched, sizeof(matched)) ||
        range_file_contains("/proc/self/smaps", base, matched, sizeof(matched))) {
        std::fprintf(stderr, "real custom-linked image leaked through procfs: %s\n", matched);
        return fail("real-SO procfs visibility check failed");
    }
    unsigned char residency = 0;
    errno = 0;
    if (mincore(reinterpret_cast<void *>(base), size, &residency) == 0 || errno != ENOMEM)
        return fail("real custom-linked image is visible to mincore");
    LinkMapSearch link_map_search{soname, false};
    dl_iterate_phdr(&find_link_map_entry, &link_map_search);
    if (link_map_search.found)
        return fail("real custom-linked image unexpectedly appeared in dl_iterate_phdr");

    std::snprintf(command, sizeof(command), "lookup 0x%lx %s", base, export_name);
    if (control(key, command, response, sizeof(response)) != 0 ||
        std::strcmp(response, "error=lookup-failed code=-16") != 0)
        return fail("private symbol lookup did not block before import repair");

    std::snprintf(command, sizeof(command), "import-next 0x%lx", base);
    if (control(key, command, response, sizeof(response)) != 0 ||
        std::strcmp(response, "error=import-next-failed code=-16") != 0)
        return fail("external import enumeration was not blocked before DT_NEEDED registration");

    unsigned int needed_registered = 0;
    if (!register_needed_libraries(key, base, needed, libraries, needed_registered) ||
        needed_registered != needed)
        return fail("real-SO DT_NEEDED registration failed");

    unsigned int imports_repaired = 0;
    if (!repair_imports(key, base, imports, libraries, imports_repaired) ||
        imports_repaired != imports)
        return fail("real-SO external import repair failed");

    unsigned int ifuncs_repaired = 0;
    unsigned int pending_ifuncs = ifuncs;
    while (pending_ifuncs != 0U) {
        unsigned int token = 0;
        unsigned long resolver = 0;
        std::snprintf(command, sizeof(command), "ifunc-next 0x%lx", base);
        if (control(key, command, response, sizeof(response)) != 0 ||
            std::sscanf(response,
                        "ok base=0x%*lx token=%u resolver=0x%lx",
                        &token,
                        &resolver) != 2 ||
            token == 0U || resolver < base || resolver >= base + size)
            return fail("real-SO IFUNC enumeration failed");
        const unsigned long target = call_arm64_ifunc_resolver(resolver);
        if (target < base || target >= base + size)
            return fail("real-SO IFUNC resolver returned an out-of-image target");
        std::snprintf(command,
                      sizeof(command),
                      "ifunc-commit 0x%lx %u 0x%lx",
                      base,
                      token,
                      target);
        unsigned int commit_ready = 0;
        if (control(key, command, response, sizeof(response)) != 0 ||
            std::sscanf(response,
                        "ok base=0x%*lx remaining=%u ready=%u",
                        &pending_ifuncs,
                        &commit_ready) != 2 ||
            commit_ready != (pending_ifuncs == 0U ? 1U : 0U))
            return fail("real-SO IFUNC commit failed");
        ++ifuncs_repaired;
    }

    unsigned long symbol_address = 0;
    unsigned long symbol_size = 0;
    unsigned int symbol_type = 0;
    std::snprintf(command, sizeof(command), "lookup 0x%lx %s", base, export_name);
    if (control(key, command, response, sizeof(response)) != 0 ||
        std::sscanf(response,
                    "ok base=0x%*lx address=0x%lx size=%lu type=%u",
                    &symbol_address,
                    &symbol_size,
                    &symbol_type) != 3 ||
        symbol_address < base || symbol_address >= base + size || symbol_type != 2U)
        return fail("real-SO private symbol lookup failed after repair");

    unsigned long callback_address = 0;
    if (!invoke_arm64_bootstrap(symbol_address, 0UL, callback_address))
        return fail("real-SO ARM64 bootstrap invocation failed");
    if (callback_address < base || callback_address >= base + size)
        return fail("real-SO function returned a callback outside the ghost image");

    if (range_file_contains("/proc/self/maps", callback_address, matched, sizeof(matched)) ||
        range_file_contains("/proc/self/smaps", callback_address, matched, sizeof(matched)))
        return fail("real-SO callback address became visible after execution");
    errno = 0;
    if (mincore(reinterpret_cast<void *>(base), size, &residency) == 0 || errno != ENOMEM)
        return fail("real-SO ghost image became visible to mincore after execution");

    if (linker_cleanup(key, base) != 0) {
        close_shared_libraries(libraries);
        return 1;
    }
    if (control(key, "capabilities", response, sizeof(response)) != 0 ||
        std::strstr(response, "active=0") == nullptr ||
        std::strstr(response, "busy=0") == nullptr ||
        std::strstr(response, "images=0") == nullptr) {
        std::fprintf(stderr, "real-SO cleanup count mismatch: %s\n", response);
        close_shared_libraries(libraries);
        return 1;
    }
    close_shared_libraries(libraries);

    std::printf("real-custom-linker verified base=0x%lx size=%lu relocations=%u needed=%u imports=%u ifuncs=%u export=0x%lx callback=0x%lx\n",
                base,
                size,
                relocations,
                needed_registered,
                imports_repaired,
                ifuncs_repaired,
                symbol_address,
                callback_address);
    std::puts("gnu-hash=1 dt-needed=1 external-imports=1 private-dynsym=1 arm64-bootstrap=1 bootstrap-wx=1 link-map-hidden=1 maps-hidden=1 smaps-hidden=1 mincore-hidden=1 function-called=1 unlinked=1");
    std::puts("stage1-real-so-test PASS");
    return 0;
}

enum class NeededFailure {
    None,
    Version,
    AmbiguousMaps,
    FileMismatch,
};

int command_needed_ifunc_test(const char *key,
                              NeededFailure expected_failure = NeededFailure::None)
{
    const char *payload = expected_failure == NeededFailure::Version
        ? "/data/local/tmp/rtgum-stage1-pixel8/rtgum-pixel8-needed-badver.so"
        : "/data/local/tmp/rtgum-stage1-pixel8/rtgum-pixel8-needed-ifunc.so";
    constexpr const char *entry_name = "ghost_needed_ifunc_probe";
    char command[512];
    char response[kControlBufferSize];
    unsigned long base = 0;
    unsigned long entry = 0;
    unsigned long size = 0;
    unsigned int relocations = 0;
    unsigned int needed = 0;
    unsigned int imports = 0;
    unsigned int ifuncs = 0;
    unsigned int ready = 0;
    SharedLibraries libraries{};
    unsigned int preloaded = 0;
    if (!preload_needed_libraries(payload, libraries, preloaded)) return 1;

    const auto fail = [&](const char *message) {
        std::fprintf(stderr, "%s\n", message);
        if (base != 0) linker_cleanup(key, base);
        close_shared_libraries(libraries);
        return 1;
    };

    std::snprintf(command, sizeof(command), "link %s %s", payload, entry_name);
    if (control(key, command, response, sizeof(response)) != 0 ||
        std::sscanf(response,
                    "ok base=0x%lx entry=0x%lx size=%lu relocations=%u needed_pending=%u imports_pending=%u ifunc_pending=%u ready=%u",
                    &base,
                    &entry,
                    &size,
                    &relocations,
                    &needed,
                    &imports,
                    &ifuncs,
                    &ready) != 8 ||
        base == 0 || size == 0 || entry != 0 || needed != preloaded ||
        needed != 1U || imports != 1U || ifuncs != 1U || ready != 0U)
        return fail("unexpected NEEDED/IFUNC image state after link");

    char matched[512]{};
    if (range_file_contains("/proc/self/maps", base, matched, sizeof(matched)) ||
        range_file_contains("/proc/self/smaps", base, matched, sizeof(matched)))
        return fail("NEEDED/IFUNC image is visible in procfs");

    unsigned long maps_address = 0;
    unsigned long maps_length = 0;
    if (!read_maps_into_ghost(key, static_cast<long>(getpid()), maps_address, maps_length))
        return fail("cannot stage current process maps in a ghost buffer");
    if (expected_failure == NeededFailure::AmbiguousMaps) {
        auto *snapshot = reinterpret_cast<char *>(maps_address);
        bool duplicated = false;
        for (unsigned long position = 0; position < maps_length;) {
            const char *line = snapshot + position;
            const char *newline = static_cast<const char *>(
                std::memchr(line, '\n', maps_length - position));
            if (!newline) break;
            const unsigned long line_length = static_cast<unsigned long>(newline - line) + 1UL;
            const char *libc = std::strstr(line, "/libc.so");
            const char *offset_zero = std::strstr(line, " 00000000 ");
            if (libc && libc < newline && offset_zero && offset_zero < newline &&
                maps_length + line_length + 1UL < 524288UL) {
                const unsigned long pristine_length = maps_length;

                /* First prove the seq_file race classification: replaying the
                 * exact same path and base is a torn snapshot, so the linker
                 * must ask for a fresh snapshot without committing anything. */
                std::memcpy(snapshot + maps_length, line, line_length);
                maps_length += line_length;
                snapshot[maps_length] = '\0';
                std::snprintf(command,
                              sizeof(command),
                              "resolve-current 0x%lx 0x%lx %lu",
                              base,
                              maps_address,
                              maps_length);
                (void)control(key, command, response, sizeof(response));
                if (std::strcmp(response,
                                "error=resolve-current-failed code=-11") != 0) {
                    free_ghost_buffer(key, maps_address);
                    return fail("identical maps replay was not classified as retryable");
                }

                /* Then retain the original fail-closed namespace test by
                 * adding the same SONAME at a distinct synthetic base. */
                maps_length = pristine_length;
                snapshot[maps_length] = '\0';
                unsigned long start = 0;
                unsigned long end = 0;
                const char *suffix = std::strchr(line, ' ');
                if (!suffix || std::sscanf(line, "%lx-%lx", &start, &end) != 2 ||
                    start > ~0UL - 0x1000UL || end > ~0UL - 0x1000UL) {
                    free_ghost_buffer(key, maps_address);
                    return fail("cannot construct distinct duplicate libc map fixture");
                }
                const int suffix_length = static_cast<int>(newline - suffix + 1);
                const int added = std::snprintf(
                    snapshot + maps_length,
                    524288UL - maps_length,
                    "%lx-%lx%.*s",
                    start + 0x1000UL,
                    end + 0x1000UL,
                    suffix_length,
                    suffix);
                if (added <= 0 ||
                    static_cast<unsigned long>(added) >= 524288UL - maps_length) {
                    free_ghost_buffer(key, maps_address);
                    return fail("cannot append distinct duplicate libc map fixture");
                }
                maps_length += static_cast<unsigned long>(added);
                duplicated = true;
                break;
            }
            position += line_length;
        }
        if (!duplicated) {
            free_ghost_buffer(key, maps_address);
            return fail("cannot construct duplicate libc map fixture");
        }
    }
    if (expected_failure == NeededFailure::FileMismatch) {
        auto *snapshot = reinterpret_cast<char *>(maps_address);
        bool replaced = false;
        for (unsigned long position = 0; position < maps_length;) {
            char *line = snapshot + position;
            const char *newline = static_cast<const char *>(
                std::memchr(line, '\n', maps_length - position));
            if (!newline) break;
            const unsigned long line_length = static_cast<unsigned long>(newline - line) + 1UL;
            char *libc = std::strstr(line, "/libc.so");
            const char *offset_zero = std::strstr(line, " 00000000 ");
            if (libc && libc < newline && offset_zero && offset_zero < newline) {
                unsigned long start = 0;
                unsigned long end = 0;
                if (std::sscanf(line, "%lx-%lx", &start, &end) != 2) break;
                libc[4] = 'x'; /* Keep the real offset-zero mapping out of the registry. */
                const int added = std::snprintf(
                    snapshot + maps_length, 524288UL - maps_length,
                    "%lx-%lx r--p 00000000 00:00 1 "
                    "/data/local/tmp/rtgum-stage1-pixel8/libc.so\n", start, end);
                if (added > 0 && static_cast<unsigned long>(added) < 524288UL - maps_length) {
                    maps_length += static_cast<unsigned long>(added);
                    replaced = true;
                }
                break;
            }
            position += line_length;
        }
        if (!replaced) {
            free_ghost_buffer(key, maps_address);
            return fail("cannot construct changed provider file fixture");
        }
    }
    std::snprintf(command,
                  sizeof(command),
                  "resolve-current 0x%lx 0x%lx %lu",
                  base,
                  maps_address,
                  maps_length);
    unsigned int registered = 0;
    unsigned int resolved = 0;
    unsigned int deferred = 0;
    const bool resolution_ok =
        control(key, command, response, sizeof(response)) == 0 &&
        std::sscanf(response,
                    "ok base=0x%*lx needed=%u imports=%u ifuncs=%u resolved=1",
                    &registered,
                    &resolved,
                    &deferred) == 3;
    free_ghost_buffer(key, maps_address);
    if (expected_failure != NeededFailure::None) {
        const char *expected_response = expected_failure == NeededFailure::Version
            ? "error=resolve-current-failed code=-2"
            : expected_failure == NeededFailure::AmbiguousMaps
                ? "error=resolve-current-failed code=-95"
                : "error=resolve-current-failed code=-2";
        if (resolution_ok || std::strcmp(response, expected_response) != 0)
            return fail("invalid version or ambiguous maps was not rejected");
        if (linker_cleanup(key, base) != 0) {
            close_shared_libraries(libraries);
            return 1;
        }
        base = 0;
        close_shared_libraries(libraries);
        if (control(key, "capabilities", response, sizeof(response)) != 0 ||
            std::strstr(response, "active=0 busy=0 images=0") == nullptr)
            return fail("GNU version rejection left active ghost state");
        if (expected_failure == NeededFailure::Version) {
            std::puts("gnu-version-mismatch=1 rejected=-2 hidden=1 freed=1");
            std::puts("stage1-needed-version-reject-test PASS");
        } else if (expected_failure == NeededFailure::AmbiguousMaps) {
            std::puts("torn-snapshot-retry=-11 duplicate-soname=1 rejected=-95 hidden=1 freed=1");
            std::puts("stage1-needed-maps-ambiguous-test PASS");
        } else {
            std::puts("provider-build-id-mismatch=1 rejected=-2 hidden=1 freed=1");
            std::puts("stage1-needed-file-mismatch-test PASS");
        }
        return 0;
    }
    if (!resolution_ok || registered != needed || resolved + deferred != imports)
        return fail("in-kernel NEEDED registration or import resolution failed");

    const unsigned int total_ifuncs = ifuncs + deferred;
    unsigned int repaired = 0;
    while (repaired < total_ifuncs) {
        unsigned int token = 0;
        unsigned long resolver = 0;
        std::snprintf(command, sizeof(command), "ifunc-next 0x%lx", base);
        if (control(key, command, response, sizeof(response)) != 0 ||
            std::sscanf(response,
                        "ok base=0x%*lx token=%u resolver=0x%lx",
                        &token,
                        &resolver) != 2 ||
            token == 0U || resolver == 0)
            return fail("image IFUNC resolver enumeration failed");
        const bool image_resolver = resolver >= base && resolver < base + size;
        char provider_map[512]{};
        if (!image_resolver &&
            (!range_file_contains("/proc/self/maps", resolver,
                                  provider_map, sizeof(provider_map)) ||
             std::strstr(provider_map, "/libc.so") == nullptr))
            return fail("provider IFUNC resolver is outside the registered libc image");
        const unsigned long target = call_arm64_ifunc_resolver(resolver);
        char target_map[512]{};
        if (image_resolver ? (target < base || target >= base + size)
                           : (!range_file_contains("/proc/self/maps", target,
                                                   target_map, sizeof(target_map)) ||
                              std::strstr(target_map, "/libc.so") == nullptr))
            return fail("image IFUNC resolver returned an invalid target");
        std::snprintf(command,
                      sizeof(command),
                      "ifunc-commit 0x%lx %u 0x%lx",
                      base,
                      token,
                      target);
        unsigned int remaining = 0;
        unsigned int commit_ready = 0;
        if (control(key, command, response, sizeof(response)) != 0 ||
            std::sscanf(response,
                        "ok base=0x%*lx remaining=%u ready=%u",
                        &remaining,
                        &commit_ready) != 2 ||
            remaining != total_ifuncs - repaired - 1U ||
            commit_ready != (remaining == 0U ? 1U : 0U))
            return fail("image IFUNC repair failed");
        ++repaired;
    }

    std::snprintf(command, sizeof(command), "lookup 0x%lx %s", base, entry_name);
    unsigned long symbol_size = 0;
    unsigned int symbol_type = 0;
    if (control(key, command, response, sizeof(response)) != 0 ||
        std::sscanf(response,
                    "ok base=0x%*lx address=0x%lx size=%lu type=%u",
                    &entry,
                    &symbol_size,
                    &symbol_type) != 3 ||
        entry < base || entry >= base + size || symbol_type != 2U)
        return fail("repaired image entry lookup failed");

    unsigned long value = 0;
    if (!invoke_arm64_bootstrap(entry, 0x1234UL, value) || value != 0x1241UL)
        return fail("ARM64 bootstrap call or resolved relocation returned the wrong value");
    if (linker_cleanup(key, base) != 0) {
        close_shared_libraries(libraries);
        return 1;
    }
    base = 0;
    close_shared_libraries(libraries);
    if (control(key, "capabilities", response, sizeof(response)) != 0 ||
        std::strstr(response, "active=0 busy=0 images=0") == nullptr)
        return fail("NEEDED/IFUNC cleanup left active ghost state");
    std::printf("needed-ifunc verified needed=%u imports=%u provider_ifunc=%u ifunc_repaired=%u result=0x%lx\n",
                registered,
                resolved + deferred,
                deferred,
                repaired,
                value);
    std::puts("kernel-resolver=1 dt-needed=1 rela-import=1 irelative=1 arm64-bootstrap=1 hidden=1 freed=1");
    std::puts("stage1-needed-ifunc-test PASS");
    return 0;
}

int command_zygote_test(const char *key)
{
    /* Remote dependency-resolution test: map the stage-2 Zygote payload
     * (DT_NEEDED libc/libdl/libm + 4 imports, all already loaded in Zygote)
     * into Zygote, let the KPM register the NEEDED libraries with its
     * in-kernel symbol resolver and repair the imports against Zygote's own
     * loaded libraries, then verify and unlink. No execution happens here
     * (stage2-test exercises the hijack). */
    constexpr const char *daemon =
        "/data/local/tmp/rtgum-stage1-pixel8/rtgum-stage2-zygote-payload.so";
    constexpr const char *entry_name = "ghost_zygote_probe";
    char command[512];
    char response[kControlBufferSize];
    char matched[512]{};
    long pid = -1;
    char process_name[32]{};
    char abi[16]{};

    /* The maps staging reads /proc/<zygote>/maps: elevate first. */
    rtgum_su_profile profile{};
    profile.uid = static_cast<std::uint32_t>(getuid());
    profile.to_uid = 0;
    if (rtgum_sc_su(key, &profile) != 0 || getuid() != 0) {
        std::fprintf(stderr, "zygote-test requires SuperCall elevation\n");
        return 1;
    }

    const long expected_pid = find_pid_by_cmdline("zygote64", true);
    std::snprintf(command, sizeof(command), "zygote-find %ld", expected_pid);
    if (expected_pid <= 0 || control(key, command, response, sizeof(response)) != 0 ||
        std::sscanf(response,
                    "ok pid=%ld name=%31s abi=%15s",
                    &pid,
                    process_name,
                    abi) != 3 ||
        pid != expected_pid || std::strcmp(process_name, "zygote64") != 0 ||
        std::strcmp(abi, "arm64") != 0) {
        std::fprintf(stderr, "unexpected Zygote discovery response: %s\n", response);
        return 1;
    }

    std::snprintf(command, sizeof(command), "zygote-link %ld %s %s", pid, daemon, entry_name);
    unsigned long base = 0;
    unsigned long entry = 0;
    unsigned long size = 0;
    unsigned int relocations = 0;
    unsigned int needed = 0;
    unsigned int imports = 0;
    unsigned int ifuncs = 0;
    unsigned int ready = 0;
    long mapped_pid = -1;
    if (control(key, command, response, sizeof(response)) != 0 ||
        std::sscanf(response,
                    "ok pid=%ld name=zygote64 base=0x%lx entry=0x%lx size=%lu relocations=%u needed=%u imports=%u ifuncs=%u ready=%u",
                    &mapped_pid,
                    &base,
                    &entry,
                    &size,
                    &relocations,
                    &needed,
                    &imports,
                    &ifuncs,
                    &ready) != 9 ||
        mapped_pid != pid || base == 0 || size == 0 || needed == 0U || imports == 0U ||
        ready > 1U) {
        std::fprintf(stderr, "unexpected Zygote linker response: %s\n", response);
        if (base != 0) {
            std::snprintf(command, sizeof(command), "zygote-unlink %ld 0x%lx", pid, base);
            if (control(key, command, response, sizeof(response)) != 0 ||
                std::strncmp(response, "ok ", 3) != 0)
                std::fprintf(stderr, "Zygote cleanup after invalid link response failed\n");
        }
        return 1;
    }
    auto cleanup = [&]() {
        std::snprintf(command, sizeof(command), "zygote-unlink %ld 0x%lx", pid, base);
        return control(key, command, response, sizeof(response)) == 0 &&
               std::strncmp(response, "ok ", 3) == 0;
    };
    auto fail = [&](const char *message) {
        std::fprintf(stderr, "%s\n", message);
        if (!cleanup()) std::fprintf(stderr, "Zygote cleanup also failed: %s\n", response);
        return 1;
    };

    std::snprintf(command, sizeof(command), "zygote-resolve %ld 0x%lx", pid, base);
    unsigned int resolved_needed = 0;
    unsigned int resolved_imports = 0;
    unsigned int deferred_ifuncs = 0;
    unsigned long maps_address = 0;
    unsigned long maps_length = 0;
    if (!read_maps_into_ghost(key, pid, maps_address, maps_length)) {
        std::fprintf(stderr, "cannot read Zygote maps into the ghost buffer\n");
        return fail("Zygote maps staging failed");
    }
    std::snprintf(command,
                  sizeof(command),
                  "zygote-resolve %ld 0x%lx 0x%lx %lu",
                  pid,
                  base,
                  maps_address,
                  maps_length);
    const bool resolved =
        control(key, command, response, sizeof(response)) == 0 &&
        std::sscanf(response,
                    "ok pid=%*ld base=0x%*lx needed=%u imports=%u ifuncs=%u resolved=1",
                    &resolved_needed,
                    &resolved_imports,
                    &deferred_ifuncs) == 3;
    free_ghost_buffer(key, maps_address);
    if (!resolved || resolved_needed != needed ||
        resolved_imports + deferred_ifuncs != imports) {
        std::fprintf(stderr, "remote dependency resolution failed: %s\n", response);
        return fail("Zygote DT_NEEDED registration and import repair failed");
    }

    std::snprintf(command, sizeof(command), "zygote-verify-ptes %ld 0x%lx", pid, base);
    unsigned long verified_size = 0;
    if (control(key, command, response, sizeof(response)) != 0 ||
        std::sscanf(response,
                    "ok pid=%*ld base=0x%*lx size=%lu ptes=1 image=1",
                    &verified_size) != 1 ||
        verified_size != size)
        return fail("KPM could not verify the remote Zygote PTEs");
    if (deferred_ifuncs == 0U) {
        std::snprintf(command, sizeof(command), "zygote-verify %ld 0x%lx", pid, base);
        if (control(key, command, response, sizeof(response)) != 0 ||
            std::sscanf(response,
                        "ok pid=%*ld base=0x%*lx size=%lu ptes=1 image=1",
                        &verified_size) != 1 ||
            verified_size != size)
            return fail("KPM could not verify the resolved remote Zygote PTEs");
    } else {
        std::snprintf(command, sizeof(command), "zygote-verify %ld 0x%lx", pid, base);
        if (control(key, command, response, sizeof(response)) != 0 ||
            std::strncmp(response, "error=zygote-verify-failed", 26) != 0)
            return fail("Unresolved Zygote image passed the readiness gate");
    }

    char maps_path[64];
    char smaps_path[64];
    std::snprintf(maps_path, sizeof(maps_path), "/proc/%ld/maps", pid);
    std::snprintf(smaps_path, sizeof(smaps_path), "/proc/%ld/smaps", pid);
    if (range_file_contains(maps_path, base, matched, sizeof(matched)) ||
        range_file_contains(smaps_path, base, matched, sizeof(matched))) {
        std::fprintf(stderr, "Zygote ghost image leaked through procfs: %s\n", matched);
        return fail("Zygote maps/smaps concealment check failed");
    }

    if (!cleanup()) {
        std::fprintf(stderr, "Zygote unlink failed: %s\n", response);
        return 1;
    }
    if (control(key, "capabilities", response, sizeof(response)) != 0 ||
        std::strstr(response, "active=0") == nullptr ||
        std::strstr(response, "busy=0") == nullptr ||
        std::strstr(response, "images=0") == nullptr) {
        std::fprintf(stderr, "Zygote cleanup count mismatch: %s\n", response);
        return 1;
    }

    std::printf("zygote-ghost-probe mapped pid=%ld base=0x%lx size=%lu relocations=%u needed=%u imports=%u ifuncs=%u\n",
                pid,
                base,
                size,
                relocations,
                resolved_needed,
                resolved_imports,
                deferred_ifuncs);
    std::printf("client-discovery=1 kernel-pid-mm=1 remote-mm=1 pt-load=1 rela=1 needed-registry=1 import-resolve=%u provider-ifunc-deferred=%u ptes-verified=1 readiness-gate=1 maps-hidden=1 smaps-hidden=1 executed=0 unlinked=1\n",
                deferred_ifuncs == 0U ? 1U : 0U,
                deferred_ifuncs);
    std::puts("stage2-zygote-resolve-probe PASS");
    return 0;
}

/* Like zygote-test but leaves the resolved image mapped (crash bisection:
 * isolates the resolve/commit path from the unlink path). */
int command_zygote_test_keep(const char *key)
{
    constexpr const char *daemon =
        "/data/local/tmp/rtgum-stage1-pixel8/rtgum-stage2-zygote-payload.so";
    constexpr const char *entry_name = "ghost_zygote_probe";
    char command[512];
    char response[kControlBufferSize];
    long pid = -1;
    char process_name[32]{};
    char abi[16]{};
    rtgum_su_profile profile{};
    profile.uid = static_cast<std::uint32_t>(getuid());
    profile.to_uid = 0;
    if (rtgum_sc_su(key, &profile) != 0 || getuid() != 0) return 1;
    const long expected_pid = find_pid_by_cmdline("zygote64", true);
    std::snprintf(command, sizeof(command), "zygote-find %ld", expected_pid);
    if (expected_pid <= 0 || control(key, command, response, sizeof(response)) != 0 ||
        std::sscanf(response, "ok pid=%ld name=%31s abi=%15s", &pid, process_name, abi) != 3 ||
        pid != expected_pid || std::strcmp(process_name, "zygote64") != 0)
        return 1;
    std::snprintf(command, sizeof(command), "zygote-link %ld %s %s", pid, daemon, entry_name);
    unsigned long base = 0;
    unsigned long entry = 0;
    unsigned long size = 0;
    unsigned int relocations = 0;
    unsigned int needed = 0;
    unsigned int imports = 0;
    unsigned int ifuncs = 0;
    unsigned int ready = 0;
    if (control(key, command, response, sizeof(response)) != 0 ||
        std::sscanf(response,
                    "ok pid=%*ld name=zygote64 base=0x%lx entry=0x%lx size=%lu relocations=%u needed=%u imports=%u ifuncs=%u ready=%u",
                    &base,
                    &entry,
                    &size,
                    &relocations,
                    &needed,
                    &imports,
                    &ifuncs,
                    &ready) != 8 ||
        base == 0 || size == 0)
        return 1;
    unsigned int resolved_needed = 0;
    unsigned int resolved_imports = 0;
    unsigned int deferred_ifuncs = 0;
    unsigned long maps_address = 0;
    unsigned long maps_length = 0;
    if (!read_maps_into_ghost(key, pid, maps_address, maps_length)) return 1;
    std::snprintf(command,
                  sizeof(command),
                  "zygote-resolve %ld 0x%lx 0x%lx %lu",
                  pid,
                  base,
                  maps_address,
                  maps_length);
    const bool resolved =
        control(key, command, response, sizeof(response)) == 0 &&
        std::sscanf(response,
                    "ok pid=%*ld base=0x%*lx needed=%u imports=%u ifuncs=%u resolved=1",
                    &resolved_needed,
                    &resolved_imports,
                    &deferred_ifuncs) == 3;
    free_ghost_buffer(key, maps_address);
    std::printf("keep: %s resolved=%d needed=%u imports=%u ifuncs=%u\n",
                response,
                resolved ? 1 : 0,
                resolved_needed,
                resolved_imports,
                deferred_ifuncs);
    return resolved ? 0 : 1;
}

struct ProcessCounts {
    unsigned long tasks = 0;
    unsigned long fds = 0;
    unsigned long sockets = 0;
};

bool count_process(const char *pid_path, ProcessCounts &counts)
{
    counts = {};
    std::string tasks_path = std::string(pid_path) + "/task";
    DIR *directory = opendir(tasks_path.c_str());
    if (!directory) return false;
    struct dirent *entry = nullptr;
    while ((entry = readdir(directory)) != nullptr) {
        if (std::strcmp(entry->d_name, ".") == 0 || std::strcmp(entry->d_name, "..") == 0)
            continue;
        ++counts.tasks;
    }
    closedir(directory);

    std::string fd_path = std::string(pid_path) + "/fd";
    directory = opendir(fd_path.c_str());
    if (!directory) return false;
    char link[96];
    while ((entry = readdir(directory)) != nullptr) {
        if (entry->d_name[0] == '.') continue;
        ++counts.fds;
        std::string link_path = fd_path + "/" + entry->d_name;
        const ssize_t length = readlink(link_path.c_str(), link, sizeof(link) - 1);
        if (length > 0) {
            link[length] = '\0';
            if (std::strncmp(link, "socket:", 7) == 0) ++counts.sockets;
        }
    }
    closedir(directory);
    return true;
}

long find_pid_by_cmdline(const char *prefix, bool exact)
{
    struct Candidate {
        long pid = -1;
        long ppid = -1;
        unsigned long threads = 0;
    };
    const std::size_t prefix_length = std::strlen(prefix);
    DIR *directory = opendir("/proc");
    if (!directory) return -1;
    struct dirent *entry = nullptr;
    std::vector<Candidate> candidates;
    while ((entry = readdir(directory)) != nullptr) {
        if (entry->d_name[0] < '0' || entry->d_name[0] > '9') continue;
        char path[64];
        std::snprintf(path, sizeof(path), "/proc/%s/cmdline", entry->d_name);
        FILE *file = std::fopen(path, "r");
        if (!file) continue;
        char cmdline[256]{};
        const std::size_t length = std::fread(cmdline, 1, sizeof(cmdline) - 1, file);
        std::fclose(file);
        if (length >= prefix_length &&
            (exact ? std::strcmp(cmdline, prefix) == 0
                   : std::strncmp(cmdline, prefix, prefix_length) == 0)) {
            Candidate candidate{};
            candidate.pid = std::atol(entry->d_name);
            std::snprintf(path, sizeof(path), "/proc/%s/status", entry->d_name);
            FILE *status = std::fopen(path, "r");
            if (status) {
                char line[128];
                while (std::fgets(line, sizeof(line), status) != nullptr) {
                    long parent = -1;
                    unsigned long threads = 0;
                    if (std::sscanf(line, "PPid:%ld", &parent) == 1)
                        candidate.ppid = parent;
                    else if (std::sscanf(line, "Threads:%lu", &threads) == 1)
                        candidate.threads = threads;
                }
                std::fclose(status);
            }
            candidates.push_back(candidate);
        }
    }
    closedir(directory);
    if (candidates.empty()) return -1;

    /* Commercial shells commonly fork a same-cmdline one-thread watchdog and
     * occasionally use it to ptrace the real app. /proc enumeration order is
     * not an API, so selecting the first match can make status polling jump to
     * the watchdog. Prefer a match whose parent is outside the matched set,
     * then the process with the largest thread group and finally the older PID.
     * The same rule remains deterministic for ordinary single-process apps. */
    const Candidate *best = nullptr;
    bool best_is_root = false;
    for (const Candidate &candidate : candidates) {
        bool is_root = true;
        for (const Candidate &other : candidates) {
            if (candidate.ppid == other.pid) {
                is_root = false;
                break;
            }
        }
        if (!best ||
            (is_root && !best_is_root) ||
            (is_root == best_is_root && candidate.threads > best->threads) ||
            (is_root == best_is_root && candidate.threads == best->threads &&
             candidate.pid < best->pid)) {
            best = &candidate;
            best_is_root = is_root;
        }
    }
    return best ? best->pid : -1;
}

long find_pid_by_comm(const char *name)
{
    if (!name || name[0] == '\0') return -1;
    DIR *directory = opendir("/proc");
    if (!directory) return -1;
    struct dirent *entry = nullptr;
    long result = -1;
    while ((entry = readdir(directory)) != nullptr) {
        if (entry->d_name[0] < '0' || entry->d_name[0] > '9') continue;
        char path[64];
        std::snprintf(path, sizeof(path), "/proc/%s/comm", entry->d_name);
        FILE *file = std::fopen(path, "r");
        if (!file) continue;
        char comm[32]{};
        if (std::fgets(comm, sizeof(comm), file) == nullptr) {
            std::fclose(file);
            continue;
        }
        std::fclose(file);
        const std::size_t length = std::strlen(comm);
        if (length > 0 && comm[length - 1] == '\n') comm[length - 1] = '\0';
        if (std::strcmp(comm, name) == 0) {
            result = std::atol(entry->d_name);
            break;
        }
    }
    closedir(directory);
    return result;
}

bool wait_for_daemon_status(const char *key,
                            long pid,
                            unsigned long phase,
                            unsigned long modules,
                            int timeout_seconds,
                            char *response,
                            unsigned long &magic,
                            unsigned long &api,
                            unsigned long &module_base)
{
    magic = 0;
    api = 0;
    module_base = 0;
    for (int attempt = 0; attempt < timeout_seconds * 2; ++attempt) {
        char command[512];
        std::snprintf(command, sizeof(command), "daemon-status %ld", pid);
        if (control(key, command, response, kControlBufferSize) != 0) return false;
        unsigned long got_phase = 0;
        unsigned long got_modules = 0;
        unsigned long got_magic = 0;
        unsigned long got_api = 0;
        unsigned long got_module_base = 0;
        if (std::sscanf(response,
                        "ok pid=%*ld phase=%lu modules=%lu extra=%*lu magic=0x%lx module_base=0x%lx api=0x%lx",
                        &got_phase,
                        &got_modules,
                        &got_magic,
                        &got_module_base,
                        &got_api) == 5) {
            magic = got_magic;
            api = got_api;
            module_base = got_module_base;
            if (got_phase >= phase && got_modules >= modules) return true;
        } else if (std::strstr(response, "error=") != nullptr) {
            return false;
        }
        usleep(500000);
    }
    return false;
}

int command_stage2_test(const char *key, const char *package)
{
    constexpr const char *daemon_path = "/data/local/tmp/rtgum-stage1-pixel8/rtgum-stage2-daemon.so";
    constexpr const char *dispatch_name = "rtgum_stage2_daemon_dispatch";
    constexpr const char *module_path = "/data/local/tmp/rtgum-stage1-pixel8/rtgum-stage2-module.ghm";
    constexpr const char *module2_path = "/data/local/tmp/rtgum-stage1-pixel8/rtgum-stage2-module2.ghm";
    if (!package || std::strlen(package) < 3U || std::strlen(package) > 127U ||
        !std::strchr(package, '.')) {
        std::fprintf(stderr, "stage2-test requires a valid Android package name\n");
        return 2;
    }
    for (const char *cursor = package; *cursor != '\0'; ++cursor) {
        if ((*cursor < 'a' || *cursor > 'z') && (*cursor < 'A' || *cursor > 'Z') &&
            (*cursor < '0' || *cursor > '9') && *cursor != '.' && *cursor != '_') {
            std::fprintf(stderr, "invalid package character\n");
            return 2;
        }
    }
    constexpr unsigned long daemon_magic = 0x4441454d4f4e3230UL; /* "DAEMON20" */
    char command[512];
    char response[kControlBufferSize];
    char matched[512]{};

    /* Elevate once: the test inspects other processes' /proc entries. */
    rtgum_su_profile profile{};
    profile.uid = static_cast<std::uint32_t>(getuid());
    profile.to_uid = 0;
    if (rtgum_sc_su(key, &profile) != 0 || getuid() != 0) {
        std::fprintf(stderr, "stage2-test requires SuperCall elevation\n");
        return 1;
    }

    /* 0. Enable the stage-2 hooks (comm matcher, daemon syscall channel,
     *    poll/epoll dispatch triggers) and wake the syscall channel. */
    if (control(key, "hook-comm", response, sizeof(response)) != 0 ||
        std::strncmp(response, "ok ", 3) != 0) {
        std::fprintf(stderr, "cannot install the comm hook: %s\n", response);
        return 1;
    }
    if (control(key, "hook-sysni", response, sizeof(response)) != 0 ||
        std::strncmp(response, "ok ", 3) != 0) {
        std::fprintf(stderr, "cannot install the sys_ni hook: %s\n", response);
        return 1;
    }
    if (control(key, "hook-poll", response, sizeof(response)) != 0 ||
        std::strncmp(response, "ok ", 3) != 0) {
        std::fprintf(stderr, "cannot install the poll hook: %s\n", response);
        return 1;
    }
    if (control(key, "hook-epoll", response, sizeof(response)) != 0 ||
        std::strncmp(response, "ok ", 3) != 0) {
        std::fprintf(stderr, "cannot install the epoll hook: %s\n", response);
        return 1;
    }
    syscall(RTGUM_DAEMON_SYSCALL, 0L, 0L, 0L, 0L, 0L, 0L);

    /* 1. Discover Zygote and take process-state baselines. */
    long zygote_pid = -1;
    char process_name[32]{};
    char abi[16]{};
    const long expected_zygote_pid = find_pid_by_cmdline("zygote64", true);
    std::snprintf(command, sizeof(command), "zygote-find %ld", expected_zygote_pid);
    if (expected_zygote_pid <= 0 ||
        control(key, command, response, sizeof(response)) != 0 ||
        std::sscanf(response, "ok pid=%ld name=%31s abi=%15s", &zygote_pid, process_name, abi) != 3 ||
        zygote_pid != expected_zygote_pid || std::strcmp(process_name, "zygote64") != 0) {
        std::fprintf(stderr, "unexpected Zygote discovery response: %s\n", response);
        return 1;
    }
    char zygote_path[64];
    std::snprintf(zygote_path, sizeof(zygote_path), "/proc/%ld", zygote_pid);
    ProcessCounts zygote_before{};
    if (!count_process(zygote_path, zygote_before)) {
        std::fprintf(stderr, "cannot baseline Zygote process state\n");
        return 1;
    }

    /* 2. Link the Daemon into Zygote and resolve its dependencies. */
    std::snprintf(command, sizeof(command), "zygote-link %ld %s %s", zygote_pid,
                  daemon_path, dispatch_name);
    unsigned long base = 0;
    unsigned long entry = 0;
    unsigned long size = 0;
    unsigned int relocations = 0;
    unsigned int needed = 0;
    unsigned int imports = 0;
    unsigned int ifuncs = 0;
    unsigned int ready = 0;
    if (control(key, command, response, sizeof(response)) != 0 ||
        std::sscanf(response,
                    "ok pid=%*ld name=zygote64 base=0x%lx entry=0x%lx size=%lu relocations=%u needed=%u imports=%u ifuncs=%u ready=%u",
                    &base,
                    &entry,
                    &size,
                    &relocations,
                    &needed,
                    &imports,
                    &ifuncs,
                    &ready) != 8 ||
        base == 0 || size == 0 || needed != 1U || imports != 1U || ifuncs != 1U || ready != 0U) {
        std::fprintf(stderr, "unexpected Daemon linker response: %s\n", response);
        return 1;
    }

    std::snprintf(command, sizeof(command), "zygote-resolve %ld 0x%lx", zygote_pid, base);
    unsigned int resolved_needed = 0;
    unsigned int resolved_imports = 0;
    unsigned int deferred_ifuncs = 0;
    unsigned long maps_address = 0;
    unsigned long maps_length = 0;
    if (!read_maps_into_ghost(key, zygote_pid, maps_address, maps_length)) {
        std::snprintf(command, sizeof(command), "zygote-unlink %ld 0x%lx", zygote_pid, base);
        control(key, command, response, sizeof(response));
        std::fprintf(stderr, "cannot stage Zygote maps into the ghost buffer\n");
        return 1;
    }
    std::snprintf(command,
                  sizeof(command),
                  "zygote-resolve %ld 0x%lx 0x%lx %lu",
                  zygote_pid,
                  base,
                  maps_address,
                  maps_length);
    const bool resolved =
        control(key, command, response, sizeof(response)) == 0 &&
        std::sscanf(response,
                    "ok pid=%*ld base=0x%*lx needed=%u imports=%u ifuncs=%u resolved=1",
                    &resolved_needed,
                    &resolved_imports,
                    &deferred_ifuncs) == 3;
    free_ghost_buffer(key, maps_address);
    if (!resolved || resolved_needed != needed || resolved_imports != imports) {
        std::fprintf(stderr, "Daemon dependency resolution failed: %s\n", response);
        std::snprintf(command, sizeof(command), "zygote-unlink %ld 0x%lx", zygote_pid, base);
        control(key, command, response, sizeof(response));
        return 1;
    }

    auto final_cleanup = [&]() {
        char stop_command[192];
        std::snprintf(stop_command, sizeof(stop_command), "am force-stop %s >/dev/null 2>&1", package);
        system(stop_command);
        std::snprintf(command, sizeof(command), "zygote-unlink %ld 0x%lx", zygote_pid, base);
        return control(key, command, response, sizeof(response)) == 0 &&
               std::strncmp(response, "ok ", 3) == 0;
    };
    auto fail = [&](const char *message) {
        std::fprintf(stderr, "%s\n", message);
        if (!final_cleanup()) std::fprintf(stderr, "cleanup failed: %s\n", response);
        return 1;
    };

    /* 3. Configure package matching. */
    std::snprintf(command,
                  sizeof(command),
                  "daemon-config %ld %s %s",
                  zygote_pid,
                  package,
                  module_path);
    if (control(key, command, response, sizeof(response)) != 0 ||
        std::strncmp(response, "ok ", 3) != 0)
        return fail("daemon package configuration failed");

    /* 4. Bootstrap: trampoline + syscall-context hijack of the Zygote main task. */
    std::snprintf(command,
                  sizeof(command),
                  "zygote-bootstrap %ld 0x%lx 0x%lx 0x%lx",
                  zygote_pid,
                  base,
                  getauxval(AT_HWCAP),
                  getauxval(AT_HWCAP2));
    unsigned long trampoline = 0;
    unsigned long ctx = 0;
    unsigned int ifunc_slots = 0;
    if (control(key, command, response, sizeof(response)) != 0 ||
        std::sscanf(response,
                    "ok pid=%*ld base=0x%*lx trampoline=0x%lx ctx=0x%lx dispatch=0x%*lx status=0x%*lx fixup=%*lu ifunc_slots=%u dispatched=1",
                    &trampoline,
                    &ctx,
                    &ifunc_slots) != 3 ||
        trampoline == 0 || ctx == 0 || ifunc_slots != 1U) {
        std::fprintf(stderr, "Zygote bootstrap failed: %s\n", response);
        return fail("Zygote bootstrap dispatch failed");
    }

    /* 5. Launch the target app: the connection wakes Zygote's poll loop,
     * whose return dispatches the Daemon INIT, and the fresh fork
     * inherits the Daemon (proof of fork inheritance). */
    char stop_command[192];
    std::snprintf(stop_command, sizeof(stop_command), "am force-stop %s >/dev/null 2>&1", package);
    system(stop_command);
    usleep(800000);
    char launch_command[256];
    std::snprintf(launch_command, sizeof(launch_command),
                  "monkey -p %s -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1", package);
    system(launch_command);
    long target_pid = -1;
    for (int attempt = 0; attempt < 60 && target_pid <= 0; ++attempt) {
        target_pid = find_pid_by_cmdline(package);
        if (target_pid <= 0) usleep(500000);
    }
    if (target_pid <= 0)
        return fail("target application did not start");

    /* 6. Wait for the Daemon INIT execution inside Zygote (dispatched as
     * poll returns after the app connection). */
    unsigned long magic = 0;
    unsigned long api = 0;
    unsigned long module_base = 0;
    if (!wait_for_daemon_status(key,
                                zygote_pid,
                                /*phase=*/1,
                                /*modules=*/0,
                                 /*timeout=*/90,
                                response,
                                magic,
                                api,
                                module_base) ||
        magic != daemon_magic || api == 0) {
        std::fprintf(stderr, "Daemon did not execute INIT in Zygote: %s\n", response);
        return fail("Zygote Daemon INIT execution failed");
    }

    /* 7. Verify maps/smaps remain hidden and observe process state. Counts
     * can change during ordinary app startup, so they are not attributed. */
    char maps_path[64];
    char smaps_path[64];
    std::snprintf(maps_path, sizeof(maps_path), "/proc/%ld/maps", zygote_pid);
    std::snprintf(smaps_path, sizeof(smaps_path), "/proc/%ld/smaps", zygote_pid);
    if (range_file_contains(maps_path, base, matched, sizeof(matched)) ||
        range_file_contains(smaps_path, base, matched, sizeof(matched))) {
        std::fprintf(stderr, "Zygote ghost image leaked through procfs: %s\n", matched);
        return fail("Zygote maps/smaps concealment check failed");
    }
    ProcessCounts zygote_after{};
    if (!count_process(zygote_path, zygote_after))
        return fail("cannot inspect Zygote process state");

    char target_path[64];
    std::snprintf(target_path, sizeof(target_path), "/proc/%ld", target_pid);

    /* 8. Package dispatch: the comm rename prctl hijacks the child and the
     * .ghm module loads; running in the child proves fork inheritance. */
    if (!wait_for_daemon_status(key,
                                 target_pid,
                                /*phase=*/3,
                                /*modules=*/1,
                                /*timeout=*/45,
                                response,
                                magic,
                                api,
                                module_base) ||
        api == 0 || module_base == 0)
        return fail("package dispatch did not load the user module");

    /* 10. The ghost image must remain absent from target maps/smaps. */
    std::snprintf(maps_path, sizeof(maps_path), "/proc/%ld/maps", target_pid);
    std::snprintf(smaps_path, sizeof(smaps_path), "/proc/%ld/smaps", target_pid);
    if (range_file_contains(maps_path, base, matched, sizeof(matched)) ||
        range_file_contains(smaps_path, base, matched, sizeof(matched)) ||
        range_file_contains(maps_path, module_base, matched, sizeof(matched)) ||
        range_file_contains(smaps_path, module_base, matched, sizeof(matched))) {
        std::fprintf(stderr, "target ghost region leaked through procfs: %s\n", matched);
        return fail("target maps/smaps concealment check failed");
    }
    ProcessCounts before_reload{};
    if (!count_process(target_path, before_reload))
        return fail("cannot baseline target process state");

    /* 11. Hot reload: clear the old module, inject module2, same process. */
    std::snprintf(command,
                  sizeof(command),
                  "daemon-reload %ld %s %s",
                  target_pid,
                  package,
                  module2_path);
    if (control(key, command, response, sizeof(response)) != 0 ||
        std::strncmp(response, "ok ", 3) != 0)
        return fail("daemon hot reload dispatch failed");
    if (!wait_for_daemon_status(key,
                                 target_pid,
                                /*phase=*/4,
                                /*modules=*/1,
                                /*timeout=*/30,
                                response,
                                magic,
                                api,
                                module_base) ||
        module_base == 0)
        return fail("hot reload did not enter the new module");

    /* 12. Observe process state after reload. Third-party apps can continue
     * starting threads and opening files during this window, so a before/after
     * count cannot attribute those changes to the injected module. */
    ProcessCounts after_reload{};
    if (!count_process(target_path, after_reload))
        return fail("cannot inspect target process state after reload");
    if (range_file_contains(maps_path, module_base, matched, sizeof(matched)) ||
        range_file_contains(smaps_path, module_base, matched, sizeof(matched))) {
        std::fprintf(stderr, "reloaded module leaked through procfs: %s\n", matched);
        return fail("reloaded module maps/smaps concealment check failed");
    }

    /* 13. Teardown: unlink the Daemon from Zygote and stop the target. */
    if (!final_cleanup()) return 1;
    bool reset = false;
    for (int attempt = 0; attempt < 40; ++attempt) {
        if (control(key, "capabilities", response, sizeof(response)) == 0 &&
            std::strstr(response, "daemon=0") != nullptr) {
            reset = true;
            break;
        }
        usleep(500000);
    }
    if (!reset) {
        std::fprintf(stderr, "daemon reset did not complete: %s\n", response);
        return 1;
    }

    std::printf("zygote-state-during-init tasks=%lu->%lu fds=%lu->%lu sockets=%lu->%lu\n",
                zygote_before.tasks, zygote_after.tasks, zygote_before.fds,
                zygote_after.fds, zygote_before.sockets, zygote_after.sockets);
    std::printf("target-state-during-reload tasks=%lu->%lu fds=%lu->%lu sockets=%lu->%lu\n",
                before_reload.tasks, after_reload.tasks, before_reload.fds,
                after_reload.fds, before_reload.sockets, after_reload.sockets);

    std::printf("stage2-inject verified zygote=%ld base=0x%lx trampoline=0x%lx ctx=0x%lx target=%ld module=%s\n",
                zygote_pid,
                base,
                trampoline,
                ctx,
                 target_pid,
                package);
    std::puts("session-auth=1 zygote-hijack=1 poll-dispatch=1 bootstrap=1 ifunc-fixup=1 needed-registry=1 import-resolve=1 daemon-init=1 fork-inherit=1 package-dispatch=1 ghost-entry=1 hot-reload=1 maps-hidden=1 smaps-hidden=1 process-state-observed=1 zygote-unlinked=1");
    std::puts("stage2-inject-test PASS");
    return 0;
}

/* Link the Daemon into Zygote, configure the lab package with the mako ART
 * module, start the app, and LEAVE IT RUNNING.
 *
 * Deliberately not a variant of command_zygote_init_test: that one asserts and
 * then unlinks everything, which is right for a regression gate and wrong for
 * iterating, because the hook and the lab's self-check disappear exactly when
 * they become interesting. The two orderings that matter here were learned the
 * hard way and are kept as-is:
 *
 *   * daemon-config runs BEFORE zygote-bootstrap (the packaged scenario does it
 *     the other way round and then fails to reach the app), and
 *   * the app is started with `monkey -p` (the launcher intent) rather than
 *     `am start -n <component>`, which returned before the process existed.
 */
int command_mako_hold(const char *key, const char *package,
                      bool use_existing_manager_config)
{
    constexpr const char *daemon_path =
        "/data/local/tmp/rtgum-stage1-pixel8/rtgum-stage2-daemon.so";
    constexpr const char *dispatch_name = "rtgum_stage2_daemon_dispatch";
    constexpr const char *module_path =
        "/data/local/tmp/rtgum-stage1-pixel8/rtgum-stage2-lab-mako.ghm";
    constexpr const char *mako_path =
        "/data/local/tmp/rtgum-stage1-pixel8/libmako-ghost.so";
    if (package == nullptr || std::strlen(package) < 3U) {
        std::fprintf(stderr, "mako-hold-test requires a package name\n");
        return 2;
    }
    char command[512];
    char response[kControlBufferSize];

    rtgum_su_profile profile{};
    profile.uid = static_cast<std::uint32_t>(getuid());
    profile.to_uid = 0;
    if (rtgum_sc_su(key, &profile) != 0 || getuid() != 0) {
        std::fprintf(stderr, "mako-hold-test requires SuperCall elevation\n");
        return 1;
    }

    for (const char *hook : {"hook-comm", "hook-sysni", "hook-poll", "hook-epoll",
                             "hook-art-shadow"}) {
        if (control(key, hook, response, sizeof(response)) != 0 ||
            std::strncmp(response, "ok ", 3) != 0) {
            std::fprintf(stderr, "%s failed: %s\n", hook, response);
            return 1;
        }
    }
    std::printf("hooks=comm+sysni+poll+epoll+art-shadow\n");
    std::fflush(stdout);

    const long zygote_pid = find_pid_by_cmdline("zygote64", true);
    if (zygote_pid <= 0) { std::fprintf(stderr, "zygote64 not found\n"); return 1; }

    /* A crashed or interrupted run leaves the Daemon registered, and then
     * bootstrap refuses with -EBUSY forever. Clear it first; the command is
     * idempotent. */
    if (!use_existing_manager_config) {
        std::snprintf(command, sizeof(command), "zygote-unlink-all %ld", zygote_pid);
        if (control(key, command, response, sizeof(response)) == 0)
            std::printf("pre-clean: %s\n", response);
    }

    std::snprintf(command, sizeof(command), "zygote-link %ld %s %s", zygote_pid,
                  daemon_path, dispatch_name);
    unsigned long base = 0;
    unsigned int needed = 0, imports = 0, ifuncs = 0;
    if (control(key, command, response, sizeof(response)) != 0 ||
        std::sscanf(response,
                    "ok pid=%*ld name=zygote64 base=0x%lx entry=%*lx size=%*lu "
                    "relocations=%*u needed=%u imports=%u ifuncs=%u",
                    &base, &needed, &imports, &ifuncs) != 4 ||
        base == 0) {
        std::fprintf(stderr, "zygote-link failed: %s\n", response);
        return 1;
    }
    std::printf("link base=0x%lx needed=%u imports=%u ifuncs=%u\n", base, needed,
                imports, ifuncs);

    unsigned long maps_address = 0, maps_length = 0;
    if (!read_maps_into_ghost(key, zygote_pid, maps_address, maps_length)) {
        std::fprintf(stderr, "maps staging failed\n");
        return 1;
    }
    std::snprintf(command, sizeof(command), "zygote-resolve %ld 0x%lx 0x%lx %lu",
                  zygote_pid, base, maps_address, maps_length);
    unsigned int resolved_needed = 0, resolved_imports = 0, deferred = 0;
    const bool resolved =
        control(key, command, response, sizeof(response)) == 0 &&
        std::sscanf(response,
                    "ok pid=%*ld base=0x%*lx needed=%u imports=%u ifuncs=%u resolved=1",
                    &resolved_needed, &resolved_imports, &deferred) == 3;
    free_ghost_buffer(key, maps_address);
    if (!resolved) { std::fprintf(stderr, "zygote-resolve failed: %s\n", response); return 1; }
    std::printf("resolve needed=%u imports=%u ifuncs=%u\n", resolved_needed,
                resolved_imports, deferred);

    if (!use_existing_manager_config) {
        std::snprintf(command, sizeof(command), "daemon-config %ld %s %s %s", zygote_pid,
                      package, module_path, mako_path);
        if (control(key, command, response, sizeof(response)) != 0 ||
            std::strncmp(response, "ok ", 3) != 0) {
            std::fprintf(stderr, "daemon-config failed: %s\n", response);
            return 1;
        }
        std::printf("config: %s\n", response);
    } else {
        std::printf("config: manager-cache\n");
    }

    std::snprintf(command, sizeof(command), "zygote-bootstrap %ld 0x%lx 0x%lx 0x%lx",
                  zygote_pid, base, getauxval(AT_HWCAP), getauxval(AT_HWCAP2));
    if (control(key, command, response, sizeof(response)) != 0 ||
        std::strstr(response, "dispatched=1") == nullptr) {
        std::fprintf(stderr, "zygote-bootstrap failed: %s\n", response);
        return 1;
    }
    std::printf("bootstrap ok\n");
    std::fflush(stdout);

    std::snprintf(command, sizeof(command), "am force-stop %s >/dev/null 2>&1", package);
    system(command);
    usleep(800000);
    std::snprintf(command, sizeof(command),
                  "monkey -p %s -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1",
                  package);
    system(command);

    long target_pid = -1;
    for (int attempt = 0; attempt < 80 && target_pid <= 0; ++attempt) {
        target_pid = find_pid_by_cmdline(package);
        if (target_pid <= 0) usleep(500000);
    }
    if (target_pid <= 0) {
        std::fprintf(stderr, "target application did not start\n");
        return 1;
    }
    std::printf("app pid=%ld\n", target_pid);
    std::printf("daemon-status: ");
    std::snprintf(command, sizeof(command), "daemon-status %ld", target_pid);
    for (int attempt = 0; attempt < 100; ++attempt) {
        if (control(key, command, response, sizeof(response)) == 0 &&
            std::strstr(response, "phase=3 ") != nullptr) {
            std::printf("%s\n", response);
            std::printf("mako-hold=1 base=0x%lx pid=%ld (daemon left linked)\n", base,
                        target_pid);
            std::fflush(stdout);
            return 0;
        }
        usleep(200000);
    }
    std::printf("%s\n", response);
    std::fprintf(stderr, "daemon did not reach phase=3\n");
    return 1;
}

/* TEMPORARY crash bisection: run everything stage2-test does up to and
 * including bootstrap, then STOP. No app is launched, so a kernel freeze
 * right after this command isolates the bootstrap publish path from the
 * app fork path. */
int command_stage2_bisect(const char *key)
{
    constexpr const char *daemon_path = "/data/local/tmp/rtgum-stage1-pixel8/rtgum-stage2-daemon.so";
    constexpr const char *dispatch_name = "rtgum_stage2_daemon_dispatch";
    constexpr const char *module_path = "/data/local/tmp/rtgum-stage1-pixel8/rtgum-stage2-module.ghm";
    constexpr const char *package = "com.android.settings";
    char command[512];
    char response[kControlBufferSize];

    rtgum_su_profile profile{};
    profile.uid = static_cast<std::uint32_t>(getuid());
    profile.to_uid = 0;
    if (rtgum_sc_su(key, &profile) != 0 || getuid() != 0) {
        std::fprintf(stderr, "stage2-bisect requires SuperCall elevation\n");
        return 1;
    }

    std::printf("bisect step=hooks-start\n");
    std::fflush(stdout);
    if (control(key, "hook-comm", response, sizeof(response)) != 0 ||
        std::strncmp(response, "ok ", 3) != 0) {
        std::fprintf(stderr, "hook-comm failed: %s\n", response);
        return 1;
    }
    std::printf("bisect step=comm-ok\n");
    std::fflush(stdout);
    if (control(key, "hook-sysni", response, sizeof(response)) != 0 ||
        std::strncmp(response, "ok ", 3) != 0) {
        std::fprintf(stderr, "hook-sysni failed: %s\n", response);
        return 1;
    }
    std::printf("bisect step=sysni-ok\n");
    std::fflush(stdout);
    if (control(key, "hook-poll", response, sizeof(response)) != 0 ||
        std::strncmp(response, "ok ", 3) != 0) {
        std::fprintf(stderr, "hook-poll failed: %s\n", response);
        return 1;
    }
    std::printf("bisect step=poll-ok\n");
    std::fflush(stdout);
    if (control(key, "hook-epoll", response, sizeof(response)) != 0 ||
        std::strncmp(response, "ok ", 3) != 0) {
        std::fprintf(stderr, "hook-epoll failed: %s\n", response);
        return 1;
    }
    std::printf("bisect step=hooks-all-ok\n");
    std::fflush(stdout);

    long zygote_pid = -1;
    char process_name[32]{};
    char abi[16]{};
    const long expected_zygote_pid = find_pid_by_cmdline("zygote64", true);
    std::snprintf(command, sizeof(command), "zygote-find %ld", expected_zygote_pid);
    if (expected_zygote_pid <= 0 ||
        control(key, command, response, sizeof(response)) != 0 ||
        std::sscanf(response, "ok pid=%ld name=%31s abi=%15s", &zygote_pid, process_name, abi) != 3 ||
        zygote_pid != expected_zygote_pid || std::strcmp(process_name, "zygote64") != 0) {
        std::fprintf(stderr, "zygote-find failed: %s\n", response);
        return 1;
    }
    std::printf("bisect step=found pid=%ld\n", zygote_pid);
    std::fflush(stdout);

    std::snprintf(command, sizeof(command), "zygote-link %ld %s %s", zygote_pid,
                  daemon_path, dispatch_name);
    unsigned long base = 0;
    unsigned long entry = 0;
    unsigned long size = 0;
    unsigned int relocations = 0;
    unsigned int needed = 0;
    unsigned int imports = 0;
    unsigned int ifuncs = 0;
    unsigned int ready = 0;
    if (control(key, command, response, sizeof(response)) != 0 ||
        std::sscanf(response,
                    "ok pid=%*ld name=zygote64 base=0x%lx entry=0x%lx size=%lu relocations=%u needed=%u imports=%u ifuncs=%u ready=%u",
                    &base,
                    &entry,
                    &size,
                    &relocations,
                    &needed,
                    &imports,
                    &ifuncs,
                    &ready) != 8 ||
        base == 0 || size == 0) {
        std::fprintf(stderr, "zygote-link failed: %s\n", response);
        return 1;
    }
    std::printf("bisect step=linked base=0x%lx needed=%u imports=%u ifuncs=%u\n",
                base,
                needed,
                imports,
                ifuncs);
    std::fflush(stdout);

    unsigned long maps_address = 0;
    unsigned long maps_length = 0;
    if (!read_maps_into_ghost(key, zygote_pid, maps_address, maps_length)) {
        std::snprintf(command, sizeof(command), "zygote-unlink %ld 0x%lx", zygote_pid, base);
        control(key, command, response, sizeof(response));
        std::fprintf(stderr, "cannot stage Zygote maps into the ghost buffer\n");
        return 1;
    }
    std::snprintf(command,
                  sizeof(command),
                  "zygote-resolve %ld 0x%lx 0x%lx %lu",
                  zygote_pid,
                  base,
                  maps_address,
                  maps_length);
    unsigned int resolved_needed = 0;
    unsigned int resolved_imports = 0;
    unsigned int deferred_ifuncs = 0;
    const bool resolved =
        control(key, command, response, sizeof(response)) == 0 &&
        std::sscanf(response,
                    "ok pid=%*ld base=0x%*lx needed=%u imports=%u ifuncs=%u resolved=1",
                    &resolved_needed,
                    &resolved_imports,
                    &deferred_ifuncs) == 3;
    free_ghost_buffer(key, maps_address);
    if (!resolved || resolved_needed != needed || resolved_imports != imports) {
        std::fprintf(stderr, "zygote-resolve failed: %s\n", response);
        std::snprintf(command, sizeof(command), "zygote-unlink %ld 0x%lx", zygote_pid, base);
        control(key, command, response, sizeof(response));
        return 1;
    }
    std::printf("bisect step=resolved ifuncs=%u\n", deferred_ifuncs);
    std::fflush(stdout);

    std::snprintf(command,
                  sizeof(command),
                  "daemon-config %ld %s %s",
                  zygote_pid,
                  package,
                  module_path);
    if (control(key, command, response, sizeof(response)) != 0 ||
        std::strncmp(response, "ok ", 3) != 0) {
        std::fprintf(stderr, "daemon-config failed: %s\n", response);
        return 1;
    }
    std::printf("bisect step=configured\n");
    std::fflush(stdout);

    std::snprintf(command,
                  sizeof(command),
                  "zygote-bootstrap %ld 0x%lx 0x%lx 0x%lx",
                  zygote_pid,
                  base,
                  getauxval(AT_HWCAP),
                  getauxval(AT_HWCAP2));
    unsigned long trampoline = 0;
    unsigned long ctx = 0;
    unsigned int ifunc_slots = 0;
    if (control(key, command, response, sizeof(response)) != 0 ||
        std::sscanf(response,
                    "ok pid=%*ld base=0x%*lx trampoline=0x%lx ctx=0x%lx dispatch=0x%*lx status=0x%*lx fixup=%*lu ifunc_slots=%u dispatched=1",
                    &trampoline,
                    &ctx,
                    &ifunc_slots) != 3 ||
        trampoline == 0 || ctx == 0) {
        std::fprintf(stderr, "zygote-bootstrap failed: %s\n", response);
        return 1;
    }
    std::printf("bisect step=bootstrapped trampoline=0x%lx ctx=0x%lx ifunc_slots=%u\n",
                trampoline,
                ctx,
                ifunc_slots);
    std::fflush(stdout);
    std::printf("BISECT-READY pid=%ld base=0x%lx trampoline=0x%lx ctx=0x%lx\n",
                zygote_pid,
                base,
                trampoline,
                ctx);
    std::fflush(stdout);
    return 0;
}

int command_list(const char *key)
{
    char names[1024]{};
    const long result = rtgum_sc_kpm_list(key, names, sizeof(names));
    if (result < 0) return report_call_error("KPM list", result);
    std::printf("loaded-kpms count=%ld\n%s", rtgum_sc_kpm_nums(key), names);
    if (names[0] && names[std::strlen(names) - 1] != '\n') std::putchar('\n');
    return 0;
}

int command_info(const char *key)
{
    char info[1024]{};
    const long result = rtgum_sc_kpm_info(key, kModuleName, info, sizeof(info));
    if (result < 0) return report_call_error("KPM info", result);
    std::printf("module-info %s\n", info);
    return 0;
}

int command_unload(const char *key)
{
    char response[kControlBufferSize];
    if (control(key, "capabilities", response, sizeof(response)) != 0) return 1;
    const char *active_field = std::strstr(response, "active=");
    const char *busy_field = std::strstr(response, "busy=");
    const char *images_field = std::strstr(response, "images=");
    unsigned int active = 0;
    unsigned int busy = 0;
    unsigned int images = 0;
    if (!active_field || !busy_field || !images_field ||
        std::sscanf(active_field, "active=%u", &active) != 1 ||
        std::sscanf(busy_field, "busy=%u", &busy) != 1 ||
        std::sscanf(images_field, "images=%u", &images) != 1) {
        std::fprintf(stderr, "cannot prove that unload is safe: %s\n", response);
        return 1;
    }
    if (active != 0 || busy != 0 || images != 0) {
        std::fprintf(stderr,
                     "refusing to unload with live ghost state: active=%u busy=%u images=%u\n",
                     active,
                     busy,
                     images);
        return 1;
    }
    const long result = rtgum_sc_kpm_unload(key, kModuleName);
    if (result != 0) return report_call_error("KPM unload", result);
    std::printf("unloaded module=%s\n", kModuleName);
    return 0;
}

int command_dmesg(const char *key)
{
    rtgum_su_profile profile{};
    profile.uid = static_cast<std::uint32_t>(getuid());
    profile.to_uid = 0;
    const long result = rtgum_sc_su(key, &profile);
    if (result != 0) return report_call_error("temporary SuperCall elevation", result);
    if (getuid() != 0) {
        std::fprintf(stderr, "SuperCall elevation returned success but uid is not zero\n");
        return 1;
    }
    execl("/system/bin/dmesg", "dmesg", static_cast<char *>(nullptr));
    std::fprintf(stderr, "exec dmesg failed: %s\n", std::strerror(errno));
    return 1;
}

int command_dmesg_watch(const char *key)
{
    rtgum_su_profile profile{};
    profile.uid = static_cast<std::uint32_t>(getuid());
    profile.to_uid = 0;
    const long result = rtgum_sc_su(key, &profile);
    if (result != 0) return report_call_error("temporary SuperCall elevation", result);
    if (getuid() != 0) {
        std::fprintf(stderr, "SuperCall elevation returned success but uid is not zero\n");
        return 1;
    }
    execl("/system/bin/dmesg", "dmesg", "-w", static_cast<char *>(nullptr));
    std::fprintf(stderr, "exec dmesg -w failed: %s\n", std::strerror(errno));
    return 1;
}

/* TEMPORARY acceptance helper: elevated /proc hygiene scan. */
static int count_dir_entries(const char *path)
{
    int count = 0;
    DIR *directory = opendir(path);
    if (!directory) return -1;
    struct dirent *entry = nullptr;
    while ((entry = readdir(directory)) != nullptr) {
        if (entry->d_name[0] == '.') continue;
        ++count;
    }
    closedir(directory);
    return count;
}

static int count_file_lines_with(const char *path, const char *needle, unsigned long &hits)
{
    FILE *file = std::fopen(path, "r");
    if (!file) return -1;
    char buffer[512];
    hits = 0;
    const std::size_t needle_length = std::strlen(needle);
    while (std::fgets(buffer, sizeof(buffer), file) != nullptr) {
        /* maps/smaps rows start with the range start address: require the
         * needle at the line start followed by '-', so "998bd000" cannot
         * false-match inside "7998bd0000-...". */
        if (std::strncmp(buffer, needle, needle_length) == 0 &&
            buffer[needle_length] == '-')
            ++hits;
    }
    std::fclose(file);
    return 0;
}

int command_proc_scan(const char *key, const char *pid_text, int address_count, char **addresses)
{
    rtgum_su_profile profile{};
    profile.uid = static_cast<std::uint32_t>(getuid());
    profile.to_uid = 0;
    const long result = rtgum_sc_su(key, &profile);
    if (result != 0) return report_call_error("temporary SuperCall elevation", result);
    if (getuid() != 0) {
        std::fprintf(stderr, "SuperCall elevation returned success but uid is not zero\n");
        return 1;
    }
    const long pid = std::atol(pid_text);
    if (pid <= 0) return 1;
    std::printf("pid=%ld", pid);
    for (int index = 0; index < address_count; ++index) {
        char maps[64];
        char smaps[64];
        std::snprintf(maps, sizeof(maps), "/proc/%ld/maps", pid);
        std::snprintf(smaps, sizeof(smaps), "/proc/%ld/smaps", pid);
        unsigned long maps_hits = 0;
        unsigned long smaps_hits = 0;
        const int maps_ok = count_file_lines_with(maps, addresses[index], maps_hits);
        const int smaps_ok = count_file_lines_with(smaps, addresses[index], smaps_hits);
        std::printf(" addr=%s maps=%lu%s smaps=%lu%s",
                    addresses[index],
                    maps_hits,
                    maps_ok == 0 ? "" : "(read-failed)",
                    smaps_hits,
                    smaps_ok == 0 ? "" : "(read-failed)");
    }
    char path[64];
    std::snprintf(path, sizeof(path), "/proc/%ld/task", pid);
    const int tasks = count_dir_entries(path);
    std::snprintf(path, sizeof(path), "/proc/%ld/fd", pid);
    const int fds = count_dir_entries(path);
    int sockets = 0;
    if (fds > 0) {
        DIR *directory = opendir(path);
        if (directory) {
            struct dirent *entry = nullptr;
            while ((entry = readdir(directory)) != nullptr) {
                if (entry->d_name[0] == '.') continue;
                char link[96];
                char target[128];
                std::snprintf(link, sizeof(link), "/proc/%ld/fd/%s", pid, entry->d_name);
                const ssize_t length = readlink(link, target, sizeof(target) - 1U);
                if (length > 0) {
                    target[length] = '\0';
                    if (std::strstr(target, "socket:") != nullptr) ++sockets;
                }
            }
            closedir(directory);
        }
    }
    std::printf(" tasks=%d fds=%d sockets=%d\n", tasks, fds, sockets);
    return 0;
}

/* TEMPORARY diagnostic: elevated dump of the latest crash tombstone. */
/* TEMPORARY diagnostic: elevated dump of an arbitrary file. */
int command_file_dump(const char *key, const char *path)
{
    rtgum_su_profile profile{};
    profile.uid = static_cast<std::uint32_t>(getuid());
    profile.to_uid = 0;
    const long result = rtgum_sc_su(key, &profile);
    if (result != 0) return report_call_error("temporary SuperCall elevation", result);
    if (getuid() != 0) return 1;
    FILE *file = std::fopen(path, "r");
    if (!file) {
        std::fprintf(stderr, "cannot open %s\n", path);
        return 1;
    }
    char buffer[4096];
    std::size_t length = 0;
    while ((length = std::fread(buffer, 1, sizeof(buffer), file)) != 0)
        std::fwrite(buffer, 1, length, stdout);
    std::fclose(file);
    return 0;
}

int command_tombstone(const char *key){
    rtgum_su_profile profile{};
    profile.uid = static_cast<std::uint32_t>(getuid());
    profile.to_uid = 0;
    const long result = rtgum_sc_su(key, &profile);
    if (result != 0) return report_call_error("temporary SuperCall elevation", result);
    if (getuid() != 0) return 1;
    char latest[96]{};
    DIR *directory = opendir("/data/tombstones");
    if (!directory) {
        std::fprintf(stderr, "cannot open /data/tombstones\n");
        return 1;
    }
    struct dirent *entry = nullptr;
    while ((entry = readdir(directory)) != nullptr) {
        if (entry->d_name[0] == '.') continue;
        std::snprintf(latest, sizeof(latest), "/data/tombstones/%s", entry->d_name);
    }
    closedir(directory);
    if (latest[0] == '\0') {
        std::printf("no tombstones\n");
        return 0;
    }
    std::printf("=== %s ===\n", latest);
    FILE *file = std::fopen(latest, "r");
    if (!file) return 1;
    char buffer[4096];
    std::size_t length = 0;
    while ((length = std::fread(buffer, 1, sizeof(buffer), file)) != 0)
        std::fwrite(buffer, 1, length, stdout);
    std::fclose(file);
    std::printf("\n");
    return 0;
}

int command_pstore(const char *key)
{
    rtgum_su_profile profile{};
    profile.uid = static_cast<std::uint32_t>(getuid());
    profile.to_uid = 0;
    const long result = rtgum_sc_su(key, &profile);
    if (result != 0) return report_call_error("temporary SuperCall elevation", result);
    if (getuid() != 0) {
        std::fprintf(stderr, "SuperCall elevation returned success but uid is not zero\n");
        return 1;
    }
    DIR *directory = opendir("/sys/fs/pstore");
    if (!directory) {
        std::fprintf(stderr, "cannot open /sys/fs/pstore: %s\n", std::strerror(errno));
        return 1;
    }
    struct dirent *entry = nullptr;
    bool any = false;
    while ((entry = readdir(directory)) != nullptr) {
        if (entry->d_name[0] == '.') continue;
        char path[160];
        std::snprintf(path, sizeof(path), "/sys/fs/pstore/%s", entry->d_name);
        FILE *file = std::fopen(path, "r");
        if (!file) continue;
        any = true;
        std::printf("=== %s ===\n", entry->d_name);
        char buffer[4096];
        std::size_t length = 0;
        while ((length = std::fread(buffer, 1, sizeof(buffer), file)) != 0)
            std::fwrite(buffer, 1, length, stdout);
        std::fclose(file);
        std::printf("\n");
    }
    closedir(directory);
    if (!any) std::printf("pstore empty\n");
    return 0;
}

bool module_is_loaded(const char *key)
{
    char info[256]{};
    return rtgum_sc_kpm_info(key, kModuleName, info, sizeof(info)) >= 0;
}

int command_probe(const char *key, const char *path)
{
    if (command_ready(key) != 0) return 1;
    if (!module_is_loaded(key)) {
        if (command_load(key, path) != 0) return 1;
    } else {
        std::printf("reuse-loaded module=%s\n", kModuleName);
    }
    if (command_ping(key) != 0) return 1;
    if (command_control(key, "capabilities") != 0) return 1;
    std::puts("stage1-probe PASS");
    return 0;
}

} // namespace

int main(int argc, char **argv)
{
    /* adb shell captures stdout through a pipe, so libc would otherwise retain
     * the last diagnostic block across a kernel panic.  Device acceptance
     * output is deliberately unbuffered to make the failing phase observable. */
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::setvbuf(stderr, nullptr, _IONBF, 0);
    if (argc < 2) {
        usage(argv[0]);
        return 2;
    }
    const char *key = require_key();
    if (!key) return 2;
    const char *command = argv[1];

    if (!std::strcmp(command, "ready")) return command_ready(key);
    if (!std::strcmp(command, "load") && argc == 3) return command_load(key, argv[2]);
    if (!std::strcmp(command, "load-nohooks") && argc == 3)
        return command_load_nohooks(key, argv[2]);
    if (!std::strcmp(command, "load-args") && argc == 4)
        return command_load_args(key, argv[2], argv[3]);
    if (!std::strcmp(command, "ping")) return command_ping(key);
    if (!std::strcmp(command, "capabilities")) return command_control(key, "capabilities");
    if (!std::strcmp(command, "auth-status"))
        return command_session_enrollment(key, "auth-status");
    if (!std::strcmp(command, "pid-probe") && argc == 3) {
        char inner[64];
        std::snprintf(inner, sizeof(inner), "pid-probe %s", argv[2]);
        return command_control(key, inner);
    }
    if (!std::strcmp(command, "session-manager"))
        return command_session_enrollment(key, "session-manager");
    if (!std::strcmp(command, "session-pair") && argc == 3) {
        char enrollment[64];
        std::snprintf(enrollment, sizeof(enrollment), "session-pair %s", argv[2]);
        return command_session_enrollment(key, enrollment);
    }
    if (!std::strcmp(command, "zygote-find") && argc == 3) {
        char inner[64];
        std::snprintf(inner, sizeof(inner), "zygote-find %s", argv[2]);
        return command_control(key, inner);
    }
    if (!std::strcmp(command, "zygote-test")) return command_zygote_test(key);
    if (!std::strcmp(command, "zygote-test-keep")) return command_zygote_test_keep(key);
    if (!std::strcmp(command, "stage2-test") && argc == 3)
        return command_stage2_test(key, argv[2]);
    if (!std::strcmp(command, "stage2-bisect")) return command_stage2_bisect(key);
    if (!std::strcmp(command, "channel-test")) return command_channel_test();
    if (!std::strcmp(command, "syscall244")) {
        errno = 0;
        const long result = syscall(244L, 0L, 0L, 0L, 0L, 0L, 0L);
        const int saved_errno = errno;
        std::printf("syscall244 result=%ld errno=%d\n", result, saved_errno);
        return result == -1L && saved_errno == ENOSYS ? 0 : 1;
    }
    if (!std::strcmp(command, "syscall283")) {
        errno = 0;
        const long result = syscall(RTGUM_DAEMON_SYSCALL, 0L, 0L, 0L, 0L, 0L, 0L);
        const int saved_errno = errno;
        std::printf("syscall283 result=%ld errno=%d\n", result, saved_errno);
        return result >= 0L && saved_errno == 0 ? 0 : 1;
    }
    if (!std::strcmp(command, "hijack-self-test"))
        return command_hijack_self_test(key);
    if (!std::strcmp(command, "taskwork-self-test"))
        return command_taskwork_selftest(key);
    if (!std::strcmp(command, "shadow-lab-test"))
        return command_shadow_lab_test(key);
    if (!std::strcmp(command, "shadow-brk-test"))
        return command_shadow_brk_test(key);
    if (!std::strcmp(command, "ghost-stress-lab-test"))
        return command_ghost_stress_lab_test(key);
    if (!std::strcmp(command, "hwbp-lab-test"))
        return command_hwbp_lab_test(key);
    if (!std::strcmp(command, "antidbg-lab-test"))
        return command_antidbg_lab_test(key);
    if (!std::strcmp(command, "shadowhook-lifecycle-test"))
        return command_shadowhook_lifecycle_test(key);
    if (!std::strcmp(command, "antidbg-ebpf-probe"))
        return command_antidbg_ebpf_probe(key);
    if (!std::strcmp(command, "read-user-race-test"))
        return command_read_user_race_test(key);
    if (!std::strcmp(command, "dbi-ldr-test"))
        return command_dbi_ldr_test(key);
    if (!std::strcmp(command, "dbi-lab-test"))
        return command_dbi_lab_test(key);
    if (!std::strcmp(command, "dbi-stalker-test"))
        return command_dbi_stalker_lab();
    if (!std::strcmp(command, "dbi-stalker-unwind-test"))
        return command_dbi_stalker_lab(true);
    if (!std::strcmp(command, "dbi-stalker-phdr-test"))
        return command_dbi_stalker_lab(false, true);
    if (!std::strcmp(command, "dbi-stalker-pac-test"))
        return command_dbi_stalker_pac_test();
    if (!std::strcmp(command, "dbi-stalker-bti-test"))
        return command_dbi_stalker_bti_test();
    if (!std::strcmp(command, "dbi-hardening-test"))
        return command_dbi_hardening_test();
    if (!std::strcmp(command, "dbi-apk-test")) {
        if (argc < 4) {
            std::fprintf(stderr,
                         "usage: dbi-apk-test <pid> <va> [symbol] [length]\n");
            return 1;
        }
        const char *symbol = argc >= 5 ? argv[4] : "epoll_wait";
        const unsigned long length =
            argc >= 6 ? std::strtoul(argv[5], nullptr, 0) : 64UL;
        return command_dbi_apk_test(key, std::strtol(argv[2], nullptr, 0),
                                    std::strtoul(argv[3], nullptr, 0), symbol,
                                    length);
    }
    if (!std::strcmp(command, "hwbp-worker-bisect"))
        return command_hwbp_worker_bisect(key);
    if (!std::strcmp(command, "hwbp-remote-bisect"))
        return command_hwbp_remote_bisect(key);
    if (!std::strcmp(command, "three-apps-gumlua-test"))
        return command_gumlua_targets_test(key, false);
    if (!std::strcmp(command, "gumlua-target-test") &&
        (argc == 5 || argc == 6)) {
        const unsigned long quiet = argc == 6 ? std::strtoul(argv[5], nullptr, 0) : 0UL;
        if (quiet > 120UL) {
            std::fprintf(stderr, "quiet-seconds must be between 0 and 120\n");
            return 2;
        }
        return command_gumlua_targets_test(key, false, false, argv[2], argv[3],
                                           argv[4], static_cast<unsigned int>(quiet));
    }
    if (!std::strcmp(command, "three-apps-dbi-test"))
        return command_gumlua_targets_test(key, true);
    if (!std::strcmp(command, "three-apps-dbi-stalker-test"))
        return command_gumlua_targets_test(key, true, true);
    if (!std::strcmp(command, "hook-probe")) return command_hook_probe();
    if (!std::strcmp(command, "comm-probe")) return command_comm_probe();
    if (!std::strcmp(command, "stage2-sandbox-test"))
        return command_stage2_sandbox_test(key);
    if (!std::strcmp(command, "zygote-init-test"))
        return command_zygote_init_test(key, 0);
    if (!std::strcmp(command, "zygote-fork-test"))
        return command_zygote_init_test(key, 1);
    if (!std::strcmp(command, "zygote-package-test"))
        return command_zygote_init_test(key, 2);
    if (!std::strcmp(command, "zygote-reload-test"))
        return command_zygote_init_test(key, 3);
    if (!std::strcmp(command, "zygote-jnicode-test"))
        return command_zygote_init_test(key, 4);
    if (!std::strcmp(command, "zygote-jnicode-java-test"))
        return command_zygote_init_test(key, 5);
    if (!std::strcmp(command, "zygote-jnicode-badver-test"))
        return command_zygote_init_test(key, 6);
    if (!std::strcmp(command, "zygote-jnicode-nosym-test"))
        return command_zygote_init_test(key, 7);
    if (!std::strcmp(command, "zygote-jnicode-mako-test"))
        return command_zygote_init_test(key, 9);
    if (!std::strcmp(command, "mako-target-test") && argc == 4)
        return command_zygote_init_test(key, 9, argv[2], argv[3]);
    if (!std::strcmp(command, "symbol-target-test") && argc == 4)
        return command_zygote_init_test(key, 10, argv[2], argv[3]);
    if (!std::strcmp(command, "zygote-dex-test"))
        return command_zygote_init_test(
            key, 11, "dev.rtgum.lab", "dev.rtgum.lab/dev.rtgum.lab.MainActivity");
    if (!std::strcmp(command, "zygote-interceptor-test"))
        return command_zygote_init_test(
            key, 12, "dev.rtgum.lab", "dev.rtgum.lab/dev.rtgum.lab.MainActivity");
    if (!std::strcmp(command, "zygote-lifecycle-test"))
        return command_zygote_init_test(
            key, 13, "dev.rtgum.lab", "dev.rtgum.lab/dev.rtgum.lab.MainActivity");
    if (!std::strcmp(command, "zygote-gtrace-test"))
        return command_zygote_init_test(
            key, 14, "dev.rtgum.lab", "dev.rtgum.lab/dev.rtgum.lab.MainActivity");
    if (!std::strcmp(command, "zygote-multitrace-test"))
        return command_zygote_init_test(
            key, 15, "dev.rtgum.lab", "dev.rtgum.lab/dev.rtgum.lab.MainActivity");
    /* Same sequence as mako-target-test but it leaves the Daemon linked and the
     * target running, so the hook and the lab's self-check stay observable.
     * Iterating on the ART path needs that: the packaged scenario asserts, then
     * tears everything down, which hides the evidence of whatever it tripped on.
     * It also starts the app with `monkey -p` (like stage2-test) rather than an
     * explicit component: the launcher intent is what the app is registered
     * for, and `am start -n` returned before the process existed in some runs. */
    if (!std::strcmp(command, "mako-hold-test") && argc == 3)
        return command_mako_hold(key, argv[2]);
    if (!std::strcmp(command, "mako-manager-test") && argc == 3)
        return command_mako_hold(key, argv[2], true);
    if (!std::strcmp(command, "trace-start"))
        return command_trace_start(key, argc, argv);
    if (!std::strcmp(command, "trace-status") && argc == 3)
        return command_trace_simple(key, "status", argv[2]);
    if (!std::strcmp(command, "trace-read") && (argc == 3 || argc == 4))
        return command_trace_read(key, argv[2], argc == 4 ? argv[3] : nullptr);
    if (!std::strcmp(command, "gtrace-read") && (argc == 6 || argc == 7))
        return command_gtrace_read(key, argc, argv);
    if (!std::strcmp(command, "trace-stop") && argc == 3)
        return command_trace_simple(key, "stop", argv[2]);
    if (!std::strcmp(command, "trace-clear") && argc == 3)
        return command_trace_simple(key, "clear", argv[2]);
    if (!std::strcmp(command, "memory-read") && (argc == 4 || argc == 5))
        return command_memory_read(key, argv[2], argv[3], argc == 5 ? argv[4] : nullptr);
    if (!std::strcmp(command, "memory-write") && argc == 5)
        return command_memory_write(key, argv[2], argv[3], argv[4]);
    if (!std::strcmp(command, "memory-status"))
        return command_control(key, "mem-status");
    if (!std::strcmp(command, "vma-dump") && argc == 3)
        return command_vma_dump(key, argv[2]);
    if (!std::strcmp(command, "vma-symbolize") && argc == 5)
        return command_vma_symbolize(key, argv[2], argv[3], argv[4]);
    if (!std::strcmp(command, "vma-proc-baseline") && argc == 3)
        return command_vma_proc_baseline(key, argv[2]);
    if (!std::strcmp(command, "vma-test-ghost-alloc") && argc == 3)
        return command_vma_test_ghost(key, "alloc", argv[2], nullptr);
    if (!std::strcmp(command, "vma-test-ghost-free") && argc == 4)
        return command_vma_test_ghost(key, "free", argv[2], argv[3]);
    if (!std::strcmp(command, "shadow-hook-enable") && argc == 2)
        return command_control(key, "hook-shadow-hook");
    if (!std::strcmp(command, "shadow-preflight") && argc == 4) {
        char inner[96];
        std::snprintf(inner, sizeof(inner), "shadow-preflight %s %s", argv[2], argv[3]);
        return command_control(key, inner);
    }
    if (!std::strcmp(command, "shadow-prepare") && argc == 4) {
        char inner[96];
        std::snprintf(inner, sizeof(inner), "shadow-prepare %s %s", argv[2], argv[3]);
        return command_control(key, inner);
    }
    if (!std::strcmp(command, "shadow-install") && argc == 4) {
        char inner[96];
        std::snprintf(inner, sizeof(inner), "shadow-install %s %s", argv[2], argv[3]);
        return command_control(key, inner);
    }
    if (!std::strcmp(command, "shadow-patch-code") && argc == 5) {
        char inner[512];
        std::snprintf(inner, sizeof(inner), "shadow-code-patch %s %s %s",
                      argv[2], argv[3], argv[4]);
        return command_control(key, inner);
    }
    if (!std::strcmp(command, "shadow-release-page") && argc == 4) {
        char inner[96];
        std::snprintf(inner, sizeof(inner), "shadow-release %s %s", argv[2], argv[3]);
        return command_control(key, inner);
    }
    if (!std::strcmp(command, "shadow-hook-status") && argc == 2)
        return command_control(key, "shadowhook-status");
    if (!std::strcmp(command, "zygote-daemon-replace-test"))
        return command_zygote_init_test(key, 8);
    if (!std::strcmp(command, "syscall279")) {
        errno = 0;
        const long result = syscall(279L, 0L, 0L, 0L, 0L, 0L, 0L);
        std::printf("syscall279 result=%ld errno=%d\n", result, errno);
        return 0;
    }
    if (!std::strcmp(command, "daemon-status") && argc == 3) {
        char inner[64];
        std::snprintf(inner, sizeof(inner), "daemon-status %s", argv[2]);
        return command_control(key, inner);
    }
    if (!std::strcmp(command, "daemon-reload") && argc == 5) {
        char inner[512];
        std::snprintf(inner, sizeof(inner), "daemon-reload %s %s %s", argv[2], argv[3], argv[4]);
        return command_control(key, inner);
    }
    if (!std::strcmp(command, "daemon-shutdown") && argc == 3) {
        char inner[64];
        std::snprintf(inner, sizeof(inner), "daemon-shutdown %s", argv[2]);
        return command_control(key, inner);
    }
    if (!std::strcmp(command, "daemon-config") && argc == 4) {
        char inner[512];
        std::snprintf(inner, sizeof(inner), "daemon-config 1 %s %s", argv[2], argv[3]);
        return command_control(key, inner);
    }
    if (!std::strcmp(command, "proc-scan") && argc >= 4)
        return command_proc_scan(key, argv[2], argc - 3, &argv[3]);
    if (!std::strcmp(command, "file-dump") && argc == 3)
        return command_file_dump(key, argv[2]);
    if (!std::strcmp(command, "ghost-test")) return command_ghost_test(key);
    if (!std::strcmp(command, "ghost-race-test")) return command_ghost_race_test(key);
    if (!std::strcmp(command, "hwbp-test")) return command_hwbp_test(key);
    if (!std::strcmp(command, "hwbp-probe-test")) return command_hwbp_probe_test(key);
    if (!std::strcmp(command, "hwbp-replace-test")) return command_hwbp_replace_test(key);
    if (!std::strcmp(command, "hwbp-capacity-test")) return command_hwbp_capacity_test(key);
    if (!std::strcmp(command, "unload-guard-test")) return command_unload_guard_test(key);
    if (!std::strcmp(command, "shadow-selftest")) return command_shadow_selftest(key);
    if (!std::strcmp(command, "fork-test")) return command_fork_test(key);
    if (!std::strcmp(command, "linker-test")) return command_linker_test(key);
    if (!std::strcmp(command, "needed-ifunc-test")) return command_needed_ifunc_test(key);
    if (!std::strcmp(command, "needed-version-reject-test"))
        return command_needed_ifunc_test(key, NeededFailure::Version);
    if (!std::strcmp(command, "needed-maps-ambiguous-test"))
        return command_needed_ifunc_test(key, NeededFailure::AmbiguousMaps);
    if (!std::strcmp(command, "needed-file-mismatch-test"))
        return command_needed_ifunc_test(key, NeededFailure::FileMismatch);
    if (!std::strcmp(command, "real-so-test")) return command_real_so_test(key);
    if (!std::strcmp(command, "control") && argc == 3) return command_control(key, argv[2]);
    if (!std::strcmp(command, "list")) return command_list(key);
    if (!std::strcmp(command, "info")) return command_info(key);
    if (!std::strcmp(command, "dmesg")) return command_dmesg(key);
    if (!std::strcmp(command, "dmesg-w")) return command_dmesg_watch(key);
    if (!std::strcmp(command, "pstore-dump")) return command_pstore(key);
    if (!std::strcmp(command, "tombstone-dump")) return command_tombstone(key);
    if (!std::strcmp(command, "unload")) return command_unload(key);
    if (!std::strcmp(command, "probe") && argc == 3) return command_probe(key, argv[2]);

    usage(argv[0]);
    return 2;
}
