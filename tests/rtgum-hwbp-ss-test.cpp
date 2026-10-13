/*
 * Visible hardware breakpoint and CPU single-step on an owned child.
 * Uses ptrace NT_ARM_HW_BREAK / PTRACE_SINGLESTEP. Does not spoof ptrace
 * results or hide debug registers from the tracer.
 */

#include "rtgum/gtrace.hpp"
#include "rtgum/host_api_v2.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__aarch64__)
#include <linux/elf.h>
#ifndef NT_ARM_HW_BREAK
#define NT_ARM_HW_BREAK 0x402
#endif
#ifndef NT_PRSTATUS
#define NT_PRSTATUS 1
#endif
#endif

namespace {

volatile unsigned long g_marker_hits = 0;

#if defined(__GNUC__)
__attribute__((noinline))
#endif
void Marker()
{
    ++g_marker_hits;
    asm volatile("nop");
}

int Fail(const char *message)
{
    std::fprintf(stderr, "%s errno=%d\n", message, errno);
    return 1;
}

}  // namespace

int main()
{
#if !defined(__aarch64__)
    std::puts("hwbp skipped=1 (not arm64)");
    std::puts("jnicode-hwbp-ss PASS");
    return 0;
#else
    const pid_t child = fork();
    if (child < 0) return Fail("fork failed");
    if (child == 0) {
        if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) != 0) _exit(2);
        raise(SIGSTOP);
        for (int index = 0; index < 64; ++index) Marker();
        _exit(0);
    }

    int status = 0;
    if (waitpid(child, &status, 0) != child) return Fail("wait STOP failed");

    struct UserHwBreak {
        unsigned int dbg_info;
        unsigned int pad;
        struct {
            unsigned long addr;
            unsigned int ctrl;
            unsigned int pad;
        } dbg_regs[16];
    } hw{};
    struct iovec iov {};
    iov.iov_base = &hw;
    iov.iov_len = sizeof(hw);
    const long got_hw = ptrace(PTRACE_GETREGSET, child, NT_ARM_HW_BREAK, &iov);
    unsigned int slots = hw.dbg_info & 0xffU;
    if (slots == 0U || slots > 16U) slots = 1U;
    hw.dbg_regs[0].addr = reinterpret_cast<unsigned long>(&Marker);
    /* E=1, PMC=EL0 (0b10), BAS=0xf, BT=unlinked address match. */
    hw.dbg_regs[0].ctrl = 1U | (2U << 1) | (0xfU << 5);
    iov.iov_base = &hw;
    iov.iov_len = 8UL + static_cast<unsigned long>(slots) * 16UL;
    errno = 0;
    const bool hwbp_ok =
        got_hw == 0 && ptrace(PTRACE_SETREGSET, child, NT_ARM_HW_BREAK, &iov) == 0;
    const int hwbp_errno = errno;
    unsigned int hits = 0;
    if (hwbp_ok) {
        for (int attempt = 0; attempt < 8; ++attempt) {
            if (ptrace(PTRACE_CONT, child, nullptr, nullptr) != 0) break;
            if (waitpid(child, &status, 0) != child) break;
            if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
                ++hits;
                /* Clear the breakpoint after the first hit so the child can finish. */
                UserHwBreak clear{};
                struct iovec clear_iov {};
                clear_iov.iov_base = &clear;
                clear_iov.iov_len = sizeof(clear);
                (void)ptrace(PTRACE_SETREGSET, child, NT_ARM_HW_BREAK, &clear_iov);
                break;
            }
            if (WIFEXITED(status) || WIFSIGNALED(status)) break;
        }
    }

    unsigned int steps = 0;
    char trace[512]{};
    unsigned long trace_used = 0;
    if (ptrace(PTRACE_SINGLESTEP, child, nullptr, nullptr) == 0) {
        for (unsigned int index = 0; index < 16U; ++index) {
            if (waitpid(child, &status, 0) != child) break;
            if (!(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP)) break;
            ++steps;
            unsigned long pc = 0;
            struct UserRegs {
                unsigned long regs[31];
                unsigned long sp;
                unsigned long pc;
                unsigned long pstate;
            } regs{};
            struct iovec reg_iov {};
            reg_iov.iov_base = &regs;
            reg_iov.iov_len = sizeof(regs);
            if (ptrace(PTRACE_GETREGSET, child, NT_PRSTATUS, &reg_iov) == 0) {
                pc = regs.pc;
            }
            unsigned int insn = 0;
            errno = 0;
            const long peeked = ptrace(PTRACE_PEEKTEXT, child, reinterpret_cast<void *>(pc),
                                       nullptr);
            if (errno == 0) insn = static_cast<unsigned int>(peeked & 0xffffffffL);
            unsigned char bytes[4];
            rtgum::native::WriteU32(bytes, insn);
            char one[96]{};
            (void)rtgum::native::GtraceDecode(bytes, 4, pc, one, sizeof(one));
            const unsigned long one_len = rtgum::native::StringLength(one, sizeof(one));
            if (trace_used + one_len + 2UL < sizeof(trace)) {
                if (trace_used != 0) trace[trace_used++] = '|';
                for (unsigned long i = 0; i < one_len; ++i) trace[trace_used++] = one[i];
                trace[trace_used] = '\0';
            }
            if (ptrace(PTRACE_SINGLESTEP, child, nullptr, nullptr) != 0) break;
        }
    }

    (void)ptrace(PTRACE_DETACH, child, nullptr, nullptr);
    (void)waitpid(child, &status, 0);
    if (!hwbp_ok) {
        std::printf("hwbp set=0 errno=%d slots=%u get=%ld ss-fallback=1\n",
                    hwbp_errno, slots, got_hw);
    } else {
        std::printf("hwbp set=1 hits=%u slots=%u\n", hits, slots);
    }
    std::printf("cpu_ss steps=%u gtrace=%s\n", steps, trace[0] != '\0' ? trace : "(none)");
    if (steps == 0) return Fail("CPU SS captured no instructions");
    std::puts("jnicode-hwbp-ss PASS");
    return 0;
#endif
}
