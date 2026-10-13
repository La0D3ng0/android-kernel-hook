#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PTRACE_GETHBPREGS
#define PTRACE_GETHBPREGS 29
#endif
#ifndef PTRACE_SETHBPREGS
#define PTRACE_SETHBPREGS 30
#endif

namespace {

__attribute__((noinline)) std::uint32_t CompatTarget(std::uint32_t value)
{
    asm volatile("nop\n\tnop\n\tnop\n\tnop" ::: "memory");
    return value + 1U;
}

alignas(4) volatile std::uint32_t CompatWatchWord = 0x52544755U;

long HbpGet(pid_t child, int number, std::uint32_t &value)
{
    errno = 0;
    return ptrace(PTRACE_GETHBPREGS, child,
                  reinterpret_cast<void *>(number), &value);
}

long HbpSet(pid_t child, int number, std::uint32_t value)
{
    errno = 0;
    return ptrace(PTRACE_SETHBPREGS, child,
                  reinterpret_cast<void *>(number), &value);
}

bool EmptySlots(pid_t child, unsigned int slots, bool watch)
{
    for (unsigned int index = 0; index < slots; ++index) {
        const int address_number = static_cast<int>(index * 2U + 1U) *
            (watch ? -1 : 1);
        const int control_number = static_cast<int>(index * 2U + 2U) *
            (watch ? -1 : 1);
        std::uint32_t address = ~0U;
        std::uint32_t control = ~0U;
        if (HbpGet(child, address_number, address) != 0 ||
            HbpGet(child, control_number, control) != 0 ||
            address != 0U || control != 0U)
            return false;
    }
    return true;
}

bool ProgramAndVerify(pid_t child, unsigned int slots, bool watch,
                      std::uint32_t address, std::uint32_t control)
{
    for (unsigned int index = 0; index < slots; ++index) {
        const int address_number = static_cast<int>(index * 2U + 1U) *
            (watch ? -1 : 1);
        const int control_number = static_cast<int>(index * 2U + 2U) *
            (watch ? -1 : 1);
        if (HbpSet(child, address_number, address) != 0 ||
            HbpSet(child, control_number, control) != 0)
            return false;
        std::uint32_t observed_address = 0U;
        std::uint32_t observed_control = 0U;
        if (HbpGet(child, address_number, observed_address) != 0 ||
            HbpGet(child, control_number, observed_control) != 0 ||
            observed_address != address || observed_control != control)
            return false;
    }
    return true;
}

}  // namespace

int main()
{
    constexpr std::uint32_t kExecuteEl0 =
        1U | (2U << 1U) | (0xfU << 5U);
    constexpr std::uint32_t kWatchWriteEl0 =
        1U | (2U << 1U) | (2U << 3U) | (0xfU << 5U);

    const pid_t child = fork();
    if (child < 0) return 2;
    if (child == 0) {
        (void)prctl(PR_SET_NAME, "dev.rtgum.lab", 0, 0, 0);
        if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) != 0) _exit(31);
        raise(SIGSTOP);
        CompatWatchWord ^= 0x01010101U;
        if (CompatTarget(8U) != 9U) _exit(32);
        raise(SIGSTOP);
        _exit(0);
    }

    int status = 0;
    if (waitpid(child, &status, 0) != child || !WIFSTOPPED(status)) {
        kill(child, SIGKILL);
        waitpid(child, nullptr, 0);
        return 3;
    }
    std::uint32_t resources = 0U;
    if (HbpGet(child, 0, resources) != 0) return 4;
    const unsigned int brp = resources & 0xffU;
    const unsigned int wrp = (resources >> 8U) & 0xffU;
    if (brp == 0U || brp > 16U || wrp == 0U || wrp > 16U ||
        !EmptySlots(child, brp, false) || !EmptySlots(child, wrp, true))
        return 5;

    const std::uint32_t execute_address = static_cast<std::uint32_t>(
        reinterpret_cast<std::uintptr_t>(&CompatTarget));
    const std::uint32_t watch_address = static_cast<std::uint32_t>(
        reinterpret_cast<std::uintptr_t>(
            const_cast<std::uint32_t *>(&CompatWatchWord)));
    if (!ProgramAndVerify(child, brp, false, execute_address, kExecuteEl0) ||
        !ProgramAndVerify(child, wrp, true, watch_address, kWatchWriteEl0))
        return 6;

    std::uint32_t overflow_address = execute_address;
    errno = 0;
    const int next_break_address = static_cast<int>(brp * 2U + 1U);
    if (ptrace(PTRACE_SETHBPREGS, child,
               reinterpret_cast<void *>(next_break_address),
               &overflow_address) != -1 || errno != EINVAL)
        return 7;
    errno = 0;
    const int next_watch_address =
        -static_cast<int>(wrp * 2U + 1U);
    if (ptrace(PTRACE_SETHBPREGS, child,
               reinterpret_cast<void *>(next_watch_address),
               &overflow_address) != -1 || errno != EINVAL)
        return 8;

    if (ptrace(PTRACE_CONT, child, nullptr, nullptr) != 0 ||
        waitpid(child, &status, 0) != child || !WIFSTOPPED(status) ||
        WSTOPSIG(status) != SIGSTOP)
        return 9;

    for (unsigned int index = 0; index < brp; ++index) {
        const int number = static_cast<int>(index * 2U + 2U);
        if (HbpSet(child, number, 0U) != 0) return 10;
    }
    for (unsigned int index = 0; index < wrp; ++index) {
        const int number = -static_cast<int>(index * 2U + 2U);
        if (HbpSet(child, number, 0U) != 0) return 11;
    }
    if (ptrace(PTRACE_DETACH, child, nullptr, nullptr) != 0 ||
        waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0)
        return 12;

    std::printf("compat32 resources=0x%08x brp=%u wrp=%u "
                "roundtrip=1 overflow=-EINVAL active-fake-trap=0 cleanup=1\n",
                resources, brp, wrp);
    std::puts("stage1-antidbg-compat32 PASS");
    return 0;
}
