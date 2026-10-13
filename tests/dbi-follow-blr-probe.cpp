// Focused device probe: a logged BLR return address must match the address
// the processor writes to LR, even when the relocated call still returns.
#include "../tools/dbi/rtgum-dbi.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <sys/mman.h>

extern "C" long dbi_blr_fixture(long (*target)());
extern "C" __attribute__((noinline)) long dbi_blr_target() { return 0x1234; }

__asm__(
    ".text\n"
    ".align 2\n"
    ".global dbi_blr_fixture\n"
    ".type dbi_blr_fixture, %function\n"
    "dbi_blr_fixture:\n"
    "stp x29, x30, [sp, #-16]!\n"
    "mov x29, sp\n"
    "blr x0\n"
    "ldp x29, x30, [sp], #16\n"
    "ret\n"
    ".size dbi_blr_fixture, .-dbi_blr_fixture\n");

int main()
{
    constexpr size_t kCodePage = 4096;
    constexpr size_t kInputBytes = 20;
    void *clone = mmap(nullptr, 2 * kCodePage, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (clone == MAP_FAILED) return 2;

    auto *records = reinterpret_cast<rtgum_dbi::SiteRecord *>(
        reinterpret_cast<uintptr_t>(clone) + kCodePage);
    records[0] = {};
    uint8_t code[512]{};
    rtgum_dbi::OffsetMapEntry map[5]{};
    rtgum_dbi::BranchTraceEntry trace[5]{};
    rtgum_dbi::LiteralRange literals[8]{};
    auto result = rtgum_dbi::make_result(code, sizeof(code), map, 5, trace, 5,
                                         literals, 8);
    result.dispatcher = {true, 1, reinterpret_cast<uintptr_t>(records),
                         sizeof(rtgum_dbi::SiteRecord), 8};
    const uintptr_t source = reinterpret_cast<uintptr_t>(&dbi_blr_fixture);
    const uintptr_t destination = reinterpret_cast<uintptr_t>(clone);
    if (!rtgum_dbi::Relocator::relocate(reinterpret_cast<const void *>(source),
                                        kInputBytes, source, destination, result)) {
        std::printf("blr-probe relocate-failed overflow=%d unsupported=%d\n",
                    result.overflow, result.unsupported);
        return 3;
    }
    std::memcpy(clone, code, result.code_size);
    __builtin___clear_cache(reinterpret_cast<char *>(clone),
                            reinterpret_cast<char *>(clone) + result.code_size);
    if (mprotect(clone, kCodePage, PROT_READ | PROT_EXEC) != 0) return 4;

    const long baseline = dbi_blr_fixture(&dbi_blr_target);
    const long relocated = reinterpret_cast<decltype(&dbi_blr_fixture)>(clone)(
        &dbi_blr_target);
    uint32_t continuation_offset = 0;
    if (!rtgum_dbi::Relocator::clone_offset_for(result, 3,
                                                continuation_offset)) return 5;
    const uintptr_t expected_continuation = destination + continuation_offset;
    const auto &record = records[0];
    std::printf("blr-probe baseline=%ld relocated=%ld sites=%u hits=%llu "
                "target=0x%llx expected-return-record=0x%llx "
                "actual-continuation=0x%llx delta=%lld\n",
                baseline, relocated, result.site_count,
                static_cast<unsigned long long>(record.hits),
                static_cast<unsigned long long>(record.target),
                static_cast<unsigned long long>(record.expected_return),
                static_cast<unsigned long long>(expected_continuation),
                static_cast<long long>(record.expected_return - expected_continuation));

    // Two far ADRP rewrites produce two inline .quad values. Check both the
    // complete reverse map and the behaviour when its metadata buffer is short.
    const uint32_t adrp_source[2] = {0x90000000U, 0x90000001U};
    uint8_t far_code[128]{};
    rtgum_dbi::OffsetMapEntry far_map[2]{};
    rtgum_dbi::BranchTraceEntry far_trace[2]{};
    rtgum_dbi::LiteralRange far_literals[2]{};
    auto far = rtgum_dbi::make_result(far_code, sizeof(far_code), far_map, 2,
                                       far_trace, 2, far_literals, 2);
    const bool far_ok = rtgum_dbi::Relocator::relocate(
        adrp_source, sizeof(adrp_source), 0x1000U, 0x1000000000ULL, far);
    uint32_t reverse_index = 0;
    const bool literal_reverse_accepted = far_ok && far.literal_size >= 1 &&
        rtgum_dbi::Relocator::original_index_for(
            far, far.literals[0].clone_offset, reverse_index);

    uint8_t short_code[128]{};
    rtgum_dbi::OffsetMapEntry short_map[2]{};
    rtgum_dbi::BranchTraceEntry short_trace[2]{};
    rtgum_dbi::LiteralRange short_literals[1]{};
    auto short_meta = rtgum_dbi::make_result(
        short_code, sizeof(short_code), short_map, 2, short_trace, 2,
        short_literals, 1);
    const bool short_ok = rtgum_dbi::Relocator::relocate(
        adrp_source, sizeof(adrp_source), 0x1000U, 0x1000000000ULL,
        short_meta);
    std::printf("literal-probe complete-ok=%d literal-count=%u recorded=%zu "
                "reverse-accepted-literal=%d short-ok=%d short-count=%u "
                "short-recorded=%zu\n",
                far_ok, far.literal_count, far.literal_size,
                literal_reverse_accepted, short_ok, short_meta.literal_count,
                short_meta.literal_size);

    const uint32_t unknown_insn = 0xffffffffU;
    uint8_t unknown_code[32]{};
    rtgum_dbi::OffsetMapEntry unknown_map[1]{};
    rtgum_dbi::BranchTraceEntry unknown_trace[1]{};
    auto unknown = rtgum_dbi::make_result(unknown_code, sizeof(unknown_code),
                                           unknown_map, 1, unknown_trace, 1);
    const bool unknown_accepted = rtgum_dbi::Relocator::relocate(
        &unknown_insn, sizeof(unknown_insn), 0x1000U, 0x2000U, unknown);
    std::printf("unknown-probe opcode=0x%08x accepted=%d unsupported=%d\n",
                unknown_insn, unknown_accepted, unknown.unsupported);

    const bool blr_valid = baseline == 0x1234 && relocated == baseline &&
        result.site_count == 1 && record.hits == 1 &&
        record.target == reinterpret_cast<uintptr_t>(&dbi_blr_target) &&
        record.expected_return == expected_continuation;
    const bool literals_valid = far_ok && far.literal_count == far.literal_size &&
        !literal_reverse_accepted && !short_ok;
    return blr_valid && literals_valid && !unknown_accepted ? 0 : 1;
}
