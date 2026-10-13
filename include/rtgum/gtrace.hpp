#pragma once

#include "rtgum/native_backend.hpp"

namespace rtgum {
namespace native {

constexpr unsigned int kGtraceInsnNop = 0xD503201FU;
constexpr unsigned int kGtraceInsnPaciasp = 0xD503233FU;
constexpr unsigned int kGtraceInsnAutiasp = 0xD50323BFU;
constexpr unsigned int kGtraceInsnPacibsp = 0xD503237FU;
constexpr unsigned int kGtraceInsnAutibsp = 0xD50323FFU;
constexpr unsigned int kGtraceInsnXpaclri = 0xD50320FFU;
constexpr unsigned int kGtraceInsnBtiC = 0xD503245FU;
constexpr unsigned int kGtraceInsnBtiJ = 0xD503249FU;
constexpr unsigned int kGtraceInsnBtiJc = 0xD50324DFU;
constexpr unsigned int kGtraceInsnBti = 0xD503241FU;
constexpr unsigned int kGtraceInsnRet = 0xD65F03C0U;

inline bool GtraceIsHintFamily(std::uint32_t insn)
{
    return (insn & 0xFFFFF01FU) == 0xD503201FU;
}

inline bool GtraceIsJunk(std::uint32_t insn)
{
    if (insn == kGtraceInsnNop || insn == kGtraceInsnPaciasp || insn == kGtraceInsnAutiasp ||
        insn == kGtraceInsnPacibsp || insn == kGtraceInsnAutibsp || insn == kGtraceInsnXpaclri ||
        insn == kGtraceInsnBti || insn == kGtraceInsnBtiC || insn == kGtraceInsnBtiJ ||
        insn == kGtraceInsnBtiJc) {
        return true;
    }
    /* HINT #n including NOP aliases used as padding. */
    if (GtraceIsHintFamily(insn)) return true;
    /* Unconditional branch to the next instruction (b #4). */
    if (insn == 0x14000001U) return true;
    return false;
}

inline bool GtraceIsRet(std::uint32_t insn)
{
    return insn == kGtraceInsnRet || (insn & 0xFFFFFC1FU) == 0xD65F0000U; /* RET Xn */
}

inline bool GtraceIsUncondBranch(std::uint32_t insn)
{
    /* Bit 31 selects BL; mask it out so both B (0x14) and BL (0x94) match. */
    return (insn & 0x7C000000U) == 0x14000000U; /* B/BL */
}

inline bool GtraceIsIndirectBranch(std::uint32_t insn)
{
    /* BR/BLR/RET, authenticated BR/BLR, and RETAA/RETAB. */
    return (insn & 0xFFFFFC1FU) == 0xD61F0000U || (insn & 0xFFFFFC1FU) == 0xD63F0000U ||
           GtraceIsRet(insn) || (insn & 0xFEFFF800U) == 0xD61F0800U ||
           (insn & 0xFEFFF800U) == 0xD63F0800U || insn == 0xD65F0BFFU ||
           insn == 0xD65F0FFFU;
}

inline long GtraceBranchOffset(std::uint32_t insn)
{
    const std::int32_t imm26 = static_cast<std::int32_t>(insn & 0x03FFFFFFU);
    const std::int32_t signed_imm = (imm26 << 6) >> 6;
    return static_cast<long>(signed_imm) * 4L;
}

inline void GtraceAppend(char *out, unsigned long capacity, unsigned long *used, const char *text)
{
    if (!out || !used || !text || capacity == 0) return;
    unsigned long length = 0;
    while (text[length] != '\0') ++length;
    if (*used >= capacity) return;
    unsigned long room = capacity - *used - 1UL;
    if (length > room) length = room;
    for (unsigned long index = 0; index < length; ++index)
        out[*used + index] = text[index];
    *used += length;
    out[*used] = '\0';
}

inline void GtraceAppendHex(char *out,
                            unsigned long capacity,
                            unsigned long *used,
                            unsigned long value)
{
    char buf[20];
    buf[0] = '0';
    buf[1] = 'x';
    unsigned int shift = 60U;
    unsigned int pos = 2;
    bool started = false;
    while (true) {
        const unsigned int digit = static_cast<unsigned int>((value >> shift) & 0xFUL);
        if (digit != 0U || started || shift == 0U) {
            started = true;
            buf[pos++] = static_cast<char>(digit < 10U ? '0' + digit : 'a' + (digit - 10U));
        }
        if (shift == 0U) break;
        shift -= 4U;
    }
    buf[pos] = '\0';
    GtraceAppend(out, capacity, used, buf);
}

/* Decode a code window. Marks PAC/BTI/NOP/HINT and b#4 as junk, follows
 * direct B/BL, and notes indirect BR/BLR so a later SS trace can fill targets.
 * Does not hide the window or rewrite memory. */
inline long GtraceDecode(const unsigned char *code,
                         unsigned long size,
                         unsigned long pc,
                         char *out,
                         unsigned long capacity)
{
    if (!code || !out || capacity < 8UL) return RTGUM_HOST_ERR_INVAL;
    if ((size & 3UL) != 0UL) return RTGUM_HOST_ERR_INVAL;
    out[0] = '\0';
    unsigned long used = 0;
    unsigned int real = 0;
    unsigned int junk = 0;
    unsigned int branches = 0;
    unsigned long offset = 0;
    while (offset + 4UL <= size) {
        const std::uint32_t insn = ReadU32(code + offset);
        const unsigned long at = pc + offset;
        if (GtraceIsJunk(insn)) {
            ++junk;
            offset += 4UL;
            continue;
        }
        ++real;
        GtraceAppend(out, capacity, &used, used == 0 ? "" : ";");
        GtraceAppendHex(out, capacity, &used, at);
        if (GtraceIsRet(insn)) {
            GtraceAppend(out, capacity, &used, ":ret");
            break;
        }
        if (GtraceIsIndirectBranch(insn)) {
            ++branches;
            GtraceAppend(out, capacity, &used, ":br");
            offset += 4UL;
            continue;
        }
        if (GtraceIsUncondBranch(insn)) {
            ++branches;
            const long delta = GtraceBranchOffset(insn);
            const unsigned long target = static_cast<unsigned long>(
                static_cast<long>(at) + delta);
            GtraceAppend(out, capacity, &used, ":b->");
            GtraceAppendHex(out, capacity, &used, target);
            /* Direct B (not BL) continues at the target if it lands in-window. */
            if ((insn & 0x80000000U) == 0U) {
                if (target >= pc && target + 4UL <= pc + size && (target % 4UL) == 0UL) {
                    offset = target - pc;
                    continue;
                }
                break;
            }
            offset += 4UL;
            continue;
        }
        GtraceAppend(out, capacity, &used, ":op");
        offset += 4UL;
    }
    GtraceAppend(out, capacity, &used, " real=");
    char count[12];
    unsigned int n = real;
    unsigned int pos = 0;
    if (n == 0U) {
        count[pos++] = '0';
    } else {
        char rev[12];
        unsigned int rpos = 0;
        while (n != 0U) {
            rev[rpos++] = static_cast<char>('0' + (n % 10U));
            n /= 10U;
        }
        while (rpos != 0U) count[pos++] = rev[--rpos];
    }
    count[pos] = '\0';
    GtraceAppend(out, capacity, &used, count);
    GtraceAppend(out, capacity, &used, " junk=");
    n = junk;
    pos = 0;
    if (n == 0U) {
        count[pos++] = '0';
    } else {
        char rev[12];
        unsigned int rpos = 0;
        while (n != 0U) {
            rev[rpos++] = static_cast<char>('0' + (n % 10U));
            n /= 10U;
        }
        while (rpos != 0U) count[pos++] = rev[--rpos];
    }
    count[pos] = '\0';
    GtraceAppend(out, capacity, &used, count);
    (void)branches;
    return 0;
}

/* Runtime GTrace -----------------------------------------------------------
 *
 * GtraceDecode above is the legacy static window helper.  It cannot recover a
 * register-indirect target and therefore must never be presented as a
 * deobfuscated execution path.  The runtime formatter below consumes only
 * records produced while instructions actually execute (Gum Stalker callouts
 * or kernel CPU single-step).  Bytes between a source and its landing are not
 * decoded; an explicit gap event describes that interval instead.
 */

enum class GtraceRuntimeKind : unsigned int {
    Op,
    B,
    Bl,
    Conditional,
    Br,
    Blr,
    Ret,
    PacBr,
    PacBlr,
    PacRet,
    Unreadable,
};

inline bool GtraceIsPacBranch(std::uint32_t insn)
{
    return (insn & 0xFEFFF800U) == 0xD61F0800U ||
           (insn & 0xFEFFF800U) == 0xD63F0800U;
}

inline bool GtraceIsPacReturn(std::uint32_t insn)
{
    return insn == 0xD65F0BFFU || insn == 0xD65F0FFFU;
}

inline bool GtraceIsConditionalBranch(std::uint32_t insn)
{
    const bool b_cond = (insn & 0xFF000010U) == 0x54000000U;
    const bool cbz = (insn & 0x7E000000U) == 0x34000000U;
    const bool tbz = (insn & 0x7E000000U) == 0x36000000U;
    return b_cond || cbz || tbz;
}

inline GtraceRuntimeKind GtraceRuntimeClassify(std::uint32_t insn)
{
    const std::uint32_t register_branch = insn & 0xFFFFFC1FU;
    if (register_branch == 0xD61F0000U) return GtraceRuntimeKind::Br;
    if (register_branch == 0xD63F0000U) return GtraceRuntimeKind::Blr;
    if (register_branch == 0xD65F0000U) return GtraceRuntimeKind::Ret;
    if (GtraceIsPacReturn(insn)) return GtraceRuntimeKind::PacRet;
    if ((insn & 0xFEFFF800U) == 0xD61F0800U) return GtraceRuntimeKind::PacBr;
    if ((insn & 0xFEFFF800U) == 0xD63F0800U) return GtraceRuntimeKind::PacBlr;
    if (GtraceIsConditionalBranch(insn)) return GtraceRuntimeKind::Conditional;
    if ((insn & 0x7C000000U) == 0x14000000U)
        return (insn & 0x80000000U) != 0U ? GtraceRuntimeKind::Bl
                                          : GtraceRuntimeKind::B;
    return GtraceRuntimeKind::Op;
}

inline const char *GtraceRuntimeKindName(GtraceRuntimeKind kind)
{
    switch (kind) {
        case GtraceRuntimeKind::Op: return "op";
        case GtraceRuntimeKind::B: return "b";
        case GtraceRuntimeKind::Bl: return "bl";
        case GtraceRuntimeKind::Conditional: return "conditional";
        case GtraceRuntimeKind::Br: return "br";
        case GtraceRuntimeKind::Blr: return "blr";
        case GtraceRuntimeKind::Ret: return "ret";
        case GtraceRuntimeKind::PacBr: return "pac-br";
        case GtraceRuntimeKind::PacBlr: return "pac-blr";
        case GtraceRuntimeKind::PacRet: return "pac-ret";
        case GtraceRuntimeKind::Unreadable: return "unreadable";
    }
    return "unreadable";
}

inline bool GtraceRuntimeIsBranch(GtraceRuntimeKind kind)
{
    return kind != GtraceRuntimeKind::Op && kind != GtraceRuntimeKind::Unreadable;
}

inline bool GtraceRuntimeIsIndirect(GtraceRuntimeKind kind)
{
    return kind == GtraceRuntimeKind::Br || kind == GtraceRuntimeKind::Blr ||
           kind == GtraceRuntimeKind::Ret || kind == GtraceRuntimeKind::PacBr ||
           kind == GtraceRuntimeKind::PacBlr || kind == GtraceRuntimeKind::PacRet;
}

inline unsigned int GtraceRuntimeTargetRegister(std::uint32_t insn,
                                                GtraceRuntimeKind kind)
{
    if (kind == GtraceRuntimeKind::PacRet) return 30U;
    if (GtraceRuntimeIsIndirect(kind)) return (insn >> 5U) & 31U;
    return 0xFFFFFFFFU;
}

struct GtraceRuntimeWriter final {
    char *out;
    unsigned long capacity;
    unsigned long used;
    bool overflow;

    void append(const char *text)
    {
        if (!text || overflow) return;
        unsigned long length = 0UL;
        while (text[length] != '\0') ++length;
        if (used >= capacity || length >= capacity - used) {
            overflow = true;
            if (capacity != 0UL) out[capacity - 1UL] = '\0';
            return;
        }
        for (unsigned long index = 0; index < length; ++index)
            out[used + index] = text[index];
        used += length;
        out[used] = '\0';
    }

    void decimal(unsigned long long value)
    {
        char reversed[24];
        unsigned int count = 0U;
        if (value == 0ULL) reversed[count++] = '0';
        while (value != 0ULL && count < sizeof(reversed)) {
            reversed[count++] = static_cast<char>('0' + (value % 10ULL));
            value /= 10ULL;
        }
        char rendered[24];
        unsigned int cursor = 0U;
        while (count != 0U) rendered[cursor++] = reversed[--count];
        rendered[cursor] = '\0';
        append(rendered);
    }

    void hex(unsigned long value)
    {
        char rendered[2U + sizeof(unsigned long) * 2U + 1U];
        rendered[0] = '0';
        rendered[1] = 'x';
        unsigned int cursor = 2U;
        bool started = false;
        for (int shift = static_cast<int>(sizeof(unsigned long) * 8U) - 4;
             shift >= 0; shift -= 4) {
            const unsigned int nibble =
                static_cast<unsigned int>((value >> shift) & 0xFUL);
            if (!started && nibble == 0U && shift != 0) continue;
            started = true;
            rendered[cursor++] = static_cast<char>(
                nibble < 10U ? '0' + nibble : 'a' + (nibble - 10U));
        }
        rendered[cursor] = '\0';
        append(rendered);
    }

    void hex32(std::uint32_t value)
    {
        static const char digits[] = "0123456789abcdef";
        char rendered[11] = {'0', 'x', '0', '0', '0', '0', '0', '0', '0', '0', '\0'};
        for (unsigned int index = 0U; index < 8U; ++index) {
            const unsigned int shift = (7U - index) * 4U;
            rendered[2U + index] = digits[(value >> shift) & 0xFU];
        }
        append(rendered);
    }
};

inline bool GtraceAddressInside(unsigned long address,
                                unsigned long image_start,
                                unsigned long image_end)
{
    return address >= image_start && address < image_end;
}

inline const char *GtraceStepSource(unsigned int flags)
{
    if ((flags & RTGUM_GTRACE_STEP_DBI_CALLOUT) != 0U) return "dbi";
    if ((flags & RTGUM_GTRACE_STEP_CPU_SINGLE_STEP) != 0U) return "cpu-ss";
    return "runtime";
}

inline long GtraceFormatPath(const RtGumGtraceStep *steps,
                             unsigned long count,
                             unsigned long image_start,
                             unsigned long image_end,
                             char *out,
                             unsigned long capacity)
{
    if (!steps || !out || capacity < 64UL || count == 0UL || count > 4096UL ||
        image_start == 0UL || image_end <= image_start ||
        ((image_start | image_end) & 3UL) != 0UL)
        return RTGUM_HOST_ERR_INVAL;
    GtraceRuntimeWriter writer{out, capacity, 0UL, false};
    out[0] = '\0';
    writer.append("gtrace-format version=2 image-start=");
    writer.hex(image_start);
    writer.append(" image-end=");
    writer.hex(image_end);
    writer.append(" records=");
    writer.decimal(count);
    writer.append("\n");

    unsigned long branches = 0UL;
    unsigned long indirect = 0UL;
    unsigned long internal_targets = 0UL;
    unsigned long gaps = 0UL;
    unsigned long skipped_bytes = 0UL;
    unsigned long losses = 0UL;
    unsigned long mismatches = 0UL;
    unsigned long unreadable = 0UL;
    unsigned long long previous_sequence = 0ULL;
    for (unsigned long index = 0UL; index < count; ++index) {
        const RtGumGtraceStep &step = steps[index];
        if (step.sequence == 0ULL || (step.pc & 3UL) != 0UL ||
            (index != 0UL && step.sequence <= previous_sequence))
            return RTGUM_HOST_ERR_INVAL;
        if (index != 0UL && step.sequence != previous_sequence + 1ULL) {
            ++losses;
            writer.append("gtrace-loss after-seq=");
            writer.decimal(previous_sequence);
            writer.append(" before-seq=");
            writer.decimal(step.sequence);
            writer.append(" missing=");
            writer.decimal(step.sequence - previous_sequence - 1ULL);
            writer.append("\n");
        }
        previous_sequence = step.sequence;
        const bool instruction_valid =
            (step.flags & RTGUM_GTRACE_STEP_INSN_VALID) != 0U;
        const bool next_valid =
            (step.flags & RTGUM_GTRACE_STEP_NEXT_VALID) != 0U;
        const GtraceRuntimeKind kind = instruction_valid
                                           ? GtraceRuntimeClassify(step.instruction)
                                           : GtraceRuntimeKind::Unreadable;
        if (!instruction_valid) ++unreadable;
        const bool branch = instruction_valid && GtraceRuntimeIsBranch(kind);
        const bool is_indirect = branch && GtraceRuntimeIsIndirect(kind);
        if (branch) ++branches;
        if (is_indirect) ++indirect;

        writer.append("gtrace-path seq=");
        writer.decimal(step.sequence);
        writer.append(" pc=");
        writer.hex(step.pc);
        writer.append(" insn=");
        if (instruction_valid)
            writer.hex32(step.instruction);
        else
            writer.append("unreadable");
        writer.append(" kind=");
        writer.append(GtraceRuntimeKindName(kind));
        writer.append(" next=");
        if (next_valid)
            writer.hex(step.next_pc);
        else
            writer.append("unknown");
        writer.append(" source=");
        writer.append(GtraceStepSource(step.flags));
        writer.append("\n");

        const unsigned long fallthrough = step.pc + 4UL;
        const bool discontinuity = next_valid && step.next_pc != fallthrough;
        if (branch || discontinuity) {
            const bool internal = next_valid &&
                GtraceAddressInside(step.next_pc, image_start, image_end);
            if (branch && internal) ++internal_targets;
            writer.append("gtrace-edge seq=");
            writer.decimal(step.sequence);
            writer.append(" source=");
            writer.hex(step.pc);
            writer.append(" kind=");
            writer.append(GtraceRuntimeKindName(kind));
            writer.append(" branch=");
            writer.append(is_indirect ? "indirect" : (branch ? "direct" : "unexpected"));
            if (is_indirect) {
                writer.append(" reg=x");
                writer.decimal(GtraceRuntimeTargetRegister(step.instruction, kind));
            }
            writer.append(" target=");
            if (next_valid)
                writer.hex(step.next_pc);
            else
                writer.append("unknown");
            writer.append(" target-scope=");
            writer.append(!next_valid ? "unknown" : (internal ? "internal" : "external"));
            writer.append("\n");

            /* Only an in-image discontinuity denotes a concrete interval in
             * the obfuscated image.  External calls/returns are edges, not
             * candidate junk ranges. */
            if (discontinuity && internal) {
                const bool forward = step.next_pc > fallthrough;
                const unsigned long low = forward ? fallthrough : step.next_pc;
                const unsigned long high = forward ? step.next_pc : fallthrough;
                const unsigned long bytes = high - low;
                ++gaps;
                skipped_bytes += forward ? bytes : 0UL;
                writer.append("gtrace-gap seq=");
                writer.decimal(step.sequence);
                writer.append(" from=");
                writer.hex(fallthrough);
                writer.append(" to=");
                writer.hex(step.next_pc);
                writer.append(" low=");
                writer.hex(low);
                writer.append(" high=");
                writer.hex(high);
                writer.append(" bytes=");
                writer.decimal(bytes);
                writer.append(" direction=");
                writer.append(forward ? "forward" : "backward");
                writer.append(" candidate-junk=");
                writer.append(forward ? "1" : "0");
                writer.append("\n");
            }
        }

        /* For a consecutive in-image record the stored architectural landing
         * must equal the next executed PC.  A mismatch is preserved as an
         * event (signal/unwind or a bad emulator), never silently repaired. */
        if (next_valid && index + 1UL < count &&
            steps[index + 1UL].sequence == step.sequence + 1ULL &&
            GtraceAddressInside(step.next_pc, image_start, image_end) &&
            steps[index + 1UL].pc != step.next_pc) {
            ++mismatches;
            writer.append("gtrace-transition-mismatch seq=");
            writer.decimal(step.sequence);
            writer.append(" expected=");
            writer.hex(step.next_pc);
            writer.append(" observed=");
            writer.hex(steps[index + 1UL].pc);
            writer.append("\n");
        }
    }

    writer.append("gtrace-summary executed=");
    writer.decimal(count);
    writer.append(" branches=");
    writer.decimal(branches);
    writer.append(" indirect=");
    writer.decimal(indirect);
    writer.append(" internal-targets=");
    writer.decimal(internal_targets);
    writer.append(" gaps=");
    writer.decimal(gaps);
    writer.append(" skipped-bytes=");
    writer.decimal(skipped_bytes);
    writer.append(" losses=");
    writer.decimal(losses);
    writer.append(" mismatches=");
    writer.decimal(mismatches);
    writer.append(" unreadable=");
    writer.decimal(unreadable);
    writer.append("\n");
    return writer.overflow ? RTGUM_HOST_ERR_NOMEM : 0L;
}

}  // namespace native
}  // namespace rtgum
