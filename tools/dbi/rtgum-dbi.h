// rtgum-dbi.h - AArch64 instruction relocation subset (freestanding core)
//
// A compact extract of the Frida Gum relocator idea: classify and rewrite the
// PC-relative instruction classes so a block can be cloned to another address,
// with an offset_map that translates any clone PC back to the original
// instruction index. Intra-block branch targets are re-pointed at the clone
// through that map; indirect br/blr are copied verbatim (their landing is a
// runtime property, never repaired statically).
//
// The core is freestanding: no libc, no STL, no allocation. Callers supply the
// output buffer, the map array and the trace array, so the same code runs in
// the control tool, in a -nostdlib user module and inside ghost memory.
//
// Layout is resolved in two passes:
//   pass 1  decode + classify + emit with placeholder branch operands and
//           record a fixup per rewritten branch;
//   pass 2  patch every fixup against the final clone layout (intra-block
//           targets from offset_map, external targets absolute).
#pragma once

#include <stdint.h>
#include <stddef.h>

namespace rtgum_dbi {

enum class InstrKind : uint8_t {
    Copy = 0,        // position-independent (arithmetic, loads/stores, ...)
    BranchImm,       // B / BL
    BranchCond,      // B.cond
    Cbz,             // CBZ / CBNZ
    Tbz,             // TBZ / TBNZ
    Adr,             // ADR
    Adrp,            // ADRP
    LdrLiteral,      // LDR (literal) family
    Br,              // BR / BLR (register indirect, copied verbatim)
    PacBranch,       // BLRAA/BRAA/... (register indirect, copied verbatim)
    Ret,             // RET (block terminator, copied verbatim)
    PacReturn,       // RETAA/RETAB (authenticated return; never rewritten)
    Unsupported,     // refuse to relocate
};

struct OffsetMapEntry {
    uint32_t orig_index;    // index of the source instruction (4-byte units)
    uint32_t clone_offset;  // byte offset of the cloned instruction
};

// One inline literal (an emitted .quad). The reverse lookup must not treat
// literal bytes as instructions, so their clone ranges are recorded.
struct LiteralRange {
    uint32_t clone_offset;
    uint32_t size;
};

// Optional indirect-branch instrumentation ("dispatcher"). When enabled, every
// BR/BLR/RET of the block is rewritten into a stub that records the actual
// runtime target before performing the original branch, so a follower can
// verify targets, cache them and check returns without single-stepping.
// A nearby record uses ADR; a distant record uses an inline absolute-address
// literal. The latter is recorded in LiteralRange like other embedded data.
struct DispatcherConfig {
    bool enabled;
    uint8_t mode;           // bit0: instrument BR/BLR, bit1: instrument RET
    /* A Shadow-hook trampoline may resume at an internal original address on
     * a BTI-enabled page. BR X16 would set an incompatible branch type for a
     * non-landing instruction; RET X16 preserves LR while using return branch
     * semantics. Ordinary DBI clones leave this false. */
    bool return_far_branches;
    uint64_t record_base;
    uint32_t record_stride;  // bytes per site (>= 32, 16-byte aligned)
    uint32_t max_sites;
};

struct SiteRecord {
    uint64_t target;          // 0x00 the raw target the branch used
    uint64_t hits;            // 0x08 how many times the site executed
    uint64_t expected_return; // 0x10 BLR: the return address the stub installs
    uint64_t reserved;        // 0x18
};

struct BranchTraceEntry {
    uint32_t orig_index;      // index of the source instruction
    InstrKind kind;           // which class produced the entry
    uint64_t target;          // absolute target; 0 when resolved at runtime
    bool intra_block;         // the target lies inside the relocated block
    bool introduced_indirect; // a direct branch became an indirect one
    bool runtime_target;      // the landing is only known at runtime
    uint8_t target_register;  // Rn for BR/BLR/PAC/RET, 0xff for direct
    bool links;               // BLR: sets LR
    uint8_t pac_modifier;     // BRAA/BRAB/... discriminator bits
    uint16_t site_index;      // dispatcher site, 0xffff when not instrumented
};

// Why an instruction could not be relocated. The writer records the source
// PC, the raw opcode, the decoded subtype and the clone-side distance so a
// rejection is diagnosable instead of silent.
enum class RejectReason : uint8_t {
    None = 0,
    LdrLiteralOutOfRange,   // scalar far rewrite unavailable
    LdrLiteralPrfm,         // PRFM is not a register load
    LdrLiteralSimd,         // SIMD/FP literal load
    LdrLiteralZeroRegister, // Rt == 31 needs SP as scratch
    OutOfRange,             // pass 2 found an unencodable delta
    Capacity,               // output buffer exhausted
    LiteralMetadataFull,    // the literal range array is full or absent
    UnknownEncoding,        // not a supported position-independent class
    InvalidInput,           // null storage, partial instruction, or bad config
};

struct RejectInfo {
    RejectReason reason;
    uint32_t orig_index;
    uint64_t source_pc;
    uint32_t opcode;
    uint8_t subtype;      // opc:V of the literal load family
    uint64_t target;      // literal VA or branch target
    uint64_t clone_pc;
    int64_t delta;        // clone_pc - target (clone side distance)
};

struct RelocationResult {
    uint8_t *code;                       // caller buffer for the clone
    size_t capacity;                     // its size in bytes
    size_t code_size;                    // bytes actually emitted
    OffsetMapEntry *map;                 // caller array (>= input instructions)
    size_t map_capacity;
    size_t map_size;
    LiteralRange *literals;              // caller array for inline .quad ranges
    size_t literal_capacity;
    size_t literal_size;
    DispatcherConfig dispatcher;         // optional indirect-branch recording
    uint32_t site_count;                 // sites assigned by the dispatcher
    BranchTraceEntry *trace;             // caller array (>= input instructions)
    size_t trace_capacity;
    size_t trace_size;
    uint32_t input_instructions;
    uint32_t literal_count;              // emitted .quad literals
    uint32_t expanded_branches;          // far-jump expansions used
    uint32_t placeholder_index;          // first byte past the real code
    bool overflow;                       // the capacity was exhausted
    bool unsupported;                    // an instruction could not be relocated
    bool out_of_range;                   // pass 2 found an unencodable delta
    RejectInfo reject;                   // details of the first rejection

    bool contains_clone_offset(uint32_t offset) const
    {
        return offset < placeholder_index;
    }
};

namespace detail {

/* Only these position-independent A64 encoding families are copied without
 * rewriting. This intentionally rejects system, SIMD/SVE and extension
 * encodings that the freestanding relocator does not decode. In particular,
 * being in a non-reserved major opcode group is not proof of a valid
 * instruction. A caller requiring wider coverage must use the Gum Stalker
 * decoder/translator, which is a separate backend. */
inline bool known_position_independent_copy(uint32_t word)
{
    if ((word & 0xffff0000U) == 0U) return true; // UDF (defined trap)
    switch (word) {
        case 0xd503201fU: // NOP
        case 0xd503245fU: // BTI c
        case 0xd503249fU: // BTI j
        case 0xd50324dfU: // BTI jc
        case 0xd503233fU: // PACIASP
        case 0xd503237fU: // PACIBSP
        case 0xd50323bfU: // AUTIASP
        case 0xd50323ffU: // AUTIBSP
            return true;
        default: break;
    }
    const uint32_t top = word & 0x1f000000U;
    if (top == 0x0a000000U || // logical register
        top == 0x0b000000U || // add/sub register
        top == 0x1a000000U || // conditional select / data register
        top == 0x1b000000U || // multiply-add family
        top == 0x11000000U)  // add/sub immediate
        return true;
    const uint32_t immediate = word & 0x1f800000U;
    if (immediate == 0x12000000U || // logical immediate
        immediate == 0x12800000U || // move-wide immediate
        immediate == 0x13000000U || // bitfield
        immediate == 0x13800000U)  // extract
        return true;
    const uint32_t memory = word & 0x3a000000U;
    return memory == 0x28000000U || // load/store pair
           memory == 0x38000000U;   // register-based load/store
}

inline int64_t sign_extend(uint64_t value, unsigned bits)
{
    const uint64_t sign_bit = 1ULL << (bits - 1U);
    const uint64_t mask = (1ULL << bits) - 1ULL;
    const int64_t v = static_cast<int64_t>(value & mask);
    return (value & sign_bit) ? (v - static_cast<int64_t>(1ULL << bits)) : v;
}

// The immediate FIELD is counted in encoded units (words for branch
// immediates; ADR byte offsets are handled by in_byte_range).
inline bool in_scaled_range(int64_t byte_delta, unsigned field_bits)
{
    if ((byte_delta & 3) != 0) return false;
    const int64_t units = byte_delta >> 2;
    const int64_t limit = 1LL << (field_bits - 1U);
    return units >= -limit && units < limit;
}

inline bool in_byte_range(int64_t byte_delta, unsigned field_bits)
{
    const int64_t limit = 1LL << (field_bits - 1U);
    return byte_delta >= -limit && byte_delta < limit;
}

inline uint32_t br_x16() { return 0xd61f0200U; }   // br x16
inline uint32_t blr_x16() { return 0xd63f0200U; }  // blr x16

// adr xN, #imm (imm in bytes, small positive value)
inline uint32_t adr_rd_imm(uint32_t rd, uint32_t imm)
{
    return 0x10000000U | rd | ((imm & 0x3U) << 29U) |
           (((imm >> 2U) & 0x7ffffU) << 5U);
}

inline uint32_t b_imm(uint32_t imm)
{
    return 0x14000000U | ((imm >> 2U) & 0x03ffffffU);
}

inline uint32_t ldr_rd_from_rn(uint32_t rd, uint32_t rn)
{
    return 0xf9400000U | rd | (rn << 5U); // ldr xN, [xM]
}

constexpr unsigned kBranchImmFieldBits = 26;   // B/BL:  +/-128MB
constexpr unsigned kBranchCondFieldBits = 19;  // B.cond/CBZ/LDR-literal: +/-1MB
constexpr unsigned kTbzFieldBits = 14;         // TBZ/TBNZ: +/-32KB
constexpr unsigned kAdrFieldBits = 21;         // ADR:   +/-1MB (byte units)

} // namespace detail

// Binds caller storage to a result record. The core never allocates.
inline RelocationResult make_result(uint8_t *code, size_t capacity,
                                    OffsetMapEntry *map, size_t map_capacity,
                                    BranchTraceEntry *trace,
                                    size_t trace_capacity,
                                    LiteralRange *literals = nullptr,
                                    size_t literal_capacity = 0)
{
    RelocationResult result{};
    result.code = code;
    result.capacity = capacity;
    result.map = map;
    result.map_capacity = map_capacity;
    result.trace = trace;
    result.trace_capacity = trace_capacity;
    result.literals = literals;
    result.literal_capacity = literal_capacity;
    return result;
}

// True when the clone offset points at inline literal data rather than at the
// start of a real instruction. Without this distinction the reverse mapping
// silently attributes .quad bytes to the preceding instruction.
inline bool clone_offset_is_literal(const RelocationResult &result,
                                    uint32_t clone_offset)
{
    for (size_t slot = 0; slot < result.literal_size; ++slot) {
        const LiteralRange &range = result.literals[slot];
        if (clone_offset >= range.clone_offset &&
            clone_offset < range.clone_offset + range.size)
            return true;
    }
    return false;
}

class Relocator {
public:
    static constexpr uint32_t kNoIndex = 0xffffffffU;

    struct Fixup {
        uint32_t word_index;      // emitted word to patch (or the literal word)
        uint32_t orig_index;
        uint32_t target_index;    // intra-block target index, else kNoIndex
        uint64_t external_target; // used when target_index == kNoIndex
        InstrKind kind;
        bool expanded;            // the literal at word_index holds the value
        bool direct_patch;        // patch an immediate field in-place
        unsigned field_bits;      // for the in-place patch
        uint32_t field_shift;
        uint32_t field_mask;
    };
    // At most one patchable operand per source instruction.
    static constexpr size_t kMaxFixups = 512;

    // Clones [input, input + byte_count) executing at source_address so that
    // the clone executes at clone_address. All output storage is caller
    // supplied through `out`.
    static bool relocate(const void *input, size_t byte_count,
                         uint64_t source_address, uint64_t clone_address,
                         RelocationResult &out)
    {
        const auto *insns = static_cast<const uint32_t *>(input);
        const size_t count = byte_count / 4U;
        const size_t capacity = out.capacity;
        out.code_size = 0;
        out.map_size = 0;
        out.trace_size = 0;
        out.literal_size = 0;
        out.site_count = 0;
        out.input_instructions = static_cast<uint32_t>(count);
        out.literal_count = 0;
        out.expanded_branches = 0;
        out.placeholder_index = 0;
        out.overflow = false;
        out.unsupported = false;
        out.out_of_range = false;
        out.reject = RejectInfo{};
        Fixup fixups[kMaxFixups];
        size_t fixup_count = 0;

        if (input == nullptr || (byte_count & 3U) != 0U ||
            count == 0 || count > 0xffffffffU ||
            byte_count > UINT64_MAX - source_address ||
            out.code == nullptr || out.map == nullptr ||
            out.map_capacity < count || out.trace == nullptr ||
            out.trace_capacity < count ||
            (out.dispatcher.mode != 0U &&
             (!out.dispatcher.enabled || out.dispatcher.mode > 3U ||
              out.dispatcher.record_stride < sizeof(SiteRecord) ||
              (out.dispatcher.record_stride & 0xfU) != 0U ||
              out.dispatcher.max_sites == 0U ||
              out.dispatcher.max_sites > 0xffffU))) {
            out.unsupported = true;
            out.reject.reason = RejectReason::InvalidInput;
            return false;
        }

        auto emit = [&](uint32_t word) -> bool {
            if (out.code_size + 4U > capacity) {
                out.overflow = true;
                return false;
            }
            out.code[out.code_size++] = static_cast<uint8_t>(word & 0xffU);
            out.code[out.code_size++] = static_cast<uint8_t>((word >> 8U) & 0xffU);
            out.code[out.code_size++] = static_cast<uint8_t>((word >> 16U) & 0xffU);
            out.code[out.code_size++] = static_cast<uint8_t>((word >> 24U) & 0xffU);
            return true;
        };
        // A .quad lives inside the emitted stream; the counter is bumped only
        // here so every literal is counted exactly once.
        auto emit_quad = [&](uint64_t value) -> bool {
            if (out.code_size + 8U > capacity) {
                out.overflow = true;
                return false;
            }
            const uint32_t literal_at = static_cast<uint32_t>(out.code_size);
            for (unsigned byte = 0; byte < 8U; ++byte)
                out.code[out.code_size++] =
                    static_cast<uint8_t>((value >> (byte * 8U)) & 0xffU);
            ++out.literal_count;
            /* The literal metadata is mandatory: silently emitting a .quad
             * without recording its range would let the reverse mapping treat
             * data as instructions. */
            if (out.literals == nullptr ||
                out.literal_size >= out.literal_capacity) {
                out.unsupported = true;
                if (out.reject.reason == RejectReason::None) {
                    out.reject.reason = RejectReason::LiteralMetadataFull;
                    out.reject.clone_pc = literal_at;
                }
                return false;
            }
            out.literals[out.literal_size].clone_offset = literal_at;
            out.literals[out.literal_size].size = 8U;
            ++out.literal_size;
            return true;
        };
        auto add_fixup = [&](const Fixup &fixup) -> bool {
            if (fixup_count >= kMaxFixups) {
                out.overflow = true;
                return false;
            }
            fixups[fixup_count++] = fixup;
            return true;
        };
        auto note_reject = [&](RejectReason reason, uint32_t orig, uint64_t src,
                               uint32_t opcode, uint8_t subtype, uint64_t target,
                               uint64_t clone_pc) {
            if (out.reject.reason != RejectReason::None) return;
            out.reject.reason = reason;
            out.reject.orig_index = orig;
            out.reject.source_pc = src;
            out.reject.opcode = opcode;
            out.reject.subtype = subtype;
            out.reject.target = target;
            out.reject.clone_pc = clone_pc;
            out.reject.delta = static_cast<int64_t>(clone_pc) -
                               static_cast<int64_t>(target);
        };
        // Far branch: x16 carries the absolute target. Nothing returns into
        // the literal, so the compact form is enough.
        auto emit_far_branch = [&](uint64_t target, uint32_t orig,
                                   uint32_t target_index) -> bool {
            const uint32_t at = static_cast<uint32_t>(out.code_size);
            if (!emit(0x58000050U)) return false; // ldr x16, #8
            if (!emit(out.dispatcher.return_far_branches ? 0xd65f0200U
                                                         : detail::br_x16()))
                return false;
            if (!emit_quad(target)) return false;
            ++out.expanded_branches;
            if (!add_fixup({at / 4U + 2U, orig, target_index, target,
                            InstrKind::BranchImm, true, false, 0, 0, 0}))
                return false;
            out.trace[out.trace_size - 1U].introduced_indirect = true;
            return true;
        };
        // Far call: the LR must point at a real instruction, so a skip branch
        // follows the blr and the literal sits behind it.
        auto emit_far_call = [&](uint64_t target, uint32_t orig,
                                 uint32_t target_index) -> bool {
            const uint32_t at = static_cast<uint32_t>(out.code_size);
            if (!emit(0x58000070U)) return false; // ldr x16, #12
            if (!emit(detail::blr_x16())) return false;
            if (!emit(detail::b_imm(12U))) return false;
            if (!emit_quad(target)) return false;
            ++out.expanded_branches;
            if (!add_fixup({at / 4U + 3U, orig, target_index, target,
                            InstrKind::BranchImm, true, false, 0, 0, 0}))
                return false;
            out.trace[out.trace_size - 1U].introduced_indirect = true;
            return true;
        };
        // Absolute value load into rd (rd itself is the address scratch, so
        // no extra register is clobbered).
        auto emit_absolute_load = [&](uint32_t rd, uint64_t value, uint32_t orig,
                                      uint32_t target_index) -> bool {
            const uint32_t at = static_cast<uint32_t>(out.code_size);
            if (!emit(detail::adr_rd_imm(rd, 12U))) return false;
            if (!emit(detail::ldr_rd_from_rn(rd, rd))) return false;
            if (!emit(detail::b_imm(12U))) return false;
            if (!emit_quad(value)) return false;
            return add_fixup({at / 4U + 3U, orig, target_index, value,
                              InstrKind::Adrp, true, false, 0, 0, 0});
        };
        // The dispatcher stub: records the target register into this site's
        // record slot (and, for BLR, the return address it is about to
        // install) and then performs the original branch unchanged. x16/x17
        // are saved and restored, and the target register is never written, so
        // the stub is transparent for any Rn -- including x16/x17/x30.
        auto emit_indirect_stub = [&](uint8_t rn, bool link, bool is_ret) -> bool {
            if (out.dispatcher.mode == 0U) return false;
            if (out.site_count >= out.dispatcher.max_sites) {
                out.overflow = true;
                return false;
            }
            const uint32_t site_index = out.site_count;
            const uint64_t site_address = out.dispatcher.record_base +
                                          static_cast<uint64_t>(site_index) *
                                              out.dispatcher.record_stride;
            const uint32_t at = static_cast<uint32_t>(out.code_size);
            const uint64_t stub_pc = clone_address + at;
            const int64_t site_delta =
                static_cast<int64_t>(site_address) -
                static_cast<int64_t>(stub_pc + 8);
            const bool far_site =
                !detail::in_byte_range(site_delta, detail::kAdrFieldBits);
            // stp x16, x17, [sp, #-32]!
            if (!emit(0xa9be47f0U)) return false;
            // str xN, [sp, #16]
            if (!emit(0xf9000be0U | rn)) return false;
            // adr x16,<site> or ldr x16,<inline absolute address>.
            const uint32_t site_load_word = static_cast<uint32_t>(out.code_size / 4U);
            if (!emit(far_site ? 0x58000010U :
                      detail::adr_rd_imm(16U, static_cast<uint32_t>(site_delta))))
                return false;
            // ldr x17, [sp, #16]
            if (!emit(0xf9400bf1U)) return false;
            // str x17, [x16]
            if (!emit(0xf9000211U)) return false;
            // Atomic hit counter: movz x17,#1 ; add x16,x16,#8 ;
            // ldadd x17,x17,[x16]  (LSE, ARMv8.1+; a plain load/add/store
            // would lose increments when several threads run the site).
            if (!emit(0xd2800031U)) return false;
            if (!emit(0x91002210U)) return false;
            if (!emit(0xf8310211U)) return false;
            uint32_t return_adr_word = 0xffffffffU;
            if (link) {
                // x16 is at record+8 after the hit counter. Store the BLR
                // continuation at record+16, i.e. [x16,#8].
                // The displacement is backfilled once the stub length is known.
                return_adr_word = static_cast<uint32_t>(out.code_size / 4U);
                if (!emit(detail::adr_rd_imm(17U, 0U))) return false;
                if (!emit(0xf9000611U)) return false;
            }
            // ldp x16, x17, [sp], #32
            if (!emit(0xa8c247f0U)) return false;
            // br/blr/ret xN
            if (is_ret) {
                if (!emit(0xd65f0000U | (static_cast<uint32_t>(rn) << 5U))) return false;
            } else if (link) {
                if (!emit(0xd63f0000U | (static_cast<uint32_t>(rn) << 5U))) return false;
            } else {
                if (!emit(0xd61f0000U | (static_cast<uint32_t>(rn) << 5U))) return false;
            }
            // BLR sets LR to the next instruction, which is a literal-skip B
            // for a far record. Preserve that exact hardware continuation.
            const uint64_t continuation = clone_address + out.code_size;
            if (far_site) {
                if (link && !emit(detail::b_imm(12U))) return false;
                const uint32_t literal_offset = static_cast<uint32_t>(out.code_size);
                if (!emit_quad(site_address)) return false;
                const int64_t literal_delta = static_cast<int64_t>(literal_offset) -
                                              static_cast<int64_t>(site_load_word * 4U);
                if (!detail::in_scaled_range(literal_delta, 19U)) return false;
                uint32_t *load = reinterpret_cast<uint32_t *>(
                    out.code + site_load_word * 4U);
                *load = 0x58000010U |
                        ((static_cast<uint32_t>(literal_delta >> 2U) & 0x7ffffU) << 5U);
            }
            if (return_adr_word != 0xffffffffU) {
                const int64_t delta =
                    static_cast<int64_t>(continuation) -
                    static_cast<int64_t>(clone_address + return_adr_word * 4U);
                if (!detail::in_byte_range(delta, detail::kAdrFieldBits)) return false;
                uint32_t *word = reinterpret_cast<uint32_t *>(
                    out.code + return_adr_word * 4U);
                *word = detail::adr_rd_imm(17U, static_cast<uint32_t>(delta));
            }
            out.site_count = site_index + 1;
            if (out.trace_size != 0)
                out.trace[out.trace_size - 1U].site_index =
                    static_cast<uint16_t>(site_index);
            return true;
        };

        for (size_t index = 0; index < count; ++index) {
            const uint32_t insn = insns[index];
            const uint64_t src_pc = source_address + index * 4U;
            const uint64_t clone_pc = clone_address + out.code_size;
            const uint32_t orig = static_cast<uint32_t>(index);
            out.map[out.map_size].orig_index = orig;
            out.map[out.map_size].clone_offset = static_cast<uint32_t>(out.code_size);
            ++out.map_size;

            auto push_trace = [&](InstrKind kind, uint64_t target, bool intra,
                                  bool runtime, uint8_t target_register = 0xffU,
                                  bool links = false, uint8_t pac_modifier = 0U) {
                out.trace[out.trace_size].orig_index = orig;
                out.trace[out.trace_size].kind = kind;
                out.trace[out.trace_size].target = target;
                out.trace[out.trace_size].intra_block = intra;
                out.trace[out.trace_size].introduced_indirect = false;
                out.trace[out.trace_size].runtime_target = runtime;
                out.trace[out.trace_size].target_register = target_register;
                out.trace[out.trace_size].links = links;
                out.trace[out.trace_size].pac_modifier = pac_modifier;
                out.trace[out.trace_size].site_index = 0xffffU;
                ++out.trace_size;
            };
            auto is_intra = [&](uint64_t target) {
                return target >= source_address &&
                       target < source_address + byte_count;
            };
            auto intra_index = [&](uint64_t target) -> uint32_t {
                if (!is_intra(target)) return kNoIndex;
                const uint64_t delta = target - source_address;
                if ((delta & 3U) != 0) return kNoIndex;
                const uint32_t at = static_cast<uint32_t>(delta / 4U);
                return at < count ? at : kNoIndex;
            };

            // B / BL
            if ((insn & 0x7c000000U) == 0x14000000U) {
                const bool link = (insn & 0x80000000U) != 0U;
                const int64_t target =
                    src_pc + detail::sign_extend(insn & 0x03ffffffU, 26) * 4;
                const uint32_t target_index =
                    intra_index(static_cast<uint64_t>(target));
                push_trace(InstrKind::BranchImm, static_cast<uint64_t>(target),
                           target_index != kNoIndex, false);
                const int64_t delta = target - static_cast<int64_t>(clone_pc);
                // An intra-block target moves with the clone, so the direct
                // form is always kept for it; the distance estimate only
                // decides the layout of external targets.
                if (target_index != kNoIndex ||
                    detail::in_scaled_range(delta, detail::kBranchImmFieldBits)) {
                    const uint32_t word = static_cast<uint32_t>(out.code_size / 4U);
                    if (!emit((insn & 0xfc000000U) |
                              (static_cast<uint32_t>(delta >> 2) & 0x03ffffffU)))
                        return false;
                    if (!add_fixup({word, orig, target_index,
                                    static_cast<uint64_t>(target),
                                    InstrKind::BranchImm, false, true,
                                    detail::kBranchImmFieldBits, 0, 0x03ffffffU}))
                        return false;
                } else if (link) {
                    if (!emit_far_call(static_cast<uint64_t>(target), orig,
                                       target_index))
                        return false;
                } else {
                    if (!emit_far_branch(static_cast<uint64_t>(target), orig,
                                         target_index))
                        return false;
                }
            }
            // B.cond
            else if ((insn & 0xff000010U) == 0x54000000U) {
                const uint32_t cond = insn & 0xfU;
                const int64_t target =
                    src_pc + detail::sign_extend((insn >> 5U) & 0x7ffffU, 19) * 4;
                const uint32_t target_index =
                    intra_index(static_cast<uint64_t>(target));
                push_trace(InstrKind::BranchCond, static_cast<uint64_t>(target),
                           target_index != kNoIndex, false);
                const int64_t delta = target - static_cast<int64_t>(clone_pc);
                if (cond != 0xeU &&
                    (target_index != kNoIndex ||
                     detail::in_scaled_range(delta, detail::kBranchCondFieldBits))) {
                    const uint32_t word = static_cast<uint32_t>(out.code_size / 4U);
                    if (!emit((insn & ~(0x7ffffU << 5U)) |
                              ((static_cast<uint32_t>(delta >> 2) & 0x7ffffU) << 5U)))
                        return false;
                    if (!add_fixup({word, orig, target_index,
                                    static_cast<uint64_t>(target),
                                    InstrKind::BranchCond, false, true,
                                    detail::kBranchCondFieldBits, 5U, 0x7ffffU}))
                        return false;
                } else {
                    // Inverted condition skips the whole 20-byte idiom.
                    if (!emit(0x54000000U | ((cond ^ 1U) & 0xfU) | (5U << 5U)))
                        return false;
                    if (!emit_far_branch(static_cast<uint64_t>(target), orig,
                                         target_index))
                        return false;
                }
            }
            // CBZ / CBNZ (bit 24 is the N opcode, bit 31 the operand size)
            else if ((insn & 0x7e000000U) == 0x34000000U) {
                const int64_t target =
                    src_pc + detail::sign_extend((insn >> 5U) & 0x7ffffU, 19) * 4;
                const uint32_t target_index =
                    intra_index(static_cast<uint64_t>(target));
                push_trace(InstrKind::Cbz, static_cast<uint64_t>(target),
                           target_index != kNoIndex, false);
                const int64_t delta = target - static_cast<int64_t>(clone_pc);
                if (target_index != kNoIndex ||
                    detail::in_scaled_range(delta, detail::kBranchCondFieldBits)) {
                    const uint32_t word = static_cast<uint32_t>(out.code_size / 4U);
                    if (!emit((insn & ~(0x7ffffU << 5U)) |
                              ((static_cast<uint32_t>(delta >> 2) & 0x7ffffU) << 5U)))
                        return false;
                    if (!add_fixup({word, orig, target_index,
                                    static_cast<uint64_t>(target),
                                    InstrKind::Cbz, false, true,
                                    detail::kBranchCondFieldBits, 5U, 0x7ffffU}))
                        return false;
                } else {
                    const uint32_t inverted =
                        (insn ^ 0x01000000U) & ~(0x7ffffU << 5U);
                    if (!emit(inverted | (5U << 5U))) return false;
                    if (!emit_far_branch(static_cast<uint64_t>(target), orig,
                                         target_index))
                        return false;
                }
            }
            // TBZ / TBNZ (bit 24 is the N opcode, bit 31 the operand size)
            else if ((insn & 0x7e000000U) == 0x36000000U) {
                const int64_t target =
                    src_pc + detail::sign_extend((insn >> 5U) & 0x3fffU, 14) * 4;
                const uint32_t target_index =
                    intra_index(static_cast<uint64_t>(target));
                push_trace(InstrKind::Tbz, static_cast<uint64_t>(target),
                           target_index != kNoIndex, false);
                const int64_t delta = target - static_cast<int64_t>(clone_pc);
                if (target_index != kNoIndex ||
                    detail::in_scaled_range(delta, detail::kTbzFieldBits)) {
                    const uint32_t word = static_cast<uint32_t>(out.code_size / 4U);
                    if (!emit((insn & ~(0x3fffU << 5U)) |
                              ((static_cast<uint32_t>(delta >> 2) & 0x3fffU) << 5U)))
                        return false;
                    if (!add_fixup({word, orig, target_index,
                                    static_cast<uint64_t>(target),
                                    InstrKind::Tbz, false, true,
                                    detail::kTbzFieldBits, 5U, 0x3fffU}))
                        return false;
                } else {
                    const uint32_t inverted =
                        (insn ^ 0x01000000U) & ~(0x3fffU << 5U);
                    if (!emit(inverted | (5U << 5U))) return false;
                    if (!emit_far_branch(static_cast<uint64_t>(target), orig,
                                         target_index))
                        return false;
                }
            }
            // ADR
            else if ((insn & 0x9f000000U) == 0x10000000U) {
                const uint32_t immlo = (insn >> 29U) & 0x3U;
                const uint32_t immhi = (insn >> 5U) & 0x7ffffU;
                const int64_t target =
                    src_pc + detail::sign_extend((immhi << 2U) | immlo, 21);
                const uint32_t target_index =
                    intra_index(static_cast<uint64_t>(target));
                push_trace(InstrKind::Adr, static_cast<uint64_t>(target),
                           target_index != kNoIndex, false);
                const int64_t delta = target - static_cast<int64_t>(clone_pc);
                const uint32_t rd = insn & 0x1fU;
                if (detail::in_byte_range(delta, detail::kAdrFieldBits)) {
                    const uint32_t value = static_cast<uint32_t>(delta);
                    const uint32_t word = static_cast<uint32_t>(out.code_size / 4U);
                    if (!emit((insn & 0x9f00001fU) | ((value & 0x3U) << 29U) |
                              (((value >> 2U) & 0x7ffffU) << 5U)))
                        return false;
                    if (!add_fixup({word, orig, target_index,
                                    static_cast<uint64_t>(target),
                                    InstrKind::Adr, false, true, 0, 0, 0}))
                        return false;
                } else {
                    if (!emit_absolute_load(rd, static_cast<uint64_t>(target), orig,
                                            target_index))
                        return false;
                }
            }
            // ADRP: the absolute page goes through the inline literal; the
            // paired ADD/LDR keeps its own low-12 bits untouched.
            else if ((insn & 0x9f000000U) == 0x90000000U) {
                const uint32_t immlo = (insn >> 29U) & 0x3U;
                const uint32_t immhi = (insn >> 5U) & 0x7ffffU;
                const int64_t page =
                    (static_cast<int64_t>(src_pc) & ~0xfffLL) +
                    detail::sign_extend((immhi << 2U) | immlo, 21) * 4096;
                push_trace(InstrKind::Adrp, static_cast<uint64_t>(page), false,
                           false);
                const uint32_t rd = insn & 0x1fU;
                if (!emit_absolute_load(rd, static_cast<uint64_t>(page), orig,
                                        kNoIndex))
                    return false;
            }
            // LDR (literal) family. The literal address always stays the
            // ORIGINAL one. In range the exact encoding is reproduced. Out of
            // range the scalar forms are rewritten subtype-correctly using the
            // destination register itself as the address scratch (it is
            // overwritten by the load anyway); PRFM is not a register load,
            // SIMD/FP needs a vector scratch and Rt==31 would mean SP, so
            // those are refused with a recorded reason.
            else if ((insn & 0x3b000000U) == 0x18000000U) {
                const int64_t literal =
                    src_pc + detail::sign_extend((insn >> 5U) & 0x7ffffU, 19) * 4;
                const uint32_t rt = insn & 0x1fU;
                const uint32_t opc = (insn >> 30U) & 0x3U;
                const uint32_t vector = (insn >> 26U) & 1U;
                const uint8_t subtype = static_cast<uint8_t>((opc << 1U) | vector);
                push_trace(InstrKind::LdrLiteral, static_cast<uint64_t>(literal),
                           false, false);
                const int64_t delta = literal - static_cast<int64_t>(clone_pc);
                if (detail::in_scaled_range(delta, detail::kBranchCondFieldBits)) {
                    const uint32_t word = static_cast<uint32_t>(out.code_size / 4U);
                    if (!emit((insn & ~(0x7ffffU << 5U)) |
                              ((static_cast<uint32_t>(delta >> 2) & 0x7ffffU) << 5U)))
                        return false;
                    if (!add_fixup({word, orig, kNoIndex,
                                    static_cast<uint64_t>(literal),
                                    InstrKind::LdrLiteral, false, true,
                                    detail::kBranchCondFieldBits, 5U, 0x7ffffU}))
                        return false;
                } else if (vector != 0U) {
                    note_reject(RejectReason::LdrLiteralSimd, orig, src_pc, insn,
                                subtype, static_cast<uint64_t>(literal), clone_pc);
                    out.unsupported = true;
                    return false;
                } else if (opc == 3U) {
                    note_reject(RejectReason::LdrLiteralPrfm, orig, src_pc, insn,
                                subtype, static_cast<uint64_t>(literal), clone_pc);
                    out.unsupported = true;
                    return false;
                } else if (rt == 31U) {
                    note_reject(RejectReason::LdrLiteralZeroRegister, orig, src_pc,
                                insn, subtype, static_cast<uint64_t>(literal),
                                clone_pc);
                    out.unsupported = true;
                    return false;
                } else {
                    // adr Rt,#16 / ldr Rt,[Rt] / <subtype> Rt,[Rt] / b .+12 / quad
                    const uint32_t at = static_cast<uint32_t>(out.code_size);
                    if (!emit(detail::adr_rd_imm(rt, 16U))) return false;
                    if (!emit(detail::ldr_rd_from_rn(rt, rt))) return false;
                    const uint32_t load =
                        opc == 0U ? (0xb9400000U | rt | (rt << 5U))   // ldr   Wt,[Xt]
                        : opc == 1U ? (0xf9400000U | rt | (rt << 5U)) // ldr   Xt,[Xt]
                                    : (0xb9800000U | rt | (rt << 5U)); // ldrsw Xt,[Xt]
                    if (!emit(load)) return false;
                    if (!emit(detail::b_imm(12U))) return false;
                    if (!emit_quad(static_cast<uint64_t>(literal))) return false;
                    if (!add_fixup({at / 4U + 4U, orig, kNoIndex,
                                    static_cast<uint64_t>(literal),
                                    InstrKind::LdrLiteral, true, false, 0, 0, 0}))
                        return false;
                }
            }
            // BR / BLR (register indirect): copied verbatim; the landing is a
            // runtime property that the simulator follows.
            else if ((insn & 0xfffffc1fU) == 0xd61f0000U ||
                     (insn & 0xfffffc1fU) == 0xd63f0000U) {
                const bool links = (insn & 0xfffffc1fU) == 0xd63f0000U;
                const uint8_t rn = static_cast<uint8_t>((insn >> 5U) & 0x1fU);
                push_trace(InstrKind::Br, 0, false, true, rn, links);
                if ((out.dispatcher.mode & 1U) != 0U) {
                    if (!emit_indirect_stub(rn, links, false)) return false;
                } else if (!emit(insn)) {
                    return false;
                }
            }
            // PAC'd branches keep their hardware authentication instruction.
            // A runtime follower still needs a post-authentication target
            // observation; a raw register value is not sufficient evidence.
            else if ((insn & 0xfefff800U) == 0xd61f0800U ||
                     (insn & 0xfefff800U) == 0xd63f0800U) {
                const bool links = (insn & 0xfefff800U) == 0xd63f0800U;
                push_trace(InstrKind::PacBranch, 0, false, true,
                           static_cast<uint8_t>((insn >> 5U) & 0x1fU), links,
                           static_cast<uint8_t>((insn >> 21U) & 0x7U));
                if (!emit(insn)) return false;
            }
            // RET
            else if ((insn & 0xfffffc1fU) == 0xd65f0000U) {
                const uint8_t rn = static_cast<uint8_t>((insn >> 5U) & 0x1fU);
                push_trace(InstrKind::Ret, 0, false, true, rn);
                if ((out.dispatcher.mode & 2U) != 0U) {
                    if (!emit_indirect_stub(rn, false, true)) return false;
                } else if (!emit(insn)) {
                    return false;
                }
            }
            // RETAA / RETAB authenticate LR against SP before returning.
            // They cannot use the ordinary RET dispatcher stub, which would
            // branch on the still-signed pointer. Keep the hardware operation
            // intact and mark the trace as requiring authenticated evidence.
            else if (insn == 0xd65f0bffU || insn == 0xd65f0fffU) {
                push_trace(InstrKind::PacReturn, 0, false, true, 30U);
                if (!emit(insn)) return false;
            }
            // Explicitly known position-independent encodings only. Unknown
            // A64 words are rejected with their raw opcode and source PC.
            else {
                if (!detail::known_position_independent_copy(insn)) {
                    const uint32_t group = (insn >> 25U) & 0xfU;
                    note_reject(RejectReason::UnknownEncoding, orig, src_pc, insn,
                                static_cast<uint8_t>(group), 0, clone_pc);
                    out.unsupported = true;
                    return false;
                }
                if (!emit(insn)) return false;
            }
        }

        out.placeholder_index = static_cast<uint32_t>(out.code_size);

        // Pass 2: resolve every fixup against the final clone layout.
        for (size_t slot = 0; slot < fixup_count; ++slot) {
            const Fixup &fixup = fixups[slot];
            uint64_t target = fixup.external_target;
            if (fixup.target_index != kNoIndex &&
                fixup.target_index < out.map_size) {
                // Intra-block: follow the clone's own layout.
                target = clone_address + out.map[fixup.target_index].clone_offset;
            }
            if (fixup.expanded) {
                uint8_t *slot_bytes = out.code + fixup.word_index * 4U;
                for (unsigned byte = 0; byte < 8U; ++byte)
                    slot_bytes[byte] =
                        static_cast<uint8_t>((target >> (byte * 8U)) & 0xffU);
                continue;
            }
            if (!fixup.direct_patch) continue;
            const uint64_t at = clone_address + fixup.word_index * 4U;
            const int64_t delta = static_cast<int64_t>(target) -
                                  static_cast<int64_t>(at);
            uint32_t *word = reinterpret_cast<uint32_t *>(
                out.code + fixup.word_index * 4U);
            if (fixup.field_bits != 0) {
                if (!detail::in_scaled_range(delta, fixup.field_bits)) {
                    out.out_of_range = true;
                    out.reject.reason = RejectReason::OutOfRange;
                    out.reject.orig_index = fixup.orig_index;
                    out.reject.target = target;
                    out.reject.clone_pc = at;
                    out.reject.delta = delta;
                    return false;
                }
                *word = (*word & ~(fixup.field_mask << fixup.field_shift)) |
                        ((static_cast<uint32_t>(delta >> 2) & fixup.field_mask)
                         << fixup.field_shift);
            } else {
                // ADR: 21-bit byte-scaled immediate split as immhi:immlo.
                if (!detail::in_byte_range(delta, detail::kAdrFieldBits)) {
                    out.out_of_range = true;
                    return false;
                }
                const uint32_t value = static_cast<uint32_t>(delta);
                *word = (*word & 0x9f00001fU) | ((value & 0x3U) << 29U) |
                        (((value >> 2U) & 0x7ffffU) << 5U);
            }
        }

        return !out.overflow && !out.unsupported && !out.out_of_range;
    }

    // Reverse lookup for fault routing: clone offset -> original index.
    static bool original_index_for(const RelocationResult &result,
                                   uint32_t clone_offset, uint32_t &orig_index)
    {
        orig_index = 0;
        if (result.map == nullptr || result.map_size == 0) return false;
        /* Only a real instruction inside the emitted code may be mapped:
         * a misaligned offset, a byte past the code, or a byte inside an
         * inline literal is not an instruction, so the lookup refuses it
         * instead of attributing data to the nearest preceding instruction. */
        if ((clone_offset & 3U) != 0U) return false;
        if (clone_offset >= result.placeholder_index) return false;
        if (clone_offset_is_literal(result, clone_offset)) return false;
        uint32_t best = 0;
        bool found = false;
        for (size_t slot = 0; slot < result.map_size; ++slot) {
            if (result.map[slot].clone_offset <= clone_offset) {
                best = result.map[slot].orig_index;
                found = true;
            } else {
                break;
            }
        }
        orig_index = best;
        return found;
    }

    // Forward lookup: original index -> clone offset.
    static bool clone_offset_for(const RelocationResult &result,
                                 uint32_t orig_index, uint32_t &clone_offset)
    {
        for (size_t slot = 0; slot < result.map_size; ++slot) {
            if (result.map[slot].orig_index == orig_index) {
                clone_offset = result.map[slot].clone_offset;
                return true;
            }
        }
        return false;
    }
};

} // namespace rtgum_dbi
