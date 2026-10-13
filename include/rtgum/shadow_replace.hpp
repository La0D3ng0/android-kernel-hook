#pragma once

#include "rtgum/host_api_v2.h"
#include "rtgum/native_backend.hpp"
#include "../../tools/dbi/rtgum-dbi.h"

namespace rtgum {
namespace shadow {

constexpr unsigned int kMaximumHooks = 16U;
/* A shadow code page is execute-only.  An LDR-literal absolute jump would
 * perform a data read from the patched page and deliberately hit the clean
 * read view.  Materialize the address entirely in registers instead. */
constexpr unsigned long kPatchJumpBytes = 20UL;
constexpr unsigned long kPacBridgeOffset = 512UL;
constexpr unsigned long kHandleTag = 0x5348000000000000UL; /* "SH" */

struct Ops final {
    long (*read_original)(unsigned long address, void *buffer,
                          unsigned long length);
    long (*ghost_alloc)(unsigned long size, unsigned int protection,
                        unsigned long *out_address);
    long (*ghost_protect)(unsigned long address, unsigned int protection);
    long (*ghost_free)(unsigned long address);
    long (*patch)(unsigned long address, const unsigned char *bytes,
                  unsigned long length, bool fork_propagate);
    long (*unpatch)(unsigned long address, unsigned long length);
    long (*query)(unsigned long address, unsigned long length);
};

struct Slot final {
    unsigned long handle;
    unsigned long retired_handle;
    unsigned long target;
    unsigned long patch_site;
    unsigned long replacement;
    unsigned long trampoline;
    unsigned long patch_length;
    unsigned int generation;
    bool active;
    bool retiring;
};

inline bool IsBti(unsigned int instruction)
{
    return instruction == 0xd503245fU || instruction == 0xd503249fU ||
           instruction == 0xd50324dfU;
}

inline bool IsPacLanding(unsigned int instruction)
{
    /* PACIASP/PACIBSP are valid BTI call landing instructions.  The engine
     * preserves them at the public entry and routes the replacement through
     * a matching AUTI bridge so its compiler prologue receives an unsigned
     * link register. */
    return instruction == 0xd503233fU || instruction == 0xd503237fU;
}

inline unsigned int PacAuthenticate(unsigned int instruction)
{
    if (instruction == 0xd503233fU) return 0xd50323bfU; /* PACIASP -> AUTIASP */
    if (instruction == 0xd503237fU) return 0xd50323ffU; /* PACIBSP -> AUTIBSP */
    return 0U;
}

inline void EncodeImmediateJump(unsigned char *output, unsigned long target)
{
    const auto word = [target](unsigned int half, unsigned int base) {
        return base |
            (static_cast<unsigned int>((target >> (half * 16U)) & 0xffffUL)
             << 5U) |
            16U; /* x16 */
    };
    native::WriteU32(output, word(0U, 0xd2800000U)); /* movz x16, #imm */
    native::WriteU32(output + 4UL, word(1U, 0xf2a00000U));
    native::WriteU32(output + 8UL, word(2U, 0xf2c00000U));
    native::WriteU32(output + 12UL, word(3U, 0xf2e00000U));
    native::WriteU32(output + 16UL, 0xd61f0200U); /* br x16 */
}

inline void EncodeContinuation(unsigned char *output, unsigned long target)
{
    native::EncodeAbsoluteJump(output, target);
    /* The continuation is inside the original function and therefore is not
     * a BTI landing pad.  RET Xn carries return branch semantics (BTYPE=00)
     * and may resume there, whereas BR X16 raises a BTI exception.  This RET
     * does not consume or modify LR; the relocated prologue has already saved
     * the original function's authenticated return address as required. */
    native::WriteU32(output + 4UL, 0xd65f0200U); /* ret x16 */
}

class Engine final {
public:
    Ops ops{};

    void Reset()
    {
        for (Slot &slot : slots_) slot = Slot{};
        next_generation_ = 1U;
    }

    long Replace(unsigned long target, unsigned long replacement,
                 bool fork_propagate, unsigned long *out_original,
                 unsigned long *out_handle)
    {
        if ((target & 3UL) != 0UL || replacement == 0UL || !out_original ||
            !out_handle)
            return RTGUM_HOST_ERR_INVAL;
        *out_original = 0UL;
        *out_handle = 0UL;
        if (!ops.read_original || !ops.ghost_alloc || !ops.ghost_protect ||
            !ops.ghost_free || !ops.patch || !ops.unpatch || !ops.query)
            return RTGUM_HOST_ERR_NOTSUP;
        for (const Slot &slot : slots_)
            if ((slot.active || slot.retiring) && slot.target == target)
                return RTGUM_HOST_ERR_EXIST;

        Slot *free_slot = nullptr;
        unsigned int slot_index = 0U;
        for (unsigned int index = 0U; index < kMaximumHooks; ++index) {
            if (!slots_[index].active && !slots_[index].retiring &&
                slots_[index].trampoline == 0UL) {
                free_slot = &slots_[index];
                slot_index = index;
                break;
            }
        }
        if (!free_slot) return RTGUM_HOST_ERR_BUSY;

        unsigned char first[32]{};
        long status = ops.read_original(target, first, sizeof(first));
        if (status != 0) return status;
        const unsigned int first_instruction = native::ReadU32(first);
        const bool preserves_bti = IsBti(first_instruction);
        const bool preserves_pac = IsPacLanding(first_instruction);
        /* Keep an implicit PAC landing instruction at the real entry.  Apart
         * from retaining BTI compatibility, this makes an execution which
         * races a clean/shadow PTE transition safe: both views sign LR before
         * reaching any common original instruction.  The bridge authenticates
         * that temporary signature before entering the C++ replacement, whose
         * own prologue signs LR normally. */
        const unsigned long source_offset =
            (preserves_bti || preserves_pac) ? 4UL : 0UL;
        const unsigned long patch_site = target + source_offset;
        const unsigned long source_length = kPatchJumpBytes;
        const unsigned long patch_length = source_length;
        if ((patch_site & (native::kPageSize - 1UL)) + patch_length >
            native::kPageSize)
            return RTGUM_HOST_ERR_NOTSUP;
        unsigned long trampoline = 0UL;
        status = ops.ghost_alloc(native::kPageSize,
                                 native::kProtRead | native::kProtWrite,
                                 &trampoline);
        if (status != 0 || trampoline == 0UL)
            return status != 0 ? status : RTGUM_HOST_ERR_NOMEM;
        auto *code = reinterpret_cast<unsigned char *>(trampoline);
        native::WriteU32(code, 0xd503245fU); /* BTI c: indirect original call */
        unsigned long trampoline_cursor = 4UL;
        if (preserves_pac) {
            /* RETAA/RETAB in the original body still requires the copied
             * frame to have signed its trampoline return address. */
            native::WriteU32(code + trampoline_cursor, first_instruction);
            trampoline_cursor += 4UL;
        }
        rtgum_dbi::OffsetMapEntry map[8]{};
        rtgum_dbi::BranchTraceEntry trace[8]{};
        rtgum_dbi::LiteralRange literals[16]{};
        auto relocated = rtgum_dbi::make_result(
            code + trampoline_cursor,
            kPacBridgeOffset - trampoline_cursor - 32UL,
            map, sizeof(map) / sizeof(map[0]), trace,
            sizeof(trace) / sizeof(trace[0]), literals,
            sizeof(literals) / sizeof(literals[0]));
        relocated.dispatcher.return_far_branches = true;
        if (!rtgum_dbi::Relocator::relocate(
                first + source_offset, source_length, patch_site,
                trampoline + trampoline_cursor, relocated)) {
            (void)ops.ghost_free(trampoline);
            return RTGUM_HOST_ERR_NOTSUP;
        }
        trampoline_cursor += relocated.code_size;
        if (trampoline_cursor + 16UL > kPacBridgeOffset) {
            (void)ops.ghost_free(trampoline);
            return RTGUM_HOST_ERR_NOMEM;
        }
        EncodeContinuation(code + trampoline_cursor,
                           patch_site + source_length);
        unsigned long replacement_target = replacement;
        if (preserves_pac) {
            auto *bridge = code + kPacBridgeOffset;
            native::WriteU32(bridge, 0xd503245fU); /* BTI c */
            native::WriteU32(bridge + 4UL,
                             PacAuthenticate(first_instruction));
            native::EncodeAbsoluteJump(bridge + 8UL, replacement);
            replacement_target = trampoline + kPacBridgeOffset;
        }
        status = ops.ghost_protect(trampoline,
                                   native::kProtRead | native::kProtExec);
        if (status != 0) {
            (void)ops.ghost_free(trampoline);
            return status;
        }

        unsigned char jump[kPatchJumpBytes]{};
        EncodeImmediateJump(jump, replacement_target);
        /* Publish the callable original before the target can branch into the
         * replacement.  The caller may pass a runtime-owned atomic word here;
         * this closes the otherwise real first-hit race after PTE activation. */
        __atomic_store_n(out_original, trampoline, __ATOMIC_RELEASE);
        status = ops.patch(patch_site, jump, patch_length, fork_propagate);
        if (status != 0) {
            __atomic_store_n(out_original, 0UL, __ATOMIC_RELEASE);
            (void)ops.ghost_free(trampoline);
            return status;
        }

        unsigned int generation = next_generation_++;
        if (next_generation_ == 0U) next_generation_ = 1U;
        free_slot->generation = generation;
        free_slot->target = target;
        free_slot->patch_site = patch_site;
        free_slot->replacement = replacement;
        free_slot->trampoline = trampoline;
        free_slot->patch_length = patch_length;
        free_slot->active = true;
        free_slot->retiring = false;
        free_slot->handle = kHandleTag |
            (static_cast<unsigned long>(generation) << 8UL) |
            (static_cast<unsigned long>(slot_index) + 1UL);
        free_slot->retired_handle = 0UL;
        __atomic_store_n(out_original, trampoline, __ATOMIC_RELEASE);
        *out_handle = free_slot->handle;
        return 0;
    }

    /* Stop new entries while retaining the original trampoline for wrappers
     * that were already in flight.  Finalize() releases it after the owner
     * observes an empty in-flight count. */
    long Deactivate(unsigned long handle)
    {
        Slot *slot = Find(handle);
        if (!slot) return IsRetired(handle) ? 0L : RTGUM_HOST_ERR_BADF;
        if (slot->retiring) return 0;
        const long status = ops.unpatch(slot->patch_site, slot->patch_length);
        if (status != 0 && status != RTGUM_HOST_ERR_NOENT) return status;
        slot->active = false;
        slot->retiring = true;
        return 0;
    }

    long Finalize(unsigned long handle)
    {
        Slot *slot = Find(handle);
        if (!slot) return IsRetired(handle) ? 0L : RTGUM_HOST_ERR_BADF;
        if (slot->active) return RTGUM_HOST_ERR_BUSY;
        if (!slot->retiring) return RTGUM_HOST_ERR_BADF;
        const unsigned long trampoline = slot->trampoline;
        const long released = trampoline != 0UL ? ops.ghost_free(trampoline) : 0L;
        if (released != 0) return released;
        const unsigned long retired = slot->handle;
        *slot = Slot{};
        slot->retired_handle = retired;
        return 0;
    }

    long Revert(unsigned long handle)
    {
        const long stopped = Deactivate(handle);
        if (stopped != 0) return stopped;
        return Finalize(handle);
    }

    long Query(unsigned long handle, unsigned int *out_state)
    {
        if (!out_state) return RTGUM_HOST_ERR_INVAL;
        Slot *slot = Find(handle);
        if (!slot) {
            if (!IsRetired(handle)) return RTGUM_HOST_ERR_BADF;
            *out_state = RTGUM_HOST_HOOK_INACTIVE;
            return 0;
        }
        if (slot->retiring) {
            *out_state = RTGUM_HOST_HOOK_INACTIVE;
            return 0;
        }
        const long active = ops.query(slot->patch_site, slot->patch_length);
        if (active < 0) return active;
        *out_state = active != 0 ? RTGUM_HOST_HOOK_ACTIVE
                                 : RTGUM_HOST_HOOK_INACTIVE;
        return 0;
    }

    bool Owns(unsigned long handle) const
    {
        return (handle & 0xffff000000000000UL) == kHandleTag;
    }

private:
    Slot *Find(unsigned long handle)
    {
        if (!Owns(handle)) return nullptr;
        const unsigned int id = static_cast<unsigned int>(handle & 0xffUL);
        if (id == 0U || id > kMaximumHooks) return nullptr;
        Slot &slot = slots_[id - 1U];
        return slot.handle == handle && (slot.active || slot.retiring)
                   ? &slot
                   : nullptr;
    }

    bool IsRetired(unsigned long handle) const
    {
        if (!Owns(handle)) return false;
        const unsigned int id = static_cast<unsigned int>(handle & 0xffUL);
        return id != 0U && id <= kMaximumHooks &&
               slots_[id - 1U].retired_handle == handle;
    }

    Slot slots_[kMaximumHooks]{};
    unsigned int next_generation_{1U};
};

}  // namespace shadow
}  // namespace rtgum
