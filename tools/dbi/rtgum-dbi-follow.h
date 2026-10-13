// rtgum-dbi-follow.h - per-thread block follower and target cache
//
// First stage of the runtime follower: it keeps, per thread, the current
// block and call state, maintains a shadow stack for returns, and resolves
// indirect branch targets through a cache keyed by (address space, original
// target, code version, branch kind). The cache is invalidated whenever the
// code version changes (unload, re-protect, rewrite).
//
// Freestanding like the relocator core: no libc, no allocation. Per-thread
// storage is owned by the caller (thread_local in the control tool, static
// storage in a -nostdlib module), so no TLS runtime support is required.
#pragma once

#include <stdint.h>
#include <stddef.h>

namespace rtgum_dbi {

enum class BranchClass : uint8_t {
    Direct = 0,   // B / BL: target is static, no cache needed
    Branch,       // BR
    Call,         // BLR
    Return,       // RET
    Pac,          // authenticated branch (kept verbatim today)
};

struct BlockKey {
    uint64_t address_space;  // mm / process identity
    uint64_t target;         // original (source-side) target address
    uint32_t code_version;   // bumped on unload / re-protect / rewrite
    BranchClass kind;
};

struct BlockEntry {
    BlockKey key;
    uint64_t clone_entry;    // translated block entry, 0 when unknown
    uint32_t hits;
    bool valid;
};

enum class FollowStatus : uint8_t {
    Ok = 0,
    CacheMiss,        // no translation yet: the caller must translate/emit
    ReturnMismatch,   // RET target differs from the shadow-stack top
    ShadowUnderflow,  // RET with an empty shadow stack
    ShadowOverflow,   // call with a full shadow stack
    StaleVersion,     // entry belonged to a previous code version
    MissingContinuation, // BLR has no known clone-side return address
    InvalidCheckpoint, // a signal checkpoint belongs to another mm/version
    LandingUnverified, // guarded-page state was not established by the caller
    InvalidLanding,    // a guarded indirect target lacks a compatible BTI pad
    AuthenticationUnverified, // a PAC branch was not authenticated in hardware
};

/* Evidence must come from the actual target process, after any PAC
 * authentication and with the target page's guarded attribute known. A
 * stripped pointer (XPACI) is never authentication evidence. For a PAC
 * branch, links distinguishes BLRAA/BLRAB from BRAA/BRAB. */
struct LandingEvidence {
    bool guard_known;
    bool guarded;
    bool authenticated;
    bool links;
    uint32_t first_instruction;
};

inline FollowStatus validate_landing(BranchClass kind,
                                     const LandingEvidence *evidence)
{
    if (kind == BranchClass::Return || kind == BranchClass::Direct)
        return FollowStatus::Ok;
    if (!evidence || !evidence->guard_known)
        return FollowStatus::LandingUnverified;
    if (kind == BranchClass::Pac && !evidence->authenticated)
        return FollowStatus::AuthenticationUnverified;
    if (!evidence->guarded) return FollowStatus::Ok;
    const bool call = kind == BranchClass::Call ||
                      (kind == BranchClass::Pac && evidence->links);
    const uint32_t word = evidence->first_instruction;
    const bool either = word == 0xd50324dfU; // BTI jc
    const bool valid = call
        ? (either || word == 0xd503245fU || // BTI c
           word == 0xd503233fU || word == 0xd503237fU) // PACIASP/IBSP
        : (either || word == 0xd503249fU); // BTI j
    return valid ? FollowStatus::Ok : FollowStatus::InvalidLanding;
}

struct CallFrame {
    uint64_t expected_return;  // clone-side continuation of the call
    uint64_t orig_caller;      // original-side call site (diagnostics)
};

struct ThreadState {
    uint64_t address_space;
    uint64_t current_orig_pc;
    uint64_t current_clone_pc;
    uint32_t code_version;
    uint32_t depth;
    CallFrame shadow[32];
};

struct SignalCheckpoint {
    uint64_t address_space;
    uint32_t code_version;
    uint32_t depth;
    CallFrame shadow[32];
};

struct FollowStats {
    uint64_t cache_hits;
    uint64_t cache_misses;
    uint64_t returns_checked;
    uint64_t returns_matched;
    uint64_t invalidations;
    uint64_t unwinds;        // non-local returns resolved by unwinding
    uint64_t tail_calls;     // frames replaced instead of pushed
    uint64_t signal_frames;  // handler call frames restored by checkpoint
};

// Fixed-size direct-mapped cache: no allocation, bounded worst case.
class TargetCache {
public:
    static constexpr size_t kSlots = 64;

    void reset()
    {
        for (size_t slot = 0; slot < kSlots; ++slot) entries_[slot] = BlockEntry{};
    }

    // A miss asks the caller to translate the block. A version mismatch for
    // the same logical target is reported without changing the cache: a stale
    // thread may still probe a slot holding a newer translation.
    FollowStatus lookup(const BlockKey &key, uint64_t &clone_entry)
    {
        BlockEntry &entry = entries_[hash(key)];
        if (!entry.valid) return FollowStatus::CacheMiss;
        if (entry.key.target != key.target ||
            entry.key.address_space != key.address_space ||
            entry.key.kind != key.kind)
            return FollowStatus::CacheMiss;
        if (entry.key.code_version != key.code_version)
            return FollowStatus::StaleVersion;
        ++entry.hits;
        clone_entry = entry.clone_entry;
        return FollowStatus::Ok;
    }

    void insert(const BlockKey &key, uint64_t clone_entry)
    {
        BlockEntry &entry = entries_[hash(key)];
        entry.key = key;
        entry.clone_entry = clone_entry;
        entry.hits = 0;
        entry.valid = true;
    }

    // Global invalidation: used when code is unloaded or rewritten.
    void invalidate_all()
    {
        reset();
    }

    // Keep only the currently active version. Equality works even when the
    // caller's 32-bit version counter wraps; numerical ordering does not.
    void invalidate_except(uint32_t code_version)
    {
        for (size_t slot = 0; slot < kSlots; ++slot) {
            if (entries_[slot].valid && entries_[slot].key.code_version != code_version)
                entries_[slot] = BlockEntry{};
        }
    }

private:
    static size_t hash(const BlockKey &key)
    {
        uint64_t value = key.target ^ (key.address_space * 0x9e3779b97f4a7c15ULL) ^
                         (static_cast<uint64_t>(key.kind) << 56) ^
                         (static_cast<uint64_t>(key.code_version) << 32);
        value ^= value >> 29;
        return static_cast<size_t>(value % kSlots);
    }

    BlockEntry entries_[kSlots];
};

// Per-thread follower. Every entry point keeps the thread's state coherent so
// a signal or a nested translation cannot observe a half-updated frame.
class Follower {
public:
    explicit Follower(ThreadState &state) : state_(state)
    {
        // ThreadState is owned by the caller and survives Follower wrappers.
        // Reconstructing this facade must not silently discard its call stack.
    }

    void begin_block(uint64_t orig_pc, uint64_t clone_pc)
    {
        state_.current_orig_pc = orig_pc;
        state_.current_clone_pc = clone_pc;
    }

    // A call (BL or BLR) pushes the clone-side continuation.
    FollowStatus on_call(uint64_t expected_return)
    {
        if (state_.depth >= 32U) return FollowStatus::ShadowOverflow;
        state_.shadow[state_.depth].expected_return = expected_return;
        state_.shadow[state_.depth].orig_caller = state_.current_orig_pc;
        ++state_.depth;
        return FollowStatus::Ok;
    }

    // A tail call transfers control without creating a new return address.
    // The existing caller continuation must remain at the top of the stack.
    FollowStatus on_tail_call(uint64_t target, FollowStats &stats)
    {
        if (state_.depth == 0U) return FollowStatus::ShadowUnderflow;
        (void)target;
        ++stats.tail_calls;
        return FollowStatus::Ok;
    }

    // A signal handler can overwrite shadow slots even when its final depth
    // equals the interrupted depth. Save the frames as well as the depth.
    SignalCheckpoint checkpoint() const
    {
        SignalCheckpoint saved{};
        saved.address_space = state_.address_space;
        saved.code_version = state_.code_version;
        saved.depth = state_.depth;
        for (uint32_t i = 0; i < saved.depth; ++i)
            saved.shadow[i] = state_.shadow[i];
        return saved;
    }
    FollowStatus restore_checkpoint(const SignalCheckpoint &saved,
                                    FollowStats &stats)
    {
        if (saved.depth > 32U || saved.address_space != state_.address_space ||
            saved.code_version != state_.code_version)
            return FollowStatus::InvalidCheckpoint;
        for (uint32_t i = 0; i < saved.depth; ++i)
            state_.shadow[i] = saved.shadow[i];
        state_.depth = saved.depth;
        ++stats.signal_frames;
        return FollowStatus::Ok;
    }

    // An ordinary RET must match the top frame. A matching outer frame alone
    // is not evidence of a legal unwind.
    FollowStatus on_return(uint64_t actual_target, FollowStats &stats)
    {
        ++stats.returns_checked;
        if (state_.depth == 0U) return FollowStatus::ShadowUnderflow;
        if (state_.shadow[state_.depth - 1U].expected_return == actual_target) {
            --state_.depth;
            ++stats.returns_matched;
            return FollowStatus::Ok;
        }
        return FollowStatus::ReturnMismatch;
    }

    // Call only after an unwinder/longjmp observer independently establishes
    // the destination frame. Its one-based index prevents a target address
    // repeated in several frames from selecting the wrong frame.
    FollowStatus on_nonlocal_return(uint64_t actual_target,
                                    uint32_t destination_frame,
                                    FollowStats &stats)
    {
        ++stats.returns_checked;
        if (destination_frame == 0U || destination_frame > state_.depth ||
            state_.shadow[destination_frame - 1U].expected_return != actual_target)
            return FollowStatus::ReturnMismatch;
        state_.depth = destination_frame - 1U;
        ++stats.unwinds;
        return FollowStatus::Ok;
    }

    // Resolution of an indirect branch at a block exit: the cache decides
    // whether the target block is already translated.
    FollowStatus on_indirect(const BlockKey &key, TargetCache &cache,
                             uint64_t &clone_entry, FollowStats &stats,
                             uint64_t expected_return = 0,
                             const LandingEvidence *landing = nullptr)
    {
        clone_entry = 0;
        if (key.address_space != state_.address_space ||
            key.code_version != state_.code_version)
            return FollowStatus::StaleVersion;
        const FollowStatus landing_status = validate_landing(key.kind, landing);
        if (landing_status != FollowStatus::Ok) return landing_status;
        const FollowStatus status = cache.lookup(key, clone_entry);
        if (status == FollowStatus::Ok) {
            ++stats.cache_hits;
            if (key.kind == BranchClass::Call ||
                (key.kind == BranchClass::Pac && landing->links)) {
                if (expected_return == 0) return FollowStatus::MissingContinuation;
                return on_call(expected_return);
            }
            if (key.kind == BranchClass::Return)
                return on_return(key.target, stats);
            return status;
        }
        ++stats.cache_misses;
        return status;
    }

    uint32_t depth() const { return state_.depth; }

private:
    ThreadState &state_;
};

} // namespace rtgum_dbi
