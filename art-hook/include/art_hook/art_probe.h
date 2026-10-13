// art_probe.h - classifying an opaque jmethodID before anything dereferences it
//
// ART does not promise that a jmethodID is a pointer. jni_id_type.h defines
// three modes for the id:
//
//   kPointer          the id IS the ArtMethod* (the historical ABI)
//   kIndices          the id is an index into a JniIdManager table, tagged so
//                     that odd values can never be mistaken for a pointer
//   kSwapablePointer  the id is a pointer into a swapable table
//
// Only the first mode can be turned into an ArtMethod address by arithmetic.
// In the other two the value is a token, and the address lives in a table that
// belongs to the runtime: it can only be obtained through the runtime's own
// decode path (JniIdManager::DecodeMethodId), which is not exported.
//
// Every bug in this area has the same shape: code takes the id, treats it as an
// address, and reads from it. On a device using kIndices that is a read from a
// small integer - a fault, not a wrong answer. The rule this file enforces is
// therefore that a classification must succeed before any dereference, and that
// "cannot decode on this runtime" is a reportable outcome rather than a reason
// to try another cast.
//
// Freestanding like the rest of the art-hook core: no allocation, no STL.
#pragma once

#include <stdint.h>
#include <stddef.h>

namespace art_hook {

// What a jmethodID value turned out to be.
enum class JniIdMode : uint8_t {
    Null = 0,          // the caller passed null
    Pointer,           // the id is directly the ArtMethod*
    Index,             // the id is a table token; the address is not derivable
    SwapablePointer,   // the id is a pointer into a table owned by the runtime
    Unresolved,        // nothing could be proven about it
};

// Why a value was classified the way it was, for logs and tests.
enum class JniIdReason : uint8_t {
    None = 0,
    IsNull,
    OddTagg,             // an odd value is a tagged index by construction
    BelowMappingFloor,   // far too small to be any address in this process
    OutsideAnyMapping,   // not a pointer into any mapping: cannot be an address
    Unaligned,           // not pointer-aligned: cannot be a Pointer-mode id
    NotReadable,         // mapped but the runtime's own read would fault
    LayoutRejected,      // readable, but no ArtMethod layout was found there
    DirectArtMethod,     // the probe accepted it as an ArtMethod record
    IndexToken,          // even value that still decoded as a table token
};

// A snapshot of what a value looks like from the outside, so classification is
// testable without a live runtime. `readable` means "a 32-byte read at this
// address would succeed"; the caller supplies it from its own range knowledge
// (mapping table, or a guarded probe), never by trying the read and hoping.
struct JniIdView {
    uintptr_t value = 0;
    bool mapped = false;        // the value lies inside a mapping
    bool executable = false;    // ... and that mapping is executable
    bool readable = false;      // ... and at least 32 bytes are readable there
    bool in_art_image = false;  // inside boot.art / an OAT / libart itself
};

struct JniIdClassification {
    JniIdMode mode = JniIdMode::Unresolved;
    JniIdReason reason = JniIdReason::None;
    uintptr_t record = 0;  // the ArtMethod address, only for JniIdMode::Pointer

    bool resolved() const { return mode == JniIdMode::Pointer && record != 0; }
    // True when the value must not be dereferenced or probed as a pointer.
    bool opaque() const {
        return mode == JniIdMode::Index || mode == JniIdMode::SwapablePointer ||
               mode == JniIdMode::Unresolved || mode == JniIdMode::Null;
    }
};

// True when the value is small enough that it cannot be an address in this
// process at all. ART maps every image, the heap and libart far above this
// bound, so a value below it is a token regardless of its tag bit - which is
// the check that distinguishes "tagged index" from "low but real address".
// The bound sits far below any plausible mapping base (the lowest mapping in an
// Android process is the 64 KiB-aligned linker region) and far above any
// plausible table index.
constexpr uintptr_t kJniIdTokenCeiling = 0x10000U;  // 64 KiB

inline bool JniIdLooksLikeToken(uintptr_t value)
{
    return value != 0 && value < kJniIdTokenCeiling;
}

// MAY THIS VALUE BE DEREFERENCED? - the safety question, answered on its own.
//
// This is the gate that must be asked BEFORE any read of the candidate, and it
// is deliberately separate from ClassifyJniId: the classifier's answer also
// depends on a layout verdict, so using it as the gate (as an earlier version
// did, with layout_ok hardcoded to false) rejects every pointer-shaped
// candidate without ever running a probe.
//
// True only for a value that is non-zero, untagged, above the mapping floor,
// inside a mapping, pointer-aligned and readable. Everything else must be
// reported, never read.
inline bool JniIdMayBeDereferenced(const JniIdView &view)
{
    return view.value != 0 && (view.value & 1U) == 0U && view.mapped &&
           (view.value & (sizeof(void *) - 1U)) == 0U && view.readable &&
           !JniIdLooksLikeToken(view.value);
}

// Classifies a jmethodID from facts the caller has already established about
// the value.
//
// USE THIS ONLY AFTER ASKING JniIdMayBeDereferenced(). `layout_ok` is the result
// of probing the value as an ArtMethod record, and this function CANNOT answer
// "is it safe to probe": every value that is merely "mapped, aligned and
// readable" comes back as Unresolved/LayoutRejected while layout_ok is false,
// and callers that treated that as final never ran a probe at all. That is not
// hypothetical - it silently made every pointer-shaped jmethodID look like a
// layout mismatch. The order is therefore:
//
//   1. JniIdMayBeDereferenced(view) -> false means STOP, report, do not read;
//   2. otherwise probe the value as an ArtMethod record;
//   3. ClassifyJniId(view, probe_result) -> the verdict.
//
// The remaining order inside this function still matters:
//
//   1. null is not an address;
//   2. an odd value is a tagged index by construction, and a value below the
//      mapping floor is a token even when it is even - both are refused before
//      anything looks at them as a pointer. This is the case that used to
//      fault: a decoder that cast 0x5 to an address and read its first word;
//   3. a value outside every mapping cannot be an address, and a value that is
//      mapped but not readable cannot be probed;
//   4. only then is a layout verdict meaningful.
inline JniIdClassification ClassifyJniId(const JniIdView &view,
                                         [[maybe_unused]] bool layout_ok)
{
    JniIdClassification result;
    if (view.value == 0) {
        result.mode = JniIdMode::Null;
        result.reason = JniIdReason::IsNull;
        return result;
    }
    // (2) The tag bit, then the magnitude. An odd id is an index token on every
    // ART version that defines kIndices; a value far below any possible mapping
    // base is a token even when it is even. Both are refused before anything
    // looks at them as a pointer, which is the case that used to fault: a
    // decoder that cast 0x5 to an address and read its first word.
    if ((view.value & 1U) != 0U) {
        result.mode = JniIdMode::Index;
        result.reason = JniIdReason::OddTagg;
        return result;
    }
    if (JniIdLooksLikeToken(view.value)) {
        result.mode = JniIdMode::Index;
        result.reason = JniIdReason::BelowMappingFloor;
        return result;
    }
    // (3) A pointer-candidate has to be a plausible pointer at all.
    if (!view.mapped) {
        result.mode = JniIdMode::Unresolved;
        result.reason = JniIdReason::OutsideAnyMapping;
        return result;
    }
    if ((view.value & (sizeof(void *) - 1U)) != 0U) {
        result.mode = JniIdMode::Unresolved;
        result.reason = JniIdReason::Unaligned;
        return result;
    }
    if (!view.readable) {
        result.mode = JniIdMode::Unresolved;
        result.reason = JniIdReason::NotReadable;
        return result;
    }
    // (4) Only now can a layout verdict say anything.
    if (!layout_ok) {
        // Readable and aligned but not an ArtMethod record. In kSwapablePointer
        // mode this is exactly what a table slot looks like, and there is no
        // way to tell it apart from an unrelated pointer without the runtime's
        // own decode; reporting "unresolved" keeps that honest.
        result.mode = JniIdMode::Unresolved;
        result.reason = JniIdReason::LayoutRejected;
        return result;
    }
    result.mode = JniIdMode::Pointer;
    result.reason = JniIdReason::DirectArtMethod;
    result.record = view.value;
    return result;
}

}  // namespace art_hook
