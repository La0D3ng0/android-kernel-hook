// rtgum-dbi-ehframe.h - clone the C++ exception frame of a relocated block
//
// A relocated block has no entry in any module's .eh_frame, so the platform
// unwinder cannot find an FDE for a PC inside the clone (it looks FDEs up by PC
// through dl_iterate_phdr and every DSO's .eh_frame_hdr). Unwinding through a
// relocated frame therefore terminates the process instead of reaching the
// caller's landing pad.
//
// For the supported CIE/LSDA/CFI subset, this header finds one complete source
// function, rebuilds its frame records using the relocator's OffsetMap, and
// registers the new FDE with the same unwinder used for exception propagation.
//
// The core is freestanding like the relocator core: no libc, no STL, no
// allocation. The caller owns the buffer and the lifetime of the buffer must
// match the clone page, because the unwinder keeps a pointer into it.
//
// Two DWARF facts drive the rewrite and are worth stating explicitly:
//   * the CIE's 'R' augmentation describes its FDE initial_location encoding;
//     the .eh_frame_hdr table has a separate encoding in its own header.
//     This builder currently emits only pcrel|sdata4 FDE locations.
//   * an encoded pointer marked DW_EH_PE_indirect holds the address of a slot.
//     Rebase the encoded slot address, then let the unwinder dereference it.
#pragma once

#include <stdint.h>
#include <stddef.h>
// The only system headers this subset needs: the loader's program-header walk
// and the Phdr field names. A -nostdlib module that cannot include them simply
// does not use this header.
#include <link.h>
#include <elf.h>
#include "rtgum-dbi.h"

// The NDK <elf.h> deliberately drops the GNU program-header types. The value is
// the psABI one and is what dl_iterate_phdr reports for PT_GNU_EH_FRAME.
#ifndef PT_GNU_EH_FRAME
#define PT_GNU_EH_FRAME 0x6474e550
#endif

namespace rtgum_dbi {

// The unwinder's dynamic-registration entry points. Declared here because the
// relocator stays usable in a -nostdlib module that may not include <unwind.h>.
extern "C" void __register_frame(void *fde_begin);
extern "C" void __deregister_frame(void *fde_begin);

// DWARF pointer encodings. Only the subset a relocation needs is listed.
enum : uint8_t {
    kEhAbsptr = 0x00,
    kEhUleb128 = 0x01,
    kEhUdata2 = 0x02,
    kEhUdata4 = 0x03,
    kEhUdata8 = 0x04,
    kEhSleb128 = 0x09,
    kEhSdata2 = 0x0a,
    kEhSdata4 = 0x0b,
    kEhSdata8 = 0x0c,
    kEhPcrel = 0x10,
    kEhTextrel = 0x20,
    kEhDatarel = 0x30,
    kEhFuncrel = 0x40,
    kEhAligned = 0x50,
    kEhIndirect = 0x80,
    kEhOmit = 0xff,
};

enum class FdeStatus : uint8_t {
    Ok = 0,
    NoModule,        // no loaded module covers the source PC
    NoEhFrame,       // the module has no PT_GNU_EH_FRAME
    NoFde,           // the .eh_frame list was walked without a covering FDE
    Truncated,       // the .eh_frame list ended mid-entry
    TooSmall,        // the caller buffer cannot hold [CIE..FDE] + terminator
    UnsupportedEnc,  // the FDE pointer uses an encoding we refuse to rewrite
    PersonaUnencodable,  // the resolved personality does not fit its field width
};

// Why find_module_for_address gave up. The walk has several early exits and a
// silent "no module" is impossible to debug from the outside, so the reason
// travels with the result.
enum class ModuleStatus : uint8_t {
    Ok = 0,
    NoCoveringSegment,  // no PT_LOAD contains the address
    NoEhFrameSegment,   // the module has no PT_GNU_EH_FRAME
    BadEhFrameHdr,      // the header is too short or not version 1
    UnsupportedPointerEncoding,  // eh_frame_ptr_enc is not pcrel|sdata4
    NoEhFrameRange,     // the .eh_frame range could not be bounded
};

// The module the source PC belongs to. The caller fills this through
// find_module_for_address and can print module_name when a lookup fails.
struct EhModule {
    uint64_t base;              // dlpi_addr
    const char *module_name;    // owned by the loader, not by us
    const uint8_t *eh_frame;    // resolved from the header, not from a program header
    uint64_t eh_frame_size;     // only the bytes the header vouches for
    const uint8_t *eh_frame_hdr;
    uint64_t eh_frame_hdr_size;
    bool found;
};

// Where the matched FDE sits inside .eh_frame and how far it reaches. The
// offsets are byte offsets from eh_frame, which is what a caller needs to
// re-derive the same FDE for a different clone address.
struct FdeLocation {
    uint32_t cie_offset;      // byte offset of the CIE the FDE points at
    uint32_t cie_size;        // CIE length field + 4 (the whole entry)
    uint32_t fde_offset;      // byte offset of the FDE
    uint32_t fde_size;        // FDE length field + 4 (the whole entry)
    uint64_t initial_location;  // source PC the FDE describes
    uint64_t address_range;
    uint8_t fde_pointer_encoding;    // the encoding initial_location used
    uint8_t personality_encoding;    // CIE 'P' encoding, kEhOmit when absent
    uint8_t lsda_encoding;           // CIE 'L' encoding, kEhOmit when absent
};

// The outcome of build_clone_fde. clone_fde is the value to hand to
// register_clone_fde; clone_size is the buffer actually used.
struct CloneFdeResult {
    FdeStatus status;
    uint8_t *clone_fde;      // first FDE, after the CIE, on success
    uint32_t clone_size;     // [CIE..FDE] + 4-byte terminator
    uint32_t cie_bytes;      // how much of clone_size is CIE
    uint32_t fde_bytes;
    uint8_t kept_encoding;   // the encoding written for initial_location
    int64_t delta;           // clone_base - source_base
    bool personality_rewritten;
    bool lsda_rewritten;
    uint32_t descriptor_count;  // exactly one for the supported single-function case
    uint32_t input_cie_size;    // what the builder was handed
    uint32_t input_fde_size;
    uint32_t input_relocated_size;
    uint64_t input_clone_base;
    uint64_t input_source_end;
};

namespace detail {

inline uint64_t read_u64(const uint8_t *p, size_t offset)
{
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i) value |= static_cast<uint64_t>(p[offset + i]) << (i * 8U);
    return value;
}

inline uint32_t read_u32(const uint8_t *p, size_t offset)
{
    return static_cast<uint32_t>(read_u64(p, offset));
}

inline int64_t read_i32(const uint8_t *p, size_t offset)
{
    return static_cast<int64_t>(static_cast<int32_t>(read_u32(p, offset)));
}

inline uint16_t read_u16(const uint8_t *p, size_t offset)
{
    return static_cast<uint16_t>(p[offset] | (static_cast<uint16_t>(p[offset + 1]) << 8U));
}

inline void write_u64(uint8_t *p, uint64_t value)
{
    for (unsigned i = 0; i < 8; ++i) p[i] = static_cast<uint8_t>(value >> (i * 8U));
}

inline void write_u32(uint8_t *p, uint32_t value)
{
    for (unsigned i = 0; i < 4; ++i) p[i] = static_cast<uint8_t>(value >> (i * 8U));
}

// Reads a bounded uleb128/sleb128. Returns the count consumed, 0 when the field
// would run past the end (malformed data must not walk off the mapping).
inline size_t read_leb(const uint8_t *p, size_t limit, uint64_t *value,
                       bool sign_extend)
{
    uint64_t result = 0;
    unsigned shift = 0;
    size_t used = 0;
    while (used < limit && used < 10U) {
        const uint8_t byte = p[used++];
        if (shift == 63U && (byte & 0x7eU) != 0U) return 0;
        result |= static_cast<uint64_t>(byte & 0x7fU) << shift;
        if ((byte & 0x80U) == 0) {
            const unsigned sign_shift = shift + 7U;
            if (sign_extend && sign_shift < 64U && (byte & 0x40U) != 0)
                result |= ~0ULL << sign_shift;
            *value = result;
            return used;
        }
        shift += 7U;
        if (shift >= 64U) return 0;
    }
    return 0;
}

// True for the fixed-size encodings this rewriter understands. The variable
// length ones (uleb128/sleb128) are deliberately absent: rewriting one for a
// new delta can need a different byte count, which would move every following
// byte of the copy.
inline bool fixed_width(uint8_t format, size_t *width)
{
    switch (format) {
    case kEhUdata2:
    case kEhSdata2:
        *width = 2;
        return true;
    case kEhUdata4:
    case kEhSdata4:
        *width = 4;
        return true;
    case kEhAbsptr:
    case kEhUdata8:
    case kEhSdata8:
        *width = 8;
        return true;
    default:
        return false;
    }
}

// Decodes one encoded pointer at `field` (an absolute address) whose meaning is
// relative to `section_address` for the datarel application. The output is an
// absolute value, so an indirect field is dereferenced here: the caller then
// re-encodes a direct pointer.
inline bool read_encoded(const uint8_t *field, size_t limit, uint8_t encoding,
                         size_t section_address, uint64_t *out)
{
    if (encoding == kEhOmit) {
        *out = 0;
        return true;
    }
    const uint8_t format = static_cast<uint8_t>(encoding & 0x0fU);
    const uint8_t application = static_cast<uint8_t>(encoding & 0x70U);
    const bool indirect = (encoding & kEhIndirect) != 0;
    size_t width = 0;
    uint64_t raw = 0;
    if (!fixed_width(format, &width)) {
        if (format != kEhUleb128 && format != kEhSleb128) return false;
        const bool sign_extend = (format == kEhSleb128);
        if (read_leb(field, limit, &raw, sign_extend) == 0) return false;
    } else {
        if (limit < width) return false;
        switch (width) {
        case 2:
            raw = read_u16(field, 0);
            break;
        case 4:
            raw = static_cast<uint64_t>(read_u32(field, 0));
            break;
        default:
            raw = read_u64(field, 0);
            break;
        }
    }
    // The 'data' forms of a relative encoding carry a signed offset. The 4-byte
    // forms are read as signed whenever they are relative: lld emits
    // DW_EH_PE_indirect|sdata4 for the lookup table and pcrel|sdata4 for the FDE
    // PC field, and both are two's-complement deltas.
    const bool relative = (application == kEhPcrel || application == kEhDatarel);
    if (width == 2 && (format == kEhSdata2 || relative))
        raw = static_cast<uint64_t>(static_cast<int64_t>(static_cast<int16_t>(raw)));
    if (width == 4 && (format == kEhSdata4 || relative))
        raw = static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(raw)));
    uint64_t value = raw;
    switch (application) {
    case kEhPcrel:
        value = reinterpret_cast<uint64_t>(field);
        break;
    case kEhDatarel:
        value = section_address;
        break;
    case kEhTextrel:
    case kEhFuncrel:
        // Not emitted by this toolchain for the fields we touch.
        return false;
    default:
        value = 0;
        break;
    }
    value += raw;
    if (indirect) {
        if (value == 0) return false;
        // The slot lives in the source image and holds the true target.
        value = *reinterpret_cast<const uint64_t *>(value);
    }
    *out = value;
    return true;
}

// Writes `value` back at `field` using `encoding` with the indirect flag
// cleared, i.e. a direct pointer the unwinder can read straight out of the copy.
// The field width is checked, so a value that no longer fits is reported rather
// than truncated into a plausible-looking wrong pointer.
inline bool write_encoded_direct(uint8_t *field, uint8_t encoding, uint64_t value)
{
    const uint8_t format = static_cast<uint8_t>(encoding & 0x0fU);
    const uint8_t application = static_cast<uint8_t>(encoding & 0x70U);
    const uint64_t field_address = reinterpret_cast<uint64_t>(field);
    uint64_t relative = value;
    switch (application) {
    case kEhPcrel:
        relative = value - field_address;
        break;
    case kEhDatarel:
        return false;  // no section base is known for a copy out of .eh_frame
    case kEhTextrel:
    case kEhFuncrel:
        return false;
    default:
        break;
    }
    size_t width = 0;
    if (!fixed_width(format, &width)) return false;
    const int64_t signed_relative = static_cast<int64_t>(relative);
    switch (width) {
    case 2:
        if (format == kEhSdata2) {
            if (signed_relative < -0x8000LL || signed_relative > 0x7fffLL) return false;
        } else if (relative > 0xffffULL) {
            return false;
        }
        field[0] = static_cast<uint8_t>(relative);
        field[1] = static_cast<uint8_t>(relative >> 8U);
        return true;
    case 4: {
        // A signed relative field accepts any two's-complement delta; an
        // absolute 32-bit field must fit in the low 32 bits unchanged.
        const bool signed_field = (format == kEhSdata4) ||
                                  (format == kEhUdata4 && application != 0);
        if (signed_field) {
            if (signed_relative < -0x80000000LL || signed_relative > 0x7fffffffLL) return false;
        } else if (relative > 0xffffffffULL) {
            return false;
        }
        write_u32(field, static_cast<uint32_t>(relative));
        return true;
    }
    default:
        write_u64(field, relative);
        return true;
    }
}

// Why find_module_for_address gave up. The walk has several early exits and a
// silent "no module" is impossible to debug from the outside, so the reason
// travels with the result.
// Finds the module that covers `address`, then resolves its .eh_frame from the
// PT_GNU_EH_FRAME segment. The segment IS .eh_frame_hdr: its first field is a
// pcrel pointer to .eh_frame, which is the only reliable way to find that
// section because .eh_frame itself has no program header of its own.
struct ModuleFinder {
    uint64_t address;
    ModuleStatus status;
    EhModule module;
};

inline int find_module_callback(struct dl_phdr_info *info, size_t info_size, void *data)
{
    (void)info_size;
    ModuleFinder *finder = static_cast<ModuleFinder *>(data);
    if (finder->module.found) return 1;
    const ElfW(Phdr) *eh_frame_hdr = nullptr;
    for (unsigned index = 0; index < info->dlpi_phnum; ++index) {
        if (info->dlpi_phdr[index].p_type == PT_GNU_EH_FRAME)
            eh_frame_hdr = &info->dlpi_phdr[index];
    }
    bool covers = false;
    for (unsigned index = 0; index < info->dlpi_phnum; ++index) {
        const ElfW(Phdr) &phdr = info->dlpi_phdr[index];
        if (phdr.p_type != PT_LOAD) continue;
        const uint64_t start = static_cast<uint64_t>(info->dlpi_addr) + phdr.p_vaddr;
        if (finder->address >= start && finder->address < start + phdr.p_memsz) {
            covers = true;
            break;
        }
    }
    if (!covers) return 0;
    if (eh_frame_hdr == nullptr) {
        finder->status = ModuleStatus::NoEhFrameSegment;
        return 1;
    }
    const uint8_t *header = reinterpret_cast<const uint8_t *>(
        static_cast<uint64_t>(info->dlpi_addr) + eh_frame_hdr->p_vaddr);
    if (eh_frame_hdr->p_memsz < 8U || header[0] != 1U) {
        finder->status = ModuleStatus::BadEhFrameHdr;
        return 1;
    }
    // version(1) eh_frame_ptr_enc fde_count_enc table_enc ...
    const uint8_t pointer_encoding = header[1];
    const uint8_t format = static_cast<uint8_t>(pointer_encoding & 0x0fU);
    size_t width = 0;
    if ((pointer_encoding & 0x70U) != kEhPcrel || !fixed_width(format, &width) ||
        width != 4U) {
        finder->status = ModuleStatus::UnsupportedPointerEncoding;
        return 1;
    }
    const uint8_t *field = header + 4U;
    // Sign-extend through int32_t: casting a negative sdata4 to int64_t by way
    // of uint64_t would zero-extend it and turn a negative offset into an
    // address far outside the mapping.
    const int64_t section_offset =
        static_cast<int64_t>(static_cast<int32_t>(read_u32(field, 0)));
    const uint64_t field_address = reinterpret_cast<uint64_t>(field);
    const uint64_t section =
        static_cast<uint64_t>(static_cast<int64_t>(field_address) + section_offset);
    // .eh_frame has no program header of its own, so its end is bounded by the
    // first thing that comes after it in the same address space: the next PT_LOAD
    // that starts past the section, or the end of the load containing it. Using
    // the PT_GNU_EH_FRAME segment's own end would be wrong - that segment only
    // covers .eh_frame_hdr and stops a few bytes into .eh_frame.
    //
    // Section headers are deliberately not consulted: on this toolchain the
    // section table and the program headers disagree about where .eh_frame
    // starts, and only the program headers describe what the loader mapped.
    uint64_t bound = 0;
    for (unsigned index = 0; index < info->dlpi_phnum; ++index) {
        const ElfW(Phdr) &phdr = info->dlpi_phdr[index];
        if (phdr.p_type != PT_LOAD) continue;
        const uint64_t start = static_cast<uint64_t>(info->dlpi_addr) + phdr.p_vaddr;
        const uint64_t end = start + phdr.p_memsz;
        if (section >= start && section < end) bound = end;
        if (start > section && (bound == 0 || start < bound)) bound = start;
    }
    if (bound <= section) {
        finder->status = ModuleStatus::NoEhFrameRange;
        return 1;
    }
    finder->module.base = info->dlpi_addr;
    finder->module.module_name = info->dlpi_name;
    finder->module.eh_frame = reinterpret_cast<const uint8_t *>(section);
    finder->module.eh_frame_size = bound - section;
    finder->module.eh_frame_hdr = header;
    finder->module.eh_frame_hdr_size = eh_frame_hdr->p_memsz;
    finder->module.found = true;
    finder->status = ModuleStatus::Ok;
    return 1;
}

// How an FDE search ended and where it was looking. A miss is otherwise
// indistinguishable from a malformed section, and the walk has several exits,
// so the reason travels with the result.
struct FdeProbe {
    uint32_t entries;        // records visited (CIE + FDE)
    uint32_t exit_code;      // 1 terminator, 2 DWARF64, 3 end of section
    uint32_t candidates;     // records whose range contained the address
    uint32_t rejected;       // candidates whose CIE made them unusable
    uint32_t fail_stage;     // stage that rejected the last candidate:
                             // 1 CIE pointer past the record, 2 CIE outside the
                             // section, 3 implausible CIE length, 4 not a
                             // zero-id version-1 'z' CIE
    uint32_t cie_offset;     // CIE offset of the last candidate
    uint32_t cie_length;     // its CIE length field
    uint8_t fail_byte;       // the augmentation letter that was rejected
    uint32_t fail_at;        // where it sat
    uint32_t fail_cursor;    // where the augmentation data cursor was
    uint32_t fail_end;       // and the bound it was compared against
    uint32_t fail_cie;       // the CIE it was parsing
    uint8_t fail_letters[4]; // the augmentation string as that CIE has it
    uint32_t last_candidate_offset;  // offset of the last covering record
    uint32_t last_offset;    // where the walk ran out of section
    uint32_t total_dbg;      // the section size it bounded reads by
    // The two offsets the CIE pointer could mean, with the bytes found there.
    uint32_t probe_count;
    uint32_t probe_offsets[2];
    uint8_t probe_bytes[2][12];
    uint32_t clone_fail;     // which build_clone_fde guard rejected the pair
    uint32_t clone_needed;   // the size it needed
    uint32_t clone_capacity; // and the size it had
    uint64_t last_initial;   // initial_location of the last FDE seen
    uint64_t last_range;     // its address_range
};

// True when the bytes at `offset` begin a CIE this rewriter can copy: a length
// that fits the section, a zero id, DWARF version 1 and the 'z' augmentation.
// The walk uses it both to accept a candidate and to locate the CIE, because
// the CIE pointer field is not always measured from the same byte across
// linkers: some emit it from the PC field, and the value can land a few bytes
// either side of the record. Validating the target is more reliable than
// trusting the arithmetic alone.
inline bool is_usable_cie(const uint8_t *frame, size_t total, size_t offset)
{
    if (offset + 11U > total) return false;
    const uint32_t length = read_u32(frame, offset);
    if (length < 4U || length == 0xffffffffU || offset + 4U + length > total)
        return false;
    if (read_u32(frame, offset + 4U) != 0 || frame[offset + 8U] != 1U ||
        frame[offset + 9U] != 'z')
        return false;
    // The augmentation block is length-prefixed, and the encodings live inside
    // it. Reading them without honouring that prefix is how a parser ends up
    // one byte out and then trips over a 'P'/'L'/'R' payload as if it were an
    // augmentation letter.
    return frame[offset + 10U] != 0;
}

// Completes an FDE record whose PC field already covers the address: resolves
// its CIE, parses the CIE augmentation and returns the encodings the rewrite
// needs. `pc_offset` is the byte offset of the record's PC field from the
// section start, i.e. fde_offset + 8. Returning false means "this candidate is
// not usable", not "the section is broken": a walk that trusted the first
// record covering an address would latch onto a stale or unrelated entry and
// never reach the real one, so the caller keeps looking.
inline bool complete_fde_location(const uint8_t *frame, size_t total,
                                  size_t fde_offset, size_t pc_offset,
                                  uint32_t length, uint32_t cie_id,
                                  uint64_t initial, uint64_t range,
                                  FdeLocation *location, FdeProbe *probe)
{
    if (cie_id > pc_offset) {
        if (probe != nullptr) probe->fail_stage = 1U;
        return false;
    }
    // The CIE pointer counts backwards from the field that holds it. Both
    // plausible bases are accepted, but only one of them lands on something
    // that actually parses as a CIE, so the search is self-checking rather than
    // a guess about the linker's convention.
    size_t cie_offset = 0;
    bool found_cie = false;
    // The CIE pointer counts backwards from the field that holds it. Both
    // plausible bases are tried in turn, and the one that lands on bytes that
    // actually parse as a CIE wins; the FDE's own record starts at fde_offset,
    // so the field is at pc_offset and a pointer that counts from there lands
    // four bytes earlier than one that counts from the record.
    const size_t bases[2] = {pc_offset, pc_offset >= 4U ? pc_offset - 4U : 0U};
    for (unsigned candidate = 0; candidate < 2U && !found_cie; ++candidate) {
        if (cie_id > bases[candidate]) continue;
        const size_t at = bases[candidate] - cie_id;
        if (probe != nullptr && probe->probe_count < 2U) {
            probe->probe_offsets[probe->probe_count] = static_cast<uint32_t>(at);
            for (unsigned i = 0; i < 12U; ++i) {
                probe->probe_bytes[probe->probe_count][i] =
                    at + i < total ? frame[at + i] : 0U;
            }
            ++probe->probe_count;
        }
        if (!is_usable_cie(frame, total, at)) continue;
        cie_offset = at;
        found_cie = true;
    }
    if (!found_cie) {
        if (probe != nullptr) probe->fail_stage = 2U;
        return false;
    }
    const uint32_t cie_length = read_u32(frame, cie_offset);
    if (probe != nullptr) {
        probe->cie_offset = static_cast<uint32_t>(cie_offset);
        probe->cie_length = cie_length;
    }
    const size_t cie_size = cie_length + 4U;
    const size_t cie_end = cie_offset + cie_size;
    location->fde_offset = static_cast<uint32_t>(fde_offset);
    location->fde_size = static_cast<uint32_t>(4U + length);
    location->cie_offset = static_cast<uint32_t>(cie_offset);
    location->cie_size = static_cast<uint32_t>(cie_size);
    location->initial_location = initial;
    location->address_range = range;
    location->fde_pointer_encoding = kEhPcrel | kEhSdata4;
    location->personality_encoding = kEhOmit;
    location->lsda_encoding = kEhOmit;
    // CIE augmentation. The 'z' form is "<letters>\0" followed by a
    // length-prefixed block holding one value per letter: 'P' an encoding byte
    // and a personality pointer, 'L' an encoding byte, 'R' the encoding of the
    // lookup-table entries (which this code never reads).
    //
    // This parse is best effort on purpose. A CIE whose augmentation does not
    // line up still describes a usable frame: the FDE's own PC field is always
    // pcrel|sdata4 and is rewritten unconditionally below, and the personality
    // and LSDA fields are located and shifted independently. Refusing the whole
    // frame because one augmentation byte is unexpected would reject frames the
    // unwinder can walk perfectly well.
    size_t cursor = cie_offset + 9U;  // at the 'z' itself
    while (cursor < cie_end && frame[cursor] != 0) ++cursor;
    if (cursor < cie_end) {
        ++cursor;  // past the augmentation string's terminator
        uint64_t augmentation_length = 0;
        const size_t leb = read_leb(frame + cursor, cie_end - cursor,
                                    &augmentation_length, false);
        if (leb != 0 && augmentation_length <= cie_end - cursor - leb) {
            const size_t augmentation_end =
                cursor + leb + static_cast<size_t>(augmentation_length);
            cursor += leb;
            size_t letter = cie_offset + 9U;
            while (letter < cie_end && frame[letter] != 0) {
                const char name = static_cast<char>(frame[letter++]);
                if (name == 'S') continue;  // signal frame: no data follows
                if (cursor >= augmentation_end) break;
                if (name == 'P') location->personality_encoding = frame[cursor++];
                else if (name == 'L') location->lsda_encoding = frame[cursor++];
                else if (name == 'R') ++cursor;
                else break;
            }
        }
    }
    return true;
}

// Callback form of the FDE lookup: given the source PC, report the FDE record
// that covers it. The platform unwinder can serve as such a finder
// (_Unwind_Find_FDE), which matters because it is the exact lookup the
// registration has to satisfy; the linear scan beside it is the portable
// fallback for a -nostdlib module that cannot call the unwinder.
//
// A finder that works on a copy of the section (as the scan does) fills the
// offsets; one that works on live memory (the unwinder) leaves them at zero and
// reports the section base instead, which must then be the section start.
using FdeFinderFn = FdeStatus (*)(const EhModule &module, uint64_t address,
                                  FdeLocation *location, FdeProbe *probe);

// Scans the .eh_frame list for the FDE covering `address`. The lookup table in
// .eh_frame_hdr is deliberately not used: its entries are encoded with the
// CIE's 'R' augmentation, which LLVM sets to DW_EH_PE_indirect on this target,
// so the table holds pointers to pointers. A linear walk over the FDE list is
// both simpler and immune to that, and it gives us the CIE offset for free.
inline FdeStatus find_fde(const EhModule &module, uint64_t address,
                          FdeLocation *location, FdeProbe *probe = nullptr)
{
    const uint8_t *frame = module.eh_frame;
    const size_t total = static_cast<size_t>(module.eh_frame_size);
    size_t offset = 0;
    // A miss must not leave a caller reading whatever the output struct held
    // before: a stale FdeLocation looks exactly like a successful lookup.
    if (location != nullptr) {
        *location = FdeLocation{};
        location->personality_encoding = kEhOmit;
        location->lsda_encoding = kEhOmit;
    }
    while (offset + 4U <= total) {
        const uint32_t length = read_u32(frame, offset);
        if (probe != nullptr) ++probe->entries;
        if (length == 0) {  // terminator
            if (probe != nullptr) probe->exit_code = 1U;
            break;
        }
        if (length == 0xffffffffU) {
            // DWARF64: the length is 8 bytes and every offset in the entry
            // shifts, so the whole walk would need a second decoder.
            if (probe != nullptr) probe->exit_code = 2U;
            return FdeStatus::UnsupportedEnc;
        }
        if (offset + 4U + length > total) {
            // The entry claims more bytes than the section has. This is the
            // normal way to reach the end of a section whose terminator was
            // stripped, so it is reported as a miss rather than corruption.
            if (probe != nullptr) probe->exit_code = 3U;
            return FdeStatus::NoFde;
        }
        const size_t entry_size = 4U + length;
        if (length < 8U) {  // too short to be a CIE or an FDE with a PC field
            offset += entry_size;
            continue;
        }
        const uint32_t id = read_u32(frame, offset + 4U);
        if (id == 0) {  // a CIE: nothing to match, step over it
            offset += entry_size;
            continue;
        }
        // An FDE. Its PC field is pcrel|sdata4 on every AArch64 toolchain here,
        // independent of the CIE's 'R' augmentation.
        const size_t pc_offset = offset + 8U;
        const uint64_t field = reinterpret_cast<uint64_t>(frame + pc_offset);
        const uint64_t initial = field + static_cast<uint64_t>(read_i32(frame, pc_offset));
        const uint64_t range = read_u32(frame, pc_offset + 4U);
        if (probe != nullptr) {
            probe->last_range = range;
            probe->last_initial = initial;
        }
        if (address >= initial && address < initial + range) {
            if (probe != nullptr) ++probe->candidates;
            if (complete_fde_location(frame, total, offset, pc_offset, length, id,
                                      initial, range, location, probe))
                return FdeStatus::Ok;
            if (probe != nullptr) {
                ++probe->rejected;
                probe->last_candidate_offset = static_cast<uint32_t>(offset);
            }
            // The record covered the address but its CIE is unusable, so it
            // cannot describe the frame. Keep looking instead of giving up.
            if (location != nullptr) {
                *location = FdeLocation{};
                location->personality_encoding = kEhOmit;
                location->lsda_encoding = kEhOmit;
            }
        }
        offset += entry_size;
    }
    if (probe != nullptr && probe->exit_code == 0U) {
        probe->exit_code = 4U;
        probe->last_offset = static_cast<uint32_t>(offset);
        probe->total_dbg = static_cast<uint32_t>(total);
    }
    return FdeStatus::NoFde;
}

}  // namespace detail

// Locates the module covering `address` and its exception-frame segments.
// `module_status`, when given, receives why the lookup failed.
inline bool find_module_for_address(uint64_t address, EhModule *module,
                                    ModuleStatus *module_status = nullptr)
{
    if (module == nullptr) return false;
    detail::ModuleFinder finder{};
    finder.address = address;
    finder.status = ModuleStatus::NoCoveringSegment;
    finder.module.found = false;
    dl_iterate_phdr(&detail::find_module_callback, &finder);
    *module = finder.module;
    if (module_status != nullptr) *module_status = finder.status;
    if (!module->found) return false;
    if (module->eh_frame == nullptr || module->eh_frame_size == 0) {
        module->found = false;
        if (module_status != nullptr) *module_status = ModuleStatus::NoEhFrameRange;
        return false;
    }
    return true;
}

// Finds the FDE covering `[source_pc, source_pc + source_length)`. The FDE must
// cover the whole relocated range, otherwise a PC in the tail of the clone
// would still have no frame description.
inline FdeStatus find_fde_for_range(uint64_t source_pc, uint32_t source_length,
                                    EhModule *module, FdeLocation *location)
{
    if (module == nullptr || location == nullptr || source_length == 0U)
        return FdeStatus::NoModule;
    if (!find_module_for_address(source_pc, module)) return FdeStatus::NoModule;
    const FdeStatus status = detail::find_fde(*module, source_pc, location);
    if (status != FdeStatus::Ok) return status;
    if (source_pc < location->initial_location ||
        source_pc - location->initial_location >= location->address_range ||
        source_length > location->address_range -
                        (source_pc - location->initial_location))
        return FdeStatus::NoFde;
    return FdeStatus::Ok;
}

// Same, with the lookup delegated to `finder`. Use it with an unwinder-backed
// finder when one is available: the unwinder is the authority on which FDE
// describes a PC, and it already accounts for the section tables.
//
// The caller must relocate the complete function identified by the returned
// FDE, starting at initial_location and covering address_range source bytes.
inline FdeStatus find_fde_for_range_with(detail::FdeFinderFn finder, uint64_t source_pc,
                                         EhModule *module,
                                         FdeLocation *location,
                                         detail::FdeProbe *probe = nullptr)
{
    if (finder == nullptr || module == nullptr || location == nullptr)
        return FdeStatus::NoModule;
    if (!find_module_for_address(source_pc, module)) return FdeStatus::NoModule;
    return finder(*module, source_pc, location, probe);
}

// Copies [CIE..FDE] into `buffer`, rewrites its PC-relative pointers for
// `clone_base`, and appends the zero terminator the dynamic table needs.
// `clone_base` must be the runtime address the relocated block will execute at.
inline CloneFdeResult build_clone_fde_span(const EhModule &module,
                                           const FdeLocation &location,
                                           uint64_t clone_base,
                                           uint32_t relocated_size,
                                           uint8_t *buffer, size_t buffer_size,
                                           const OffsetMapEntry *map,
                                           size_t map_size);

// Compatibility helper for an unchanged, instruction-for-instruction clone.
// Expanded code must supply the real OffsetMap to build_clone_fde_span.
inline CloneFdeResult build_clone_fde(const EhModule &module,
                                      const FdeLocation &location,
                                      uint64_t clone_base, uint8_t *buffer,
                                      size_t buffer_size,
                                      detail::FdeProbe *probe = nullptr)
{
    CloneFdeResult result{};
    if (location.address_range == 0 || location.address_range > 1024U ||
        (location.address_range & 3U) != 0U) {
        result.status = FdeStatus::UnsupportedEnc;
        return result;
    }
    OffsetMapEntry identity[256];
    const size_t count = static_cast<size_t>(location.address_range / 4U);
    for (size_t i = 0; i < count; ++i) {
        identity[i].orig_index = static_cast<uint32_t>(i);
        identity[i].clone_offset = static_cast<uint32_t>(i * 4U);
    }
    result = build_clone_fde_span(module, location, clone_base,
                                  static_cast<uint32_t>(location.address_range),
                                  buffer, buffer_size, identity, count);
    if (probe != nullptr && result.status != FdeStatus::Ok)
        probe->clone_fail = static_cast<uint32_t>(result.status);
    return result;
}

// Hands the clone's FDE list to the unwinder. The buffer must stay mapped for
// as long as the clone can raise, and must be passed back unchanged.
inline void register_clone_fde(void *clone_fde)
{
    if (clone_fde != nullptr) __register_frame(clone_fde);
}

inline void unregister_clone_fde(void *clone_fde)
{
    if (clone_fde != nullptr) __deregister_frame(clone_fde);
}

// Copy a CIE while preserving its personality. A copied pcrel personality
// field must still resolve to the source image's personality slot/function;
// clearing it would discard the language-specific exception handler.
inline FdeStatus build_rebased_cie(const uint8_t *frame,
                                   const FdeLocation &location,
                                   uint8_t *out, size_t out_size,
                                   uint8_t *lsda_encoding,
                                   bool *personality_rewritten,
                                   uint64_t *code_alignment)
{
    const uint8_t *cie = frame + location.cie_offset;
    const size_t cie_size = location.cie_size;
    if (cie_size < 12U || cie_size > out_size) return FdeStatus::TooSmall;
    for (size_t i = 0; i < cie_size; ++i) out[i] = cie[i];
    *personality_rewritten = false;
    *lsda_encoding = kEhOmit;
    // This builder only handles the length-prefixed augmentation layout.
    if (cie[8] != 1U || cie[9] != 'z') return FdeStatus::UnsupportedEnc;
    size_t cursor = 9U;
    while (cursor < cie_size && cie[cursor] != 0) ++cursor;
    if (cursor >= cie_size) return FdeStatus::Truncated;
    const size_t letters_end = cursor;
    ++cursor;  // past the NUL
    uint64_t ignored = 0;
    size_t leb = detail::read_leb(cie + cursor, cie_size - cursor,
                                  code_alignment, false);
    if (leb == 0) return FdeStatus::Truncated;
    cursor += leb;  // code alignment factor
    leb = detail::read_leb(cie + cursor, cie_size - cursor, &ignored, true);
    if (leb == 0) return FdeStatus::Truncated;
    cursor += leb;  // data alignment factor
    if (cursor >= cie_size) return FdeStatus::Truncated;
    ++cursor;  // version 1 return-address register
    uint64_t block_length = 0;
    leb = detail::read_leb(cie + cursor, cie_size - cursor, &block_length, false);
    if (leb == 0 || block_length > cie_size - cursor - leb)
        return FdeStatus::Truncated;
    const size_t block_end = cursor + leb + static_cast<size_t>(block_length);
    size_t data = cursor + leb;
    for (size_t i = 10U; i < letters_end; ++i) {
        const char name = static_cast<char>(cie[i]);
        if (name == 'S' || name == 'B' || name == 'G') continue;
        if (data >= block_end) return FdeStatus::Truncated;
        if (name == 'L') {
            *lsda_encoding = cie[data++];
            continue;
        }
        if (name == 'R') {
            if (cie[data++] != location.fde_pointer_encoding)
                return FdeStatus::UnsupportedEnc;
            continue;
        }
        if (name != 'P') return FdeStatus::UnsupportedEnc;
        const uint8_t encoding = cie[data++];
        size_t width = 0;
        if (!detail::fixed_width(static_cast<uint8_t>(encoding & 0x0fU), &width) ||
            width > block_end - data)
            return FdeStatus::UnsupportedEnc;
        // For an indirect encoding, preserve the address of the original
        // slot. The unwinder performs the dereference after decoding.
        const uint8_t direct = static_cast<uint8_t>(encoding & ~kEhIndirect);
        uint64_t target = 0;
        if (!detail::read_encoded(cie + data, width, direct, 0, &target) ||
            !detail::write_encoded_direct(out + data, direct, target))
            return FdeStatus::PersonaUnencodable;
        *personality_rewritten = true;
        data += width;
    }
    return FdeStatus::Ok;
}

inline bool write_uleb(uint8_t *out, size_t capacity, size_t *used,
                       uint64_t value)
{
    do {
        if (*used >= capacity) return false;
        uint8_t byte = static_cast<uint8_t>(value & 0x7fU);
        value >>= 7U;
        if (value != 0) byte |= 0x80U;
        out[(*used)++] = byte;
    } while (value != 0);
    return true;
}

inline bool map_frame_offset(const OffsetMapEntry *map, size_t map_size,
                             uint32_t source_length, uint32_t clone_length,
                             uint64_t source_offset, uint32_t *clone_offset)
{
    if (source_offset > source_length || (source_offset & 3U) != 0)
        return false;
    if (source_offset == source_length) {
        *clone_offset = clone_length;
        return true;
    }
    for (size_t i = 0; i < map_size; ++i) {
        if (map[i].orig_index == source_offset / 4U) {
            *clone_offset = map[i].clone_offset;
            return true;
        }
    }
    return false;
}

// Rebuild the subset of Itanium LSDA that is safe to translate without
// changing the action/type tables: omitted LPStart and type table, ULEB128
// call-site entries, and action 0. Everything else is rejected explicitly.
inline FdeStatus build_relocated_lsda(const uint8_t *source, size_t source_cap,
                                       uint32_t source_length,
                                       uint32_t clone_length,
                                       const OffsetMapEntry *map,
                                       size_t map_size, uint8_t *out,
                                       size_t out_cap, size_t *out_used)
{
    if (map == nullptr || map_size == 0 || source_cap < 4U ||
        source[0] != kEhOmit || source[1] != kEhOmit ||
        source[2] != kEhUleb128)
        return FdeStatus::UnsupportedEnc;
    size_t cursor = 3U;
    uint64_t table_length = 0;
    size_t leb = detail::read_leb(source + cursor, source_cap - cursor,
                                  &table_length, false);
    if (leb == 0 || table_length > source_cap - cursor - leb)
        return FdeStatus::Truncated;
    cursor += leb;
    const size_t table_end = cursor + static_cast<size_t>(table_length);
    uint8_t entries[256];
    size_t entries_used = 0;
    while (cursor < table_end) {
        uint64_t values[4]{};
        for (unsigned field = 0; field < 4U; ++field) {
            leb = detail::read_leb(source + cursor, table_end - cursor,
                                    &values[field], false);
            if (leb == 0) return FdeStatus::Truncated;
            cursor += leb;
        }
        if (values[3] != 0 || values[0] > source_length ||
            values[1] > source_length - values[0])
            return FdeStatus::UnsupportedEnc;
        uint32_t start = 0, end = 0, landing = 0;
        if (!map_frame_offset(map, map_size, source_length, clone_length,
                              values[0], &start) ||
            !map_frame_offset(map, map_size, source_length, clone_length,
                              values[0] + values[1], &end) ||
            (values[2] != 0 &&
             !map_frame_offset(map, map_size, source_length, clone_length,
                               values[2], &landing)) || end < start)
            return FdeStatus::UnsupportedEnc;
        if (!write_uleb(entries, sizeof(entries), &entries_used, start) ||
            !write_uleb(entries, sizeof(entries), &entries_used, end - start) ||
            !write_uleb(entries, sizeof(entries), &entries_used, landing) ||
            !write_uleb(entries, sizeof(entries), &entries_used, 0U))
            return FdeStatus::TooSmall;
    }
    size_t used = 0;
    if (out_cap < 3U) return FdeStatus::TooSmall;
    out[used++] = kEhOmit;
    out[used++] = kEhOmit;
    out[used++] = kEhUleb128;
    if (!write_uleb(out, out_cap, &used, entries_used) ||
        entries_used > out_cap - used)
        return FdeStatus::TooSmall;
    for (size_t i = 0; i < entries_used; ++i) out[used++] = entries[i];
    *out_used = used;
    return FdeStatus::Ok;
}

// Translate DW_CFA location advances through the instruction OffsetMap. The
// remaining supported opcodes are copied verbatim; unknown operands cannot be
// skipped safely and therefore reject the frame.
inline FdeStatus build_relocated_cfi(const uint8_t *source, size_t source_size,
                                     uint32_t source_length,
                                     uint32_t clone_length,
                                     uint64_t code_alignment,
                                     const OffsetMapEntry *map, size_t map_size,
                                     uint8_t *out, size_t out_cap,
                                     size_t *out_used)
{
    if (code_alignment == 0 || map == nullptr || map_size == 0)
        return FdeStatus::UnsupportedEnc;
    size_t cursor = 0, used = 0;
    uint64_t source_location = 0;
    uint32_t clone_location = 0;
    while (cursor < source_size) {
        const size_t start = cursor;
        const uint8_t opcode = source[cursor++];
        uint64_t advance_units = 0;
        bool advance = false;
        if ((opcode & 0xc0U) == 0x40U) {
            advance_units = opcode & 0x3fU;
            advance = true;
        } else if (opcode == 0x02U || opcode == 0x03U || opcode == 0x04U) {
            const unsigned width = opcode == 0x02U ? 1U :
                                   (opcode == 0x03U ? 2U : 4U);
            if (width > source_size - cursor) return FdeStatus::Truncated;
            for (unsigned i = 0; i < width; ++i)
                advance_units |= static_cast<uint64_t>(source[cursor++]) << (i * 8U);
            advance = true;
        }
        if (advance) {
            if (source_location > source_length ||
                advance_units > (source_length - source_location) / code_alignment)
                return FdeStatus::UnsupportedEnc;
            source_location += advance_units * code_alignment;
            uint32_t next_clone = 0;
            if (!map_frame_offset(map, map_size, source_length, clone_length,
                                  source_location, &next_clone) ||
                next_clone < clone_location ||
                (next_clone - clone_location) % code_alignment != 0)
                return FdeStatus::UnsupportedEnc;
            const uint64_t units = (next_clone - clone_location) / code_alignment;
            if (units > 0xffffffffULL || used + 5U > out_cap)
                return FdeStatus::TooSmall;
            out[used++] = 0x04U;  // DW_CFA_advance_loc4
            detail::write_u32(out + used, static_cast<uint32_t>(units));
            used += 4U;
            clone_location = next_clone;
            continue;
        }
        if (opcode == 0x01U) return FdeStatus::UnsupportedEnc; // DW_CFA_set_loc
        unsigned uleb_count = 0;
        bool sleb_last = false;
        bool expression = false;
        if ((opcode & 0xc0U) == 0x80U) uleb_count = 1U;
        else if ((opcode & 0xc0U) == 0xc0U) uleb_count = 0U;
        else if (opcode == 0x00U || opcode == 0x0aU || opcode == 0x0bU ||
                 opcode == 0x2dU) uleb_count = 0U;
        else if (opcode == 0x05U || opcode == 0x09U || opcode == 0x0cU ||
                 opcode == 0x14U || opcode == 0x2fU) uleb_count = 2U;
        else if (opcode == 0x06U || opcode == 0x07U || opcode == 0x08U ||
                 opcode == 0x0dU || opcode == 0x0eU || opcode == 0x2eU)
            uleb_count = 1U;
        else if (opcode == 0x11U || opcode == 0x12U || opcode == 0x15U) {
            uleb_count = opcode == 0x12U ? 1U : 1U;
            sleb_last = true;
        } else if (opcode == 0x13U) sleb_last = true;
        else if (opcode == 0x0fU || opcode == 0x10U || opcode == 0x16U) {
            uleb_count = opcode == 0x0fU ? 0U : 1U;
            expression = true;
        } else return FdeStatus::UnsupportedEnc;
        uint64_t ignored = 0;
        for (unsigned i = 0; i < uleb_count; ++i) {
            const size_t n = detail::read_leb(source + cursor,
                                               source_size - cursor,
                                               &ignored, false);
            if (n == 0) return FdeStatus::Truncated;
            cursor += n;
        }
        if (sleb_last) {
            const size_t n = detail::read_leb(source + cursor,
                                               source_size - cursor,
                                               &ignored, true);
            if (n == 0) return FdeStatus::Truncated;
            cursor += n;
        }
        if (expression) {
            const size_t n = detail::read_leb(source + cursor,
                                               source_size - cursor,
                                               &ignored, false);
            if (n == 0 || ignored > source_size - cursor - n)
                return FdeStatus::Truncated;
            cursor += n + static_cast<size_t>(ignored);
        }
        if (cursor - start > out_cap - used) return FdeStatus::TooSmall;
        for (size_t i = start; i < cursor; ++i) out[used++] = source[i];
    }
    *out_used = used;
    return FdeStatus::Ok;
}

// Builds one FDE for one relocated source function. The caller must pass the
// function's complete OffsetMap and its clone length. A single FDE covers an
// expanded function; artificial 256-byte slabs would make LSDA and CFI offsets
// relative to the wrong function start.
inline CloneFdeResult build_clone_fde_span(const EhModule &module,
                                           const FdeLocation &location,
                                           uint64_t clone_base,
                                           uint32_t relocated_size,
                                           uint8_t *buffer, size_t buffer_size,
                                           const OffsetMapEntry *map = nullptr,
                                           size_t map_size = 0)
{
    CloneFdeResult result{};
    result.status = FdeStatus::Ok;
    result.delta = static_cast<int64_t>(clone_base) -
                   static_cast<int64_t>(location.initial_location);
    result.kept_encoding = kEhPcrel | kEhSdata4;
    result.input_cie_size = location.cie_size;
    result.input_fde_size = location.fde_size;
    result.input_relocated_size = relocated_size;
    result.input_clone_base = clone_base;
    result.input_source_end = location.initial_location + location.address_range;

    const size_t cie_size = location.cie_size;
    if (location.cie_offset + cie_size > module.eh_frame_size || cie_size < 12U) {
        result.status = FdeStatus::NoFde;
        return result;
    }
    constexpr size_t kFdeHeader = 16U;
    const size_t source_body =
        location.fde_size > kFdeHeader ? location.fde_size - kFdeHeader : 0U;
    if (source_body == 0U || relocated_size == 0U ||
        location.address_range > 0xffffffffULL) {
        result.status = FdeStatus::NoFde;
        return result;
    }
    if ((location.address_range & 3U) != 0U || map == nullptr ||
        map_size != location.address_range / 4U ||
        location.fde_pointer_encoding != (kEhPcrel | kEhSdata4)) {
        result.status = FdeStatus::UnsupportedEnc;
        return result;
    }
    for (size_t i = 0; i < map_size; ++i) {
        if (map[i].orig_index != i ||
            map[i].clone_offset >= relocated_size ||
            (i != 0 && map[i].clone_offset <= map[i - 1U].clone_offset)) {
            result.status = FdeStatus::UnsupportedEnc;
            return result;
        }
    }
    if (static_cast<size_t>(location.fde_offset) +
            location.fde_size > module.eh_frame_size) {
        result.status = FdeStatus::NoFde;
        return result;
    }

    if (buffer == nullptr || buffer_size < cie_size) {
        result.status = FdeStatus::TooSmall;
        result.clone_size = static_cast<uint32_t>(cie_size);
        return result;
    }
    uint8_t lsda_encoding = kEhOmit;
    uint64_t code_alignment = 0;
    result.status = build_rebased_cie(module.eh_frame, location, buffer,
                                      buffer_size, &lsda_encoding,
                                      &result.personality_rewritten,
                                      &code_alignment);
    if (result.status != FdeStatus::Ok) return result;

    const uint8_t *frame = module.eh_frame;
    const uint8_t *source_fde = frame + location.fde_offset;
    uint64_t aug_length = 0;
    const size_t aug_leb = detail::read_leb(source_fde + kFdeHeader,
                                             source_body, &aug_length, false);
    if (aug_leb == 0 || aug_length > source_body - aug_leb) {
        result.status = FdeStatus::Truncated;
        return result;
    }
    const size_t cfi_offset = kFdeHeader + aug_leb +
                              static_cast<size_t>(aug_length);
    uint8_t cfi_copy[512];
    size_t cfi_used = 0;
    result.status = build_relocated_cfi(
        source_fde + cfi_offset, location.fde_size - cfi_offset,
        static_cast<uint32_t>(location.address_range), relocated_size,
        code_alignment, map, map_size, cfi_copy, sizeof(cfi_copy), &cfi_used);
    if (result.status != FdeStatus::Ok) return result;
    const size_t prefix_size = cfi_offset - kFdeHeader;
    const size_t fde_size = kFdeHeader + prefix_size + cfi_used;
    size_t lsda_offset = 0;
    uint64_t lsda_target = 0;
    bool has_lsda = false;
    if (lsda_encoding != kEhOmit) {
        lsda_offset = kFdeHeader + aug_leb;
        size_t width = 0;
        if (!detail::fixed_width(static_cast<uint8_t>(lsda_encoding & 0x0fU),
                                 &width) || width > aug_length) {
            result.status = FdeStatus::UnsupportedEnc;
            return result;
        }
        uint64_t raw = 0;
        for (size_t i = 0; i < width; ++i)
            raw |= static_cast<uint64_t>(source_fde[lsda_offset + i]) << (i * 8U);
        if (raw != 0) {
            const uint8_t direct = static_cast<uint8_t>(lsda_encoding & ~kEhIndirect);
            if (!detail::read_encoded(source_fde + lsda_offset, width, direct,
                                      0, &lsda_target)) {
                result.status = FdeStatus::UnsupportedEnc;
                return result;
            }
            has_lsda = true;
        }
    }
    uint8_t lsda_copy[256];
    size_t lsda_used = 0;
    if (has_lsda) {
        if ((lsda_encoding & kEhIndirect) != 0) {
            result.status = FdeStatus::UnsupportedEnc;
            return result;
        }
        const size_t page_remaining =
            0x1000U - static_cast<size_t>(lsda_target & 0xfffU);
        const size_t source_cap = page_remaining < sizeof(lsda_copy)
                                      ? page_remaining : sizeof(lsda_copy);
        result.status = build_relocated_lsda(
            reinterpret_cast<const uint8_t *>(lsda_target), source_cap,
            static_cast<uint32_t>(location.address_range), relocated_size,
            map, map_size, lsda_copy, sizeof(lsda_copy), &lsda_used);
        if (result.status != FdeStatus::Ok) return result;
    }
    const size_t fixed_size = cie_size + fde_size + 4U;
    const size_t needed = fixed_size + lsda_used;
    if (needed > buffer_size) {
        result.status = FdeStatus::TooSmall;
        result.clone_size = static_cast<uint32_t>(needed);
        return result;
    }
    uint8_t *record = buffer + cie_size;
    detail::write_u32(record, static_cast<uint32_t>(fde_size - 4U));
    detail::write_u32(record + 4U,
                      static_cast<uint32_t>(record + 4U - buffer));
    if (!detail::write_encoded_direct(record + 8U, kEhPcrel | kEhSdata4,
                                      clone_base)) {
        result.status = FdeStatus::UnsupportedEnc;
        return result;
    }
    detail::write_u32(record + 12U, relocated_size);
    for (size_t i = 0; i < prefix_size; ++i)
        record[kFdeHeader + i] = source_fde[kFdeHeader + i];
    for (size_t i = 0; i < cfi_used; ++i)
        record[kFdeHeader + prefix_size + i] = cfi_copy[i];
    detail::write_u32(buffer + cie_size + fde_size, 0U);
    if (has_lsda) {
        uint8_t *clone_lsda = buffer + fixed_size;
        for (size_t i = 0; i < lsda_used; ++i) clone_lsda[i] = lsda_copy[i];
        if (!detail::write_encoded_direct(record + lsda_offset, lsda_encoding,
                                          reinterpret_cast<uint64_t>(clone_lsda))) {
            result.status = FdeStatus::UnsupportedEnc;
            return result;
        }
        result.lsda_rewritten = true;
    }
    result.clone_fde = buffer + cie_size;
    result.descriptor_count = 1U;
    result.clone_size = static_cast<uint32_t>(needed);
    result.cie_bytes = static_cast<uint32_t>(cie_size);
    result.fde_bytes = static_cast<uint32_t>(fde_size);
    return result;
}

// LLVM libunwind's __register_frame accepts one FDE, not a CIE/FDE list.
inline void register_clone_fde_span(const CloneFdeResult &span)
{
    if (span.status != FdeStatus::Ok || span.clone_fde == nullptr) return;
    for (uint32_t i = 0; i < span.descriptor_count; ++i)
        __register_frame(span.clone_fde + static_cast<size_t>(i) * span.fde_bytes);
}

inline void unregister_clone_fde_span(const CloneFdeResult &span)
{
    if (span.status != FdeStatus::Ok || span.clone_fde == nullptr) return;
    for (uint32_t i = 0; i < span.descriptor_count; ++i)
        __deregister_frame(span.clone_fde + static_cast<size_t>(i) * span.fde_bytes);
}

}  // namespace rtgum_dbi
