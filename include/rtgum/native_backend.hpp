#pragma once

#include "rtgum/host_api_v2.h"

#include <cstddef>
#include <cstdint>

namespace rtgum {
namespace native {

constexpr unsigned long kPatchBytes = 16UL;
constexpr unsigned long kTrampolineBytes = 32UL;
constexpr unsigned long kPageSize = 4096UL;
/* LSPlant Init on a debuggable Android 16 process inline-hooks more than 8 ART
 * functions. Native tests still use a handful of slots. */
constexpr unsigned int kMaxHooks = 64U;
/* Android 16 app maps on Pixel 8 exceeded 300 KiB; keep a 1 MiB window. */
constexpr unsigned int kMapsCapacity = 1048576U;

constexpr unsigned long kProtRead = 1UL;
constexpr unsigned long kProtWrite = 2UL;
constexpr unsigned long kProtExec = 4UL;
constexpr unsigned long kMapPrivate = 0x02UL;
constexpr unsigned long kMapAnonymous = 0x20UL;

struct MemoryOps {
    long (*open_read)(const char *path);
    long (*read)(long fd, void *buffer, unsigned long size);
    long (*close)(long fd);
    long (*mmap)(unsigned long size, unsigned long protection);
    long (*mprotect)(unsigned long address, unsigned long size, unsigned long protection);
    long (*munmap)(unsigned long address, unsigned long size);
    void (*clear_cache)(unsigned long address, unsigned long size);
    long (*clone)(void (*function)(void *), void *argument);
    long (*sleep_ms)(unsigned int milliseconds);
    /* Optional process-aware resolver.  The stage-2 Daemon binds this to its
     * kernel-VMA/ELF cache so FindExport, WaitExport and HookSymbol cannot
     * drift into separate address-discovery implementations. */
    long (*find_export)(const char *soname,
                        const char *symbol,
                        unsigned long *out_address);
};

struct HookSlot {
    unsigned long handle;
    unsigned long target;
    unsigned long replacement;
    unsigned long trampoline;
    unsigned long retired_handle;
    unsigned char original[kPatchBytes];
    unsigned int generation;
    bool used;
};

inline unsigned long AlignDown(unsigned long value, unsigned long align)
{
    return value & ~(align - 1UL);
}

inline unsigned long AlignUp(unsigned long value, unsigned long align)
{
    return (value + align - 1UL) & ~(align - 1UL);
}

inline std::uint16_t ReadU16(const unsigned char *bytes)
{
    return static_cast<std::uint16_t>(bytes[0] | (static_cast<unsigned>(bytes[1]) << 8));
}

inline std::uint32_t ReadU32(const unsigned char *bytes)
{
    return static_cast<std::uint32_t>(bytes[0]) |
           (static_cast<std::uint32_t>(bytes[1]) << 8) |
           (static_cast<std::uint32_t>(bytes[2]) << 16) |
           (static_cast<std::uint32_t>(bytes[3]) << 24);
}

inline std::uint64_t ReadU64(const unsigned char *bytes)
{
    return static_cast<std::uint64_t>(ReadU32(bytes)) |
           (static_cast<std::uint64_t>(ReadU32(bytes + 4)) << 32);
}

inline void WriteU32(unsigned char *bytes, std::uint32_t value)
{
    bytes[0] = static_cast<unsigned char>(value);
    bytes[1] = static_cast<unsigned char>(value >> 8);
    bytes[2] = static_cast<unsigned char>(value >> 16);
    bytes[3] = static_cast<unsigned char>(value >> 24);
}

inline void WriteU64(unsigned char *bytes, std::uint64_t value)
{
    WriteU32(bytes, static_cast<std::uint32_t>(value));
    WriteU32(bytes + 4, static_cast<std::uint32_t>(value >> 32));
}

inline void CopyBytes(void *destination, const void *source, unsigned long length)
{
    auto *out = static_cast<unsigned char *>(destination);
    const auto *in = static_cast<const unsigned char *>(source);
    for (unsigned long index = 0; index < length; ++index) out[index] = in[index];
}

inline unsigned long StringLength(const char *text, unsigned long limit)
{
    unsigned long length = 0;
    if (!text) return 0;
    while (length < limit && text[length] != '\0') ++length;
    return length;
}

inline bool StringsEqual(const char *left, const char *right)
{
    if (!left || !right) return false;
    while (*left != '\0' && *left == *right) {
        ++left;
        ++right;
    }
    return *left == *right;
}

inline bool PathHasSoname(const char *path, const char *soname)
{
    if (!path || !soname || *soname == '\0') return false;
    const unsigned long path_length = StringLength(path, 4096);
    const unsigned long name_length = StringLength(soname, 256);
    if (name_length == 0 || path_length < name_length) return false;
    const char *tail = path + (path_length - name_length);
    if (!StringsEqual(tail, soname)) return false;
    return path_length == name_length || tail[-1] == '/';
}

inline bool PathEndsWith(const char *path, const char *suffix)
{
    if (!path || !suffix || *suffix == '\0') return false;
    const unsigned long path_length = StringLength(path, 4096);
    const unsigned long suffix_length = StringLength(suffix, 16);
    if (path_length < suffix_length) return false;
    return StringsEqual(path + (path_length - suffix_length), suffix);
}

inline bool PathLooksLikeApk(const char *path)
{
    if (!path || path[0] != '/') return false;
    if (PathEndsWith(path, ".apk")) return true;
    const unsigned long path_length = StringLength(path, 4096);
    for (unsigned long index = 0; index + 6 <= path_length; ++index) {
        if (path[index] == '.' && path[index + 1] == 'a' && path[index + 2] == 'p' &&
            path[index + 3] == 'k' && path[index + 4] == '!' && path[index + 5] == '/') {
            return true;
        }
    }
    return false;
}

inline bool PermsReadable(const char *perms)
{
    return perms && perms[0] == 'r';
}

inline bool PermsExecutable(const char *perms)
{
    return perms && perms[2] == 'x';
}

inline bool PagesArePresent(unsigned long address, unsigned long length)
{
#if defined(__aarch64__) && defined(__linux__)
    if (address == 0 || length == 0) return false;
    unsigned char vec[32];
    const unsigned long page = address & ~(kPageSize - 1UL);
    const unsigned long last = address + (length - 1UL);
    if (last < address) return false;
    const unsigned long span = (last - page) + 1UL;
    const unsigned long pages = (span + kPageSize - 1UL) / kPageSize;
    if (pages == 0 || pages > 32UL) return false;
    register long x8 asm("x8") = 232L; /* mincore */
    register long x0 asm("x0") = static_cast<long>(page);
    register long x1 asm("x1") = static_cast<long>(pages * kPageSize);
    register long x2 asm("x2") = reinterpret_cast<long>(vec);
    asm volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x8) : "memory");
    if (x0 != 0) return false;
    for (unsigned long index = 0; index < pages; ++index) {
        if ((vec[index] & 1U) == 0U) return false;
    }
    return true;
#else
    (void)address;
    (void)length;
    return true;
#endif
}

inline const unsigned char *PeekMapped(unsigned long address, unsigned long length)
{
    if (!PagesArePresent(address, length)) return nullptr;
    return reinterpret_cast<const unsigned char *>(address);
}

inline bool MappedElf64Le(unsigned long address)
{
    const unsigned char *ehdr = PeekMapped(address, 6);
    if (!ehdr) return false;
    return ehdr[0] == 0x7f && ehdr[1] == 'E' && ehdr[2] == 'L' && ehdr[3] == 'F' &&
           ehdr[4] == 2 && ehdr[5] == 1;
}

inline const char *ParseHex(const char *cursor, unsigned long *value)
{
    if (!cursor || !value) return nullptr;
    unsigned long result = 0;
    bool any = false;
    while (*cursor != '\0') {
        unsigned int digit = 0;
        if (*cursor >= '0' && *cursor <= '9') digit = static_cast<unsigned int>(*cursor - '0');
        else if (*cursor >= 'a' && *cursor <= 'f')
            digit = static_cast<unsigned int>(*cursor - 'a' + 10);
        else if (*cursor >= 'A' && *cursor <= 'F')
            digit = static_cast<unsigned int>(*cursor - 'A' + 10);
        else
            break;
        result = (result << 4) | digit;
        any = true;
        ++cursor;
    }
    if (!any) return nullptr;
    *value = result;
    return cursor;
}

struct MapsRegion {
    unsigned long start;
    unsigned long end;
    char perms[5];
    char path[256];
};

inline bool ParseMapsRegion(const char *line, const char *newline, MapsRegion *out)
{
    if (!line || !newline || !out || newline < line) return false;
    unsigned long start = 0;
    unsigned long end = 0;
    const char *cursor = ParseHex(line, &start);
    if (!cursor || *cursor != '-') return false;
    cursor = ParseHex(cursor + 1, &end);
    if (!cursor || *cursor != ' ' || end <= start) return false;
    ++cursor;
    char perms[5]{};
    unsigned int perm_length = 0;
    while (perm_length < 4U && cursor < newline && *cursor != ' ' && *cursor != '\t') {
        perms[perm_length++] = *cursor++;
    }
    if (perm_length == 0U) return false;
    const char *path = newline;
    while (path > line && path[-1] != ' ' && path[-1] != '\t') --path;
    char name[256];
    unsigned long length = 0;
    const char *end_path = newline;
    if (end_path > path && end_path[-1] == '\r') --end_path;
    if (path[0] == '/' || path[0] == '[') {
        while (path + length < end_path && length + 1 < sizeof(name)) {
            name[length] = path[length];
            ++length;
        }
    }
    name[length] = '\0';
    out->start = start;
    out->end = end;
    for (unsigned int index = 0; index < 5U; ++index) out->perms[index] = perms[index];
    CopyBytes(out->path, name, length + 1);
    return true;
}

inline bool InstructionIsPcRelative(std::uint32_t insn)
{
    if ((insn & 0x1F000000U) == 0x10000000U) return true; /* ADR/ADRP */
    if ((insn & 0x7C000000U) == 0x14000000U) return true; /* B/BL */
    if ((insn & 0xFF000010U) == 0x54000000U) return true; /* B.cond */
    if ((insn & 0x7E000000U) == 0x34000000U) return true; /* CBZ/CBNZ */
    if ((insn & 0x7E000000U) == 0x36000000U) return true; /* TBZ/TBNZ */
    if ((insn & 0x3B000000U) == 0x18000000U) return true; /* LDR/PRFM literal */
    return false;
}

inline bool PrologueIsCopyable(const unsigned char *bytes)
{
    for (unsigned long offset = 0; offset < kPatchBytes; offset += 4UL) {
        if (InstructionIsPcRelative(ReadU32(bytes + offset))) return false;
    }
    return true;
}

inline void EncodeAbsoluteJump(unsigned char *bytes, unsigned long target)
{
    WriteU32(bytes, 0x58000050U); /* LDR X16, #8 */
    WriteU32(bytes + 4, 0xD61F0200U); /* BR X16 */
    WriteU64(bytes + 8, target);
}

inline bool RangeFits(std::uint64_t offset, std::uint64_t length, std::uint64_t size)
{
    if (offset > size) return false;
    return length <= size - offset;
}

struct ElfView {
    const unsigned char *base;
    unsigned long size;
};

inline const unsigned char *FileOffset(const ElfView &image, std::uint64_t offset, std::uint64_t length)
{
    if (!image.base || !RangeFits(offset, length, image.size)) return nullptr;
    return image.base + offset;
}

inline const unsigned char *FileVaddr(const ElfView &image, std::uint64_t vaddr, std::uint64_t length)
{
    const unsigned char *ehdr = FileOffset(image, 0, 64);
    if (!ehdr) return nullptr;
    const std::uint64_t phoff = ReadU64(ehdr + 32);
    const std::uint16_t phentsize = ReadU16(ehdr + 54);
    const std::uint16_t phnum = ReadU16(ehdr + 56);
    if (phentsize < 56) return nullptr;
    for (std::uint16_t index = 0; index < phnum; ++index) {
        const unsigned char *phdr = FileOffset(image,
                                               phoff + static_cast<std::uint64_t>(index) * phentsize,
                                               56);
        if (!phdr) return nullptr;
        if (ReadU32(phdr) != 1U) continue; /* PT_LOAD */
        const std::uint64_t p_vaddr = ReadU64(phdr + 16);
        const std::uint64_t p_offset = ReadU64(phdr + 8);
        const std::uint64_t p_filesz = ReadU64(phdr + 32);
        if (vaddr < p_vaddr || vaddr - p_vaddr >= p_filesz) continue;
        const std::uint64_t delta = vaddr - p_vaddr;
        if (length > p_filesz - delta) return nullptr;
        return FileOffset(image, p_offset + delta, length);
    }
    return nullptr;
}

inline std::uint32_t GnuHash(const char *name)
{
    std::uint32_t hash = 5381U;
    for (const unsigned char *cursor = reinterpret_cast<const unsigned char *>(name);
         *cursor != 0;
         ++cursor) {
        hash = (hash << 5) + hash + *cursor;
    }
    return hash;
}

inline long LookupSymbolInElfFile(const unsigned char *file,
                                  unsigned long size,
                                  const char *symbol,
                                  unsigned long *out_vaddr)
{
    if (!file || !symbol || !out_vaddr || *symbol == '\0') return RTGUM_HOST_ERR_INVAL;
    ElfView image{file, size};
    const unsigned char *ehdr = FileOffset(image, 0, 64);
    if (!ehdr) return RTGUM_HOST_ERR_NOENT;
    if (ehdr[0] != 0x7f || ehdr[1] != 'E' || ehdr[2] != 'L' || ehdr[3] != 'F') {
        return RTGUM_HOST_ERR_NOENT;
    }
    if (ehdr[4] != 2 || ehdr[5] != 1) return RTGUM_HOST_ERR_NOTSUP;
    const std::uint64_t phoff = ReadU64(ehdr + 32);
    const std::uint16_t phentsize = ReadU16(ehdr + 54);
    const std::uint16_t phnum = ReadU16(ehdr + 56);
    if (phentsize < 56) return RTGUM_HOST_ERR_NOTSUP;
    std::uint64_t dyn_vaddr = 0;
    std::uint64_t dyn_filesz = 0;
    bool have_dynamic = false;
    for (std::uint16_t index = 0; index < phnum; ++index) {
        const unsigned char *phdr = FileOffset(image,
                                               phoff + static_cast<std::uint64_t>(index) * phentsize,
                                               56);
        if (!phdr) return RTGUM_HOST_ERR_NOENT;
        if (ReadU32(phdr) != 2U) continue; /* PT_DYNAMIC */
        dyn_vaddr = ReadU64(phdr + 16);
        dyn_filesz = ReadU64(phdr + 32);
        have_dynamic = true;
        break;
    }
    if (!have_dynamic || dyn_filesz < 16) return RTGUM_HOST_ERR_NOENT;

    std::uint64_t symtab = 0;
    std::uint64_t strtab = 0;
    std::uint64_t gnu_hash = 0;
    std::uint64_t syment = 24;
    const unsigned char *dyn = FileVaddr(image, dyn_vaddr, dyn_filesz);
    if (!dyn) return RTGUM_HOST_ERR_NOENT;
    for (std::uint64_t offset = 0; offset + 16 <= dyn_filesz; offset += 16) {
        const std::uint64_t tag = ReadU64(dyn + offset);
        const std::uint64_t value = ReadU64(dyn + offset + 8);
        if (tag == 0) break;
        if (tag == 6) symtab = value;
        else if (tag == 5) strtab = value;
        else if (tag == 11) syment = value;
        else if (tag == 0x6ffffef5ULL) gnu_hash = value;
    }
    if (symtab == 0 || strtab == 0 || gnu_hash == 0 || syment != 24) {
        return RTGUM_HOST_ERR_NOTSUP;
    }

    const unsigned char *gnu = FileVaddr(image, gnu_hash, 16);
    if (!gnu) return RTGUM_HOST_ERR_NOENT;
    const std::uint32_t nbuckets = ReadU32(gnu);
    const std::uint32_t symoffset = ReadU32(gnu + 4);
    const std::uint32_t bloom_size = ReadU32(gnu + 8);
    const std::uint32_t bloom_shift = ReadU32(gnu + 12);
    if (nbuckets == 0 || bloom_size == 0) return RTGUM_HOST_ERR_NOENT;
    const std::uint64_t header_bytes =
        16ULL + static_cast<std::uint64_t>(bloom_size) * 8ULL +
        static_cast<std::uint64_t>(nbuckets) * 4ULL;
    gnu = FileVaddr(image, gnu_hash, header_bytes + 4);
    if (!gnu) return RTGUM_HOST_ERR_NOENT;
    const unsigned char *bloom = gnu + 16;
    const unsigned char *buckets = bloom + static_cast<std::uint64_t>(bloom_size) * 8ULL;

    const std::uint32_t hash = GnuHash(symbol);
    const std::uint64_t bloom_word = ReadU64(
        bloom + static_cast<std::uint64_t>(hash / 64U % bloom_size) * 8ULL);
    const std::uint64_t mask =
        (1ULL << (hash % 64U)) | (1ULL << ((hash >> bloom_shift) % 64U));
    if ((bloom_word & mask) != mask) return RTGUM_HOST_ERR_NOENT;

    std::uint32_t index = ReadU32(buckets + static_cast<std::uint64_t>(hash % nbuckets) * 4ULL);
    if (index < symoffset) return RTGUM_HOST_ERR_NOENT;
    for (;;) {
        const unsigned char *chain = FileVaddr(
            image,
            gnu_hash + header_bytes + static_cast<std::uint64_t>(index - symoffset) * 4ULL,
            4);
        if (!chain) return RTGUM_HOST_ERR_NOENT;
        const std::uint32_t chain_hash = ReadU32(chain);
        if ((chain_hash | 1U) == (hash | 1U)) {
            const unsigned char *sym = FileVaddr(
                image, symtab + static_cast<std::uint64_t>(index) * syment, syment);
            if (!sym) return RTGUM_HOST_ERR_NOENT;
            const std::uint32_t name_offset = ReadU32(sym);
            const std::uint16_t shndx = ReadU16(sym + 6);
            const std::uint64_t value = ReadU64(sym + 8);
            const unsigned char *name = FileVaddr(image, strtab + name_offset, 1);
            if (name && shndx != 0 && StringsEqual(reinterpret_cast<const char *>(name), symbol)) {
                *out_vaddr = static_cast<unsigned long>(value);
                return 0;
            }
        }
        if ((chain_hash & 1U) != 0U) break;
        ++index;
    }
    return RTGUM_HOST_ERR_NOENT;
}

inline long LookupSymbolInMappedElf(unsigned long load_base,
                                    const char *symbol,
                                    unsigned long *out_address)
{
    if (load_base == 0 || !symbol || !out_address) return RTGUM_HOST_ERR_INVAL;
    const unsigned char *ehdr = PeekMapped(load_base, 64);
    if (!ehdr) return RTGUM_HOST_ERR_NOENT;
    if (ehdr[0] != 0x7f || ehdr[1] != 'E' || ehdr[2] != 'L' || ehdr[3] != 'F') {
        return RTGUM_HOST_ERR_NOENT;
    }
    if (ehdr[4] != 2 || ehdr[5] != 1) return RTGUM_HOST_ERR_NOTSUP;
    const std::uint64_t phoff = ReadU64(ehdr + 32);
    const std::uint16_t phentsize = ReadU16(ehdr + 54);
    const std::uint16_t phnum = ReadU16(ehdr + 56);
    if (phentsize < 56 || phnum == 0) return RTGUM_HOST_ERR_NOTSUP;
    std::uint64_t min_vaddr = ~0ULL;
    std::uint64_t dyn_vaddr = 0;
    bool have_dynamic = false;
    for (std::uint16_t index = 0; index < phnum; ++index) {
        const unsigned char *phdr = PeekMapped(
            load_base + phoff + static_cast<std::uint64_t>(index) * phentsize, 56);
        if (!phdr) return RTGUM_HOST_ERR_NOENT;
        const std::uint32_t type = ReadU32(phdr);
        const std::uint64_t p_vaddr = ReadU64(phdr + 16);
        if (type == 1U && p_vaddr < min_vaddr) min_vaddr = p_vaddr;
        if (type == 2U) {
            dyn_vaddr = p_vaddr;
            have_dynamic = true;
        }
    }
    if (!have_dynamic || min_vaddr == ~0ULL) return RTGUM_HOST_ERR_NOENT;
    const std::uint64_t bias = load_base - min_vaddr;
    std::uint64_t symtab = 0;
    std::uint64_t strtab = 0;
    std::uint64_t gnu_hash = 0;
    std::uint64_t syment = 24;
    for (unsigned int entry = 0; entry < 64U; ++entry) {
        const unsigned char *dyn = PeekMapped(bias + dyn_vaddr + entry * 16U, 16);
        if (!dyn) return RTGUM_HOST_ERR_NOENT;
        const std::uint64_t tag = ReadU64(dyn);
        const std::uint64_t value = ReadU64(dyn + 8);
        if (tag == 0) break;
        if (tag == 6) symtab = value;
        else if (tag == 5) strtab = value;
        else if (tag == 11) syment = value;
        else if (tag == 0x6ffffef5ULL) gnu_hash = value;
    }
    if (symtab == 0 || strtab == 0 || gnu_hash == 0 || syment != 24) {
        return RTGUM_HOST_ERR_NOTSUP;
    }
    const unsigned char *gnu = PeekMapped(bias + gnu_hash, 16);
    if (!gnu) return RTGUM_HOST_ERR_NOENT;
    const std::uint32_t nbuckets = ReadU32(gnu);
    const std::uint32_t symoffset = ReadU32(gnu + 4);
    const std::uint32_t bloom_size = ReadU32(gnu + 8);
    const std::uint32_t bloom_shift = ReadU32(gnu + 12);
    if (nbuckets == 0 || bloom_size == 0) return RTGUM_HOST_ERR_NOENT;
    const std::uint64_t header_bytes =
        16ULL + static_cast<std::uint64_t>(bloom_size) * 8ULL +
        static_cast<std::uint64_t>(nbuckets) * 4ULL;
    gnu = PeekMapped(bias + gnu_hash, header_bytes + 4);
    if (!gnu) return RTGUM_HOST_ERR_NOENT;
    const unsigned char *bloom = gnu + 16;
    const unsigned char *buckets = bloom + static_cast<std::uint64_t>(bloom_size) * 8ULL;
    const unsigned char *chains = buckets + static_cast<std::uint64_t>(nbuckets) * 4ULL;
    const std::uint32_t hash = GnuHash(symbol);
    const std::uint64_t bloom_word = ReadU64(
        bloom + static_cast<std::uint64_t>(hash / 64U % bloom_size) * 8ULL);
    const std::uint64_t mask =
        (1ULL << (hash % 64U)) | (1ULL << ((hash >> bloom_shift) % 64U));
    if ((bloom_word & mask) != mask) return RTGUM_HOST_ERR_NOENT;
    std::uint32_t index = ReadU32(buckets + static_cast<std::uint64_t>(hash % nbuckets) * 4ULL);
    if (index < symoffset) return RTGUM_HOST_ERR_NOENT;
    for (;;) {
        const unsigned char *chain = PeekMapped(
            reinterpret_cast<unsigned long>(
                chains + static_cast<std::uint64_t>(index - symoffset) * 4ULL),
            4);
        if (!chain) return RTGUM_HOST_ERR_NOENT;
        const std::uint32_t chain_hash = ReadU32(chain);
        if ((chain_hash | 1U) == (hash | 1U)) {
            const unsigned char *sym = PeekMapped(
                bias + symtab + static_cast<std::uint64_t>(index) * syment, syment);
            if (!sym) return RTGUM_HOST_ERR_NOENT;
            const std::uint32_t name_offset = ReadU32(sym);
            const std::uint16_t shndx = ReadU16(sym + 6);
            const std::uint64_t value = ReadU64(sym + 8);
            const unsigned char *name = PeekMapped(bias + strtab + name_offset, 80);
            if (name && shndx != 0 &&
                StringsEqual(reinterpret_cast<const char *>(name), symbol)) {
                *out_address = static_cast<unsigned long>(bias + value);
                return 0;
            }
        }
        if ((chain_hash & 1U) != 0U) break;
        ++index;
    }
    return RTGUM_HOST_ERR_NOENT;
}

inline long FindSonameBase(const char *maps, const char *soname, unsigned long *out_base)
{
    if (!maps || !soname || !out_base) return RTGUM_HOST_ERR_INVAL;
    unsigned long best = ~0UL;
    const char *line = maps;
    while (*line != '\0') {
        const char *newline = line;
        while (*newline != '\0' && *newline != '\n') ++newline;
        MapsRegion region{};
        if (ParseMapsRegion(line, newline, &region) &&
            PathHasSoname(region.path, soname) && region.start < best) {
            best = region.start;
        }
        line = (*newline == '\n') ? newline + 1 : newline;
    }
    if (best == ~0UL) return RTGUM_HOST_ERR_NOENT;
    *out_base = best;
    return 0;
}

inline long FindSymbolInApkMappedElfs(const char *maps,
                                      const char *symbol,
                                      unsigned long *out_address)
{
    if (!maps || !symbol || !out_address) return RTGUM_HOST_ERR_INVAL;
    const char *line = maps;
    while (*line != '\0') {
        const char *newline = line;
        while (*newline != '\0' && *newline != '\n') ++newline;
        MapsRegion region{};
        if (ParseMapsRegion(line, newline, &region) && PermsReadable(region.perms) &&
            PermsExecutable(region.perms) && PathLooksLikeApk(region.path) &&
            MappedElf64Le(region.start)) {
            if (LookupSymbolInMappedElf(region.start, symbol, out_address) == 0) {
                return 0;
            }
        }
        line = (*newline == '\n') ? newline + 1 : newline;
    }
    return RTGUM_HOST_ERR_NOENT;
}

struct Engine {
    MemoryOps ops{};
    HookSlot slots[kMaxHooks]{};
    unsigned int next_generation{1};
    int last_step{0};

    void Reset()
    {
        for (unsigned int index = 0; index < kMaxHooks; ++index) slots[index] = HookSlot{};
        next_generation = 1;
    }

    unsigned int NextGeneration()
    {
        unsigned int generation = next_generation++;
        if (next_generation == 0U) next_generation = 1U;
        return generation;
    }

    long ReadMaps(char *buffer, unsigned long capacity, unsigned long *out_length)
    {
        if (!ops.open_read || !ops.read || !ops.close || !buffer || capacity < 2) {
            return RTGUM_HOST_ERR_INVAL;
        }
        const long fd = ops.open_read("/proc/self/maps");
        if (fd < 0) return fd;
        unsigned long filled = 0;
        while (filled + 1 < capacity) {
            const long count = ops.read(fd, buffer + filled, capacity - 1 - filled);
            if (count < 0) {
                ops.close(fd);
                return count;
            }
            if (count == 0) break;
            filled += static_cast<unsigned long>(count);
        }
        ops.close(fd);
        buffer[filled] = '\0';
        if (out_length) *out_length = filled;
        return 0;
    }

    long FindExport(const char *soname, const char *symbol, unsigned long *out_address)
    {
        if (!soname || !symbol || !out_address) return RTGUM_HOST_ERR_INVAL;
        *out_address = 0;
        if (ops.find_export) {
            const long status = ops.find_export(soname, symbol, out_address);
            if (status != 0) *out_address = 0;
            return status;
        }
        if (!ops.mmap || !ops.munmap) return RTGUM_HOST_ERR_NOTSUP;
        const long mapped = ops.mmap(kMapsCapacity, kProtRead | kProtWrite);
        if (mapped <= 0) return mapped < 0 ? mapped : RTGUM_HOST_ERR_NOMEM;
        auto *maps = reinterpret_cast<char *>(static_cast<unsigned long>(mapped));
        const long maps_status = ReadMaps(maps, kMapsCapacity, nullptr);
        long result = maps_status;
        if (maps_status == 0) {
            unsigned long base = 0;
            if (FindSonameBase(maps, soname, &base) == 0) {
                result = LookupSymbolInMappedElf(base, symbol, out_address);
            } else {
                result = RTGUM_HOST_ERR_NOENT;
            }
            if (result != 0) result = FindSymbolInApkMappedElfs(maps, symbol, out_address);
        }
        ops.munmap(static_cast<unsigned long>(mapped), kMapsCapacity);
        return result;
    }

    long WaitExport(const char *soname,
                    const char *symbol,
                    unsigned int timeout_ms,
                    unsigned long *out_address)
    {
        if (!soname || !symbol || !out_address) return RTGUM_HOST_ERR_INVAL;
        *out_address = 0;
        unsigned int elapsed = 0;
        for (;;) {
            unsigned long address = 0;
            const long found = FindExport(soname, symbol, &address);
            if (found == 0 && address != 0) {
                *out_address = address;
                return 0;
            }
            if (found != 0 && found != RTGUM_HOST_ERR_NOENT) return found;
            if (elapsed >= timeout_ms) return RTGUM_HOST_ERR_NOENT;
            unsigned int step = 2U;
            if (timeout_ms - elapsed < step) step = timeout_ms - elapsed;
            if (step == 0U || !ops.sleep_ms) return RTGUM_HOST_ERR_NOENT;
            (void)ops.sleep_ms(step);
            elapsed += step;
        }
    }

    long HookSymbol(const char *soname,
                    const char *symbol,
                    unsigned long replacement,
                    unsigned long *out_original,
                    unsigned long *out_handle)
    {
        if (!soname || !symbol || replacement == 0 || !out_original || !out_handle)
            return RTGUM_HOST_ERR_INVAL;
        *out_original = 0;
        *out_handle = 0;
        unsigned long target = 0;
        const long found = FindExport(soname, symbol, &target);
        if (found != 0) return found;
        if (target == 0) return RTGUM_HOST_ERR_NOENT;
        return Replace(target, replacement, out_original, out_handle);
    }

    long Replace(unsigned long target,
                 unsigned long replacement,
                 unsigned long *out_original,
                 unsigned long *out_handle)
    {
        if ((target & 3UL) != 0UL || replacement == 0 || !out_original || !out_handle) {
            return RTGUM_HOST_ERR_INVAL;
        }
        if (!ops.mmap || !ops.mprotect || !ops.munmap || !ops.clear_cache) {
            return RTGUM_HOST_ERR_NOTSUP;
        }
        for (unsigned int index = 0; index < kMaxHooks; ++index) {
            if (slots[index].used && slots[index].target == target) return RTGUM_HOST_ERR_EXIST;
        }
        int free_index = -1;
        for (unsigned int index = 0; index < kMaxHooks; ++index) {
            if (!slots[index].used) {
                free_index = static_cast<int>(index);
                break;
            }
        }
        if (free_index < 0) return RTGUM_HOST_ERR_BUSY;

        unsigned char prologue[kPatchBytes];
        CopyBytes(prologue, reinterpret_cast<const void *>(target), kPatchBytes);
        if (!PrologueIsCopyable(prologue)) return RTGUM_HOST_ERR_NOTSUP;

        last_step = 1;
        const long trampoline = ops.mmap(kPageSize, kProtRead | kProtWrite);
        if (trampoline <= 0) return trampoline < 0 ? trampoline : RTGUM_HOST_ERR_NOMEM;
        auto *tramp = reinterpret_cast<unsigned char *>(static_cast<unsigned long>(trampoline));
        CopyBytes(tramp, prologue, kPatchBytes);
        EncodeAbsoluteJump(tramp + kPatchBytes, target + kPatchBytes);
        last_step = 2;
        const long rx = ops.mprotect(static_cast<unsigned long>(trampoline),
                                     kPageSize,
                                     kProtRead | kProtExec);
        if (rx != 0) {
            ops.munmap(static_cast<unsigned long>(trampoline), kPageSize);
            return rx;
        }
        ops.clear_cache(static_cast<unsigned long>(trampoline), kTrampolineBytes);

        const unsigned long page = AlignDown(target, kPageSize);
        unsigned long span = kPageSize;
        if (AlignDown(target + kPatchBytes - 1UL, kPageSize) != page) span = kPageSize * 2UL;
        last_step = 3;
        const long writable = ops.mprotect(page, span, kProtRead | kProtWrite | kProtExec);
        if (writable != 0) {
            ops.munmap(static_cast<unsigned long>(trampoline), kPageSize);
            return writable;
        }
        auto *entry = reinterpret_cast<unsigned char *>(target);
        EncodeAbsoluteJump(entry, replacement);
        last_step = 4;
        const long executable = ops.mprotect(page, span, kProtRead | kProtExec);
        if (executable != 0) {
            CopyBytes(entry, prologue, kPatchBytes);
            (void)ops.mprotect(page, span, kProtRead | kProtExec);
            ops.clear_cache(target, kPatchBytes);
            ops.munmap(static_cast<unsigned long>(trampoline), kPageSize);
            return executable;
        }
        last_step = 5;
        ops.clear_cache(target, kPatchBytes);

        HookSlot &slot = slots[static_cast<unsigned int>(free_index)];
        const unsigned int generation = NextGeneration();
        slot.used = true;
        slot.generation = generation;
        slot.target = target;
        slot.replacement = replacement;
        slot.trampoline = static_cast<unsigned long>(trampoline);
        CopyBytes(slot.original, prologue, kPatchBytes);
        slot.handle = (static_cast<unsigned long>(generation) << 8) |
                      (static_cast<unsigned long>(free_index) + 1UL);
        slot.retired_handle = 0;
        *out_original = slot.trampoline;
        *out_handle = slot.handle;
        return 0;
    }

    long Revert(unsigned long handle)
    {
        if (handle == 0) return RTGUM_HOST_ERR_BADF;
        const unsigned int slot_id = static_cast<unsigned int>(handle & 0xffUL);
        if (slot_id == 0 || slot_id > kMaxHooks) return RTGUM_HOST_ERR_BADF;
        HookSlot &slot = slots[slot_id - 1U];
        if (!slot.used) {
            return slot.retired_handle == handle ? 0 : RTGUM_HOST_ERR_BADF;
        }
        if (slot.handle != handle) return RTGUM_HOST_ERR_BADF;
        if (!ops.mprotect || !ops.munmap || !ops.clear_cache) return RTGUM_HOST_ERR_NOTSUP;

        const unsigned long page = AlignDown(slot.target, kPageSize);
        unsigned long span = kPageSize;
        if (AlignDown(slot.target + kPatchBytes - 1UL, kPageSize) != page) span = kPageSize * 2UL;
        const long writable = ops.mprotect(page, span, kProtRead | kProtWrite | kProtExec);
        if (writable != 0) return writable;
        CopyBytes(reinterpret_cast<void *>(slot.target), slot.original, kPatchBytes);
        const long executable = ops.mprotect(page, span, kProtRead | kProtExec);
        ops.clear_cache(slot.target, kPatchBytes);
        if (slot.trampoline != 0) ops.munmap(slot.trampoline, kPageSize);
        slot.retired_handle = handle;
        slot.used = false;
        slot.handle = 0;
        slot.target = 0;
        slot.trampoline = 0;
        return executable;
    }

    long RevertByTarget(unsigned long target)
    {
        if (target == 0) return RTGUM_HOST_ERR_INVAL;
        for (unsigned int index = 0; index < kMaxHooks; ++index) {
            if (slots[index].used && slots[index].target == target) {
                return Revert(slots[index].handle);
            }
        }
        return RTGUM_HOST_ERR_NOENT;
    }

    long Query(unsigned long handle, unsigned int *out_backend, unsigned int *out_state)
    {
        if (!out_backend || !out_state || handle == 0) return RTGUM_HOST_ERR_INVAL;
        const unsigned int slot_id = static_cast<unsigned int>(handle & 0xffUL);
        if (slot_id == 0 || slot_id > kMaxHooks) return RTGUM_HOST_ERR_BADF;
        const HookSlot &slot = slots[slot_id - 1U];
        *out_backend = RTGUM_HOST_BACKEND_NATIVE;
        if (slot.used && slot.handle == handle) {
            *out_state = RTGUM_HOST_HOOK_ACTIVE;
            return 0;
        }
        if (slot.retired_handle == handle) {
            *out_state = RTGUM_HOST_HOOK_INACTIVE;
            return 0;
        }
        return RTGUM_HOST_ERR_BADF;
    }

    long Defer(void (*function)(void *), void *argument)
    {
        if (!function) return RTGUM_HOST_ERR_INVAL;
        if (!ops.clone) return RTGUM_HOST_ERR_NOTSUP;
        return ops.clone(function, argument);
    }

    long SleepMs(unsigned int milliseconds)
    {
        if (!ops.sleep_ms) return RTGUM_HOST_ERR_NOTSUP;
        return ops.sleep_ms(milliseconds);
    }
};

}  // namespace native
}  // namespace rtgum
