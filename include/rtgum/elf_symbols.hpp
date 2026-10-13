#pragma once

#include "rtgum/native_backend.hpp"

namespace rtgum {
namespace native {

constexpr std::uint32_t kShtSymtab = 2U;
constexpr std::uint32_t kShtDynsym = 11U;
constexpr unsigned char kSttFunc = 2U;
constexpr unsigned char kSttGnuIfunc = 10U;

struct ElfSymbol {
    const char *name;
    std::uint64_t value;
    std::uint16_t shndx;
    unsigned char type;
};

inline unsigned long MinPtLoadVaddr(const unsigned char *file, unsigned long size)
{
    ElfView image{file, size};
    const unsigned char *ehdr = FileOffset(image, 0, 64);
    if (!ehdr) return 0;
    const std::uint64_t phoff = ReadU64(ehdr + 32);
    const std::uint16_t phentsize = ReadU16(ehdr + 54);
    const std::uint16_t phnum = ReadU16(ehdr + 56);
    if (phentsize < 56) return 0;
    std::uint64_t min_vaddr = ~0ULL;
    for (std::uint16_t index = 0; index < phnum; ++index) {
        const unsigned char *phdr = FileOffset(
            image, phoff + static_cast<std::uint64_t>(index) * phentsize, 56);
        if (!phdr) return 0;
        if (ReadU32(phdr) != 1U) continue;
        const std::uint64_t p_vaddr = ReadU64(phdr + 16);
        if (p_vaddr < min_vaddr) min_vaddr = p_vaddr;
    }
    return min_vaddr == ~0ULL ? 0UL : static_cast<unsigned long>(min_vaddr);
}

inline bool WalkElfFileSymbols(const unsigned char *file,
                               unsigned long size,
                               bool (*visit)(const ElfSymbol *, void *),
                               void *context)
{
    if (!file || !visit) return false;
    ElfView image{file, size};
    const unsigned char *ehdr = FileOffset(image, 0, 64);
    if (!ehdr || ehdr[0] != 0x7f || ehdr[1] != 'E' || ehdr[2] != 'L' || ehdr[3] != 'F') {
        return false;
    }
    if (ehdr[4] != 2 || ehdr[5] != 1) return false;
    const std::uint64_t shoff = ReadU64(ehdr + 40);
    const std::uint16_t shentsize = ReadU16(ehdr + 58);
    const std::uint16_t shnum = ReadU16(ehdr + 60);
    if (shentsize < 64 || shnum == 0) return false;

    for (std::uint16_t index = 0; index < shnum; ++index) {
        const unsigned char *shdr =
            FileOffset(image, shoff + static_cast<std::uint64_t>(index) * shentsize, 64);
        if (!shdr) return false;
        const std::uint32_t type = ReadU32(shdr + 4);
        if (type != kShtSymtab && type != kShtDynsym) continue;
        const std::uint64_t offset = ReadU64(shdr + 24);
        const std::uint64_t section_size = ReadU64(shdr + 32);
        const std::uint32_t link = ReadU32(shdr + 40);
        const std::uint64_t entsize = ReadU64(shdr + 56);
        if (entsize != 24 || link >= shnum) continue;
        const unsigned char *str_shdr =
            FileOffset(image, shoff + static_cast<std::uint64_t>(link) * shentsize, 64);
        if (!str_shdr) return false;
        const std::uint64_t str_offset = ReadU64(str_shdr + 24);
        const std::uint64_t str_size = ReadU64(str_shdr + 32);
        if (section_size < 24 || str_size == 0) continue;
        const unsigned long count = static_cast<unsigned long>(section_size / 24ULL);
        for (unsigned long symbol_index = 1; symbol_index < count; ++symbol_index) {
            const unsigned char *sym = FileOffset(image, offset + symbol_index * 24ULL, 24);
            if (!sym) return false;
            const std::uint32_t name_offset = ReadU32(sym);
            const unsigned char info = sym[4];
            const std::uint16_t shndx = ReadU16(sym + 6);
            const std::uint64_t value = ReadU64(sym + 8);
            if (name_offset >= str_size || shndx == 0) continue;
            const unsigned char *name = FileOffset(image, str_offset + name_offset, 1);
            if (!name || name[0] == '\0' || name[0] == '$') continue;
            ElfSymbol parsed{};
            parsed.name = reinterpret_cast<const char *>(name);
            parsed.value = value;
            parsed.shndx = shndx;
            parsed.type = static_cast<unsigned char>(info & 0x0fU);
            if (!visit(&parsed, context)) return true;
        }
    }
    return true;
}

struct ExactSymbolSearch {
    const char *name;
    std::uint64_t value;
    bool found;
};

inline bool VisitExactSymbol(const ElfSymbol *symbol, void *context)
{
    auto *search = static_cast<ExactSymbolSearch *>(context);
    if (!StringsEqual(symbol->name, search->name)) return true;
    if (symbol->type != kSttFunc && symbol->type != kSttGnuIfunc && symbol->type != 0) {
        return true;
    }
    search->value = symbol->value;
    search->found = true;
    return false;
}

struct PrefixSymbolSearch {
    const char *prefix;
    unsigned long prefix_length;
    std::uint64_t value;
    bool found;
};

inline bool VisitPrefixSymbol(const ElfSymbol *symbol, void *context)
{
    auto *search = static_cast<PrefixSymbolSearch *>(context);
    unsigned long index = 0;
    while (index < search->prefix_length && symbol->name[index] != '\0' &&
           symbol->name[index] == search->prefix[index]) {
        ++index;
    }
    if (index != search->prefix_length) return true;
    if (symbol->type != kSttFunc && symbol->type != kSttGnuIfunc && symbol->type != 0) {
        return true;
    }
    search->value = symbol->value;
    search->found = true;
    return false;
}

inline long LookupSymbolInElfSymtab(const unsigned char *file,
                                    unsigned long size,
                                    const char *symbol,
                                    unsigned long *out_vaddr)
{
    if (!file || !symbol || !out_vaddr || *symbol == '\0') return RTGUM_HOST_ERR_INVAL;
    ExactSymbolSearch search{symbol, 0, false};
    if (!WalkElfFileSymbols(file, size, VisitExactSymbol, &search)) {
        return RTGUM_HOST_ERR_NOENT;
    }
    if (!search.found) return RTGUM_HOST_ERR_NOENT;
    *out_vaddr = static_cast<unsigned long>(search.value);
    return 0;
}

inline long LookupSymbolPrefixInElfSymtab(const unsigned char *file,
                                          unsigned long size,
                                          const char *prefix,
                                          unsigned long *out_vaddr)
{
    if (!file || !prefix || !out_vaddr || *prefix == '\0') return RTGUM_HOST_ERR_INVAL;
    PrefixSymbolSearch search{prefix, StringLength(prefix, 512), 0, false};
    if (!WalkElfFileSymbols(file, size, VisitPrefixSymbol, &search)) {
        return RTGUM_HOST_ERR_NOENT;
    }
    if (!search.found) return RTGUM_HOST_ERR_NOENT;
    *out_vaddr = static_cast<unsigned long>(search.value);
    return 0;
}

inline long FindSonameLoadBias(const char *maps,
                               const char *soname,
                               unsigned long *out_bias)
{
    unsigned long base = 0;
    const long status = FindSonameBase(maps, soname, &base);
    if (status != 0) return status;
    *out_bias = base;
    return 0;
}

}  // namespace native
}  // namespace rtgum
