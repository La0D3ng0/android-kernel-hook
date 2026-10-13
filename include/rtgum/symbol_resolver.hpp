#pragma once

/*
 * Freestanding ELF symbol resolver used by the VMA-less stage-2 Daemon.
 *
 * The resolver deliberately has no dependency on libdl or link_map.  Normal
 * images are discovered from a kernel VMA snapshot and inspected through the
 * authenticated memory-read primitive.  VMA-less images are registered by
 * the private loader and their original ELF bytes are supplied read-only by
 * the KPM.  Disk images are parsed once into fixed-capacity, sorted caches;
 * .symtab is preferred and .dynsym is the fallback.
 */

#include "rtgum/native_backend.hpp"

#include <cstddef>
#include <cstdint>

namespace rtgum {
namespace symbols {

constexpr unsigned long kPageSize = 4096UL;
constexpr unsigned int kMaximumVmas = 4096U;
constexpr unsigned int kMaximumMappedImages = 192U;
constexpr unsigned int kMaximumGhostImages = 16U;
constexpr unsigned int kMaximumCaches = 4U;
/* These buffers live in an on-demand ghost allocation, not in the Daemon
 * image.  The limits cover the full API-36 linker64 table (11,203 retained
 * symbols / about 395 KiB of names) while retaining an explicit bound for
 * malformed or developer-sized ELF files. */
constexpr unsigned int kMaximumSymbolsPerCache = 16384U;
constexpr unsigned int kCacheNameBytes = 512U * 1024U;
constexpr unsigned long kMaximumElfBytes = 16UL * 1024UL * 1024UL;
constexpr unsigned int kMaximumDynamicSymbols = 65536U;
constexpr unsigned int kMaximumBatchPcs = 1024U;

struct VmaRange final {
    unsigned long start;
    unsigned long end;
};

struct ResolverOps final {
    long (*vma_snapshot)(VmaRange *ranges,
                         unsigned int capacity,
                         unsigned int *out_count);
    long (*memory_read)(unsigned long address, void *buffer, unsigned long length);
    long (*ghost_file_size)(unsigned long base, unsigned long *out_size);
    long (*ghost_file_copy)(unsigned long base, void *buffer, unsigned long length);
    long (*open_read)(const char *path);
    long (*read)(long descriptor, void *buffer, unsigned long length);
    long (*seek)(long descriptor, long offset, int whence);
    long (*close)(long descriptor);
    long (*map_rw)(unsigned long size);
    long (*unmap)(unsigned long address, unsigned long size);
    long (*allocate_cache)(unsigned long size, unsigned long *out_address);
    long (*release_cache)(unsigned long address);
};

struct ResolvedSymbol final {
    char module[96];
    char symbol[192];
    unsigned long address;
    unsigned long offset;
    bool ghost;
};

namespace detail {

inline unsigned long AlignDown(unsigned long value)
{
    return value & ~(kPageSize - 1UL);
}

inline unsigned long AlignUp(unsigned long value)
{
    if (value > ~0UL - (kPageSize - 1UL)) return 0;
    return (value + kPageSize - 1UL) & ~(kPageSize - 1UL);
}

inline unsigned long Length(const char *text, unsigned long limit)
{
    unsigned long length = 0;
    if (!text) return 0;
    while (length < limit && text[length] != '\0') ++length;
    return length;
}

inline bool Equal(const char *left, const char *right)
{
    if (!left || !right) return false;
    while (*left != '\0' && *left == *right) {
        ++left;
        ++right;
    }
    return *left == *right;
}

inline int Compare(const char *left, const char *right)
{
    if (!left) return right ? -1 : 0;
    if (!right) return 1;
    while (*left != '\0' && *left == *right) {
        ++left;
        ++right;
    }
    return static_cast<unsigned char>(*left) -
           static_cast<unsigned char>(*right);
}

inline void Copy(char *destination, unsigned long capacity, const char *source)
{
    if (!destination || capacity == 0) return;
    unsigned long index = 0;
    while (source && source[index] != '\0' && index + 1UL < capacity) {
        destination[index] = source[index];
        ++index;
    }
    destination[index] = '\0';
}

inline const char *BaseName(const char *path)
{
    if (!path) return "";
    const char *base = path;
    for (const char *cursor = path; *cursor != '\0'; ++cursor) {
        if (*cursor == '/') base = cursor + 1;
    }
    return base;
}

inline bool Append(char *out,
                   unsigned long capacity,
                   unsigned long &cursor,
                   const char *text)
{
    if (!out || capacity == 0 || !text) return false;
    while (*text != '\0') {
        if (cursor + 1UL >= capacity) return false;
        out[cursor++] = *text++;
    }
    out[cursor] = '\0';
    return true;
}

inline bool AppendHex(char *out,
                      unsigned long capacity,
                      unsigned long &cursor,
                      unsigned long value,
                      bool prefix)
{
    static constexpr char kDigits[] = "0123456789abcdef";
    if (prefix && !Append(out, capacity, cursor, "0x")) return false;
    bool started = false;
    for (int shift = static_cast<int>(sizeof(unsigned long) * 8U) - 4;
         shift >= 0;
         shift -= 4) {
        const unsigned long digit = (value >> shift) & 0xfUL;
        if (!started && digit == 0UL && shift != 0) continue;
        started = true;
        if (cursor + 1UL >= capacity) return false;
        out[cursor++] = kDigits[digit];
    }
    out[cursor] = '\0';
    return true;
}

inline bool RangeValid(unsigned long offset,
                       unsigned long length,
                       unsigned long total)
{
    return offset <= total && length <= total - offset;
}

inline bool ValidElfHeader(const unsigned char *header)
{
    return header && header[0] == 0x7fU && header[1] == 'E' &&
           header[2] == 'L' && header[3] == 'F' && header[4] == 2U &&
           header[5] == 1U && native::ReadU16(header + 18) == 183U;
}

inline bool ValidMappedElfHeader(const unsigned char *header)
{
    if (!header || header[0] != 0x7fU || header[1] != 'E' ||
        header[2] != 'L' || header[3] != 'F' || header[4] != 2U ||
        header[5] != 1U || header[6] != 1U)
        return false;

    if (native::ReadU16(header + 16) == 3U &&
        native::ReadU16(header + 18) == 183U)
        return true;

    /* Gum's AArch64 interceptor may use the otherwise unused ELF e_ident
     * padding as a nearby deflector.  Its 16-byte sequence starts at +8 and
     * overwrites e_type/e_machine with the embedded target address while the
     * program-header table and PT_DYNAMIC remain intact:
     *
     *     ldr x16, #8; br x16; .quad target
     *
     * This is observed after gum_init_embedded(), so a bounded image cache
     * can legitimately encounter it during an on-demand scan.  Accept only
     * this exact code-cave signature here; disk ELF parsing remains strict,
     * and InspectMappedImage still validates the complete PHDR/DYNAMIC/hash/
     * SONAME chain before returning an image. */
    return native::ReadU32(header + 8) == 0x58000050U &&
           native::ReadU32(header + 12) == 0xd61f0200U;
}

} // namespace detail

class Resolver final {
public:
    void Reset()
    {
        Lock guard(*this);
        vma_count_ = 0;
        image_count_ = 0;
        image_victim_ = 0;
        package_[0] = '\0';
        generation_ = 1;
        for (unsigned int index = 0; index < kMaximumGhostImages; ++index)
            ghosts_[index] = GhostImage{};
        for (unsigned int index = 0; index < kMaximumCaches; ++index) {
            if (caches_[index] && ops_.release_cache) {
                const unsigned long names =
                    reinterpret_cast<unsigned long>(caches_[index]->names);
                if (names != 0) (void)ops_.release_cache(names);
                (void)ops_.release_cache(
                    reinterpret_cast<unsigned long>(caches_[index]));
            }
            caches_[index] = nullptr;
        }
    }

    ResolverOps &ops() { return ops_; }

    void SetPackage(const char *package)
    {
        Lock guard(*this);
        detail::Copy(package_, sizeof(package_), package);
    }

    long RegisterGhost(const char *path,
                       unsigned long base,
                       unsigned long mapped_size)
    {
        if (!path || *path == '\0' || base == 0 || mapped_size == 0)
            return RTGUM_HOST_ERR_INVAL;
        Lock guard(*this);
        for (unsigned int index = 0; index < kMaximumGhostImages; ++index) {
            if (ghosts_[index].used && ghosts_[index].base == base) {
                detail::Copy(ghosts_[index].path, sizeof(ghosts_[index].path), path);
                detail::Copy(ghosts_[index].soname, sizeof(ghosts_[index].soname),
                             detail::BaseName(path));
                ghosts_[index].mapped_size = mapped_size;
                return 0;
            }
        }
        for (unsigned int index = 0; index < kMaximumGhostImages; ++index) {
            if (ghosts_[index].used) continue;
            GhostImage &image = ghosts_[index];
            image = {};
            image.used = true;
            image.base = base;
            image.mapped_size = mapped_size;
            detail::Copy(image.path, sizeof(image.path), path);
            detail::Copy(image.soname, sizeof(image.soname), detail::BaseName(path));
            return 0;
        }
        return RTGUM_HOST_ERR_NOMEM;
    }

    /* Remove the registry entry only after every in-flight resolver call has
     * left the lock.  The caller can then safely ask the KPM to free the ELF
     * bytes and mappings.  The path is returned so a failed unlink can restore
     * the registry without losing its identity. */
    bool TakeGhost(unsigned long base,
                   char *path,
                   unsigned long path_capacity,
                   unsigned long &mapped_size)
    {
        Lock guard(*this);
        for (unsigned int index = 0; index < kMaximumGhostImages; ++index) {
            GhostImage &image = ghosts_[index];
            if (!image.used || image.base != base) continue;
            detail::Copy(path, path_capacity, image.path);
            mapped_size = image.mapped_size;
            image = {};
            for (unsigned int cache = 0; cache < kMaximumCaches; ++cache) {
                if (caches_[cache] && caches_[cache]->used &&
                    caches_[cache]->source_base == base)
                    caches_[cache]->used = false;
            }
            return true;
        }
        if (path && path_capacity != 0) path[0] = '\0';
        mapped_size = 0;
        return false;
    }

    long Refresh()
    {
        Lock guard(*this);
        return RefreshLocked();
    }

    long FindExport(const char *soname,
                    const char *symbol,
                    unsigned long *out_address)
    {
        if (!soname || !symbol || !out_address || *soname == '\0' || *symbol == '\0')
            return RTGUM_HOST_ERR_INVAL;
        *out_address = 0;
        Lock guard(*this);
        long status = FindExportLocked(soname, symbol, out_address);
        if (status == RTGUM_HOST_ERR_NOENT) {
            const long refreshed = RefreshLocked();
            if (refreshed != 0) return refreshed;
            status = FindExportLocked(soname, symbol, out_address);
        }
        if (status != 0) *out_address = 0;
        return status;
    }

    long Symbolize(unsigned long pc,
                   ResolvedSymbol *out_symbol)
    {
        if (pc == 0 || !out_symbol) return RTGUM_HOST_ERR_INVAL;
        *out_symbol = {};
        Lock guard(*this);
        long status = SymbolizeLocked(pc, *out_symbol);
        if (status == RTGUM_HOST_ERR_NOENT) {
            const long refreshed = RefreshLocked();
            if (refreshed != 0) return refreshed;
            status = SymbolizeLocked(pc, *out_symbol);
        }
        return status;
    }

    long Format(unsigned long pc, char *out, unsigned long capacity)
    {
        if (!out || capacity == 0) return RTGUM_HOST_ERR_INVAL;
        out[0] = '\0';
        ResolvedSymbol resolved{};
        const long status = Symbolize(pc, &resolved);
        if (status != 0) {
            detail::Copy(out, capacity, "symbol not found");
            return status;
        }
        unsigned long cursor = 0;
        if (!detail::Append(out, capacity, cursor, resolved.module) ||
            !detail::Append(out, capacity, cursor, "!") ||
            !detail::Append(out, capacity, cursor, resolved.symbol) ||
            !detail::Append(out, capacity, cursor, "+") ||
            !detail::AppendHex(out, capacity, cursor, resolved.offset, true)) {
            out[0] = '\0';
            return RTGUM_HOST_ERR_NOMEM;
        }
        return 0;
    }

    long FormatBatch(const unsigned long *pcs,
                     unsigned long count,
                     char *out,
                     unsigned long capacity)
    {
        if (!pcs || !out || capacity == 0 || count == 0 ||
            count > kMaximumBatchPcs)
            return RTGUM_HOST_ERR_INVAL;
        out[0] = '\0';
        unsigned long cursor = 0;
        long first_error = 0;
        for (unsigned long index = 0; index < count; ++index) {
            char one[320];
            const long status = Format(pcs[index], one, sizeof(one));
            if (status != 0 && first_error == 0) first_error = status;
            if (!detail::AppendHex(out, capacity, cursor, pcs[index], true) ||
                !detail::Append(out, capacity, cursor, " ") ||
                !detail::Append(out, capacity, cursor, one) ||
                !detail::Append(out, capacity, cursor, "\n")) {
                out[0] = '\0';
                return RTGUM_HOST_ERR_NOMEM;
            }
        }
        return first_error;
    }

    void DebugImages(char *out, unsigned long capacity)
    {
        if (!out || capacity == 0) return;
        Lock guard(*this);
        unsigned long cursor = 0;
        out[0] = '\0';
        (void)detail::Append(out, capacity, cursor, "resolver stage=");
        (void)detail::Append(out, capacity, cursor, debug_stage_);
        (void)detail::Append(out, capacity, cursor, " request=");
        (void)detail::Append(out, capacity, cursor, debug_request_);
        (void)detail::Append(out, capacity, cursor, " mapped=");
        for (unsigned int index = 0; index < image_count_; ++index) {
            if (index != 0U &&
                !detail::Append(out, capacity, cursor, ","))
                break;
            if (!detail::Append(out, capacity, cursor, images_[index].soname)) break;
        }
        (void)detail::Append(out, capacity, cursor, " ghost=");
        for (unsigned int index = 0; index < kMaximumGhostImages; ++index) {
            if (!ghosts_[index].used) continue;
            if (!detail::Append(out, capacity, cursor, ghosts_[index].soname)) break;
            (void)detail::Append(out, capacity, cursor, ",");
        }
    }

private:
    struct Lock final {
        explicit Lock(Resolver &owner) : owner_(owner)
        {
            while (__atomic_test_and_set(&owner_.locked_, __ATOMIC_ACQUIRE)) {
#if defined(__aarch64__)
                __asm__ volatile("yield" ::: "memory");
#endif
            }
        }
        ~Lock() { __atomic_clear(&owner_.locked_, __ATOMIC_RELEASE); }
        Resolver &owner_;
    };

    struct DynamicImage final {
        bool used;
        unsigned long first;
        unsigned long last;
        unsigned long load_bias;
        unsigned long minimum;
        unsigned long maximum;
        unsigned long symtab;
        unsigned long strtab;
        unsigned long string_size;
        unsigned long gnu_hash;
        unsigned long sysv_hash;
        unsigned int symbol_count;
        char soname[96];
    };

    struct GhostImage final {
        bool used;
        unsigned long base;
        unsigned long mapped_size;
        char path[160];
        char soname[96];
    };

    struct SymbolRecord final {
        unsigned long value;
        unsigned int size;
        unsigned int name_offset;
    };

    struct ElfCache final {
        bool used;
        bool full_symbols;
        unsigned long source_base; /* zero for an ordinary disk image */
        unsigned long minimum;
        unsigned long maximum;
        unsigned long last_use;
        unsigned int count;
        unsigned int name_used;
        char *names;
        char key[160];
        SymbolRecord symbols[kMaximumSymbolsPerCache];
        unsigned int by_name[kMaximumSymbolsPerCache];
        unsigned int by_value[kMaximumSymbolsPerCache];
    };

    static_assert(sizeof(ElfCache) <= 512UL * 1024UL,
                  "symbol record cache must fit one ghost allocation");
    static_assert(kCacheNameBytes <= 512U * 1024U,
                  "symbol name cache must fit one ghost allocation");

    bool ReadMemory(unsigned long address, void *buffer, unsigned long length) const
    {
        return ops_.memory_read && length != 0 &&
               ops_.memory_read(address, buffer, length) == 0;
    }

    bool VmaContains(unsigned long address) const
    {
        unsigned int low = 0;
        unsigned int high = vma_count_;
        while (low < high) {
            const unsigned int middle = low + (high - low) / 2U;
            if (vmas_[middle].start <= address)
                low = middle + 1U;
            else
                high = middle;
        }
        if (low == 0) return false;
        const VmaRange &range = vmas_[low - 1U];
        return address >= range.start && address < range.end;
    }

    unsigned long NormalizeDynamicPointer(unsigned long value,
                                          unsigned long bias) const
    {
        if (VmaContains(value)) return value;
        if (value > ~0UL - bias) return 0;
        return bias + value;
    }

    bool ReadCString(unsigned long address,
                     char *out,
                     unsigned long capacity) const
    {
        if (!out || capacity < 2UL) return false;
        unsigned long copied = 0;
        while (copied + 1UL < capacity) {
            unsigned char block[64];
            unsigned long chunk = capacity - 1UL - copied;
            if (chunk > sizeof(block)) chunk = sizeof(block);
            if (!ReadMemory(address + copied, block, chunk)) return false;
            for (unsigned long index = 0; index < chunk; ++index) {
                out[copied++] = static_cast<char>(block[index]);
                if (block[index] == 0U) return copied > 1UL;
            }
        }
        out[capacity - 1UL] = '\0';
        return false;
    }

    long GnuSymbolCount(unsigned long gnu_hash, unsigned int &out_count) const
    {
        out_count = 0;
        unsigned char header[16];
        if (!ReadMemory(gnu_hash, header, sizeof(header))) return RTGUM_HOST_ERR_NOENT;
        const unsigned int buckets = native::ReadU32(header);
        const unsigned int symbol_offset = native::ReadU32(header + 4);
        const unsigned int bloom_size = native::ReadU32(header + 8);
        if (buckets == 0U || bloom_size == 0U || buckets > kMaximumDynamicSymbols)
            return RTGUM_HOST_ERR_NOENT;
        const unsigned long bucket_address =
            gnu_hash + 16UL + static_cast<unsigned long>(bloom_size) * 8UL;
        unsigned int maximum = 0;
        for (unsigned int index = 0; index < buckets; ++index) {
            unsigned char bytes[4];
            if (!ReadMemory(bucket_address + static_cast<unsigned long>(index) * 4UL,
                            bytes, sizeof(bytes)))
                return RTGUM_HOST_ERR_NOENT;
            const unsigned int value = native::ReadU32(bytes);
            if (value > maximum) maximum = value;
        }
        if (maximum < symbol_offset) {
            out_count = symbol_offset;
            return 0;
        }
        const unsigned long chain_address = bucket_address +
            static_cast<unsigned long>(buckets) * 4UL;
        unsigned int index = maximum;
        while (index < kMaximumDynamicSymbols) {
            unsigned char bytes[4];
            if (!ReadMemory(chain_address +
                                static_cast<unsigned long>(index - symbol_offset) * 4UL,
                            bytes, sizeof(bytes)))
                return RTGUM_HOST_ERR_NOENT;
            ++index;
            if ((native::ReadU32(bytes) & 1U) != 0U) {
                out_count = index;
                return 0;
            }
        }
        return RTGUM_HOST_ERR_NOTSUP;
    }

    long InspectMappedImage(unsigned long header_address, DynamicImage &image) const
    {
        image = {};
        unsigned char header[64];
        if (!ReadMemory(header_address, header, sizeof(header)) ||
            !detail::ValidMappedElfHeader(header))
            return RTGUM_HOST_ERR_NOENT;
        const unsigned long phoff = static_cast<unsigned long>(native::ReadU64(header + 32));
        const unsigned int phentsize = native::ReadU16(header + 54);
        const unsigned int phnum = native::ReadU16(header + 56);
        if (phentsize < 56U || phnum == 0U || phnum > 256U || phoff > 65536UL)
            return RTGUM_HOST_ERR_NOTSUP;

        unsigned long minimum = ~0UL;
        unsigned long maximum = 0;
        unsigned long dynamic_vaddr = 0;
        unsigned long dynamic_size = 0;
        for (unsigned int index = 0; index < phnum; ++index) {
            unsigned char program[56];
            if (!ReadMemory(header_address + phoff +
                                static_cast<unsigned long>(index) * phentsize,
                            program, sizeof(program)))
                return RTGUM_HOST_ERR_NOENT;
            const unsigned int type = native::ReadU32(program);
            const unsigned long vaddr =
                static_cast<unsigned long>(native::ReadU64(program + 16));
            const unsigned long memsz =
                static_cast<unsigned long>(native::ReadU64(program + 40));
            if (type == 1U && memsz != 0) {
                const unsigned long first = detail::AlignDown(vaddr);
                const unsigned long last = detail::AlignUp(vaddr + memsz);
                if (last == 0 || last <= first) return RTGUM_HOST_ERR_NOTSUP;
                if (first < minimum) minimum = first;
                if (last > maximum) maximum = last;
            } else if (type == 2U) {
                dynamic_vaddr = vaddr;
                dynamic_size = memsz;
            }
        }
        if (minimum == ~0UL || maximum <= minimum || dynamic_vaddr == 0 ||
            header_address < minimum)
            return RTGUM_HOST_ERR_NOENT;
        const unsigned long bias = header_address - minimum;
        if (maximum > ~0UL - bias) return RTGUM_HOST_ERR_NOTSUP;

        unsigned long symtab_value = 0;
        unsigned long strtab_value = 0;
        unsigned long gnu_hash_value = 0;
        unsigned long sysv_hash_value = 0;
        unsigned long string_size = 0;
        unsigned long soname_offset = ~0UL;
        unsigned long syment = 24UL;
        unsigned long entries = dynamic_size / 16UL;
        if (entries == 0 || entries > 4096UL) entries = 4096UL;
        for (unsigned long index = 0; index < entries; ++index) {
            unsigned char dynamic[16];
            if (!ReadMemory(bias + dynamic_vaddr + index * 16UL,
                            dynamic, sizeof(dynamic)))
                return RTGUM_HOST_ERR_NOENT;
            const unsigned long tag =
                static_cast<unsigned long>(native::ReadU64(dynamic));
            const unsigned long value =
                static_cast<unsigned long>(native::ReadU64(dynamic + 8));
            if (tag == 0UL) break;
            if (tag == 4UL) sysv_hash_value = value;
            else if (tag == 5UL) strtab_value = value;
            else if (tag == 6UL) symtab_value = value;
            else if (tag == 10UL) string_size = value;
            else if (tag == 11UL) syment = value;
            else if (tag == 14UL) soname_offset = value;
            else if (tag == 0x6ffffef5UL) gnu_hash_value = value;
        }
        if (symtab_value == 0 || strtab_value == 0 || syment != 24UL ||
            soname_offset == ~0UL)
            return RTGUM_HOST_ERR_NOENT;
        const unsigned long symtab = NormalizeDynamicPointer(symtab_value, bias);
        const unsigned long strtab = NormalizeDynamicPointer(strtab_value, bias);
        const unsigned long gnu_hash = gnu_hash_value == 0
                                           ? 0
                                           : NormalizeDynamicPointer(gnu_hash_value, bias);
        const unsigned long sysv_hash = sysv_hash_value == 0
                                            ? 0
                                            : NormalizeDynamicPointer(sysv_hash_value, bias);
        if (symtab == 0 || strtab == 0) return RTGUM_HOST_ERR_NOENT;
        unsigned int symbol_count = 0;
        if (sysv_hash != 0) {
            unsigned char words[8];
            if (!ReadMemory(sysv_hash, words, sizeof(words)))
                return RTGUM_HOST_ERR_NOENT;
            symbol_count = native::ReadU32(words + 4);
        } else if (gnu_hash != 0) {
            const long status = GnuSymbolCount(gnu_hash, symbol_count);
            if (status != 0) return status;
        }
        if (symbol_count == 0U || symbol_count > kMaximumDynamicSymbols)
            return RTGUM_HOST_ERR_NOTSUP;
        char soname[96];
        if (string_size != 0 && soname_offset >= string_size)
            return RTGUM_HOST_ERR_NOENT;
        if (!ReadCString(strtab + soname_offset, soname, sizeof(soname)))
            return RTGUM_HOST_ERR_NOENT;

        image.used = true;
        image.first = bias + minimum;
        image.last = bias + maximum;
        image.load_bias = bias;
        image.minimum = minimum;
        image.maximum = maximum;
        image.symtab = symtab;
        image.strtab = strtab;
        image.string_size = string_size;
        image.gnu_hash = gnu_hash;
        image.sysv_hash = sysv_hash;
        image.symbol_count = symbol_count;
        detail::Copy(image.soname, sizeof(image.soname), soname);
        return 0;
    }

    long RefreshLocked()
    {
        if (!ops_.vma_snapshot || !ops_.memory_read) return RTGUM_HOST_ERR_NOTSUP;
        unsigned int count = 0;
        const long status = ops_.vma_snapshot(vmas_, kMaximumVmas, &count);
        if (status != 0) return status;
        if (count == 0U || count > kMaximumVmas) return RTGUM_HOST_ERR_NOENT;
        vma_count_ = count;
        image_count_ = 0;
        image_victim_ = 0;
        for (unsigned int index = 0; index < vma_count_ &&
                                      image_count_ < kMaximumMappedImages;
             ++index) {
            unsigned char magic[6];
            if (!ReadMemory(vmas_[index].start, magic, sizeof(magic)) ||
                magic[0] != 0x7fU || magic[1] != 'E' || magic[2] != 'L' ||
                magic[3] != 'F' || magic[4] != 2U || magic[5] != 1U)
                continue;
            DynamicImage candidate{};
            if (InspectMappedImage(vmas_[index].start, candidate) != 0) continue;
            bool duplicate = false;
            for (unsigned int known = 0; known < image_count_; ++known) {
                if (images_[known].load_bias == candidate.load_bias) {
                    duplicate = true;
                    break;
                }
            }
            if (!duplicate) images_[image_count_++] = candidate;
        }
        return 0;
    }

    void RememberMappedImage(const DynamicImage &candidate)
    {
        for (unsigned int index = 0; index < image_count_; ++index) {
            if (images_[index].load_bias == candidate.load_bias) {
                images_[index] = candidate;
                return;
            }
        }
        if (image_count_ < kMaximumMappedImages) {
            images_[image_count_++] = candidate;
            return;
        }
        /* A modern Android app can have more than 200 ELF images before libc
         * in address order.  The fixed directory is therefore a cache rather
         * than a completeness boundary: an on-demand hit replaces one entry
         * and is retained for subsequent Hook and trace lookups. */
        images_[image_victim_++ % kMaximumMappedImages] = candidate;
    }

    long FindMappedImageByName(const char *soname, DynamicImage &out)
    {
        for (unsigned int index = 0; index < image_count_; ++index) {
            if (images_[index].used &&
                detail::Equal(images_[index].soname, soname)) {
                out = images_[index];
                return 0;
            }
        }
        /* Refresh deliberately keeps a bounded image cache.  Continue over
         * the complete kernel VMA snapshot on a cache miss so late images
         * such as bionic libc cannot disappear merely because many APEX/OAT
         * images sort below them. */
        for (unsigned int index = 0; index < vma_count_; ++index) {
            DynamicImage candidate{};
            if (InspectMappedImage(vmas_[index].start, candidate) != 0)
                continue;
            if (!detail::Equal(candidate.soname, soname)) continue;
            out = candidate;
            RememberMappedImage(candidate);
            return 0;
        }
        return RTGUM_HOST_ERR_NOENT;
    }

    long FindMappedImageForPc(unsigned long pc, DynamicImage &out)
    {
        for (unsigned int index = 0; index < image_count_; ++index) {
            const DynamicImage &image = images_[index];
            if (image.used && pc >= image.first && pc < image.last) {
                out = image;
                return 0;
            }
        }
        for (unsigned int index = 0; index < vma_count_; ++index) {
            DynamicImage candidate{};
            if (InspectMappedImage(vmas_[index].start, candidate) != 0)
                continue;
            if (pc < candidate.first || pc >= candidate.last) continue;
            out = candidate;
            RememberMappedImage(candidate);
            return 0;
        }
        return RTGUM_HOST_ERR_NOENT;
    }

    static std::uint32_t GnuHash(const char *text)
    {
        std::uint32_t hash = 5381U;
        while (text && *text != '\0')
            hash = hash * 33U + static_cast<unsigned char>(*text++);
        return hash;
    }

    long MappedLookupExact(const DynamicImage &image,
                           const char *name,
                           unsigned long &value) const
    {
        value = 0;
        if (image.gnu_hash == 0) {
            /* SysV-only images are rare on current Android.  A bounded linear
             * scan keeps them correct without importing another hash parser. */
            for (unsigned int index = 1; index < image.symbol_count; ++index) {
                unsigned char symbol[24];
                if (!ReadMemory(image.symtab + static_cast<unsigned long>(index) * 24UL,
                                symbol, sizeof(symbol)))
                    return RTGUM_HOST_ERR_NOENT;
                if (native::ReadU16(symbol + 6) == 0U) continue;
                char candidate[192];
                if (!ReadCString(image.strtab + native::ReadU32(symbol), candidate,
                                 sizeof(candidate)))
                    continue;
                if (detail::Equal(candidate, name)) {
                    value = static_cast<unsigned long>(native::ReadU64(symbol + 8));
                    return value == 0 ? RTGUM_HOST_ERR_NOENT : 0;
                }
            }
            return RTGUM_HOST_ERR_NOENT;
        }

        unsigned char header[16];
        if (!ReadMemory(image.gnu_hash, header, sizeof(header)))
            return RTGUM_HOST_ERR_NOENT;
        const unsigned int buckets = native::ReadU32(header);
        const unsigned int symbol_offset = native::ReadU32(header + 4);
        const unsigned int bloom_size = native::ReadU32(header + 8);
        const unsigned int bloom_shift = native::ReadU32(header + 12);
        if (buckets == 0U || bloom_size == 0U) return RTGUM_HOST_ERR_NOENT;
        const std::uint32_t hash = GnuHash(name);
        const unsigned long bloom_address = image.gnu_hash + 16UL;
        unsigned char bloom_bytes[8];
        if (!ReadMemory(bloom_address +
                            static_cast<unsigned long>((hash / 64U) % bloom_size) * 8UL,
                        bloom_bytes, sizeof(bloom_bytes)))
            return RTGUM_HOST_ERR_NOENT;
        const std::uint64_t bloom = native::ReadU64(bloom_bytes);
        const std::uint64_t mask = (1ULL << (hash % 64U)) |
                                   (1ULL << ((hash >> bloom_shift) % 64U));
        if ((bloom & mask) != mask) return RTGUM_HOST_ERR_NOENT;
        const unsigned long bucket_address =
            bloom_address + static_cast<unsigned long>(bloom_size) * 8UL;
        unsigned char bucket_bytes[4];
        if (!ReadMemory(bucket_address +
                            static_cast<unsigned long>(hash % buckets) * 4UL,
                        bucket_bytes, sizeof(bucket_bytes)))
            return RTGUM_HOST_ERR_NOENT;
        unsigned int index = native::ReadU32(bucket_bytes);
        if (index < symbol_offset) return RTGUM_HOST_ERR_NOENT;
        const unsigned long chain_address =
            bucket_address + static_cast<unsigned long>(buckets) * 4UL;
        while (index < image.symbol_count) {
            unsigned char chain_bytes[4];
            if (!ReadMemory(chain_address +
                                static_cast<unsigned long>(index - symbol_offset) * 4UL,
                            chain_bytes, sizeof(chain_bytes)))
                return RTGUM_HOST_ERR_NOENT;
            const unsigned int chain = native::ReadU32(chain_bytes);
            if ((chain | 1U) == (hash | 1U)) {
                unsigned char symbol[24];
                if (!ReadMemory(image.symtab + static_cast<unsigned long>(index) * 24UL,
                                symbol, sizeof(symbol)))
                    return RTGUM_HOST_ERR_NOENT;
                if (native::ReadU16(symbol + 6) != 0U) {
                    char candidate[192];
                    if (ReadCString(image.strtab + native::ReadU32(symbol), candidate,
                                    sizeof(candidate)) &&
                        detail::Equal(candidate, name)) {
                        value = static_cast<unsigned long>(native::ReadU64(symbol + 8));
                        return value == 0 ? RTGUM_HOST_ERR_NOENT : 0;
                    }
                }
            }
            if ((chain & 1U) != 0U) break;
            ++index;
        }
        return RTGUM_HOST_ERR_NOENT;
    }

    long MappedLookupNearest(const DynamicImage &image,
                             unsigned long relative,
                             char *name,
                             unsigned long name_capacity,
                             unsigned long &value) const
    {
        value = 0;
        unsigned int best = 0;
        bool found = false;
        unsigned char block[3072];
        constexpr unsigned int symbols_per_block = sizeof(block) / 24U;
        for (unsigned int first = 1; first < image.symbol_count;
             first += symbols_per_block) {
            unsigned int count = image.symbol_count - first;
            if (count > symbols_per_block) count = symbols_per_block;
            if (!ReadMemory(image.symtab + static_cast<unsigned long>(first) * 24UL,
                            block, static_cast<unsigned long>(count) * 24UL))
                return RTGUM_HOST_ERR_NOENT;
            for (unsigned int slot = 0; slot < count; ++slot) {
                const unsigned char *symbol = block + slot * 24U;
                const unsigned char type = symbol[4] & 0xfU;
                if ((type != 0U && type != 2U && type != 10U) ||
                    native::ReadU16(symbol + 6) == 0U)
                    continue;
                const unsigned long candidate =
                    static_cast<unsigned long>(native::ReadU64(symbol + 8));
                if (candidate == 0 || candidate > relative ||
                    (found && candidate < value))
                    continue;
                found = true;
                value = candidate;
                best = first + slot;
            }
        }
        if (!found) return RTGUM_HOST_ERR_NOENT;
        unsigned char symbol[24];
        if (!ReadMemory(image.symtab + static_cast<unsigned long>(best) * 24UL,
                        symbol, sizeof(symbol)) ||
            !ReadCString(image.strtab + native::ReadU32(symbol), name, name_capacity))
            return RTGUM_HOST_ERR_NOENT;
        return 0;
    }

    static int CompareName(const ElfCache &cache,
                           unsigned int left,
                           unsigned int right)
    {
        return detail::Compare(cache.names + cache.symbols[left].name_offset,
                               cache.names + cache.symbols[right].name_offset);
    }

    static int CompareValue(const ElfCache &cache,
                            unsigned int left,
                            unsigned int right)
    {
        const SymbolRecord &a = cache.symbols[left];
        const SymbolRecord &b = cache.symbols[right];
        if (a.value < b.value) return -1;
        if (a.value > b.value) return 1;
        if (a.size > b.size) return -1;
        if (a.size < b.size) return 1;
        return CompareName(cache, left, right);
    }

    template <bool ByName>
    static void Sift(ElfCache &cache,
                     unsigned int *indices,
                     unsigned int root,
                     unsigned int count)
    {
        for (;;) {
            unsigned int child = root * 2U + 1U;
            if (child >= count) return;
            if (child + 1U < count) {
                const int order = ByName
                                      ? CompareName(cache, indices[child], indices[child + 1U])
                                      : CompareValue(cache, indices[child], indices[child + 1U]);
                if (order < 0) ++child;
            }
            const int order = ByName
                                  ? CompareName(cache, indices[root], indices[child])
                                  : CompareValue(cache, indices[root], indices[child]);
            if (order >= 0) return;
            const unsigned int temporary = indices[root];
            indices[root] = indices[child];
            indices[child] = temporary;
            root = child;
        }
    }

    template <bool ByName>
    static void HeapSort(ElfCache &cache, unsigned int *indices)
    {
        const unsigned int count = cache.count;
        if (count < 2U) return;
        for (unsigned int start = count / 2U; start > 0U; --start)
            Sift<ByName>(cache, indices, start - 1U, count);
        for (unsigned int end = count; end > 1U; --end) {
            const unsigned int temporary = indices[0];
            indices[0] = indices[end - 1U];
            indices[end - 1U] = temporary;
            Sift<ByName>(cache, indices, 0U, end - 1U);
        }
    }

    long ParseElf(const unsigned char *file,
                  unsigned long size,
                  const char *key,
                  unsigned long source_base,
                  ElfCache &cache)
    {
        cache.used = false;
        cache.count = 0;
        cache.name_used = 0;
        cache.source_base = source_base;
        cache.minimum = ~0UL;
        cache.maximum = 0;
        cache.full_symbols = false;
        detail::Copy(cache.key, sizeof(cache.key), key);
        if (!cache.names) return RTGUM_HOST_ERR_NOMEM;
        if (!file || size < 64UL || !detail::ValidElfHeader(file) ||
            native::ReadU16(file + 16) != 3U)
            return RTGUM_HOST_ERR_INVAL;
        const unsigned long phoff =
            static_cast<unsigned long>(native::ReadU64(file + 32));
        const unsigned int phentsize = native::ReadU16(file + 54);
        const unsigned int phnum = native::ReadU16(file + 56);
        if (phentsize < 56U || phnum == 0U ||
            !detail::RangeValid(phoff,
                                static_cast<unsigned long>(phentsize) * phnum,
                                size))
            return RTGUM_HOST_ERR_INVAL;
        for (unsigned int index = 0; index < phnum; ++index) {
            const unsigned char *program =
                file + phoff + static_cast<unsigned long>(index) * phentsize;
            if (native::ReadU32(program) != 1U) continue;
            const unsigned long vaddr =
                static_cast<unsigned long>(native::ReadU64(program + 16));
            const unsigned long memsz =
                static_cast<unsigned long>(native::ReadU64(program + 40));
            if (memsz == 0 || vaddr > ~0UL - memsz) continue;
            const unsigned long first = detail::AlignDown(vaddr);
            const unsigned long last = detail::AlignUp(vaddr + memsz);
            if (last == 0) return RTGUM_HOST_ERR_INVAL;
            if (first < cache.minimum) cache.minimum = first;
            if (last > cache.maximum) cache.maximum = last;
        }
        if (cache.minimum == ~0UL || cache.maximum <= cache.minimum)
            return RTGUM_HOST_ERR_INVAL;

        const unsigned long shoff =
            static_cast<unsigned long>(native::ReadU64(file + 40));
        const unsigned int shentsize = native::ReadU16(file + 58);
        const unsigned int shnum = native::ReadU16(file + 60);
        if (shentsize < 64U || shnum == 0U ||
            !detail::RangeValid(shoff,
                                static_cast<unsigned long>(shentsize) * shnum,
                                size))
            return RTGUM_HOST_ERR_NOENT;

        int sections[2] = {-1, -1};
        for (unsigned int index = 0; index < shnum; ++index) {
            const unsigned char *section =
                file + shoff + static_cast<unsigned long>(index) * shentsize;
            const unsigned int type = native::ReadU32(section + 4);
            if (type == 2U && sections[0] < 0)
                sections[0] = static_cast<int>(index);
            else if (type == 11U && sections[1] < 0)
                sections[1] = static_cast<int>(index);
        }

        long last_status = RTGUM_HOST_ERR_NOENT;
        for (unsigned int pass = 0; pass < 2U; ++pass) {
            const int selected = sections[pass];
            if (selected < 0) continue;
            cache.count = 0;
            cache.name_used = 0;
            cache.full_symbols = pass == 0U;
            const unsigned char *section =
                file + shoff + static_cast<unsigned long>(selected) * shentsize;
            const unsigned long offset =
                static_cast<unsigned long>(native::ReadU64(section + 24));
            const unsigned long bytes =
                static_cast<unsigned long>(native::ReadU64(section + 32));
            const unsigned int string_index = native::ReadU32(section + 40);
            const unsigned long entry_size =
                static_cast<unsigned long>(native::ReadU64(section + 56));
            if (entry_size != 24UL || string_index >= shnum ||
                !detail::RangeValid(offset, bytes, size)) {
                last_status = RTGUM_HOST_ERR_INVAL;
                continue;
            }
            const unsigned char *strings_section =
                file + shoff + static_cast<unsigned long>(string_index) * shentsize;
            const unsigned long strings_offset =
                static_cast<unsigned long>(native::ReadU64(strings_section + 24));
            const unsigned long strings_size =
                static_cast<unsigned long>(native::ReadU64(strings_section + 32));
            if (!detail::RangeValid(strings_offset, strings_size, size)) {
                last_status = RTGUM_HOST_ERR_INVAL;
                continue;
            }
            const unsigned long symbol_count = bytes / 24UL;
            bool overflow = false;
            for (unsigned long index = 1; index < symbol_count; ++index) {
                const unsigned char *symbol = file + offset + index * 24UL;
                const unsigned int name_offset = native::ReadU32(symbol);
                const unsigned char type = symbol[4] & 0xfU;
                const unsigned int section_index = native::ReadU16(symbol + 6);
                const unsigned long value =
                    static_cast<unsigned long>(native::ReadU64(symbol + 8));
                const unsigned long symbol_size =
                    static_cast<unsigned long>(native::ReadU64(symbol + 16));
                if ((type != 0U && type != 1U && type != 2U && type != 10U) ||
                    section_index == 0U || value == 0 || name_offset >= strings_size)
                    continue;
                const char *name = reinterpret_cast<const char *>(
                    file + strings_offset + name_offset);
                const unsigned long available = strings_size - name_offset;
                const unsigned long name_length = detail::Length(name, available);
                if (name_length == 0 || name_length == available || name[0] == '$')
                    continue;
                if (cache.count >= kMaximumSymbolsPerCache ||
                    name_length + 1UL > kCacheNameBytes - cache.name_used) {
                    overflow = true;
                    break;
                }
                SymbolRecord &record = cache.symbols[cache.count];
                record.value = value;
                record.size = symbol_size > static_cast<unsigned long>(~0U)
                                  ? ~0U
                                  : static_cast<unsigned int>(symbol_size);
                record.name_offset = cache.name_used;
                for (unsigned long character = 0; character <= name_length; ++character)
                    cache.names[cache.name_used + character] = name[character];
                cache.name_used += static_cast<unsigned int>(name_length + 1UL);
                cache.by_name[cache.count] = cache.count;
                cache.by_value[cache.count] = cache.count;
                ++cache.count;
            }
            if (overflow) {
                /* Prefer .symtab, but a bounded cache must not make a large
                 * unstripped system image unusable.  Retry its .dynsym; small
                 * private modules still retain local symbols from .symtab. */
                last_status = RTGUM_HOST_ERR_NOMEM;
                continue;
            }
            if (cache.count == 0U) {
                last_status = RTGUM_HOST_ERR_NOENT;
                continue;
            }
            HeapSort<true>(cache, cache.by_name);
            HeapSort<false>(cache, cache.by_value);
            cache.used = true;
            cache.last_use = generation_++;
            return 0;
        }
        return last_status;
    }

    ElfCache *FindCache(const char *key, unsigned long source_base)
    {
        for (unsigned int index = 0; index < kMaximumCaches; ++index) {
            ElfCache *cache = caches_[index];
            if (cache && cache->used && cache->source_base == source_base &&
                detail::Equal(cache->key, key)) {
                cache->last_use = generation_++;
                return cache;
            }
        }
        return nullptr;
    }

    ElfCache *ClaimCache(long &status)
    {
        status = 0;
        unsigned int selected = 0;
        unsigned long oldest = ~0UL;
        for (unsigned int index = 0; index < kMaximumCaches; ++index) {
            if (!caches_[index]) {
                if (!ops_.allocate_cache) {
                    status = RTGUM_HOST_ERR_NOTSUP;
                    return nullptr;
                }
                unsigned long address = 0;
                status = ops_.allocate_cache(sizeof(ElfCache), &address);
                if (status != 0 || address == 0) {
                    if (status == 0) status = RTGUM_HOST_ERR_NOMEM;
                    return nullptr;
                }
                unsigned long names = 0;
                status = ops_.allocate_cache(kCacheNameBytes, &names);
                if (status != 0 || names == 0) {
                    if (ops_.release_cache) (void)ops_.release_cache(address);
                    if (status == 0) status = RTGUM_HOST_ERR_NOMEM;
                    return nullptr;
                }
                ElfCache *cache = reinterpret_cast<ElfCache *>(address);
                cache->used = false;
                cache->names = reinterpret_cast<char *>(names);
                caches_[index] = cache;
                return cache;
            }
            if (!caches_[index]->used) return caches_[index];
            if (caches_[index]->last_use < oldest) {
                oldest = caches_[index]->last_use;
                selected = index;
            }
        }
        caches_[selected]->used = false;
        return caches_[selected];
    }

    long LoadFile(const char *path,
                  const char *key,
                  unsigned long source_base,
                  ElfCache *&out_cache,
                  bool ghost)
    {
        out_cache = FindCache(key, source_base);
        if (out_cache) return 0;
        if (!ops_.map_rw || !ops_.unmap) return RTGUM_HOST_ERR_NOTSUP;
        unsigned long size = 0;
        long descriptor = -1;
        if (ghost) {
            if (!ops_.ghost_file_size || !ops_.ghost_file_copy)
                return RTGUM_HOST_ERR_NOTSUP;
            const long size_status = ops_.ghost_file_size(source_base, &size);
            if (size_status != 0) return size_status;
        } else {
            if (!ops_.open_read || !ops_.read || !ops_.seek || !ops_.close)
                return RTGUM_HOST_ERR_NOTSUP;
            descriptor = ops_.open_read(path);
            if (descriptor < 0) return descriptor;
            const long end = ops_.seek(descriptor, 0, 2);
            if (end <= 0) {
                ops_.close(descriptor);
                return end < 0 ? end : RTGUM_HOST_ERR_NOENT;
            }
            size = static_cast<unsigned long>(end);
            if (ops_.seek(descriptor, 0, 0) < 0) {
                ops_.close(descriptor);
                return RTGUM_HOST_ERR_NOENT;
            }
        }
        if (size == 0 || size > kMaximumElfBytes) {
            if (descriptor >= 0) ops_.close(descriptor);
            return RTGUM_HOST_ERR_NOTSUP;
        }
        const unsigned long mapped_size = detail::AlignUp(size);
        const long mapped = ops_.map_rw(mapped_size);
        if (mapped <= 0) {
            if (descriptor >= 0) ops_.close(descriptor);
            return mapped < 0 ? mapped : RTGUM_HOST_ERR_NOMEM;
        }
        auto *buffer = reinterpret_cast<unsigned char *>(
            static_cast<unsigned long>(mapped));
        long status = 0;
        if (ghost) {
            status = ops_.ghost_file_copy(source_base, buffer, size);
        } else {
            unsigned long total = 0;
            while (total < size) {
                const long read = ops_.read(descriptor, buffer + total, size - total);
                if (read <= 0) {
                    status = read < 0 ? read : RTGUM_HOST_ERR_NOENT;
                    break;
                }
                total += static_cast<unsigned long>(read);
            }
            ops_.close(descriptor);
        }
        long cache_status = 0;
        ElfCache *cache = ClaimCache(cache_status);
        if (!cache) {
            ops_.unmap(static_cast<unsigned long>(mapped), mapped_size);
            return cache_status;
        }
        if (status == 0)
            status = ParseElf(buffer, size, key, source_base, *cache);
        ops_.unmap(static_cast<unsigned long>(mapped), mapped_size);
        if (status != 0) {
            cache->used = false;
            return status;
        }
        out_cache = cache;
        return 0;
    }

    bool BuildPath(char *out,
                   unsigned long capacity,
                   const char *prefix,
                   const char *soname) const
    {
        if (!out || capacity == 0 || !prefix || !soname) return false;
        unsigned long cursor = 0;
        out[0] = '\0';
        return detail::Append(out, capacity, cursor, prefix) &&
               detail::Append(out, capacity, cursor, soname);
    }

    long EnsureDiskCache(const char *soname, ElfCache *&cache)
    {
        cache = FindCache(soname, 0);
        if (cache) return 0;
        char path[256];
        /* The executable Android linker advertises DT_SONAME=ld-android.so,
         * while the file containing its local/hidden .symtab is named
         * .../bin/linker64.  Library-directory probing can therefore never
         * reach symbols such as soinfo::call_constructors().  Keep this
         * explicit alias ahead of the ordinary SONAME search; the parsed cache
         * is still keyed by the mapped image's SONAME so load-bias validation
         * in FindExportLocked remains unchanged. */
        if (detail::Equal(soname, "ld-android.so") ||
            detail::Equal(soname, "linker64")) {
            static constexpr const char *kLinkerPaths[] = {
                "/apex/com.android.runtime/bin/linker64",
                "/system/bin/linker64",
            };
            for (const char *linker_path : kLinkerPaths) {
                if (LoadFile(linker_path, soname, 0, cache, false) == 0)
                    return 0;
            }
        }
        if (package_[0] != '\0') {
            unsigned long cursor = 0;
            path[0] = '\0';
            if (detail::Append(path, sizeof(path), cursor, "/data/data/") &&
                detail::Append(path, sizeof(path), cursor, package_) &&
                detail::Append(path, sizeof(path), cursor, "/code_cache/") &&
                detail::Append(path, sizeof(path), cursor, soname)) {
                if (LoadFile(path, soname, 0, cache, false) == 0) return 0;
            }
        }
        static constexpr const char *kPrefixes[] = {
            "/apex/com.android.runtime/lib64/bionic/",
            "/apex/com.android.art/lib64/",
            "/apex/com.android.i18n/lib64/",
            "/system/lib64/",
            "/system_ext/lib64/",
            "/product/lib64/",
            "/vendor/lib64/",
            "/odm/lib64/",
        };
        for (const char *prefix : kPrefixes) {
            if (!BuildPath(path, sizeof(path), prefix, soname)) continue;
            if (LoadFile(path, soname, 0, cache, false) == 0) return 0;
        }
        return RTGUM_HOST_ERR_NOENT;
    }

    long EnsureGhostCache(const GhostImage &image, ElfCache *&cache)
    {
        const long status = LoadFile(image.path, image.soname, image.base,
                                     cache, true);
        if (status == 0 && cache) {
            /* The private loader maps [minimum, maximum) at image.base. */
            if (cache->maximum <= cache->minimum ||
                cache->maximum - cache->minimum > image.mapped_size)
                return RTGUM_HOST_ERR_INVAL;
        }
        return status;
    }

    static long CacheLookupExact(ElfCache &cache,
                                 const char *name,
                                 unsigned long &value)
    {
        value = 0;
        unsigned int low = 0;
        unsigned int high = cache.count;
        while (low < high) {
            const unsigned int middle = low + (high - low) / 2U;
            const SymbolRecord &record = cache.symbols[cache.by_name[middle]];
            const int order = detail::Compare(cache.names + record.name_offset, name);
            if (order < 0)
                low = middle + 1U;
            else
                high = middle;
        }
        if (low >= cache.count) return RTGUM_HOST_ERR_NOENT;
        const SymbolRecord &record = cache.symbols[cache.by_name[low]];
        if (!detail::Equal(cache.names + record.name_offset, name))
            return RTGUM_HOST_ERR_NOENT;
        value = record.value;
        return value == 0 ? RTGUM_HOST_ERR_NOENT : 0;
    }

    static long CacheLookupNearest(ElfCache &cache,
                                   unsigned long relative,
                                   char *name,
                                   unsigned long name_capacity,
                                   unsigned long &value)
    {
        value = 0;
        unsigned int low = 0;
        unsigned int high = cache.count;
        while (low < high) {
            const unsigned int middle = low + (high - low) / 2U;
            const SymbolRecord &record = cache.symbols[cache.by_value[middle]];
            if (record.value <= relative)
                low = middle + 1U;
            else
                high = middle;
        }
        if (low == 0U) return RTGUM_HOST_ERR_NOENT;
        const SymbolRecord &record = cache.symbols[cache.by_value[low - 1U]];
        value = record.value;
        detail::Copy(name, name_capacity, cache.names + record.name_offset);
        return value == 0 ? RTGUM_HOST_ERR_NOENT : 0;
    }

    long FindExportLocked(const char *soname,
                          const char *symbol,
                          unsigned long *out_address)
    {
        detail::Copy(debug_request_, sizeof(debug_request_), soname);
        detail::Copy(debug_stage_, sizeof(debug_stage_), "no-image");
        for (unsigned int index = 0; index < kMaximumGhostImages; ++index) {
            const GhostImage &image = ghosts_[index];
            if (!image.used || !detail::Equal(image.soname, soname)) continue;
            detail::Copy(debug_stage_, sizeof(debug_stage_), "ghost-match");
            ElfCache *cache = nullptr;
            const long loaded = EnsureGhostCache(image, cache);
            if (loaded != 0) {
                detail::Copy(debug_stage_, sizeof(debug_stage_), "ghost-cache-failed");
                return loaded;
            }
            unsigned long value = 0;
            const long found = CacheLookupExact(*cache, symbol, value);
            if (found != 0) {
                detail::Copy(debug_stage_, sizeof(debug_stage_), "ghost-symbol-miss");
                return found;
            }
            if (value < cache->minimum || value >= cache->maximum)
                return RTGUM_HOST_ERR_NOENT;
            *out_address = image.base + (value - cache->minimum);
            detail::Copy(debug_stage_, sizeof(debug_stage_), "ghost-hit");
            return *out_address == 0 ? RTGUM_HOST_ERR_NOENT : 0;
        }
        DynamicImage image{};
        if (FindMappedImageByName(soname, image) != 0)
            return RTGUM_HOST_ERR_NOENT;
        detail::Copy(debug_stage_, sizeof(debug_stage_), "mapped-match");
        unsigned long value = 0;
        const long mapped = MappedLookupExact(image, symbol, value);
        if (mapped == 0) {
            if (value < image.minimum || value >= image.maximum) {
                detail::Copy(debug_stage_, sizeof(debug_stage_), "mapped-range-reject");
                return RTGUM_HOST_ERR_NOENT;
            }
            *out_address = image.load_bias + value;
            detail::Copy(debug_stage_, sizeof(debug_stage_), "mapped-hit");
            return *out_address == 0 ? RTGUM_HOST_ERR_NOENT : 0;
        }

        /* Exported symbols come directly from the mapped .dynsym.  Only an
         * actual dynamic miss opens the on-disk ELF and consults its preferred
         * full table.  Besides matching linker semantics, this keeps ordinary
         * Zygote bootstrap lookups from allocating a large ghost cache that
         * every subsequent child would inherit. */
        ElfCache *cache = nullptr;
        if (EnsureDiskCache(soname, cache) == 0 && cache &&
            CacheLookupExact(*cache, symbol, value) == 0) {
            if (value >= image.minimum && value < image.maximum) {
                *out_address = image.load_bias + value;
                detail::Copy(debug_stage_, sizeof(debug_stage_), "disk-hit");
                return 0;
            }
        }
        detail::Copy(debug_stage_, sizeof(debug_stage_), "mapped-symbol-miss");
        return mapped;
    }

    long SymbolizeLocked(unsigned long pc, ResolvedSymbol &resolved)
    {
        for (unsigned int index = 0; index < kMaximumGhostImages; ++index) {
            const GhostImage &image = ghosts_[index];
            if (!image.used || pc < image.base || pc - image.base >= image.mapped_size)
                continue;
            ElfCache *cache = nullptr;
            const long loaded = EnsureGhostCache(image, cache);
            if (loaded != 0) return loaded;
            const unsigned long relative = pc - image.base + cache->minimum;
            unsigned long value = 0;
            const long found = CacheLookupNearest(*cache, relative,
                                                  resolved.symbol,
                                                  sizeof(resolved.symbol), value);
            if (found != 0) return found;
            detail::Copy(resolved.module, sizeof(resolved.module), image.soname);
            resolved.address = image.base + (value - cache->minimum);
            resolved.offset = relative - value;
            resolved.ghost = true;
            return 0;
        }
        DynamicImage image{};
        if (FindMappedImageForPc(pc, image) != 0)
            return RTGUM_HOST_ERR_NOENT;
        const unsigned long relative = pc - image.load_bias;
        unsigned long value = 0;
        ElfCache *cache = nullptr;
        long found = RTGUM_HOST_ERR_NOENT;
        if (EnsureDiskCache(image.soname, cache) == 0 && cache) {
            found = CacheLookupNearest(*cache, relative,
                                       resolved.symbol,
                                       sizeof(resolved.symbol), value);
        }
        if (found != 0) {
            found = MappedLookupNearest(image, relative,
                                        resolved.symbol,
                                        sizeof(resolved.symbol), value);
        }
        if (found != 0) return found;
        detail::Copy(resolved.module, sizeof(resolved.module), image.soname);
        resolved.address = image.load_bias + value;
        resolved.offset = relative - value;
        resolved.ghost = false;
        return 0;
    }

    ResolverOps ops_{};
    volatile bool locked_ = false;
    unsigned long generation_ = 1;
    char package_[64]{};
    VmaRange vmas_[kMaximumVmas]{};
    unsigned int vma_count_ = 0;
    DynamicImage images_[kMaximumMappedImages]{};
    unsigned int image_count_ = 0;
    unsigned int image_victim_ = 0;
    GhostImage ghosts_[kMaximumGhostImages]{};
    ElfCache *caches_[kMaximumCaches]{};
    char debug_stage_[48]{};
    char debug_request_[96]{};
};

} // namespace symbols
} // namespace rtgum
