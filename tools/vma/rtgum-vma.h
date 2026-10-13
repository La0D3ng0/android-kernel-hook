#ifndef RTGUM_TOOLS_VMA_H
#define RTGUM_TOOLS_VMA_H

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <elf.h>
#include <memory>
#include <string>
#include <sys/stat.h>
#include <unordered_map>
#include <utility>
#include <vector>

namespace rtgum::vma {

struct Range final {
    std::uint64_t start = 0;
    std::uint64_t end = 0;

    bool contains(std::uint64_t address) const
    {
        return address >= start && address < end;
    }
};

struct Snapshot final {
    long pid = -1;
    bool ghost_excluded = false;
    std::vector<Range> ranges;

    const Range *find(std::uint64_t address) const
    {
        const auto it = std::upper_bound(
            ranges.begin(), ranges.end(), address,
            [](std::uint64_t value, const Range &range) { return value < range.start; });
        if (it == ranges.begin()) return nullptr;
        const Range &candidate = *(it - 1);
        return candidate.contains(address) ? &candidate : nullptr;
    }
};

inline bool ParseDecimalField(const char *line, const char *field,
                              unsigned long long &value)
{
    const char *at = std::strstr(line, field);
    if (!at) return false;
    at += std::strlen(field);
    char *end = nullptr;
    value = std::strtoull(at, &end, 10);
    return end != at;
}

inline bool ParseSnapshot(const char *text, Snapshot &snapshot, std::string &error)
{
    snapshot = {};
    if (!text || std::strncmp(text, "ok vma-dump=1 ", 14) != 0) {
        error = "kernel response is not a VMA snapshot";
        return false;
    }
    const char *header_end = std::strchr(text, '\n');
    if (!header_end) {
        error = "VMA snapshot header is unterminated";
        return false;
    }
    std::string header(text, static_cast<std::size_t>(header_end - text));
    unsigned long long pid = 0;
    unsigned long long count = 0;
    if (!ParseDecimalField(header.c_str(), "pid=", pid) ||
        !ParseDecimalField(header.c_str(), "count=", count) ||
        count > 65536ULL) {
        error = "VMA snapshot header fields are invalid";
        return false;
    }
    snapshot.pid = static_cast<long>(pid);
    snapshot.ghost_excluded =
        header.find("ghost=excluded-vmaless") != std::string::npos;

    const char *line = header_end + 1;
    snapshot.ranges.reserve(static_cast<std::size_t>(count));
    while (*line != '\0') {
        const char *newline = std::strchr(line, '\n');
        const char *line_end = newline ? newline : line + std::strlen(line);
        if (line_end != line) {
            unsigned long long start = 0;
            unsigned long long end = 0;
            int consumed = 0;
            if (std::sscanf(line, "vma %llx-%llx%n", &start, &end, &consumed) != 2 ||
                line + consumed != line_end || start >= end) {
                error = "malformed VMA record";
                return false;
            }
            snapshot.ranges.push_back({start, end});
        }
        if (!newline) break;
        line = newline + 1;
    }
    if (snapshot.ranges.size() != static_cast<std::size_t>(count)) {
        error = "VMA record count does not match the header";
        return false;
    }
    std::sort(snapshot.ranges.begin(), snapshot.ranges.end(),
              [](const Range &left, const Range &right) {
                  return left.start < right.start ||
                         (left.start == right.start && left.end < right.end);
              });
    for (std::size_t index = 1; index < snapshot.ranges.size(); ++index) {
        if (snapshot.ranges[index - 1].end > snapshot.ranges[index].start) {
            error = "overlapping VMA records";
            return false;
        }
    }
    if (!snapshot.ghost_excluded) {
        error = "kernel did not declare the VMA-less ghost exclusion contract";
        return false;
    }
    return true;
}

class PerPidCache final {
public:
    bool update(const char *text, std::string &error)
    {
        Snapshot snapshot;
        if (!ParseSnapshot(text, snapshot, error)) return false;
        snapshots_[snapshot.pid] = std::move(snapshot);
        return true;
    }

    const Snapshot *get(long pid) const
    {
        const auto found = snapshots_.find(pid);
        return found == snapshots_.end() ? nullptr : &found->second;
    }

    void invalidate(long pid) { snapshots_.erase(pid); }

private:
    std::unordered_map<long, Snapshot> snapshots_;
};

struct Symbolized final {
    std::string module;
    std::string symbol;
    std::uint64_t offset = 0;
    std::uint64_t load_bias = 0;
    Range vma;
};

class ElfImage final {
public:
    bool load(const char *path, std::string &error)
    {
        path_ = path ? path : "";
        if (path_.empty()) {
            error = "ELF path is empty";
            return false;
        }
        struct stat metadata {};
        if (::stat(path_.c_str(), &metadata) != 0 || metadata.st_size <= 0 ||
            metadata.st_size > 128LL * 1024LL * 1024LL) {
            error = "ELF file size is invalid";
            return false;
        }
        std::FILE *file = std::fopen(path_.c_str(), "rb");
        if (!file) {
            error = "cannot open ELF file";
            return false;
        }
        bytes_.resize(static_cast<std::size_t>(metadata.st_size));
        const std::size_t got = std::fread(bytes_.data(), 1, bytes_.size(), file);
        std::fclose(file);
        if (got != bytes_.size()) {
            error = "short ELF file read";
            return false;
        }
        if (!range_valid(0, sizeof(Elf64_Ehdr))) {
            error = "ELF header is truncated";
            return false;
        }
        header_ = reinterpret_cast<const Elf64_Ehdr *>(bytes_.data());
        if (std::memcmp(header_->e_ident, ELFMAG, SELFMAG) != 0 ||
            header_->e_ident[EI_CLASS] != ELFCLASS64 ||
            header_->e_ident[EI_DATA] != ELFDATA2LSB ||
            header_->e_machine != EM_AARCH64 ||
            header_->e_phentsize != sizeof(Elf64_Phdr)) {
            error = "file is not a little-endian AArch64 ELF64 image";
            return false;
        }
        if (!range_valid(header_->e_phoff,
                         static_cast<std::uint64_t>(header_->e_phnum) *
                             sizeof(Elf64_Phdr))) {
            error = "ELF program headers are invalid";
            return false;
        }
        const auto *programs = reinterpret_cast<const Elf64_Phdr *>(
            bytes_.data() + header_->e_phoff);
        for (unsigned int index = 0; index < header_->e_phnum; ++index) {
            const Elf64_Phdr &program = programs[index];
            if (program.p_type != PT_LOAD || program.p_memsz == 0) continue;
            if (program.p_vaddr + program.p_memsz < program.p_vaddr) {
                error = "ELF PT_LOAD overflows";
                return false;
            }
            loads_.push_back({program.p_vaddr, program.p_memsz, program.p_flags});
        }
        if (loads_.empty()) {
            error = "ELF has no PT_LOAD segments";
            return false;
        }
        if (header_->e_shnum != 0) {
            if (header_->e_shentsize != sizeof(Elf64_Shdr) ||
                !range_valid(header_->e_shoff,
                             static_cast<std::uint64_t>(header_->e_shnum) *
                                 sizeof(Elf64_Shdr))) {
                error = "ELF section headers are invalid";
                return false;
            }
            const auto *sections = reinterpret_cast<const Elf64_Shdr *>(
                bytes_.data() + header_->e_shoff);
            for (unsigned int index = 0; index < header_->e_shnum; ++index) {
                const Elf64_Shdr &section = sections[index];
                if (section.sh_type != SHT_SYMTAB && section.sh_type != SHT_DYNSYM)
                    continue;
                if (section.sh_entsize != sizeof(Elf64_Sym) ||
                    section.sh_link >= header_->e_shnum ||
                    !range_valid(section.sh_offset, section.sh_size))
                    continue;
                const Elf64_Shdr &strings = sections[section.sh_link];
                if (strings.sh_type != SHT_STRTAB ||
                    !range_valid(strings.sh_offset, strings.sh_size))
                    continue;
                const char *names = reinterpret_cast<const char *>(
                    bytes_.data() + strings.sh_offset);
                const auto *table = reinterpret_cast<const Elf64_Sym *>(
                    bytes_.data() + section.sh_offset);
                const std::size_t count =
                    static_cast<std::size_t>(section.sh_size / sizeof(Elf64_Sym));
                for (std::size_t symbol_index = 0; symbol_index < count; ++symbol_index) {
                    const Elf64_Sym &symbol = table[symbol_index];
                    const unsigned int type = ELF64_ST_TYPE(symbol.st_info);
                    if ((type != STT_FUNC && type != STT_GNU_IFUNC) ||
                        symbol.st_shndx == SHN_UNDEF || symbol.st_value == 0 ||
                        symbol.st_name >= strings.sh_size)
                        continue;
                    const char *name = names + symbol.st_name;
                    const std::size_t remaining =
                        static_cast<std::size_t>(strings.sh_size - symbol.st_name);
                    if (!std::memchr(name, '\0', remaining) || name[0] == '\0') continue;
                    symbols_.push_back(
                        {symbol.st_value, symbol.st_size, std::string(name)});
                }
            }
        }
        if (symbols_.empty()) {
            error = "ELF contains no function symbols";
            return false;
        }
        std::sort(symbols_.begin(), symbols_.end(),
                  [](const Symbol &left, const Symbol &right) {
                      if (left.value != right.value) return left.value < right.value;
                      if (left.size != right.size) return left.size > right.size;
                      return left.name < right.name;
                  });
        module_ = basename(path_);
        return true;
    }

    bool symbolize(const Snapshot &snapshot, std::uint64_t pc,
                   Symbolized &result, std::string &error) const
    {
        const Range *pc_vma = snapshot.find(pc);
        if (!pc_vma) {
            error = "PC is outside the cached VMA snapshot";
            return false;
        }
        std::uint64_t best_bias = 0;
        unsigned int best_score = 0;
        bool found_bias = false;
        for (const Load &executable : loads_) {
            if ((executable.flags & PF_X) == 0) continue;
            const std::uint64_t segment_page = page_down(executable.vaddr);
            if (pc_vma->start < segment_page) continue;
            const std::uint64_t bias = pc_vma->start - segment_page;
            if (pc < bias) continue;
            const std::uint64_t relative = pc - bias;
            if (relative < executable.vaddr ||
                relative >= executable.vaddr + executable.memsz)
                continue;
            unsigned int score = snapshot.find(bias) ? 1U : 0U;
            for (const Load &load : loads_) {
                const std::uint64_t first = bias + page_down(load.vaddr);
                const std::uint64_t last = bias + page_up(load.vaddr + load.memsz);
                if (last > first && snapshot.find(first) && snapshot.find(last - 1U))
                    ++score;
            }
            if (!found_bias || score > best_score) {
                found_bias = true;
                best_bias = bias;
                best_score = score;
            }
        }
        if (!found_bias || pc < best_bias) {
            error = "no executable PT_LOAD matches the PC VMA";
            return false;
        }
        const std::uint64_t relative = pc - best_bias;
        const Symbol *best = nullptr;
        for (const Symbol &symbol : symbols_) {
            if (symbol.value > relative) break;
            if (!best || symbol.value > best->value ||
                (symbol.value == best->value && symbol.size > best->size))
                best = &symbol;
        }
        if (!best) {
            error = "no function symbol precedes the relative PC";
            return false;
        }
        result.module = module_;
        result.symbol = best->name;
        result.offset = relative - best->value;
        result.load_bias = best_bias;
        result.vma = *pc_vma;
        return true;
    }

    const unsigned char *header_prefix(std::size_t &length) const
    {
        length = bytes_.size() < 64U ? bytes_.size() : 64U;
        return bytes_.data();
    }

private:
    struct Load final {
        std::uint64_t vaddr;
        std::uint64_t memsz;
        std::uint32_t flags;
    };
    struct Symbol final {
        std::uint64_t value;
        std::uint64_t size;
        std::string name;
    };

    static constexpr std::uint64_t kPageSize = 4096ULL;
    static std::uint64_t page_down(std::uint64_t value)
    {
        return value & ~(kPageSize - 1ULL);
    }
    static std::uint64_t page_up(std::uint64_t value)
    {
        return (value + kPageSize - 1ULL) & ~(kPageSize - 1ULL);
    }
    bool range_valid(std::uint64_t offset, std::uint64_t size) const
    {
        return offset <= bytes_.size() && size <= bytes_.size() - offset;
    }
    static std::string basename(const std::string &path)
    {
        const std::size_t slash = path.find_last_of("/\\");
        return slash == std::string::npos ? path : path.substr(slash + 1U);
    }

    std::string path_;
    std::string module_;
    std::vector<unsigned char> bytes_;
    const Elf64_Ehdr *header_ = nullptr;
    std::vector<Load> loads_;
    std::vector<Symbol> symbols_;
};

class ElfCache final {
public:
    const ElfImage *get(const char *path, bool &cache_hit, std::string &error)
    {
        const std::string key = path ? path : "";
        const auto found = images_.find(key);
        if (found != images_.end()) {
            cache_hit = true;
            return found->second.get();
        }
        cache_hit = false;
        auto image = std::make_unique<ElfImage>();
        if (!image->load(path, error)) return nullptr;
        const ElfImage *result = image.get();
        images_.emplace(key, std::move(image));
        return result;
    }

private:
    std::unordered_map<std::string, std::unique_ptr<ElfImage>> images_;
};

} // namespace rtgum::vma

#endif
