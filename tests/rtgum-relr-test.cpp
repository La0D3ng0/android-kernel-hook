/*
 * Apply compiler-generated DT_RELR to a writable image copy.
 * Packed APS2 stays -ENOTSUP. Does not hide mappings.
 */

#include "rtgum/elf_namespace.hpp"
#include "rtgum/elf_relr.hpp"
#include "rtgum/elf_symbols.hpp"
#include "rtgum/host_api_v2.h"
#include "rtgum/native_backend.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace {

constexpr unsigned long kPtLoad = 1UL;
constexpr unsigned long kPtDynamic = 2UL;
constexpr unsigned long kDtNull = 0UL;
constexpr unsigned long kDtNeeded = 1UL;
constexpr unsigned long kLoadBias = 0x10000000UL;

int Fail(const char *message)
{
    std::fprintf(stderr, "%s\n", message);
    return 1;
}

const unsigned char *FileAt(const unsigned char *file,
                            unsigned long file_size,
                            unsigned long offset,
                            unsigned long length)
{
    if (offset > file_size || length > file_size - offset) return nullptr;
    return file + offset;
}

}  // namespace

int main(int argc, char **argv)
{
    if (argc != 2) return Fail("usage: rtgum-relr-test <librtgum-relr-sample.so>");
    const int fd = open(argv[1], O_RDONLY | O_CLOEXEC);
    if (fd < 0) return Fail("open sample failed");
    struct stat info {};
    if (fstat(fd, &info) != 0 || info.st_size <= 0) {
        close(fd);
        return Fail("fstat sample failed");
    }
    const auto file_size = static_cast<unsigned long>(info.st_size);
    void *map = mmap(nullptr, static_cast<size_t>(file_size), PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (map == MAP_FAILED) return Fail("mmap sample failed");
    const auto *file = static_cast<const unsigned char *>(map);

    if (file_size < 64UL || file[0] != 0x7f || file[1] != 'E' || file[2] != 'L' ||
        file[3] != 'F' || file[4] != 2 || file[5] != 1) {
        munmap(map, static_cast<size_t>(file_size));
        return Fail("sample is not ELF64 LE");
    }
    const unsigned long phoff = rtgum::native::ReadU64(file + 32);
    const unsigned int phentsize = rtgum::native::ReadU16(file + 54);
    const unsigned int phnum = rtgum::native::ReadU16(file + 56);
    if (phentsize < 56U || phnum == 0U) {
        munmap(map, static_cast<size_t>(file_size));
        return Fail("program headers missing");
    }

    unsigned long image_size = 0;
    unsigned long dyn_file = 0;
    unsigned long dyn_size = 0;
    for (unsigned int index = 0; index < phnum; ++index) {
        const unsigned char *ph = FileAt(file, file_size, phoff + index * phentsize, phentsize);
        if (!ph) {
            munmap(map, static_cast<size_t>(file_size));
            return Fail("program header out of range");
        }
        const unsigned int type = rtgum::native::ReadU32(ph);
        const unsigned long offset = rtgum::native::ReadU64(ph + 8);
        const unsigned long vaddr = rtgum::native::ReadU64(ph + 16);
        const unsigned long filesz = rtgum::native::ReadU64(ph + 32);
        const unsigned long memsz = rtgum::native::ReadU64(ph + 40);
        if (type == kPtLoad) {
            const unsigned long end = vaddr + memsz;
            if (end > image_size) image_size = end;
        } else if (type == kPtDynamic) {
            dyn_file = offset;
            dyn_size = filesz;
        }
        (void)vaddr;
    }
    if (image_size < 16UL || dyn_size < 16UL) {
        munmap(map, static_cast<size_t>(file_size));
        return Fail("PT_LOAD/PT_DYNAMIC missing");
    }

    const unsigned char *dynamic = FileAt(file, file_size, dyn_file, dyn_size);
    if (!dynamic) {
        munmap(map, static_cast<size_t>(file_size));
        return Fail("dynamic out of range");
    }
    unsigned long relr_vaddr = 0;
    unsigned long relr_size = 0;
    rtgum::native::DynamicRelocKind kind{};
    for (unsigned long offset = 0; offset + 16UL <= dyn_size; offset += 16UL) {
        const unsigned long tag = rtgum::native::ReadU64(dynamic + offset);
        const unsigned long value = rtgum::native::ReadU64(dynamic + offset + 8);
        if (tag == kDtNull) break;
        rtgum::native::ClassifyDynamicTag(tag, &kind);
        if (tag == rtgum::native::kDtRelr || tag == 0x6fffe000UL) relr_vaddr = value;
        if (tag == rtgum::native::kDtRelrSize || tag == 0x6fffe001UL) relr_size = value;
        (void)kDtNeeded;
    }
    if (kind.android_packed) {
        munmap(map, static_cast<size_t>(file_size));
        std::puts("relr packed=APS2 notsup=1");
        std::puts("jnicode-relr PASS");
        return 0;
    }
    if ((!kind.relr && !kind.android_relr) || relr_vaddr == 0 || relr_size == 0) {
        munmap(map, static_cast<size_t>(file_size));
        return Fail("sample has no DT_RELR/ANDROID_RELR");
    }

    unsigned long relr_file = 0;
    bool relr_mapped = false;
    for (unsigned int index = 0; index < phnum; ++index) {
        const unsigned char *ph = file + phoff + index * phentsize;
        if (rtgum::native::ReadU32(ph) != kPtLoad) continue;
        const unsigned long offset = rtgum::native::ReadU64(ph + 8);
        const unsigned long vaddr = rtgum::native::ReadU64(ph + 16);
        const unsigned long filesz = rtgum::native::ReadU64(ph + 32);
        if (relr_vaddr >= vaddr && relr_vaddr + relr_size <= vaddr + filesz) {
            relr_file = offset + (relr_vaddr - vaddr);
            relr_mapped = true;
            break;
        }
    }
    const unsigned char *relr = relr_mapped ? FileAt(file, file_size, relr_file, relr_size) : nullptr;
    if (!relr) {
        munmap(map, static_cast<size_t>(file_size));
        return Fail("DT_RELR is not file-backed");
    }
    if (rtgum::native::LooksLikeAps2(relr, relr_size)) {
        munmap(map, static_cast<size_t>(file_size));
        std::puts("relr table=APS2 notsup=1");
        std::puts("jnicode-relr PASS");
        return 0;
    }

    std::vector<unsigned char> image(static_cast<std::size_t>(image_size), 0);
    for (unsigned int index = 0; index < phnum; ++index) {
        const unsigned char *ph = file + phoff + index * phentsize;
        if (rtgum::native::ReadU32(ph) != kPtLoad) continue;
        const unsigned long offset = rtgum::native::ReadU64(ph + 8);
        const unsigned long vaddr = rtgum::native::ReadU64(ph + 16);
        const unsigned long filesz = rtgum::native::ReadU64(ph + 32);
        const unsigned char *src = FileAt(file, file_size, offset, filesz);
        if (!src || vaddr + filesz > image_size) {
            munmap(map, static_cast<size_t>(file_size));
            return Fail("PT_LOAD copy failed");
        }
        std::memcpy(image.data() + vaddr, src, static_cast<std::size_t>(filesz));
    }

    const unsigned long first_offset = rtgum::native::ReadU64(relr);
    if ((first_offset & 1UL) != 0UL || first_offset + 8UL > image_size) {
        munmap(map, static_cast<size_t>(file_size));
        return Fail("first RELR entry is not a valid offset");
    }
    const unsigned long before = rtgum::native::ReadU64(image.data() + first_offset);
    const long applied =
        rtgum::native::ApplyRelr(image.data(), image_size, relr, relr_size, kLoadBias);
    if (applied != 0) {
        munmap(map, static_cast<size_t>(file_size));
        std::fprintf(stderr, "ApplyRelr rc=%ld\n", applied);
        return 1;
    }
    const unsigned long after = rtgum::native::ReadU64(image.data() + first_offset);
    if (after != before + kLoadBias) {
        munmap(map, static_cast<size_t>(file_size));
        std::fprintf(stderr, "relocated word=0x%lx before=0x%lx\n", after, before);
        return 1;
    }

    rtgum::native::NamespaceTable table{};
    table.Reset();
    if (table.Register("librtgum-relr-sample.so", argv[1]) != 0)
        return Fail("namespace register failed");
    if (table.Register("librtgum-relr-sample.so", "/system/lib64/librtgum-relr-sample.so") !=
        RTGUM_HOST_ERR_NOTSUP) {
        munmap(map, static_cast<size_t>(file_size));
        return Fail("duplicate SONAME should be NOTSUP");
    }

    munmap(map, static_cast<size_t>(file_size));
    std::printf("relr size=%lu tag=%s offset=0x%lx applied=1 ns=1\n",
                relr_size, kind.android_relr ? "ANDROID_RELR" : "DT_RELR", first_offset);
    std::puts("jnicode-relr PASS");
    return 0;
}
