#include "rtgum/elf_image.hpp"

#include <cstring>
#include <limits>

namespace rtgum {
namespace {

constexpr std::size_t kElf64HeaderSize = 64;
constexpr std::uint8_t kElfClass64 = 2;
constexpr std::uint8_t kElfDataLittleEndian = 1;
constexpr std::uint32_t kElfVersionCurrent = 1;

template <typename T>
T ReadLittleEndian(const std::uint8_t* bytes) noexcept {
    T value = 0;
    for (std::size_t index = 0; index < sizeof(T); ++index) {
        value |= static_cast<T>(bytes[index]) << (index * 8U);
    }
    return value;
}

bool RangeFits(std::uint64_t offset, std::uint64_t count, std::uint64_t item_size,
               std::size_t image_size) noexcept {
    if (item_size != 0 && count > std::numeric_limits<std::uint64_t>::max() / item_size) {
        return false;
    }
    const std::uint64_t byte_count = count * item_size;
    if (offset > std::numeric_limits<std::uint64_t>::max() - byte_count) {
        return false;
    }
    return offset + byte_count <= static_cast<std::uint64_t>(image_size);
}

}  // namespace

ElfImageView::ElfImageView(const void* data, std::size_t size) noexcept
    : data_(static_cast<const std::uint8_t*>(data)), size_(size) {}

Status ElfImageView::Validate64LittleEndian(ElfImageInfo* output) const {
    if (output == nullptr) {
        return {StatusCode::kInvalidArgument, "output must not be null"};
    }
    if (data_ == nullptr || size_ < kElf64HeaderSize) {
        return {StatusCode::kIntegrityError, "ELF header is truncated"};
    }

    constexpr std::uint8_t magic[] = {0x7f, 'E', 'L', 'F'};
    if (std::memcmp(data_, magic, sizeof(magic)) != 0) {
        return {StatusCode::kIntegrityError, "ELF magic is invalid"};
    }
    if (data_[4] != kElfClass64 || data_[5] != kElfDataLittleEndian) {
        return {StatusCode::kUnsupported,
                "only little-endian ELF64 images are supported"};
    }
    if (ReadLittleEndian<std::uint32_t>(data_ + 20) != kElfVersionCurrent) {
        return {StatusCode::kIntegrityError, "ELF version is invalid"};
    }

    const std::uint16_t header_size = ReadLittleEndian<std::uint16_t>(data_ + 52);
    const std::uint16_t program_header_size =
        ReadLittleEndian<std::uint16_t>(data_ + 54);
    const std::uint16_t program_header_count =
        ReadLittleEndian<std::uint16_t>(data_ + 56);
    const std::uint64_t program_header_offset =
        ReadLittleEndian<std::uint64_t>(data_ + 32);

    if (header_size != kElf64HeaderSize) {
        return {StatusCode::kIntegrityError, "unexpected ELF64 header size"};
    }
    if (program_header_count != 0 && program_header_size < 56) {
        return {StatusCode::kIntegrityError, "ELF program header is too small"};
    }
    if (!RangeFits(program_header_offset, program_header_count,
                   program_header_size, size_)) {
        return {StatusCode::kIntegrityError,
                "ELF program header table is outside the image"};
    }

    output->type = ReadLittleEndian<std::uint16_t>(data_ + 16);
    output->machine = ReadLittleEndian<std::uint16_t>(data_ + 18);
    output->entry = ReadLittleEndian<std::uint64_t>(data_ + 24);
    output->program_header_offset = program_header_offset;
    output->program_header_count = program_header_count;
    return Status::Ok();
}

}  // namespace rtgum

