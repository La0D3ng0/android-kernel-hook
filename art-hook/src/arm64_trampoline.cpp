// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#include "art_hook/arm64_trampoline.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string>

namespace art_hook {
namespace {

constexpr std::uint8_t kSp = 31;
constexpr std::uint8_t kX16 = 16;
constexpr std::uint8_t kX17 = 17;
constexpr std::uint32_t kBtiC = 0xd503245fU;
constexpr std::uint32_t kRet = 0xd65f03c0U;

class Assembler final {
public:
  void Emit(std::uint32_t instruction) { words_.push_back(instruction); }

  void AddImmediate(std::uint8_t destination, std::uint8_t source,
                    std::uint16_t immediate) {
    RequireRegister(destination);
    RequireRegister(source);
    if (immediate > 4095U) {
      throw std::invalid_argument("ADD immediate exceeds 12 bits");
    }
    Emit(0x91000000U | (static_cast<std::uint32_t>(immediate) << 10U) |
         (static_cast<std::uint32_t>(source) << 5U) | destination);
  }

  void SubImmediate(std::uint8_t destination, std::uint8_t source,
                    std::uint16_t immediate) {
    RequireRegister(destination);
    RequireRegister(source);
    if (immediate > 4095U) {
      throw std::invalid_argument("SUB immediate exceeds 12 bits");
    }
    Emit(0xd1000000U | (static_cast<std::uint32_t>(immediate) << 10U) |
         (static_cast<std::uint32_t>(source) << 5U) | destination);
  }

  void StpX(std::uint8_t first, std::uint8_t second, std::uint16_t offset) {
    EmitPair(0xa9000000U, first, second, offset, 8U, false);
  }

  void LdpX(std::uint8_t first, std::uint8_t second, std::uint16_t offset) {
    EmitPair(0xa9400000U, first, second, offset, 8U, false);
  }

  void StpQ(std::uint8_t first, std::uint8_t second, std::uint16_t offset) {
    EmitPair(0xad000000U, first, second, offset, 16U, true);
  }

  void LdpQ(std::uint8_t first, std::uint8_t second, std::uint16_t offset) {
    EmitPair(0xad400000U, first, second, offset, 16U, true);
  }

  void StrX(std::uint8_t source, std::uint8_t base, std::uint16_t offset) {
    EmitLoadStore(0xf9000000U, source, base, offset);
  }

  void LdrX(std::uint8_t destination, std::uint8_t base, std::uint16_t offset) {
    EmitLoadStore(0xf9400000U, destination, base, offset);
  }

  void MrsNzcv(std::uint8_t destination) {
    RequireGeneralRegister(destination);
    Emit(0xd53b4200U | destination);
  }
  void MsrNzcv(std::uint8_t source) {
    RequireGeneralRegister(source);
    Emit(0xd51b4200U | source);
  }
  void MrsFpcr(std::uint8_t destination) {
    RequireGeneralRegister(destination);
    Emit(0xd53b4400U | destination);
  }
  void MsrFpcr(std::uint8_t source) {
    RequireGeneralRegister(source);
    Emit(0xd51b4400U | source);
  }
  void MrsFpsr(std::uint8_t destination) {
    RequireGeneralRegister(destination);
    Emit(0xd53b4420U | destination);
  }
  void MsrFpsr(std::uint8_t source) {
    RequireGeneralRegister(source);
    Emit(0xd51b4420U | source);
  }

  void LoadImmediate(std::uint8_t destination, std::uint64_t value) {
    RequireGeneralRegister(destination);
    Emit(0xd2800000U | (static_cast<std::uint32_t>(value & 0xffffU) << 5U) |
         destination);
    for (std::uint32_t part = 1; part < 4; ++part) {
      const auto chunk =
          static_cast<std::uint32_t>((value >> (part * 16U)) & 0xffffU);
      Emit(0xf2800000U | (part << 21U) | (chunk << 5U) | destination);
    }
  }

  void Blr(std::uint8_t target) {
    RequireGeneralRegister(target);
    Emit(0xd63f0000U | (static_cast<std::uint32_t>(target) << 5U));
  }

  void Br(std::uint8_t target) {
    RequireGeneralRegister(target);
    Emit(0xd61f0000U | (static_cast<std::uint32_t>(target) << 5U));
  }

  void CbzX(std::uint8_t value, std::int32_t byte_offset) {
    RequireGeneralRegister(value);
    if ((byte_offset & 3) != 0) {
      throw std::invalid_argument("CBZ target must be instruction aligned");
    }
    const std::int32_t immediate = byte_offset / 4;
    if (immediate < -(1 << 18) || immediate >= (1 << 18)) {
      throw std::invalid_argument("CBZ target is out of range");
    }
    Emit(0xb4000000U |
         ((static_cast<std::uint32_t>(immediate) & 0x7ffffU) << 5U) | value);
  }

  [[nodiscard]] std::vector<std::uint32_t> TakeWords() {
    return std::move(words_);
  }

private:
  static void RequireRegister(std::uint8_t reg) {
    if (reg > 31U) {
      throw std::invalid_argument("invalid ARM64 register");
    }
  }

  static void RequireGeneralRegister(std::uint8_t reg) {
    if (reg > 30U) {
      throw std::invalid_argument("expected x0-x30");
    }
  }

  void EmitPair(std::uint32_t opcode, std::uint8_t first, std::uint8_t second,
                std::uint16_t offset, std::uint16_t scale,
                bool vector_registers) {
    if (vector_registers) {
      RequireRegister(first);
      RequireRegister(second);
    } else {
      RequireGeneralRegister(first);
      RequireGeneralRegister(second);
    }
    if ((offset % scale) != 0 || (offset / scale) > 63U) {
      throw std::invalid_argument("pair load/store offset is out of range");
    }
    const auto immediate = static_cast<std::uint32_t>(offset / scale);
    Emit(opcode | (immediate << 15U) |
         (static_cast<std::uint32_t>(second) << 10U) |
         (static_cast<std::uint32_t>(kSp) << 5U) | first);
  }

  void EmitLoadStore(std::uint32_t opcode, std::uint8_t reg, std::uint8_t base,
                     std::uint16_t offset) {
    RequireGeneralRegister(reg);
    RequireRegister(base);
    if ((offset % 8U) != 0 || (offset / 8U) > 4095U) {
      throw std::invalid_argument("64-bit load/store offset is out of range");
    }
    Emit(opcode | (static_cast<std::uint32_t>(offset / 8U) << 10U) |
         (static_cast<std::uint32_t>(base) << 5U) | reg);
  }

  std::vector<std::uint32_t> words_;
};

std::vector<std::uint32_t> BuildTrampoline(Arm64Dispatch dispatch,
                                           void *user_data) {
  constexpr auto kFrameSize =
      static_cast<std::uint16_t>(sizeof(Arm64CpuContext));
  constexpr auto kSpOffset =
      static_cast<std::uint16_t>(offsetof(Arm64CpuContext, sp));
  constexpr auto kNzcvOffset =
      static_cast<std::uint16_t>(offsetof(Arm64CpuContext, nzcv));
  constexpr auto kFpcrOffset =
      static_cast<std::uint16_t>(offsetof(Arm64CpuContext, fpcr));
  constexpr auto kFpsrOffset =
      static_cast<std::uint16_t>(offsetof(Arm64CpuContext, fpsr));
  constexpr auto kVectorOffset =
      static_cast<std::uint16_t>(offsetof(Arm64CpuContext, q));
  constexpr auto kNextPcOffset =
      static_cast<std::uint16_t>(offsetof(Arm64CpuContext, next_pc));
  constexpr auto kUserDataOffset =
      static_cast<std::uint16_t>(offsetof(Arm64CpuContext, user_data));
  static_assert(sizeof(Arm64CpuContext) <= 4095U);

  Assembler code;
  code.Emit(kBtiC);
  code.SubImmediate(kSp, kSp, kFrameSize);

  for (std::uint8_t reg = 0; reg < 30U; reg += 2U) {
    code.StpX(reg, static_cast<std::uint8_t>(reg + 1U),
              static_cast<std::uint16_t>(reg * sizeof(std::uint64_t)));
  }
  code.StrX(30, kSp, static_cast<std::uint16_t>(30U * sizeof(std::uint64_t)));

  code.AddImmediate(kX16, kSp, kFrameSize);
  code.StrX(kX16, kSp, kSpOffset);
  code.MrsNzcv(kX16);
  code.StrX(kX16, kSp, kNzcvOffset);
  code.MrsFpcr(kX16);
  code.StrX(kX16, kSp, kFpcrOffset);
  code.MrsFpsr(kX16);
  code.StrX(kX16, kSp, kFpsrOffset);

  for (std::uint8_t reg = 0; reg < 32U; reg += 2U) {
    code.StpQ(reg, static_cast<std::uint8_t>(reg + 1U),
              static_cast<std::uint16_t>(kVectorOffset +
                                         reg * sizeof(Arm64VectorRegister)));
  }

  // x29 points at the saved x29/x30 pair while dispatch is running.
  code.AddImmediate(29, kSp,
                    static_cast<std::uint16_t>(29U * sizeof(std::uint64_t)));

  code.LoadImmediate(kX16, reinterpret_cast<std::uintptr_t>(user_data));
  code.StrX(kX16, kSp, kUserDataOffset);
  code.AddImmediate(0, kSp, 0);
  code.LoadImmediate(1, reinterpret_cast<std::uintptr_t>(user_data));
  code.LoadImmediate(kX16, reinterpret_cast<std::uintptr_t>(dispatch));
  code.Blr(kX16);
  code.StrX(0, kSp, kNextPcOffset);

  for (std::uint8_t reg = 0; reg < 32U; reg += 2U) {
    code.LdpQ(reg, static_cast<std::uint8_t>(reg + 1U),
              static_cast<std::uint16_t>(kVectorOffset +
                                         reg * sizeof(Arm64VectorRegister)));
  }

  code.LdrX(kX16, kSp, kNzcvOffset);
  code.MsrNzcv(kX16);
  code.LdrX(kX16, kSp, kFpcrOffset);
  code.MsrFpcr(kX16);
  code.LdrX(kX16, kSp, kFpsrOffset);
  code.MsrFpsr(kX16);

  for (std::uint8_t reg = 0; reg < 16U; reg += 2U) {
    code.LdpX(reg, static_cast<std::uint8_t>(reg + 1U),
              static_cast<std::uint16_t>(reg * sizeof(std::uint64_t)));
  }
  code.LdrX(kX17, kSp, static_cast<std::uint16_t>(17U * sizeof(std::uint64_t)));
  for (std::uint8_t reg = 18; reg < 30U; reg += 2U) {
    code.LdpX(reg, static_cast<std::uint8_t>(reg + 1U),
              static_cast<std::uint16_t>(reg * sizeof(std::uint64_t)));
  }
  code.LdrX(30, kSp, static_cast<std::uint16_t>(30U * sizeof(std::uint64_t)));
  code.LdrX(kX16, kSp, kNextPcOffset);
  code.AddImmediate(kSp, kSp, kFrameSize);
  code.CbzX(kX16, 8);
  code.Br(kX16);
  code.Emit(kRet);

  return code.TakeWords();
}

std::size_t AlignUp(std::size_t value, std::size_t alignment) {
  return (value + alignment - 1U) & ~(alignment - 1U);
}

} // namespace

Result<std::unique_ptr<Arm64Trampoline>>
Arm64Trampoline::Create(Arm64Dispatch dispatch, void *user_data) {
  if (dispatch == nullptr) {
    return Status(StatusCode::kInvalidArgument,
                  "ARM64 trampoline dispatch is null");
  }

  std::vector<std::uint32_t> words;
  try {
    words = BuildTrampoline(dispatch, user_data);
  } catch (const std::exception &error) {
    return Status(StatusCode::kPlatformError,
                  std::string("unable to encode ARM64 trampoline: ") +
                      error.what());
  }

  const std::size_t code_size = words.size() * sizeof(std::uint32_t);
  const std::size_t slice_size = AlignUp(code_size, 64U);
  if (slice_size == 0 || slice_size > 4096U) {
    return Status(StatusCode::kResourceExhausted,
                  "ARM64 trampoline exceeds one page");
  }

  auto allocator = std::make_unique<CodeAllocator>(slice_size);
  auto allocation = allocator->Allocate();
  if (!allocation.ok()) {
    return allocation.status();
  }
  std::memcpy(allocation.value(), words.data(), code_size);
  Status seal = allocator->Seal();
  if (!seal.ok()) {
    return seal;
  }

  return std::unique_ptr<Arm64Trampoline>(new Arm64Trampoline(
      std::move(allocator), allocation.value(), std::move(words)));
}

Result<std::unique_ptr<Arm64Trampoline>>
Arm64Trampoline::Create(Arm64Dispatch dispatch, void *user_data,
                        SliceAllocator &allocator) {
  if (dispatch == nullptr) {
    return Status(StatusCode::kInvalidArgument,
                  "ARM64 trampoline dispatch is null");
  }

  std::vector<std::uint32_t> words;
  try {
    words = BuildTrampoline(dispatch, user_data);
  } catch (const std::exception &error) {
    return Status(StatusCode::kPlatformError,
                  std::string("unable to encode ARM64 trampoline: ") +
                      error.what());
  }

  const std::size_t code_size = words.size() * sizeof(std::uint32_t);
  const std::size_t slice_size = AlignUp(code_size, 64U);
  if (slice_size == 0 || slice_size > 4096U) {
    return Status(StatusCode::kResourceExhausted,
                  "ARM64 trampoline exceeds one page");
  }

  auto allocation = allocator.Allocate(slice_size);
  if (!allocation.ok()) {
    return allocation.status();
  }
  Status write = allocator.Write(allocation.value(), words.data(), code_size);
  if (!write.ok()) {
    (void)allocator.Free(allocation.value());
    return write;
  }
  // Backends that hand out writable pages flip to RX here. Ghost pools already
  // committed through the KPM alias and flushed the complete backing page.
  Status finalize = allocator.Finalize(allocation.value());
  if (!finalize.ok()) {
    return finalize;
  }

  return std::unique_ptr<Arm64Trampoline>(new Arm64Trampoline(
      nullptr, allocation.value(), std::move(words)));
}

} // namespace art_hook
