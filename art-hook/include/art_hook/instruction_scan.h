// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#pragma once

#include <cstddef>
#include <optional>

namespace art_hook {  // C++ public API

// Decoder must return an instruction with a `next` address. TryParse receives
// the current instruction and a pointer to the previous instruction.
template <typename Address, typename Decoder, typename TryParse>
auto ParseInstructionsAt(Address address, Decoder&& decode,
                         TryParse&& try_parse, std::size_t limit)
    -> decltype(try_parse(decode(address), nullptr)) {
  using MaybeValue = decltype(try_parse(decode(address), nullptr));
  using Instruction = decltype(decode(address));

  Address cursor = address;
  std::optional<Instruction> previous;
  for (std::size_t i = 0; i < limit; ++i) {
    Instruction instruction = decode(cursor);
    MaybeValue value = try_parse(instruction,
                                 previous ? &*previous : nullptr);
    if (value.has_value()) {
      return value;
    }
    cursor = instruction.next;
    previous = std::move(instruction);
  }
  return MaybeValue{};
}

}  // namespace art_hook
