// SPDX-License-Identifier: LGPL-2.0 WITH WxWindows-exception-3.1
#include "art_hook/dex.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <map>
#include <set>
#include <tuple>
#include <unordered_map>
#include <utility>

#include "art_hook/jni_types.h"

namespace art_hook {
namespace {

constexpr std::uint32_t kEndianTag = 0x12345678;
constexpr std::size_t kHeaderSize = 0x70;
constexpr std::uint16_t kTypeHeaderItem = 0x0000;
constexpr std::uint16_t kTypeStringIdItem = 0x0001;
constexpr std::uint16_t kTypeTypeIdItem = 0x0002;
constexpr std::uint16_t kTypeProtoIdItem = 0x0003;
constexpr std::uint16_t kTypeFieldIdItem = 0x0004;
constexpr std::uint16_t kTypeMethodIdItem = 0x0005;
constexpr std::uint16_t kTypeClassDefItem = 0x0006;
constexpr std::uint16_t kTypeMapList = 0x1000;
constexpr std::uint16_t kTypeTypeList = 0x1001;
constexpr std::uint16_t kTypeClassDataItem = 0x2000;
constexpr std::uint16_t kTypeCodeItem = 0x2001;
constexpr std::uint16_t kTypeStringDataItem = 0x2002;

std::size_t Align(std::size_t value, std::size_t alignment) {
  return (value + alignment - 1U) & ~(alignment - 1U);
}

void AppendU16(std::vector<std::uint8_t>& output, std::uint16_t value) {
  output.push_back(static_cast<std::uint8_t>(value));
  output.push_back(static_cast<std::uint8_t>(value >> 8U));
}

void AppendU32(std::vector<std::uint8_t>& output, std::uint32_t value) {
  for (unsigned shift = 0; shift < 32; shift += 8) {
    output.push_back(static_cast<std::uint8_t>(value >> shift));
  }
}

void WriteU16(std::vector<std::uint8_t>& output, std::size_t offset,
              std::uint16_t value) {
  output.at(offset) = static_cast<std::uint8_t>(value);
  output.at(offset + 1) = static_cast<std::uint8_t>(value >> 8U);
}

void WriteU32(std::vector<std::uint8_t>& output, std::size_t offset,
              std::uint32_t value) {
  for (unsigned shift = 0; shift < 32; shift += 8) {
    output.at(offset + shift / 8U) =
        static_cast<std::uint8_t>(value >> shift);
  }
}

std::uint32_t ReadU32(const std::vector<std::uint8_t>& input,
                      std::size_t offset) {
  return static_cast<std::uint32_t>(input.at(offset)) |
         (static_cast<std::uint32_t>(input.at(offset + 1)) << 8U) |
         (static_cast<std::uint32_t>(input.at(offset + 2)) << 16U) |
         (static_cast<std::uint32_t>(input.at(offset + 3)) << 24U);
}

void PadTo(std::vector<std::uint8_t>& output, std::size_t alignment) {
  output.resize(Align(output.size(), alignment), 0);
}

Result<std::size_t> Utf16Length(std::string_view text) {
  std::size_t length = 0;
  for (std::size_t i = 0; i < text.size();) {
    const auto first = static_cast<unsigned char>(text[i]);
    if (first == 0) {
      return Status(StatusCode::kInvalidArgument,
                    "DEX strings cannot contain embedded NUL");
    }
    std::size_t width = 0;
    std::uint32_t codepoint = 0;
    if (first < 0x80U) {
      width = 1;
      codepoint = first;
    } else if ((first & 0xe0U) == 0xc0U) {
      width = 2;
      codepoint = first & 0x1fU;
    } else if ((first & 0xf0U) == 0xe0U) {
      width = 3;
      codepoint = first & 0x0fU;
    } else {
      return Status(StatusCode::kUnsupported,
                    "DEX builder currently accepts BMP UTF-8 only");
    }
    if (i + width > text.size()) {
      return Status(StatusCode::kInvalidArgument, "truncated UTF-8 string");
    }
    for (std::size_t j = 1; j < width; ++j) {
      const auto continuation = static_cast<unsigned char>(text[i + j]);
      if ((continuation & 0xc0U) != 0x80U) {
        return Status(StatusCode::kInvalidArgument, "invalid UTF-8 string");
      }
      codepoint = (codepoint << 6U) | (continuation & 0x3fU);
    }
    if (codepoint > 0xffffU ||
        (codepoint >= 0xd800U && codepoint <= 0xdfffU)) {
      return Status(StatusCode::kUnsupported,
                    "DEX builder currently accepts BMP UTF-8 only");
    }
    ++length;
    i += width;
  }
  return length;
}

std::array<std::uint8_t, 20> Sha1(const std::uint8_t* data,
                                  std::size_t size) {
  std::uint32_t h0 = 0x67452301U;
  std::uint32_t h1 = 0xefcdab89U;
  std::uint32_t h2 = 0x98badcfeU;
  std::uint32_t h3 = 0x10325476U;
  std::uint32_t h4 = 0xc3d2e1f0U;

  std::vector<std::uint8_t> message(data, data + size);
  message.push_back(0x80U);
  while ((message.size() % 64U) != 56U) {
    message.push_back(0);
  }
  const std::uint64_t bit_length = static_cast<std::uint64_t>(size) * 8U;
  for (int shift = 56; shift >= 0; shift -= 8) {
    message.push_back(static_cast<std::uint8_t>(bit_length >> shift));
  }

  for (std::size_t chunk = 0; chunk < message.size(); chunk += 64) {
    std::array<std::uint32_t, 80> words{};
    for (std::size_t i = 0; i < 16; ++i) {
      const std::size_t p = chunk + i * 4;
      words[i] = (static_cast<std::uint32_t>(message[p]) << 24U) |
                 (static_cast<std::uint32_t>(message[p + 1]) << 16U) |
                 (static_cast<std::uint32_t>(message[p + 2]) << 8U) |
                 static_cast<std::uint32_t>(message[p + 3]);
    }
    for (std::size_t i = 16; i < words.size(); ++i) {
      const std::uint32_t value =
          words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16];
      words[i] = (value << 1U) | (value >> 31U);
    }

    std::uint32_t a = h0;
    std::uint32_t b = h1;
    std::uint32_t c = h2;
    std::uint32_t d = h3;
    std::uint32_t e = h4;
    for (std::size_t i = 0; i < words.size(); ++i) {
      std::uint32_t function = 0;
      std::uint32_t constant = 0;
      if (i < 20) {
        function = (b & c) | ((~b) & d);
        constant = 0x5a827999U;
      } else if (i < 40) {
        function = b ^ c ^ d;
        constant = 0x6ed9eba1U;
      } else if (i < 60) {
        function = (b & c) | (b & d) | (c & d);
        constant = 0x8f1bbcdcU;
      } else {
        function = b ^ c ^ d;
        constant = 0xca62c1d6U;
      }
      const std::uint32_t rotate_a = (a << 5U) | (a >> 27U);
      const std::uint32_t temp = rotate_a + function + e + constant + words[i];
      e = d;
      d = c;
      c = (b << 30U) | (b >> 2U);
      b = a;
      a = temp;
    }
    h0 += a;
    h1 += b;
    h2 += c;
    h3 += d;
    h4 += e;
  }

  std::array<std::uint8_t, 20> digest{};
  const std::array<std::uint32_t, 5> words = {h0, h1, h2, h3, h4};
  for (std::size_t i = 0; i < words.size(); ++i) {
    digest[i * 4] = static_cast<std::uint8_t>(words[i] >> 24U);
    digest[i * 4 + 1] = static_cast<std::uint8_t>(words[i] >> 16U);
    digest[i * 4 + 2] = static_cast<std::uint8_t>(words[i] >> 8U);
    digest[i * 4 + 3] = static_cast<std::uint8_t>(words[i]);
  }
  return digest;
}

struct Proto final {
  std::string return_type;
  std::vector<std::string> arguments;
  std::string shorty;
  std::uint32_t parameters_offset = 0;
};

struct Field final {
  std::string holder;
  std::string type;
  std::string name;
  std::uint32_t access_flags = 0;
};

struct Method final {
  std::string holder;
  std::size_t proto = 0;
  std::string proto_key;
  std::string name;
  std::uint32_t access_flags = 0;
  bool generated_constructor = false;
  std::uint32_t code_offset = 0;
};

std::string ProtoKey(std::string_view return_type,
                     const std::vector<std::string>& arguments) {
  std::string key(return_type);
  for (const auto& argument : arguments) {
    key.push_back('|');
    key += argument;
  }
  return key;
}

Status ValidateTypeName(const std::string& name, bool allow_void) {
  auto parsed = ParseType(name);
  if (!parsed.ok() || parsed.value().jni_name != name) {
    return Status(StatusCode::kInvalidArgument,
                  "DEX type must be a canonical JNI descriptor: " + name);
  }
  if (!allow_void && parsed.value().kind == JavaTypeKind::kPrimitive &&
      parsed.value().primitive == PrimitiveType::kVoid) {
    return Status(StatusCode::kInvalidArgument,
                  "void is not allowed here");
  }
  return Status::Ok();
}

}  // namespace

std::vector<std::uint8_t> EncodeUleb128(std::uint32_t value) {
  std::vector<std::uint8_t> result;
  do {
    std::uint8_t byte = static_cast<std::uint8_t>(value & 0x7fU);
    value >>= 7U;
    if (value != 0) {
      byte |= 0x80U;
    }
    result.push_back(byte);
  } while (value != 0);
  return result;
}

std::uint32_t Adler32(const std::uint8_t* data, std::size_t size) {
  constexpr std::uint32_t kMod = 65521U;
  std::uint32_t a = 1;
  std::uint32_t b = 0;
  for (std::size_t i = 0; i < size; ++i) {
    a = (a + data[i]) % kMod;
    b = (b + a) % kMod;
  }
  return (b << 16U) | a;
}

Result<std::vector<std::uint8_t>> DexBuilder::Build(DexClassSpec spec) const {
  Status status = ValidateTypeName(spec.name, false);
  if (!status.ok() || spec.name.front() != 'L') {
    return status.ok()
               ? Status(StatusCode::kInvalidArgument,
                        "class name must be an object descriptor")
               : status;
  }
  status = ValidateTypeName(spec.super_class, false);
  if (!status.ok()) {
    return status;
  }
  for (const auto& interface_name : spec.interfaces) {
    status = ValidateTypeName(interface_name, false);
    if (!status.ok()) {
      return status;
    }
  }
  for (const auto& field : spec.fields) {
    status = ValidateTypeName(field.type, false);
    if (!status.ok()) {
      return status;
    }
    if (field.name.empty()) {
      return Status(StatusCode::kInvalidArgument, "field name is empty");
    }
  }

  bool has_constructor = false;
  for (const auto& method : spec.methods) {
    status = ValidateTypeName(method.return_type, true);
    if (!status.ok()) {
      return status;
    }
    for (const auto& argument : method.arguments) {
      status = ValidateTypeName(argument, false);
      if (!status.ok()) {
        return status;
      }
    }
    if (method.name.empty()) {
      return Status(StatusCode::kInvalidArgument, "method name is empty");
    }
    has_constructor = has_constructor || method.name == "<init>";
  }
  if (!has_constructor) {
    spec.methods.push_back(
        {"<init>", "V", {}, kDexAccPublic | kDexAccConstructor});
  }

  std::set<std::string> string_set = {spec.name, spec.super_class,
                                      spec.source_file_name, "<init>"};
  std::set<std::string> type_set = {spec.name, spec.super_class};
  for (const auto& interface_name : spec.interfaces) {
    string_set.insert(interface_name);
    type_set.insert(interface_name);
  }
  for (const auto& field : spec.fields) {
    string_set.insert(field.name);
    string_set.insert(field.type);
    type_set.insert(field.type);
  }

  std::vector<Proto> protos;
  std::unordered_map<std::string, std::size_t> proto_by_key;
  auto intern_proto = [&](const std::string& return_type,
                          const std::vector<std::string>& arguments) {
    const std::string key = ProtoKey(return_type, arguments);
    const auto found = proto_by_key.find(key);
    if (found != proto_by_key.end()) {
      return found->second;
    }
    Proto proto;
    proto.return_type = return_type;
    proto.arguments = arguments;
    auto return_parsed = ParseType(return_type);
    proto.shorty.push_back(TypeToShorty(return_parsed.value()));
    for (const auto& argument : arguments) {
      auto parsed = ParseType(argument);
      proto.shorty.push_back(TypeToShorty(parsed.value()));
    }
    const std::size_t index = protos.size();
    protos.push_back(std::move(proto));
    proto_by_key.emplace(key, index);
    return index;
  };

  std::vector<Field> fields;
  for (const auto& field : spec.fields) {
    fields.push_back({spec.name, field.type, field.name, field.access_flags});
  }
  std::vector<Method> methods;
  for (const auto& method : spec.methods) {
    string_set.insert(method.name);
    string_set.insert(method.return_type);
    type_set.insert(method.return_type);
    for (const auto& argument : method.arguments) {
      string_set.insert(argument);
      type_set.insert(argument);
    }
    const std::size_t proto = intern_proto(method.return_type, method.arguments);
    string_set.insert(protos[proto].shorty);
    std::uint32_t access_flags = method.access_flags;
    if (method.name == "<init>") {
      access_flags |= kDexAccConstructor;
    }
    methods.push_back({spec.name, proto,
                       ProtoKey(method.return_type, method.arguments),
                       method.name, access_flags,
                       method.name == "<init>" && !has_constructor, 0});
  }

  const std::size_t void_proto = intern_proto("V", {});
  string_set.insert("V");
  type_set.insert("V");
  string_set.insert(protos[void_proto].shorty);
  if (!has_constructor) {
    methods.push_back({spec.super_class, void_proto, ProtoKey("V", {}),
                       "<init>", 0, false, 0});
  }

  std::vector<std::string> strings(string_set.begin(), string_set.end());
  std::unordered_map<std::string, std::uint32_t> string_index;
  for (std::size_t i = 0; i < strings.size(); ++i) {
    string_index.emplace(strings[i], static_cast<std::uint32_t>(i));
  }

  std::vector<std::string> types(type_set.begin(), type_set.end());
  std::sort(types.begin(), types.end(), [&](const auto& a, const auto& b) {
    return string_index.at(a) < string_index.at(b);
  });
  std::unordered_map<std::string, std::uint16_t> type_index;
  for (std::size_t i = 0; i < types.size(); ++i) {
    if (i > 0xffffU) {
      return Status(StatusCode::kResourceExhausted,
                    "DEX type index exceeds 16 bits");
    }
    type_index.emplace(types[i], static_cast<std::uint16_t>(i));
  }

  std::sort(protos.begin(), protos.end(), [&](const Proto& a, const Proto& b) {
    const auto a_key = std::make_tuple(type_index.at(a.return_type), a.arguments);
    const auto b_key = std::make_tuple(type_index.at(b.return_type), b.arguments);
    return a_key < b_key;
  });
  proto_by_key.clear();
  for (std::size_t i = 0; i < protos.size(); ++i) {
    proto_by_key.emplace(ProtoKey(protos[i].return_type, protos[i].arguments), i);
  }
  for (auto& method : methods) {
    method.proto = proto_by_key.at(method.proto_key);
  }
  const std::size_t sorted_void_proto = proto_by_key.at(ProtoKey("V", {}));

  std::sort(fields.begin(), fields.end(), [&](const Field& a, const Field& b) {
    return std::make_tuple(type_index.at(a.holder), string_index.at(a.name),
                           type_index.at(a.type)) <
           std::make_tuple(type_index.at(b.holder), string_index.at(b.name),
                           type_index.at(b.type));
  });
  std::sort(methods.begin(), methods.end(), [&](const Method& a, const Method& b) {
    return std::make_tuple(type_index.at(a.holder), string_index.at(a.name),
                           a.proto) <
           std::make_tuple(type_index.at(b.holder), string_index.at(b.name),
                           b.proto);
  });

  const std::size_t string_ids_offset = kHeaderSize;
  const std::size_t type_ids_offset = string_ids_offset + strings.size() * 4U;
  const std::size_t proto_ids_offset = type_ids_offset + types.size() * 4U;
  const std::size_t field_ids_offset = proto_ids_offset + protos.size() * 12U;
  const std::size_t method_ids_offset = field_ids_offset + fields.size() * 8U;
  const std::size_t class_defs_offset = method_ids_offset + methods.size() * 8U;
  const std::size_t data_offset = class_defs_offset + 32U;

  std::vector<std::uint8_t> dex(data_offset, 0);
  const std::array<std::uint8_t, 8> magic = {'d', 'e', 'x', '\n', '0', '3',
                                             '5', 0};
  std::copy(magic.begin(), magic.end(), dex.begin());

  for (std::size_t i = 0; i < types.size(); ++i) {
    WriteU32(dex, type_ids_offset + i * 4U, string_index.at(types[i]));
  }
  for (std::size_t i = 0; i < fields.size(); ++i) {
    const auto& field = fields[i];
    WriteU16(dex, field_ids_offset + i * 8U, type_index.at(field.holder));
    WriteU16(dex, field_ids_offset + i * 8U + 2U,
             type_index.at(field.type));
    WriteU32(dex, field_ids_offset + i * 8U + 4U,
             string_index.at(field.name));
  }
  for (std::size_t i = 0; i < methods.size(); ++i) {
    const auto& method = methods[i];
    WriteU16(dex, method_ids_offset + i * 8U, type_index.at(method.holder));
    WriteU16(dex, method_ids_offset + i * 8U + 2U,
             static_cast<std::uint16_t>(method.proto));
    WriteU32(dex, method_ids_offset + i * 8U + 4U,
             string_index.at(method.name));
  }

  std::uint32_t first_type_list_offset = 0;
  std::uint32_t type_list_count = 0;
  std::map<std::vector<std::uint16_t>, std::uint32_t> type_list_offsets;
  auto append_type_list = [&](const std::vector<std::uint16_t>& entries) {
    if (entries.empty()) {
      return 0U;
    }
    const auto found = type_list_offsets.find(entries);
    if (found != type_list_offsets.end()) {
      return found->second;
    }
    PadTo(dex, 4);
    const auto offset = static_cast<std::uint32_t>(dex.size());
    if (first_type_list_offset == 0) {
      first_type_list_offset = offset;
    }
    AppendU32(dex, static_cast<std::uint32_t>(entries.size()));
    for (const auto entry : entries) {
      AppendU16(dex, entry);
    }
    type_list_offsets.emplace(entries, offset);
    ++type_list_count;
    return offset;
  };

  for (auto& proto : protos) {
    std::vector<std::uint16_t> parameters;
    for (const auto& argument : proto.arguments) {
      parameters.push_back(type_index.at(argument));
    }
    proto.parameters_offset = append_type_list(parameters);
  }
  std::vector<std::uint16_t> interface_types;
  for (const auto& interface_name : spec.interfaces) {
    interface_types.push_back(type_index.at(interface_name));
  }
  std::sort(interface_types.begin(), interface_types.end());
  const std::uint32_t interfaces_offset = append_type_list(interface_types);

  for (std::size_t i = 0; i < protos.size(); ++i) {
    const auto& proto = protos[i];
    WriteU32(dex, proto_ids_offset + i * 12U,
             string_index.at(proto.shorty));
    WriteU32(dex, proto_ids_offset + i * 12U + 4U,
             type_index.at(proto.return_type));
    WriteU32(dex, proto_ids_offset + i * 12U + 8U,
             proto.parameters_offset);
  }

  std::uint32_t code_offset = 0;
  if (!has_constructor) {
    PadTo(dex, 4);
    code_offset = static_cast<std::uint32_t>(dex.size());
    AppendU16(dex, 1);  // registers_size
    AppendU16(dex, 1);  // ins_size
    AppendU16(dex, 1);  // outs_size
    AppendU16(dex, 0);  // tries_size
    AppendU32(dex, 0);  // debug_info_off
    AppendU32(dex, 4);  // insns_size
    std::size_t super_constructor_index = 0;
    for (std::size_t i = 0; i < methods.size(); ++i) {
      if (methods[i].holder == spec.super_class &&
          methods[i].name == "<init>" &&
          methods[i].proto == sorted_void_proto) {
        super_constructor_index = i;
      }
    }
    AppendU16(dex, 0x1070);  // invoke-direct {v0}, method@BBBB
    AppendU16(dex, static_cast<std::uint16_t>(super_constructor_index));
    AppendU16(dex, 0x0000);
    AppendU16(dex, 0x000e);  // return-void
  }

  auto encode_members = [&](const std::vector<std::pair<std::size_t,
                                                         std::uint32_t>>& items,
                            bool methods_list) {
    std::vector<std::uint8_t> encoded;
    std::size_t previous = 0;
    for (std::size_t i = 0; i < items.size(); ++i) {
      const std::size_t difference = i == 0 ? items[i].first
                                             : items[i].first - previous;
      const auto diff = EncodeUleb128(static_cast<std::uint32_t>(difference));
      encoded.insert(encoded.end(), diff.begin(), diff.end());
      const auto flags = EncodeUleb128(items[i].second);
      encoded.insert(encoded.end(), flags.begin(), flags.end());
      if (methods_list) {
        const auto code = EncodeUleb128(
            methods[items[i].first].generated_constructor ? code_offset : 0U);
        encoded.insert(encoded.end(), code.begin(), code.end());
      }
      previous = items[i].first;
    }
    return encoded;
  };

  std::vector<std::pair<std::size_t, std::uint32_t>> static_fields;
  std::vector<std::pair<std::size_t, std::uint32_t>> instance_fields;
  for (std::size_t i = 0; i < fields.size(); ++i) {
    if (fields[i].holder != spec.name) {
      continue;
    }
    auto& target = (fields[i].access_flags & kDexAccStatic) != 0
                       ? static_fields
                       : instance_fields;
    target.emplace_back(i, fields[i].access_flags);
  }
  std::vector<std::pair<std::size_t, std::uint32_t>> direct_methods;
  std::vector<std::pair<std::size_t, std::uint32_t>> virtual_methods;
  for (std::size_t i = 0; i < methods.size(); ++i) {
    if (methods[i].holder != spec.name) {
      continue;
    }
    const bool direct = methods[i].name == "<init>" ||
                        (methods[i].access_flags &
                         (kDexAccStatic | kDexAccPrivate)) != 0;
    auto& target = direct ? direct_methods : virtual_methods;
    target.emplace_back(i, methods[i].access_flags);
  }

  const std::uint32_t class_data_offset = static_cast<std::uint32_t>(dex.size());
  for (const std::size_t count : {static_fields.size(), instance_fields.size(),
                                  direct_methods.size(), virtual_methods.size()}) {
    const auto encoded = EncodeUleb128(static_cast<std::uint32_t>(count));
    dex.insert(dex.end(), encoded.begin(), encoded.end());
  }
  for (const auto* group : {&static_fields, &instance_fields}) {
    auto encoded = encode_members(*group, false);
    dex.insert(dex.end(), encoded.begin(), encoded.end());
  }
  for (const auto* group : {&direct_methods, &virtual_methods}) {
    auto encoded = encode_members(*group, true);
    dex.insert(dex.end(), encoded.begin(), encoded.end());
  }

  const std::uint32_t first_string_data_offset =
      static_cast<std::uint32_t>(dex.size());
  for (std::size_t i = 0; i < strings.size(); ++i) {
    WriteU32(dex, string_ids_offset + i * 4U,
             static_cast<std::uint32_t>(dex.size()));
    auto length = Utf16Length(strings[i]);
    if (!length.ok()) {
      return length.status();
    }
    const auto encoded = EncodeUleb128(static_cast<std::uint32_t>(length.value()));
    dex.insert(dex.end(), encoded.begin(), encoded.end());
    dex.insert(dex.end(), strings[i].begin(), strings[i].end());
    dex.push_back(0);
  }

  PadTo(dex, 4);
  const std::uint32_t map_offset = static_cast<std::uint32_t>(dex.size());
  struct MapEntry final {
    std::uint16_t type;
    std::uint32_t size;
    std::uint32_t offset;
  };
  std::vector<MapEntry> map = {
      {kTypeHeaderItem, 1, 0},
      {kTypeStringIdItem, static_cast<std::uint32_t>(strings.size()),
       static_cast<std::uint32_t>(string_ids_offset)},
      {kTypeTypeIdItem, static_cast<std::uint32_t>(types.size()),
       static_cast<std::uint32_t>(type_ids_offset)},
      {kTypeProtoIdItem, static_cast<std::uint32_t>(protos.size()),
       static_cast<std::uint32_t>(proto_ids_offset)},
      {kTypeClassDefItem, 1, static_cast<std::uint32_t>(class_defs_offset)},
  };
  if (!fields.empty()) {
    map.push_back({kTypeFieldIdItem, static_cast<std::uint32_t>(fields.size()),
                   static_cast<std::uint32_t>(field_ids_offset)});
  }
  if (!methods.empty()) {
    map.push_back({kTypeMethodIdItem,
                   static_cast<std::uint32_t>(methods.size()),
                   static_cast<std::uint32_t>(method_ids_offset)});
  }
  if (type_list_count != 0) {
    map.push_back(
        {kTypeTypeList, type_list_count, first_type_list_offset});
  }
  if (code_offset != 0) {
    map.push_back({kTypeCodeItem, 1, code_offset});
  }
  map.push_back({kTypeClassDataItem, 1, class_data_offset});
  map.push_back({kTypeStringDataItem,
                 static_cast<std::uint32_t>(strings.size()),
                 first_string_data_offset});
  map.push_back({kTypeMapList, 1, map_offset});
  std::sort(map.begin(), map.end(),
            [](const MapEntry& a, const MapEntry& b) {
              return a.offset < b.offset;
            });
  AppendU32(dex, static_cast<std::uint32_t>(map.size()));
  for (const auto& entry : map) {
    AppendU16(dex, entry.type);
    AppendU16(dex, 0);
    AppendU32(dex, entry.size);
    AppendU32(dex, entry.offset);
  }

  const auto no_index = 0xffffffffU;
  WriteU32(dex, class_defs_offset, type_index.at(spec.name));
  WriteU32(dex, class_defs_offset + 4U, kDexAccPublic);
  WriteU32(dex, class_defs_offset + 8U, type_index.at(spec.super_class));
  WriteU32(dex, class_defs_offset + 12U, interfaces_offset);
  WriteU32(dex, class_defs_offset + 16U,
           string_index.at(spec.source_file_name));
  WriteU32(dex, class_defs_offset + 20U, 0);
  WriteU32(dex, class_defs_offset + 24U, class_data_offset);
  WriteU32(dex, class_defs_offset + 28U, 0);

  WriteU32(dex, 32, static_cast<std::uint32_t>(dex.size()));
  WriteU32(dex, 36, static_cast<std::uint32_t>(kHeaderSize));
  WriteU32(dex, 40, kEndianTag);
  WriteU32(dex, 44, 0);
  WriteU32(dex, 48, 0);
  WriteU32(dex, 52, map_offset);
  WriteU32(dex, 56, static_cast<std::uint32_t>(strings.size()));
  WriteU32(dex, 60, static_cast<std::uint32_t>(string_ids_offset));
  WriteU32(dex, 64, static_cast<std::uint32_t>(types.size()));
  WriteU32(dex, 68, static_cast<std::uint32_t>(type_ids_offset));
  WriteU32(dex, 72, static_cast<std::uint32_t>(protos.size()));
  WriteU32(dex, 76, static_cast<std::uint32_t>(proto_ids_offset));
  WriteU32(dex, 80, static_cast<std::uint32_t>(fields.size()));
  WriteU32(dex, 84,
           fields.empty() ? 0U : static_cast<std::uint32_t>(field_ids_offset));
  WriteU32(dex, 88, static_cast<std::uint32_t>(methods.size()));
  WriteU32(dex, 92, static_cast<std::uint32_t>(method_ids_offset));
  WriteU32(dex, 96, 1);
  WriteU32(dex, 100, static_cast<std::uint32_t>(class_defs_offset));
  WriteU32(dex, 104, static_cast<std::uint32_t>(dex.size() - data_offset));
  WriteU32(dex, 108, static_cast<std::uint32_t>(data_offset));

  const auto digest = Sha1(dex.data() + 32U, dex.size() - 32U);
  std::copy(digest.begin(), digest.end(), dex.begin() + 12U);
  WriteU32(dex, 8, Adler32(dex.data() + 12U, dex.size() - 12U));

  status = ValidateDex(dex);
  if (!status.ok()) {
    return status;
  }
  (void)no_index;
  return dex;
}

Status ValidateDex(const std::vector<std::uint8_t>& dex) {
  if (dex.size() < kHeaderSize) {
    return Status(StatusCode::kInvalidArgument, "DEX is smaller than header");
  }
  const std::array<std::uint8_t, 4> prefix = {'d', 'e', 'x', '\n'};
  if (!std::equal(prefix.begin(), prefix.end(), dex.begin()) || dex[7] != 0) {
    return Status(StatusCode::kInvalidArgument, "invalid DEX magic");
  }
  if (ReadU32(dex, 32) != dex.size() || ReadU32(dex, 36) != kHeaderSize ||
      ReadU32(dex, 40) != kEndianTag) {
    return Status(StatusCode::kInvalidArgument,
                  "invalid DEX header dimensions");
  }
  const std::uint32_t expected = Adler32(dex.data() + 12U, dex.size() - 12U);
  if (ReadU32(dex, 8) != expected) {
    return Status(StatusCode::kInvalidArgument, "DEX checksum mismatch");
  }
  const auto digest = Sha1(dex.data() + 32U, dex.size() - 32U);
  if (!std::equal(digest.begin(), digest.end(), dex.begin() + 12U)) {
    return Status(StatusCode::kInvalidArgument, "DEX signature mismatch");
  }
  return Status::Ok();
}

}  // namespace art_hook
