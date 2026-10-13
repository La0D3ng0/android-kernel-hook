#pragma once

#include "rtgum/native_backend.hpp"

#include <cstddef>
#include <cstdint>

namespace rtgum {
namespace native {

constexpr unsigned long kDtRelr = 36UL;
constexpr unsigned long kDtRelrSize = 35UL;
constexpr unsigned long kDtRelrEnt = 37UL;
constexpr unsigned long kDtAndroidRel = 0x6000000fUL;
constexpr unsigned long kDtAndroidRelSize = 0x60000010UL;
constexpr unsigned long kDtAndroidRela = 0x60000011UL;
constexpr unsigned long kDtAndroidRelaSize = 0x60000012UL;

inline bool LooksLikeAps2(const unsigned char *data, unsigned long size)
{
    if (!data || size < 4UL) return false;
    return data[0] == 'A' && data[1] == 'P' && data[2] == 'S' && data[3] == '2';
}

/* Apply ELF RELR (relative-only) to a writable image. Each even entry is an
 * offset; each odd entry is a 63-bit bitmap covering the next 63 words.
 * Returns 0, INVAL, or NOTSUP. Does not handle Android packed APS2. */
inline long ApplyRelr(unsigned char *base,
                      unsigned long image_size,
                      const unsigned char *relr,
                      unsigned long relr_size,
                      unsigned long load_bias)
{
    if (!base || !relr) return RTGUM_HOST_ERR_INVAL;
    if ((relr_size & 7UL) != 0UL) return RTGUM_HOST_ERR_INVAL;
    if (LooksLikeAps2(relr, relr_size)) return RTGUM_HOST_ERR_NOTSUP;
    unsigned long where = 0;
    bool have_where = false;
    for (unsigned long offset = 0; offset < relr_size; offset += 8UL) {
        const unsigned long entry = ReadU64(relr + offset);
        if ((entry & 1UL) == 0UL) {
            if (entry + 8UL > image_size) return RTGUM_HOST_ERR_INVAL;
            unsigned long value = ReadU64(base + entry);
            value += load_bias;
            WriteU64(base + entry, value);
            where = entry + 8UL;
            have_where = true;
            continue;
        }
        if (!have_where) return RTGUM_HOST_ERR_INVAL;
        for (unsigned int bit = 1U; bit < 64U; ++bit) {
            if (where + 8UL > image_size) return RTGUM_HOST_ERR_INVAL;
            if ((entry & (1ULL << bit)) != 0ULL) {
                unsigned long value = ReadU64(base + where);
                value += load_bias;
                WriteU64(base + where, value);
            }
            where += 8UL;
        }
    }
    return 0;
}

struct DynamicRelocKind {
    bool rela = false;
    bool relr = false;
    bool android_packed = false;
    bool android_relr = false;
};

inline void ClassifyDynamicTag(unsigned long tag, DynamicRelocKind *kind)
{
    if (!kind) return;
    if (tag == 7UL || tag == 8UL || tag == 9UL) kind->rela = true;
    if (tag == kDtRelr || tag == kDtRelrSize || tag == kDtRelrEnt) kind->relr = true;
    if (tag == kDtAndroidRel || tag == kDtAndroidRelSize || tag == kDtAndroidRela ||
        tag == kDtAndroidRelaSize) {
        kind->android_packed = true;
    }
    if (tag == 0x6fffe000UL || tag == 0x6fffe001UL) kind->android_relr = true;
}

}  // namespace native
}  // namespace rtgum
