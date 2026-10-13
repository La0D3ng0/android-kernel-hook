#pragma once

#include "rtgum/host_api_v2.h"
#include "rtgum/native_backend.hpp"

namespace rtgum {
namespace native {

constexpr unsigned int kMaxNamespaceEntries = 32U;

struct NamespaceEntry {
    char soname[64];
    char path[256];
    bool used;
};

struct NamespaceTable {
    NamespaceEntry entries[kMaxNamespaceEntries];

    void Reset()
    {
        for (unsigned int index = 0; index < kMaxNamespaceEntries; ++index)
            entries[index] = NamespaceEntry{};
    }

    /* Record soname -> path. A second mapping of the same SONAME with a
     * different path is ambiguous without a bionic namespace id. */
    long Register(const char *soname, const char *path)
    {
        if (!soname || !path || *soname == '\0' || *path == '\0') return RTGUM_HOST_ERR_INVAL;
        const unsigned long name_length = StringLength(soname, sizeof(NamespaceEntry::soname) - 1U);
        const unsigned long path_length = StringLength(path, sizeof(NamespaceEntry::path) - 1U);
        if (name_length >= sizeof(NamespaceEntry::soname) - 1U ||
            path_length >= sizeof(NamespaceEntry::path) - 1U) {
            return RTGUM_HOST_ERR_INVAL;
        }
        int free_index = -1;
        for (unsigned int index = 0; index < kMaxNamespaceEntries; ++index) {
            if (!entries[index].used) {
                if (free_index < 0) free_index = static_cast<int>(index);
                continue;
            }
            if (!StringsEqual(entries[index].soname, soname)) continue;
            if (StringsEqual(entries[index].path, path)) return 0;
            return RTGUM_HOST_ERR_NOTSUP;
        }
        if (free_index < 0) return RTGUM_HOST_ERR_BUSY;
        NamespaceEntry &entry = entries[static_cast<unsigned int>(free_index)];
        CopyBytes(entry.soname, soname, name_length + 1U);
        CopyBytes(entry.path, path, path_length + 1U);
        entry.used = true;
        return 0;
    }

    long Lookup(const char *soname, char *out_path, unsigned long capacity) const
    {
        if (!soname || !out_path || capacity < 2UL) return RTGUM_HOST_ERR_INVAL;
        int found = -1;
        for (unsigned int index = 0; index < kMaxNamespaceEntries; ++index) {
            if (!entries[index].used) continue;
            if (!StringsEqual(entries[index].soname, soname)) continue;
            if (found >= 0) return RTGUM_HOST_ERR_NOTSUP;
            found = static_cast<int>(index);
        }
        if (found < 0) return RTGUM_HOST_ERR_NOENT;
        const unsigned long path_length =
            StringLength(entries[static_cast<unsigned int>(found)].path,
                         sizeof(NamespaceEntry::path) - 1U);
        if (path_length + 1U > capacity) return RTGUM_HOST_ERR_INVAL;
        CopyBytes(out_path, entries[static_cast<unsigned int>(found)].path, path_length + 1U);
        return 0;
    }
};

}  // namespace native
}  // namespace rtgum
