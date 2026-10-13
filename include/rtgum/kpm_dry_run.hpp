#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_set>
#include <vector>

#include "rtgum/status.hpp"

namespace rtgum {

struct KpmManifest {
    std::uint32_t schema_version{1};
    std::string module_id;
    std::string target_package;
    std::string payload_path;
    std::string payload_sha256;
    std::int64_t expires_at_epoch_seconds{0};
};

struct KpmDryRunPlan {
    std::string backend{"kpm-dry-run"};
    std::string module_id;
    std::string target_package;
    std::string payload_path;
    std::string payload_sha256;
    bool kernel_write{false};
    bool mapping_concealment{false};
    std::vector<std::string> audit_steps;
};

class KpmDryRunPlanner final {
public:
    Status AllowTargetPackage(std::string package_name);
    Status BuildPlan(const KpmManifest& manifest,
                     std::int64_t now_epoch_seconds,
                     KpmDryRunPlan* output) const;

    [[nodiscard]] std::size_t allowlist_size() const noexcept;

private:
    std::unordered_set<std::string> allowed_packages_;
};

}  // namespace rtgum

