#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>

#include "rtgum/kpm_dry_run.hpp"

namespace {

bool ParseEpoch(const char* text, std::int64_t* output) {
    if (text == nullptr || output == nullptr) {
        return false;
    }
    char* end = nullptr;
    errno = 0;
    const long long value = std::strtoll(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0') {
        return false;
    }
    *output = static_cast<std::int64_t>(value);
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 7) {
        std::cerr << "usage: rtgum_kpm_plan <allowed-package> <target-package> "
                     "<module-id> <payload-path> <sha256> <expires-epoch>\n";
        return 2;
    }

    std::int64_t expires_at = 0;
    if (!ParseEpoch(argv[6], &expires_at)) {
        std::cerr << "invalid expiration epoch\n";
        return 2;
    }

    rtgum::KpmDryRunPlanner planner;
    rtgum::Status status = planner.AllowTargetPackage(argv[1]);
    if (!status.ok()) {
        std::cerr << "allowlist error: " << status.message() << '\n';
        return 1;
    }

    rtgum::KpmManifest manifest;
    manifest.module_id = argv[3];
    manifest.target_package = argv[2];
    manifest.payload_path = argv[4];
    manifest.payload_sha256 = argv[5];
    manifest.expires_at_epoch_seconds = expires_at;

    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
    rtgum::KpmDryRunPlan plan;
    status = planner.BuildPlan(manifest, now, &plan);
    if (!status.ok()) {
        std::cerr << "plan denied: " << status.message() << '\n';
        return 1;
    }

    std::cout << "backend=" << plan.backend << '\n'
              << "module_id=" << plan.module_id << '\n'
              << "target_package=" << plan.target_package << '\n'
              << "payload_path=" << plan.payload_path << '\n'
              << "kernel_write=" << plan.kernel_write << '\n'
              << "mapping_concealment=" << plan.mapping_concealment << '\n';
    for (const std::string& step : plan.audit_steps) {
        std::cout << "audit_step=" << step << '\n';
    }
    return 0;
}

