#include "rtgum/kpm_dry_run.hpp"

#include <algorithm>
#include <cctype>
#include <utility>

namespace rtgum {
namespace {

constexpr std::uint32_t kManifestSchemaVersion = 1;
constexpr std::int64_t kMaximumPlanLifetimeSeconds = 24 * 60 * 60;
constexpr char kPayloadRoot[] = "/data/local/tmp/rtgum/";

bool IsAsciiLetter(char value) noexcept {
    const unsigned char byte = static_cast<unsigned char>(value);
    return std::isalpha(byte) != 0;
}

bool IsPackageCharacter(char value) noexcept {
    const unsigned char byte = static_cast<unsigned char>(value);
    return std::isalnum(byte) != 0 || value == '_';
}

bool IsValidPackageName(const std::string& value) noexcept {
    if (value.empty() || value.size() > 255 || value.find('.') == std::string::npos) {
        return false;
    }

    bool at_segment_start = true;
    for (char character : value) {
        if (character == '.') {
            if (at_segment_start) {
                return false;
            }
            at_segment_start = true;
            continue;
        }
        if (at_segment_start) {
            if (!IsAsciiLetter(character)) {
                return false;
            }
            at_segment_start = false;
        } else if (!IsPackageCharacter(character)) {
            return false;
        }
    }
    return !at_segment_start;
}

bool IsValidModuleId(const std::string& value) noexcept {
    if (value.empty() || value.size() > 64) {
        return false;
    }
    return std::all_of(value.begin(), value.end(), [](char character) {
        const unsigned char byte = static_cast<unsigned char>(character);
        return std::isalnum(byte) != 0 || character == '.' || character == '_' ||
               character == '-';
    });
}

bool IsSha256(const std::string& value) noexcept {
    return value.size() == 64 &&
           std::all_of(value.begin(), value.end(), [](char character) {
               const unsigned char byte = static_cast<unsigned char>(character);
               return std::isxdigit(byte) != 0;
           });
}

bool IsAllowedPayloadPath(const std::string& path) noexcept {
    if (path.size() <= sizeof(kPayloadRoot) - 1 ||
        path.compare(0, sizeof(kPayloadRoot) - 1, kPayloadRoot) != 0) {
        return false;
    }
    if (path.find("/../") != std::string::npos ||
        path.find("/./") != std::string::npos || path.back() == '/') {
        return false;
    }
    return path.compare(path.size() - 3, 3, "/..") != 0 &&
           path.compare(path.size() - 2, 2, "/.") != 0;
}

}  // namespace

Status KpmDryRunPlanner::AllowTargetPackage(std::string package_name) {
    if (!IsValidPackageName(package_name)) {
        return {StatusCode::kInvalidArgument, "invalid Android package name"};
    }
    allowed_packages_.insert(std::move(package_name));
    return Status::Ok();
}

Status KpmDryRunPlanner::BuildPlan(const KpmManifest& manifest,
                                   std::int64_t now_epoch_seconds,
                                   KpmDryRunPlan* output) const {
    if (output == nullptr) {
        return {StatusCode::kInvalidArgument, "output must not be null"};
    }
    *output = {};

    if (manifest.schema_version != kManifestSchemaVersion) {
        return {StatusCode::kUnsupported, "unsupported KPM manifest schema"};
    }
    if (!IsValidModuleId(manifest.module_id)) {
        return {StatusCode::kInvalidArgument, "invalid module id"};
    }
    if (!IsValidPackageName(manifest.target_package)) {
        return {StatusCode::kInvalidArgument, "invalid target package"};
    }
    if (allowed_packages_.find(manifest.target_package) == allowed_packages_.end()) {
        return {StatusCode::kPolicyDenied, "target package is not allowlisted"};
    }
    if (!IsAllowedPayloadPath(manifest.payload_path)) {
        return {StatusCode::kPolicyDenied,
                "payload must stay under /data/local/tmp/rtgum/"};
    }
    if (!IsSha256(manifest.payload_sha256)) {
        return {StatusCode::kInvalidArgument, "payload SHA-256 must be 64 hex digits"};
    }
    if (now_epoch_seconds < 0 || manifest.expires_at_epoch_seconds <= now_epoch_seconds) {
        return {StatusCode::kPolicyDenied, "activation plan is expired"};
    }
    if (manifest.expires_at_epoch_seconds - now_epoch_seconds >
        kMaximumPlanLifetimeSeconds) {
        return {StatusCode::kPolicyDenied, "activation plan lifetime exceeds 24 hours"};
    }

    output->module_id = manifest.module_id;
    output->target_package = manifest.target_package;
    output->payload_path = manifest.payload_path;
    output->payload_sha256 = manifest.payload_sha256;
    output->audit_steps = {
        "manifest_validated",
        "target_allowlist_matched",
        "payload_hash_verification_required",
        "operator_confirmation_required",
        "dry_run_only",
    };
    return Status::Ok();
}

std::size_t KpmDryRunPlanner::allowlist_size() const noexcept {
    return allowed_packages_.size();
}

}  // namespace rtgum

