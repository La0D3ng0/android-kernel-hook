#include "rtgum/module_runtime.hpp"

#include <filesystem>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <utility>

#include "rtgum/system_library.hpp"

namespace rtgum {
namespace {

class VisibleModuleImage final : public ModuleImage {
public:
    explicit VisibleModuleImage(std::unique_ptr<SystemLibrary> library)
        : library_(std::move(library)) {}

    Status FindSymbol(std::string_view name, void** output) override {
        return library_->FindSymbol(name, output);
    }

private:
    std::unique_ptr<SystemLibrary> library_;
};

bool ValidPackageName(std::string_view name) {
    if (name.empty() || name.size() > 255) return false;
    bool segment_start = true;
    bool has_dot = false;
    for (const char character : name) {
        if (character == '.') {
            if (segment_start) return false;
            segment_start = true;
            has_dot = true;
            continue;
        }
        const bool alpha = (character >= 'a' && character <= 'z') ||
                           (character >= 'A' && character <= 'Z');
        const bool digit = character >= '0' && character <= '9';
        if (!alpha && character != '_' && !(digit && !segment_start)) return false;
        segment_start = false;
    }
    return has_dot && !segment_start;
}

bool ValidModulePath(const std::string& path) {
    if (path.empty()) return false;
    const std::filesystem::path candidate(path);
    return candidate.is_absolute() && candidate.extension() == ".ghm";
}

bool ValidScriptPath(const std::string& path) {
    if (path.empty()) return true;
    const std::filesystem::path candidate(path);
    return candidate.is_absolute() && candidate.extension() == ".lua";
}

Status ReadScript(const std::string& path, std::string* output) {
    constexpr std::size_t kMaximumScriptSize = 256U * 1024U;
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input) return {StatusCode::kSystemError, "Lua script cannot be opened"};
    const std::streampos end = input.tellg();
    if (end < 0 || static_cast<std::uintmax_t>(end) > kMaximumScriptSize) {
        return {StatusCode::kIntegrityError, "Lua script is too large"};
    }
    const std::size_t size = static_cast<std::size_t>(end);
    input.seekg(0);
    std::string script(size, '\0');
    if (size != 0 && !input.read(&script[0], static_cast<std::streamsize>(size))) {
        return {StatusCode::kSystemError, "Lua script read failed"};
    }
    if (script.find('\0') != std::string::npos) {
        return {StatusCode::kIntegrityError, "Lua script contains NUL bytes"};
    }
    *output = std::move(script);
    return Status::Ok();
}

}  // namespace

Status VisibleModuleLoader::Open(const std::string& absolute_path,
                                 std::unique_ptr<ModuleImage>* output) {
    if (!output) return {StatusCode::kInvalidArgument, "output must not be null"};
    output->reset();
    std::unique_ptr<SystemLibrary> library;
    const Status status = SystemLibrary::Open(absolute_path, &library);
    if (!status.ok()) return status;
    output->reset(new VisibleModuleImage(std::move(library)));
    return Status::Ok();
}

ModuleRuntime::ModuleRuntime(GhostApi* api, ModuleLoader* loader, Drain drain)
    : api_(api), loader_(loader), drain_(std::move(drain)) {}

ModuleRuntime::~ModuleRuntime() {
    if (!Unload().ok()) {
        // Retain the mapping if the host could not prove callbacks are quiescent.
        (void)image_.release();
    }
}

Status ModuleRuntime::Configure(std::vector<ModuleSelection> selections) {
    for (std::size_t index = 0; index < selections.size(); ++index) {
        const auto& selection = selections[index];
        if (!ValidPackageName(selection.package_name) ||
            !ValidModulePath(selection.absolute_path) ||
            !ValidScriptPath(selection.script_path)) {
            return {StatusCode::kInvalidArgument, "invalid package or module path"};
        }
        for (std::size_t prior = 0; prior < index; ++prior) {
            if (selections[prior].package_name == selection.package_name) {
                return {StatusCode::kInvalidArgument, "duplicate package configuration"};
            }
        }
    }
    std::lock_guard<std::mutex> lock(mutex_);
    selections_ = std::move(selections);
    return Status::Ok();
}

Status ModuleRuntime::LoadForPackage(std::string_view package_name) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (image_) return {StatusCode::kInvalidState, "a module is already active"};
    return LoadLocked(package_name);
}

Status ModuleRuntime::ReloadForPackage(std::string_view package_name) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!image_ || active_package_ != package_name) {
        return {StatusCode::kInvalidState, "package has no active module"};
    }
    const Status cleared = UnloadLocked();
    if (!cleared.ok()) return cleared;
    return LoadLocked(package_name);
}

Status ModuleRuntime::Unload() {
    std::lock_guard<std::mutex> lock(mutex_);
    return UnloadLocked();
}

bool ModuleRuntime::active() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return image_ != nullptr;
}

std::string ModuleRuntime::active_package() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return active_package_;
}

Status ModuleRuntime::LoadLocked(std::string_view package_name) {
    if (!api_ || api_->version != RTGUM_GHOST_API_VERSION || !loader_ || !drain_) {
        return {StatusCode::kInvalidArgument, "module host is incomplete"};
    }
    const ModuleSelection* selected = nullptr;
    for (const auto& entry : selections_) {
        if (entry.package_name == package_name) {
            selected = &entry;
            break;
        }
    }
    if (!selected) return {StatusCode::kPolicyDenied, "package is not configured"};

    std::unique_ptr<ModuleImage> candidate;
    Status status = loader_->Open(selected->absolute_path, &candidate);
    if (!status.ok()) return status;
    if (!candidate) return {StatusCode::kSystemError, "module loader returned no image"};

    void* entry = nullptr;
    status = candidate->FindSymbol("ghostEntry", &entry);
    if (!status.ok() || !entry) {
        return {StatusCode::kIntegrityError, "module has no ghostEntry"};
    }
    void* unload = nullptr;
    (void)candidate->FindSymbol("ghostModuleUnload", &unload);

    image_ = std::move(candidate);
    active_package_ = std::string(package_name);
    unload_entry_ = reinterpret_cast<GhostModuleUnload>(unload);
    unload_callback_done_ = false;
    script_started_ = false;
    try {
        reinterpret_cast<GhostEntry>(entry)(api_);
    } catch (...) {
        const Status cleared = UnloadLocked();
        if (!cleared.ok()) return cleared;
        return {StatusCode::kSystemError, "module entry threw an exception"};
    }
    if (!selected->script_path.empty()) {
        const HostApiV2* host = api_->host;
        const unsigned long minimum_size =
            offsetof(HostApiV2, lua_stop) + sizeof(host->lua_stop);
        if (!host || host->version != RTGUM_HOST_API_V2_VERSION ||
            host->size < minimum_size ||
            (host->capabilities & RTGUM_HOST_CAP_LUA) == 0UL ||
            !host->lua_eval || !host->lua_stop) {
            const Status cleared = UnloadLocked();
            if (!cleared.ok()) return cleared;
            return {StatusCode::kUnsupported, "Lua host capability is unavailable"};
        }
        std::string script;
        status = ReadScript(selected->script_path, &script);
        if (!status.ok()) {
            const Status cleared = UnloadLocked();
            return cleared.ok() ? status : cleared;
        }
        char error[256]{};
        script_started_ = true;
        long result = 0;
        try {
            result = host->lua_eval(script.c_str(), error, sizeof(error));
        } catch (...) {
            result = RTGUM_HOST_ERR_NXIO;
        }
        if (result != 0) {
            const Status cleared = UnloadLocked();
            if (!cleared.ok()) return cleared;
            return {StatusCode::kSystemError,
                    error[0] ? error : "Lua script evaluation failed"};
        }
    }
    return Status::Ok();
}

Status ModuleRuntime::UnloadLocked() {
    if (!image_) return Status::Ok();
    Status drained;
    try {
        drained = drain_();
    } catch (...) {
        return {StatusCode::kSystemError, "module drain threw an exception"};
    }
    if (!drained.ok()) return drained;
    if (!unload_callback_done_) {
        unload_callback_done_ = true;
        if (unload_entry_) {
            try {
                unload_entry_(api_);
            } catch (...) {
                return {StatusCode::kSystemError, "module unload callback threw"};
            }
        }
    }
    if (script_started_) {
        const HostApiV2* host = api_->host;
        long stopped = RTGUM_HOST_ERR_NOTSUP;
        try {
            if (host && host->lua_stop) stopped = host->lua_stop();
        } catch (...) {
            stopped = RTGUM_HOST_ERR_NXIO;
        }
        if (stopped != 0) {
            return {StatusCode::kSystemError, "Lua VM could not be stopped"};
        }
        script_started_ = false;
    }
    image_.reset();
    unload_entry_ = nullptr;
    unload_callback_done_ = false;
    active_package_.clear();
    return Status::Ok();
}

}  // namespace rtgum
