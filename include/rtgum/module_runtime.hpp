#pragma once

#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

#include "rtgum/ghost_api.h"
#include "rtgum/status.hpp"

namespace rtgum {

struct ModuleSelection {
    std::string package_name;
    std::string absolute_path;
    std::string script_path{};
};

class ModuleImage {
public:
    virtual ~ModuleImage() = default;
    virtual Status FindSymbol(std::string_view name, void** output) = 0;
};

class ModuleLoader {
public:
    virtual ~ModuleLoader() = default;
    virtual Status Open(const std::string& absolute_path,
                        std::unique_ptr<ModuleImage>* output) = 0;
};

// Loads modules through the ordinary platform loader in the current process.
class VisibleModuleLoader final : public ModuleLoader {
public:
    Status Open(const std::string& absolute_path,
                std::unique_ptr<ModuleImage>* output) override;
};

// The host must revoke module hooks and wait for module-owned work in Drain.
// A failed Drain keeps the image loaded so callbacks cannot point to unmapped code.
class ModuleRuntime final {
public:
    using Drain = std::function<Status()>;

    ModuleRuntime(GhostApi* api, ModuleLoader* loader, Drain drain);
    ~ModuleRuntime();

    ModuleRuntime(const ModuleRuntime&) = delete;
    ModuleRuntime& operator=(const ModuleRuntime&) = delete;

    Status Configure(std::vector<ModuleSelection> selections);
    Status LoadForPackage(std::string_view package_name);
    Status ReloadForPackage(std::string_view package_name);
    Status Unload();

    [[nodiscard]] bool active() const;
    [[nodiscard]] std::string active_package() const;

private:
    Status LoadLocked(std::string_view package_name);
    Status UnloadLocked();

    GhostApi* api_;
    ModuleLoader* loader_;
    Drain drain_;
    mutable std::mutex mutex_;
    std::vector<ModuleSelection> selections_;
    std::unique_ptr<ModuleImage> image_;
    GhostModuleUnload unload_entry_{nullptr};
    bool unload_callback_done_{false};
    bool script_started_{false};
    std::string active_package_;
};

}  // namespace rtgum
