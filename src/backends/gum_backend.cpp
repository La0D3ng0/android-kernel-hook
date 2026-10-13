#include "rtgum/gum_backend.hpp"

#include <frida-gum.h>
#include <cstddef>
#include <mutex>

namespace rtgum {
namespace {

std::mutex g_gum_mutex;
std::size_t g_gum_users = 0;

long FindExport(const char* soname, const char* symbol, unsigned long* output) {
    if (!soname || !symbol || !output) return RTGUM_HOST_ERR_INVAL;
    *output = 0;
    std::lock_guard<std::mutex> lock(g_gum_mutex);
    if (g_gum_users == 0) return RTGUM_HOST_ERR_NXIO;
    GumModule* module = gum_process_find_module_by_name(soname);
    if (!module) return RTGUM_HOST_ERR_NOENT;
    const GumAddress address = gum_module_find_export_by_name(module, symbol);
    g_object_unref(module);
    if (address == 0) return RTGUM_HOST_ERR_NOENT;
    *output = static_cast<unsigned long>(address);
    return 0;
}

class GumBackend final : public Component {
public:
    ~GumBackend() override { Stop(); }

    [[nodiscard]] std::string_view name() const noexcept override {
        return "frida-gum";
    }

    Status Start() override {
        std::lock_guard<std::mutex> lock(g_gum_mutex);
        if (!started_) {
            if (g_gum_users == 0) gum_init_embedded();
            ++g_gum_users;
            started_ = true;
        }
        return Status::Ok();
    }

    void Stop() noexcept override {
        std::lock_guard<std::mutex> lock(g_gum_mutex);
        if (started_) {
            --g_gum_users;
            if (g_gum_users == 0) gum_deinit_embedded();
            started_ = false;
        }
    }

private:
    bool started_{false};
};

}  // namespace

std::unique_ptr<Component> CreateGumBackend() {
    return std::make_unique<GumBackend>();
}

Status BindGumReadOnlyHostApi(HostApiV2* host) {
    constexpr std::size_t kMinimumSize =
        offsetof(HostApiV2, find_export) + sizeof(host->find_export);
    if (!host || host->version != RTGUM_HOST_API_V2_VERSION ||
        host->size < kMinimumSize) {
        return {StatusCode::kInvalidArgument, "invalid HostApiV2 table"};
    }
    std::lock_guard<std::mutex> lock(g_gum_mutex);
    if (g_gum_users == 0) {
        return {StatusCode::kInvalidState, "Gum is not running"};
    }
    host->find_export = FindExport;
    host->capabilities |= RTGUM_HOST_CAP_FIND_EXPORT;
    return Status::Ok();
}

}  // namespace rtgum
