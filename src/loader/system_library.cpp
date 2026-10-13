#include "rtgum/system_library.hpp"

#include <filesystem>
#include <utility>

#if defined(_WIN32)
#include <windows.h>
#else
#include <dlfcn.h>
#endif

namespace rtgum {

SystemLibrary::SystemLibrary(void* handle, std::string path) noexcept
    : handle_(handle), path_(std::move(path)) {}

SystemLibrary::~SystemLibrary() {
    if (handle_ == nullptr) {
        return;
    }
#if defined(_WIN32)
    (void)FreeLibrary(static_cast<HMODULE>(handle_));
#else
    (void)dlclose(handle_);
#endif
}

Status SystemLibrary::Open(const std::string& absolute_path,
                           std::unique_ptr<SystemLibrary>* output) {
    if (output == nullptr) {
        return {StatusCode::kInvalidArgument, "output must not be null"};
    }
    output->reset();
    if (absolute_path.empty() || !std::filesystem::path(absolute_path).is_absolute()) {
        return {StatusCode::kInvalidArgument,
                "library path must be an absolute filesystem path"};
    }

#if defined(_WIN32)
    HMODULE handle = LoadLibraryA(absolute_path.c_str());
    if (handle == nullptr) {
        return {StatusCode::kSystemError, "LoadLibraryA failed"};
    }
    void* raw_handle = handle;
#else
    dlerror();
    void* raw_handle = dlopen(absolute_path.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (raw_handle == nullptr) {
        const char* error = dlerror();
        return {StatusCode::kSystemError,
                error == nullptr ? "dlopen failed" : error};
    }
#endif

    output->reset(new SystemLibrary(raw_handle, absolute_path));
    return Status::Ok();
}

Status SystemLibrary::FindSymbol(std::string_view name, void** output) const {
    if (output == nullptr || name.empty()) {
        return {StatusCode::kInvalidArgument,
                "symbol name and output must be provided"};
    }
    *output = nullptr;
    const std::string owned_name(name);

#if defined(_WIN32)
    FARPROC symbol = GetProcAddress(static_cast<HMODULE>(handle_), owned_name.c_str());
    if (symbol == nullptr) {
        return {StatusCode::kSystemError, "GetProcAddress failed"};
    }
    *output = reinterpret_cast<void*>(symbol);
#else
    dlerror();
    void* symbol = dlsym(handle_, owned_name.c_str());
    const char* error = dlerror();
    if (error != nullptr) {
        return {StatusCode::kSystemError, error};
    }
    *output = symbol;
#endif
    return Status::Ok();
}

const std::string& SystemLibrary::path() const noexcept {
    return path_;
}

}  // namespace rtgum

