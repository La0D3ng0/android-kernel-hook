#pragma once

#include <memory>
#include <string>
#include <string_view>

#include "rtgum/status.hpp"

namespace rtgum {

class SystemLibrary final {
public:
    ~SystemLibrary();

    SystemLibrary(const SystemLibrary&) = delete;
    SystemLibrary& operator=(const SystemLibrary&) = delete;

    static Status Open(const std::string& absolute_path,
                       std::unique_ptr<SystemLibrary>* output);
    Status FindSymbol(std::string_view name, void** output) const;

    [[nodiscard]] const std::string& path() const noexcept;

private:
    SystemLibrary(void* handle, std::string path) noexcept;

    void* handle_{nullptr};
    std::string path_;
};

}  // namespace rtgum

