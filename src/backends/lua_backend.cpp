#include "rtgum/lua_backend.hpp"

#include <lauxlib.h>
#include <lua.h>

namespace rtgum {
namespace {

class LuaBackend final : public Component {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "lua-5.4";
    }

    Status Start() override {
        if (state_ != nullptr) {
            return Status::Ok();
        }
        state_ = luaL_newstate();
        if (state_ == nullptr) {
            return {StatusCode::kSystemError, "luaL_newstate failed"};
        }
        return Status::Ok();
    }

    void Stop() noexcept override {
        if (state_ != nullptr) {
            lua_close(state_);
            state_ = nullptr;
        }
    }

private:
    lua_State* state_{nullptr};
};

}  // namespace

std::unique_ptr<Component> CreateLuaBackend() {
    return std::make_unique<LuaBackend>();
}

}  // namespace rtgum
