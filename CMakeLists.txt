cmake_minimum_required(VERSION 3.20)

project(android_kernel_hook VERSION 0.1.0 LANGUAGES CXX)

option(RTGUM_BUILD_EXAMPLES "Build rt-gum examples" ON)
option(RTGUM_BUILD_TESTS "Build rt-gum tests" ON)
option(RTGUM_WITH_FRIDA_GUM "Enable the embedded Frida Gum lifecycle adapter" OFF)
option(RTGUM_WITH_LUA "Enable the Lua 5.4 lifecycle adapter" OFF)
set(RTGUM_FRIDA_GUM_DEVKIT "" CACHE PATH
    "Directory containing frida-gum.h and libfrida-gum.a for the target platform")

add_library(rtgum_core
    src/core/runtime.cpp
    src/activation/kpm_dry_run.cpp
    src/art/art_probe.cpp
    src/memory/memory_region.cpp
    src/loader/elf_image.cpp
    src/loader/module_runtime.cpp
    src/loader/system_library.cpp
)
add_library(rtgum::core ALIAS rtgum_core)

target_compile_features(rtgum_core PUBLIC cxx_std_17)
target_include_directories(rtgum_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)
target_link_libraries(rtgum_core PRIVATE ${CMAKE_DL_LIBS})

if(MSVC)
    target_compile_options(rtgum_core PRIVATE /W4 /permissive-)
else()
    target_compile_options(rtgum_core PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
endif()

if((RTGUM_WITH_FRIDA_GUM AND NOT RTGUM_FRIDA_GUM_DEVKIT) OR RTGUM_WITH_LUA)
    find_package(PkgConfig REQUIRED)
endif()

if(RTGUM_WITH_FRIDA_GUM)
    add_library(rtgum_gum_backend src/backends/gum_backend.cpp)
    add_library(rtgum::gum_backend ALIAS rtgum_gum_backend)
    target_compile_features(rtgum_gum_backend PUBLIC cxx_std_17)
    target_include_directories(rtgum_gum_backend PUBLIC include)
    target_link_libraries(rtgum_gum_backend PUBLIC rtgum::core)
    if(RTGUM_FRIDA_GUM_DEVKIT)
        if(NOT EXISTS "${RTGUM_FRIDA_GUM_DEVKIT}/frida-gum.h" OR
           NOT EXISTS "${RTGUM_FRIDA_GUM_DEVKIT}/libfrida-gum.a")
            message(FATAL_ERROR "RTGUM_FRIDA_GUM_DEVKIT needs frida-gum.h and libfrida-gum.a")
        endif()
        add_library(rtgum_frida_gum_devkit STATIC IMPORTED)
        set_target_properties(rtgum_frida_gum_devkit PROPERTIES
            IMPORTED_LOCATION "${RTGUM_FRIDA_GUM_DEVKIT}/libfrida-gum.a"
            INTERFACE_INCLUDE_DIRECTORIES "${RTGUM_FRIDA_GUM_DEVKIT}")
        target_link_libraries(rtgum_gum_backend PUBLIC rtgum_frida_gum_devkit)
        if(ANDROID)
            target_compile_definitions(rtgum_gum_backend PRIVATE ANDROID)
            target_link_libraries(rtgum_gum_backend PUBLIC log m dl)
        endif()
    else()
        pkg_check_modules(FRIDA_GUM REQUIRED IMPORTED_TARGET frida-gum-1.0)
        target_link_libraries(rtgum_gum_backend PUBLIC PkgConfig::FRIDA_GUM)
    endif()
endif()

if(RTGUM_WITH_LUA)
    pkg_check_modules(LUA54 REQUIRED IMPORTED_TARGET lua5.4)
    add_library(rtgum_lua_backend src/backends/lua_backend.cpp)
    add_library(rtgum::lua_backend ALIAS rtgum_lua_backend)
    target_compile_features(rtgum_lua_backend PUBLIC cxx_std_17)
    target_include_directories(rtgum_lua_backend PUBLIC include)
    target_link_libraries(rtgum_lua_backend PUBLIC rtgum::core PkgConfig::LUA54)
endif()

if(RTGUM_BUILD_EXAMPLES)
    add_executable(rtgum_probe examples/rtgum_probe.cpp)
    target_link_libraries(rtgum_probe PRIVATE rtgum::core)

    add_executable(rtgum_kpm_plan examples/rtgum_kpm_plan.cpp)
    target_link_libraries(rtgum_kpm_plan PRIVATE rtgum::core)

    if(RTGUM_WITH_FRIDA_GUM)
        add_executable(rtgum_gum_smoke examples/rtgum_gum_smoke.cpp)
        target_link_libraries(rtgum_gum_smoke PRIVATE rtgum::gum_backend)
        if(ANDROID)
            add_executable(rtgum_gum_lua_smoke examples/rtgum_gum_lua_smoke.cpp)
            target_link_libraries(rtgum_gum_lua_smoke PRIVATE rtgum::gum_backend)
        endif()
    endif()
endif()

if(RTGUM_BUILD_TESTS)
    enable_testing()
    add_executable(rtgum_tests tests/rtgum_tests.cpp)
    target_link_libraries(rtgum_tests PRIVATE rtgum::core)
    target_compile_definitions(rtgum_tests PRIVATE RTGUM_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
    add_test(NAME rtgum_tests COMMAND rtgum_tests)
endif()
