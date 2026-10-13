cmake_minimum_required(VERSION 3.28)

project(art_hook VERSION 0.1.0 LANGUAGES CXX)

option(ART_HOOK_BUILD_TESTS "Build native unit tests" ON)
option(ART_HOOK_BUILD_SHARED "Build the Android JNI shared library" ON)
option(ART_HOOK_BUILD_MAKO "Build the standalone Mako reflection library" ON)
option(ART_HOOK_WITH_LSPLANT "Build the LSPlant ART backend" ON)
option(ART_HOOK_WITH_FRIDA_GUM "Build the official Frida Gum devkit adapter" OFF)
option(ART_HOOK_FRIDA_GUM_OPTIONS_API
       "Use the newer GumAttachOptions/GumReplaceOptions interceptor ABI" OFF)

add_library(art_hook_core STATIC
    src/arm64_trampoline.cpp
    src/art_deoptimization.cpp
    src/art_entrypoint.cpp
    src/art_flags.cpp
    src/art_method.cpp
    src/art_quick_hook.cpp
    src/class_factory.cpp
    src/class_model.cpp
    src/code_allocator.cpp
    src/dex.cpp
    src/gum_interceptor.cpp
    src/hotspot_method.cpp
    src/java_proxy.cpp
    src/jni_types.cpp
    src/jvmti.cpp
    src/lsplant_arm64_bridge.cpp
    src/runtime_api.cpp
    src/status.cpp
    src/vm.cpp
)
add_library(art_hook::core ALIAS art_hook_core)

target_compile_features(art_hook_core PUBLIC cxx_std_23)
target_include_directories(art_hook_core PUBLIC include)
set_target_properties(art_hook_core PROPERTIES POSITION_INDEPENDENT_CODE ON)

if(ART_HOOK_WITH_LSPLANT)
    if(NOT ANDROID)
        message(FATAL_ERROR "ART_HOOK_WITH_LSPLANT requires an Android toolchain")
    endif()

    set(LSPLANT_BUILD_SHARED OFF CACHE BOOL "" FORCE)
    set(DEX_BUILDER_BUILD_SHARED OFF CACHE BOOL "" FORCE)
    add_subdirectory(
        third_party/lsplant/lsplant/src/main/jni
        third_party/lsplant-build
        EXCLUDE_FROM_ALL
    )
    target_sources(art_hook_core PRIVATE src/lsplant_backend.cpp)
    target_link_libraries(art_hook_core PUBLIC lsplant_static)
    target_compile_definitions(art_hook_core PUBLIC ART_HOOK_HAS_LSPLANT=1)
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        target_compile_options(lsplant_static PRIVATE
            -Wno-gnu-string-literal-operator-template
        )
    endif()
endif()

if(ART_HOOK_WITH_FRIDA_GUM)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(FRIDA_GUM REQUIRED IMPORTED_TARGET frida-gum-1.0)
    target_sources(art_hook_core PRIVATE src/gum_interceptor_devkit.cpp)
    target_link_libraries(art_hook_core PUBLIC PkgConfig::FRIDA_GUM)
    if(ART_HOOK_FRIDA_GUM_OPTIONS_API)
        target_compile_definitions(art_hook_core PRIVATE
            ART_HOOK_FRIDA_GUM_OPTIONS_API=1
        )
    endif()
endif()

if(MSVC)
    target_compile_options(art_hook_core PRIVATE /W4 /permissive-)
else()
    target_compile_options(art_hook_core PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion -Wshadow
    )
endif()

if(ANDROID)
    target_link_libraries(art_hook_core PUBLIC android log dl)
endif()

if(ART_HOOK_BUILD_SHARED)
    if(NOT ANDROID)
        message(FATAL_ERROR "ART_HOOK_BUILD_SHARED requires an Android toolchain")
    endif()

    add_library(art-hook SHARED
        src/jni_entry.cpp
    )
    target_compile_features(art-hook PRIVATE cxx_std_23)
    target_include_directories(art-hook PRIVATE include)
    target_link_libraries(art-hook PRIVATE art_hook::core dl)
    target_link_options(art-hook PRIVATE
        "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/art-hook.map.txt"
    )
    set_target_properties(art-hook PROPERTIES
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN YES
    )
endif()

if(ART_HOOK_BUILD_MAKO)
    if(NOT ANDROID)
        message(FATAL_ERROR "ART_HOOK_BUILD_MAKO requires an Android toolchain")
    endif()

    # Mako's public-reflection entrypoint is a separate DSO. It deliberately
    # does not link the LSPlant backend or the Daemon.
    add_library(mako SHARED src/mako.cpp src/mako_reflection_cache.cpp)
    target_compile_features(mako PRIVATE cxx_std_17)
    target_include_directories(mako PUBLIC include)
    target_link_options(mako PRIVATE
        "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/art-mako.map.txt"
    )
    set_target_properties(mako PROPERTIES
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN YES
    )

    # A small JNI cache owner can be loaded and prepared before fork, while
    # Mako itself remains a child-only, on-demand DSO.
    add_library(mako-cache SHARED src/mako_seed.cpp src/mako_reflection_cache.cpp)
    target_compile_features(mako-cache PRIVATE cxx_std_17)
    target_include_directories(mako-cache PUBLIC include)
    target_link_options(mako-cache PRIVATE
        "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/art-mako-cache.map.txt"
    )
    set_target_properties(mako-cache PROPERTIES
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN YES
    )

    # Ghost-loadable hook engine for the KPM remote linker. Static libc++ keeps
    # DT_NEEDED small; the authoritative build is tools/build-mako-ghost.ps1.
    add_library(mako-ghost SHARED
        src/mako_ghost.cpp
        src/ghost_jump_pool.cpp
        src/arm64_trampoline.cpp
        src/status.cpp
        src/art_method.cpp
        src/code_allocator.cpp
    )
    target_compile_features(mako-ghost PRIVATE cxx_std_17)
    target_include_directories(mako-ghost PRIVATE include src)
    target_link_options(mako-ghost PRIVATE
        "-static-libstdc++"
        "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/art-mako-ghost.map.txt"
    )
    set_target_properties(mako-ghost PROPERTIES
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN YES
    )
endif()

if(ART_HOOK_BUILD_TESTS)
    enable_testing()
    add_executable(art_hook_tests tests/art_hook_tests.cpp)
    target_compile_features(art_hook_tests PRIVATE cxx_std_23)
    target_link_libraries(art_hook_tests PRIVATE art_hook::core)
    add_test(NAME art_hook_tests COMMAND art_hook_tests)

    if(ANDROID)
        if(ART_HOOK_BUILD_MAKO)
            add_library(mako-live-test SHARED tests/mako_live_test.cpp)
            target_compile_features(mako-live-test PRIVATE cxx_std_17)
            target_include_directories(mako-live-test PRIVATE include)
            target_link_libraries(mako-live-test PRIVATE dl)
            target_link_options(mako-live-test PRIVATE
                "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/art-mako-live-test.map.txt"
            )
            set_target_properties(mako-live-test PROPERTIES
                CXX_VISIBILITY_PRESET hidden
                VISIBILITY_INLINES_HIDDEN YES
            )
        endif()

        add_library(art-hook-live-test SHARED
            tests/art_method_live_test.cpp
        )
        target_compile_features(art-hook-live-test PRIVATE cxx_std_23)
        target_include_directories(art-hook-live-test PRIVATE include)
        target_link_libraries(art-hook-live-test PRIVATE art_hook::core dl)
        target_link_options(art-hook-live-test PRIVATE
            "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/art-hook-live-test.map.txt"
        )
        set_target_properties(art-hook-live-test PROPERTIES
            CXX_VISIBILITY_PRESET hidden
            VISIBILITY_INLINES_HIDDEN YES
        )

        add_library(art-hook-gum-live-test SHARED
            tests/gum_interceptor_live_test.cpp
        )
        target_compile_features(art-hook-gum-live-test PRIVATE cxx_std_23)
        target_include_directories(art-hook-gum-live-test PRIVATE include)
        target_link_libraries(art-hook-gum-live-test PRIVATE art_hook::core dl)
        target_link_options(art-hook-gum-live-test PRIVATE
            "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/art-hook-gum-live-test.map.txt"
        )
        set_target_properties(art-hook-gum-live-test PROPERTIES
            CXX_VISIBILITY_PRESET hidden
            VISIBILITY_INLINES_HIDDEN YES
        )

        add_library(art-hook-java-proxy-live-test SHARED
            tests/java_proxy_live_test.cpp
        )
        target_compile_features(art-hook-java-proxy-live-test PRIVATE cxx_std_23)
        target_include_directories(art-hook-java-proxy-live-test PRIVATE include)
        target_link_libraries(art-hook-java-proxy-live-test PRIVATE art_hook::core dl)
        target_link_options(art-hook-java-proxy-live-test PRIVATE
            "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/art-hook-java-proxy-live-test.map.txt"
        )
        set_target_properties(art-hook-java-proxy-live-test PROPERTIES
            CXX_VISIBILITY_PRESET hidden
            VISIBILITY_INLINES_HIDDEN YES
        )

        add_library(rtgum-jnicode-java-hook SHARED
            ${CMAKE_CURRENT_SOURCE_DIR}/../tests/jnicode-java-hook-test.cpp
        )
        target_compile_features(rtgum-jnicode-java-hook PRIVATE cxx_std_23)
        target_include_directories(rtgum-jnicode-java-hook PRIVATE
            include
            ${CMAKE_CURRENT_SOURCE_DIR}/../include
        )
        target_link_libraries(rtgum-jnicode-java-hook PRIVATE art_hook::core log dl)
        target_link_options(rtgum-jnicode-java-hook PRIVATE
            "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/../tests/jnicode-java-hook-test.map.txt"
        )
        set_target_properties(rtgum-jnicode-java-hook PROPERTIES
            CXX_VISIBILITY_PRESET hidden
            VISIBILITY_INLINES_HIDDEN YES
            OUTPUT_NAME rtgum-jnicode-java-hook
        )
    endif()
endif()
