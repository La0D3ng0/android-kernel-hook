#!/usr/bin/env sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build_dir=${1:-"$project_dir/out/host"}
cxx=${CXX:-clang++}

mkdir -p "$build_dir"

common_flags="-std=c++17 -O2 -g -Wall -Wextra -Wpedantic -Wconversion -pthread"
includes="-I$project_dir/include"
sources="$project_dir/src/core/runtime.cpp $project_dir/src/activation/kpm_dry_run.cpp $project_dir/src/art/art_probe.cpp $project_dir/src/memory/memory_region.cpp $project_dir/src/loader/elf_image.cpp $project_dir/src/loader/module_runtime.cpp $project_dir/src/loader/system_library.cpp"

# shellcheck disable=SC2086
$cxx $common_flags $includes -DRTGUM_SOURCE_DIR=\"$project_dir\" $sources "$project_dir/tests/rtgum_tests.cpp" \
    -ldl -o "$build_dir/rtgum_tests"
# shellcheck disable=SC2086
$cxx $common_flags $includes $sources "$project_dir/examples/rtgum_probe.cpp" \
    -ldl -o "$build_dir/rtgum_probe"
$cxx $common_flags $includes $sources "$project_dir/examples/rtgum_kpm_plan.cpp" \
    -ldl -o "$build_dir/rtgum_kpm_plan"

"$build_dir/rtgum_tests"
"$build_dir/rtgum_probe"
