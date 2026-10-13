# art-hook

`art-hook` is an independent C++23 migration project based on the module
boundaries of `frida-java-bridge/lib`. It does not modify or generate files in
the upstream repository.

The current implementation is an Android-first native core. It replaces
JavaScript runtime conveniences with typed C++ APIs and standard JNI calls:

- status and result propagation;
- thread-safe LRU and one-time memoization;
- generic decoded-instruction scanning;
- page-backed code allocation with W^X sealing;
- ARM64 trampolines with GPR, SIMD, NZCV, FPCR, and FPSR context capture;
- runtime-probed `ArtMethod` layouts, transactional field patching, and
  conflict-aware rollback;
- a process-wide recursive ART thread-suspension gate that serializes separate
  gate instances and guarantees ResumeAll on mutation failures;
- safe exact/masked `ArtMethod` flag updates, API-dependent hook policy, and
  explicit visibility/final/native controls;
- an `ArtQuickHook` composition layer plus one-step `HookMethodSafe`;
- paired `ArtMethodInterceptor` entry/return trampolines with raw ARM64
  `on_enter` and `on_leave` callbacks;
- version-neutral Gum Interceptor inline hooks, instruction probes, native
  replacements with original-function bridges, transactions, and rollback;
- API-routed selective, full, and boot-image deoptimization through
  caller-supplied, version-checked ART wrappers and a Runnable-state gate;
- JNI type and method descriptor parsing;
- `JavaVM` thread attachment and local-reference RAII;
- the JVMTI operations used by the source bridge;
- ART/runtime discovery without hard-coded private offsets;
- JNI reflection-based class models;
- standalone Mako JNI reflection preparation, method resolution by name or
  `Method` object, and reflection-derived shorty values;
- owned Java object/class proxies with lazy inherited member lookup, exact
  overload dispatch, constructors, fields, and virtual/direct/static JNI calls;
- versioned HotSpot Method/ConstMethod cloning, native replacement,
  methods-array/vtable/jmethodID installation, original-call resolution,
  rollback, and code-sweep routing;
- LSPlant-backed ART method hook/unhook and inline deoptimization through a
  project-owned C++ facade;
- a project-encoded ARM64 LSPlant ArtMethod bridge, while retaining the full
  ARM64 callback-context trampoline for C++ and future Lua dispatch;
- native method registration and in-memory DEX class loading;
- single-class DEX generation with fields, overloaded native methods, and a
  generated default constructor.

## Build

The checked-in build script uses NDK r29, CMake 3.31.12, and Ninja 1.13.2 to
produce ARM64 C++23 binaries:

```powershell
E:\rt-gum-sdk\art-hook\tools\build-android.ps1
```

Artifacts are written to `out/android-arm64-cxx23/`:

- `art_hook_tests`: standalone native tests;
- `libart-hook.so`: JNI-loadable shared library.
- `libmako.so`: independent JNI reflection component (no Daemon or LSPlant
  link dependency).
- `libart-hook-live-test.so`: test-only live `ArtMethod` lifecycle harness.
- `libart-hook-gum-live-test.so`: test-only ARM64 Gum inline-hook harness.
- `libart-hook-java-proxy-live-test.so`: test-only real-JNI proxy harness.

The same sources may be consumed through `CMakeLists.txt` with an Android
toolchain file. Public headers use `.h` consistently and are under
`include/art_hook/`; `api.h` is the umbrella include.

## Compatibility Boundary

This is not a source-to-source transpilation. Frida Java Bridge relies on
JavaScript proxies, `NativeFunction`, `NativeCallback`, Gum Interceptor, runtime
machine-code writers, and private ART structures. Those concepts have no
automatic C++ equivalent.

`ArtMethod` mutation is available only after a known native probe identifies
the layout and the caller supplies version-correct thread-state and ART
wrappers. The library does not guess private symbols. Gum relocation is
available through the versioned adapter and an optional matching Frida Gum
devkit. Automatic private-runtime symbol discovery remains outside the
implemented boundary. JavaScript's property traps and implicit value coercion
become the explicit typed `JavaObjectProxy` API. HotSpot private calls are
supplied through `HotSpotMethodApi` and a VM-operation
`HotSpotMutationGate`.
See `MIGRATION_MATRIX.md`, `docs/ARM64_ARTMETHOD_TRAMPOLINE.md`,
`docs/MAKO.md`,
`docs/LSPLANT_BACKEND.md`,
`docs/ENTRYPOINT_DEOPTIMIZATION.md`, `docs/STW_FLAGS.md`, and
`docs/GUM_INTERCEPTOR.md`, and `docs/JAVA_PROXY_HOTSPOT.md` for details.

## Minimal Use

```cpp
#include "art_hook/api.h"

art_hook::DexClassSpec spec;
spec.name = "Lre/frida/NativeProbe;";
spec.methods.push_back({"ping", "I", {"I"},
                        art_hook::kDexAccPublic |
                            art_hook::kDexAccNative});

art_hook::DexBuilder builder;
auto dex = builder.Build(std::move(spec));
if (!dex.ok()) {
  // dex.status().ToString()
}
```

## Provenance

The migration inventory was made from `frida-java-bridge` 7.0.13 at revision
`b38a5b6`, including the pre-existing local changes in `lib/android.js`.
Licensing and attribution are recorded in `NOTICE.md`.

The exact build, device, ART parser, class-loader, and JNI load results are in
`VERIFICATION.md`.
