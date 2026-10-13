# Migration Matrix

| JavaScript source | C++ destination | Status | Notes |
|---|---|---|---|
| `alloc.js` | `code_allocator.h/.cpp` | Implemented | Page slices, alignment, near validation, recycle, and W^X sealing. |
| `android.d.ts` | `runtime_api.h`, `vm.h` | Partial | Runtime discovery and typed handles exist; ART stack visitor is pending. |
| `android.js` | `runtime_api.h/.cpp`, `art_method.h/.cpp`, `art_flags.h/.cpp`, `arm64_trampoline.h/.cpp`, `art_quick_hook.h/.cpp`, `art_entrypoint.h/.cpp`, `art_deoptimization.h/.cpp`, `gum_interceptor.h/.cpp`, `lsplant_backend.h/.cpp`, `lsplant_arm64_bridge.h/.cpp` | Partial | LSPlant now owns version-dependent ART method backup, hook/unhook, and inline deoptimization. Its AArch64 ArtMethod bridge request is validated and re-emitted by the project W^X allocator; the full callback-context trampoline remains project-owned. Paired entry/return interception, process-wide STW, flag updates, and Gum transactions remain available. A production inline-hook provider and full `.dynsym`/`.symtab` `libart.so` resolver are still explicit embedding services; API 21/22 object cloning, backtrace, global ART patches, and typed Java callback marshalling remain. |
| `api.js` | `api.h`, `runtime_api.h/.cpp` | Native replacement | Runtime selection is represented by `RuntimeFlavor`. |
| `class-factory.js` | `class_factory.h/.cpp`, `java_proxy.h/.cpp` | Partial | Class lookup, native registration, memory DEX loading, loader-based class lookup, owned wrapper handles, lazy proxy member lookup, hierarchy traversal, exact overload dispatch, constructors, fields, virtual/direct/static JNI calls, clone, identity, and disposal are implemented. JavaScript property assignment, implicit value coercion, `choose`, and loader cache semantics remain. |
| `class-model.js` | `class_model.h/.cpp` | Native replacement | Fields, methods, constructors, descriptors, and modifiers are enumerated through JNI reflection. Private ART/JVMTI bulk enumeration remains. |
| `env.js` | `vm.h/.cpp` plus standard `JNIEnv` | Native replacement | JNI already provides the complete typed vtable in C++; helpers cover strings, class names, exceptions, and local refs. |
| `jvm.js` | `runtime_api.h/.cpp`, `hotspot_method.h/.cpp` | Partial | Versioned Method/ConstMethod and InstanceKlass layouts, cloning, native preparation, methods-array/vtable/jmethodID installation, old/obsolete flags, original-target resolution, rollback, sweep routing, and failed-sweep lifetime retention are implemented. Private HotSpot symbol discovery, x64 vtable-offset decoding, and VMThread wrappers remain embedding backends. |
| `jvmti.js` | `jvmti.h/.cpp` | Implemented | Deallocate, loaded classes, instance iteration, tag lookup, and capability request are mapped to the JVMTI ABI used by the source. |
| `lru.js` | `lru.h` | Implemented | Thread-safe LRU with replacement/eviction destruction. |
| `machine-code.js` | `instruction_scan.h` | Implemented | Decoder-independent instruction walk with previous-instruction context. |
| `memoize.js` | `memoize.h` | Implemented | Thread-safe first-successful-computation semantics. |
| `mkdex.js` | `dex.h/.cpp` | Partial | Single-class DEX, fields, interfaces, overloaded methods, default constructor, hashes, and map are implemented. Throws annotations and multi-class emission remain. |
| `result.js` | `status.h/.cpp`, `jni_result.h` | Implemented | Typed status/result and JNI error conversion. |
| `types.js` | `jni_types.h/.cpp` | Partial | Primitive/object/array descriptors, method descriptors, slot sizes, and shorties are implemented. JS boxing, wrapper compatibility, and primitive-array proxy behavior become typed JNI call-site responsibilities. |
| `vm.js` | `vm.h/.cpp` | Implemented | Attach/get-env/detach lifetime is RAII-based; local refs are move-only. |

## Verification Gates

The following gates define “working” for implemented rows:

1. NDK r29 arm64 C++23 build through CMake 3.31 with module scanning and
   warnings enabled.
2. Standalone native tests pass on the target Android device.
3. Generated DEX passes an Android DEX parser or class-loader smoke test.
4. `libart-hook.so` loads through a real `JavaVM` and reports JNI 1.6.
5. The upstream repository has no new working-tree changes after the build.

The ARM64 trampoline and live `ArtMethod` activation add a further gate: the
generated instructions must execute in a controlled target process and the
target method must be restored successfully. This gate passed on Android API
30, including 1024 paired entry/return calls and ten consecutive live
suspend/activate/call/revert cycles. Redirecting compiled direct calls requires
a target-specific adapter for the implemented deoptimization interface or a
compiled-code backend.

The Gum gate additionally executes an ARM64 native target through attach,
probe, replace, the relocated original bridge, detach, and revert. The final
call after each rollback must return the unmodified result.

Rows marked **Partial** or **Pending backend** are not included in a claim of
full behavioral parity.

The LSPlant bridge adds a fail-closed gate: the exact bridge request emitted by
the pinned LSPlant revision must decode successfully, the replacement bridge
must be W^X sealed, and its allocator/recycler lifecycle must pass on the target
ARM64 device. Full `LsplantBackend::Hook()` integration additionally requires
the embedding process to supply its inline-hook and complete ELF symbol
resolver services.
