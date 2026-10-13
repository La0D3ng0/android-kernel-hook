# README

> Thanks to the authors whose ideas inspired this project. The implementation
> was later extended and refined. References:
>
> https://bbs.kanxue.com/thread-290718.htm
>
> https://mp.weixin.qq.com/s/qxnGYSdayzhOUXUE1gqP9A?click_id=887424564
>
> https://bbs.kanxue.com/thread-292175.htm
>
> https://github.com/kkkbbb/mkpms

**A modular in-process instrumentation framework for Android ARM64.** It uses
KernelPatch, Frida Gum and Lua to provide native hooks, ART hooks, shadow pages,
tracing, DBI, in-memory DEX loading, a `.ghm` module runtime and an Android
Manager.

[中文](README.md)

> [!IMPORTANT]
>
> - android-kernel-hook is intended for devices you own, test applications and
>   explicitly authorized security research. Kernel modules, temporary boot
>   images and Zygote experiments can reboot a device. Back up your data and
>   make sure fastboot recovery is available before testing.
> - Pixel 8 or Pixel 9 devices are recommended because they support EPAN.
>   Devices without EPAN require complex instruction emulation in the KPM. An
>   earlier Xiaomi test device was particularly prone to crashes.

## Device environment

The following is the device configuration used for development and testing:

- Device: `Pixel 8`
- Fingerprint: `google/shiba/shiba:16/CP1A.260405.005/15001963:user/release-keys`
- Android: `16`
- ABI: `arm64-v8a`
- Kernel: `6.1.145-android14-11-gfa1d6308d1fe-ab14691759`

If your environment differs, review and adapt all device-specific settings
before rebuilding.

## Introduction

android-kernel-hook connects injection, module distribution and hook features
into one runtime:

```text
Manager selects applications and modules
        ↓
KernelPatch Module manages target processes, page tables and lifecycle
        ↓
Daemon loads .ghm / Gum / Lua / ART Hook inside the target process
        ↓
Modules enable hooks, traces, DEX or symbol lookup by package name
```

A module only includes the public header and exports `ghostEntry`. It does not
link against a separate SDK library:

```cpp
#include "rtgum/ghost_api.h"

extern "C" __attribute__((visibility("default")))
void ghostEntry(GhostApi *api) {
    if (api != nullptr && api->log != nullptr) {
        api->log("hello from android-kernel-hook module");
    }
}
```

## Features

| Area | Features |
| --- | --- |
| KPM / Daemon | ARM64 ELF loading, relocation, IFUNC, process lifecycle and hot reload |
| Module runtime | Package-based `.ghm` distribution through `GhostApi` / `HostApiV2` |
| Native hooks | Frida Gum Interceptor, replace/revert, Stalker and Lua bindings |
| ART hooks | Standalone mako backend, reflected method lookup and ART shadow data pages |
| Shadow pages | Dual code/data views, incremental patches and fork lifecycle handling |
| Trace / DBI | CPU single step, ring buffers, ARM64 relocation and per-handle trace contexts |
| Memory / symbols | Kernel cross-process access, VMA dump, ELF symbol cache and symbolization |
| Extensions | In-memory DEX, Binder/Linker interception and JNI lifecycle tracing |
| Manager | Application allowlist, module import, switches, pairing, status and logs |

## Current validation scope

- Primary device: Google Pixel 8 (`shiba`), ARM64.
- Primary OS: Android 16 / API 36.
- KPM baseline: KernelPatch 0.13.9; Stage 0 compatibility code uses 0.12.2.
- Windows toolchain: PowerShell 7, JDK 17, Android SDK 35, NDK r25c and r29.
- The base C++ runtime can be built with a regular CMake toolchain on Linux,
  macOS or Windows.

Other devices, kernels and Android releases require fresh validation of kernel
symbols, structure offsets and exception paths.

The `rtgum` package names, include paths, ABI symbols and artifact prefixes are
existing compatibility identifiers and can be left unchanged.

## Frida-detection boundary

On the tested device and samples, the kernel path does not require
`frida-server`, a listening socket or ptrace. `TracerPid` remains zero, and the
Gum/Lua ghost mappings are absent from target maps/smaps. These results show
that the project reduces common userspace Frida indicators.

This does not mean that the framework is completely invisible or undetectable
in every application. Memory signatures, code integrity, exception timing,
PAC/BTI behavior, KernelPatch/root indicators and vendor-specific checks still
require per-device and per-application validation. Only a limited set of APKs
has been tested so far, and this area will continue to be improved.

## Repository layout

```text
include/rtgum/   Public module and runtime interfaces
src/             Cross-platform base runtime
kpm/             KernelPatch module sources
art-hook/        mako / ART Hook implementation
manager-app/     Android Manager App
lab-apk/         Self-contained acceptance application
tests/           Host, JNI, Stage 2 and module fixtures
tools/           Build, deployment and device smoke-test scripts
patches/         Patches for pinned third-party dependencies
third_party/     Lightweight third-party sources kept in the repository
```

## Quick start

### 1. Install prerequisites

For the base tests:

- Git 2.35+
- CMake 3.20+
- A C++17 compiler: Clang, GCC or Visual Studio

For the complete Android build:

- PowerShell 7
- JDK 17
- Android SDK Platform 35 and Build Tools 35.0.0
- Android NDK r25c (`25.2.9519653`)
- Android NDK r29 (`29.0.14206865`)
- `adb` and `fastboot`

### 2. Fetch source dependencies

```powershell
git clone <your-repository-url> android-kernel-hook
Set-Location android-kernel-hook
pwsh ./tools/bootstrap-dependencies.ps1
pwsh ./tools/fetch-frida-gum-devkit.ps1
```

`bootstrap-dependencies.ps1` checks out pinned revisions and applies the
android-kernel-hook patches. Pass `-Force` when you intentionally want to
recreate the dependency directories.

### 3. Run host tests first

```powershell
cmake -S . -B build -DRTGUM_BUILD_TESTS=ON
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

On Linux or macOS you can also run:

```bash
./tools/build-host.sh
```

### 4. Build Android artifacts

The example below uses the default Android Studio SDK location. Adjust it for
your machine:

```powershell
$Sdk = "$env:LOCALAPPDATA\Android\Sdk"
$Ndk25 = "$Sdk\ndk\25.2.9519653"
$Ndk29 = "$Sdk\ndk\29.0.14206865"

pwsh ./tools/build-android.ps1 -NdkPath $Ndk25
pwsh ./tools/build-stage2-daemon.ps1 -NdkPath $Ndk25
pwsh ./tools/build-manager.ps1 -SdkPath $Sdk -NdkPath $Ndk25
pwsh ./tools/configure-manager-trust.ps1 -SdkPath $Sdk
pwsh ./tools/build-stage1-kpm-windows.ps1 -NdkPath $Ndk29
pwsh ./tools/build-stage1-client.ps1 -NdkPath $Ndk29
pwsh ./lab-apk/build-lab-apk.ps1 -SdkPath $Sdk
```

`configure-manager-trust.ps1` reads the certificate SHA-256 from the signed APK
and modifies only the local KernelPatch source. The repository does not store
your private key or certificate digest. Manager upgrades must keep using the
same keystore. If the keystore changes, run this script again and rebuild the
KPM. Generated files are written to `out/`.

### 5. Run a device smoke test

Confirm that the device is running the matching KernelPatch environment and
prepare your own superkey file. Protect your superkey, temporary session key,
boot image and device serial number.

```powershell
$Serial = '<adb-device-serial>'
$Adb = "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe"

pwsh ./tools/smoke-stage1-pixel8.ps1 `
  -Mode NoHooks `
  -DeviceSerial $Serial `
  -AdbPath $Adb `
  -SuperKeyFile '<path-to-your-superkey-file>'
```

`NoHooks` validates the KPM channel and cleanup paths first. After it passes,
select scenarios such as `ThreeApps`, `GumLuaTarget`, `DbiLab`, `AntiDebug`,
`DexLoader` or `Interceptors` as needed.

Use `-FreshBoot` only when a temporary boot image exactly matching the device
has already been prepared.

## Manager workflow

1. Build and install `out/manager-build/rtgum-manager-debug.apk`.
2. Open Manager and complete KernelPatch pairing.
3. Import a `.ghm` module from **Modules**.
4. Add a test application to the allowlist in **Apps** and enable its module.
5. Start the target application and inspect loading, hook and cleanup events in
   **Logs**.
6. Disable the application switch and restart it to verify that the module is
   no longer distributed.

## Troubleshooting

### **A dependency directory is missing**

Run `pwsh ./tools/bootstrap-dependencies.ps1`.

### **The Frida Gum devkit is missing**

Run `pwsh ./tools/fetch-frida-gum-devkit.ps1`. The script verifies the archive
SHA-256.

### **The NDK compiler cannot be found**

Pass the correct `-NdkPath`. Stage 2 uses r25c; the KPM and controller use r29.

### **The device reboots once after entering fastboot**

One reboot is expected when using `fastboot boot` with a temporary image.
Repeated reboots after Android starts are abnormal; stop the smoke test and
inspect serial, ramoops or kernel logs.

## Development status

Current acceptance testing for android-kernel-hook is focused on the Pixel 8.
Interfaces and device adaptations may still change. When reporting an issue,
include the build command, Android version, kernel version, KernelPatch version
and a minimal log with all secrets removed.

## License

This project is released under the [MIT License](LICENSE). Third-party projects
referenced or included in this repository remain subject to their respective
licenses and copyright notices.

## Disclaimer

- This project is intended only for lawful education, research, development,
  debugging and explicitly authorized security testing. You are responsible
  for complying with applicable laws and for obtaining permission from the
  owners of every device, application and dataset involved.
- Do not use this project for unauthorized access, surveillance, data
  collection, cheating, service disruption or circumvention of third-party
  security controls. You are solely responsible for legal liability, account
  actions and other consequences arising from your conduct.
- This project modifies the kernel, process page tables, Zygote and application
  runtime state. It can cause application crashes, device reboots, boot loops,
  data loss or an unbootable device. Back up important data and prepare an
  exactly matching factory image and fastboot recovery environment first.
- The project is currently validated mainly on the device configuration listed
  above. Compatibility with other devices, kernels or Android releases is not
  guaranteed. The project also makes no guarantee that it can bypass a given
  detection system, remain completely invisible or be suitable for production.
- The software is provided “AS IS”, without warranty of any kind, express or
  implied. To the maximum extent permitted by applicable law, the authors and
  contributors are not liable for direct, indirect, incidental, special or
  consequential damages arising from use of, or inability to use, the software.
- Names, trademarks, source code and licenses belonging to Frida, KernelPatch,
  Lua, LSPlant and other third-party components remain the property of their
  respective owners. You must also comply with their licenses and applicable
  platform terms.
