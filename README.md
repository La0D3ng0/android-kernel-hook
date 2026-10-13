# README

> 感谢大佬提供的思路，后续也优化了一些内容，参考链接：
>
> https://bbs.kanxue.com/thread-290718.htm
>
> https://mp.weixin.qq.com/s/qxnGYSdayzhOUXUE1gqP9A?click_id=887424564
>
> https://bbs.kanxue.com/thread-292175.htm
>
> https://github.com/kkkbbb/mkpms

**面向 Android ARM64 的模块化进程内插桩框架。** 以 KernelPatch、Frida Gum 和 Lua 为核心，提供原生 Hook、ART Hook、Shadow Page、Trace、DBI、DEX 内存加载、`.ghm` 模块运行时和 Android Manager。

[English](README_EN.md)

> [!IMPORTANT]
>
> - android-kernel-hook 面向自有设备、测试应用和已获授权的安全研究。内核模块、临时启动镜像和 Zygote 实验都有使设备重启的风险。请先备份数据，并确认能够进入 fastboot 恢复。
> - 推荐使用 pixel 8/9 手机进行操作，因为支持 EPAN ，如果设备不支持 EPAN 会很坑, 在 KPM 中做指令模拟确实能跑，但是太复杂，先前尝试过 xiaomi 的手机，非常容易崩

## 设备环境

以下是我自己使用的设备信息：

- 设备：`Pixel 8`
- Fingerprint：`google/shiba/shiba:16/CP1A.260405.005/15001963:user/release-keys`
- Android：`16`
- ABI：`arm64-v8a`
- Kernel：`6.1.145-android14-11-gfa1d6308d1fe-ab14691759`

各位重构的时候，如果不一致需要修改环境。

## android-kernel-hook  简介

android-kernel-hook 把注入、模块分发和 Hook 能力组合成一条完整链路：

```text
Manager 配置应用和模块
        ↓
KernelPatch Module 管理目标进程、页表和生命周期
        ↓
Daemon 在目标进程中加载 .ghm / Gum / Lua / ART Hook
        ↓
模块按包名启用 Hook、Trace、DEX 或符号解析功能
```

模块只需要包含公开头文件并导出 `ghostEntry`，无需链接独立 SDK 库：

```cpp
#include "rtgum/ghost_api.h"

extern "C" __attribute__((visibility("default")))
void ghostEntry(GhostApi *api) {
    if (api != nullptr && api->log != nullptr) {
        api->log("hello from android-kernel-hook module");
    }
}
```

## 主要能力

| 模块 | 能力 |
| --- | --- |
| KPM / Daemon | ARM64 ELF 加载、重定位、IFUNC、进程生命周期和热重载 |
| 模块运行时 | 按包名分发 `.ghm`，统一 `GhostApi` / `HostApiV2` 接口 |
| Native Hook | Frida Gum Interceptor、replace/revert、Stalker 和 Lua 绑定 |
| ART Hook | 独立 mako 后端、反射方法定位和 ART Shadow Data Page |
| Shadow Page | 代码页与数据页双视图、增量 patch 和 fork 生命周期处理 |
| Trace / DBI | CPU 单步、ring buffer、ARM64 指令重定位和多 Trace 上下文 |
| 内存与符号 | 内核跨进程读写、VMA dump、ELF 符号缓存和地址反查 |
| 扩展能力 | DEX 内存加载、Binder/Linker 拦截和 JNI 生命周期 Trace |
| Manager | 应用白名单、模块导入、开关、配对、状态和日志界面 |

## 当前验证范围

- 主要设备：Google Pixel 8 (`shiba`)，ARM64。
- 主要系统：Android 16 / API 36。
- KPM 基线：KernelPatch 0.13.9；Stage 0 兼容代码使用 0.12.2。
- Windows 构建链：PowerShell 7、JDK 17、Android SDK 35、NDK r25c 与 r29。
- 基础 C++ 运行时可以在普通 Linux/macOS/Windows CMake 环境中构建。

其他设备、内核或 Android 版本需要重新验证符号、结构偏移和异常处理路径。

源码中的 `rtgum` 包名、头文件路径、ABI 符号和产物名前缀是现有兼容标识，不必在意。

## 关于 Frida 检测

在已测设备和样本上，内核链路不需要 `frida-server`、监听端口或 ptrace，`TracerPid` 保持为 0，Gum/Lua 幽灵映射不会出现在目标进程的 maps/smaps 中。这些结果说明项目减少了常见用户态 Frida 暴露面。

这不代表对任意应用“完全无痕”或“不可检测”。内存特征、代码完整性、异常时序、PAC/BTI、KernelPatch/root 状态和厂商私有检测仍需逐设备、逐应用验证。目前只测试了部分 apk ，后续会继续迭代。

## 仓库结构

```text
include/rtgum/   模块和运行时公开接口
src/             跨平台基础运行时
kpm/             KernelPatch 模块源码
art-hook/        mako / ART Hook 实现
manager-app/     Android Manager App
lab-apk/         可自行构建的验收应用
tests/           主机、JNI、Stage 2 和模块夹具
tools/           构建、部署和真机烟测脚本
patches/         固定版本第三方依赖补丁
third_party/     随仓库保留的轻量第三方源码
```

## 快速开始

### 1. 准备环境

只运行基础测试时需要：

- Git 2.35+
- CMake 3.20+
- 支持 C++17 的 Clang、GCC 或 Visual Studio

构建 Android 全链路还需要：

- PowerShell 7
- JDK 17
- Android SDK Platform 35 与 Build Tools 35.0.0
- Android NDK r25c (`25.2.9519653`)
- Android NDK r29 (`29.0.14206865`)
- `adb` 与 `fastboot`

### 2. 拉取源码依赖

```powershell
git clone <your-repository-url> android-kernel-hook
Set-Location android-kernel-hook
pwsh ./tools/bootstrap-dependencies.ps1
pwsh ./tools/fetch-frida-gum-devkit.ps1
```

`bootstrap-dependencies.ps1` 会检出固定提交，并自动应用 android-kernel-hook 所需补丁。需要重新创建依赖目录时可以加 `-Force`。

### 3. 先运行主机测试

```powershell
cmake -S . -B build -DRTGUM_BUILD_TESTS=ON
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

Linux/macOS 也可以直接运行：

```bash
./tools/build-host.sh
```

### 4. 构建 Android 产物

下面示例使用 Android Studio 的默认 SDK 目录，请按实际安装位置修改：

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

`configure-manager-trust.ps1` 从已签名 APK 读取证书 SHA-256，并只修改本地 KernelPatch 源码；仓库不会保存你的私钥或证书摘要。Manager 升级必须继续使用同一份 keystore。更换 keystore 后，需要重新执行该脚本并重建 KPM。生成文件位于 `out/`

### 5. 运行真机烟测

先确认设备已经处于匹配的 KernelPatch 环境，并准备好自己的 superkey 文件。请保护好你的 superkey、临时 session key、boot 镜像或设备序列号。

```powershell
$Serial = '<adb-device-serial>'
$Adb = "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe"

pwsh ./tools/smoke-stage1-pixel8.ps1 `
  -Mode NoHooks `
  -DeviceSerial $Serial `
  -AdbPath $Adb `
  -SuperKeyFile '<path-to-your-superkey-file>'
```

`NoHooks` 先验证 KPM 通道和清理路径。确认通过后，再根据需要选择 `ThreeApps`、`GumLuaTarget`、`DbiLab`、`AntiDebug`、`DexLoader`、`Interceptors` 等模式。

注意，只有在已经准备好与当前设备完全匹配的临时 boot 镜像时才使用 `-FreshBoot`。

## Manager 使用流程

1. 构建并安装 `out/manager-build/rtgum-manager-debug.apk`。
2. 打开 Manager，完成 KernelPatch 配对。
3. 在 **Modules** 中导入 `.ghm` 模块。
4. 在 **Apps** 中把测试应用加入白名单并启用所需模块。
5. 启动目标应用，在 **Logs** 中检查模块加载、Hook 命中和清理结果。
6. 关闭应用开关后重新启动目标应用，确认模块不再分发。

## 常见问题

### **脚本提示依赖目录不存在**

运行 `pwsh ./tools/bootstrap-dependencies.ps1`。

### **找不到 Frida Gum devkit**

运行 `pwsh ./tools/fetch-frida-gum-devkit.ps1`。脚本会校验下载文件的 SHA-256。

### **找不到 NDK 编译器**

给构建脚本传入正确的 `-NdkPath`。Stage 2 使用 r25c，KPM 与控制端使用 r29。

### **设备进入 fastboot 后重启一次**

使用 `fastboot boot` 临时启动镜像时会发生一次正常重启。Android 启动后反复重启才是
异常，应停止烟测并检查串口、ramoops 或内核日志。

## 开发状态

android-kernel-hook 当前验收集中在 Pixel 8。接口和设备适配仍可能变化。提交问题时请提供构建命令、系统版本、内核版本、KernelPatch 版本和去除密钥后的最小日志。

## 许可证

本项目基于 [MIT License](LICENSE) 发布。仓库中引用或包含的第三方项目仍遵循其各自的许可证与版权声明。

## 免责声明

- 本项目仅用于合法的学习、研究、开发调试与已获明确授权的安全测试。使用者必须确保其操作符合所在地法律法规，并已取得设备、应用及数据所有者的授权。
- 请勿将本项目用于未经授权的访问、监控、数据获取、作弊、破坏服务或规避第三方安全机制。因使用者的行为产生的法律责任、账号处置或其他后果由使用者自行承担。
- 本项目会修改内核、进程页表、Zygote 及应用运行状态，可能导致应用崩溃、设备重启、启动循环、数据丢失或设备无法启动。请在操作前备份重要数据，并准备与设备完全匹配的原厂镜像和 fastboot 恢复环境。
- 项目目前主要在上述 Pixel 8 环境中验证，不保证兼容其他设备、内核或 Android 版本，也不保证能够绕过任何检测、保持完全无痕或适用于生产环境。
- 本软件按“原样”提供，不附带任何明示或默示保证。在适用法律允许的最大范围内，项目作者与贡献者不对使用或无法使用本软件造成的直接、间接、附带、特殊或后果性损失承担责任。
- Frida、KernelPatch、Lua、LSPlant 及其他第三方组件的名称、商标、源码与许可证归各自权利人所有；使用者还需遵守这些项目的许可证及相关平台条款。
