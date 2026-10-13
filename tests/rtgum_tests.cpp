#include <array>
#include <cstdint>
#include <iostream>
#include <memory>
#include <string_view>
#include <vector>

#include "rtgum/art_probe.hpp"
#include "rtgum/elf_image.hpp"
#include "rtgum/elf_namespace.hpp"
#include "rtgum/elf_relr.hpp"
#include "rtgum/ghost_api.h"
#include "rtgum/gtrace.hpp"
#include "rtgum/kpm_dry_run.hpp"
#include "rtgum/memory_region.hpp"
#include "rtgum/module_runtime.hpp"
#include "rtgum/native_backend.hpp"
#include "rtgum/runtime.hpp"
#include "rtgum/system_library.hpp"

#include <cstddef>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>

namespace {

int failures = 0;

void Expect(bool condition, std::string_view message) {
    if (!condition) {
        ++failures;
        std::cerr << "FAIL: " << message << '\n';
    }
}

class RecordingComponent final : public rtgum::Component {
public:
    RecordingComponent(int id, bool fail_start, std::vector<int>* events)
        : id_(id), fail_start_(fail_start), events_(events) {}

    [[nodiscard]] std::string_view name() const noexcept override {
        return "recording-component";
    }

    rtgum::Status Start() override {
        events_->push_back(id_);
        if (fail_start_) {
            return {rtgum::StatusCode::kSystemError, "requested failure"};
        }
        started_ = true;
        return rtgum::Status::Ok();
    }

    void Stop() noexcept override {
        if (started_) {
            events_->push_back(-id_);
            started_ = false;
        }
    }

private:
    int id_;
    bool fail_start_;
    std::vector<int>* events_;
    bool started_{false};
};

void TestRuntimeRollback() {
    std::vector<int> events;
    rtgum::Runtime runtime;
    Expect(runtime.Add(std::make_unique<RecordingComponent>(1, false, &events)).ok(),
           "first component should be accepted");
    Expect(runtime.Add(std::make_unique<RecordingComponent>(2, true, &events)).ok(),
           "second component should be accepted");

    const rtgum::Status status = runtime.Start();
    Expect(!status.ok(), "runtime start should fail");
    Expect(runtime.state() == rtgum::RuntimeState::kFailed,
           "runtime should enter failed state");
    Expect(events == std::vector<int>({1, 2, -1}),
           "started components should roll back in reverse order");
    Expect(runtime.Stop().ok(), "failed runtime should be stoppable");
    Expect(events == std::vector<int>({1, 2, -1}),
           "stop after rollback should not stop inactive components again");
}

void TestMemoryRegionWxPolicy() {
    std::unique_ptr<rtgum::MemoryRegion> region;
    Expect(rtgum::MemoryRegion::Allocate(1, &region).ok(),
           "memory region should allocate");
    Expect(region != nullptr && region->writable() && !region->executable(),
           "new memory should be writable and non-executable");

    constexpr std::array<std::uint8_t, 4> bytes = {1, 2, 3, 4};
    Expect(region->Write(0, bytes.data(), bytes.size()).ok(),
           "write should work before sealing");
    Expect(region->SealExecutable().ok(), "sealing should work");
    Expect(!region->writable() && region->executable(),
           "sealed memory should be executable and non-writable");
    Expect(!region->Write(0, bytes.data(), bytes.size()).ok(),
           "write should fail after sealing");
}

void Put16(std::array<std::uint8_t, 64>* image, std::size_t offset,
           std::uint16_t value) {
    (*image)[offset] = static_cast<std::uint8_t>(value & 0xffU);
    (*image)[offset + 1] = static_cast<std::uint8_t>(value >> 8U);
}

void Put32(std::array<std::uint8_t, 64>* image, std::size_t offset,
           std::uint32_t value) {
    for (std::size_t index = 0; index < 4; ++index) {
        (*image)[offset + index] =
            static_cast<std::uint8_t>((value >> (index * 8U)) & 0xffU);
    }
}

void TestElfValidation() {
    std::array<std::uint8_t, 64> image{};
    image[0] = 0x7f;
    image[1] = 'E';
    image[2] = 'L';
    image[3] = 'F';
    image[4] = 2;
    image[5] = 1;
    Put16(&image, 16, 3);
    Put16(&image, 18, 183);
    Put32(&image, 20, 1);
    Put16(&image, 52, 64);
    Put16(&image, 54, 56);
    Put16(&image, 56, 0);

    rtgum::ElfImageInfo info;
    const rtgum::Status status =
        rtgum::ElfImageView(image.data(), image.size())
            .Validate64LittleEndian(&info);
    Expect(status.ok(), "minimal ELF64 header should validate");
    Expect(info.machine == 183, "ELF machine should be AArch64");

    image[0] = 0;
    Expect(!rtgum::ElfImageView(image.data(), image.size())
                .Validate64LittleEndian(&info)
                .ok(),
           "invalid ELF magic should fail");
}

void TestReadOnlyArtProbe() {
    rtgum::ArtRuntimeInfo info;
    Expect(rtgum::ProbeArtRuntime(&info).ok(),
           "read-only ART probe should complete");
    Expect(!rtgum::ProbeArtRuntime(nullptr).ok(),
           "ART probe should reject null output");
}

void TestSystemLibraryValidation() {
    std::unique_ptr<rtgum::SystemLibrary> library;
    Expect(!rtgum::SystemLibrary::Open("relative-library.so", &library).ok(),
           "system loader should reject relative paths");
    Expect(library == nullptr, "failed load should not return a library");
}

std::vector<std::string>* g_module_events = nullptr;

void TestModuleEntry(GhostApi*) {
    g_module_events->push_back("entry");
}

void TestModuleUnload(GhostApi*) {
    g_module_events->push_back("unload");
}

long TestLuaEval(const char* script, char*, unsigned long) {
    g_module_events->push_back(std::string("lua:") + script);
    return 0;
}

long TestLuaStop() {
    g_module_events->push_back("lua-stop");
    return 0;
}

class FakeModuleImage final : public rtgum::ModuleImage {
public:
    explicit FakeModuleImage(std::vector<std::string>* events) : events_(events) {}
    ~FakeModuleImage() override { events_->push_back("close"); }

    rtgum::Status FindSymbol(std::string_view name, void** output) override {
        if (!output) return {rtgum::StatusCode::kInvalidArgument, "null output"};
        *output = nullptr;
        if (name == "ghostEntry") {
            *output = reinterpret_cast<void*>(&TestModuleEntry);
        } else if (name == "ghostModuleUnload") {
            *output = reinterpret_cast<void*>(&TestModuleUnload);
        }
        return rtgum::Status::Ok();
    }

private:
    std::vector<std::string>* events_;
};

class FakeModuleLoader final : public rtgum::ModuleLoader {
public:
    explicit FakeModuleLoader(std::vector<std::string>* events) : events_(events) {}

    rtgum::Status Open(const std::string& path,
                       std::unique_ptr<rtgum::ModuleImage>* output) override {
        events_->push_back("open:" + path);
        output->reset(new FakeModuleImage(events_));
        return rtgum::Status::Ok();
    }

private:
    std::vector<std::string>* events_;
};

void TestModuleRuntimeReload() {
    std::vector<std::string> events;
    g_module_events = &events;
    FakeModuleLoader loader(&events);
    GhostApi api{};
    api.version = RTGUM_GHOST_API_VERSION;
    bool drain_blocked = false;
    rtgum::ModuleRuntime modules(&api, &loader, [&]() {
        events.push_back("drain");
        return drain_blocked
                   ? rtgum::Status(rtgum::StatusCode::kInvalidState, "work is live")
                   : rtgum::Status::Ok();
    });
#if defined(_WIN32)
    const std::string first = "C:\\rtgum\\first.ghm";
    const std::string second = "C:\\rtgum\\second.ghm";
#else
    const std::string first = "/tmp/rtgum/first.ghm";
    const std::string second = "/tmp/rtgum/second.ghm";
#endif
    Expect(!modules.Configure({{"com.example.app", first},
                               {"com.example.app", second}}).ok(),
           "duplicate package configuration should be rejected");
    Expect(modules.Configure({{"com.example.app", first}}).ok(),
           "valid module configuration should be accepted");
    Expect(!modules.LoadForPackage("com.example.app2").ok() && events.empty(),
           "package matching must be exact");
    Expect(modules.LoadForPackage("com.example.app").ok(),
           "configured module should load");
    Expect(modules.active() && modules.active_package() == "com.example.app",
           "active package should be recorded");
    Expect(modules.Configure({{"com.example.app", second}}).ok(),
           "replacement configuration should be accepted while active");
    drain_blocked = true;
    Expect(!modules.ReloadForPackage("com.example.app").ok() && modules.active(),
           "failed drain must retain old module image");
    Expect(events == std::vector<std::string>({"open:" + first, "entry", "drain"}),
           "failed drain must retain the image without calling module cleanup");
    drain_blocked = false;
    Expect(modules.ReloadForPackage("com.example.app").ok(),
           "reload should succeed after work drains");
    Expect(events == std::vector<std::string>({"open:" + first, "entry", "drain",
                                               "drain", "unload", "close",
                                               "open:" + second, "entry"}),
           "old image must close before replacement entry runs");
    Expect(modules.Unload().ok() && !modules.active(), "module should unload cleanly");
    Expect(events == std::vector<std::string>({"open:" + first, "entry", "drain",
                                               "drain", "unload", "close",
                                               "open:" + second, "entry", "drain",
                                               "unload", "close"}),
           "final unload should clear the replacement image");
    g_module_events = nullptr;
}

void TestModuleRuntimeScript() {
    std::vector<std::string> events;
    g_module_events = &events;
    FakeModuleLoader loader(&events);
    HostApiV2 host{};
    host.version = RTGUM_HOST_API_V2_VERSION;
    host.size = sizeof(host);
    host.capabilities = RTGUM_HOST_CAP_LUA;
    host.lua_eval = TestLuaEval;
    host.lua_stop = TestLuaStop;
    GhostApi api{};
    api.version = RTGUM_GHOST_API_VERSION;
    api.host = &host;
    rtgum::ModuleRuntime modules(&api, &loader, [&]() {
        events.push_back("drain");
        return rtgum::Status::Ok();
    });
    const std::filesystem::path script =
        std::filesystem::absolute("rtgum-module-runtime-test.lua");
    {
        std::ofstream output(script, std::ios::binary);
        output << "return 40 + 2";
    }
#if defined(_WIN32)
    const std::string module = "C:\\rtgum\\script.ghm";
#else
    const std::string module = "/tmp/rtgum/script.ghm";
#endif
    Expect(modules.Configure({{"com.example.lua", module, script.string()}}).ok(),
           "module and Lua script should configure together");
    Expect(modules.LoadForPackage("com.example.lua").ok(),
           "module entry and Lua script should start together");
    Expect(modules.Unload().ok(), "module and Lua VM should stop together");
    Expect(events == std::vector<std::string>({"open:" + module, "entry",
                                               "lua:return 40 + 2", "drain",
                                               "unload", "lua-stop", "close"}),
           "script starts after entry and stops after module work drains");
    std::error_code ignored;
    std::filesystem::remove(script, ignored);
    g_module_events = nullptr;
}

rtgum::KpmManifest ValidKpmManifest() {
    rtgum::KpmManifest manifest;
    manifest.module_id = "ctf.probe";
    manifest.target_package = "com.ctf.target";
    manifest.payload_path = "/data/local/tmp/rtgum/payload.so";
    manifest.payload_sha256 = std::string(64, 'a');
    manifest.expires_at_epoch_seconds = 1'100;
    return manifest;
}

void TestKpmDryRunPolicy() {
    rtgum::KpmDryRunPlanner planner;
    Expect(planner.AllowTargetPackage("com.ctf.target").ok(),
           "valid package should be allowlisted");
    Expect(!planner.AllowTargetPackage("invalid-package").ok(),
           "invalid package should be rejected");

    rtgum::KpmDryRunPlan plan;
    rtgum::KpmManifest manifest = ValidKpmManifest();
    Expect(planner.BuildPlan(manifest, 1'000, &plan).ok(),
           "valid dry-run manifest should produce a plan");
    Expect(plan.backend == "kpm-dry-run", "plan should use dry-run backend");
    Expect(!plan.kernel_write && !plan.mapping_concealment,
           "dry-run plan must not enable kernel write or concealment");

    manifest.target_package = "com.ctf.other";
    Expect(!planner.BuildPlan(manifest, 1'000, &plan).ok(),
           "non-allowlisted package should be denied");

    manifest = ValidKpmManifest();
    manifest.payload_path = "/data/local/tmp/payload.so";
    Expect(!planner.BuildPlan(manifest, 1'000, &plan).ok(),
           "payload outside the controlled root should be denied");

    manifest = ValidKpmManifest();
    manifest.payload_sha256 = "abcd";
    Expect(!planner.BuildPlan(manifest, 1'000, &plan).ok(),
           "short payload digest should be rejected");

    manifest = ValidKpmManifest();
    manifest.expires_at_epoch_seconds = 100'000;
    Expect(!planner.BuildPlan(manifest, 1'000, &plan).ok(),
           "plan lifetime over 24 hours should be denied");
}

std::string SourcePath(std::string_view relative)
{
#ifdef RTGUM_SOURCE_DIR
    return std::string(RTGUM_SOURCE_DIR) + "/" + std::string(relative);
#else
    return std::string(relative);
#endif
}

std::vector<std::uint8_t> ReadAllBytes(const std::string &path)
{
    std::ifstream input(path, std::ios::binary);
    if (!input) return {};
    return std::vector<std::uint8_t>(std::istreambuf_iterator<char>(input),
                                     std::istreambuf_iterator<char>());
}

void TestGhostApiV1Layout()
{
    Expect(offsetof(GhostApi, version) == 0, "GhostApi.version offset");
    Expect(offsetof(GhostApi, reserved) == sizeof(unsigned long),
           "GhostApi.reserved stays after version");
    Expect(offsetof(GhostApi, host) == offsetof(GhostApi, exit) + sizeof(void (*)(int)),
           "HostApiV2 pointer is appended after the v1 function table");
    Expect(RTGUM_GHOST_API_VERSION == 1UL, "GhostApi version remains 1");
}

void TestHostApiV2Layout()
{
    Expect(offsetof(HostApiV2, hook_native_symbol) >
               offsetof(HostApiV2, hook_java_method),
           "hook_native_symbol is appended after Java pointers");
    Expect(offsetof(HostApiV2, wait_export) >
               offsetof(HostApiV2, hook_native_symbol),
           "wait_export is appended after hook_native_symbol");
    Expect((RTGUM_HOST_CAP_NATIVE_SYMBOL &
            (RTGUM_HOST_CAP_FIND_EXPORT | RTGUM_HOST_CAP_NATIVE_REPLACE |
             RTGUM_HOST_CAP_DEFER | RTGUM_HOST_CAP_JAVA_HOOK)) == 0UL,
           "NATIVE_SYMBOL is a distinct capability bit");
    Expect((RTGUM_HOST_CAP_WAIT_EXPORT &
            (RTGUM_HOST_CAP_FIND_EXPORT | RTGUM_HOST_CAP_NATIVE_REPLACE |
             RTGUM_HOST_CAP_DEFER | RTGUM_HOST_CAP_JAVA_HOOK |
             RTGUM_HOST_CAP_NATIVE_SYMBOL)) == 0UL,
           "WAIT_EXPORT is a distinct capability bit");
    Expect(offsetof(HostApiV2, load_dex) > offsetof(HostApiV2, wait_export),
           "load_dex is appended after wait_export");
    Expect(offsetof(HostApiV2, lua_eval) > offsetof(HostApiV2, unload_dex),
           "lua_eval is appended after unload_dex");
    Expect(offsetof(HostApiV2, hook_binder) > offsetof(HostApiV2, lua_stop),
           "hook_binder is appended after lua_stop");
    Expect(offsetof(HostApiV2, gtrace_decode) > offsetof(HostApiV2, hook_binder),
           "gtrace_decode is appended after hook_binder");
    Expect((RTGUM_HOST_CAP_LOAD_DEX & RTGUM_HOST_CAP_WAIT_EXPORT) == 0UL,
           "LOAD_DEX is a distinct capability bit");
    Expect((RTGUM_HOST_CAP_LUA & RTGUM_HOST_CAP_LOAD_DEX) == 0UL,
           "LUA is a distinct capability bit");
    Expect(offsetof(HostApiV2, binder_interceptor_register) >
               offsetof(HostApiV2, log),
           "native interceptors are appended after the stable v2 table");
    Expect(offsetof(HostApiV2, linker_interceptor_register) >
               offsetof(HostApiV2, binder_interceptor_register),
           "linker interceptor follows Binder interceptor");
    Expect((RTGUM_HOST_CAP_BINDER_INTERCEPTOR &
            RTGUM_HOST_CAP_LINKER_INTERCEPTOR) == 0UL,
           "interceptor capability bits are independent");
    Expect(offsetof(HostApiV2, so_lifecycle_register) >
               offsetof(HostApiV2, interceptor_query),
           "SO lifecycle API is append-only");
    Expect(offsetof(HostApiV2, jni_trace_register) >
               offsetof(HostApiV2, so_lifecycle_register),
           "JNI trace follows SO lifecycle");
    Expect(offsetof(HostApiV2, gtrace_format_path) >
               offsetof(HostApiV2, jni_trace_register),
           "runtime GTrace formatter is append-only");
    Expect(offsetof(HostApiV2, trace_start) >
               offsetof(HostApiV2, gtrace_format_path),
           "multi-trace registration is append-only");
    Expect(offsetof(HostApiV2, trace_query) >
               offsetof(HostApiV2, trace_stop),
           "multi-trace query follows teardown");
    Expect(offsetof(HostApiV2, lua_eval_async) >
               offsetof(HostApiV2, trace_query),
           "asynchronous Lua submission is appended after the stable table");
    Expect((RTGUM_HOST_CAP_MULTI_TRACE &
            (RTGUM_HOST_CAP_GTRACE_RUNTIME |
             RTGUM_HOST_CAP_DBI_STALKER_RANGE)) == 0UL,
           "MULTI_TRACE is a distinct capability bit");
    Expect((RTGUM_HOST_CAP_LUA_ASYNC &
            (RTGUM_HOST_CAP_LUA | RTGUM_HOST_CAP_MULTI_TRACE |
             RTGUM_HOST_CAP_GTRACE_RUNTIME)) == 0UL,
           "LUA_ASYNC is a distinct capability bit");
    Expect(RTGUM_TRACE_CONFIG_VERSION == 1UL &&
               RTGUM_TRACE_BATCH_VERSION == 1UL &&
               RTGUM_TRACE_STATS_VERSION == 1UL,
           "multi-trace records use the first ABI revision");
    Expect((RTGUM_HOST_CAP_SO_LIFECYCLE & RTGUM_HOST_CAP_JNI_TRACE) == 0UL,
           "lifecycle capability bits are independent");
    Expect(RTGUM_JNI_REGISTER_NATIVES_INDEX == 215U,
           "RegisterNatives keeps its specified JNI table index");
    Expect(RTGUM_MODULE_EXTRA_HOST_UNAVAILABLE == 0xE0UL, "badver extra is 224");
    Expect(RTGUM_MODULE_EXTRA_LOOKUP_FAILED == 0xE3UL, "nosym extra is 227");
    Expect(RTGUM_MODULE_EXTRA_LOADDEX_FAILED == 0xE5UL, "loaddex extra is 229");
}

void TestRelrApply()
{
    unsigned char image[32]{};
    rtgum::native::WriteU64(image + 0, 0x1000ULL);
    rtgum::native::WriteU64(image + 8, 0x2000ULL);
    rtgum::native::WriteU64(image + 16, 0x3000ULL);
    rtgum::native::WriteU64(image + 24, 0x4000ULL);
    unsigned char relr[16]{};
    rtgum::native::WriteU64(relr + 0, 0x0ULL);  /* offset 0 */
    rtgum::native::WriteU64(relr + 8, 0x10ULL); /* offset 16 */
    Expect(rtgum::native::ApplyRelr(image, sizeof(image), relr, sizeof(relr), 0x1000UL) == 0,
           "RELR apply should succeed");
    Expect(rtgum::native::ReadU64(image + 0) == 0x2000ULL, "first RELR word");
    Expect(rtgum::native::ReadU64(image + 8) == 0x2000ULL, "untouched second word");
    Expect(rtgum::native::ReadU64(image + 16) == 0x4000ULL, "third RELR word");
    unsigned char packed[8] = {'A', 'P', 'S', '2', 0, 0, 0, 0};
    Expect(rtgum::native::ApplyRelr(image, sizeof(image), packed, sizeof(packed), 0) ==
               RTGUM_HOST_ERR_NOTSUP,
           "APS2 packed relocs stay unsupported");
    rtgum::native::DynamicRelocKind kind{};
    rtgum::native::ClassifyDynamicTag(36UL, &kind);
    rtgum::native::ClassifyDynamicTag(0x60000011UL, &kind);
    rtgum::native::ClassifyDynamicTag(0x6fffe000UL, &kind);
    Expect(kind.relr && kind.android_packed && kind.android_relr,
           "dynamic tags classify RELR, APS2, and ANDROID_RELR");
}

void TestNamespaceTable()
{
    rtgum::native::NamespaceTable table{};
    table.Reset();
    Expect(table.Register("libc.so", "/apex/com.android.runtime/lib64/bionic/libc.so") == 0,
           "first SONAME register");
    Expect(table.Register("libc.so", "/apex/com.android.runtime/lib64/bionic/libc.so") == 0,
           "same path is idempotent");
    Expect(table.Register("libc.so", "/system/lib64/libc.so") == RTGUM_HOST_ERR_NOTSUP,
           "duplicate SONAME different path is rejected");
    char path[256]{};
    Expect(table.Lookup("libc.so", path, sizeof(path)) == 0, "lookup libc");
    Expect(table.Lookup("libmissing.so", path, sizeof(path)) == RTGUM_HOST_ERR_NOENT,
           "missing SONAME");
}

void TestGtraceDecode()
{
    unsigned char code[16] = {
        0x3f, 0x23, 0x03, 0xd5, /* paciasp junk */
        0x1f, 0x20, 0x03, 0xd5, /* nop junk */
        0x00, 0x00, 0x00, 0x91, /* add x0, x0, #0 */
        0xc0, 0x03, 0x5f, 0xd6, /* ret */
    };
    char text[256]{};
    Expect(rtgum::native::GtraceDecode(code, sizeof(code), 0x1000UL, text, sizeof(text)) == 0,
           "gtrace decode");
    Expect(std::strstr(text, "real=") != nullptr, "gtrace reports real count");
    Expect(std::strstr(text, "junk=") != nullptr, "gtrace reports junk count");
    Expect(std::strstr(text, ":ret") != nullptr, "gtrace sees ret");
    Expect(rtgum::native::GtraceIsJunk(0xD503233FU), "PACIASP is junk");
    Expect(!rtgum::native::GtraceIsJunk(0xD65F03C0U), "RET is not junk");
    Expect(rtgum::native::GtraceIsUncondBranch(0x14000001U), "B is direct branch");
    Expect(rtgum::native::GtraceIsUncondBranch(0x94000001U), "BL is direct branch");
    Expect(rtgum::native::GtraceRuntimeClassify(0x94000001U) ==
               rtgum::native::GtraceRuntimeKind::Bl,
           "runtime GTrace keeps BL distinct from B");

    const unsigned int dynamic = RTGUM_GTRACE_STEP_INSN_VALID |
                                 RTGUM_GTRACE_STEP_NEXT_VALID |
                                 RTGUM_GTRACE_STEP_DYNAMIC |
                                 RTGUM_GTRACE_STEP_DBI_CALLOUT;
    const RtGumGtraceStep steps[] = {
        {1, 0x1000UL, 0x1004UL, 0x0B010000U, dynamic}, /* add w0,w0,w1 */
        {2, 0x1004UL, 0x1008UL, 0x100000B0U, dynamic}, /* adr x16, 0x1018 */
        {3, 0x1008UL, 0x1018UL, 0xD61F0200U, dynamic}, /* br x16 */
        {4, 0x1018UL, 0x101CUL, 0x11009C00U, dynamic}, /* add w0,w0,#39 */
        {5, 0x101CUL, 0x2000UL, 0xD65F03C0U, dynamic}, /* ret */
    };
    char path[4096]{};
    Expect(rtgum::native::GtraceFormatPath(
               steps, sizeof(steps) / sizeof(steps[0]), 0x1000UL, 0x1020UL,
               path, sizeof(path)) == 0,
           "runtime gtrace path formatting");
    Expect(std::strstr(path,
                       "kind=br branch=indirect reg=x16 target=0x1018 "
                       "target-scope=internal") != nullptr,
           "runtime gtrace records the BR register landing");
    Expect(std::strstr(path,
                       "from=0x100c to=0x1018 low=0x100c high=0x1018 "
                       "bytes=12 direction=forward candidate-junk=1") != nullptr,
           "runtime gtrace emits an explicit skipped interval");
    Expect(std::strstr(path, "pc=0x100c") == nullptr &&
               std::strstr(path, "pc=0x1010") == nullptr &&
               std::strstr(path, "pc=0x1014") == nullptr,
           "unexecuted junk is absent from the runtime path");
    Expect(std::strstr(path,
                       "gtrace-summary executed=5 branches=2 indirect=2 "
                       "internal-targets=1 gaps=1 skipped-bytes=12 losses=0 "
                       "mismatches=0 unreadable=0") != nullptr,
           "runtime gtrace summary is machine-checkable");
    char short_path[64]{};
    Expect(rtgum::native::GtraceFormatPath(
               steps, sizeof(steps) / sizeof(steps[0]), 0x1000UL, 0x1020UL,
               short_path, sizeof(short_path)) == RTGUM_HOST_ERR_NOMEM,
           "runtime gtrace reports output truncation");
}

void TestElfExportLookup()
{
    const std::string path = SourcePath("out/apk-baseline/lib/arm64-v8a/libjnicode.so");
    const std::vector<std::uint8_t> image = ReadAllBytes(path);
    Expect(!image.empty(), "libjnicode.so baseline image should be readable");
    if (image.empty()) return;

    unsigned long vaddr = 0;
    Expect(rtgum::native::LookupSymbolInElfFile(image.data(), image.size(),
                                                RTGUM_JNI_STRING_FROM_JNI,
                                                &vaddr) == 0,
           "JNI export should resolve via GNU hash");
    Expect(vaddr == 0x21b40UL, "stringFromJNI vaddr should match the baseline SO");
    Expect(rtgum::native::LookupSymbolInElfFile(image.data(), image.size(),
                                                "definitely_missing_symbol",
                                                &vaddr) == RTGUM_HOST_ERR_NOENT,
           "missing symbol should return ENOENT");
}

void TestProloguePolicy()
{
    unsigned char copyable[16] = {
        0xff, 0xc3, 0x01, 0xd1,
        0xfd, 0x7b, 0x06, 0xa9,
        0xfd, 0x83, 0x01, 0x91,
        0x48, 0xd0, 0x3b, 0xd5,
    };
    Expect(rtgum::native::PrologueIsCopyable(copyable),
           "stringFromJNI prologue should be copyable");
    unsigned char adrp[16] = {
        0x00, 0x00, 0x00, 0x90,
        0x1f, 0x20, 0x03, 0xd5,
        0x1f, 0x20, 0x03, 0xd5,
        0x1f, 0x20, 0x03, 0xd5,
    };
    Expect(!rtgum::native::PrologueIsCopyable(adrp),
           "ADRP prologue should be rejected");
    unsigned char stub[16]{};
    rtgum::native::EncodeAbsoluteJump(stub, 0x123456789abcdef0ULL);
    Expect(stub[0] == 0x50 && stub[4] == 0x00 && stub[5] == 0x02 && stub[6] == 0x1f &&
               stub[7] == 0xd6,
           "absolute jump encoding should use LDR/BR X16");
}

void TestMapsSoname()
{
    const char *maps =
        "aaaab000-aaaac000 r--p 00000000 07:30 1 /system/lib64/libc.so\n"
        "bbbb0000-bbbb1000 r--p 00000000 07:30 2 /data/app/x/lib/arm64/libjnicode.so\n"
        "bbbb1000-bbbb2000 r-xp 00001000 07:30 2 /data/app/x/lib/arm64/libjnicode.so\n";
    unsigned long base = 0;
    Expect(rtgum::native::FindSonameBase(maps, "libjnicode.so", &base) == 0,
           "soname should match the lowest mapping");
    Expect(base == 0xbbbb0000UL, "lowest libjnicode mapping should win");
    Expect(rtgum::native::FindSonameBase(maps, "libmissing.so", &base) ==
               RTGUM_HOST_ERR_NOENT,
           "unknown soname should return ENOENT");

    Expect(rtgum::native::PathHasSoname(
               "/data/app/x/base.apk!/lib/arm64-v8a/libjnicode.so", "libjnicode.so"),
           "zip-aligned maps path should still match the soname");
    Expect(rtgum::native::PathLooksLikeApk(
               "/data/app/~~x==/com.laodeng.jnicode-y==/base.apk"),
           "extracted-APK mapping path should be recognized");
    Expect(rtgum::native::PathLooksLikeApk(
               "/data/app/x/base.apk!/lib/arm64-v8a/libjnicode.so"),
           "apk!/ native path should be recognized");
    Expect(!rtgum::native::PathLooksLikeApk(
               "[anon:dalvik-classes.dex extracted .../base.apk]"),
           "dalvik extract labels are not file-backed APK mappings");
    Expect(!rtgum::native::PathLooksLikeApk("/system/lib64/libc.so"),
           "ordinary .so paths are not APK mappings");

    const char *apk_maps =
        "6f79c12000-6f79d55000 r--s 001f5000 fe:40 18686 /data/app/x/base.apk\n"
        "6fafba4000-6fafbf1000 r-xp 000d0000 fe:40 18686 /data/app/x/base.apk\n"
        "6fafbf4000-6fafbf9000 r--p 0011c000 fe:40 18686 /data/app/x/base.apk\n";
    Expect(rtgum::native::FindSonameBase(apk_maps, "libjnicode.so", &base) ==
               RTGUM_HOST_ERR_NOENT,
           "APK-backed native mappings do not expose the soname");
    rtgum::native::MapsRegion region{};
    const char *rxp =
        "6fafba4000-6fafbf1000 r-xp 000d0000 fe:40 18686 /data/app/x/base.apk";
    Expect(rtgum::native::ParseMapsRegion(rxp, rxp + std::strlen(rxp), &region),
           "APK r-xp line should parse");
    Expect(region.start == 0x6fafba4000UL, "APK r-xp start should parse");
    Expect(region.perms[0] == 'r' && region.perms[2] == 'x',
           "APK r-xp perms should parse");
    Expect(rtgum::native::PathLooksLikeApk(region.path) &&
               rtgum::native::PermsReadable(region.perms),
           "APK r-xp region should be an ELF candidate");
}

#if ULONG_MAX > 0xffffffffUL
unsigned char g_fake_page[4096];
unsigned char g_code[64];

long TestMmap(unsigned long, unsigned long)
{
    return reinterpret_cast<long>(g_fake_page);
}

long TestMprotect(unsigned long, unsigned long, unsigned long) { return 0; }
long TestMunmap(unsigned long, unsigned long) { return 0; }
void TestClearCache(unsigned long, unsigned long) {}

void TestHandleLifecycle()
{
    using namespace rtgum::native;
    std::uint32_t *insns = reinterpret_cast<std::uint32_t *>(g_code);
    insns[0] = 0xd101c3ffU;
    insns[1] = 0xa9067bfdU;
    insns[2] = 0x910183fdU;
    insns[3] = 0xd53bd048U;
    Engine engine;
    engine.ops.mmap = TestMmap;
    engine.ops.mprotect = TestMprotect;
    engine.ops.munmap = TestMunmap;
    engine.ops.clear_cache = TestClearCache;

    unsigned long original = 0;
    unsigned long handle = 0;
    const unsigned long target = reinterpret_cast<unsigned long>(g_code);
    const unsigned long replacement = target + 32UL;
    Expect(engine.Replace(target, replacement, &original, &handle) == 0,
           "copyable prologue should install");
    Expect(original == reinterpret_cast<unsigned long>(g_fake_page),
           "original entry should be the trampoline");
    Expect(ReadU32(g_code) == 0x58000050U, "target should receive the absolute jump");
    unsigned long original2 = 0;
    unsigned long handle2 = 0;
    Expect(engine.Replace(target, replacement, &original2, &handle2) ==
               RTGUM_HOST_ERR_EXIST,
           "duplicate replace should fail");
    unsigned int backend = 0;
    unsigned int state = 0;
    Expect(engine.Query(handle, &backend, &state) == 0 &&
               backend == RTGUM_HOST_BACKEND_NATIVE &&
               state == RTGUM_HOST_HOOK_ACTIVE,
           "active handle should query as native/active");
    Expect(engine.Revert(handle) == 0, "first revert should succeed");
    Expect(ReadU32(g_code) == 0xd101c3ffU, "target bytes should be restored");
    Expect(engine.Revert(handle) == 0, "second revert of the same handle is idempotent");
    Expect(engine.Revert(handle + 16UL) == RTGUM_HOST_ERR_BADF,
           "stale generation should be rejected");
    Expect(engine.Query(handle, &backend, &state) == 0 &&
               state == RTGUM_HOST_HOOK_INACTIVE,
           "reverted handle should query inactive");
}
#endif

}  // namespace

int main() {
    TestRuntimeRollback();
    TestMemoryRegionWxPolicy();
    TestElfValidation();
    TestReadOnlyArtProbe();
    TestSystemLibraryValidation();
    TestModuleRuntimeReload();
    TestModuleRuntimeScript();
    TestKpmDryRunPolicy();
    TestGhostApiV1Layout();
    TestHostApiV2Layout();
    TestRelrApply();
    TestNamespaceTable();
    TestGtraceDecode();
    TestElfExportLookup();
    TestProloguePolicy();
    TestMapsSoname();
#if ULONG_MAX > 0xffffffffUL
    TestHandleLifecycle();
#endif

    if (failures != 0) {
        std::cerr << failures << " test assertion(s) failed\n";
        return 1;
    }
    std::cout << "all rt-gum tests passed\n";
    return 0;
}
