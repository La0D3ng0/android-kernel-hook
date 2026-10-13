param(
    [string]$NdkPath = "",
    [int]$Api = 30,
    [string]$OutputDirectory = "",
    [string]$DexFixtureInclude = ""
)

$ErrorActionPreference = "Stop"
$projectDirectory = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($NdkPath)) {
    $NdkPath = Join-Path $projectDirectory ".toolchains\android-ndk-r25c"
}
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $projectDirectory "out\kpm-stage1-pixel8-review"
}

$compiler = Join-Path $NdkPath "toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android$Api-clang++.cmd"
$readelf = Join-Path $NdkPath "toolchains\llvm\prebuilt\windows-x86_64\bin\llvm-readelf.exe"
$daemonSource = Join-Path $projectDirectory "tests\stage2-daemon.cpp"
$moduleSource = Join-Path $projectDirectory "tests\stage2-module.cpp"
$module2Source = Join-Path $projectDirectory "tests\stage2-module2.cpp"
$jnicodeSource = Join-Path $projectDirectory "tests\stage2-jnicode-module.cpp"
$jnicodeJavaSource = Join-Path $projectDirectory "tests\stage2-jnicode-java-module.cpp"
$jnicodeMakoSource = Join-Path $projectDirectory "tests\stage2-jnicode-mako-module.cpp"
$labMakoSource = Join-Path $projectDirectory "tests\stage2-lab-mako-module.cpp"
$symbolModuleSource = Join-Path $projectDirectory "tests\stage2-symbol-module.cpp"
$jnicodeBadverSource = Join-Path $projectDirectory "tests\stage2-jnicode-badver-module.cpp"
$jnicodeNosymSource = Join-Path $projectDirectory "tests\stage2-jnicode-nosym-module.cpp"
$zygotePayloadSource = Join-Path $projectDirectory "tests\stage2-zygote-payload.cpp"
$gumGhostSource = Join-Path $projectDirectory "tests\stage2-gum-ghost.cpp"
$gumluaModuleSource = Join-Path $projectDirectory "tests\stage2-gumlua-module.cpp"
$dexModuleSource = Join-Path $projectDirectory "tests\stage2-dex-module.cpp"
$interceptorModuleSource = Join-Path $projectDirectory "tests\stage2-interceptor-module.cpp"
$lifecycleModuleSource = Join-Path $projectDirectory "tests\stage2-lifecycle-module.cpp"
$gtraceModuleSource = Join-Path $projectDirectory "tests\stage2-gtrace-module.cpp"
$multiTraceModuleSource = Join-Path $projectDirectory "tests\stage2-multitrace-module.cpp"
$dexFixtureDirectory = Join-Path $projectDirectory "tests\dex-fixture"
if ([string]::IsNullOrWhiteSpace($DexFixtureInclude)) {
    $DexFixtureInclude = Join-Path $dexFixtureDirectory "rtgum-dex-fixture.inc"
} else {
    $DexFixtureInclude = [System.IO.Path]::GetFullPath($DexFixtureInclude)
    $dexFixtureDirectory = Split-Path -Parent $DexFixtureInclude
}
$gumDevkit = Join-Path $projectDirectory ".toolchains\frida-gum-devkit-17.22.2-android-arm64"
$strip = Join-Path $NdkPath "toolchains\llvm\prebuilt\windows-x86_64\bin\llvm-strip.exe"
$include = Join-Path $projectDirectory "include"
$artInclude = Join-Path $projectDirectory "art-hook\include"
$daemonOutput = Join-Path $OutputDirectory "rtgum-stage2-daemon.so"
$moduleOutput = Join-Path $OutputDirectory "rtgum-stage2-module.ghm"
$module2Output = Join-Path $OutputDirectory "rtgum-stage2-module2.ghm"
$jnicodeOutput = Join-Path $OutputDirectory "rtgum-stage2-jnicode.ghm"
$jnicodeJavaOutput = Join-Path $OutputDirectory "rtgum-stage2-jnicode-java.ghm"
$jnicodeMakoOutput = Join-Path $OutputDirectory "rtgum-stage2-jnicode-mako.ghm"
$labMakoOutput = Join-Path $OutputDirectory "rtgum-stage2-lab-mako.ghm"
$symbolModuleOutput = Join-Path $OutputDirectory "rtgum-stage2-symbol.ghm"
$jnicodeBadverOutput = Join-Path $OutputDirectory "rtgum-stage2-jnicode-badver.ghm"
$jnicodeNosymOutput = Join-Path $OutputDirectory "rtgum-stage2-jnicode-nosym.ghm"
$zygotePayloadOutput = Join-Path $OutputDirectory "rtgum-stage2-zygote-payload.so"
$gumGhostOutput = Join-Path $OutputDirectory "librtgum-gum-ghost.so"
$gumGhostDebugOutput = Join-Path $OutputDirectory "librtgum-gum-ghost-debug.so"
$gumWxArchive = Join-Path $OutputDirectory "libfrida-gum-wx.a"
$gumluaModuleOutput = Join-Path $OutputDirectory "rtgum-stage2-gumlua.ghm"
$dexModuleOutput = Join-Path $OutputDirectory "rtgum-stage2-dex.ghm"
$interceptorModuleOutput = Join-Path $OutputDirectory "rtgum-stage2-interceptors.ghm"
$lifecycleModuleOutput = Join-Path $OutputDirectory "rtgum-stage2-lifecycle.ghm"
$gtraceModuleOutput = Join-Path $OutputDirectory "rtgum-stage2-gtrace.ghm"
$multiTraceModuleOutput = Join-Path $OutputDirectory "rtgum-stage2-multitrace.ghm"
foreach ($required in @($compiler, $readelf, $daemonSource, $moduleSource, $module2Source, $jnicodeSource, $jnicodeJavaSource, $jnicodeMakoSource, $labMakoSource, $symbolModuleSource, $jnicodeBadverSource, $jnicodeNosymSource, $zygotePayloadSource, $gumGhostSource, $gumluaModuleSource, $dexModuleSource, $interceptorModuleSource, $lifecycleModuleSource, $gtraceModuleSource, $multiTraceModuleSource, $dexFixtureInclude, $include, $artInclude, (Join-Path $gumDevkit 'frida-gum.h'), (Join-Path $gumDevkit 'libfrida-gum.a'))) {
    if (-not (Test-Path -LiteralPath $required)) { throw "Required path not found: $required" }
}

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null

# Keep the separately loaded Lua helper and its ABI test in lockstep with the
# Daemon.  Stage-2 smoke tests must never silently reuse an older helper SO.
$luaHelperBuild = Join-Path $PSScriptRoot "build-jnicode-lua-helper.ps1"
& $luaHelperBuild -NdkPath $NdkPath -Api $Api -OutputDirectory $OutputDirectory
if ($LASTEXITCODE -ne 0) {
    throw "Lua helper build failed with exit code $LASTEXITCODE"
}

# The Daemon must stay import-resolvable by the KPM remote linker: only libc.so
# (memset and pthread lifecycle), GNU hash, eager binding, and a writable GOT so
# the bootstrap IFUNC fixup can patch the daemon's own IRELATIVE slot from user
# mode (no RELRO). Keep atomics inline: compiler-rt outline helpers are not an
# Android libc export and therefore cannot be repaired by this linker.
$daemonFlags = @(
    "-std=c++17", "-O2", "-fPIC", "-shared", "-nostdlib", "-fno-exceptions", "-fno-rtti",
    "-fno-builtin", "-mno-outline-atomics", "-mbranch-protection=standard",
    "-fvisibility=hidden", "-I$include", "-I$artInclude",
    "-Wl,-soname,rtgum-stage2-daemon.so", "-Wl,--hash-style=gnu",
    "-Wl,-z,now", "-Wl,--no-as-needed", "-lc"
)
& $compiler @daemonFlags $daemonSource "-o" $daemonOutput
if ($LASTEXITCODE -ne 0) { throw "Stage-2 Daemon compilation failed with exit code $LASTEXITCODE" }

# User modules (.ghm) are self-contained: no libc, GhostApi only.
$moduleFlags = @(
    "-std=c++17", "-O2", "-fPIC", "-shared", "-nostdlib", "-fno-exceptions", "-fno-rtti",
    "-fno-builtin", "-mbranch-protection=standard", "-fvisibility=hidden", "-I$include",
    "-Wl,-soname,rtgum-stage2-module.ghm", "-Wl,--hash-style=gnu",
    "-Wl,-z,now"
)
& $compiler @moduleFlags $moduleSource "-o" $moduleOutput
if ($LASTEXITCODE -ne 0) { throw "Stage-2 module compilation failed with exit code $LASTEXITCODE" }
& $compiler @moduleFlags $module2Source "-o" $module2Output
if ($LASTEXITCODE -ne 0) { throw "Stage-2 module2 compilation failed with exit code $LASTEXITCODE" }
$symbolModuleFlags = @(
    "-std=c++17", "-O2", "-fPIC", "-shared", "-nostdlib", "-fno-exceptions", "-fno-rtti",
    "-fno-builtin", "-fvisibility=hidden", "-I$include",
    "-Wl,-soname,rtgum-stage2-symbol.ghm", "-Wl,--hash-style=gnu", "-Wl,-z,now"
)
& $compiler @symbolModuleFlags $symbolModuleSource "-o" $symbolModuleOutput
if ($LASTEXITCODE -ne 0) { throw "Stage-2 symbol module compilation failed with exit code $LASTEXITCODE" }
$jnicodeFlags = @(
    "-std=c++17", "-O2", "-fPIC", "-shared", "-nostdlib", "-fno-exceptions", "-fno-rtti",
    "-fno-builtin", "-fno-stack-protector", "-mno-outline-atomics", "-fvisibility=hidden", "-I$include",
    "-Wl,-soname,rtgum-stage2-jnicode.ghm", "-Wl,--hash-style=gnu",
    "-Wl,-z,now"
)
& $compiler @jnicodeFlags $jnicodeSource "-o" $jnicodeOutput
if ($LASTEXITCODE -ne 0) { throw "Stage-2 jnicode module compilation failed with exit code $LASTEXITCODE" }
$jnicodeJavaFlags = @(
    "-std=c++17", "-O2", "-fPIC", "-shared", "-nostdlib", "-fno-exceptions", "-fno-rtti",
    "-fno-builtin", "-fno-stack-protector", "-mno-outline-atomics", "-fvisibility=hidden", "-I$include",
    "-Wl,-soname,rtgum-stage2-jnicode-java.ghm", "-Wl,--hash-style=gnu",
    "-Wl,-z,now"
)
& $compiler @jnicodeJavaFlags $jnicodeJavaSource "-o" $jnicodeJavaOutput
if ($LASTEXITCODE -ne 0) { throw "Stage-2 jnicode Java module compilation failed with exit code $LASTEXITCODE" }
& $compiler @jnicodeJavaFlags $jnicodeMakoSource "-o" $jnicodeMakoOutput
if ($LASTEXITCODE -ne 0) { throw "Stage-2 jnicode Mako module compilation failed with exit code $LASTEXITCODE" }
# ART acceptance module: hooks LabTarget.add so the lab's self-check has a live
# hook to compare the scanner's view against.
& $compiler @jnicodeJavaFlags $labMakoSource "-o" $labMakoOutput
if ($LASTEXITCODE -ne 0) { throw "Stage-2 lab Mako module compilation failed with exit code $LASTEXITCODE" }
$jnicodeErrorFlags = @(
    "-std=c++17", "-O2", "-fPIC", "-shared", "-nostdlib", "-fno-exceptions", "-fno-rtti",
    "-fno-builtin", "-fno-stack-protector", "-fvisibility=hidden", "-I$include",
    "-Wl,--hash-style=gnu", "-Wl,-z,now"
)
& $compiler @jnicodeErrorFlags "-Wl,-soname,rtgum-stage2-jnicode-badver.ghm" $jnicodeBadverSource "-o" $jnicodeBadverOutput
if ($LASTEXITCODE -ne 0) { throw "Stage-2 jnicode badver module compilation failed with exit code $LASTEXITCODE" }
& $compiler @jnicodeErrorFlags "-Wl,-soname,rtgum-stage2-jnicode-nosym.ghm" $jnicodeNosymSource "-o" $jnicodeNosymOutput
if ($LASTEXITCODE -ne 0) { throw "Stage-2 jnicode nosym module compilation failed with exit code $LASTEXITCODE" }

# Remote-resolution payload: NEEDED libc/libdl/libm, all already loaded in
# Zygote, so the in-kernel resolver can repair every import without loading
# anything new into Zygote.
$zygotePayloadFlags = @(
    "-std=c++17", "-O2", "-fPIC", "-shared", "-nostdlib", "-fno-exceptions", "-fno-rtti",
    "-fno-builtin", "-fvisibility=hidden",
    "-Wl,-soname,rtgum-stage2-zygote-payload.so", "-Wl,--hash-style=gnu",
    "-Wl,-z,now", "-Wl,--no-as-needed", "-lc", "-ldl", "-lm"
)
& $compiler @zygotePayloadFlags $zygotePayloadSource "-o" $zygotePayloadOutput
if ($LASTEXITCODE -ne 0) { throw "Stage-2 zygote payload compilation failed with exit code $LASTEXITCODE" }

# Gum ghost backend: the Frida Gum devkit plus libc/libdl/libm. Imports are
# resolved by the KPM remote linker against the target app's loaded
# libraries, so the image itself stays VMA-less. -ffunction-sections plus
# --gc-sections keeps the stripped image small enough for the kernel linker.
$gumWxPatch = Join-Path $PSScriptRoot "patch-frida-gum-wx.ps1"
& $gumWxPatch -SourceArchive (Join-Path $gumDevkit 'libfrida-gum.a') `
    -OutputArchive $gumWxArchive -NdkPath $NdkPath
if ($LASTEXITCODE -ne 0) { throw "Frida Gum W^X patch failed with exit code $LASTEXITCODE" }

$gumGhostFlags = @(
    "-std=c++17", "-O2", "-fPIC", "-shared", "-fno-exceptions", "-fno-rtti",
    "-fno-builtin", "-fvisibility=hidden", "-ffunction-sections", "-fdata-sections",
    "-static-libstdc++", "-I$include", "-I$gumDevkit",
    "-Wl,-soname,librtgum-gum-ghost.so", "-Wl,--hash-style=gnu",
    "-Wl,-z,now", "-Wl,--no-as-needed", "-Wl,--gc-sections",
    "-Wl,--wrap=gum_query_cpu_features",
    "-Wl,--wrap=gum_query_is_rwx_supported",
    "-Wl,--wrap=gum_query_rwx_support",
    "-Wl,--wrap=gum_memory_allocate_near",
    "-Wl,--wrap=gum_memory_patch_code",
    "-Wl,--wrap=gum_memory_patch_code_pages",
    "-lc", "-ldl", "-lm", "-llog",
    $gumWxArchive
)
& $compiler @gumGhostFlags $gumGhostSource "-o" $gumGhostOutput
if ($LASTEXITCODE -ne 0) { throw "Gum ghost backend compilation failed with exit code $LASTEXITCODE" }
Copy-Item -LiteralPath $gumGhostOutput -Destination $gumGhostDebugOutput -Force
& $strip --strip-unneeded $gumGhostOutput
if ($LASTEXITCODE -ne 0) { throw "Gum ghost backend strip failed with exit code $LASTEXITCODE" }

# Gum Lua demo module (.ghm): declaration-only, GhostApi, no DT_NEEDED.
& $compiler @moduleFlags $gumluaModuleSource "-o" $gumluaModuleOutput
if ($LASTEXITCODE -ne 0) { throw "Stage-2 gumlua module compilation failed with exit code $LASTEXITCODE" }

# Daemon-owned in-memory DEX acceptance module. The generated DEX include is
# input data only; the resulting .ghm remains declaration-only and has no
# DT_NEEDED libraries.
$dexModuleFlags = @(
    "-std=c++17", "-O2", "-fPIC", "-shared", "-nostdlib", "-fno-exceptions", "-fno-rtti",
    "-fno-builtin", "-fno-stack-protector", "-mno-outline-atomics", "-fvisibility=hidden",
    "-I$include", "-I$dexFixtureDirectory",
    "-Wl,-soname,rtgum-stage2-dex.ghm", "-Wl,--hash-style=gnu", "-Wl,-z,now"
)
& $compiler @dexModuleFlags $dexModuleSource "-o" $dexModuleOutput
if ($LASTEXITCODE -ne 0) { throw "Stage-2 DEX module compilation failed with exit code $LASTEXITCODE" }

# Binder/Linker interception acceptance module.  Callback entry points carry
# BTI/PAC because the Daemon invokes them indirectly from Shadow replacements.
$interceptorModuleFlags = @(
    "-std=c++17", "-O2", "-fPIC", "-shared", "-nostdlib", "-fno-exceptions", "-fno-rtti",
    "-fno-builtin", "-fno-stack-protector", "-mno-outline-atomics",
    "-mbranch-protection=standard", "-fvisibility=hidden", "-I$include",
    "-Wl,-soname,rtgum-stage2-interceptors.ghm", "-Wl,--hash-style=gnu", "-Wl,-z,now"
)
& $compiler @interceptorModuleFlags $interceptorModuleSource "-o" $interceptorModuleOutput
if ($LASTEXITCODE -ne 0) { throw "Stage-2 interceptor module compilation failed with exit code $LASTEXITCODE" }

$lifecycleModuleFlags = $interceptorModuleFlags.Clone()
$lifecycleModuleFlags[$lifecycleModuleFlags.IndexOf("-Wl,-soname,rtgum-stage2-interceptors.ghm")] = `
    "-Wl,-soname,rtgum-stage2-lifecycle.ghm"
& $compiler @lifecycleModuleFlags $lifecycleModuleSource "-o" $lifecycleModuleOutput
if ($LASTEXITCODE -ne 0) { throw "Stage-2 lifecycle module compilation failed with exit code $LASTEXITCODE" }

$gtraceModuleFlags = $interceptorModuleFlags.Clone()
$gtraceModuleFlags[$gtraceModuleFlags.IndexOf("-Wl,-soname,rtgum-stage2-interceptors.ghm")] = `
    "-Wl,-soname,rtgum-stage2-gtrace.ghm"
& $compiler @gtraceModuleFlags $gtraceModuleSource "-o" $gtraceModuleOutput
if ($LASTEXITCODE -ne 0) { throw "Stage-2 GTrace module compilation failed with exit code $LASTEXITCODE" }

$multiTraceModuleFlags = $interceptorModuleFlags.Clone()
$multiTraceModuleFlags[$multiTraceModuleFlags.IndexOf("-Wl,-soname,rtgum-stage2-interceptors.ghm")] = `
    "-Wl,-soname,rtgum-stage2-multitrace.ghm"
& $compiler @multiTraceModuleFlags $multiTraceModuleSource "-o" $multiTraceModuleOutput
if ($LASTEXITCODE -ne 0) { throw "Stage-2 multi-trace module compilation failed with exit code $LASTEXITCODE" }

# In-app DBI module (.ghm): relocates a real libc function of the target
# process into a ghost page and executes the clone inside that process.
$dbiModuleSource = Join-Path $projectDirectory "tests\stage2-dbi-module.cpp"
$dbiModuleOutput = Join-Path $OutputDirectory "rtgum-stage2-dbi.ghm"
& $compiler @moduleFlags $dbiModuleSource "-o" $dbiModuleOutput
if ($LASTEXITCODE -ne 0) { throw "Stage-2 DBI module compilation failed with exit code $LASTEXITCODE" }
$dbiStalkerModuleOutput = Join-Path $OutputDirectory "rtgum-stage2-dbi-stalker.ghm"
& $compiler @moduleFlags '-DRTGUM_DBI_STALKER_REQUIRED=1' $dbiModuleSource '-o' $dbiStalkerModuleOutput
if ($LASTEXITCODE -ne 0) { throw "Stage-2 DBI Stalker module compilation failed with exit code $LASTEXITCODE" }

function Verify-Image {
    param([string]$Path, [string[]]$RequiredSymbols, [string]$Label, [switch]$RequireRelative)
    $header = (& $readelf --file-header $Path) -join "`n"
    $dynamic = (& $readelf --dynamic-table $Path) -join "`n"
    $symbols = (& $readelf --wide --dyn-syms $Path) -join "`n"
    $relocations = (& $readelf --wide --relocs $Path) -join "`n"
    if ($header -notmatch "Type:\s+DYN" -or $header -notmatch "Machine:\s+AArch64") {
        throw "$Label is not an AArch64 ET_DYN image"
    }
    if ($dynamic -notmatch "\(GNU_HASH\)") { throw "$Label is missing the GNU hash" }
    foreach ($symbol in $RequiredSymbols) {
        if ($symbols -notmatch [regex]::Escape($symbol)) {
            throw "$Label is missing required export $symbol"
        }
    }
    if ($RequireRelative -and $relocations -notmatch "R_AARCH64_RELATIVE") {
        throw "$Label does not exercise a RELATIVE relocation"
    }
}

Verify-Image -Path $daemonOutput -Label "Daemon" -RequireRelative -RequiredSymbols @(
    "rtgum_stage2_daemon_dispatch",
    "rtgum_stage2_daemon_entry",
    "rtgum_stage2_daemon_ifunc_probe",
    "rtgum_stage2_daemon_ctx",
    "rtgum_stage2_daemon_trampoline",
    "rtgum_stage2_daemon_status",
    "rtgum_stage2_daemon_descriptor"
)
$daemonDynamic = (& $readelf --dynamic-table $daemonOutput) -join "`n"
if ($daemonDynamic -notmatch "\(NEEDED\).*libc\.so") {
    throw "Daemon does not declare DT_NEEDED libc.so"
}
$daemonSymbols = (& $readelf --wide --dyn-syms $daemonOutput) -join "`n"
foreach ($import in @('memset', 'pthread_create', 'pthread_detach')) {
    if ($daemonSymbols -notmatch "UND.*$import") {
        throw "Daemon does not import $import from libc.so"
    }
}
if ($daemonSymbols -match "UND.*__aarch64_.*") {
    throw "Daemon contains an unresolved outlined atomic helper"
}
$daemonRelocs = (& $readelf --wide --relocs $daemonOutput) -join "`n"
if ($daemonRelocs -notmatch "rtgum_stage2_daemon_ifunc_probe") {
    throw "Daemon does not reference its IFUNC probe in a relocation"
}
$daemonSymbols = (& $readelf --wide --dyn-syms $daemonOutput) -join "`n"
if ($daemonSymbols -notmatch "IFUNC.*rtgum_stage2_daemon_ifunc_probe") {
    throw "Daemon IFUNC probe is not a dynamic IFUNC symbol"
}
foreach ($sym in @("rtgum_stage2_daemon_ctx", "rtgum_stage2_daemon_trampoline")) {
    $match = [regex]::Match($daemonSymbols, "(?m)^\s*\d+:\s+[0-9a-f]+\s+4096\s+OBJECT\s+GLOBAL\s+DEFAULT\s+\d+\s+$sym`$")
    if (-not $match.Success) { throw "$sym is missing or is not a 4096-byte export" }
}

Verify-Image -Path $moduleOutput -Label "Module" -RequiredSymbols @("ghostEntry", "ghostModuleUnload")
$dbiStalkerDynamic = (& $readelf --dynamic-table $dbiStalkerModuleOutput) -join "`n"
Verify-Image -Path $dbiStalkerModuleOutput -Label "DBIStalkerModule" -RequiredSymbols @("ghostEntry", "ghostModuleUnload")
if ($dbiStalkerDynamic -match "\(NEEDED\)") { throw "DBI Stalker module unexpectedly declares DT_NEEDED entries" }
$moduleDynamic = (& $readelf --dynamic-table $moduleOutput) -join "`n"
if ($moduleDynamic -match "\(NEEDED\)") { throw "Module unexpectedly declares DT_NEEDED entries" }

Verify-Image -Path $module2Output -Label "Module2" -RequiredSymbols @("ghostEntry", "ghostModuleUnload")
$module2Dynamic = (& $readelf --dynamic-table $module2Output) -join "`n"
if ($module2Dynamic -match "\(NEEDED\)") { throw "Module2 unexpectedly declares DT_NEEDED entries" }

Verify-Image -Path $symbolModuleOutput -Label "SymbolModule" -RequiredSymbols @("ghostEntry", "ghostModuleUnload")
$symbolModuleDynamic = (& $readelf --dynamic-table $symbolModuleOutput) -join "`n"
if ($symbolModuleDynamic -match "\(NEEDED\)") { throw "Symbol module unexpectedly declares DT_NEEDED entries" }
$symbolModuleDynsyms = (& $readelf --wide --dyn-syms $symbolModuleOutput) -join "`n"
if ($symbolModuleDynsyms -match "ghost_symbol_probe") {
    throw "Symbol module probe leaked into .dynsym; full-table fallback is not exercised"
}
$symbolModuleSymbols = (& $readelf --wide --symbols $symbolModuleOutput) -join "`n"
if ($symbolModuleSymbols -notmatch "ghost_symbol_probe") {
    throw "Symbol module probe is missing from .symtab"
}

Verify-Image -Path $jnicodeOutput -Label "JniCodeModule" -RequiredSymbols @("ghostEntry", "ghostModuleUnload")
$jnicodeDynamic = (& $readelf --dynamic-table $jnicodeOutput) -join "`n"
if ($jnicodeDynamic -match "\(NEEDED\)") { throw "JniCode module unexpectedly declares DT_NEEDED entries" }

Verify-Image -Path $jnicodeJavaOutput -Label "JniCodeJavaModule" -RequiredSymbols @("ghostEntry", "ghostModuleUnload")
$jnicodeJavaDynamic = (& $readelf --dynamic-table $jnicodeJavaOutput) -join "`n"
if ($jnicodeJavaDynamic -match "\(NEEDED\)") { throw "JniCode Java module unexpectedly declares DT_NEEDED entries" }

Verify-Image -Path $jnicodeMakoOutput -Label "JniCodeMakoModule" -RequiredSymbols @("ghostEntry", "ghostModuleUnload")
$jnicodeMakoDynamic = (& $readelf --dynamic-table $jnicodeMakoOutput) -join "`n"
if ($jnicodeMakoDynamic -match "\(NEEDED\)") { throw "JniCode Mako module unexpectedly declares DT_NEEDED entries" }

Verify-Image -Path $labMakoOutput -Label "LabMakoModule" -RequiredSymbols @("ghostEntry", "ghostModuleUnload")
$labMakoDynamic = (& $readelf --dynamic-table $labMakoOutput) -join "`n"
if ($labMakoDynamic -match "\(NEEDED\)") { throw "Lab Mako module unexpectedly declares DT_NEEDED entries" }

Verify-Image -Path $jnicodeBadverOutput -Label "JniCodeBadverModule" -RequiredSymbols @("ghostEntry", "ghostModuleUnload")
$jnicodeBadverDynamic = (& $readelf --dynamic-table $jnicodeBadverOutput) -join "`n"
if ($jnicodeBadverDynamic -match "\(NEEDED\)") { throw "JniCode badver module unexpectedly declares DT_NEEDED entries" }

Verify-Image -Path $jnicodeNosymOutput -Label "JniCodeNosymModule" -RequiredSymbols @("ghostEntry", "ghostModuleUnload")
$jnicodeNosymDynamic = (& $readelf --dynamic-table $jnicodeNosymOutput) -join "`n"
if ($jnicodeNosymDynamic -match "\(NEEDED\)") { throw "JniCode nosym module unexpectedly declares DT_NEEDED entries" }

Verify-Image -Path $zygotePayloadOutput -Label "ZygotePayload" -RequiredSymbols @("ghost_zygote_probe")
$zygotePayloadDynamic = (& $readelf --dynamic-table $zygotePayloadOutput) -join "`n"
foreach ($needed in @("libc.so", "libdl.so", "libm.so")) {
    if ($zygotePayloadDynamic -notmatch [regex]::Escape($needed)) {
        throw "Zygote payload is missing DT_NEEDED $needed"
    }
}
$zygotePayloadSymbols = (& $readelf --wide --dyn-syms $zygotePayloadOutput) -join "`n"
foreach ($import in @("memset", "strlen", "dlopen", "pow")) {
    if ($zygotePayloadSymbols -notmatch ("UND.*" + [regex]::Escape($import))) {
        throw "Zygote payload does not import $import"
    }
}

Verify-Image -Path $gumGhostOutput -Label "GumGhost" -RequiredSymbols @("rtgum_gum_entry", "ghostEntry")
$gumGhostDynamic = (& $readelf --dynamic-table $gumGhostOutput) -join "`n"
foreach ($needed in @("libc.so", "libdl.so", "libm.so")) {
    if ($gumGhostDynamic -notmatch [regex]::Escape($needed)) {
        throw "Gum ghost backend is missing DT_NEEDED $needed"
    }
}
$gumGhostSegments = (& $readelf --program-headers $gumGhostOutput) -join "`n"
if ($gumGhostSegments -match "TLS") {
    throw "Gum ghost backend has a PT_TLS segment; the kernel linker does not support TLS"
}
$gumGhostSymbols = (& $readelf --wide --dyn-syms $gumGhostOutput) -join "`n"
foreach ($import in @("fopen", "dlsym", "malloc", "pthread_mutex_lock")) {
    if ($gumGhostSymbols -notmatch ("UND.*" + [regex]::Escape($import))) {
        throw "Gum ghost backend does not import $import"
    }
}
# mmap/munmap/mprotect are DEFINED locally: they interpose Gum's calls and
# route anonymous mappings to the KPM ghost allocator.
foreach ($defined in @("mmap", "munmap", "mprotect")) {
    if ($gumGhostSymbols -notmatch ("(?m)^\s*\d+:\s+[0-9a-f]+\s+\d+\s+FUNC\s+GLOBAL\s+DEFAULT\s+\d+\s+" + [regex]::Escape($defined) + "\s*$")) {
        throw "Gum ghost backend does not define $defined"
    }
}
$gumGhostSize = (Get-Item -LiteralPath $gumGhostOutput).Length
if ($gumGhostSize -gt 16MB) { throw "Gum ghost backend exceeds the 16MB kernel linker cap: $gumGhostSize" }

Verify-Image -Path $gumluaModuleOutput -Label "GumLuaModule" -RequiredSymbols @("ghostEntry", "ghostModuleUnload")
$gumluaModuleDynamic = (& $readelf --dynamic-table $gumluaModuleOutput) -join "`n"
if ($gumluaModuleDynamic -match "\(NEEDED\)") { throw "GumLua module unexpectedly declares DT_NEEDED entries" }

Verify-Image -Path $dexModuleOutput -Label "DexModule" -RequiredSymbols @("ghostEntry", "ghostModuleUnload")
$dexModuleDynamic = (& $readelf --dynamic-table $dexModuleOutput) -join "`n"
if ($dexModuleDynamic -match "\(NEEDED\)") { throw "DEX module unexpectedly declares DT_NEEDED entries" }

Verify-Image -Path $interceptorModuleOutput -Label "InterceptorModule" -RequiredSymbols @("ghostEntry", "ghostModuleUnload")
$interceptorModuleDynamic = (& $readelf --dynamic-table $interceptorModuleOutput) -join "`n"
if ($interceptorModuleDynamic -match "\(NEEDED\)") { throw "Interceptor module unexpectedly declares DT_NEEDED entries" }

Verify-Image -Path $lifecycleModuleOutput -Label "LifecycleModule" -RequiredSymbols @("ghostEntry", "ghostModuleUnload")
$lifecycleModuleDynamic = (& $readelf --dynamic-table $lifecycleModuleOutput) -join "`n"
if ($lifecycleModuleDynamic -match "\(NEEDED\)") { throw "Lifecycle module unexpectedly declares DT_NEEDED entries" }

Verify-Image -Path $gtraceModuleOutput -Label "GTraceModule" -RequiredSymbols @("ghostEntry", "ghostModuleUnload")
$gtraceModuleDynamic = (& $readelf --dynamic-table $gtraceModuleOutput) -join "`n"
if ($gtraceModuleDynamic -match "\(NEEDED\)") { throw "GTrace module unexpectedly declares DT_NEEDED entries" }

Verify-Image -Path $multiTraceModuleOutput -Label "MultiTraceModule" -RequiredSymbols @("ghostEntry", "ghostModuleUnload")
$multiTraceModuleDynamic = (& $readelf --dynamic-table $multiTraceModuleOutput) -join "`n"
if ($multiTraceModuleDynamic -match "\(NEEDED\)") { throw "Multi-trace module unexpectedly declares DT_NEEDED entries" }

Get-Item -LiteralPath $daemonOutput, $moduleOutput, $module2Output, $symbolModuleOutput, $jnicodeOutput, $jnicodeJavaOutput, $jnicodeMakoOutput, $labMakoOutput, $jnicodeBadverOutput, $jnicodeNosymOutput, $zygotePayloadOutput, $gumGhostOutput, $gumluaModuleOutput, $dexModuleOutput, $interceptorModuleOutput, $lifecycleModuleOutput, $gtraceModuleOutput, $multiTraceModuleOutput |
    Select-Object FullName, Length, LastWriteTime
Write-Output 'stage2-daemon PASS'
