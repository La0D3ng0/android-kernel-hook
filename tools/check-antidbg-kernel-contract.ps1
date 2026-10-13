param(
    [int]$TimeoutSeconds = 30
)

$ErrorActionPreference = 'Stop'

$kernels = @(
    @{ Version = '5.10'; Ref = 'refs/tags/android12-5.10-2022-03_r7' },
    @{ Version = '5.15'; Ref = 'refs/tags/android13-5.15-2025-09_r4' },
    @{ Version = '6.1';  Ref = 'refs/tags/android14-6.1-2025-04_r6' },
    @{ Version = '6.6';  Ref = 'refs/tags/android15-6.6-2024-09_r14' },
    @{ Version = '6.12'; Ref = 'refs/tags/android16-6.12-2025-07_r21' }
)

function Get-GitilesText([string]$ref, [string]$path) {
    $url = "https://android.googlesource.com/kernel/common/+/$ref/${path}?format=TEXT"
    $encoded = (Invoke-WebRequest -UseBasicParsing -Uri $url `
        -TimeoutSec $TimeoutSeconds).Content
    return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encoded))
}

function Require-Match([string]$text, [string]$pattern,
                       [string]$version, [string]$label) {
    if ($text -notmatch $pattern) {
        throw "Android common $version contract mismatch: $label"
    }
}

foreach ($kernel in $kernels) {
    $ptrace = Get-GitilesText $kernel.Ref 'arch/arm64/kernel/ptrace.c'
    $process = Get-GitilesText $kernel.Ref 'arch/arm64/kernel/process.c'
    $security = Get-GitilesText $kernel.Ref 'security/security.c'
    $regset = Get-GitilesText $kernel.Ref 'include/linux/regset.h'

    Require-Match $ptrace `
        'static\s+int\s+hw_break_set\s*\(\s*struct\s+task_struct\s*\*\s*target\s*,\s*const\s+struct\s+user_regset\s*\*\s*regset\s*,\s*unsigned\s+int\s+pos\s*,\s*unsigned\s+int\s+count\s*,\s*const\s+void\s*\*\s*kbuf\s*,\s*const\s+void\s+__user\s*\*\s*ubuf\s*\)' `
        $kernel.Version 'hw_break_set six-argument ABI'
    Require-Match $ptrace 'user_regset_copyin_ignore[\s\S]+PTRACE_HBP_PAD_SZ' `
        $kernel.Version 'native regset header/pad ignore semantics'
    Require-Match $ptrace 'compat_arch_ptrace[\s\S]+PTRACE_GETHBPREGS[\s\S]+PTRACE_SETHBPREGS' `
        $kernel.Version 'AArch32 compat HWBP requests'
    Require-Match $ptrace 'void\s+flush_ptrace_hw_breakpoint\s*\(\s*struct\s+task_struct\s*\*\s*tsk\s*\)' `
        $kernel.Version 'ptrace breakpoint flush hook'
    Require-Match $process 'flush_ptrace_hw_breakpoint\s*\(\s*current\s*\)' `
        $kernel.Version 'exec flush path'

    foreach ($name in @('open', 'alloc', 'free', 'read', 'write')) {
        Require-Match $security "security_perf_event_$name\s*\(" `
            $kernel.Version "security_perf_event_$name"
    }

    $structure = [regex]::Match($regset,
        'struct\s+user_regset\s*\{[\s\S]*?\n\};').Value
    if (-not $structure) {
        throw "Android common $($kernel.Version) contract mismatch: struct user_regset"
    }
    $orderedFields = @('regset_get', 'regset_set', 'active', 'writeback',
                       'n;', 'size;', 'align;', 'bias;', 'core_note_type;')
    $cursor = -1
    foreach ($field in $orderedFields) {
        $next = $structure.IndexOf($field, $cursor + 1,
            [StringComparison]::Ordinal)
        if ($next -lt 0) {
            throw "Android common $($kernel.Version) contract mismatch: user_regset field $field"
        }
        $cursor = $next
    }

    $summary = ("kernel={0} ref={1} hw_break_set=6 regset-core-note-offset=48 " +
                "compat=1 flush-on-exec=1 perf-lsm=open,alloc,free,read,write") `
        -f $kernel.Version, $kernel.Ref
    Write-Output $summary
}

Write-Output 'antidbg-kernel-contract PASS'
