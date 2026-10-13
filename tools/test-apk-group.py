"""Run one test-apk/<group> through static, KPM/Gum/Lua and Frida checks.

Every APK gets an isolated fresh KernelPatch boot.  Evidence is retained under
out/apk-groups/group-<n>/.  The primary Markdown report is written beside the
tested APKs as test-apk/<n>/TEST_REPORT.md and mirrored under docs/reports.  If
no device is attached, static analysis still completes and the report records
the dynamic phase as BLOCKED.
"""

from __future__ import annotations

import argparse
import os
import datetime as dt
import hashlib
import json
import pathlib
import re
import subprocess
import time
import zipfile
from typing import Any


MARKERS = (
    b"frida",
    b"gum-js-loop",
    b"gmain",
    b"linjector",
    b"xposed",
    b"substrate",
    b"magisk",
    b"tracerpid",
    b"/proc/self/maps",
    b"/proc/self/status",
    b"/proc/net/tcp",
    b"ptrace",
    b"perf_event_open",
    b"ro.debuggable",
    b"ro.secure",
    b"zygisk",
)


def run(
    command: list[str], *, check: bool = True, timeout: int | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=check,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def first(pattern: str, text: str, label: str) -> str:
    match = re.search(pattern, text, re.MULTILINE)
    if not match:
        raise RuntimeError(f"cannot parse {label}")
    return match.group(1)


def analyze_apk(
    apk: pathlib.Path, aapt: pathlib.Path, apksigner: pathlib.Path
) -> dict[str, Any]:
    badging = run([str(aapt), "dump", "badging", str(apk)]).stdout
    signing = run(
        [str(apksigner), "verify", "--verbose", "--print-certs", str(apk)]
    ).stdout
    package = first(r"^package: name='([^']+)'", badging, "package")
    version = first(r"^package: .* versionName='([^']+)'", badging, "versionName")
    version_code = first(r"^package: .* versionCode='([^']+)'", badging, "versionCode")
    activity = first(r"^launchable-activity: name='([^']+)'", badging, "activity")
    component = f"{package}/{activity}"
    target_sdk_match = re.search(r"^targetSdkVersion:'([^']+)'", badging, re.MULTILINE)
    min_sdk_match = re.search(r"^sdkVersion:'([^']+)'", badging, re.MULTILINE)
    cert_match = re.search(
        r"Signer #1 certificate SHA-256 digest: ([0-9a-f]+)", signing, re.I
    )
    labels = re.findall(r"^application-label(?:-[^:]+)?:'([^']*)'", badging, re.MULTILINE)
    native_code = re.search(r"^native-code: (.+)$", badging, re.MULTILINE)
    markers: dict[str, dict[str, int]] = {}
    libraries: list[str] = []
    dex_files: list[str] = []
    packed_assets: list[str] = []
    with zipfile.ZipFile(apk) as archive:
        for name in archive.namelist():
            if name.endswith(".dex"):
                dex_files.append(name)
            if name.startswith("lib/") and name.endswith(".so"):
                libraries.append(name)
            if "jiagu" in name.lower() or "protect" in name.lower():
                packed_assets.append(name)
            if not (name.endswith(".dex") or name.endswith(".so")):
                continue
            data = archive.read(name).lower()
            found = {
                marker.decode("ascii"): data.count(marker)
                for marker in MARKERS
                if marker in data
            }
            if found:
                markers[name] = found
    manifest = run(
        [str(aapt), "dump", "xmltree", str(apk), "AndroidManifest.xml"]
    ).stdout
    application_match = re.search(
        r"E: application \([^\n]+\)(.*?)(?=\n\s{4}E: (?:activity|service|receiver|provider|uses-library) \(|\Z)",
        manifest,
        re.DOTALL,
    )
    application_block = application_match.group(1) if application_match else ""
    app_class_match = re.search(
        r'android:name\([^\n]+\)="([^"]+)"', application_block
    )
    debuggable_match = re.search(r"android:debuggable[^\n]+=.*0xffffffff", application_block)
    return {
        "file": apk.name,
        "path": str(apk),
        "sha256": sha256(apk),
        "size": apk.stat().st_size,
        "package": package,
        "version": version,
        "versionCode": version_code,
        "label": labels[0] if labels else "",
        "activity": activity,
        "component": component,
        "minSdk": min_sdk_match.group(1) if min_sdk_match else "",
        "targetSdk": target_sdk_match.group(1) if target_sdk_match else "",
        "nativeCode": native_code.group(1) if native_code else "",
        "certificateSha256": cert_match.group(1).lower() if cert_match else "",
        "applicationClass": app_class_match.group(1) if app_class_match else "",
        "debuggable": bool(debuggable_match),
        "dexFiles": dex_files,
        "libraries": libraries,
        "packedAssets": sorted(packed_assets),
        "markers": markers,
    }


def adb(adb_path: pathlib.Path, serial: str, *args: str, check: bool = True) -> str:
    return run([str(adb_path), "-s", serial, *args], check=check).stdout.strip()


def su(adb_path: pathlib.Path, serial: str, command: str, check: bool = True) -> str:
    quoted = command.replace("'", "'\"'\"'")
    return adb(adb_path, serial, "shell", f"su -c '{quoted}'", check=check)


def cleanup_frida_server(adb_path: pathlib.Path, serial: str) -> dict[str, Any]:
    """Remove the visible Frida control run before the clean recovery probe.

    Detaching the session only removes the in-process agent.  Applications that
    scan /data/local/tmp or the process list still see the server and may execute
    their anti-Frida kill path, which would falsely look like a KPM cleanup bug.
    """

    before = su(adb_path, serial, "pidof rtgum-frida-server", check=False)
    file_before = su(
        adb_path,
        serial,
        "[ -e /data/local/tmp/rtgum-frida-server ] && echo 1 || echo 0",
        check=False,
    ) == "1"
    su(
        adb_path,
        serial,
        "pkill -f '[r]tgum-frida-server' 2>/dev/null || true",
        check=False,
    )
    deadline = time.monotonic() + 5.0
    after = before
    while time.monotonic() < deadline:
        after = su(adb_path, serial, "pidof rtgum-frida-server", check=False)
        if not after:
            break
        time.sleep(0.25)
    if after:
        su(
            adb_path,
            serial,
            "pkill -9 -f '[r]tgum-frida-server' 2>/dev/null || true",
            check=False,
        )
        time.sleep(0.25)
        after = su(adb_path, serial, "pidof rtgum-frida-server", check=False)
    su(
        adb_path,
        serial,
        "rm -f /data/local/tmp/rtgum-frida-server "
        "/data/local/tmp/rtgum-frida-server.log",
        check=False,
    )
    file_after = su(
        adb_path,
        serial,
        "[ -e /data/local/tmp/rtgum-frida-server ] && echo 1 || echo 0",
        check=False,
    ) == "1"
    return {
        "pidsBefore": before.split(),
        "pidsAfter": after.split(),
        "fileBefore": file_before,
        "fileAfter": file_after,
    }


def install_apk(
    adb_path: pathlib.Path,
    serial: str,
    apk: pathlib.Path,
    *,
    timeout: int = 180,
) -> subprocess.CompletedProcess[str]:
    """Install one fixture while restoring Android verifier policy afterwards.

    Android 16's package verifier can reject older protected APK fixtures even
    when the same APK was explicitly selected for a local device test.  Change
    only the three verifier settings for the duration of the install and put
    every original value back before launching the app.
    """

    overrides = {
        "verifier_verify_adb_installs": "0",
        "package_verifier_enable": "0",
        "package_verifier_user_consent": "-1",
    }
    original = {
        key: adb(
            adb_path,
            serial,
            "shell",
            "settings",
            "get",
            "global",
            key,
            check=False,
        )
        for key in overrides
    }
    try:
        for key, value in overrides.items():
            adb(
                adb_path,
                serial,
                "shell",
                "settings",
                "put",
                "global",
                key,
                value,
            )
        return run(
            [
                str(adb_path),
                "-s",
                serial,
                "install",
                "--no-streaming",
                "-r",
                "-d",
                str(apk),
            ],
            check=False,
            timeout=timeout,
        )
    finally:
        for key, value in original.items():
            if not value or value == "null":
                adb(
                    adb_path,
                    serial,
                    "shell",
                    "settings",
                    "delete",
                    "global",
                    key,
                    check=False,
                )
            else:
                adb(
                    adb_path,
                    serial,
                    "shell",
                    "settings",
                    "put",
                    "global",
                    key,
                    value,
                    check=False,
                )


def pid_candidates(adb_path: pathlib.Path, serial: str, package: str) -> list[int]:
    text = adb(adb_path, serial, "shell", "pidof", package, check=False)
    return sorted({int(value) for value in text.split() if value.isdigit()})


def process_info(
    adb_path: pathlib.Path, serial: str, pid: int
) -> dict[str, int] | None:
    status = su(
        adb_path, serial, f"cat /proc/{pid}/status 2>/dev/null", check=False
    )
    if not status:
        return None
    fields: dict[str, int] = {}
    for line in status.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        if key in {"Pid", "PPid", "TracerPid", "Threads"}:
            token = value.strip().split()[0] if value.strip() else ""
            if token.isdigit():
                fields[key] = int(token)
    if fields.get("Pid") != pid:
        return None
    stat = su(adb_path, serial, f"cat /proc/{pid}/stat 2>/dev/null", check=False)
    close = stat.rfind(")")
    tail = stat[close + 2 :].split() if close >= 0 else []
    # /proc/<pid>/stat field 22 is starttime; tail[0] is field 3.
    start_time = int(tail[19]) if len(tail) > 19 and tail[19].isdigit() else 0
    return {
        "pid": pid,
        "ppid": fields.get("PPid", 0),
        "tracerPid": fields.get("TracerPid", -1),
        "threads": fields.get("Threads", 0),
        "startTime": start_time,
    }


def process_inventory(
    adb_path: pathlib.Path, serial: str, package: str
) -> list[dict[str, int]]:
    return [
        info
        for pid in pid_candidates(adb_path, serial, package)
        if (info := process_info(adb_path, serial, pid)) is not None
    ]


def pidof(adb_path: pathlib.Path, serial: str, package: str) -> int:
    """Select the Android app process when a shell adds a same-name guard.

    Several commercial shells fork a one-thread child, rename it to the package,
    and optionally use it as a ptrace watchdog.  Treating multi-value pidof output
    as failure makes both the healthy baseline and Frida result inconclusive.  The
    real app is the candidate whose parent is outside the candidate set; thread
    count and start time make the choice deterministic if more than one remains.
    """

    inventory = process_inventory(adb_path, serial, package)
    if not inventory:
        return 0
    ids = {item["pid"] for item in inventory}
    roots = [item for item in inventory if item["ppid"] not in ids]
    pool = roots or inventory
    pool.sort(
        key=lambda item: (
            -item["threads"],
            item["startTime"] if item["startTime"] else 2**63,
            item["pid"],
        )
    )
    return pool[0]["pid"]


def process_alive(adb_path: pathlib.Path, serial: str, pid: int) -> bool:
    return process_info(adb_path, serial, pid) is not None


def wait_device(adb_path: pathlib.Path, serial: str, timeout: int = 240) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = adb(adb_path, serial, "get-state", check=False)
        booted = adb(
            adb_path, serial, "shell", "getprop", "sys.boot_completed", check=False
        )
        if state == "device" and booted == "1":
            return
        time.sleep(3)
    raise RuntimeError("device did not finish booting")


def fresh_boot(
    adb_path: pathlib.Path,
    fastboot: pathlib.Path,
    boot_image: pathlib.Path,
    serial: str,
) -> dict[str, str]:
    before = adb(
        adb_path,
        serial,
        "shell",
        "cat",
        "/proc/sys/kernel/random/boot_id",
        check=False,
    )
    adb(adb_path, serial, "reboot", "bootloader")
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        devices = run([str(fastboot), "devices"], check=False).stdout
        if serial in devices:
            break
        time.sleep(2)
    else:
        raise RuntimeError("device did not enter fastboot")
    boot = run([str(fastboot), "-s", serial, "boot", str(boot_image)], check=False)
    if boot.returncode != 0:
        raise RuntimeError(f"fastboot boot failed: {boot.stdout} {boot.stderr}")
    wait_device(adb_path, serial)
    after = adb(
        adb_path, serial, "shell", "cat", "/proc/sys/kernel/random/boot_id"
    )
    if before and before == after:
        raise RuntimeError("fresh boot did not change boot_id")
    return {"before": before, "after": after, "fastboot": boot.stdout.strip()}


def wait_stable_pid(
    adb_path: pathlib.Path, serial: str, package: str, timeout: int = 30
) -> int:
    deadline = time.monotonic() + timeout
    candidate = 0
    since = 0.0
    while time.monotonic() < deadline:
        current = pidof(adb_path, serial, package)
        if current > 0 and current == candidate:
            if time.monotonic() - since >= 2.0:
                return current
        else:
            candidate = current
            since = time.monotonic()
        time.sleep(0.25)
    return 0


def launch_probe(
    adb_path: pathlib.Path,
    serial: str,
    package: str,
    component: str,
    quiet_seconds: int,
) -> dict[str, Any]:
    adb(adb_path, serial, "logcat", "-b", "crash", "-c", check=False)
    adb(adb_path, serial, "shell", "am", "force-stop", package, check=False)
    start = adb(
        adb_path,
        serial,
        "shell",
        "am",
        "start",
        "-f",
        "0x10008000",
        "-n",
        component,
        check=False,
    )
    pid = wait_stable_pid(adb_path, serial, package)
    if pid <= 0:
        return {"pass": False, "start": start, "failure": "no stable PID"}
    inventory_before = process_inventory(adb_path, serial, package)
    candidates_before = [item["pid"] for item in inventory_before]
    tracer = su(
        adb_path,
        serial,
        f"awk '/^TracerPid:/{{print $2}}' /proc/{pid}/status",
        check=False,
    )
    # Stop waiting as soon as the exact process dies.  The caller may perform
    # one documented cold-start retry for applications whose first-run UI has
    # its own transient crash; waiting out the whole observation window adds
    # no evidence once /proc/<pid> is gone.
    deadline = time.monotonic() + quiet_seconds
    while time.monotonic() < deadline and process_alive(adb_path, serial, pid):
        time.sleep(min(0.5, deadline - time.monotonic()))
    inventory_after = process_inventory(adb_path, serial, package)
    candidates_after = [item["pid"] for item in inventory_after]
    after = pidof(adb_path, serial, package)
    alive = process_alive(adb_path, serial, pid)
    after_info = process_info(adb_path, serial, pid)
    tracer_after = after_info["tracerPid"] if after_info else -1
    tracer_value = int(tracer) if tracer.isdigit() else -1
    tracer_is_app_owned = tracer_value > 0 and tracer_value in candidates_before
    tracer_after_is_app_owned = (
        tracer_after > 0 and tracer_after in candidates_after
    )
    tracer_allowed = tracer_value == 0 or tracer_is_app_owned
    tracer_after_allowed = tracer_after == 0 or tracer_after_is_app_owned
    crash = adb(
        adb_path,
        serial,
        "logcat",
        "-b",
        "crash",
        "-d",
        "-v",
        "threadtime",
        check=False,
    )
    adb(adb_path, serial, "shell", "am", "force-stop", package, check=False)
    return {
        "pass": alive and tracer_allowed and tracer_after_allowed and package not in crash,
        "start": start,
        "pid": pid,
        "pidAfter": after,
        "processAliveAfter": alive,
        "pidCandidatesBefore": candidates_before,
        "pidCandidatesAfter": candidates_after,
        "tracerPid": tracer,
        "tracerPidAfter": tracer_after,
        "appOwnedTracer": tracer_is_app_owned or tracer_after_is_app_owned,
        "crashLog": crash,
    }


def render_report(
    report_path: pathlib.Path,
    group: str,
    records: list[dict[str, Any]],
    device_status: str,
    device_meta: dict[str, str] | None,
    quiet_seconds: int,
) -> None:
    generated = dt.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %z")
    lines = [
        f"# test-apk/{group} 链路测试报告",
        "",
        f"- 生成时间：{generated}",
        f"- 动态测试状态：**{device_status}**",
        "- 判定拆分：内核/Gum/Lua 链路与普通可见 Frida 分开报告。",
        "",
        "## 测试方法",
        "",
        f"- 每个可安装 APK 使用独立 fresh boot，并分别观察 {quiet_seconds} 秒基线、"
        f"{quiet_seconds} 秒 KPM/Gum/Lua Hook、{quiet_seconds} 秒普通 Frida 和 "
        f"{quiet_seconds} 秒卸载恢复。",
        "- 每次安装并核对 APK 哈希后清除应用数据，避免上一轮保存状态、缓存或账号会话"
        "污染无 Hook 基线。",
        "- 若清数据后的无 Hook 冷启动因应用自身异常退出，最多进行三次冷启动；每次"
        "失败都保留日志，首个稳定结果作为可运行基线，所有前置失败仍显式列出。",
        "- APK 不包含设备支持的 ABI 时记为 `BLOCKED` 并保留 PackageManager 原始错误，"
        "不把设备兼容性阻塞计成 Hook 链路失败。",
        "- KPM 链路验证 `Zygote → Daemon → .ghm → Gum → Lua`，对 "
        "`libc.so!open/openat` 安装 Hook，要求目标 PID 命中、持续存活并完成清理。",
        "- 普通 Frida 同时安装 native `getpid/openat` 与 Java "
        "`ContextWrapper.getPackageName` Hook，每秒 RPC 读取心跳。进程存活按原始 "
        "`/proc/<pid>/stat` 判定；若壳创建同包名守护进程，则按父子关系、线程数"
        "与启动时间选定业务主进程，并保留全部候选 PID。",
        "- 恢复阶段先停止 Frida server，并删除测试 server 与日志文件，避免把可见"
        "控制面仍在运行时的反 Frida 退出误判为 KPM 卸载污染。",
        "- APK 与所有推送产物均校验 SHA-256；安装验证器只在安装窗口临时调整，"
        "完成后恢复原设置。",
        "",
        "## 本轮运行时与测试工具修复",
        "",
        "- Gum 后端在绑定时复制 `RtGumHost` 表，并由显式能力位决定是否调用 ghost "
        "内存回调，消除异步 Gum worker 对 Daemon 数据页的借用生命周期。",
        "- KPM 的 `exec_mmap` 清理增加 `mm_users` 门控；`vfork/CLONE_VM` 子进程 "
        "exec 时不再误删仍由父进程使用的 Daemon、模块和 Lua ghost 映射。",
        "- Frida 存活判定固定跟踪原始 `/proc/<pid>/stat`，避免壳改变进程名后 "
        "`pidof` 返回空而形成假失败。",
        "- 多 PID 判定识别壳的同名一线程守护进程；应用自有 tracer 单独标注，"
        "不会被误当成测试器残留的外部 tracer。",
        "- Stage-1 控制器的进程定位同步改为按父子关系和线程数选择业务主进程，"
        "不再依赖 `/proc` 目录枚举的偶然顺序。",
        "- Gum/Lua ELF 字节只进入 KPM 缓存；Daemon 内存 linker 直接建立 VMA-less "
        "PTE，不使用应用 `code_cache` staging，也不把 backend 注册进平台 `link_map`。",
        "- Gum 修改普通 SO 代码时使用 execute-only Shadow Code Page；普通读取与 GUP "
        "看到原始页，CPU 取指看到补丁页。应用自身写同页时通过 COW + task_work + "
        "单步完成差分同步并重放框架补丁。",
        "- Shadow 补丁、Gum/Lua linker 镜像、普通 ghost span 与 near thunk 组成完整的 "
        "fork 传播闭包；子进程获得独立物理页副本。",
        "- KPM 卸载只解绑全局热路径回调并保留空的 KernelPatch transit，避免在途 CPU "
        "与 live-text hot-unpatch 竞争。",
        "- 普通 Frida 与干净恢复之间显式清理 server 进程和文件；保留清理前恢复"
        "作为 A/B 对照，避免会话 detach 与控制面卸载混为一谈。",
        "- smoke 失败时先保存全缓冲 logcat 与 `ApplicationExitInfo`，防止后续 "
        "force-stop 覆盖真实退出现场。",
        "- 内核 linker 将 maps 中同一路径、同基址的重复行识别为 seq-file 撕裂快照并"
        "返回 `EAGAIN`；Daemon 有界重取快照，同名不同基址仍按歧义映射拒绝。",
        "- 自动化 smoke 失败后会解除 Zygote 镜像、停止继承进程并卸载 KPM；若引用在"
        "限定时间内仍未归零，则重启到干净系统后再进行普通 Frida 对照。",
        "",
        "## 测试边界",
        "",
        "- Daemon、`.ghm`、Gum、Lua 以及 Gum 运行时代码池均为 VMA-less PTE。"
        "验收同时检查 `/proc/<pid>/maps` 与 `/proc/<pid>/smaps`，并拒绝 backend "
        "命名段、staging 文件和 `link_map` 注册。应用自身的堆、ART/JIT 与系统 SO "
        "仍按 Android 原生方式可见。",
        "- 本轮 maps 隐身口径不覆盖具备内核权限、直接遍历页表或扫描 PFN 的检测器。",
        f"- 动态观察窗口为每阶段 {quiet_seconds} 秒；结论覆盖正常启动与本轮操作，"
        "不等同于长时间运行或应用内所有业务路径。",
        "",
        "## APK 清单与静态画像",
        "",
        "| APK | 包名 / 版本 | SDK | ABI / Native | 壳与静态保护线索 |",
        "| --- | --- | --- | --- | --- |",
    ]
    for record in records:
        marker_names = sorted(
            {marker for values in record["markers"].values() for marker in values}
        )
        protection = []
        if record["applicationClass"]:
            protection.append(f"Application={record['applicationClass']}")
        if record["packedAssets"]:
            protection.append("jiagu/protect 资源")
        if marker_names:
            protection.append("字符串：" + ", ".join(marker_names))
        lines.append(
            f"| `{record['file']}` | `{record['package']}` {record['version']} "
            f"({record['versionCode']}) | min {record['minSdk']} / target "
            f"{record['targetSdk']} | {record['nativeCode'] or '无'} / "
            f"{len(record['libraries'])} SO | {'；'.join(protection) or '未见明显线索'} |"
        )
    lines += [
        "",
        "静态字符串只能作为动态测试优先级线索，不能单独证明存在反 Frida 行为。",
        "",
        "## 文件与签名证据",
        "",
    ]
    for record in records:
        lines += [
            f"### {record['package']}",
            "",
            f"- SHA-256：`{record['sha256']}`",
            f"- 签名证书 SHA-256：`{record['certificateSha256']}`",
            f"- 启动组件：`{record['component']}`",
            f"- DEX：{', '.join(record['dexFiles'])}",
            f"- debuggable：`{str(record['debuggable']).lower()}`",
            "",
        ]
    if device_meta:
        lines += [
            "## 设备环境",
            "",
            f"- 设备：`{device_meta.get('model', '')}`",
            f"- Fingerprint：`{device_meta.get('fingerprint', '')}`",
            f"- Android：`{device_meta.get('android', '')}`",
            f"- ABI：`{device_meta.get('abi', '')}`",
            f"- Kernel：`{device_meta.get('kernel', '')}`",
            "",
        ]
    lines += [
        "## 动态结果",
        "",
        "| 包名 | 无 Hook 启动/恢复 | KPM→Zygote→Daemon→Gum/Lua | maps/smaps | Hook 存活 | 普通 Frida native+Java | 结论 |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for record in records:
        dynamic = record.get("dynamic", {})
        compatibility = dynamic.get("compatibility", {})
        baseline = dynamic.get("baseline", {})
        kernel = dynamic.get("kernel", {})
        frida_result = dynamic.get("frida", {})
        recovery = dynamic.get("recovery", {})
        kernel_pass = bool(kernel.get("pass"))
        frida_pass = bool(frida_result.get("pass"))
        baseline_pass = bool(baseline.get("pass"))
        recovered = bool(recovery.get("pass"))
        if compatibility:
            values = (
                "BLOCKED",
                "未运行",
                "未运行",
                "未运行",
                "未运行",
                "设备 ABI 不兼容",
            )
        elif device_status == "BLOCKED":
            values = ("未运行", "未运行", "未运行", "未运行", "未运行", "BLOCKED")
        else:
            baseline_flaky = (
                not baseline_pass
                and recovered
                and bool(dynamic.get("baselineFailedAttempts"))
            )
            chain_pass = kernel_pass and recovered
            values = (
                (
                    "PASS"
                    if baseline_pass and recovered
                    else "首启 FAIL / 恢复 PASS"
                    if baseline_flaky
                    else "FAIL"
                ),
                "PASS" if kernel_pass else "FAIL",
                "HIDDEN"
                if kernel.get("mapsHidden") and kernel.get("smapsHidden")
                else "FAIL",
                "PASS" if kernel.get("survived") else "FAIL",
                "PASS" if frida_pass else "FAIL（见逐包证据）",
                (
                    "PASS（样本首启异常）"
                    if chain_pass and baseline_flaky
                    else "PASS"
                    if baseline_pass and chain_pass
                    else "链路未通过"
                ),
            )
        lines.append(
            f"| `{record['package']}` | {values[0]} | {values[1]} | {values[2]} | "
            f"{values[3]} | {values[4]} | **{values[5]}** |"
        )
    lines += ["", "## 逐包证据", ""]
    for record in records:
        dynamic = record.get("dynamic", {})
        lines += [f"### {record['package']}", ""]
        compatibility = dynamic.get("compatibility")
        if compatibility:
            lines += [
                "- 动态阶段：`BLOCKED`",
                f"  - 原因：`{compatibility.get('reason', 'device compatibility')}`",
                f"  - APK ABI：`{compatibility.get('apkAbis', '')}`；设备 ABI："
                f"`{compatibility.get('deviceAbis', '')}`",
                f"  - 安装器：`{compatibility.get('installerError', '')}`",
                f"  - 证据文件：`{compatibility.get('evidence', '')}`",
                "",
            ]
            continue
        if device_status == "BLOCKED":
            lines += ["- 动态阶段未运行：ADB 与 fastboot 均未发现目标设备。", ""]
            continue
        for name, label in (
            ("baseline", "基线"),
            ("kernel", "内核/Gum/Lua"),
            ("frida", "普通 Frida"),
            ("recovery", "卸载后恢复"),
        ):
            value = dynamic.get(name, {})
            lines.append(f"- {label}：`{'PASS' if value.get('pass') else 'FAIL'}`")
            if value.get("failure"):
                lines.append(f"  - 失败：`{value['failure']}`")
            if value.get("evidence"):
                lines.append(f"  - 证据文件：`{value['evidence']}`")
            if name == "baseline" and value:
                lines.append(
                    f"  - PID：`{value.get('pid', 0)}` → `{value.get('pidAfter', 0)}`；"
                    f"候选={value.get('pidCandidatesBefore', [])} → "
                    f"{value.get('pidCandidatesAfter', [])}；TracerPid="
                    f"`{value.get('tracerPid', '')}` → "
                    f"`{value.get('tracerPidAfter', '')}`；应用自有 tracer="
                    f"`{str(bool(value.get('appOwnedTracer'))).lower()}`"
                )
                failed_attempts = dynamic.get("baselineFailedAttempts", [])
                for attempt_index, attempt in enumerate(failed_attempts, 1):
                    attempt_crash = str(attempt.get("crashLog") or "")
                    exception = re.search(
                        r"(?:FATAL EXCEPTION:[^\n]*\n.*?\n)?[^\n]*?(java\.[A-Za-z0-9_.]+(?:Exception|Error):[^\n]*)",
                        attempt_crash,
                        re.DOTALL,
                    )
                    summary = (
                        exception.group(1).strip()
                        if exception
                        else attempt.get("failure", "process exited")
                    )
                    lines.append(
                        f"  - 清数据冷启动尝试 {attempt_index}：`FAIL`；原因："
                        f"`{summary}`；证据：`{attempt.get('evidence', '')}`"
                    )
                if failed_attempts:
                    lines.append(
                        f"  - 最终基线尝试 {len(failed_attempts) + 1}："
                        f"`{'PASS' if value.get('pass') else 'FAIL'}`"
                    )
            if name == "kernel" and value:
                lines.append(
                    f"  - PID：`{value.get('pid', 0)}`；armed="
                    f"`{str(bool(value.get('armed'))).lower()}`；hook fired="
                    f"`{str(bool(value.get('hookFired'))).lower()}`；"
                    f"maps hidden=`{str(bool(value.get('mapsHidden'))).lower()}`；"
                    f"smaps hidden=`{str(bool(value.get('smapsHidden'))).lower()}`；"
                    f"backends VMA-less="
                    f"`{str(bool(value.get('backendsVmaless'))).lower()}`"
                )
            if name == "frida" and value:
                final = value.get("final") or (
                    value.get("snapshots", [{}])[-1]
                    if value.get("snapshots")
                    else {}
                )
                if not final:
                    final = next(
                        (
                            item
                            for item in reversed(value.get("messages", []))
                            if isinstance(item, dict) and item.get("kind") == "heartbeat"
                        ),
                        {},
                    )
                kinds = {
                    item.get("kind")
                    for item in value.get("messages", [])
                    if isinstance(item, dict)
                }
                detached = value.get("detached")
                detach_summary = "none"
                if isinstance(detached, dict):
                    detach_summary = str(detached.get("reason", "unknown"))
                    crash_text = str(detached.get("crash") or "")
                    fault = re.search(r"fault addr (0x[0-9a-fA-F]+)", crash_text)
                    if fault:
                        detach_summary += f"; fault={fault.group(1)}"
                lines.append(
                    f"  - PID：`{value.get('pid', 0)}`；原 PID 存活="
                    f"`{str(bool(value.get('processAliveAfter'))).lower()}`；"
                    f"pidof=`{value.get('pidofAfter', value.get('pidAfter', 0))}`；"
                    f"候选={value.get('pidCandidatesBefore', [])} → "
                    f"{value.get('pidCandidatesAfter', [])}；"
                    f"TracerPid `{value.get('tracerPidBefore', '')}` → "
                    f"`{value.get('tracerPidDuring', '')}`"
                )
                lines.append(
                    f"  - native ready=`{str('native-ready' in kinds).lower()}`；"
                    f"Java ready=`{str('java-ready' in kinds).lower()}`；心跳="
                    f"`{final.get('heartbeats', final.get('sequence', 0))}`；native hits="
                    f"`{final.get('nativeHits', 0)}`；Java hits="
                    f"`{final.get('javaHits', 0)}`；脚本错误="
                    f"`{len(value.get('errors', []))}`；观察期 detach="
                    f"`{detach_summary}`"
                )
                if value.get("failurePhase") or value.get("exitSignal"):
                    lines.append(
                        f"  - 失败阶段=`{value.get('failurePhase', 'unknown')}`；"
                        f"退出信号=`{value.get('exitSignal', 'unknown')}`；"
                        "符合可见 Frida 触发的主动终止="
                        f"`{str(bool(value.get('probableAntiFridaKill'))).lower()}`"
                    )
                if value.get("diagnosticRecheck"):
                    lines.append(
                        f"  - 诊断复验：`{value.get('diagnosticRecheck')}`；"
                        f"清理后无 Hook 恢复："
                        f"`{'PASS' if value.get('diagnosticRecoveryPass') else 'FAIL'}`；"
                        f"证据：`{value.get('diagnosticRecoveryEvidence', '')}`"
                    )
                visible_recovery = dynamic.get("recoveryWithVisibleServer")
                if visible_recovery:
                    lines.append(
                        "  - A/B 对照：Frida 控制面仍可见时恢复="
                        f"`{'PASS' if visible_recovery.get('pass') else 'FAIL'}`；"
                        "清理控制面后的恢复结果见下项。"
                    )
            if name == "recovery" and value:
                lines.append(
                    f"  - PID：`{value.get('pid', 0)}` → `{value.get('pidAfter', 0)}`；"
                    f"候选={value.get('pidCandidatesBefore', [])} → "
                    f"{value.get('pidCandidatesAfter', [])}；TracerPid="
                    f"`{value.get('tracerPid', '')}` → "
                    f"`{value.get('tracerPidAfter', '')}`；应用自有 tracer="
                    f"`{str(bool(value.get('appOwnedTracer'))).lower()}`"
                )
        selector = dynamic.get("selectorFixSmoke")
        if selector:
            lines.append(
                "- 多 PID 控制器与后端清理回归："
                f"`{'PASS' if selector.get('pass') else 'FAIL'}`；PID="
                f"`{selector.get('pid', 0)}`；观察=`{selector.get('quietSeconds', 0)}` 秒；"
                f"staging 清理=`{str(bool(selector.get('stagedBackendsCleaned'))).lower()}`；"
                f"证据文件：`{selector.get('evidence', '')}`"
            )
        lines.append("")
    lines += [
        "## 判定口径",
        "",
        "1. 内核链路必须出现单包验收 PASS、PID 级 `open/openat` 命中、限定时间存活和完整清理。",
        "2. 普通 Frida 必须同时完成 native 与 Java hook，期间 PID 不变、session 不 detach、心跳持续。",
        "3. 每个包完成后重新无 Hook 启动；原业务 PID 存活、无外部 tracer 且 "
        "crash buffer 无该包记录才算恢复。壳创建的同 UID/同包守护 tracer 会明确"
        "记录，但不作为测试器泄漏。",
        "4. 普通 Frida 被应用加固杀死会单独报告，不直接否定 KPM/Gum 链路。",
        "5. 设备不支持 APK ABI 时标记 `BLOCKED`；需要相应 ABI 的真机补测，不能以"
        "重打包或替换原生库的结果代替原样 APK 验收。",
        "",
    ]
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    root = pathlib.Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser()
    parser.add_argument("--group", default="1")
    parser.add_argument("--serial", default=os.environ.get("ANDROID_SERIAL", ""))
    parser.add_argument("--quiet-seconds", type=int, default=15)
    parser.add_argument("--static-only", action="store_true")
    args = parser.parse_args()
    if not args.serial and not args.static_only:
        parser.error('--serial is required (or set ANDROID_SERIAL)')
    if not re.fullmatch(r"[0-9]+", args.group):
        raise SystemExit("group must be numeric")
    if not 5 <= args.quiet_seconds <= 120:
        raise SystemExit("quiet-seconds must be between 5 and 120")

    sdk = pathlib.Path.home() / "AppData" / "Local" / "Android" / "Sdk"
    aapt = sdk / "build-tools" / "35.0.0" / "aapt.exe"
    apksigner = sdk / "build-tools" / "35.0.0" / "apksigner.bat"
    adb_path = root / ".toolchains" / "platform-tools-37.0.1" / "platform-tools" / "adb.exe"
    fastboot = root / ".toolchains" / "platform-tools-37.0.1" / "platform-tools" / "fastboot.exe"
    boot_image = root / "out" / "device" / "pixel8" / "boot-kp0139-stage1-v5-cp1a.260405.005.img"
    python = root / ".toolchains" / "frida-pixel8-17.22.0" / "Scripts" / "python.exe"
    group_dir = root / "test-apk" / args.group
    output_dir = root / "out" / "apk-groups" / f"group-{args.group}"
    report_path = group_dir / "TEST_REPORT.md"
    report_mirror = root / "docs" / "reports" / f"test-apk-group-{args.group}.md"
    output_dir.mkdir(parents=True, exist_ok=True)
    apks = sorted(group_dir.glob("*.apk"))
    if not apks:
        raise SystemExit(f"no APKs in {group_dir}")
    records = [analyze_apk(apk, aapt, apksigner) for apk in apks]
    (output_dir / "static.json").write_text(
        json.dumps(records, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    devices = run([str(adb_path), "devices"], check=False).stdout
    connected = bool(re.search(rf"^{re.escape(args.serial)}\s+device$", devices, re.M))
    device_meta: dict[str, str] | None = None
    if args.static_only or not connected:
        render_report(
            report_path, args.group, records, "BLOCKED", None, args.quiet_seconds
        )
        render_report(
            report_mirror, args.group, records, "BLOCKED", None, args.quiet_seconds
        )
        print(f"report={report_path}")
        reason = "static-only" if args.static_only else "device-not-connected"
        print(f"dynamic=BLOCKED reason={reason}")
        return 0 if args.static_only else 2

    device_meta = {
        "model": adb(adb_path, args.serial, "shell", "getprop", "ro.product.model"),
        "fingerprint": adb(adb_path, args.serial, "shell", "getprop", "ro.build.fingerprint"),
        "android": adb(adb_path, args.serial, "shell", "getprop", "ro.build.version.release"),
        "abi": adb(adb_path, args.serial, "shell", "getprop", "ro.product.cpu.abi"),
        "kernel": adb(adb_path, args.serial, "shell", "uname", "-r"),
    }
    any_failure = False
    any_blocked = False
    for index, record in enumerate(records):
        record["dynamic"] = {}
        label = re.sub(r"[^A-Za-z0-9_-]", "_", record["package"])[-48:]
        evidence_dir = output_dir / label
        evidence_dir.mkdir(parents=True, exist_ok=True)
        for stale_evidence in evidence_dir.iterdir():
            if stale_evidence.is_file():
                stale_evidence.unlink()
        try:
            record["dynamic"]["boot"] = fresh_boot(
                adb_path, fastboot, boot_image, args.serial
            )
            install = install_apk(
                adb_path, args.serial, pathlib.Path(record["path"]), timeout=180
            )
            (evidence_dir / "install.txt").write_text(
                install.stdout + install.stderr, encoding="utf-8"
            )
            if install.returncode != 0 or "Success" not in install.stdout:
                install_text = install.stdout + install.stderr
                if "INSTALL_FAILED_NO_MATCHING_ABIS" in install_text:
                    record["dynamic"]["compatibility"] = {
                        "reason": "APK has no ABI supported by this device",
                        "apkAbis": record.get("nativeCode", ""),
                        "deviceAbis": device_meta.get("abi", "") if device_meta else "",
                        "installerError": "INSTALL_FAILED_NO_MATCHING_ABIS (-113)",
                        "evidence": str(
                            (evidence_dir / "install.txt").relative_to(root)
                        ),
                    }
                    any_blocked = True
                    continue
                raise RuntimeError("APK install/update failed")
            installed_path = adb(
                adb_path, args.serial, "shell", "pm", "path", record["package"]
            ).removeprefix("package:")
            installed_hash = adb(
                adb_path, args.serial, "shell", "sha256sum", installed_path
            ).split()[0]
            if installed_hash.lower() != record["sha256"]:
                raise RuntimeError("installed APK SHA-256 differs from source")
            clear_result = adb(
                adb_path,
                args.serial,
                "shell",
                "pm",
                "clear",
                record["package"],
                check=False,
            )
            record["dynamic"]["dataReset"] = {
                "pass": clear_result.strip() == "Success",
                "result": clear_result.strip(),
            }
            if clear_result.strip() != "Success":
                raise RuntimeError(f"pm clear failed: {clear_result.strip()}")
            resolved = adb(
                adb_path,
                args.serial,
                "shell",
                "cmd",
                "package",
                "resolve-activity",
                "--brief",
                "-c",
                "android.intent.category.LAUNCHER",
                record["package"],
            ).splitlines()[-1]
            if "/" not in resolved:
                raise RuntimeError("launcher activity did not resolve")
            record["component"] = resolved
            failed_baselines: list[dict[str, Any]] = []
            baseline: dict[str, Any] = {}
            for baseline_attempt in range(1, 4):
                baseline = launch_probe(
                    adb_path,
                    args.serial,
                    record["package"],
                    resolved,
                    args.quiet_seconds,
                )
                if baseline["pass"] or baseline_attempt == 3:
                    break
                failed_path = evidence_dir / f"baseline-attempt-{baseline_attempt}.json"
                failed_path.write_text(
                    json.dumps(baseline, ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )
                baseline["evidence"] = str(failed_path.relative_to(root))
                failed_baselines.append(baseline)
                time.sleep(1)
            if failed_baselines:
                baseline["retriedAfterFailures"] = len(failed_baselines)
                record["dynamic"]["baselineFailedAttempts"] = failed_baselines
            baseline_path = evidence_dir / "baseline.json"
            baseline_path.write_text(
                json.dumps(baseline, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            baseline["evidence"] = str(baseline_path.relative_to(root))
            record["dynamic"]["baseline"] = baseline

            smoke = run(
                [
                    "powershell",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(root / "tools" / "smoke-stage1-pixel8.ps1"),
                    "-Mode",
                    "GumLuaTarget",
                    "-DeviceSerial",
                    args.serial,
                    "-TargetPackage",
                    record["package"],
                    "-TargetComponent",
                    resolved,
                    "-TargetLabel",
                    label,
                    "-HookQuietSeconds",
                    str(args.quiet_seconds),
                    "-RunLabel",
                    f"group{args.group}-{index + 1}",
                    "-CleanupOnFailure",
                ],
                check=False,
                timeout=900,
            )
            smoke_text = smoke.stdout + smoke.stderr
            smoke_path = evidence_dir / "kernel-gumlua.txt"
            smoke_path.write_text(smoke_text, encoding="utf-8")
            hit = re.search(
                r"gumlua-armed=(\d+)\s+hook-fired=(\d+)\s+pid=(\d+)",
                smoke_text,
            )
            maps_hidden = "maps-hidden=1" in smoke_text
            smaps_hidden = "smaps-hidden=1" in smoke_text
            backends_vmaless = "backends-vmaless=1" in smoke_text
            kernel = {
                "pass": smoke.returncode == 0
                and "stage2-single-app-gumlua PASS" in smoke_text
                and bool(hit)
                and hit.group(1) == "1"
                and hit.group(2) == "1"
                and maps_hidden
                and smaps_hidden
                and backends_vmaless,
                "survived": f"hook-survived=1 quiet-seconds={args.quiet_seconds}" in smoke_text,
                "pid": int(hit.group(3)) if hit else 0,
                "armed": bool(hit) and hit.group(1) == "1",
                "hookFired": bool(hit) and hit.group(2) == "1",
                "mapsHidden": maps_hidden,
                "smapsHidden": smaps_hidden,
                "backendsVmaless": backends_vmaless,
                "evidence": str(smoke_path.relative_to(root)),
            }
            if smoke.returncode != 0:
                kernel["failure"] = f"smoke exit={smoke.returncode}"
                # Never run the visible Frida control phase in a kernel state
                # left behind by a failed smoke. The PowerShell runner first
                # attempts an in-place unlink for diagnostics and speed; this
                # outer reboot is the final isolation boundary even if that
                # cleanup path itself regresses.
                adb(adb_path, args.serial, "reboot", check=False)
                wait_device(adb_path, args.serial)
                kernel["failureCleanup"] = "clean reboot before Frida control"
            record["dynamic"]["kernel"] = kernel

            frida_json = evidence_dir / "frida.json"
            frida_json.unlink(missing_ok=True)
            frida_json.with_suffix(".logcat.txt").unlink(missing_ok=True)
            frida_run = run(
                [
                    str(python),
                    str(root / "tools" / "test-frida-apk-survival.py"),
                    "--serial",
                    args.serial,
                    "--package",
                    record["package"],
                    "--component",
                    resolved,
                    "--duration",
                    str(args.quiet_seconds),
                    "--output",
                    str(frida_json),
                ],
                check=False,
                timeout=240,
            )
            if frida_json.is_file():
                frida_result = json.loads(frida_json.read_text(encoding="utf-8"))
            else:
                frida_result = {
                    "pass": False,
                    "failure": (
                        f"Frida runner exit={frida_run.returncode} produced no JSON"
                    ),
                }
            frida_result["evidence"] = str(frida_json.relative_to(root))
            record["dynamic"]["frida"] = frida_result
            (evidence_dir / "frida-console.txt").write_text(
                frida_run.stdout + frida_run.stderr, encoding="utf-8"
            )

            record["dynamic"]["fridaCleanup"] = cleanup_frida_server(
                adb_path, args.serial
            )
            recovery = launch_probe(
                adb_path,
                args.serial,
                record["package"],
                resolved,
                args.quiet_seconds,
            )
            recovery_path = evidence_dir / "recovery.json"
            recovery_path.write_text(
                json.dumps(recovery, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            recovery["evidence"] = str(recovery_path.relative_to(root))
            record["dynamic"]["recovery"] = recovery
            if (
                not kernel["pass"]
                or not kernel["survived"]
                or not recovery["pass"]
            ):
                any_failure = True
        except Exception as error:
            any_failure = True
            record["dynamic"].setdefault(
                "kernel", {"pass": False, "survived": False, "failure": str(error)}
            )
            record["dynamic"].setdefault(
                "frida", {"pass": False, "failure": "not reached"}
            )
            record["dynamic"].setdefault(
                "recovery", {"pass": False, "failure": "not reached"}
            )
        finally:
            adb(
                adb_path,
                args.serial,
                "shell",
                "am",
                "force-stop",
                record["package"],
                check=False,
            )
            report_status = "PARTIAL" if any_blocked else "COMPLETE"
            render_report(
                report_path,
                args.group,
                records,
                report_status,
                device_meta,
                args.quiet_seconds,
            )
            render_report(
                report_mirror,
                args.group,
                records,
                report_status,
                device_meta,
                args.quiet_seconds,
            )
            (output_dir / "results.json").write_text(
                json.dumps(records, ensure_ascii=False, indent=2), encoding="utf-8"
            )
    cleanup_frida_server(adb_path, args.serial)
    print(f"report={report_path}")
    result = "FAIL" if any_failure else ("PARTIAL" if any_blocked else "PASS")
    print(f"result={result}")
    return 1 if any_failure else 0


if __name__ == "__main__":
    raise SystemExit(main())
