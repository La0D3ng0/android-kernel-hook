"""Attach a visible Frida session to one APK and verify hook/script survival.

This is deliberately separate from the KPM/GhostApi path.  It represents the
ordinary reverse-engineering baseline: launch the installed app normally,
attach frida-server, install low-impact native and Java hooks, and observe the
same PID for a bounded interval.  Results are emitted as JSON for the group
report generator.
"""

from __future__ import annotations

import argparse
import os
import json
import pathlib
import re
import subprocess
import tempfile
import threading
import time
from typing import Any

import frida


def run(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=check,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def adb(adb_path: str, serial: str, *args: str, check: bool = True) -> str:
    return run([adb_path, "-s", serial, *args], check=check).stdout.strip()


def su(adb_path: str, serial: str, command: str, *, check: bool = True) -> str:
    quoted = command.replace("'", "'\"'\"'")
    return adb(adb_path, serial, "shell", f"su -c '{quoted}'", check=check)


def pid_candidates(adb_path: str, serial: str, package: str) -> list[int]:
    output = adb(adb_path, serial, "shell", "pidof", package, check=False)
    return sorted({int(value) for value in output.split() if value.isdigit()})


def process_info(adb_path: str, serial: str, pid: int) -> dict[str, int] | None:
    status = su(adb_path, serial, f"cat /proc/{pid}/status 2>/dev/null", check=False)
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
    start_time = int(tail[19]) if len(tail) > 19 and tail[19].isdigit() else 0
    return {
        "pid": pid,
        "ppid": fields.get("PPid", 0),
        "tracerPid": fields.get("TracerPid", -1),
        "threads": fields.get("Threads", 0),
        "startTime": start_time,
    }


def process_inventory(adb_path: str, serial: str, package: str) -> list[dict[str, int]]:
    return [
        info
        for pid in pid_candidates(adb_path, serial, package)
        if (info := process_info(adb_path, serial, pid)) is not None
    ]


def pidof(adb_path: str, serial: str, package: str) -> int:
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


def tracer_pid(adb_path: str, serial: str, pid: int) -> int:
    output = su(
        adb_path,
        serial,
        f"awk '/^TracerPid:/{{print $2}}' /proc/{pid}/status",
        check=False,
    )
    return int(output) if output.isdigit() else -1


def process_alive(adb_path: str, serial: str, pid: int) -> bool:
    """Check the attached PID directly instead of trusting pidof.

    Some protected applications change the task name after unpacking.  In that
    case Android's pidof briefly or permanently stops matching the package even
    though the same process and Frida session remain alive.
    """

    stat = su(adb_path, serial, f"cat /proc/{pid}/stat 2>/dev/null", check=False)
    close = stat.rfind(")")
    if close < 0 or close + 2 >= len(stat):
        return False
    state = stat[close + 2 : close + 3]
    return state not in {"Z", "X", "x"}


def ensure_server(adb_path: str, serial: str, server: pathlib.Path) -> None:
    running = su(adb_path, serial, "pidof rtgum-frida-server", check=False)
    if running:
        return
    remote = "/data/local/tmp/rtgum-frida-server"
    run([adb_path, "-s", serial, "push", str(server), remote])
    su(adb_path, serial, f"chmod 0755 {remote}")
    adb(
        adb_path,
        serial,
        "shell",
        f"su -c 'nohup {remote} >/data/local/tmp/rtgum-frida-server.log 2>&1 &'",
        check=False,
    )
    deadline = time.monotonic() + 8.0
    while time.monotonic() < deadline:
        if su(adb_path, serial, "pidof rtgum-frida-server", check=False):
            return
        time.sleep(0.25)
    raise RuntimeError("frida-server did not start")


def wait_for_stable_pid(adb_path: str, serial: str, package: str, timeout: float) -> int:
    deadline = time.monotonic() + timeout
    candidate = 0
    stable_since = 0.0
    while time.monotonic() < deadline:
        current = pidof(adb_path, serial, package)
        if current > 0 and current == candidate:
            if time.monotonic() - stable_since >= 2.0:
                return current
        else:
            candidate = current
            stable_since = time.monotonic()
        time.sleep(0.25)
    return 0


def main() -> int:
    root = pathlib.Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser()
    parser.add_argument("--serial", default=os.environ.get("ANDROID_SERIAL", ""))
    parser.add_argument(
        "--adb",
        default=str(root / ".toolchains" / "platform-tools-37.0.1" /
                    "platform-tools" / "adb.exe"),
    )
    parser.add_argument("--package", required=True)
    parser.add_argument("--component", required=True)
    parser.add_argument("--duration", type=int, default=15)
    parser.add_argument(
        "--script", default=str(root / "tests" / "apk-frida-survival.js")
    )
    parser.add_argument(
        "--frida-server",
        default=str(root / "out" / "device" / "pixel8" /
                    "frida-server-17.22.0-android-arm64"),
    )
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if not args.serial:
        parser.error('--serial is required (or set ANDROID_SERIAL)')
    if not 5 <= args.duration <= 120:
        raise SystemExit("duration must be between 5 and 120 seconds")

    output_path = pathlib.Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="rtgum-apk-frida-") as directory:
        bundle = pathlib.Path(directory) / "apk-frida-survival-bundle.js"
        # Compile through the Frida Python binding so the compiler and runtime
        # always come from the same installation.  Older frida-tools releases
        # import a top-level `_frida` module and fail with Frida 17, whose
        # extension lives at `frida._frida`; that host-side mismatch must not
        # be reported as an application killing the injected script.
        script_source = frida.Compiler().build(
            str(pathlib.Path(args.script).resolve()),
            project_root=str(root),
            bundle_format="iife",
            type_check="none",
            source_maps="omitted",
            compression="none",
            platform="gum",
        )
        bundle.write_text(script_source, encoding="utf-8")
    result: dict[str, Any] = {
        "package": args.package,
        "component": args.component,
        "durationSeconds": args.duration,
        "pass": False,
        "messages": [],
        "errors": [],
        "detached": None,
    }
    session = None
    script = None
    detached = threading.Event()
    phase = "prepare"
    try:
        phase = "server-start"
        ensure_server(args.adb, args.serial, pathlib.Path(args.frida_server))
        adb(args.adb, args.serial, "logcat", "-c", check=False)
        phase = "launch"
        adb(args.adb, args.serial, "shell", "am", "force-stop", args.package)
        adb(
            args.adb,
            args.serial,
            "shell",
            "am",
            "start",
            "-f",
            "0x10008000",
            "-n",
            args.component,
        )
        phase = "wait-stable-pid"
        pid = wait_for_stable_pid(args.adb, args.serial, args.package, 30.0)
        if pid <= 0:
            raise RuntimeError("app process did not reach a stable PID")
        result["pid"] = pid
        result["pidCandidatesBefore"] = pid_candidates(
            args.adb, args.serial, args.package
        )
        result["tracerPidBefore"] = tracer_pid(args.adb, args.serial, pid)

        phase = "attach"
        device = frida.get_usb_device(timeout=10)
        session = device.attach(pid)
        cleanup_started = threading.Event()

        def on_detached(reason: str, crash: Any) -> None:
            value = {"reason": reason, "crash": str(crash) if crash else None}
            if cleanup_started.is_set():
                result["cleanupDetached"] = value
            else:
                result["detached"] = value
                detached.set()

        session.on("detached", on_detached)
        phase = "script-create"
        script = session.create_script(script_source)

        def on_message(message: dict[str, Any], data: Any) -> None:
            if message.get("type") == "send":
                result["messages"].append(message.get("payload"))
            elif message.get("type") == "error":
                result["errors"].append(message)

        script.on("message", on_message)
        phase = "script-load"
        script.load()
        time.sleep(1.0)
        result["tracerPidDuring"] = tracer_pid(args.adb, args.serial, pid)

        phase = "observe"
        snapshots: list[dict[str, Any]] = []
        observed_at = time.monotonic()
        deadline = observed_at + args.duration
        while time.monotonic() < deadline:
            if detached.is_set():
                break
            current = pidof(args.adb, args.serial, args.package)
            alive = process_alive(args.adb, args.serial, pid)
            if not alive:
                result["pidofAtFailure"] = current
                result["processGoneAtSeconds"] = round(
                    time.monotonic() - observed_at, 3
                )
                break
            snapshot = script.exports_sync.snapshot()
            snapshot["pidof"] = current
            snapshot["pidCandidates"] = pid_candidates(
                args.adb, args.serial, args.package
            )
            snapshot["processAlive"] = alive
            snapshots.append(snapshot)
            time.sleep(1.0)
        result["snapshots"] = snapshots
        result["pidofAfter"] = pidof(args.adb, args.serial, args.package)
        result["pidCandidatesAfter"] = pid_candidates(
            args.adb, args.serial, args.package
        )
        result["processAliveAfter"] = process_alive(args.adb, args.serial, pid)
        result["pidAfter"] = pid if result["processAliveAfter"] else 0
        if script is not None and not detached.is_set():
            result["final"] = script.exports_sync.dispose()
        final = result.get("final") or (snapshots[-1] if snapshots else {})
        kinds = {
            item.get("kind") for item in result["messages"] if isinstance(item, dict)
        }
        result["pass"] = bool(
            not detached.is_set()
            and not result["errors"]
            and result["processAliveAfter"]
            and "native-ready" in kinds
            and "java-ready" in kinds
            and int(final.get("nativeHits", 0)) >= args.duration
            and int(final.get("heartbeats", 0)) >= args.duration - 1
            and int(final.get("javaHits", 0)) >= 1
            and final.get("packageName") == args.package
        )
        if not result["pass"]:
            raise RuntimeError("Frida hook/script survival criteria were not met")
        phase = "complete"
    except Exception as error:  # Preserve all evidence for the report.
        result["failure"] = f"{type(error).__name__}: {error}"
        result["failurePhase"] = phase
    finally:
        if "cleanup_started" in locals():
            cleanup_started.set()
        if script is not None:
            try:
                script.unload()
            except frida.InvalidOperationError:
                pass
        if session is not None:
            try:
                session.detach()
            except frida.InvalidOperationError:
                pass
        result["crashLog"] = adb(
            args.adb,
            args.serial,
            "logcat",
            "-b",
            "crash",
            "-d",
            "-v",
            "threadtime",
            check=False,
        )
        result["exitInfo"] = adb(
            args.adb,
            args.serial,
            "shell",
            "dumpsys",
            "activity",
            "exit-info",
            args.package,
            check=False,
        )
        target_pid = int(result.get("pid", 0) or 0)
        if target_pid > 0:
            exit_match = re.search(
                rf"pid={target_pid}\b.*?reason=(\d+)\s+\([^\n]*\).*?status=(\d+)",
                result["exitInfo"],
                re.DOTALL,
            )
            if exit_match:
                result["exitReason"] = int(exit_match.group(1))
                result["exitStatus"] = int(exit_match.group(2))
                if result["exitReason"] == 2 and result["exitStatus"] == 9:
                    result["exitSignal"] = 9
                    result["probableAntiFridaKill"] = phase in {
                        "attach",
                        "script-create",
                        "script-load",
                        "observe",
                    }
        logcat_path = output_path.with_suffix(".logcat.txt")
        logcat_path.write_text(
            adb(
                args.adb,
                args.serial,
                "logcat",
                "-b",
                "all",
                "-d",
                "-v",
                "threadtime",
                check=False,
            ),
            encoding="utf-8",
        )
        result["logcatEvidence"] = str(logcat_path)
        adb(args.adb, args.serial, "shell", "am", "force-stop", args.package, check=False)
        output_path.write_text(
            json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    print(json.dumps({key: result.get(key) for key in (
        "package", "pid", "pass", "tracerPidBefore", "tracerPidDuring",
        "pidAfter", "detached", "failure")}, ensure_ascii=False))
    return 0 if result["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
