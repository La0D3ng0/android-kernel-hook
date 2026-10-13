"""Visible Frida oracle for active hooks in the user's debuggable test APK.

This does not exercise the KPM/GhostApi injection path. Run it with the
matching Frida 17.22.0 Python environment while a temporary frida-server is
available on the Pixel 8.
"""

import argparse
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

import frida


PACKAGE = "com.laodeng.jnicode"
REMOTE_XML = "/sdcard/rtgum-active-hook-test.xml"


def adb(serial, *args, capture=False):
    result = subprocess.run(
        ["adb", "-s", serial, *args],
        check=True,
        capture_output=capture,
        text=True,
    )
    return result.stdout if capture else ""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--serial", default=os.environ.get("ANDROID_SERIAL", ""))
    parser.add_argument(
        "--script",
        default=str(pathlib.Path(__file__).resolve().parents[1]
                    / "tests" / "jnicode-active-hook.js"),
    )
    args = parser.parse_args()
    if not args.serial:
        parser.error('--serial is required (or set ANDROID_SERIAL)')

    compiler = pathlib.Path(sys.prefix) / "Scripts" / "frida-compile.exe"
    if not compiler.is_file():
        raise RuntimeError(f"Missing frida-compile in active environment: {compiler}")
    with tempfile.TemporaryDirectory(prefix="rtgum-jnicode-") as build_dir:
        bundle = pathlib.Path(build_dir) / "active-hook.js"
        subprocess.run(
            [str(compiler), args.script, "-o", str(bundle), "-S"],
            check=True,
        )
        script_source = bundle.read_text(encoding="utf-8")

    adb(args.serial, "shell", "am", "force-stop", PACKAGE)
    device = frida.get_usb_device(timeout=10)
    pid = device.spawn([PACKAGE])
    session = None
    script = None
    resumed = False
    observations = {}
    errors = []
    try:
        session = device.attach(pid)
        script = session.create_script(script_source)

        def on_message(message, data):
            if message.get("type") == "send":
                payload = message.get("payload")
                if isinstance(payload, dict) and "kind" in payload:
                    observations[payload["kind"]] = payload
            elif message.get("type") == "error":
                errors.append(message.get("description", str(message)))

        script.on("message", on_message)
        script.load()
        device.resume(pid)
        resumed = True

        deadline = time.monotonic() + 20
        while time.monotonic() < deadline and not errors:
            if "native" in observations and "onCreate" in observations:
                break
            time.sleep(0.1)
        if errors:
            raise RuntimeError("Frida script error: " + " | ".join(errors))
        native = observations.get("native")
        activity = observations.get("onCreate")
        if not native or not activity:
            raise RuntimeError(f"Expected both hooks, observed: {observations}")
        if native.get("original") != "Hello from C++" or native.get("replacement") != "Hooked from JNI":
            raise RuntimeError(f"Native result mismatch: {native}")
        if activity.get("before") != "Hooked from JNI" or activity.get("after") != "Hooked by onCreate":
            raise RuntimeError(f"onCreate result mismatch: {activity}")

        adb(args.serial, "shell", "uiautomator", "dump", REMOTE_XML)
        xml_text = adb(args.serial, "shell", "cat", REMOTE_XML, capture=True)
        texts = {node.attrib.get("text") for node in ET.fromstring(xml_text).iter("node")}
        if "Hooked by onCreate" not in texts:
            raise RuntimeError("Hooked onCreate text is absent from the UI hierarchy")

        print("native original=Hello from C++ replacement=Hooked from JNI")
        print("onCreate before=Hooked from JNI after=Hooked by onCreate")
        print("ui=Hooked by onCreate active-hooks PASS")
    finally:
        try:
            adb(args.serial, "shell", "rm", "-f", REMOTE_XML)
        except subprocess.CalledProcessError:
            pass
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
        if not resumed:
            try:
                device.kill(pid)
            except frida.ProcessNotFoundError:
                pass
        try:
            adb(args.serial, "shell", "am", "force-stop", PACKAGE)
        except subprocess.CalledProcessError:
            pass


if __name__ == "__main__":
    main()
