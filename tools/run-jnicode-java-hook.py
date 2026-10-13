"""Load the JNICode Java-hook SO into the owned APK and verify onCreate.

Frida is only the memfd loader. The rewrite is implemented by
librtgum-jnicode-java-hook.so (LSPlant + HostApiV2 native inline hook).
"""

from __future__ import annotations

import argparse
import os
import pathlib
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET

import frida

PACKAGE = "com.laodeng.jnicode"
ACTIVITY = "com.laodeng.jnicode.MainActivity"
REMOTE_XML = "/data/local/tmp/rtgum-jnicode-java-ui.xml"
REPLACEMENT = "Hooked by onCreate"
ORIGINAL = "Hello from C++"


def adb(adb_path: str, serial: str, *args: str, capture: bool = False) -> str:
    result = subprocess.run(
        [adb_path, "-s", serial, *args],
        check=True,
        capture_output=capture,
        text=True,
    )
    return result.stdout if capture else ""


def su(adb_path: str, serial: str, command: str, capture: bool = False) -> str:
    quoted = command.replace("'", "'\"'\"'")
    return adb(adb_path, serial, "shell", f"su -c '{quoted}'", capture=capture)


def ensure_frida_server(adb_path: str, serial: str, server: pathlib.Path) -> None:
    try:
        running = su(adb_path, serial, "pidof rtgum-frida-server", capture=True).strip()
    except subprocess.CalledProcessError:
        running = ""
    if running:
        return
    remote = "/data/local/tmp/rtgum-frida-server"
    subprocess.run(
        [adb_path, "-s", serial, "push", str(server), remote],
        check=True,
        capture_output=True,
        text=True,
    )
    su(adb_path, serial, f"chmod 755 {remote}")
    subprocess.run(
        [adb_path, "-s", serial, "shell",
         f"su -c 'nohup {remote} >/dev/null 2>&1 &'"],
        check=False,
        capture_output=True,
        text=True,
    )
    time.sleep(1.5)


def dump_texts(adb_path: str, serial: str) -> set[str]:
    adb(adb_path, serial, "shell", "uiautomator", "dump", REMOTE_XML)
    xml_text = adb(adb_path, serial, "shell", "cat", REMOTE_XML, capture=True)
    return {node.attrib.get("text") for node in ET.fromstring(xml_text).iter("node")}


def start_main_activity(adb_path: str, serial: str) -> None:
    # Android 16 `am start` dropped `--activity-new-task`. NEW_TASK|CLEAR_TASK
    # is 0x10008000 and is required so onCreate runs again after the hook.
    adb(
        adb_path, serial, "shell", "am", "start",
        "-f", "0x10008000",
        "-n", f"{PACKAGE}/{ACTIVITY}",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--serial", default=os.environ.get("ANDROID_SERIAL", ""))
    parser.add_argument(
        "--adb",
        default=str(pathlib.Path(__file__).resolve().parents[1]
                    / ".toolchains" / "platform-tools-37.0.1"
                    / "platform-tools" / "adb.exe"),
    )
    parser.add_argument(
        "--library",
        default=str(pathlib.Path(__file__).resolve().parents[1]
                    / "art-hook" / "out" / "android-arm64-cxx23"
                    / "librtgum-jnicode-java-hook.so"),
    )
    parser.add_argument(
        "--frida-server",
        default=str(pathlib.Path(__file__).resolve().parents[1]
                    / "out" / "device" / "pixel8"
                    / "frida-server-17.8.2-android-arm64"),
    )
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()
    if not args.serial:
        parser.error('--serial is required (or set ANDROID_SERIAL)')

    library = pathlib.Path(args.library)
    if not library.is_file():
        raise SystemExit(f"missing Java-hook library: {library}")
    data = library.read_bytes()

    ensure_frida_server(args.adb, args.serial, pathlib.Path(args.frida_server))
    adb(args.adb, args.serial, "shell", "am", "force-stop", PACKAGE)
    time.sleep(0.4)

    device = frida.get_usb_device(timeout=10)
    pid = device.spawn([PACKAGE])
    session = device.attach(pid)
    completed = threading.Event()
    outcome: dict[str, object] = {}

    source = r"""
let installFn = null;
let output = null;

recv('library', function (message, data) {
  try {
    const libc = Process.getModuleByName('libc.so');
    const libdl = Process.getModuleByName('libdl.so');
    const memfdCreate = new NativeFunction(
        libc.getExportByName('memfd_create'), 'int', ['pointer', 'uint']);
    const write = new NativeFunction(
        libc.getExportByName('write'), 'long', ['int', 'pointer', 'ulong']);
    const close = new NativeFunction(
        libc.getExportByName('close'), 'int', ['int']);
    const androidDlopenExt = new NativeFunction(
        libdl.getExportByName('android_dlopen_ext'),
        'pointer', ['pointer', 'int', 'pointer']);
    const dlsym = new NativeFunction(
        libdl.getExportByName('dlsym'), 'pointer', ['pointer', 'pointer']);
    const dlerror = new NativeFunction(
        libdl.getExportByName('dlerror'), 'pointer', []);

    const name = Memory.allocUtf8String('librtgum-jnicode-java-hook.so');
    const fd = memfdCreate(name, 0);
    if (fd === -1) {
      throw new Error('memfd_create failed');
    }
    const bytes = Memory.alloc(data.byteLength);
    bytes.writeByteArray(data);
    let offset = 0;
    while (offset !== data.byteLength) {
      const count = write(fd, bytes.add(offset), data.byteLength - offset);
      const written = count.toNumber();
      if (written <= 0) {
        close(fd);
        throw new Error('write(memfd) failed at offset ' + offset);
      }
      offset += written;
    }

    const extinfo = Memory.alloc(48);
    extinfo.writeByteArray(new Uint8Array(48).buffer);
    extinfo.writeU64(0x10);
    extinfo.add(28).writeS32(fd);
    const handle = androidDlopenExt(name, 2, extinfo);
    if (handle.isNull()) {
      const error = dlerror();
      close(fd);
      throw new Error(error.isNull() ? 'android_dlopen_ext failed'
                                     : error.readUtf8String());
    }
    function mustSymbol(symbolName) {
      const pointer = dlsym(handle, Memory.allocUtf8String(symbolName));
      if (pointer.isNull()) {
        close(fd);
        throw new Error('dlsym(' + symbolName + ') failed');
      }
      return pointer;
    }
    const probe = new NativeFunction(
        mustSymbol('rtgum_jnicode_java_probe'),
        'int', ['pointer', 'pointer', 'ulong']);
    installFn = new NativeFunction(
        mustSymbol('rtgum_jnicode_java_hook_install'),
        'int', ['pointer', 'pointer', 'ulong']);
    output = Memory.alloc(1024);
    output.writeUtf8String('');
    const probeCode = probe(ptr(0), output, 1024);
    close(fd);
    send({
      kind: 'probe',
      probeCode: probeCode,
      probeMessage: output.readUtf8String()
    });
  } catch (error) {
    send({ kind: 'error', message: error.toString() });
  }
});

function onInstall() {
  try {
    output.writeUtf8String('');
    const installCode = installFn(ptr(0), output, 1024);
    send({
      kind: 'install',
      installCode: installCode,
      installMessage: output.readUtf8String()
    });
  } catch (error) {
    send({ kind: 'error', message: error.toString() });
  }
  recv('install', onInstall);
}
recv('install', onInstall);
"""
    script = session.create_script(source)

    def wait_message(kind: str) -> dict[str, object]:
        completed.clear()
        outcome.clear()
        if not completed.wait(args.timeout):
            device.kill(pid)
            raise SystemExit(f"Java-hook {kind} timed out")
        if outcome.get("kind") == "error" or "error" in outcome:
            device.kill(pid)
            raise SystemExit(f"Java-hook {kind} failed: {outcome}")
        return dict(outcome)

    def on_message(message, _data):
        payload = message.get("payload") if message.get("type") == "send" else None
        if payload is None:
            outcome["error"] = message.get("description", str(message))
            completed.set()
            return
        outcome.update(payload)
        completed.set()

    script.on("message", on_message)
    script.load()
    script.post({"type": "library"}, data)
    probe = wait_message("probe")
    print(f"probe code={probe.get('probeCode')} {probe.get('probeMessage')}")
    if probe.get("probeCode") != 0:
        device.kill(pid)
        raise SystemExit("Java-hook probe failed")

    device.resume(pid)
    time.sleep(1.8)
    script.post({"type": "install"})
    installed = wait_message("install")
    print(f"install code={installed.get('installCode')} {installed.get('installMessage')}")
    if installed.get("installCode") != 0:
        time.sleep(1.5)
        script.post({"type": "install"})
        installed = wait_message("install")
        print(f"install-retry code={installed.get('installCode')} {installed.get('installMessage')}")
        if installed.get("installCode") != 0:
            device.kill(pid)
            raise SystemExit("Java onCreate hook install failed")

    start_main_activity(args.adb, args.serial)
    time.sleep(2.5)
    adb(args.adb, args.serial, "shell", "wm", "dismiss-keyguard")
    texts = dump_texts(args.adb, args.serial)
    if REPLACEMENT not in texts:
        adb(args.adb, args.serial, "shell", "am", "force-stop", PACKAGE)
        raise SystemExit(f"UI missing {REPLACEMENT!r}; texts={texts}")
    print(f"ui={REPLACEMENT}")

    adb(args.adb, args.serial, "shell", "am", "force-stop", PACKAGE)
    time.sleep(0.5)
    start_main_activity(args.adb, args.serial)
    time.sleep(2.0)
    restored = dump_texts(args.adb, args.serial)
    adb(args.adb, args.serial, "shell", "am", "force-stop", PACKAGE)
    try:
        session.detach()
    except frida.InvalidOperationError:
        pass
    if ORIGINAL not in restored:
        raise SystemExit(f"restore missing {ORIGINAL!r}; texts={restored}")
    print(f"restored={ORIGINAL}")
    print("jnicode-java-hook PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
