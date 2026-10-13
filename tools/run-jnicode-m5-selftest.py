"""Visible-path loadDex / Binder / GTrace self-tests in the owned JNICode APK.

Frida is only the memfd loader for librtgum-jnicode-java-hook.so.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import subprocess
import sys
import threading
import time

import frida

PACKAGE = "com.laodeng.jnicode"


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


SOURCE = r"""
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
    if (fd === -1) throw new Error('memfd_create failed');
    const bytes = Memory.alloc(data.byteLength);
    bytes.writeByteArray(data);
    let offset = 0;
    while (offset !== data.byteLength) {
      const count = write(fd, bytes.add(offset), data.byteLength - offset);
      const written = count.toNumber();
      if (written <= 0) {
        close(fd);
        throw new Error('write(memfd) failed');
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
    const output = Memory.alloc(1024);
    function run(symbol, takesEnv) {
      output.writeUtf8String('');
      const fn = new NativeFunction(
          mustSymbol(symbol), 'int',
          takesEnv ? ['pointer', 'pointer', 'ulong'] : ['pointer', 'ulong']);
      const code = takesEnv ? fn(ptr(0), output, 1024) : fn(output, 1024);
      return { code: code, message: output.readUtf8String() };
    }
    close(fd);
    const gtrace = run('rtgum_jnicode_gtrace_selftest', false);
    const loaddex = run('rtgum_jnicode_loaddex_selftest', true);
    const binder = run('rtgum_jnicode_binder_selftest', true);
    send({
      kind: 'selftest',
      gtraceCode: gtrace.code,
      gtraceMessage: gtrace.message,
      loaddexCode: loaddex.code,
      loaddexMessage: loaddex.message,
      binderCode: binder.code,
      binderMessage: binder.message
    });
  } catch (error) {
    send({ kind: 'error', message: error.toString() });
  }
});
"""


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
    parser.add_argument("--timeout", type=float, default=40.0)
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

    def on_message(message, _data):
        payload = message.get("payload") if message.get("type") == "send" else None
        if payload is None:
            outcome["error"] = message.get("description", str(message))
            completed.set()
            return
        outcome.update(payload)
        completed.set()

    script = session.create_script(SOURCE)
    script.on("message", on_message)
    script.load()
    device.resume(pid)
    time.sleep(1.5)
    completed.clear()
    outcome.clear()
    script.post({"type": "library"}, data)
    if not completed.wait(args.timeout):
        device.kill(pid)
        raise SystemExit("M5 selftest timed out")
    if outcome.get("kind") != "selftest":
        device.kill(pid)
        raise SystemExit(f"M5 selftest failed: {outcome}")
    print(f"gtrace code={outcome.get('gtraceCode')} {outcome.get('gtraceMessage')}")
    print(f"loaddex code={outcome.get('loaddexCode')} {outcome.get('loaddexMessage')}")
    print(f"binder code={outcome.get('binderCode')} {outcome.get('binderMessage')}")
    failed = []
    if outcome.get("gtraceCode") != 0:
        failed.append("gtrace")
    if outcome.get("loaddexCode") != 0:
        failed.append("loaddex")
    if outcome.get("binderCode") != 0:
        failed.append("binder")
    adb(args.adb, args.serial, "shell", "am", "force-stop", PACKAGE)
    session.detach()
    if failed:
        raise SystemExit("M5 selftest failed: " + ",".join(failed))
    print("jnicode-m5-selftest PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
