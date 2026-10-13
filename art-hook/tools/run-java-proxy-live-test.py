#!/usr/bin/env python3
"""Run the JNI Java proxy live test through an existing Frida session."""

from __future__ import annotations

import argparse
import pathlib
import sys
import threading

import frida
import frida_tools


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("library", type=pathlib.Path)
    parser.add_argument("--process", default="com.android.settings")
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()

    data = args.library.read_bytes()
    device = frida.get_usb_device(timeout=10)
    target: str | int = args.process
    for application in device.enumerate_applications():
        if application.identifier == args.process and application.pid != 0:
            target = application.pid
            break
    session = device.attach(target)
    completed = threading.Event()
    outcome: dict[str, object] = {}

    bridge_path = pathlib.Path(frida_tools.__file__).parent / "bridges" / "java.js"
    source = bridge_path.read_text(encoding="utf-8") + r"""
Object.defineProperty(globalThis, 'Java', { value: bridge });
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

    const name = Memory.allocUtf8String('libart-hook-java-proxy-live-test.so');
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

    // android_dlextinfo on arm64: flags, reserved addr/size, two fds,
    // library_fd_offset, namespace. ANDROID_DLEXT_USE_LIBRARY_FD is 0x10.
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
    const symbol = dlsym(
        handle, Memory.allocUtf8String('art_hook_java_proxy_live_test'));
    if (symbol.isNull()) {
      close(fd);
      throw new Error('dlsym(art_hook_java_proxy_live_test) failed');
    }

    Java.performNow(function () {
      const run = new NativeFunction(
          symbol, 'int', ['pointer', 'pointer', 'ulong']);
      const output = Memory.alloc(512);
      output.writeUtf8String('');
      const code = run(Java.vm.getEnv().handle, output, 512);
      close(fd);
      send({ kind: 'result', code, message: output.readUtf8String(),
             path: 'memfd' });
    });
  } catch (error) {
    send({ kind: 'error', message: error.stack || String(error) });
  }
});
"""

    def on_message(message: dict[str, object], payload: bytes | None) -> None:
        del payload
        if message.get("type") == "send":
            outcome.update(message.get("payload", {}))
        else:
            outcome.update(kind="error", message=str(message))
        completed.set()

    script = session.create_script(source)
    script.on("message", on_message)
    script.load()
    script.post({"type": "library"}, data=data)
    if not completed.wait(args.timeout):
        print("JAVA_PROXY_LIVE_TEST_TIMEOUT", file=sys.stderr)
        return 2

    kind = outcome.get("kind")
    code = int(outcome.get("code", -1))
    message = str(outcome.get("message", ""))
    print(f"JAVA_PROXY_LIVE_TEST kind={kind} code={code} message={message}")
    return 0 if kind == "result" and code == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
