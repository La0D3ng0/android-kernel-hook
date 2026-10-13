package dev.rtgum.lab;

import java.io.BufferedReader;
import java.io.FileReader;

/** Fixture addresses and the tracer self-check for kernel memory I/O tests. */
public final class MemoryProbe {
    public static final long MAGIC = 0x4c414201L;

    static {
        System.loadLibrary("ghostlab");
    }

    private MemoryProbe() {}

    /** {magicAddress, codeAddress, magicValue}. */
    public static native long[] nativeSnapshot();

    /** Calls the exported native fixture on the receiver/main thread. */
    public static native int nativeTraceLabAdd(int left, int right);

    /** Executes the BR-over-junk GTrace fixture on the receiver/main thread. */
    public static native int nativeTraceFlower(int left, int right);

    /** {mask, slots, ptraceSeventhErrno, perfSeventhErrno, activeSignal}. */
    public static native long[] nativeHwbpSelfCheck();

    public static int tracerPid() {
        try (BufferedReader reader = new BufferedReader(
                new FileReader("/proc/self/status"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (!line.startsWith("TracerPid:")) continue;
                return Integer.parseInt(line.substring("TracerPid:".length()).trim());
            }
        } catch (Throwable ignored) {
            return -1;
        }
        return -1;
    }
}
