package dev.rtgum.lab;

/** Native registration target for the early-SO lifecycle acceptance path.
 * libghostlab registers this method from JNI_OnLoad rather than exporting a
 * Java_* name, so RegisterNatives tracing observes the real function pointer. */
public final class LifecycleProbe {
    private LifecycleProbe() {}

    public static native int nativeValue();
}
