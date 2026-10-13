package com.rtgum.mako;

/** JNI entry invoked by a JavaVM parent after loading libmako-cache.so. */
public final class PreForkHost {
    private PreForkHost() {}

    private static String loadedPath;

    /** Loads the cache library from this class's loader namespace. */
    public static synchronized void load(String absolutePath) {
        if (loadedPath == null) {
            System.load(absolutePath);
            loadedPath = absolutePath;
        } else if (!loadedPath.equals(absolutePath)) {
            throw new IllegalStateException("Mako cache library path changed");
        }
    }

    /** Loads and prepares the cache at a Java-host-controlled pre-fork point. */
    public static synchronized int loadAndPrepare(String absolutePath) {
        load(absolutePath);
        return prepare();
    }

    /** Returns MAKO_OK (zero) only after the reflection seed is complete. */
    public static native int prepare();

    /** Reports whether this process has a complete seed. */
    public static native boolean ready();
}
