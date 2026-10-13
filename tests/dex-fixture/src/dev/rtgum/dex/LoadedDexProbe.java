package dev.rtgum.dex;

import java.lang.reflect.Method;

/** Small acceptance payload for the Daemon-owned in-memory DEX loader. */
public final class LoadedDexProbe {
    private LoadedDexProbe() {
    }

    public static int answer(int left, int right) {
        return left + right + 39;
    }

    /**
     * Resolves an app-owned class through this class' defining loader. An
     * app-parent loader returns 3; a bootstrap-isolated loader returns -1.
     */
    public static int appVisible() {
        try {
            Class<?> target = Class.forName("dev.rtgum.lab.LabTarget");
            Method method = target.getDeclaredMethod(
                    "untouched", int.class, int.class);
            Object value = method.invoke(null, 1, 2);
            return ((Integer) value).intValue();
        } catch (Throwable ignored) {
            return -1;
        }
    }
}
