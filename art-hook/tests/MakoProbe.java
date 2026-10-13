import com.rtgum.mako.PreForkHost;

public final class MakoProbe {
    private MakoProbe() {}

    public static long sample(int number, String[] names, double ratio) {
        return number + names.length + (long) ratio;
    }

    private static native String runNative(boolean inherited);

    public static void main(String[] args) {
        boolean inherited = args.length == 0;
        if (inherited) {
            PreForkHost.load("/data/local/tmp/libmako-cache.so");
            if (PreForkHost.ready()) {
                throw new AssertionError("cache prepared during library load");
            }
            if (PreForkHost.loadAndPrepare("/data/local/tmp/libmako-cache.so") != 0 ||
                !PreForkHost.ready()) {
                throw new AssertionError("pre-fork JNI host entry failed");
            }
        }
        System.load("/data/local/tmp/libmako-live-test.so");
        String result = runNative(inherited);
        System.out.println(result);
        String expected = inherited ? "mako inherited cache: PASS" :
                                      "mako fallback: PASS";
        if (!expected.equals(result)) {
            throw new AssertionError(result);
        }
    }
}
