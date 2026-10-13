package dev.rtgum.lab;

import android.app.Activity;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.lang.reflect.Method;
import java.util.Locale;

/**
 * The ART hook acceptance UI.
 *
 * <p>Everything on screen is produced by calling the fixture and scanning it, so
 * the two halves of the acceptance criterion are visible side by side:
 *
 * <ul>
 *   <li>{@code LabTarget.add(1, 2)} must display 42 once the framework hooks it,
 *       and 3 when it does not;
 *   <li>the same-page control {@code LabTarget.untouched(1, 2)} must keep
 *       displaying 3 in both cases;
 *   <li>the ArtMethod self-check must report that the untrusted reader still sees
 *       the pre-hook entry bytes.
 * </ul>
 *
 * <p>The self-check needs a baseline: the scanner's own reading of both entry
 * fields taken <em>before</em> any hook exists. That baseline is captured on the
 * first refresh, which is why the activity runs one scan at startup and the
 * later refreshes compare against it. A check without a baseline can only ever
 * say INCONCLUSIVE, and it says so rather than guessing.
 *
 * <p>The manifest also exposes one test-only GC receiver. It lets the device
 * harness deterministically exercise ART's LinearAlloc remap while this
 * activity and its hook are live; it contains no framework functionality.
 */
public final class MainActivity extends Activity {

    /** Logcat tag the test harness polls for the current state. */
    private static final String TAG = "rtgum-lab";

    private TextView addResult;
    private TextView addDetail;
    private TextView untouchedResult;
    private TextView untouchedDetail;
    private TextView scanResult;
    private TextView scanDetail;
    private TextView scanContract;
    private TextView memoryResult;
    private TextView memoryDetail;
    private TextView hwbpResult;
    private TextView hwbpDetail;

    private Method addMethod;
    private Method untouchedMethod;
    private ArtMethodScanner.Baseline addBaseline;
    private ArtMethodScanner.Baseline untouchedBaseline;
    /** True when the fixture was already returning 42 at baseline time. */
    private boolean baselineTakenWhileHooked;
    private boolean hookObserved;
    private int automaticChecks;
    private long[] hwbpSnapshot;
    private long hwbpLastAttemptMs;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(buildUi());
        ArtMethodScanner.setBaselineReady(false);
        final boolean baselineReady = captureBaseline();
        ArtMethodScanner.setBaselineReady(baselineReady);
        // libghostlab's JNI_OnLoad registers this method dynamically. Besides
        // making the fixture visible in logcat, this proves that tracing
        // RegisterNatives did not alter the table submitted to ART.
        try {
            Log.i(TAG, "lifecycle-native=0x"
                    + Integer.toHexString(LifecycleProbe.nativeValue()));
        } catch (Throwable error) {
            Log.e(TAG, "lifecycle native registration failed", error);
        }
        // The in-process module waits on the native baseline gate. Emit the
        // log only after publishing it with release semantics so a harness that
        // observes this line cannot race ahead of the two baseline reads.
        Log.i(TAG, "baseline-ready=" + baselineReady + " pid="
                + android.os.Process.myPid());
        Log.i(TAG, "ui-ready pid=" + android.os.Process.myPid());
        refresh();
        schedulePostInstallCheck();
    }

    /** Keep the fixture automatable even while the test phone is locked. The
     * pre-hook baseline is already published before this starts; subsequent
     * checks only wait for the asynchronously installed hook and stop at the
     * first behavioural hit. */
    private void schedulePostInstallCheck() {
        final Handler handler = new Handler(Looper.getMainLooper());
        handler.postDelayed(new Runnable() {
            @Override
            public void run() {
                refresh();
                automaticChecks++;
                if (!hookObserved && automaticChecks < 40) {
                    handler.postDelayed(this, 250L);
                }
            }
        }, 250L);
    }

    private View buildUi() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (16 * getResources().getDisplayMetrics().density);
        root.setPadding(pad, pad, pad, pad);

        root.addView(heading("ART Hook Lab"));
        root.addView(note("LabTarget.add(1,2) is the hook target. "
                + "LabTarget.untouched(1,2) is the same-page control: it must "
                + "never change."));

        addResult = value("add(1,2) = ?");
        root.addView(addResult);
        addDetail = note("");
        root.addView(addDetail);

        untouchedResult = value("untouched(1,2) = ?");
        root.addView(untouchedResult);
        untouchedDetail = note("");
        root.addView(untouchedDetail);

        root.addView(spacer());
        root.addView(heading("ArtMethod self-check"));
        scanResult = value("scan = ?");
        root.addView(scanResult);
        scanDetail = note("");
        root.addView(scanDetail);
        scanContract = note("");
        scanContract.setTypeface(Typeface.MONOSPACE);
        root.addView(scanContract);

        root.addView(spacer());
        root.addView(heading("Kernel memory I/O self-check"));
        memoryResult = value("TracerPid = ?");
        root.addView(memoryResult);
        memoryDetail = note("");
        memoryDetail.setTypeface(Typeface.MONOSPACE);
        root.addView(memoryDetail);

        root.addView(spacer());
        root.addView(heading("HWBP anti-debug self-check"));
        hwbpResult = value("HWBP = ?");
        root.addView(hwbpResult);
        hwbpDetail = note("");
        hwbpDetail.setTypeface(Typeface.MONOSPACE);
        root.addView(hwbpDetail);

        root.addView(spacer());
        Button call = new Button(this);
        call.setText("调用 LabTarget.add(1,2)");
        // Anonymous classes rather than lambdas: the build compiles against the
        // platform android.jar as the bootclasspath, which has no
        // java.lang.invoke.LambdaMetafactory, so a lambda would not link.
        call.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                refresh();
            }
        });
        root.addView(call);

        Button rescan = new Button(this);
        rescan.setText("重新自检");
        rescan.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                refresh();
            }
        });
        root.addView(rescan);

        Button rebaseline = new Button(this);
        rebaseline.setText("重取基线（未 hook 时用）");
        rebaseline.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                captureBaseline();
                refresh();
            }
        });
        root.addView(rebaseline);

        ScrollView scroll = new ScrollView(this);
        scroll.addView(root);
        return scroll;
    }

    private TextView heading(String text) {
        TextView view = new TextView(this);
        view.setText(text);
        view.setTextSize(20f);
        view.setTypeface(Typeface.DEFAULT_BOLD);
        return view;
    }

    private TextView value(String text) {
        TextView view = new TextView(this);
        view.setText(text);
        view.setTextSize(28f);
        view.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        return view;
    }

    private TextView note(String text) {
        TextView view = new TextView(this);
        view.setText(text);
        view.setTextSize(12f);
        view.setTextColor(Color.DKGRAY);
        view.setGravity(Gravity.START);
        return view;
    }

    private View spacer() {
        View view = new View(this);
        view.setMinimumHeight((int) (12 * getResources().getDisplayMetrics().density));
        return view;
    }

    private void resolveMethods() {
        if (addMethod != null) return;
        try {
            addMethod = LabTarget.class.getDeclaredMethod("add", int.class, int.class);
            untouchedMethod =
                    LabTarget.class.getDeclaredMethod("untouched", int.class, int.class);
        } catch (Throwable t) {
            Log.e(TAG, "fixture lookup failed", t);
        }
    }

    /**
     * Records what an untrusted reader sees for both entry fields, before any
     * hook is installed. Every later verdict compares against this.
     *
     * <p>Taking a baseline at startup is only valid when the hook is not live
     * yet. The framework installs its hook from a deferred poller inside this
     * process, so the two can race: the fixture value is checked here and the
     * result is reported in the log and in the contract, so a baseline captured
     * against an already-hooked method is visible as such instead of being
     * silently used as a "before" reading.
     */
    private boolean captureBaseline() {
        resolveMethods();
        if (addMethod == null) return false;
        try {
            baselineTakenWhileHooked = LabTarget.add(1, 2) == 42;
            addBaseline = ArtMethodScanner.baselineOf(addMethod, "add");
            untouchedBaseline = ArtMethodScanner.baselineOf(untouchedMethod, "untouched");
            Log.i(TAG, String.format(Locale.US,
                    "baseline hooked-at-capture=%s add=%s(0x%x) untouched=%s(0x%x) "
                            + "same-page-baseline=%s",
                    baselineTakenWhileHooked,
                    addBaseline.readable ? "readable" : "unreadable",
                    addBaseline.value,
                    untouchedBaseline.readable ? "readable" : "unreadable",
                    untouchedBaseline.value,
                    addBaseline.readable && untouchedBaseline.readable
                            && (addBaseline.value != 0L) && (untouchedBaseline.value != 0L)));
            return !baselineTakenWhileHooked && addBaseline.readable
                    && untouchedBaseline.readable && addBaseline.looksLegitimate
                    && untouchedBaseline.looksLegitimate;
        } catch (Throwable t) {
            Log.e(TAG, "baseline capture failed", t);
            return false;
        }
    }

    /** Runs the fixture and the scan, and pushes the outcome to the UI + log. */
    private void refresh() {
        int addValue = LabTarget.add(1, 2);
        int untouchedValue = LabTarget.untouched(1, 2);
        // The hook being live is a behavioural fact, and it has to be taken from
        // the fixture rather than inferred from memory: an untouched entry field
        // looks identical whether the framework hid a rewrite or never rewrote
        // anything. 42 is the value the framework writes.
        boolean hookActive = addValue == 42;
        hookObserved = hookActive;

        addResult.setText(String.format(Locale.US, "add(1,2) = %d", addValue));
        addDetail.setText(hookActive ? "hook 生效（42）" : "hook 未生效（3）");
        untouchedResult.setText(String.format(Locale.US, "untouched(1,2) = %d", untouchedValue));
        untouchedDetail.setText("同页对照：任何情况下都应为 3");

        runSelfCheck(hookActive);
        runMemorySelfCheck();
        runHwbpSelfCheck();

        Log.i(TAG, String.format(Locale.US, "state add=%d untouched=%d scan=%s",
                addValue, untouchedValue, scanResult.getText()));
    }

    private void runMemorySelfCheck() {
        try {
            long[] snapshot = MemoryProbe.nativeSnapshot();
            int tracer = MemoryProbe.tracerPid();
            boolean ready = snapshot != null && snapshot.length == 3
                    && snapshot[0] != 0L && snapshot[1] != 0L
                    && snapshot[2] == MemoryProbe.MAGIC;
            boolean pass = ready && tracer == 0;
            memoryResult.setText(tracer >= 0
                    ? "TracerPid = " + tracer + (pass ? "  PASS" : "  FAIL")
                    : "TracerPid = unreadable");
            memoryResult.setTextColor(pass ? Color.rgb(0, 128, 0) : Color.RED);
            if (ready) {
                memoryDetail.setText(String.format(Locale.US,
                        "magic=0x%x @ 0x%x\nlab_add @ 0x%x",
                        snapshot[2], snapshot[0], snapshot[1]));
                Log.i(TAG, String.format(Locale.US,
                        "memory-selfcheck pid=%d magic=0x%x magic-va=0x%x "
                                + "code-va=0x%x tracer=%d pass=%s",
                        android.os.Process.myPid(), snapshot[2], snapshot[0],
                        snapshot[1], tracer, pass));
            } else {
                memoryDetail.setText("native fixture unavailable");
                Log.e(TAG, "memory-selfcheck fixture unavailable tracer=" + tracer);
            }
        } catch (Throwable error) {
            memoryResult.setText("TracerPid = ERROR");
            memoryResult.setTextColor(Color.RED);
            memoryDetail.setText(String.valueOf(error));
            Log.e(TAG, "memory-selfcheck failed", error);
        }
    }

    /**
     * Runs the real ptrace/perf syscall probe in a short-lived child. The
     * activity itself is never attached, so this can be green at the same time
     * as the TracerPid lamp above. A failed result is retried at most once every
     * two seconds so opening the Lab before the Manager enables the kernel
     * feature can recover without repeatedly forking at the UI refresh rate.
     */
    private void runHwbpSelfCheck() {
        try {
            final long now = android.os.SystemClock.elapsedRealtime();
            final boolean cachedPass = hwbpSnapshot != null
                    && hwbpSnapshot.length == 8 && hwbpSnapshot[0] == 0xffffL;
            if (!cachedPass && now - hwbpLastAttemptMs >= 2000L) {
                hwbpLastAttemptMs = now;
                hwbpSnapshot = MemoryProbe.nativeHwbpSelfCheck();
            }
            if (hwbpSnapshot == null || hwbpSnapshot.length != 8) {
                hwbpResult.setText("HWBP = INCONCLUSIVE");
                hwbpResult.setTextColor(Color.rgb(196, 128, 0));
                hwbpDetail.setText("native probe unavailable");
                return;
            }
            final long mask = hwbpSnapshot[0];
            final int tracer = MemoryProbe.tracerPid();
            final boolean pass = mask == 0xffffL && tracer == 0;
            hwbpResult.setText(pass ? "HWBP = PASS" : "HWBP = FAIL");
            hwbpResult.setTextColor(pass ? Color.rgb(0, 128, 0) : Color.RED);
            hwbpDetail.setText(String.format(Locale.US,
                    "mask=0x%x BRP=%d WRP=%d active-signal=%d\n"
                            + "overflow: ptrace=%d/%d perf=%d/%d\n"
                            + "empty/fill/rw/trigger/FD-lifecycle/cleanup",
                    mask, hwbpSnapshot[1], hwbpSnapshot[5], hwbpSnapshot[4],
                    hwbpSnapshot[2], hwbpSnapshot[6], hwbpSnapshot[3],
                    hwbpSnapshot[7]));
            Log.i(TAG, String.format(Locale.US,
                    "hwbp-selfcheck mask=0x%x brp=%d wrp=%d "
                            + "ptrace-brp=%d perf-brp=%d ptrace-wrp=%d perf-wrp=%d "
                            + "active-signal=%d tracer=%d pass=%s perf-ioctl=%s "
                            + "perf-read=%s fd-lifecycle=%s",
                    mask, hwbpSnapshot[1], hwbpSnapshot[5],
                    hwbpSnapshot[2], hwbpSnapshot[3], hwbpSnapshot[6],
                    hwbpSnapshot[7], hwbpSnapshot[4], tracer, pass,
                    (mask & (1L << 4)) != 0L,
                    (mask & (1L << 4)) != 0L,
                    (mask & (1L << 14)) != 0L));
        } catch (Throwable error) {
            hwbpResult.setText("HWBP = ERROR");
            hwbpResult.setTextColor(Color.RED);
            hwbpDetail.setText(String.valueOf(error));
            Log.e(TAG, "hwbp-selfcheck failed", error);
        }
    }

    private void runSelfCheck(boolean hookActive) {
        try {
            resolveMethods();
            if (addMethod == null) {
                scanResult.setText("scan = 无法取得夹具方法");
                scanResult.setTextColor(Color.RED);
                return;
            }
            if (addBaseline == null) captureBaseline();

            ArtMethodScanner.Session session = ArtMethodScanner.run(
                    addMethod, untouchedMethod, addBaseline, untouchedBaseline,
                    hookActive, baselineTakenWhileHooked);

            String contract = ArtMethodScanner.contract(session);
            scanContract.setText(contract);

            switch (session.result) {
                case PASS:
                    scanResult.setText("scan = PASS");
                    scanResult.setTextColor(Color.rgb(0, 128, 0));
                    break;
                case FAIL:
                    scanResult.setText("scan = FAIL");
                    scanResult.setTextColor(Color.RED);
                    break;
                default:
                    scanResult.setText("scan = INCONCLUSIVE");
                    scanResult.setTextColor(Color.rgb(196, 128, 0));
                    break;
            }

            StringBuilder detail = new StringBuilder();
            detail.append(ArtMethodScanner.describe(session.add));
            if (session.untouched != null) {
                detail.append('\n').append(ArtMethodScanner.describe(session.untouched));
            }
            detail.append("\nsame-page=").append(session.samePage);
            scanDetail.setText(detail.toString());

            // One line per contract field group, so the harness can grep either
            // the log or the UI and see the same thing.
            Log.i(TAG, "selfcheck " + contract.replace('\n', ' '));
        } catch (Throwable t) {
            scanResult.setText("scan = 异常");
            scanResult.setTextColor(Color.RED);
            scanDetail.setText(String.valueOf(t));
            Log.e(TAG, "selfcheck failed", t);
        }
    }
}
