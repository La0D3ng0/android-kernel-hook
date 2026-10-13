package dev.rtgum.lab;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

/** Main-thread rendezvous for the bounded kernel CPU trace acceptance test. */
public final class TraceReceiver extends BroadcastReceiver {
    private static final String TAG = "rtgum-lab";

    @Override
    public void onReceive(Context context, Intent intent) {
        final boolean flower = intent != null
                && "dev.rtgum.lab.RUN_GTRACE".equals(intent.getAction());
        final int value = flower
                ? MemoryProbe.nativeTraceFlower(1, 2)
                : MemoryProbe.nativeTraceLabAdd(1, 2);
        final int tracer = MemoryProbe.tracerPid();
        Log.i(TAG, (flower ? "gtrace-result" : "kernel-trace-result")
                + " value=" + value
                + " pid=" + android.os.Process.myPid()
                + " tid=" + android.os.Process.myTid()
                + " tracer=" + tracer);
    }
}
