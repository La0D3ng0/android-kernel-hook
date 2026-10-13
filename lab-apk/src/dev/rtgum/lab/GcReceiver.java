package dev.rtgum.lab;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

/** Test-only trigger for deterministic ART full-GC/shadow-page acceptance. */
public final class GcReceiver extends BroadcastReceiver {
    private static final String TAG = "rtgum-lab";

    @Override
    public void onReceive(Context context, Intent intent) {
        final PendingResult pending = goAsync();
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    Log.i(TAG, "gc-cycle-start");
                    // Several explicit rounds cover a concurrent collection
                    // that may already be in flight when the broadcast arrives.
                    for (int round = 0; round < 3; ++round) {
                        System.gc();
                        System.runFinalization();
                        try {
                            Thread.sleep(250L);
                        } catch (InterruptedException ignored) {
                            Thread.currentThread().interrupt();
                            break;
                        }
                    }
                    Log.i(TAG, "gc-cycle-done");
                } finally {
                    pending.finish();
                }
            }
        }, "rtgum-lab-gc").start();
    }
}
