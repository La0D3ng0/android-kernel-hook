package dev.rtgum.manager;

import android.app.Activity;
import android.app.Instrumentation;
import android.os.Bundle;

import java.io.File;

/** Device smoke test for the ordinary Android loader and Manager's private storage. */
public final class LoaderInstrumentation extends Instrumentation {
    @Override
    public void onCreate(Bundle arguments) {
        super.onCreate(arguments);
        start();
    }

    @Override
    public void onStart() {
        Bundle result = new Bundle();
        File modules = new File(getTargetContext().getFilesDir(), "modules");
        File[] files = modules.listFiles((directory, name) -> name.endsWith(".ghm"));
        if (files == null || files.length == 0) {
            result.putString("stream", "No Manager module has been imported for the loader test.");
            finish(Activity.RESULT_CANCELED, result);
            return;
        }
        try {
            System.load(files[0].getAbsolutePath());
            result.putString("stream", "Loaded " + files[0].getAbsolutePath());
            finish(Activity.RESULT_OK, result);
        } catch (UnsatisfiedLinkError error) {
            result.putString("stream", "Loader rejected module: " + error.getMessage());
            finish(Activity.RESULT_CANCELED, result);
        }
    }
}
