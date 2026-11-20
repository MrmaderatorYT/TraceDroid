// TraceDroid - offline DFIR / SOC triage for Android.
// Copyright (C) CyberCraft Studio. GNU GPL v3.0 or later.
package com.ccs.tracedroid;

import android.app.Application;
import android.content.Context;
import android.os.Handler;
import android.os.Looper;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Application singleton: shared background executor and main-thread handler. No network, no telemetry. */
public final class TraceDroidApp extends Application {
    private final ExecutorService io = Executors.newFixedThreadPool(3);
    private final Handler main = new Handler(Looper.getMainLooper());

    public static TraceDroidApp from(Context context) {
        return (TraceDroidApp) context.getApplicationContext();
    }

    /** Pool for short, read-mostly work (timeline pages, detail lookups, file listing). */
    public ExecutorService io() {
        return io;
    }

    public void postMain(Runnable action) {
        main.post(action);
    }
}
