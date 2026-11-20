// TraceDroid - offline DFIR / SOC triage for Android.
// Copyright (C) CyberCraft Studio. GNU GPL v3.0 or later.
package com.ccs.tracedroid.jni;

/**
 * Receives progress from long-running native operations. Called synchronously on the thread that
 * invoked the native method (a background executor thread, never the UI thread). Throwing from
 * the callback aborts the native operation and propagates the exception to the caller.
 */
public interface NativeProgressListener {
    void onProgress(int stage, long current, long total);
}
