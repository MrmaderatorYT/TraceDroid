// TraceDroid - offline DFIR / SOC triage for Android.
// Copyright (C) CyberCraft Studio. GNU GPL v3.0 or later.
package com.ccs.tracedroid.jni;

/** Raised by the native engine for malformed evidence, bad rules, I/O failures and similar errors. */
public final class NativeEngineException extends RuntimeException {
    public NativeEngineException(String message) {
        super(message);
    }
}
