// TraceDroid - offline DFIR / SOC triage for Android.
// Copyright (C) CyberCraft Studio. GNU GPL v3.0 or later.
package com.ccs.tracedroid.util;

import android.content.Context;

import androidx.annotation.ColorInt;
import androidx.core.content.ContextCompat;

import com.ccs.tracedroid.R;

/** Sigma severity levels as used across the UI (0 = no alert, 1..5 = informational..critical). */
public final class Severity {
    public static final int NONE = 0;
    public static final int CRITICAL = 5;

    private static final int[] COLORS = {
            R.color.sev_none, R.color.sev_info, R.color.sev_low, R.color.sev_medium, R.color.sev_high,
            R.color.sev_critical};
    private static final int[] NAMES = {
            R.string.sev_none, R.string.sev_info, R.string.sev_low, R.string.sev_medium, R.string.sev_high,
            R.string.sev_critical};

    private Severity() {
    }

    private static int clamp(int severity) {
        return Math.max(0, Math.min(CRITICAL, severity));
    }

    @ColorInt
    public static int color(Context context, int severity) {
        return ContextCompat.getColor(context, COLORS[clamp(severity)]);
    }

    public static String name(Context context, int severity) {
        return context.getString(NAMES[clamp(severity)]);
    }

    /** All severity colours indexed by level, resolved once for hot drawing paths. */
    public static int[] palette(Context context) {
        int[] palette = new int[COLORS.length];
        for (int i = 0; i < palette.length; i++) {
            palette[i] = ContextCompat.getColor(context, COLORS[i]);
        }
        return palette;
    }
}
