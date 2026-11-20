// TraceDroid - offline DFIR / SOC triage for Android.
// Copyright (C) CyberCraft Studio. GNU GPL v3.0 or later.
package com.ccs.tracedroid.model;

import androidx.annotation.NonNull;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/** One timeline row, decoded from the native page buffer (see ForensicSession::fetchPage). */
public final class EventRow {
    public final int eventIndex;
    public final long recordId;
    public final long timeMs;
    public final int eventId;
    public final int severity;
    public final int level;
    public final int alertCount;
    public final String channel;
    public final String computer;
    public final String title;
    public final String summary;

    private EventRow(ByteBuffer in) {
        eventIndex = in.getInt();
        recordId = in.getLong();
        timeMs = in.getLong();
        eventId = in.getInt();
        severity = in.get() & 0xFF;
        level = in.get() & 0xFF;
        alertCount = in.getShort() & 0xFFFF;
        channel = readString(in);
        computer = readString(in);
        title = readString(in);
        summary = readString(in);
    }

    static String readString(ByteBuffer in) {
        int length = in.getShort() & 0xFFFF;
        if (length == 0) {
            return "";
        }
        byte[] bytes = new byte[length];
        in.get(bytes);
        return new String(bytes, StandardCharsets.UTF_8);
    }

    /** Decodes a page: u32 row count followed by the rows. The buffer must be little-endian. */
    @NonNull
    public static List<EventRow> decodePage(@NonNull ByteBuffer in) {
        int count = in.getInt();
        List<EventRow> rows = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            rows.add(new EventRow(in));
        }
        return rows;
    }
}
