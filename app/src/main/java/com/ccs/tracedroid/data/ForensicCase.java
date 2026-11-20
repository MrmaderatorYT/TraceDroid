// TraceDroid - offline DFIR / SOC triage for Android.
// Copyright (C) CyberCraft Studio. GNU GPL v3.0 or later.
package com.ccs.tracedroid.data;

import androidx.annotation.NonNull;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;

/** Metadata of one forensic case. Evidence lives in sub-directories of {@link #directory}. */
public final class ForensicCase {
    public final String id;
    public final String name;
    public final String examiner;
    public final String notes;
    public final long createdAtMs;
    public final File directory;

    public ForensicCase(String id, String name, String examiner, String notes, long createdAtMs, File directory) {
        this.id = id;
        this.name = name;
        this.examiner = examiner;
        this.notes = notes;
        this.createdAtMs = createdAtMs;
        this.directory = directory;
    }

    @NonNull
    JSONObject toJson() throws JSONException {
        return new JSONObject()
                .put("id", id)
                .put("name", name)
                .put("examiner", examiner)
                .put("notes", notes)
                .put("createdAtMs", createdAtMs);
    }

    @NonNull
    static ForensicCase fromJson(JSONObject json, File directory) throws JSONException {
        return new ForensicCase(json.getString("id"), json.optString("name", "Untitled case"),
                json.optString("examiner", ""), json.optString("notes", ""), json.optLong("createdAtMs", 0),
                directory);
    }
}
