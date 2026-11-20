// TraceDroid - offline DFIR / SOC triage for Android.
// Copyright (C) CyberCraft Studio. GNU GPL v3.0 or later.
package com.ccs.tracedroid.ui.yara;

import android.app.Application;
import android.content.ContentResolver;
import android.database.Cursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.provider.DocumentsContract;

import androidx.annotation.NonNull;
import androidx.lifecycle.AndroidViewModel;
import androidx.lifecycle.LiveData;
import androidx.lifecycle.MutableLiveData;

import com.ccs.tracedroid.R;
import com.ccs.tracedroid.data.CaseRepository;
import com.ccs.tracedroid.data.ForensicCase;
import com.ccs.tracedroid.jni.NativeForensicEngine;
import com.ccs.tracedroid.ui.cases.CaseViewModel;
import com.ccs.tracedroid.util.Formats;
import com.ccs.tracedroid.util.HexDump;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CancellationException;

/** Keeps YARA scan results across configuration changes and runs scans on the case worker thread. */
public final class YaraViewModel extends AndroidViewModel {
    private static final int SCAN_TIMEOUT_SECONDS = 180;
    private static final int MAX_TREE_FILES = 20000;

    /** One result row: a rule match on an artifact, or a status line for a clean / failed artifact. */
    static final class Item {
        static final int MATCH = 0;
        static final int CLEAN = 1;
        static final int ERROR = 2;

        final int kind;
        final String artifact;
        final String title;
        final String tags;
        final String detail;
        /** Monospace hex preview of the matched strings (empty unless {@link #MATCH}). */
        final String hex;

        Item(int kind, String artifact, String title, String tags, String detail, String hex) {
            this.kind = kind;
            this.artifact = artifact;
            this.title = title;
            this.tags = tags;
            this.detail = detail;
            this.hex = hex;
        }
    }

    private static final class Target {
        final Uri uri;
        final String name;

        Target(Uri uri, String name) {
            this.uri = uri;
            this.name = name;
        }
    }

    private final MutableLiveData<List<Item>> results = new MutableLiveData<>(new ArrayList<>());
    private final MutableLiveData<String> summary = new MutableLiveData<>("");

    public YaraViewModel(@NonNull Application application) {
        super(application);
    }

    LiveData<List<Item>> results() {
        return results;
    }

    LiveData<String> summary() {
        return summary;
    }

    void scanDocuments(CaseViewModel caseModel, List<Uri> uris) {
        caseModel.runExclusive(R.string.op_yara_scan, () -> {
            ContentResolver resolver = getApplication().getContentResolver();
            List<Target> targets = new ArrayList<>();
            for (Uri uri : uris) {
                targets.add(new Target(uri, CaseRepository.displayName(resolver, uri)));
            }
            scan(caseModel, targets);
        });
    }

    void scanTree(CaseViewModel caseModel, Uri tree) {
        caseModel.runExclusive(R.string.op_yara_scan, () -> {
            List<Target> targets = new ArrayList<>();
            collect(tree, DocumentsContract.getTreeDocumentId(tree), "", targets, 0);
            scan(caseModel, targets);
        });
    }

    private void collect(Uri tree, String documentId, String prefix, List<Target> out, int depth) {
        if (depth > 24 || out.size() >= MAX_TREE_FILES) {
            return;
        }
        List<String[]> entries = new ArrayList<>();
        Uri children = DocumentsContract.buildChildDocumentsUriUsingTree(tree, documentId);
        try (Cursor cursor = getApplication().getContentResolver().query(children, new String[]{
                DocumentsContract.Document.COLUMN_DOCUMENT_ID, DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                DocumentsContract.Document.COLUMN_MIME_TYPE}, null, null, null)) {
            while (cursor != null && cursor.moveToNext()) {
                entries.add(new String[]{cursor.getString(0), cursor.getString(1), cursor.getString(2)});
            }
        } catch (RuntimeException ignored) {
            return;  // unreadable directory: skip it, keep scanning the rest
        }
        for (String[] entry : entries) {
            String name = prefix + (entry[1] == null ? "unnamed" : entry[1]);
            if (DocumentsContract.Document.MIME_TYPE_DIR.equals(entry[2])) {
                collect(tree, entry[0], name + "/", out, depth + 1);
            } else if (out.size() < MAX_TREE_FILES) {
                out.add(new Target(DocumentsContract.buildDocumentUriUsingTree(tree, entry[0]), name));
            }
        }
    }

    /** Runs on the case worker thread. */
    private void scan(CaseViewModel caseModel, List<Target> targets) {
        final NativeForensicEngine engine = caseModel.engine();
        final ForensicCase forensicCase = caseModel.forensicCase();
        if (engine == null || forensicCase == null) {
            return;
        }
        final String label = getApplication().getString(R.string.op_yara_scan);
        final ContentResolver resolver = getApplication().getContentResolver();
        final List<Item> items = new ArrayList<>();
        int matchedArtifacts = 0;
        long bytes = 0;
        int scanned = 0;
        boolean cancelled = false;

        for (Target target : targets) {
            caseModel.setProgress(label + "  " + target.name, scanned, targets.size());
            try (ParcelFileDescriptor pfd = resolver.openFileDescriptor(target.uri, "r")) {
                if (pfd == null) {
                    throw new IOException("provider returned no descriptor");
                }
                // Hand a detached descriptor to native code: libyara maps the artifact directly,
                // nothing is copied onto the Java heap. Native code closes the descriptor.
                JSONObject result = new JSONObject(engine.yaraScanFd(pfd.detachFd(), target.name, SCAN_TIMEOUT_SECONDS));
                bytes += result.optLong("bytesScanned");
                int matches = appendResult(items, target.name, result);
                if (matches > 0) {
                    matchedArtifacts++;
                    caseModel.repository().log(forensicCase, "YARA_MATCH", String.format(Locale.ROOT,
                            "artifact=\"%s\" rules=%d", target.name, matches));
                }
            } catch (CancellationException e) {
                cancelled = true;
            } catch (IOException | JSONException | RuntimeException e) {
                items.add(new Item(Item.ERROR, target.name, getApplication().getString(R.string.yara_scan_error),
                        "", String.valueOf(e.getMessage()), ""));
            }
            scanned++;
            if (cancelled || Thread.currentThread().isInterrupted()) {
                break;
            }
        }
        results.postValue(items);
        summary.postValue(getApplication().getString(R.string.yara_summary, scanned, Formats.bytes(bytes),
                matchedArtifacts));
    }

    private int appendResult(List<Item> items, String artifact, JSONObject result) {
        String error = result.optString("error");
        if (!error.isEmpty()) {
            items.add(new Item(Item.ERROR, artifact, getApplication().getString(R.string.yara_scan_error), "", error, ""));
            return 0;
        }
        JSONArray matches = result.optJSONArray("matches");
        int count = matches == null ? 0 : matches.length();
        if (count == 0) {
            String note = result.optBoolean("timedOut") ? getApplication().getString(R.string.yara_timeout)
                    : Formats.bytes(result.optLong("bytesScanned"));
            items.add(new Item(Item.CLEAN, artifact, getApplication().getString(R.string.yara_no_match), "", note, ""));
            return 0;
        }
        for (int i = 0; i < count; i++) {
            JSONObject match = matches.optJSONObject(i);
            if (match == null) {
                continue;
            }
            StringBuilder tags = new StringBuilder();
            JSONArray tagArray = match.optJSONArray("tags");
            for (int t = 0; tagArray != null && t < tagArray.length(); t++) {
                tags.append(t == 0 ? "" : "  ").append(tagArray.optString(t));
            }
            StringBuilder detail = new StringBuilder();
            String namespace = match.optString("namespace");
            if (!namespace.isEmpty() && !"default".equals(namespace)) {
                detail.append(namespace).append('\n');
            }
            JSONArray meta = match.optJSONArray("meta");
            for (int m = 0; meta != null && m < meta.length(); m++) {
                JSONObject entry = meta.optJSONObject(m);
                if (entry != null) {
                    detail.append(entry.optString("name")).append(" = ").append(entry.optString("value")).append('\n');
                }
            }
            StringBuilder hex = new StringBuilder();
            JSONArray strings = match.optJSONArray("strings");
            int shown = strings == null ? 0 : Math.min(strings.length(), 12);
            for (int s = 0; s < shown; s++) {
                JSONObject string = strings.optJSONObject(s);
                if (string == null) {
                    continue;
                }
                long offset = string.optLong("offset");
                hex.append(String.format(Locale.ROOT, "%s @ 0x%x (%d bytes)\n", string.optString("id"), offset,
                        string.optInt("length")));
                hex.append(HexDump.format(HexDump.parse(string.optString("context")), string.optLong("contextOffset")));
                hex.append(s + 1 < shown ? "\n\n" : "");
            }
            int total = match.optInt("totalStrings");
            if (total > shown) {
                hex.append("\n\n").append(getApplication().getString(R.string.yara_more_strings, total - shown));
            }
            items.add(new Item(Item.MATCH, artifact, match.optString("rule"), tags.toString(),
                    detail.toString().trim(), hex.toString()));
        }
        return count;
    }
}
