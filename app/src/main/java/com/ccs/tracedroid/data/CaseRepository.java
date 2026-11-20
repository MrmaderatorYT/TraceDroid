// TraceDroid - offline DFIR / SOC triage for Android.
// Copyright (C) CyberCraft Studio. GNU GPL v3.0 or later.
package com.ccs.tracedroid.data;

import android.content.ContentResolver;
import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.provider.DocumentsContract;
import android.provider.OpenableColumns;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.ccs.tracedroid.util.Formats;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

/**
 * Case storage in app-private internal storage:
 *
 * <pre>
 * files/cases/&lt;uuid&gt;/case.json      metadata
 *                      custody.log    append-only chain-of-custody log (UTC, SHA-256 of every import)
 *                      index.tdx      native event index snapshot
 *                      evtx/ sigma/ yara/   working copies of imported evidence and rule packs
 * </pre>
 *
 * Evidence is copied (never moved or modified) and hashed during the copy, so the originals on
 * shared storage stay untouched.
 */
public final class CaseRepository {
    public static final String KIND_EVTX = "evtx";
    public static final String KIND_SIGMA = "sigma";
    public static final String KIND_YARA = "yara";

    private static final String META_FILE = "case.json";
    private static final String CUSTODY_FILE = "custody.log";
    private static final String INDEX_FILE = "index.tdx";

    private final Context context;
    private final File root;

    public CaseRepository(Context context) {
        this.context = context.getApplicationContext();
        this.root = new File(this.context.getFilesDir(), "cases");
    }

    /** Result of one import: the working copy and its digest. */
    public static final class Imported {
        public final File file;
        public final String sha256;
        public final long size;

        Imported(File file, String sha256, long size) {
            this.file = file;
            this.sha256 = sha256;
            this.size = size;
        }
    }

    @NonNull
    public List<ForensicCase> list() {
        List<ForensicCase> cases = new ArrayList<>();
        File[] dirs = root.listFiles(File::isDirectory);
        if (dirs != null) {
            for (File dir : dirs) {
                ForensicCase c = read(dir);
                if (c != null) {
                    cases.add(c);
                }
            }
        }
        cases.sort(Comparator.comparingLong((ForensicCase c) -> c.createdAtMs).reversed());
        return cases;
    }

    @Nullable
    public ForensicCase find(String id) {
        if (id == null || !id.matches("[0-9a-fA-F-]{36}")) {
            return null;
        }
        return read(new File(root, id));
    }

    @Nullable
    private ForensicCase read(File dir) {
        File meta = new File(dir, META_FILE);
        if (!meta.isFile()) {
            return null;
        }
        try {
            String json = new String(Files.readAllBytes(meta.toPath()), StandardCharsets.UTF_8);
            return ForensicCase.fromJson(new JSONObject(json), dir);
        } catch (IOException | JSONException e) {
            return null;
        }
    }

    @NonNull
    public ForensicCase create(String name, String examiner, String notes) throws IOException {
        String id = UUID.randomUUID().toString();
        File dir = new File(root, id);
        for (String kind : new String[]{KIND_EVTX, KIND_SIGMA, KIND_YARA}) {
            File sub = new File(dir, kind);
            if (!sub.mkdirs() && !sub.isDirectory()) {
                throw new IOException("cannot create case directory");
            }
        }
        ForensicCase c = new ForensicCase(id, name, examiner, notes, System.currentTimeMillis(), dir);
        try {
            Files.write(new File(dir, META_FILE).toPath(), c.toJson().toString(2).getBytes(StandardCharsets.UTF_8));
        } catch (JSONException e) {
            throw new IOException(e);
        }
        log(c, "CASE_CREATED", "name=\"" + name + "\" examiner=\"" + examiner + "\"");
        return c;
    }

    public void delete(ForensicCase c) {
        deleteRecursively(c.directory);
    }

    private static void deleteRecursively(File file) {
        File[] children = file.listFiles();
        if (children != null) {
            for (File child : children) {
                deleteRecursively(child);
            }
        }
        //noinspection ResultOfMethodCallIgnored
        file.delete();
    }

    @NonNull
    public File directory(ForensicCase c, String kind) {
        File dir = new File(c.directory, kind);
        //noinspection ResultOfMethodCallIgnored
        dir.mkdirs();
        return dir;
    }

    @NonNull
    public File indexFile(ForensicCase c) {
        return new File(c.directory, INDEX_FILE);
    }

    /** Regular files below the given evidence directory (recursive), sorted by path. */
    @NonNull
    public List<File> files(ForensicCase c, String kind) {
        List<File> out = new ArrayList<>();
        collect(directory(c, kind), out);
        Collections.sort(out);
        return out;
    }

    private static void collect(File dir, List<File> out) {
        File[] children = dir.listFiles();
        if (children == null) {
            return;
        }
        for (File child : children) {
            if (child.isDirectory()) {
                collect(child, out);
            } else {
                out.add(child);
            }
        }
    }

    /** Removes all files of one kind (used by "clear rules"). */
    public void clear(ForensicCase c, String kind) {
        File dir = directory(c, kind);
        File[] children = dir.listFiles();
        if (children != null) {
            for (File child : children) {
                deleteRecursively(child);
            }
        }
        log(c, "CLEARED", "kind=" + kind);
    }

    // ---- import through the Storage Access Framework ----

    @NonNull
    public static String displayName(ContentResolver resolver, Uri uri) {
        try (Cursor cursor = resolver.query(uri, new String[]{OpenableColumns.DISPLAY_NAME}, null, null, null)) {
            if (cursor != null && cursor.moveToFirst() && !cursor.isNull(0)) {
                return cursor.getString(0);
            }
        } catch (RuntimeException ignored) {
            // Providers may reject the projection; fall back to the URI.
        }
        String last = uri.getLastPathSegment();
        return last == null ? "artifact" : last;
    }

    private static String safeName(String name) {
        String cleaned = name.replaceAll("[\\\\/:*?\"<>|\\p{Cntrl}]", "_").trim();
        if (cleaned.isEmpty() || cleaned.equals(".") || cleaned.equals("..")) {
            cleaned = "artifact";
        }
        return cleaned.length() > 120 ? cleaned.substring(cleaned.length() - 120) : cleaned;
    }

    private static File uniqueTarget(File dir, String name) {
        File target = new File(dir, name);
        if (!target.exists()) {
            return target;
        }
        int dot = name.lastIndexOf('.');
        String stem = dot > 0 ? name.substring(0, dot) : name;
        String ext = dot > 0 ? name.substring(dot) : "";
        for (int i = 1; ; i++) {
            target = new File(dir, stem + "-" + i + ext);
            if (!target.exists()) {
                return target;
            }
        }
    }

    /** Copies one SAF document into the case, hashing it on the way, and records it in the custody log. */
    @NonNull
    public Imported importDocument(ForensicCase c, String kind, Uri uri) throws IOException {
        ContentResolver resolver = context.getContentResolver();
        return copyInto(c, kind, directory(c, kind), uri, displayName(resolver, uri));
    }

    private Imported copyInto(ForensicCase c, String kind, File dir, Uri uri, String name) throws IOException {
        //noinspection ResultOfMethodCallIgnored
        dir.mkdirs();
        File target = uniqueTarget(dir, safeName(name));
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IOException(e);
        }
        long total = 0;
        try (InputStream in = context.getContentResolver().openInputStream(uri);
             OutputStream out = new FileOutputStream(target)) {
            if (in == null) {
                throw new IOException("provider returned no data for " + name);
            }
            byte[] buffer = new byte[1 << 20];
            int n;
            while ((n = in.read(buffer)) > 0) {
                out.write(buffer, 0, n);
                digest.update(buffer, 0, n);
                total += n;
            }
        } catch (IOException | RuntimeException e) {
            //noinspection ResultOfMethodCallIgnored
            target.delete();
            throw e instanceof IOException ? (IOException) e : new IOException(e);
        }
        String sha256 = Formats.hex(digest.digest());
        log(c, "IMPORTED", String.format(Locale.ROOT, "kind=%s file=\"%s\" size=%d sha256=%s source=\"%s\"",
                kind, target.getName(), total, sha256, name));
        return new Imported(target, sha256, total);
    }

    /**
     * Recursively copies every document below a SAF tree whose name ends with one of
     * {@code extensions} (lower-case, with dot). Directory structure is preserved.
     *
     * @return number of files imported
     */
    public int importTree(ForensicCase c, String kind, Uri treeUri, String... extensions) throws IOException {
        String rootId = DocumentsContract.getTreeDocumentId(treeUri);
        String rootName = safeName(displayName(context.getContentResolver(),
                DocumentsContract.buildDocumentUriUsingTree(treeUri, rootId)));
        return importChildren(c, kind, treeUri, rootId, new File(directory(c, kind), rootName),
                Arrays.asList(extensions), 0);
    }

    private int importChildren(ForensicCase c, String kind, Uri treeUri, String documentId, File targetDir,
                               List<String> extensions, int depth) throws IOException {
        if (depth > 24) {
            return 0;
        }
        Uri children = DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, documentId);
        List<String[]> entries = new ArrayList<>();
        try (Cursor cursor = context.getContentResolver().query(children, new String[]{
                DocumentsContract.Document.COLUMN_DOCUMENT_ID, DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                DocumentsContract.Document.COLUMN_MIME_TYPE}, null, null, null)) {
            while (cursor != null && cursor.moveToNext()) {
                entries.add(new String[]{cursor.getString(0), cursor.getString(1), cursor.getString(2)});
            }
        }
        int imported = 0;
        for (String[] entry : entries) {
            String name = entry[1] == null ? "unnamed" : entry[1];
            if (DocumentsContract.Document.MIME_TYPE_DIR.equals(entry[2])) {
                imported += importChildren(c, kind, treeUri, entry[0], new File(targetDir, safeName(name)),
                        extensions, depth + 1);
                continue;
            }
            String lower = name.toLowerCase(Locale.ROOT);
            boolean wanted = extensions.isEmpty();
            for (String ext : extensions) {
                wanted |= lower.endsWith(ext);
            }
            if (wanted) {
                copyInto(c, kind, targetDir, DocumentsContract.buildDocumentUriUsingTree(treeUri, entry[0]), name);
                imported++;
            }
        }
        return imported;
    }

    // ---- chain of custody ----

    public void log(ForensicCase c, String action, String detail) {
        String line = Formats.utc(System.currentTimeMillis()) + "Z " + action + " " + detail + "\n";
        try {
            Files.write(new File(c.directory, CUSTODY_FILE).toPath(), line.getBytes(StandardCharsets.UTF_8),
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException ignored) {
            // The log is best-effort; failing to append must not abort the analysis itself.
        }
    }

    @NonNull
    public String custodyLog(ForensicCase c) {
        try {
            return new String(Files.readAllBytes(new File(c.directory, CUSTODY_FILE).toPath()), StandardCharsets.UTF_8);
        } catch (IOException e) {
            return "";
        }
    }
}
