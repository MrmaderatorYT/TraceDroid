// TraceDroid - offline DFIR / SOC triage for Android.
// Copyright (C) CyberCraft Studio. GNU GPL v3.0 or later.
package com.ccs.tracedroid.ui.cases;

import android.app.Application;
import android.net.Uri;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.lifecycle.AndroidViewModel;
import androidx.lifecycle.LiveData;
import androidx.lifecycle.MutableLiveData;

import com.ccs.tracedroid.R;
import com.ccs.tracedroid.data.CaseRepository;
import com.ccs.tracedroid.data.ForensicCase;
import com.ccs.tracedroid.jni.NativeForensicEngine;
import com.ccs.tracedroid.jni.NativeProgressListener;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Owns the native engine of the open case for the lifetime of the workspace (it survives
 * configuration changes) and serialises all heavy engine work on a single background thread.
 * Fragments observe the LiveData below and re-query when {@link #dataVersion()} changes.
 */
public final class CaseViewModel extends AndroidViewModel {

    /** Snapshot of the background worker state for the progress bar. */
    public static final class Progress {
        public final boolean busy;
        public final String label;
        /** 0..100, or -1 when indeterminate. */
        public final int percent;

        Progress(boolean busy, String label, int percent) {
            this.busy = busy;
            this.label = label;
            this.percent = percent;
        }
    }

    private interface Task {
        void run() throws Exception;
    }

    private final CaseRepository repository;
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final MutableLiveData<Progress> progress = new MutableLiveData<>(new Progress(false, "", -1));
    private final MutableLiveData<Integer> dataVersion = new MutableLiveData<>(0);
    private final MutableLiveData<JSONObject> stats = new MutableLiveData<>();
    private final MutableLiveData<JSONObject> sigmaSummary = new MutableLiveData<>();
    private final MutableLiveData<JSONObject> yaraInfo = new MutableLiveData<>();
    private final MutableLiveData<String> message = new MutableLiveData<>();

    private volatile NativeForensicEngine engine;
    private volatile ForensicCase forensicCase;
    private int version;

    public CaseViewModel(@NonNull Application application) {
        super(application);
        repository = new CaseRepository(application);
    }

    public LiveData<Progress> progress() {
        return progress;
    }

    /** Incremented whenever events or alerts changed; observers should refresh their queries. */
    public LiveData<Integer> dataVersion() {
        return dataVersion;
    }

    public LiveData<JSONObject> stats() {
        return stats;
    }

    public LiveData<JSONObject> sigmaSummary() {
        return sigmaSummary;
    }

    public LiveData<JSONObject> yaraInfo() {
        return yaraInfo;
    }

    /** One-shot user-visible messages; call {@link #consumeMessage()} after showing one. */
    public LiveData<String> message() {
        return message;
    }

    public void consumeMessage() {
        message.setValue(null);
    }

    /** The engine, or null until {@link #open(String)} has been called. */
    @Nullable
    public NativeForensicEngine engine() {
        return engine;
    }

    @Nullable
    public ForensicCase forensicCase() {
        return forensicCase;
    }

    public CaseRepository repository() {
        return repository;
    }

    /** Opens the case once; later calls (e.g. after rotation) are no-ops. Returns false for an unknown id. */
    public boolean open(String caseId) {
        if (engine != null) {
            return true;
        }
        ForensicCase c = repository.find(caseId);
        if (c == null) {
            return false;
        }
        forensicCase = c;
        engine = new NativeForensicEngine();
        submit(R.string.op_opening, this::bootstrap);
        return true;
    }

    public void cancelCurrent() {
        NativeForensicEngine e = engine;
        if (e != null) {
            e.cancel();
        }
    }

    // ---- operations ----

    public void importEvtx(List<Uri> uris) {
        submit(R.string.op_importing, () -> {
            int events = 0;
            for (Uri uri : uris) {
                setLabel(text(R.string.op_copying, CaseRepository.displayName(resolver(), uri)));
                CaseRepository.Imported imported = repository.importDocument(forensicCase, CaseRepository.KIND_EVTX, uri);
                try {
                    events += ingest(imported.file);
                } catch (CancellationException e) {
                    throw e;
                } catch (RuntimeException e) {
                    // Not a parsable EVTX file: do not keep it as evidence of this kind.
                    //noinspection ResultOfMethodCallIgnored
                    imported.file.delete();
                    repository.log(forensicCase, "REJECTED", "file=\"" + imported.file.getName() + "\" reason=\"" + e.getMessage() + "\"");
                    post(text(R.string.msg_ingest_failed, imported.file.getName(), e.getMessage()));
                }
            }
            persistIndex();
            scanIfPossible();
            post(text(R.string.msg_events_added, events));
        });
    }

    public void importSigmaFiles(List<Uri> uris) {
        submit(R.string.op_importing, () -> {
            for (Uri uri : uris) {
                repository.importDocument(forensicCase, CaseRepository.KIND_SIGMA, uri);
            }
            reloadSigma();
        });
    }

    public void importSigmaTree(Uri tree) {
        submit(R.string.op_importing, () -> {
            int files = repository.importTree(forensicCase, CaseRepository.KIND_SIGMA, tree, ".yml", ".yaml");
            post(text(R.string.msg_files_imported, files));
            reloadSigma();
        });
    }

    public void clearSigma() {
        submit(R.string.op_working, () -> {
            repository.clear(forensicCase, CaseRepository.KIND_SIGMA);
            engine.clearSigmaRules();
        });
    }

    public void rescanSigma() {
        submit(R.string.op_sigma, this::scanIfPossible);
    }

    public void importYaraFiles(List<Uri> uris) {
        submit(R.string.op_importing, () -> {
            for (Uri uri : uris) {
                repository.importDocument(forensicCase, CaseRepository.KIND_YARA, uri);
            }
            compileYara(true);
        });
    }

    public void importYaraTree(Uri tree) {
        submit(R.string.op_importing, () -> {
            int files = repository.importTree(forensicCase, CaseRepository.KIND_YARA, tree, ".yar", ".yara");
            post(text(R.string.msg_files_imported, files));
            compileYara(true);
        });
    }

    public void clearYara() {
        submit(R.string.op_working, () -> {
            repository.clear(forensicCase, CaseRepository.KIND_YARA);
            compileYara(false);
        });
    }

    /** Throws the whole index away and re-parses every EVTX file of the case. */
    public void rebuildIndex() {
        submit(R.string.op_parsing, () -> {
            engine.clearEvents();
            //noinspection ResultOfMethodCallIgnored
            repository.indexFile(forensicCase).delete();
            ingestAll();
            persistIndex();
            scanIfPossible();
        });
    }

    // ---- worker-thread helpers ----

    private void bootstrap() throws JSONException {
        File index = repository.indexFile(forensicCase);
        boolean loaded = index.isFile() && engine.loadIndex(index.getAbsolutePath());
        if (!loaded) {
            ingestAll();
            persistIndex();
        }
        int rules = repository.files(forensicCase, CaseRepository.KIND_SIGMA).isEmpty() ? 0
                : engine.loadSigmaRules(repository.directory(forensicCase, CaseRepository.KIND_SIGMA).getAbsolutePath());
        if (rules > 0) {
            scanIfPossible();
        }
        compileYara(false);
    }

    private void ingestAll() throws JSONException {
        for (File file : repository.files(forensicCase, CaseRepository.KIND_EVTX)) {
            try {
                ingest(file);
            } catch (CancellationException e) {
                throw e;
            } catch (RuntimeException e) {
                post(text(R.string.msg_ingest_failed, file.getName(), e.getMessage()));
            }
        }
    }

    private int ingest(File file) throws JSONException {
        setLabel(text(R.string.op_parsing_file, file.getName()));
        JSONObject report = new JSONObject(engine.ingestEvtx(file.getAbsolutePath(), listener(R.string.op_parsing)));
        repository.log(forensicCase, "INGESTED", String.format(Locale.ROOT,
                "file=\"%s\" events=%d failedRecords=%d badChunks=%d dirty=%b", file.getName(),
                report.optLong("events"), report.optLong("failedRecords"), report.optLong("badChunks"),
                report.optBoolean("dirty")));
        long failed = report.optLong("failedRecords");
        long badChunks = report.optLong("badChunks");
        if (failed > 0 || badChunks > 0) {
            post(text(R.string.msg_ingest_damage, file.getName(), failed, badChunks));
        }
        return (int) report.optLong("events");
    }

    private void persistIndex() {
        setLabel(text(R.string.op_saving_index));
        engine.saveIndex(repository.indexFile(forensicCase).getAbsolutePath());
    }

    private void reloadSigma() throws JSONException {
        engine.clearSigmaRules();
        int rules = engine.loadSigmaRules(repository.directory(forensicCase, CaseRepository.KIND_SIGMA).getAbsolutePath());
        post(text(R.string.msg_rules_loaded, rules));
        scanIfPossible();
    }

    private void scanIfPossible() throws JSONException {
        JSONObject current = new JSONObject(engine.stats());
        if (current.optLong("events") == 0 || current.optLong("sigmaRules") == 0) {
            return;
        }
        setLabel(text(R.string.op_sigma));
        engine.runSigmaScan(listener(R.string.op_sigma));
    }

    private void compileYara(boolean announce) {
        File dir = repository.directory(forensicCase, CaseRepository.KIND_YARA);
        if (!repository.files(forensicCase, CaseRepository.KIND_YARA).isEmpty()) {
            setLabel(text(R.string.op_yara_compile));
            int rules = engine.compileYaraRules(dir.getAbsolutePath());
            if (announce) {
                post(text(R.string.msg_yara_rules, rules));
            }
        } else {
            engine.compileYaraRules(dir.getAbsolutePath());
        }
    }

    /**
     * Runs {@code task} on the worker thread with busy state, error reporting and a state refresh.
     * Tasks queue up behind each other, so imports and scans never run concurrently.
     */
    private void submit(int labelRes, Task task) {
        final String label = text(labelRes);
        worker.execute(() -> {
            progress.postValue(new Progress(true, label, -1));
            try {
                task.run();
            } catch (CancellationException e) {
                post(text(R.string.msg_cancelled));
            } catch (Exception e) {
                String reason = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
                post(text(R.string.msg_failed, reason));
            } finally {
                refreshState();
                progress.postValue(new Progress(false, "", -1));
            }
        });
    }

    /** Runs arbitrary engine work (e.g. a YARA scan) behind the same queue and progress UI. */
    public void runExclusive(int labelRes, Runnable work) {
        submit(labelRes, work::run);
    }

    public void setLabel(String label) {
        progress.postValue(new Progress(true, label, -1));
    }

    public void setProgress(String label, long current, long total) {
        int percent = total > 0 ? (int) Math.min(100, current * 100 / total) : -1;
        progress.postValue(new Progress(true, label, percent));
    }

    private NativeProgressListener listener(int labelRes) {
        final String label = text(labelRes);
        return (stage, current, total) -> setProgress(label, current, total);
    }

    private void refreshState() {
        NativeForensicEngine e = engine;
        if (e == null) {
            return;
        }
        try {
            stats.postValue(new JSONObject(e.stats()));
            sigmaSummary.postValue(new JSONObject(e.sigmaSummary()));
            yaraInfo.postValue(new JSONObject(e.yaraDiagnostics()));
        } catch (JSONException | RuntimeException ignored) {
            // Engine closed while refreshing, or malformed JSON: keep the previous state.
        }
        dataVersion.postValue(++version);
    }

    private void post(String text) {
        message.postValue(text);
    }

    private String text(int res, Object... args) {
        return getApplication().getString(res, args);
    }

    private android.content.ContentResolver resolver() {
        return getApplication().getContentResolver();
    }

    @Override
    protected void onCleared() {
        final NativeForensicEngine e = engine;
        engine = null;
        if (e != null) {
            e.cancel();
            // Close behind any task that is still unwinding so native memory is never freed under it.
            worker.execute(e::close);
        }
        worker.shutdown();
    }
}
