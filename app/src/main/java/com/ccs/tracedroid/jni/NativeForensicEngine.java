// TraceDroid - offline DFIR / SOC triage for Android.
// Copyright (C) CyberCraft Studio. GNU GPL v3.0 or later.
package com.ccs.tracedroid.jni;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.ccs.tracedroid.model.EventRow;
import com.ccs.tracedroid.model.GraphModel;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.List;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Java face of the C++ forensic engine. One instance owns one native session (an RAII C++ object
 * addressed through {@code nativeHandle}); {@link #close()} destroys it.
 *
 * <p>Threading: every method may be called from any background thread. Calls hold a shared
 * lifecycle lock so that {@link #close()} can never free the native session underneath a running
 * operation; long operations can be interrupted with {@link #cancel()}. Do not call the heavy
 * methods on the UI thread.
 */
public final class NativeForensicEngine implements AutoCloseable {

    public static final int STAGE_PARSE = 1;
    public static final int STAGE_INDEX = 2;
    public static final int STAGE_SIGMA = 3;
    public static final int STAGE_GRAPH = 4;
    public static final int STAGE_YARA = 5;

    public static final int LAYOUT_HIERARCHICAL = 0;
    public static final int LAYOUT_FORCE_DIRECTED = 1;

    private static final int PAGE_BUFFER_BYTES = 512 * 1024;

    static {
        System.loadLibrary("tracedroid");
    }

    private final ReentrantReadWriteLock lifecycle = new ReentrantReadWriteLock();
    private final ThreadLocal<ByteBuffer> pageBuffers = ThreadLocal.withInitial(
            () -> ByteBuffer.allocateDirect(PAGE_BUFFER_BYTES).order(ByteOrder.LITTLE_ENDIAN));
    private long nativeHandle;

    public NativeForensicEngine() {
        nativeHandle = nativeCreate();
        if (nativeHandle == 0) {
            throw new NativeEngineException("could not create native session");
        }
    }

    private interface Call<T> {
        T run(long handle);
    }

    private <T> T call(Call<T> body) {
        lifecycle.readLock().lock();
        try {
            if (nativeHandle == 0) {
                throw new IllegalStateException("native engine is closed");
            }
            return body.run(nativeHandle);
        } finally {
            lifecycle.readLock().unlock();
        }
    }

    /** Asks the operation currently running on another thread to stop; it then throws CancellationException. */
    public void cancel() {
        lifecycle.readLock().lock();
        try {
            if (nativeHandle != 0) {
                nativeCancel(nativeHandle);
            }
        } finally {
            lifecycle.readLock().unlock();
        }
    }

    /** Cancels running work, waits for it to unwind and releases all native memory. Idempotent. */
    @Override
    public void close() {
        cancel();
        lifecycle.writeLock().lock();
        try {
            if (nativeHandle != 0) {
                nativeDestroy(nativeHandle);
                nativeHandle = 0;
            }
        } finally {
            lifecycle.writeLock().unlock();
        }
    }

    // ---- evidence ----

    /** Parses an .evtx file into the index; returns a JSON ingest report. */
    @NonNull
    public String ingestEvtx(@NonNull String path, @Nullable NativeProgressListener listener) {
        return call(h -> nativeIngestEvtx(h, path, listener));
    }

    public void clearEvents() {
        call(h -> {
            nativeClearEvents(h);
            return null;
        });
    }

    public void saveIndex(@NonNull String path) {
        call(h -> {
            nativeSaveIndex(h, path);
            return null;
        });
    }

    public boolean loadIndex(@NonNull String path) {
        return call(h -> nativeLoadIndex(h, path));
    }

    // ---- Sigma ----

    /** Loads a rule file or a directory of rules; returns the number of rules added. */
    public int loadSigmaRules(@NonNull String path) {
        return call(h -> nativeLoadSigmaRules(h, path));
    }

    public void clearSigmaRules() {
        call(h -> {
            nativeClearSigmaRules(h);
            return null;
        });
    }

    /** Evaluates all loaded rules against all events; returns the JSON scan summary. */
    @NonNull
    public String runSigmaScan(@Nullable NativeProgressListener listener) {
        return call(h -> nativeRunSigmaScan(h, listener));
    }

    @NonNull
    public String sigmaSummary() {
        return call(NativeForensicEngine::nativeSigmaSummary);
    }

    // ---- timeline ----

    /**
     * Runs a filter natively and keeps the result set for paging.
     *
     * @param eventId     -1 for any
     * @param minSeverity 0 for any, otherwise the minimum Sigma level (1..5)
     * @return number of matching events
     */
    public int query(@NonNull String text, boolean regex, int eventId, int minSeverity, long fromMs, long toMs) {
        return call(h -> nativeQuery(h, text, regex, eventId, minSeverity, fromMs, toMs));
    }

    /** Fetches rows [offset, offset + limit) of the current result set through a direct buffer. */
    @NonNull
    public List<EventRow> fetchPage(int offset, int limit) {
        return call(h -> {
            ByteBuffer buffer = pageBuffers.get();
            buffer.clear();
            int written = nativeFetchPage(h, offset, limit, buffer);
            buffer.limit(written);
            return EventRow.decodePage(buffer);
        });
    }

    /** Full event as JSON: fields with match highlighting, Sigma alerts and the rendered XML. */
    @NonNull
    public String eventDetail(int eventIndex) {
        return call(h -> nativeEventDetail(h, eventIndex));
    }

    // ---- graph ----

    /**
     * Rebuilds the process / network graph and computes its layout natively.
     * The geometry arrives as a direct ByteBuffer that aliases native memory; it is decoded into
     * a self-contained {@link GraphModel} before the lifecycle lock is released.
     */
    @NonNull
    public GraphModel buildGraph(int layoutMode, int minSeverity, boolean includeNetwork, boolean includeDns,
                                 int maxNodes, @Nullable NativeProgressListener listener) {
        return call(h -> {
            ByteBuffer geometry = nativeBuildGraph(h, layoutMode, minSeverity, includeNetwork, includeDns,
                    maxNodes, listener);
            return GraphModel.decode(geometry.asReadOnlyBuffer().order(ByteOrder.LITTLE_ENDIAN));
        });
    }

    @NonNull
    public String graphNodeDetail(int nodeIndex) {
        return call(h -> nativeGraphNodeDetail(h, nodeIndex));
    }

    // ---- YARA ----

    /** Compiles a .yar file or a directory of rule files, replacing the loaded rule set. */
    public int compileYaraRules(@NonNull String path) {
        return call(h -> nativeCompileYaraRules(h, path));
    }

    @NonNull
    public String yaraDiagnostics() {
        return call(NativeForensicEngine::nativeYaraDiagnostics);
    }

    /**
     * Scans an artifact by file descriptor.
     *
     * @param detachedFd a descriptor obtained from {@code ParcelFileDescriptor.detachFd()};
     *                   ownership passes to native code, which closes it in every case
     */
    @NonNull
    public String yaraScanFd(int detachedFd, @NonNull String displayName, int timeoutSeconds) {
        lifecycle.readLock().lock();
        try {
            if (nativeHandle == 0) {
                // Native code never saw the descriptor, so it must be released here.
                android.os.ParcelFileDescriptor.adoptFd(detachedFd).close();
                throw new IllegalStateException("native engine is closed");
            }
            return nativeYaraScanFd(nativeHandle, detachedFd, displayName, timeoutSeconds);
        } catch (java.io.IOException e) {
            throw new IllegalStateException("native engine is closed", e);
        } finally {
            lifecycle.readLock().unlock();
        }
    }

    @NonNull
    public String stats() {
        return call(NativeForensicEngine::nativeStats);
    }

    // ---- native methods (registered in JNI_OnLoad) ----

    private static native long nativeCreate();

    private static native void nativeDestroy(long handle);

    private static native void nativeCancel(long handle);

    private static native String nativeIngestEvtx(long handle, String path, NativeProgressListener listener);

    private static native void nativeClearEvents(long handle);

    private static native void nativeSaveIndex(long handle, String path);

    private static native boolean nativeLoadIndex(long handle, String path);

    private static native int nativeLoadSigmaRules(long handle, String path);

    private static native void nativeClearSigmaRules(long handle);

    private static native String nativeRunSigmaScan(long handle, NativeProgressListener listener);

    private static native String nativeSigmaSummary(long handle);

    private static native int nativeQuery(long handle, String text, boolean regex, int eventId, int minSeverity,
                                          long fromMs, long toMs);

    private static native int nativeFetchPage(long handle, int offset, int limit, ByteBuffer out);

    private static native String nativeEventDetail(long handle, int eventIndex);

    private static native ByteBuffer nativeBuildGraph(long handle, int layoutMode, int minSeverity,
                                                      boolean includeNetwork, boolean includeDns, int maxNodes,
                                                      NativeProgressListener listener);

    private static native String nativeGraphNodeDetail(long handle, int nodeIndex);

    private static native int nativeCompileYaraRules(long handle, String path);

    private static native String nativeYaraDiagnostics(long handle);

    private static native String nativeYaraScanFd(long handle, int fd, String displayName, int timeoutSeconds);

    private static native String nativeStats(long handle);
}
