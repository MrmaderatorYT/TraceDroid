// TraceDroid - offline DFIR / SOC triage for Android.
// Copyright (C) CyberCraft Studio. GNU GPL v3.0 or later.
//
// JNI surface of the native forensic engine (com.ccs.tracedroid.jni.NativeForensicEngine).
//
// Contract:
//  * The Java side holds a `long` handle that is a ForensicSession*; nativeDestroy deletes it.
//  * No C++ exception ever crosses the JNI boundary: every entry point runs inside guarded(),
//    which converts C++ exceptions into pending Java exceptions.
//  * Strings cross the boundary as UTF-16 (GetStringRegion / NewString). NewStringUTF and
//    GetStringUTFChars use *modified* UTF-8, which cannot represent supplementary characters
//    and embedded NULs, so they are never fed with evidence-derived data.
//  * Bulk data moves through direct ByteBuffers: event pages are written into a Java-allocated
//    buffer, graph geometry is exposed as a read-only view of session-owned memory.
#include <jni.h>

#include <new>
#include <stdexcept>
#include <string>
#include <unistd.h>

#include "common/Util.hpp"
#include "core/ForensicSession.hpp"

namespace {

using td::ForensicSession;

constexpr const char* kEngineClass = "com/ccs/tracedroid/jni/NativeForensicEngine";
constexpr const char* kEngineException = "com/ccs/tracedroid/jni/NativeEngineException";

/// Thrown to unwind native code when a Java exception is already pending (e.g. from a callback).
struct JavaExceptionPending {};

struct UniqueFd {
    explicit UniqueFd(int fd) : fd(fd) {}
    ~UniqueFd() {
        if (fd >= 0) ::close(fd);
    }
    UniqueFd(const UniqueFd&) = delete;
    UniqueFd& operator=(const UniqueFd&) = delete;
    int fd;
};

/// Deletes a JNI local reference at scope exit.
template <typename T>
struct LocalRef {
    LocalRef(JNIEnv* env, T ref) : env(env), ref(ref) {}
    ~LocalRef() {
        if (ref) env->DeleteLocalRef(ref);
    }
    LocalRef(const LocalRef&) = delete;
    LocalRef& operator=(const LocalRef&) = delete;
    JNIEnv* env;
    T ref;
};

std::string toUtf8(JNIEnv* env, jstring s) {
    if (!s) return {};
    const jsize len = env->GetStringLength(s);
    std::u16string units(static_cast<size_t>(len), u'\0');
    if (len > 0) env->GetStringRegion(s, 0, len, reinterpret_cast<jchar*>(units.data()));
    if (env->ExceptionCheck()) throw JavaExceptionPending{};
    std::string out;
    // jchar is a native-endian UTF-16 code unit; every supported ABI is little-endian.
    td::utf16leToUtf8(reinterpret_cast<const uint8_t*>(units.data()), units.size(), out, /*stopAtNul=*/false);
    return out;
}

jstring toJString(JNIEnv* env, std::string_view utf8) {
    const std::u16string units = td::utf8ToUtf16(utf8);
    jstring s = env->NewString(reinterpret_cast<const jchar*>(units.data()), static_cast<jsize>(units.size()));
    if (!s) throw JavaExceptionPending{};  // OutOfMemoryError is pending
    return s;
}

void throwJava(JNIEnv* env, const char* className, std::string_view message) {
    if (env->ExceptionCheck()) return;
    const LocalRef<jclass> cls(env, env->FindClass(className));
    if (!cls.ref) return;  // NoClassDefFoundError is pending
    const jmethodID ctor = env->GetMethodID(cls.ref, "<init>", "(Ljava/lang/String;)V");
    if (!ctor) return;
    const std::u16string units = td::utf8ToUtf16(message);
    const LocalRef<jstring> text(env, env->NewString(reinterpret_cast<const jchar*>(units.data()),
                                                     static_cast<jsize>(units.size())));
    if (!text.ref) return;
    const LocalRef<jobject> ex(env, env->NewObject(cls.ref, ctor, text.ref));
    if (ex.ref) env->Throw(static_cast<jthrowable>(ex.ref));
}

/// Maps the in-flight C++ exception to a pending Java exception.
void translateException(JNIEnv* env) {
    try {
        throw;
    } catch (const JavaExceptionPending&) {
        // already pending
    } catch (const td::Cancelled& e) {
        throwJava(env, "java/util/concurrent/CancellationException", e.what());
    } catch (const std::bad_alloc&) {
        throwJava(env, "java/lang/OutOfMemoryError", "native forensic engine ran out of memory");
    } catch (const std::out_of_range& e) {
        throwJava(env, "java/lang/IndexOutOfBoundsException", e.what());
    } catch (const std::invalid_argument& e) {
        throwJava(env, "java/lang/IllegalArgumentException", e.what());
    } catch (const std::exception& e) {
        throwJava(env, kEngineException, e.what());
    } catch (...) {
        throwJava(env, kEngineException, "unknown native error");
    }
}

template <typename Fn>
auto guarded(JNIEnv* env, Fn&& fn) -> decltype(fn()) {
    using Result = decltype(fn());
    try {
        return fn();
    } catch (...) {
        translateException(env);
    }
    if constexpr (!std::is_void_v<Result>) return Result{};
}

ForensicSession& session(jlong handle) {
    if (handle == 0) throw std::invalid_argument("native session is closed");
    return *reinterpret_cast<ForensicSession*>(handle);
}

/// Bridges td::ProgressFn to NativeProgressListener.onProgress(int, long, long).
/// Invoked on the thread that entered the native method, so `env` is valid.
td::ProgressFn makeProgress(JNIEnv* env, jobject listener) {
    if (!listener) return {};
    const LocalRef<jclass> cls(env, env->GetObjectClass(listener));
    const jmethodID method = env->GetMethodID(cls.ref, "onProgress", "(IJJ)V");
    if (!method) throw JavaExceptionPending{};
    return [env, listener, method](int stage, uint64_t current, uint64_t total) {
        env->CallVoidMethod(listener, method, static_cast<jint>(stage), static_cast<jlong>(current),
                            static_cast<jlong>(total));
        if (env->ExceptionCheck()) throw JavaExceptionPending{};  // listener threw: abort the operation
    };
}

// ---------------------------------------------------------------- lifecycle

jlong nativeCreate(JNIEnv* env, jclass) {
    return guarded(env, [&]() -> jlong { return reinterpret_cast<jlong>(new ForensicSession()); });
}

void nativeDestroy(JNIEnv* env, jclass, jlong handle) {
    guarded(env, [&] { delete reinterpret_cast<ForensicSession*>(handle); });
}

void nativeCancel(JNIEnv* env, jclass, jlong handle) {
    guarded(env, [&] { session(handle).cancel(); });
}

// ---------------------------------------------------------------- evidence

jstring nativeIngestEvtx(JNIEnv* env, jclass, jlong handle, jstring path, jobject listener) {
    return guarded(env, [&]() -> jstring {
        return toJString(env, session(handle).ingestEvtx(toUtf8(env, path), makeProgress(env, listener)));
    });
}

void nativeClearEvents(JNIEnv* env, jclass, jlong handle) {
    guarded(env, [&] { session(handle).clearEvents(); });
}

void nativeSaveIndex(JNIEnv* env, jclass, jlong handle, jstring path) {
    guarded(env, [&] { session(handle).saveIndex(toUtf8(env, path)); });
}

jboolean nativeLoadIndex(JNIEnv* env, jclass, jlong handle, jstring path) {
    return guarded(env, [&]() -> jboolean { return session(handle).loadIndex(toUtf8(env, path)) ? JNI_TRUE : JNI_FALSE; });
}

// ---------------------------------------------------------------- Sigma

jint nativeLoadSigmaRules(JNIEnv* env, jclass, jlong handle, jstring path) {
    return guarded(env, [&]() -> jint { return static_cast<jint>(session(handle).loadSigmaRules(toUtf8(env, path))); });
}

void nativeClearSigmaRules(JNIEnv* env, jclass, jlong handle) {
    guarded(env, [&] { session(handle).clearSigmaRules(); });
}

jstring nativeRunSigmaScan(JNIEnv* env, jclass, jlong handle, jobject listener) {
    return guarded(env, [&]() -> jstring {
        return toJString(env, session(handle).runSigmaScan(makeProgress(env, listener)));
    });
}

jstring nativeSigmaSummary(JNIEnv* env, jclass, jlong handle) {
    return guarded(env, [&]() -> jstring { return toJString(env, session(handle).sigmaSummaryJson()); });
}

// ---------------------------------------------------------------- timeline

jint nativeQuery(JNIEnv* env, jclass, jlong handle, jstring text, jboolean regex, jint eventId, jint minSeverity,
                 jlong fromMs, jlong toMs) {
    return guarded(env, [&]() -> jint {
        td::QuerySpec spec;
        spec.text = toUtf8(env, text);
        spec.regex = regex == JNI_TRUE;
        spec.eventId = eventId;
        spec.minSeverity = minSeverity;
        spec.fromMs = fromMs;
        spec.toMs = toMs;
        return static_cast<jint>(session(handle).query(spec));
    });
}

jint nativeFetchPage(JNIEnv* env, jclass, jlong handle, jint offset, jint limit, jobject buffer) {
    return guarded(env, [&]() -> jint {
        if (!buffer || offset < 0 || limit < 0) throw std::invalid_argument("invalid page request");
        auto* address = static_cast<uint8_t*>(env->GetDirectBufferAddress(buffer));
        const jlong capacity = env->GetDirectBufferCapacity(buffer);
        if (!address || capacity <= 0) throw std::invalid_argument("page buffer must be a direct ByteBuffer");
        return static_cast<jint>(session(handle).fetchPage(static_cast<uint32_t>(offset), static_cast<uint32_t>(limit),
                                                           address, static_cast<size_t>(capacity)));
    });
}

jstring nativeEventDetail(JNIEnv* env, jclass, jlong handle, jint eventIndex) {
    return guarded(env, [&]() -> jstring {
        if (eventIndex < 0) throw std::out_of_range("negative event index");
        return toJString(env, session(handle).eventDetailJson(static_cast<uint32_t>(eventIndex)));
    });
}

// ---------------------------------------------------------------- graph

jobject nativeBuildGraph(JNIEnv* env, jclass, jlong handle, jint layoutMode, jint minSeverity, jboolean includeNetwork,
                         jboolean includeDns, jint maxNodes, jobject listener) {
    return guarded(env, [&]() -> jobject {
        td::graph::BuildOptions options;
        options.minSeverity = minSeverity;
        options.includeNetwork = includeNetwork == JNI_TRUE;
        options.includeDns = includeDns == JNI_TRUE;
        if (maxNodes > 0) options.maxNodes = static_cast<size_t>(maxNodes);
        const auto mode = layoutMode == 1 ? td::graph::LayoutMode::ForceDirected : td::graph::LayoutMode::Hierarchical;
        const auto geometry = session(handle).buildGraph(mode, options, makeProgress(env, listener));
        // The buffer aliases session-owned memory; the Java wrapper copies it before releasing its lock.
        jobject view = env->NewDirectByteBuffer(const_cast<uint8_t*>(geometry.data()), static_cast<jlong>(geometry.size()));
        if (!view) throw JavaExceptionPending{};
        return view;
    });
}

jstring nativeGraphNodeDetail(JNIEnv* env, jclass, jlong handle, jint nodeIndex) {
    return guarded(env, [&]() -> jstring {
        if (nodeIndex < 0) throw std::out_of_range("negative node index");
        return toJString(env, session(handle).graphNodeDetailJson(static_cast<uint32_t>(nodeIndex)));
    });
}

// ---------------------------------------------------------------- YARA

jint nativeCompileYaraRules(JNIEnv* env, jclass, jlong handle, jstring path) {
    return guarded(env, [&]() -> jint { return static_cast<jint>(session(handle).compileYaraRules(toUtf8(env, path))); });
}

jstring nativeYaraDiagnostics(JNIEnv* env, jclass, jlong handle) {
    return guarded(env, [&]() -> jstring { return toJString(env, session(handle).yaraDiagnosticsJson()); });
}

jstring nativeYaraScanFd(JNIEnv* env, jclass, jlong handle, jint fd, jstring displayName, jint timeoutSeconds) {
    // The descriptor was detached from its ParcelFileDescriptor: native code owns it from here,
    // including on every error path.
    const UniqueFd owned(fd);
    return guarded(env, [&]() -> jstring {
        if (owned.fd < 0) throw std::invalid_argument("invalid file descriptor");
        return toJString(env, session(handle).yaraScanFd(owned.fd, toUtf8(env, displayName), timeoutSeconds));
    });
}

jstring nativeStats(JNIEnv* env, jclass, jlong handle) {
    return guarded(env, [&]() -> jstring { return toJString(env, session(handle).statsJson()); });
}

#define TD_NATIVE(name, sig) {const_cast<char*>(#name), const_cast<char*>(sig), reinterpret_cast<void*>(name)}

const JNINativeMethod kMethods[] = {
    TD_NATIVE(nativeCreate, "()J"),
    TD_NATIVE(nativeDestroy, "(J)V"),
    TD_NATIVE(nativeCancel, "(J)V"),
    TD_NATIVE(nativeIngestEvtx, "(JLjava/lang/String;Lcom/ccs/tracedroid/jni/NativeProgressListener;)Ljava/lang/String;"),
    TD_NATIVE(nativeClearEvents, "(J)V"),
    TD_NATIVE(nativeSaveIndex, "(JLjava/lang/String;)V"),
    TD_NATIVE(nativeLoadIndex, "(JLjava/lang/String;)Z"),
    TD_NATIVE(nativeLoadSigmaRules, "(JLjava/lang/String;)I"),
    TD_NATIVE(nativeClearSigmaRules, "(J)V"),
    TD_NATIVE(nativeRunSigmaScan, "(JLcom/ccs/tracedroid/jni/NativeProgressListener;)Ljava/lang/String;"),
    TD_NATIVE(nativeSigmaSummary, "(J)Ljava/lang/String;"),
    TD_NATIVE(nativeQuery, "(JLjava/lang/String;ZIIJJ)I"),
    TD_NATIVE(nativeFetchPage, "(JIILjava/nio/ByteBuffer;)I"),
    TD_NATIVE(nativeEventDetail, "(JI)Ljava/lang/String;"),
    TD_NATIVE(nativeBuildGraph, "(JIIZZILcom/ccs/tracedroid/jni/NativeProgressListener;)Ljava/nio/ByteBuffer;"),
    TD_NATIVE(nativeGraphNodeDetail, "(JI)Ljava/lang/String;"),
    TD_NATIVE(nativeCompileYaraRules, "(JLjava/lang/String;)I"),
    TD_NATIVE(nativeYaraDiagnostics, "(J)Ljava/lang/String;"),
    TD_NATIVE(nativeYaraScanFd, "(JILjava/lang/String;I)Ljava/lang/String;"),
    TD_NATIVE(nativeStats, "(J)Ljava/lang/String;"),
};

}  // namespace

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    jclass cls = env->FindClass(kEngineClass);
    if (!cls) return JNI_ERR;
    const jint rc = env->RegisterNatives(cls, kMethods, static_cast<jint>(sizeof kMethods / sizeof kMethods[0]));
    env->DeleteLocalRef(cls);
    return rc == JNI_OK ? JNI_VERSION_1_6 : JNI_ERR;
}
