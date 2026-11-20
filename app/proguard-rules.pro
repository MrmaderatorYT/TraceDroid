# JNI entry points and callback interfaces are resolved by name from native code.
-keep class com.ccs.tracedroid.jni.** { *; }
-keepclasseswithmembernames class * { native <methods>; }
