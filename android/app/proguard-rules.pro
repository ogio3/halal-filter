# JNI bridge — keep native methods and public static accessors
-keep class com.halalfilter.bridge.NativeFilter {
    native <methods>;
    public static *;
}

# Stack traces for crash debugging in release builds
-keepattributes SourceFile,LineNumberTable

# Manifest-referenced components (safety net for R8)
-keep class com.halalfilter.vpn.BootReceiver { *; }
