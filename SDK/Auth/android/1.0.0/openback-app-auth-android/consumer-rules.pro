# OpenBack App Auth: keep the serializers of the models (kotlinx.serialization).
-keepattributes *Annotation*, InnerClasses
-keepclassmembers class io.openback.appauth.android.** {
    *** Companion;
}
-keepclasseswithmembers class io.openback.appauth.android.** {
    kotlinx.serialization.KSerializer serializer(...);
}
-keep,includedescriptorclasses class io.openback.appauth.android.**$$serializer { *; }
