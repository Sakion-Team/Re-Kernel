# ReKernel AAR consumer ProGuard/R8 rules.
# These rules are automatically applied to consuming projects when R8 is enabled.
-keep class org.sakion.rekernel.ReKernel {
    *;
}

-keep interface org.sakion.rekernel.ReKernel$Callback {
    *;
}
