#!/system/bin/sh
MODDIR=${0%/*}
insmod "$MODDIR"/lkm-loader.ko module_path="$MODDIR/re-kernel.ko"