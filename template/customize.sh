SKIPUNZIP=0

KERNEL_VERSION=$(uname -r)

ui_print "当前内核版本: $KERNEL_VERSION"

if [[ "$KERNEL_VERSION" == *"6.12"* ]]; then
    ui_print "检测到内核版本为 android16-6.12"
    cp $MODPATH/lib/android16-6.12-lkmloader.ko $MODPATH/lkm-loader.ko
    cp $MODPATH/lkm/android16-6.12_rekernel.ko $MODPATH/re-kernel.ko
elif [[ "$KERNEL_VERSION" == *"6.6"* ]]; then
    ui_print "检测到内核版本为 android15-6.6"
    cp $MODPATH/lib/android15-6.6-lkmloader.ko $MODPATH/lkm-loader.ko
    cp $MODPATH/lkm/android15-6.6_rekernel.ko $MODPATH/re-kernel.ko
elif [[ "$KERNEL_VERSION" == *"14"* && "$KERNEL_VERSION" == *"6.1"* ]]; then
    ui_print "检测到内核版本为 android14-6.1"
    cp $MODPATH/lib/android14-6.1-lkmloader.ko $MODPATH/lkm-loader.ko
    cp $MODPATH/lkm/android14-6.1_rekernel.ko $MODPATH/re-kernel.ko
elif [[ "$KERNEL_VERSION" == *"14"* && "$KERNEL_VERSION" == *"5.15"* ]]; then
    ui_print "检测到内核版本为 android14-14-5.15"
    cp $MODPATH/lib/android14-5.15-lkmloader.ko $MODPATH/lkm-loader.ko
    cp $MODPATH/lkm/android14-5.15_rekernel.ko $MODPATH/re-kernel.ko
elif [[ "$KERNEL_VERSION" == *"13"* && "$KERNEL_VERSION" == *"5.15"* ]]; then
    ui_print "检测到内核版本为 android13-13-5.15"
    cp $MODPATH/lib/android13-5.15-lkmloader.ko $MODPATH/lkm-loader.ko
    cp $MODPATH/lkm/android13-5.15_rekernel.ko $MODPATH/re-kernel.ko
elif [[ "$KERNEL_VERSION" == *"13"* && "$KERNEL_VERSION" == *"5.10"* ]]; then
    ui_print "检测到内核版本为 android13-13-5.10"
    cp $MODPATH/lib/android13-5.10-lkmloader.ko $MODPATH/lkm-loader.ko
    cp $MODPATH/lkm/android13-5.10_rekernel.ko $MODPATH/re-kernel.ko
elif [[ "$KERNEL_VERSION" == *"12"* && "$KERNEL_VERSION" == *"5.10"* ]]; then
    ui_print "检测到内核版本为 android12-12-5.10"
    cp $MODPATH/lib/android12-5.10-lkmloader.ko $MODPATH/lkm-loader.ko
    cp $MODPATH/lkm/android12-5.10_rekernel.ko $MODPATH/re-kernel.ko
else
    abort "无法匹配到支持的内核版本，请手动检查内核版本并选择相应的模块"
fi

rm -rf $MODPATH/lib
rm -rf $MODPATH/lkm

set_perm $MODPATH/lkm-loader.ko 0 0 0755
set_perm $MODPATH/re-kernel.ko 0 0 0755

ui_print "操作完成！内核端口ID: 100"
