SKIPUNZIP=0
KERNEL_VERSION=$(uname -r)
ui_print "- 当前系统内核: $KERNEL_VERSION"

CORE_VER=${KERNEL_VERSION%%-*}
CORE_VER=${CORE_VER%.*}

AND_VER=${KERNEL_VERSION#*-android}
AND_VER=${AND_VER%%-*}

SUPPORTED_VERS=""
for file in "$MODPATH/module"/*_rekernel.ko; do
    name=${file##*/} 
    SUPPORTED_VERS="$SUPPORTED_VERS ${name%_rekernel.ko}"
done

TEMP_VER="android${AND_VER}-${CORE_VER}"

if [ -f "$MODPATH/module/${TEMP_VER}_rekernel.ko" ] && [ -f "$MODPATH/loader/${TEMP_VER}-lkmloader.ko" ]; then
    TARGET_VER="$TEMP_VER"
elif [[ "$CORE_VER" == "5.10" ]]; then
    TARGET_VER="android12-5.10"
elif [[ "$CORE_VER" == "5.15" ]]; then
    TARGET_VER="android13-5.15"
elif [[ "$CORE_VER" == "6.1" ]]; then
    TARGET_VER="android14-6.1"
elif [[ "$CORE_VER" == "6.6" ]]; then
    TARGET_VER="android15-6.6"
elif [[ "$CORE_VER" == "6.12" ]]; then
    TARGET_VER="android16-6.12"
else
    abort "! 自动匹配失败，请查看安装脚本并自行修改"
fi

ui_print "- 自动匹配成功: $TARGET_VER"
LKM_SRC="$MODPATH/loader/${TARGET_VER}-lkmloader.ko"
REK_SRC="$MODPATH/module/${TARGET_VER}_rekernel.ko"
cp "$LKM_SRC" "$MODPATH/lkm-loader.ko"
cp "$REK_SRC" "$MODPATH/re-kernel.ko"

rm -rf $MODPATH/loader
rm -rf $MODPATH/module

set_perm "$MODPATH/lkm-loader.ko" 0 0 0755
set_perm "$MODPATH/re-kernel.ko" 0 0 0755

ui_print "- 操作完成！内核端口ID: 100"