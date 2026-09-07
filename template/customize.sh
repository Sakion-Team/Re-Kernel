SKIPUNZIP=0

set_perm_recursive "$MODPATH"/kmod 0 0 0755 0755

KERNEL_VERSION=$(uname -r)
ui_print "- 当前内核版本: $KERNEL_VERSION"

CORE_VER=${KERNEL_VERSION%%-*}
CORE_VER=${CORE_VER%.*}

if [[ "$KERNEL_VERSION" == *"android"* ]]; then
    AND_VER=${KERNEL_VERSION#*-android}
    AND_VER=${AND_VER%%-*}
else
    [ "$CORE_VER" = "6.18" ] && AND_VER="17"
    [ "$CORE_VER" = "6.12" ] && AND_VER="16"
    [ "$CORE_VER" = "6.6" ]  && AND_VER="15"
    [ "$CORE_VER" = "6.1" ]  && AND_VER="14"
    [ "$CORE_VER" = "5.15" ] && AND_VER="13"
    [ "$CORE_VER" = "5.10" ] && AND_VER="12"
fi

TARGET_VER="android${AND_VER}-${CORE_VER}"

if ls $MODPATH/kmod/rekernel-${TARGET_VER}* >/dev/null 2>&1; then
    ui_print "- 自动匹配成功: $TARGET_VER"
else
    abort "! 自动匹配失败，请查看安装脚本并自行修改"
fi

cp -fp "$MODPATH"/kmod/rekernel-${TARGET_VER}* "$MODPATH"/
rm -rf $MODPATH/kmod

ui_print "- 操作完成！内核端口ID: 100"REK_SRC="$MODPATH/module/${TARGET_VER}_rekernel.ko"
