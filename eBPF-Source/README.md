# Re:Kernel — eBPF

如果与你的设备不兼容 请替换include/vmlinux.h

提取设备中的sys/kernel/btf/vmlinux文件 然后通过

bpftool btf dump file vmlinux.btf format c > "include/vmlinux.h"

获取vmlinux.h 然后替换include/vmlinux.h即可