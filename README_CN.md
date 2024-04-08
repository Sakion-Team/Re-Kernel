# Re-Kernel
[![C](https://img.shields.io/badge/language-C-%23f34b7d.svg?style=plastic)](https://en.wikipedia.org/wiki/C_(programming_language)) 
[![Windows](https://img.shields.io/badge/platform-Android-0078d7.svg?style=plastic)](https://en.wikipedia.org/wiki/Microsoft_Windows) 
[![x86](https://img.shields.io/badge/arch-AArch64-red.svg?style=plastic)](https://en.wikipedia.org/wiki/AArch64)

使墓碑用户获得更好的使用体验。

## 开始使用

### 特殊准备
如果你需要使用Re:Kernel的话 你需要一台已经被Root的设备 目前有三种方法可以安装Re:Kernel到你的设备当中

#### 推荐: Magisk模块(内核版本大于等于5.10)
刷入Re:Kernel模块到你的设备 这样Re:Kernel将会在每次开机后自动挂载

#### 手动挂载(内核版本大于等于5.10)
下载Re:Kernel内核模块，然后将他放入根目录下的data文件夹 并使用`insmod`命令挂载内核模块

#### 刷写内核(仅内核版本小于等于5.4)
从 Re:Kernel已适配机型列表 中寻找你设备的内核 并将手机进入fastboot模式 然后使用`fastboot flash boot`命令将内核刷入你的手机

## 为墓碑接入Re:Kernel
Re:Kernel内核开放了一个Netlink服务器 允许所有墓碑开发者将其接入自己的墓碑当中 详情请前往仓库的 [Develop](https://github.com/Sakion-Team/Re-Kernel/tree/main/Develop) 文件夹中查看

## 为内核提供Re:Kernel支持
对于内核版本小于等于5.4的用户 我们提供方法让用户可以自行将Re:Kernel代码插入你的设备内核当中 让其内核支持Re:Binder 但前提是 你必须有能力从你设备的内核源码编译出一个可以开机并且能正常使用的内核 如果内核不开源的话 这几乎是不可能的

当然 如果你的内核开源 也可以尝试在 [Issues](https://github.com/Sakion-Team/Re-Kernel/issues) 中创建内核适配请求 开发者可能会为你的内核适配Re:Kernel
