# Re-Kernel
[![C](https://img.shields.io/badge/language-C-%23f34b7d.svg?style=plastic)](https://en.wikipedia.org/wiki/C_(programming_language)) 
[![Windows](https://img.shields.io/badge/platform-Android-0078d7.svg?style=plastic)](https://en.wikipedia.org/wiki/Microsoft_Windows) 
[![x86](https://img.shields.io/badge/arch-AArch64-red.svg?style=plastic)](https://en.wikipedia.org/wiki/AArch64)

Make tombstone users get a better experience.

## Downloading
Find your device kernel from the [list of supported devices](https://github.com/Sakion-Team/Re-Kernel/tree/main/Supported-Devices), and download it.

## Start use
Tip: MIUI/HyperOS or ColorOS/RealmeUI do not require the use of this kernel.

### Warning
If you cannot to recover the device after it bootloop, please use methods 1 and 3 with caution!

When using method 1, Please make sure you have a computer or your Magisk/KernelSU that can use the rescue function, otherwise it may bootlooppppp!

When using method 3, please make sure you have a computer nearby, otherwise it may bootlooppppp!

### Prerequisites
If you need to use Re: Kernel, you need a device that has already been rooted. There are currently three ways to install Re:Kernel into your device.

#### Method 1: Recommendation: Magisk Module(Need your kernel version >= 5.10)
Flash in the Re:Kernel module to your device so that Re:Kernel will automatically mount after each boot up.

#### Method 2: Manual mounting(Need your kernel version >= 5.10)
Download Re:Kernel LKM, then place it in the data folder in the root directory and use the `insmod` command to mount the kernel module (it will stop working after rebooting, which means it needs to be mounted again every time it when your device boot) Suggest using this method first to ensure that the kernel module does not cause problems with your device!

### Method 3: Flashing Kernel(Only your kernel version <= 5.4)
Find your device kernel from the [list of supported devices](https://github.com/Sakion-Team/Re-Kernel/tree/main/Supported-Devices), and enter the fastboot mode of the phone, then use the `fastboot flash boot` command or use another kernel flasher to flash the kernel into your phone.

## Connecting the tombstone to Re:Kernel
Re:Kernel has opened a Netlink server that allows all tombstone developers to integrate it into their own tombstones. For details, please go to the [Develop](https://github.com/Sakion-Team/Re-Kernel/tree/main/Develop) folder in the repository to view.

## Integrate Re:Kernel for non GKI or GKI1.0 kernels
For users with kernel versions less than or equal to 5.4, we provide a method for users to insert Re:Kernel code into their device's kernel to support Re:Kernel. However, you should be able to build a bootable kernel from your kernel source code. If the kernel is not open source, this is almost impossible.

Of course, if your kernel is open-source, you can also try [Issues](https://github.com/Sakion-Team/Re-Kernel/issues) Creating kernel adaptation requests in may cause developers to integrate Re:Kernel to your kernel.
