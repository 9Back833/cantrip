# CapBuddy

CapBuddy is a project based on CantripOS.Project link for CantripOS:[CantripOS](https://github.com/AmbiML/sparrow-cantrip-full).

Differences from CantripOS:

Change the original management method of CantripOS for frames to Buddy management strategy.

Modification of kernel config:

Due to Retype "fanout" limit of 256 objects: split our request accordingly.To match the Buddy management strategy, we have modified the Retype "fanout" limit to 1024

How to run:

Consistent with the startup process of CantripOs.

Getting started with repo & the build system.

To get started follow these steps:

1. Clone the CapBuddy project from the GitHub.
2. Download, build, and boot the system to the Cantrip shell prompt.
   For now the only target platform that works is "rpi3"
   (for a raspi3b machine running in simulation on qemu).

``` shell
cd sparrow
export PLATFORM=rpi3
source build/setup.sh
m simulate
```
