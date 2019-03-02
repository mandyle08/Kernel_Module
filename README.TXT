/*****************************************************************************/

Comp 3000 final Project
Packet detection using Kernel Module - Linux
Amanda Le, Phil Neff - Group 57

/*****************************************************************************/
Compilation Instructions

-decompress files within folder
-navigate to folder with files
- in terminal type: make
-after compilation type : sudo insmod packet.ko
-you may be prompted for sudo password - if so enter it.
-once install is done to see module type : watch "dmesg | tail -40"(this will updated last 40 lines of buffer in 2sec intervals)
-conversely you can navigate to /var/log/ and opening syslog file for full details
- to remove module type sudo rmmod packet

/*****************************************************************************/