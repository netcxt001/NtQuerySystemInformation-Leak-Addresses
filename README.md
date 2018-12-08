# NtQuerySystemInformation-Leak-Addresses
C program to leak kernel memory addresses via NtQuerySystemInformation undocumented function (Windows 7 x86)

This program exactly leaks the HalDispatchTable+0x4 very useful in kernel exploits for an arbitrary overwrite bug.

Some structs have been added for load the NtQuerySystemInformation function.
