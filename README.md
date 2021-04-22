# How to avoid DLL injection?

* Proof-of-Concept on how to block DLLs from being forcibly loaded onto a process
* Effective against many HIPS/Debugging tools
* Works for most DLLs loaded both from user & kernelmode
* Exception are DLLs loaded manually through ZwMapViewOfSection (which is the case of some system DLLs loaded during process startup)

# Simple trick
* Create a suspended process
* Hook the LdrLoadDll function to filter function inside its own address space
* Resume the process
