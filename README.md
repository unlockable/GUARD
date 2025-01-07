# GUARD

GUARD (Generic Unpacking with API Restoration and De-obfuscation) repository.

We share the source files, experiment files, and results. 

We believe that providing access to these materials will enhance the evaluation process and enable a better understanding of the work presented in the paper.

Please refer to the paper presented in SAC '25: Proceedings of the 40th ACM/SIGAPP Symposium on Applied Computing for details.

# Usage

Current GUARD distributed version works with Pin v3.22

You can download it, here(https://www.intel.com/content/www/us/en/developer/articles/tool/pin-a-binary-instrumentation-tool-downloads.html).

We use Pin in order to automatically execute target file until OEP address.

```bash
pin.exe -t <Pin DLL> -o <Target File Path>
```
If you want to use other analysis tools like x64dbg, you can use its scripts or manually trace instructions until OEP.

For GUARD executable inputs, you need PID of target process, and OEP address.

To build GUARD executable, we used Visual Studio 17 2022.

```bash
mkdir build && cd build
cmake -G "Visual Studio 17 2022" ..
cmake --build . --config Release
```
After that, simply execute GUARD with inputs

```bash
GUARD.exe <Target PID> "" -ep=0xOEP ""
```

# Acknowledgements
1. Pin tool implementation
   - To implement OEP search, we refered paper
   - Lee, Young Bi, Jae Hyuk Suk, and Dong Hoon Lee. "Bypassing anti-analysis of commercial protector methods using DBI tools." IEEE Access 9 (2021): 7655-7673.
   - And, to bypass heaven's gate technique, which is default anti-debugging method of < v3.6 VMProtect, we refered to and used implementation of following paper work
   - Hwang, Seon-Jin, et al. "Bypassing Heaven’s Gate Technique Using Black-Box Testing." Sensors 23.23 (2023): 9417.
   - https://github.com/unlockable/Bypassing-Heaven-s-Gate

2. IAT Restoration
   - To implement IAT search and restoration, we used VMPDump as base code. We changed its implementation that use Vtil to unicorn based and implemented sIAT and other functionalities
   - https://github.com/0xnobody/vmpdump
