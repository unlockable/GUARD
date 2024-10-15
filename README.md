# GUARD

GUARD (Generic Unpacking with API Restoration and De-obfuscation) temporary repository.

As part of the submission (double-blind review), we would like to share the source files, experiment files, and results for review purposes. 

We believe that providing access to these materials will enhance the evaluation process and enable a better understanding of the work presented in the paper.

To facilitate the review, we have prepared the following items for submission:

Source files, Experiment Files and Results.

We believe that sharing the source code after acceptance will provide the research community with a deeper understanding of the underlying implementation and enable further exploration and collaboration.

Please let me know if there are any specific guidelines or instructions regarding the submission of these files. 

If you prefer a particular method of file sharing or have a designated platform for code review, kindly inform me, and we will promptly comply with your requirements (unlockable7@gmail.com).

Thank you for considering our submission and for your attention to this matter. We are eagerly looking forward to the opportunity to present our work.


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
