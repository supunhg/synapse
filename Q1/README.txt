Poll-based heuristic upload detector (fast fallback)
============================================

This is a simple, fast fallback implementation that polls active TCP connections
and heuristically checks common user folders for recently modified files by
process. It is an approximation and intentionally lightweight.

COMPILE ON WINDOWS (as Administrator):

MSVC (Visual Studio Developer Command Prompt):
  cl /nologo /W3 /Fe:poll_monitor.exe Q1\src\poll_monitor.c /I Q1\include iphlpapi.lib psapi.lib

MinGW (MSYS2 UCRT64):
  set PATH=C:\msys64\ucrt64\bin;%PATH%
  gcc -O2 -municode -o Q1\poll_monitor.exe Q1/src/poll_monitor.c -I Q1/include -ladvapi32 -lws2_32 -liphlpapi -lpsapi

RUN (Administrator recommended):
  cd Q1
  .\poll_monitor.exe

Notes:
- This approach is heuristic: it reports likely uploads by pairing ESTABLISHED
  outbound TCP connections with recently modified files in common directories.
- It is much easier to run and debug than ETW or kernel approaches, but less
  precise. Use Procmon correlation (tools/correlate_procmon.py) for stronger
  evidence when needed.
