ETW-based upload monitor for Windows
====================================

This is the real file-I/O observation path again. It uses ETW to watch file
activity and network sends, then correlates them by PID and timestamp so the
monitor can print likely upload activity to the terminal and log file.

COMPILE ON WINDOWS (as Administrator):

MSVC (Visual Studio Developer Command Prompt):
  cl /nologo /W3 /Fe:etw_monitor.exe Q1\src\etw_monitor.c /I Q1\include advapi32.lib ws2_32.lib iphlpapi.lib

MinGW (MSYS2 UCRT64):
  set PATH=C:\msys64\ucrt64\bin;%PATH%
  gcc -O2 -municode -o Q1\etw_monitor.exe Q1/src/etw_monitor.c -I Q1/include -ladvapi32 -lws2_32 -liphlpapi

RUN (Administrator recommended):
  cd Q1
  .\etw_monitor.exe

Notes:
- ETW needs Administrator privileges.
- If you need the old heuristic fallback, it is still available in the repo as
  a separate path, but Q1 now points back to the ETW monitor.
