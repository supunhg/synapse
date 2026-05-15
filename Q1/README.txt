Minimal ETW-based upload monitor for Windows
============================================

COMPILE ON WINDOWS (as Administrator):

MSVC (Visual Studio Developer Command Prompt):
  cl /nologo /W3 /Fe:etw_monitor.exe Q1\src\etw_monitor.c /I Q1\include advapi32.lib ws2_32.lib iphlpapi.lib

MinGW:
  gcc -O2 -o etw_monitor.exe Q1/src/etw_monitor.c -I Q1/include -ladvapi32 -lws2_32 -liphlpapi

RUN (requires Administrator):
  .\etw_monitor.exe

WHAT IT DOES:
1. Starts an ETW kernel trace session
2. Enables File I/O and TCP/IP providers
3. Correlates file events with network events by Process ID and timestamp
4. Prints the required upload details to the console
