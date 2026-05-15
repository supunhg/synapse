Build and run instructions for the ETW-based upload monitor.

On Windows (MSVC - Developer Command Prompt):

cl /nologo /W3 /Fe:etw_monitor.exe Q1\\src\\correlator.c Q1\\src\\etw_monitor.c /I Q1\\include

On Windows (MinGW):

x86_64-w64-mingw32-gcc -O2 -o etw_monitor.exe Q1/src/correlator.c Q1/src/etw_monitor.c -I Q1/include -lws2_32

Notes:
- The ETW consumer (`etw_monitor.c`) is Windows-specific and requires Administrator privileges to capture kernel providers.
- While on macOS, you can build and test the correlator and simulator: see `tools/sim_event_gen.c`.
- After successful Windows testing, place screenshots and sample logs under the `Q1/` folder for submission.
