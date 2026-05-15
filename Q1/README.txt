API-hooked upload monitor for Windows
=====================================

Q1 now uses a DLL injected into the target process. The DLL hooks `CreateFileW`, `ReadFile`, `connect`, `send`, `WSASend`, and `closesocket` through the vendor MinHook-compatible layer in `third_party/MinHook`.

Build
-----

MSYS2 UCRT64 / MinGW:

```bat
cd Q1
build.bat
```

Manual commands:

```bat
set PATH=C:\msys64\ucrt64\bin;%PATH%
gcc -O2 -Wall -Wextra -I third_party\MinHook\include -I monitor -shared -o monitor.dll monitor\monitor.c monitor\hooks.c monitor\tracking.c monitor\logger.c third_party\MinHook\src\minhook_shim.c -lws2_32 -lpsapi -ladvapi32
gcc -O2 -Wall -Wextra -I injector -o injector.exe injector\injector.c
```

Run
---

1. Start a target process that reads a file and uploads data.
2. Inject the monitor DLL:

```bat
cd Q1
injector.exe chrome.exe C:\Users\Windows\Documents\github\synapse\Q1\monitor.dll
```

3. Review `Q1\logs\uploads.log` and debugger output.

Expected output
--------------

```text
[hook] CreateFileW process=chrome.exe handle=0x00000000000003F4 file=C:\temp\sample.bin access=0x80000000
[hook] ReadFile process=chrome.exe handle=0x00000000000003F4 bytes=4096
[hook] connect process=chrome.exe socket=0x00000000000001B8 remote=93.184.216.34:443
[hook] send process=chrome.exe socket=0x00000000000001B8 bytes=4096
[upload] timestamp=2026-05-15 14:22:31.123 pid=1234 process=chrome.exe remote=93.184.216.34:443 file=C:\temp\sample.bin bytes=4096
```

Notes
-----

- Correlation triggers when the same process reads a file and performs `send()`/`WSASend()` within five seconds.
- Socket endpoints are resolved using `getpeername()` and `inet_ntop()`.
- Logs are written to `logs\uploads.log` next to the injected DLL.
