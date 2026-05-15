@echo off
setlocal

set ROOT=%~dp0
set GCC=C:\msys64\ucrt64\bin\gcc.exe
if exist "%GCC%" (
  set CC=%GCC%
) else (
  set CC=gcc
)

if not exist "%ROOT%logs" mkdir "%ROOT%logs"

"%CC%" -O2 -Wall -Wextra -I "%ROOT%third_party\MinHook\include" -I "%ROOT%monitor" -shared -o "%ROOT%monitor.dll" ^
  "%ROOT%monitor\monitor.c" "%ROOT%monitor\hooks.c" "%ROOT%monitor\tracking.c" "%ROOT%monitor\logger.c" "%ROOT%third_party\MinHook\src\minhook_shim.c" ^
  -lws2_32 -lpsapi -ladvapi32
if errorlevel 1 exit /b %errorlevel%

"%CC%" -O2 -Wall -Wextra -I "%ROOT%injector" -o "%ROOT%injector.exe" "%ROOT%injector\injector.c"
exit /b %errorlevel%