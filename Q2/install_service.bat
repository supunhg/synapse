@echo off
REM Install ETW Upload Monitor as Windows Service
REM Run as Administrator

echo Installing Synapse Upload Monitor Service...
echo.
echo Step 1: Compiling etw_service.c
echo.

REM Compile the service
cl /nologo /W3 /Fe:etw_service.exe Q1\src\etw_service.c /I Q1\include

if %ERRORLEVEL% NEQ 0 (
    echo Compilation failed!
    echo Make sure you're running this from the synapse directory in Visual Studio Command Prompt.
    pause
    exit /b 1
)

echo.
echo Step 2: Installing service (requires Administrator)
echo.

REM Install the service
etw_service.exe install

if %ERRORLEVEL% NEQ 0 (
    echo Installation failed!
    echo Make sure you're running as Administrator.
    pause
    exit /b 1
)

echo.
echo Step 3: Verifying service installation
echo.

REM Verify service
sc query SynapseUploadMonitor

echo.
echo Service installed successfully!
echo The service will start automatically at the next system reboot.
echo.
echo To start the service now, run:
echo   net start SynapseUploadMonitor
echo.
echo To view logs, check upload_log.txt in the current directory.
echo.
pause
