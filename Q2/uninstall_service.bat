@echo off
REM Uninstall ETW Upload Monitor Windows Service
REM Run as Administrator

echo Uninstalling Synapse Upload Monitor Service...
echo.
echo Step 1: Stopping service
echo.

net stop SynapseUploadMonitor

echo.
echo Step 2: Uninstalling service (requires Administrator)
echo.

REM Uninstall the service
etw_service.exe uninstall

if %ERRORLEVEL% NEQ 0 (
    echo Uninstallation failed!
    echo Make sure you're running as Administrator.
    pause
    exit /b 1
)

echo.
echo Step 3: Verifying removal
echo.

sc query SynapseUploadMonitor

echo.
echo Service uninstalled successfully!
echo.
pause
