ETW-Based Upload Monitor - Q2 & Q3 Deliverable
=================================================

This folder contains the Windows Service deliverable for auto-start monitoring.
Standalone monitor source remains in Q1/. This README describes compilation, usage, and service installation.

============================================
Q2: STANDALONE EXECUTABLE (Manual Monitoring)
============================================

COMPILATION (on Windows with Administrator privileges):

MSVC (Visual Studio Developer Command Prompt):
  cd /path/to/synapse
  cl /nologo /W3 /Fe:etw_monitor.exe Q1\src\etw_monitor.c /I Q1\include advapi32.lib ws2_32.lib iphlpapi.lib

MinGW:
  cd /path/to/synapse
  gcc -O2 -o etw_monitor.exe Q1/src/etw_monitor.c -I Q1/include -ladvapi32 -lws2_32 -liphlpapi

RUN (requires Administrator privileges):
  .\etw_monitor.exe

OUTPUT:
- Prints detected file uploads to console (stdout)
- Writes to log file: upload_log.txt
- Format: Tab-separated with timestamp, PID, local/remote IP:port, process, file path, bytes

============================================
Q3: WINDOWS SERVICE (Auto-start at reboot)
============================================

This is the recommended deployment method for continuous monitoring without user interaction.

INSTALLATION:

Option 1: Using the batch script (recommended)
  1. Open Command Prompt as Administrator
  2. Navigate to the synapse directory
  3. Run: install_service.bat
     This will:
     - Compile etw_service.exe
     - Install as Windows Service named "SynapseUploadMonitor"
     - Configure to auto-start at system reboot

Option 2: Manual compilation and installation
  1. Compile:
    cl /nologo /W3 /Fe:etw_service.exe Q2\src\etw_service.c /I Q2\include advapi32.lib ws2_32.lib iphlpapi.lib
  
  2. Install service (requires Admin):
     etw_service.exe install
  
  3. Start service immediately:
     net start SynapseUploadMonitor

VERIFICATION:

Check service status:
  sc query SynapseUploadMonitor
  
Or use Services Manager:
  Press Win+R, type: services.msc
  Look for "Synapse Upload Monitor"

VIEW LOGS:

Monitor logs are written to:
  upload_log.txt (in the same directory where service is running)
  service_debug.log (debug information)

UNINSTALLATION:

Option 1: Using batch script
  uninstall_service.bat

Option 2: Manual
  1. Stop service:
     net stop SynapseUploadMonitor
  
  2. Uninstall:
     etw_service.exe uninstall

SERVICE BEHAVIOR:

- Automatically starts when Windows boots
- Runs continuously in background (no user interaction needed)
- Logs all detected file uploads to upload_log.txt
- Can be stopped via Services Manager or: net stop SynapseUploadMonitor
- Can be restarted via Services Manager or: net start SynapseUploadMonitor

LOG FORMAT:

  YYYY-MM-DD HH:MM:SS	PID:12345	TCP	LOCAL_IP:PORT	REMOTE_IP:PORT	Process:app.exe	DetectedFile:path (size)

EXAMPLE:
  2025-12-09 08:47:20	PID:18376	TCP	13.107.11.10:49730	165.22.221.132:443	Process:firefox.exe	DetectedFile:C:\Users\Lanka\AppData\Local\Temp (30MB)

REQUIREMENTS:

- Windows 10 or later
- Administrator privileges (for installation and ETW kernel provider access)
- Latest Windows SDK headers (evntrace.h, evntcons.h)

See Q1/sample_logs/ for example output.
