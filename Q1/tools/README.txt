Procmon correlation tool
========================

Use the following steps to produce a CSV from Procmon and run the correlator:

1. Run Procmon.exe as Administrator.
2. Start capture, reproduce the suspected upload, stop capture.
3. File -> Save -> All events -> CSV -> save as procmon.csv in Q1\tools.
4. Run:
   python correlate_procmon.py procmon.csv > upload_log.txt

The script will print probable upload events by matching recent file I/O with network events.
