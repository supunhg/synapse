#!/usr/bin/env python3
"""
Correlate Procmon CSV export with network events to find file uploads.

Usage:
  1. Run Procmon (ProcMon.exe) as Administrator.
  2. Start capture, reproduce the upload, stop capture.
  3. File -> Save -> All events -> CSV -> save as procmon.csv
  4. Run: python correlate_procmon.py procmon.csv > upload_log.txt

This script looks for file read/write events and TCP connect/send events
and correlates them by PID and timestamp proximity (5 seconds default).
"""
import csv
import sys
import re
from datetime import datetime, timedelta

if len(sys.argv) < 2:
    print("Usage: correlate_procmon.py procmon.csv")
    sys.exit(1)

FNAME = sys.argv[1]
TIME_FMT = "%H:%M:%S.%f"
WINDOW = timedelta(seconds=5)

file_events = []  # (time, pid, process, path)
net_events = []   # (time, pid, process, remote)

ip_port_re = re.compile(r"Remote Address:\s*([0-9\.]+):([0-9]+)")

with open(FNAME, newline='', encoding='utf-8', errors='replace') as f:
    reader = csv.DictReader(f)
    for row in reader:
        tod = row.get('Time of Day') or row.get('Time') or row.get('Time of Day (UTC)')
        proc = row.get('Process Name') or row.get('Process')
        pid = row.get('PID') or row.get('ProcessId')
        op = row.get('Operation') or row.get('Op')
        path = row.get('Path') or row.get('Detail') or ''
        detail = row.get('Detail') or ''
        try:
            t = datetime.strptime(tod, TIME_FMT)
        except Exception:
            # Some Procmon variants include date; try splitting
            try:
                t = datetime.strptime(tod.split()[1], TIME_FMT)
            except Exception:
                continue
        try:
            pid_i = int(pid)
        except Exception:
            pid_i = 0

        if op and ('ReadFile' in op or 'WriteFile' in op or 'CreateFile' in op or 'CloseFile' in op):
            file_events.append((t, pid_i, proc, path))
        elif op and ('TCP' in op or 'Send' in op or 'Connect' in op or 'UDP' in op):
            # try to extract remote address from Detail
            m = ip_port_re.search(detail)
            remote = None
            if m:
                remote = f"{m.group(1)}:{m.group(2)}"
            else:
                # sometimes Path contains remote info
                m2 = re.search(r'([0-9\.]+):([0-9]+)', detail or path)
                if m2:
                    remote = f"{m2.group(1)}:{m2.group(2)}"
            net_events.append((t, pid_i, proc, remote))

# correlate
out_lines = []
for nt, npid, nproc, remote in net_events:
    if remote is None:
        continue
    # find closest file event with same pid within WINDOW
    candidate = None
    best_dt = WINDOW
    for ft, fpid, fproc, fpath in file_events:
        if fpid != npid:
            continue
        dt = abs(nt - ft)
        if dt <= best_dt:
            best_dt = dt
            candidate = (ft, fpid, fproc, fpath)
    if candidate:
        ft, fpid, fproc, fpath = candidate
        ts = nt.strftime('%Y-%m-%d %H:%M:%S')
        out_lines.append(f"{ts}\tPID:{npid}\tTCP\t{remote}\tProcess:{nproc}\tDetectedFile:{fpath}")

for l in out_lines:
    print(l)
