#!/usr/bin/env python3

import os
import csv
import psutil
import socket
import datetime
import platform
import re
import uuid

# Define risk levels for suspicious processes
MALICIOUS_PROCESSES = {
    "cmd.exe": "high",
    "powershell.exe": "high",
    "taskmgr.exe": "low",
    "winlogon.exe": "medium",
    "svchost.exe": "medium",
    "explorer.exe": "low",
    "rundll32.exe": "high",
    "regsvr32.exe": "high",
    "lsass.exe": "critical",
    "wmiprvse.exe": "medium",
    "python.exe": "low",
}

# Get current timestamp
timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

# Define filenames
process_risk_csv = f"process_risk_{timestamp}.csv"
server_analysis_csv = f"server_analysis_{timestamp}.csv"
only_risk_csv = f"only_risk_{timestamp}.csv"

# Step 1: Convert .xyz files to .csv
mypath = os.getcwd()
files = os.listdir(mypath)
for f in files:
    if f.endswith(".xyz"):
        with open(f, "r") as fx:
            lines = fx.readlines()
        
        if not lines:
            continue
        
        data = lines[0].strip().split(",")
        mytype, myname = data[0], data[1]
        new_filename = f"{mytype}-{timestamp}-{myname}.csv"
        
        with open(new_filename, "w") as new_file:
            for line in lines:
                new_file.write(line)
        
        os.remove(f)

# Step 2: Analyze running processes
process_data = []
malicious_count = 0

for proc in psutil.process_iter(attrs=['pid', 'name', 'cpu_percent', 'memory_percent']):
    try:
        pname = proc.info['name'].lower()
        risk_level = MALICIOUS_PROCESSES.get(pname, "unknown")
        process_data.append([proc.info['pid'], pname, proc.info['cpu_percent'], proc.info['memory_percent'], risk_level])
        
        if risk_level in ["high", "critical"]:
            malicious_count += 1
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        continue

# Write process risk levels to CSV
with open(process_risk_csv, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["PID", "Process Name", "CPU Usage (%)", "Memory Usage (%)", "Risk Level"])
    writer.writerows(process_data)

print(f"Process risk analysis saved to {process_risk_csv}")

# Step 3: Extract only malicious processes to a separate CSV
filtered_data = [row for row in process_data if row[4] in ["low", "medium", "high", "critical"]]

with open(only_risk_csv, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["PID", "Process Name", "CPU Usage (%)", "Memory Usage (%)", "Risk Level"])
    writer.writerows(filtered_data)

print(f"Filtered risk data saved to {only_risk_csv}")

# Step 4: Determine if the server is performing malicious activity
is_malicious = "Yes" if malicious_count > 2 else "No"

server_data = [
    ["Hostname", socket.gethostname()],
    ["IP Address", socket.gethostbyname(socket.gethostname())],
    ["Open Ports", len(psutil.net_connections(kind='inet'))],
    ["Malicious Processes Count", malicious_count],
    ["Server Malicious Activity", is_malicious]
]

with open(server_analysis_csv, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerows(server_data)

print(f"Server analysis saved to {server_analysis_csv}")

# Step 5: Gather additional system information
def getSystem():
    return f"platform,{platform.system()}\n" \
           f"platform-release,{platform.release()}\n" \
           f"platform-version,{platform.version()}\n" \
           f"architecture,{platform.machine()}\n" \
           f"hostname,{socket.gethostname()}\n" \
           f"ip-address,{socket.gethostbyname(socket.gethostname())}\n" \
           f"mac-address,{':'.join(re.findall('..', '%012x' % uuid.getnode()))}\n" \
           f"processor,{platform.processor().replace(',', ' ')}\n" \
           f"ram,{round(psutil.virtual_memory().total / (1024.0 ** 3))}GB\n"

def getProcess():
    output = "PROCESSID, PROCESSNAME, STATUS, STARTTIME\n"
    for proc in psutil.process_iter():
        try:
            output += f"{proc.pid},{proc.name()},{proc.status()},{proc.create_time()}\n"
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return output

def getConnection():
    output = "PROCESSID, STATUS, LOCALIP, LOCALPORT, REMOTEIP, REMOTEPORT\n"
    for cons in psutil.net_connections(kind='inet'):
        try:
            remote_ip = cons.raddr.ip if cons.raddr else ""
            remote_port = cons.raddr.port if cons.raddr else ""
            output += f"{cons.pid},{cons.status},{cons.laddr.ip},{cons.laddr.port},{remote_ip},{remote_port}\n"
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return output

print(getSystem())
print(getProcess())
print(getConnection())
