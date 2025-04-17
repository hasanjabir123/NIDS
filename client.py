#!/usr/bin/env python3

import os
import platform
import sys
import socket
import selectors
import types
import psutil
import re
import uuid

sel = selectors.DefaultSelector()
messages = [b"Message 1 from client.", b"Message 2 from client."]

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

def getSystem():
    output = "NAME,DETAILS\n"
    output += f"platform,{platform.system()}\n"
    output += f"platform-release,{platform.release()}\n"
    output += f"platform-version,{platform.version()}\n"
    output += f"architecture,{platform.machine()}\n"
    output += f"hostname,{socket.gethostname()}\n"
    output += f"ip-address,{socket.gethostbyname(socket.gethostname())}\n"
    output += f"mac-address,{':'.join(re.findall('..', '%012x' % uuid.getnode()))}\n"
    output += f"processor,{platform.processor().replace(',', ' ')}\n"
    output += f"ram,{round(psutil.virtual_memory().total / (1024.0 ** 3))}GB\n"
    return output

def getWinSystem():
    return os.popen('wmic computersystem list full /format:Textvaluelist').read()

def getWinProcess():
    return os.popen('wmic process get description, processid /format:csv').read()

def getWinConnection():
    return os.popen('netstat -an').read()

def os_info():
    return platform.system()

def cpu_info():
    if platform.system() == 'Windows':
        return platform.processor()
    elif platform.system() == 'Darwin':
        command = '/usr/sbin/sysctl -n machdep.cpu.brand_string'
        return os.popen(command).read().strip()
    elif platform.system() == 'Linux':
        command = 'cat /proc/cpuinfo'
        return os.popen(command).read().strip()
    return 'platform not identified'

def start_connections(host, port, num_conns, sysData):
    server_addr = (host, port)
    for i in range(num_conns):
        connid = i + 1
        print("Starting connection", connid, "to", server_addr)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)
        sock.connect_ex(server_addr)
        events = selectors.EVENT_READ | selectors.EVENT_WRITE
        data = types.SimpleNamespace(
            connid=connid,
            msg_total=sum(len(m) for m in sysData),
            recv_total=0,
            messages=list(sysData),
            outb=b"",
        )
        sel.register(sock, events, data=data)

def service_connection(key, mask):
    sock = key.fileobj
    data = key.data
    if mask & selectors.EVENT_READ:
        recv_data = sock.recv(1024)  # Should be ready to read
        if recv_data:
            print("Received", repr(recv_data), "from connection", data.connid)
            data.recv_total += len(recv_data)
        if not recv_data or data.recv_total == data.msg_total:
            print("Closing connection", data.connid)
            sel.unregister(sock)
            sock.close()
    if mask & selectors.EVENT_WRITE:
        if not data.outb and data.messages:
            data.outb = data.messages.pop(0)
        if data.outb:
            print("Sending", repr(data.outb), "to connection", data.connid)
            sent = sock.send(data.outb)  # Should be ready to write
            data.outb = data.outb[sent:]

if len(sys.argv) != 4:
    print("Usage:", sys.argv[0], "<host> <port> <num_connections>")
    sys.exit(1)

host, port = sys.argv[1:3]
host = socket.gethostbyname(host)
hostname = socket.gethostname()

myMessages = [
    f"SYSINFO,{hostname},{host},{port}~`~`~`~`~`\n".encode(),
    getSystem().encode()
]
start_connections(host, int(port), 1, myMessages)

myMessages = [
    f"PROINFO,{hostname},{host},{port}~`~`~`~`~`\n".encode(),
    getProcess().encode()
]
start_connections(host, int(port), 1, myMessages)

myMessages = [
    f"NETINFO,{hostname},{host},{port}~`~`~`~`~`\n".encode(),
    getConnection().encode()
]
start_connections(host, int(port), 1, myMessages)

print(cpu_info())

try:
    while True:
        events = sel.select(timeout=1)
        if events:
            for key, mask in events:
                service_connection(key, mask)
        if not sel.get_map():  # Exit if no more monitored sockets
            break
except KeyboardInterrupt:
    print("Caught keyboard interrupt, exiting")
finally:
    sel.close()
