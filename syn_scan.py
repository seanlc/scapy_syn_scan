# usage syn_scan lowPort highPort

import sys
from scapy.all import *
import threading

def scan_port(prt):
    pkt = IP(dst="scanme.nmap.org")/TCP(dport = prt, flags="S")
    res = sr1(pkt)
    respFlags = int(res[TCP].flags)
    if respFlags == 18:
        openPorts.append(prt)

lowPrt = int(sys.argv[1])
highPrt = int(sys.argv[2])
openPorts = []

for i in range(lowPrt, highPrt + 1):
    scan_port(i)

for prt in openPorts:
    print("%s is open" % prt)
