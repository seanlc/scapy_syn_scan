# usage syn_scan lowPort highPort
from multiprocessing.pool import ThreadPool

import sys
from scapy.all import *

def scan_port(prt):
    pkt = IP(dst="scanme.nmap.org")/TCP(dport = prt, flags="S")
    res = sr1(pkt)
    respFlags = int(res[TCP].flags)
    if respFlags == 18:
        openPorts.append(prt)

def build_ports():
    for n in range(lowPrt, highPrt):
        ports.append(n)

def scan_ports():
    pool = ThreadPool()
    pool.map(scan_port, ports)

def print_open_ports():
    for prt in openPorts:
        print("%s is open" % prt)


lowPrt = int(sys.argv[1])
highPrt = int(sys.argv[2])
openPorts = []
ports = []
threads = []

build_ports()

scan_ports()

print_open_ports()
