#!/bin/env python3

from scapy.all import *
import sys
from datetime import datetime
import socket
import os

from packets import *
from appsettings import *

RED = '\33[31m'
CYAN = '\33[36m'
GREEN = '\33[32m'
WHITE = '\33[0m'

# Init objects
Settings = AppSettings()
Packets = Packets()

# Versioning
__version__ = "0.1"

# Generic timestamp for local logging
timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())

def print_banner():
    print(f"\n{CYAN}==================================================\n")
    print(f"{WHITE} TRIPWIRE {CYAN}- a portscan honeypot({WHITE}v{__version__}{CYAN})")
    print(f"{CYAN} listening on",Settings.iface ,Settings.listening_ip ,Settings.listening_tcp_ports, Settings.listening_udp_ports)
    print(f"\n=================================================={WHITE} \n")

while True:
 try:
  os.system('clear')
  print_banner()
  sniffer = sniff(lfilter=Packets.build_lfilter, count=0, prn=Packets.parse_packet, iface=Settings.iface)
  # If we Ctrl-C, then exit
  sys.exit()
 except socket.error:
  print('This script must be run as root / Administrator.  Exiting...')
  sys.exit() 
