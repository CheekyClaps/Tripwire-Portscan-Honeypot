from scapy.all import *
from appsettings import *
from ntfy import *

Settings = AppSettings()

class Packets:

    ## Dictionary mapping of TCP flags 
    def get_tcp_flags(self, flags):
        tcp_flag_mapping = {
            '': 'TCP NULL',
            'A': 'TCP ACK',
            'CRW': 'TCP CRW',
            'ECE': 'TCP ECE-Echo',
            'F': 'TCP FIN',
            'FPU': 'TCP FPU',
            'PSH': 'TCP PSH',
            'RST': 'TCP RST',
            'S': 'TCP SYN', 
            'SEC': 'TCP SEC',
            'URG': 'TCP URG',
            ('URG', 'PSH', 'F'): 'XMAS',
            ('URG', 'PSH', 'F', 'A'): 'XMAS',
            ('S', 'F'): 'SYN/FIN',
            ('F', 'A'): 'FIN/ACK',
            ('SEC', 'S', 'S'): 'CONN',
            ('URG', 'PSH', 'A', 'RST', 'S', 'F'): 'ALL-FLAGS'
        } 
        return tcp_flag_mapping.get(flags)

    ## Dictionary mapping of ICMP Codes
    def get_icmp_codes(self, code):
        icmp_codes_mapping = { 
           (0, 0): 'ICMP Echo Reply (Ping Reply)',
            # Types 1 and 2 are reserved
            (3, 0): 'Destination network unreachable',
            (3, 1): 'Destination host unreachable',
            (3, 2): 'Desination protocol unreachable',
            (3, 3): 'Destination port unreachable',
            (3, 4): 'Fragmentation required, Don\'t Fragment (DF) Flag Set',
            (3, 5): 'Source route failed',
            (3, 6): 'Destination network unknown',
            (3, 7): 'Destination host unknown',
            (3, 8): 'Source host isolated',
            (3, 9): 'Network administratively prohibited',
            (3, 10): 'Host administratively prohibited',
            (3, 11): 'Network unreachable for TOS',
            (3, 12): 'Host unreachable for TOS',
            (3, 13): 'Communication administratively prohibited',
            (3, 14): 'Host Precedence Violation',
            (3, 15): 'Precendence cutoff in effect',
            # Code (4, 0) is deprecated
            (5, 0): 'Redirect Datagram for the Network',
            (5, 1): 'Redirect Datagram for the Host',
            (5, 2): 'Redirect Datagram for the TOS and network',
            (5, 3): 'Redirect Datagram for the TOS and host',
            # Type 6 is deprecated
            # Type 7 is reserved
            (8, 0): 'Echo / Ping Request',
            (9, 0): 'Router advertisement',
            (10, 0): 'Router discovery / selection / solicitation',
            (11, 0): 'TTL expired in transit',
            (11, 1): 'Fragment reassembly time exceeded',
            (12, 0): 'Bad IP Header',
            (12, 1): 'Bad IP Header: Missing a required option',
            (12, 2): 'Bad IP Header: Bad length',
            (13, 0): 'Timestamp',
            (14, 0): 'Timestamp Reply'
            # The rest are deprecated, reserved, or experiemental
        }
        return icmp_codes_mapping.get(code, 'unknown')

    ## Packet filter - check if packets are tcp, udp or that the belong to out defined ports
    def build_lfilter(self, pkt):
        if IP in pkt:
            if not Settings.debug and pkt[IP].src == Settings.listening_ip:
                return False
            elif Settings.debug and pkt[IP].src == Settings.listening_ip: 
                return True
        elif ARP in pkt:
            if pkt[ARP].pdst in Settings.listening_ip:
                return True
            elif pkt[ARP].psrc in Settings.listening_ip:
                return True
        elif TCP in pkt:
            if pkt[TCP].dport and pkt[TCP].dport in Settings.listening_tcp_ports:
                return True
            elif pkt[TCP].sport and pkt[TCP].sport in Settings.listening_tcp_ports:
                return True
        elif UDP in pkt:
            if pkt[UDP].dport and pkt[UDP].dport in Settings.listening_udp_ports:
                return True
            elif pkt[UDP].sport and pkt[UDP].sport in Settings.listening_udp_ports:
                return True
        elif ICMP in pkt:
            return True
        else:
            return False

    ## Packet parser - So if its all still holds True then analyse packets
    def parse_packet(self, pkt):
        if IP in pkt:
            sourceAddr = pkt[IP].src
            destAddr = pkt[IP].dst
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        elif ARP in pkt:
            sourceAddr = pkt[ARP].psrc
            destAddr = pkt[ARP].pdst
            print('[{0}] [ARP] {1} -> {3}'.format(timestamp, sourceAddr, destAddr))
        elif TCP in pkt:
            sourcePort = pkt[TCP].sport
            destPort = pkt[TCP].dport
            flags = self.get_tcp_flags(str(pkt[TCP].flags))
            print('[{0}] [TCP] {1}:{2} -> {3}:{4} - {5}'.format(timestamp, sourceAddr, sourcePort, destAddr, destPort, flags))
        elif UDP in pkt:
            sourcePort = pkt[UDP].sport
            destPort = pkt[UDP].dport
            print('[{0}] [UDP] {1}:{2} -> {3}:{4}'.format(timestamp, sourceAddr, sourcePort, destAddr, destPort))
        elif ICMP in pkt:
            type = pkt[ICMP].type
            code = pkt[ICMP].code
            icmp_codes = self.get_icmp_codes((type, code))
            print('[{0}] [ICMP Type {1}, Code {2}: {3}] {4} -> {5}'.format(timestamp, type, code, 
            icmp_codes if icmp_codes else '',
                sourceAddr, destAddr))
        else:
            pkt.summary
            print('Packet not an IP packet')
            return
        return
