from alarm import *
from appsettings import *
from scapy.all import *

# Init
Settings = AppSettings()
Alarm = Alarm()

class Packets:

    ## Dictionary mapping of TCP flags 
    def __get_tcp_flags(self, flags):
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
    def __get_icmp_codes(self, code):
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
   

    ## Packet handlers
    def __tcp_packet_handler(self, pkt, srcIP, dstIP, timestamp):
        srcPort = pkt[TCP].sport
        dstPort = pkt[TCP].dport
        flags = self.__get_tcp_flags(str(pkt[TCP].flags))
        Alarm.tcp_alert_handler(srcIP, dstIP, timestamp, srcPort, srcPort, dstPort, flags)

    def __udp_packet_handler(self, pkt, srcIP, dstIP, timestamp):
        srcPort = pkt[UDP].sport
        dstPort = pkt[UDP].dport
        Alarm.udp_alert_handler(srcIP, dstIP, timestamp, srcPort, srcPort, dstPort)

    def __icmp_packet_handler(self, pkt, srcIP, dstIP, timestamp):
        icmpType = pkt[ICMP].type
        icmpCode = pkt[ICMP].code
        icmpInfo = self.__get_icmp_codes((icmpType, icmpCode))
        Alarm.icmp_alert_handler(srcIP, dstIP, timestamp, icmpType, icmpCode, icmpInfo)

    def __arp_packet_handler(self, pkt, timestamp):
        sourceAddr = pkt[ARP].psrc
        destAddr = pkt[ARP].pdst
        Alarm.arp_alert_handler(timestamp, sourceAddr, destAddr)

    ## Packet filter
    def build_lfilter(self, pkt):
        if IP in pkt:
            if Settings.debug and pkt[IP].src == Settings.listening_ip: 
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
        elif ARP in pkt:
            if pkt[ARP].pdst in Settings.listening_ip:
                return True
            elif pkt[ARP].psrc in Settings.listening_ip:
                return True


    ## Packet parser 
    def parse_packet(self, pkt):
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        if IP in pkt:
            srcIP = pkt[IP].src
            dstIP = pkt[IP].dst
            if TCP in pkt:
                self.__tcp_packet_handler(pkt, srcIP, dstIP, timestamp)
            elif UDP in pkt:
                self.__udp_packet_handler(pkt, srcIP, dstIP, timestamp)
            elif ICMP in pkt:
                self.__icmp_packet_handler(pkt, srcIP, dstIP, timestamp)
        elif ARP in pkt:
            self.__arp_packet_handler(pkt, timestamp)
        else:
            pkt.summary
            print('Packet not an IP packet')
            return
        return

