import pync

class Alarm:

    def tcp_alert_handler(srcIP, dstIP, timestamp, srcPort, dstPort, flags):
        print('[{0}] [{1}] {2}:{3} -> {4}:{5} - {6}'.format(timestamp, pktType, srcIP, srcPort, dstIP, dstPort, flags if flags else ''))
        pync.notify( 'TCP port tripped, possible scan detected!', title='Tripwire')

    def udp_alert_handler(pkt, srcIP, dstIP, timestamp):
        print('[{0}] [{1}] {2}:{3} -> {4}:{5} - {6}'.format(timestamp, pktType, srcIP, srcPort, dstIP, dstPort, flags if flags else ''))
        pync.notify( 'UDP port tripped, possible scan detected!', title='Tripwire')

    def icmp_alert_handler(srcIP, dstIP, timestamp, icmpType, icmpCode, icmpInfo):
        print('[{0}] [{1}] [Type {2}, Code {3}: {4}] {5} -> {6}'.format(timestamp, pktType, icmpType, icmpCode, icmpInfo if icmpInfo else '', srcIP, dstIP))
        pync.notify( 'ICMP - {icmpInfo} possible scan detected!', title='Tripwire')

    def arp_alert_handler(timestamp, sourceAddr, destAddr):
        print('[{0}] [ARP] {1} -> {2}'.format(timestamp, sourceAddr, destAddr))

    #def __log():
