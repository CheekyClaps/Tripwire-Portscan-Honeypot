import pync

class Alarm:

    def tcp_alert_handler(self, srcIP, dstIP, timestamp, srcPort, dstPort, flags):
        print('[{0}] [TCP] {1}:{2} -> {3}:{4} - {5}'.format(timestamp, srcIP, srcPort, dstIP, dstPort, flags if flags else ''))
        pync.notify( 'TCP port tripped, possible scan detected!', title='Tripwire')

    def udp_alert_handler(self, pkt, srcIP, dstIP, timestamp):
        print('[{0}] [UDP] {1}:{2} -> {3}:{4} - {5}'.format(timestamp, srcIP, srcPort, dstIP, dstPort, flags if flags else ''))
        pync.notify( 'UDP port tripped, possible scan detected!', title='Tripwire')

    def icmp_alert_handler(self, srcIP, dstIP, timestamp, icmpType, icmpCode, icmpInfo):
        print('[{0}] [ICMP] [Type {1}, Code {2}: {3}] {4} -> {5}'.format(timestamp, icmpType, icmpCode, icmpInfo if icmpInfo else '', srcIP, dstIP))
        pync.notify( 'ICMP - {0} possible scan detected!'.format(icmpInfo if icmpInfo else '', srcIP, dstIP), title='Tripwire')

    def arp_alert_handler(self, timestamp, sourceAddr, destAddr):
        print('[{0}] [ARP] {1} -> {2}'.format(timestamp, sourceAddr, destAddr))

    #def __log():
