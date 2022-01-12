import argparse
import sys
import ipaddress
from scapy.all import sr1
from scapy.layers.inet import TCP, UDP, ICMP, IP, RandShort
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from scapy.layers.dns import DNS, DNSQR
from time import perf_counter
import ipwhois


def get_whois(ip):
    return ipwhois.IPWhois(ip).lookup_whois()['asn']


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('ip', type=str, help='IP address')
    parser.add_argument('protocol', type=str, help='tcp/udp/icmp protocol')
    parser.add_argument('-t', type=float, default=2, help='timeout for answer')
    parser.add_argument('-p', type=int, help='port (for tcp or udp)')
    parser.add_argument('-n', type=int, default=30, help='max number of requests')
    parser.add_argument('-v', action='store_true', help='display the autonomous system number for each ip address')
    args = parser.parse_args()
    return args.ip, args.protocol, args.t, args.p, args.n, args.v


def check_ip(ip):
    try:
        correct_ip = ipaddress.ip_address(ip)
    except ValueError:
        print('Invalid IP')
        sys.exit(-1)


def check_protocol(protocol):
    if protocol not in ['tcp', 'udp', 'icmp']:
        print('Protocol should be one of the list: tcp, udp, icmp')
        sys.exit(-2)


def check_timeout(timeout):
    if timeout <= 0:
        print('Timeout should be positive')
        sys.exit(-3)


def check_port(port, protocol):
    if protocol == 'icmp':
        return
    if port is None:
        print('Missing port for tcp/udp')
        sys.exit(-4)
    if port < 0 or port > 65535:
        print('Port should be in range (0, 65535)')
        sys.exit(-5)


def check_requests_num(num):
    if num <= 0:
        print('Number of requests should be positive')
        sys.exit(-6)


def check_args(ip, protocol, timeout, port, requests_num):
    check_ip(ip)
    check_protocol(protocol)
    check_timeout(timeout)
    check_port(port, protocol)
    check_requests_num(requests_num)


def traceroute(ip, protocol, timeout, request_num, port, verbose):
    if protocol == 'tcp':
        transport_part = TCP(dport=port)
    elif protocol == 'udp':
        transport_part = UDP(dport=port) / DNS(rd=1, qd=DNSQR(qname='python.org'))
    else:
        if ':' not in ip:
            transport_part = ICMP()
        else:
            transport_part = ICMPv6EchoRequest()

    current_ttl = 1
    while current_ttl < request_num + 1:
        if ':' in ip:
            package = IPv6(dst=ip, ttl=current_ttl, id=RandShort()) / transport_part
        else:
            package = IP(dst=ip, ttl=current_ttl, id=RandShort()) / transport_part
        start_time = perf_counter()
        answer = sr1(package, timeout=timeout, verbose=0)
        total_time = str(round(perf_counter() - start_time, 3)) + 'ms'
        if not answer:
            print(f'{str(current_ttl).ljust(6)} *')
        else:
            if verbose:
                whois = get_whois(answer.src) if current_ttl != 1 else 'local'
                print(f'{str(current_ttl).ljust(6)} {answer.src.ljust(18)} {total_time.ljust(10)} {whois}')
            else:
                print(f'{str(current_ttl).ljust(6)} {answer.src.ljust(18)} {total_time.ljust(10)}')
            if answer.src == ip:
                break
        current_ttl += 1


def main():
    ip, protocol, timeout, port, requests_num, verbose = get_args()
    check_args(ip, protocol, timeout, port, requests_num)
    traceroute(ip, protocol, timeout, requests_num, port, verbose)


if __name__ == '__main__':
    main()
