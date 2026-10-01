#!/usr/bin/env python3
"""Simple LAN scanner: ping sweep + ARP table + reverse DNS.

    python3 lanscan.py                 # your /24
    python3 lanscan.py 192.168.1.0/24
"""
import ipaddress
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor


def my_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("10.255.255.255", 1))  # sends nothing, just picks the interface
    ip = s.getsockname()[0]
    s.close()
    return ip


def ping(ip):
    r = subprocess.run(["ping", "-c", "1", "-W", "1", ip],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return r.returncode == 0


def arp_table():
    # pinging fills the ARP table even for hosts that block ping
    table = {}
    with open("/proc/net/arp") as f:
        next(f)
        for line in f:
            ip, _, flags, mac = line.split()[:4]
            if flags != "0x0":
                table[ip] = mac
    return table


def hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return "-"


def main():
    me = my_ip()
    target = sys.argv[1] if len(sys.argv) > 1 else me + "/24"
    if "/" not in target:
        target += "/24"
    net = ipaddress.ip_network(target, strict=False)
    hosts = [str(h) for h in net.hosts()]

    print(f"Scanning {net}...")
    with ThreadPoolExecutor(64) as ex:
        alive = {ip for ip, ok in zip(hosts, ex.map(ping, hosts)) if ok}

    arp = {ip: mac for ip, mac in arp_table().items() if ipaddress.ip_address(ip) in net}
    found = sorted(alive | set(arp) | ({me} if ipaddress.ip_address(me) in net else set()),
                   key=ipaddress.ip_address)

    with ThreadPoolExecutor(32) as ex:
        names = list(ex.map(hostname, found))

    print(f"\n{'IP':<16}{'MAC':<19}HOSTNAME")
    for ip, name in zip(found, names):
        mac = arp.get(ip, "(this host)" if ip == me else "-")
        print(f"{ip:<16}{mac:<19}{socket.gethostname() if ip == me else name}")
    print(f"\n{len(found)} devices")


if __name__ == "__main__":
    main()
