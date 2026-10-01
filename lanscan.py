#!/usr/bin/env python3
"""Simple LAN scanner: ping sweep + ARP table + hostnames.

    python3 lanscan.py                 # your /24
    python3 lanscan.py 192.168.1.0/24

Hostnames, first hit wins:
  dns     - your system resolver
  router  - PTR query straight to the gateway (DHCP names)
  mdns    - asks the device itself on 5353 (Linux/avahi, Apple, Android, printers)
  netbios - asks the device itself on 137 (Windows, Samba)
"""
import ipaddress
import random
import socket
import struct
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

TIMEOUT = 1.0


def my_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("10.255.255.255", 1))  # sends nothing, just picks the interface
    ip = s.getsockname()[0]
    s.close()
    return ip


def gateway():
    with open("/proc/net/route") as f:
        for line in f:
            p = line.split()
            if p[1] == "00000000" and p[2] != "00000000":
                return socket.inet_ntoa(struct.pack("<I", int(p[2], 16)))
    return None


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


# ---------------------------------------------------------------- name lookups
def udp(server, port, packet):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(TIMEOUT)
    try:
        s.sendto(packet, (server, port))
        return s.recv(4096)
    except OSError:
        return None
    finally:
        s.close()


def read_name(buf, off):
    """Decode a DNS name (with compression). Returns (name, offset after it)."""
    labels, end = [], None
    while buf[off]:
        if buf[off] >= 0xC0:                       # pointer
            end = end or off + 2
            off = ((buf[off] & 0x3F) << 8) | buf[off + 1]
            continue
        labels.append(buf[off + 1:off + 1 + buf[off]].decode(errors="replace"))
        off += 1 + buf[off]
    return ".".join(labels), end or off + 1


def ptr_query(ip, server, port):
    """Reverse lookup of `ip`, asked to `server` (DNS on 53, mDNS on 5353)."""
    qname = b"".join(bytes([len(p)]) + p.encode()
                     for p in ip.split(".")[::-1] + ["in-addr", "arpa"]) + b"\0"
    pkt = struct.pack(">6H", random.getrandbits(16), 0x0100, 1, 0, 0, 0) + qname + b"\0\x0c\0\x01"
    data = udp(server, port, pkt)
    if not data:
        return None
    try:
        qd, an = struct.unpack(">HH", data[4:8])
        off = 12
        for _ in range(qd):
            off = read_name(data, off)[1] + 4
        for _ in range(an):
            off = read_name(data, off)[1]
            rtype, _, _, rdlen = struct.unpack(">HHIH", data[off:off + 10])
            off += 10
            if rtype == 12:                        # PTR
                return read_name(data, off)[0].removesuffix(".local") or None
            off += rdlen
    except (IndexError, struct.error):
        pass
    return None


def netbios(ip):
    pkt = struct.pack(">6H", random.getrandbits(16), 0, 1, 0, 0, 0) \
        + b"\x20" + b"CK" + b"A" * 30 + b"\0" + b"\0\x21\0\x01"
    data = udp(ip, 137, pkt)
    if not data or len(data) < 57:
        return None
    try:
        off = 56                                   # header + name + rr fields
        for i in range(data[off]):
            e = off + 1 + i * 18
            name, suffix, flags = data[e:e + 15], data[e + 15], data[e + 16]
            if suffix == 0 and not flags & 0x80:   # unique workstation name
                return name.decode(errors="replace").strip()
    except IndexError:
        pass
    return None


def hostname(ip, gw):
    try:
        name = socket.gethostbyaddr(ip)[0]
        if name != ip:
            return name, "dns"
    except OSError:
        pass
    if gw:
        name = ptr_query(ip, gw, 53)
        if name:
            return name, "router"
    name = ptr_query(ip, ip, 5353)
    if name:
        return name, "mdns"
    name = netbios(ip)
    if name:
        return name, "netbios"
    return "-", ""


# ------------------------------------------------------------------------ main
def main():
    me, gw = my_ip(), gateway()
    target = sys.argv[1] if len(sys.argv) > 1 else me + "/24"
    if "/" not in target:
        target += "/24"
    net = ipaddress.ip_network(target, strict=False)
    hosts = [str(h) for h in net.hosts()]

    print(f"Scanning {net}...")
    with ThreadPoolExecutor(64) as ex:
        alive = {ip for ip, ok in zip(hosts, ex.map(ping, hosts)) if ok}

    arp = {ip: mac for ip, mac in arp_table().items() if ipaddress.ip_address(ip) in net}
    found = alive | set(arp)
    if ipaddress.ip_address(me) in net:
        found.add(me)
    found = sorted(found, key=ipaddress.ip_address)

    print(f"{len(found)} hosts up, resolving names...")
    with ThreadPoolExecutor(32) as ex:
        names = list(ex.map(lambda ip: hostname(ip, gw), found))

    print(f"\n{'IP':<16}{'MAC':<19}{'HOSTNAME':<32}VIA")
    for ip, (name, via) in zip(found, names):
        if ip == me:
            name, via = socket.gethostname(), "this host"
        print(f"{ip:<16}{arp.get(ip, '-'):<19}{name:<32}{via}")
    named = sum(n != "-" for n, _ in names)
    print(f"\n{len(found)} devices, {named} named")


if __name__ == "__main__":
    main()
