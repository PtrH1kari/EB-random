#!/usr/bin/env python3
"""lanscan - find devices on a local network and resolve their host names.

Usage:
    python3 lanscan.py                    # auto-detect your /24
    python3 lanscan.py 192.168.1.0/24
    python3 lanscan.py 192.168.1.1        # bare IP -> its /24
    python3 lanscan.py 10.0.0.0/22 -j 256 -t 0.8

How it works (stdlib only, no root needed, Linux/macOS/Windows):
  1. Discovery: ICMP ping + parallel TCP connect probes to common ports
     (catches hosts that drop ping), then reads the OS ARP table - every
     probe triggers ARP, so even fully firewalled devices show up there.
  2. Names, first hit wins: reverse DNS (router's DHCP names) ->
     mDNS PTR query (Apple, Linux/avahi, printers, IoT) -> NetBIOS (Windows/Samba).
"""
import argparse
import errno
import ipaddress
import platform
import random
import re
import selectors
import socket
import struct
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

OS = platform.system()
PROBE_PORTS = (80, 443, 22, 445, 139, 53, 554, 8080, 62078)  # 62078 = iPhone
ALIVE_ERRS = {0, errno.ECONNREFUSED, 10061}  # refused = host is up


# ---------------------------------------------------------------- discovery
def ping(ip, timeout):
    if OS == "Windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    elif OS == "Darwin":
        cmd = ["ping", "-c", "1", "-t", str(max(1, round(timeout))), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, round(timeout))), ip]
    try:
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except (FileNotFoundError, PermissionError):
        return False
    # Windows ping returns 0 on "destination unreachable" too
    return r.returncode == 0 and (OS != "Windows" or b"TTL=" in r.stdout.upper())


def tcp_alive(ip, timeout):
    # selectors (epoll/kqueue) instead of select(): select breaks on fds > 1024
    sel, socks = selectors.DefaultSelector(), []
    try:
        for port in PROBE_PORTS:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socks.append(s)
            s.setblocking(False)
            err = s.connect_ex((ip, port))
            if err in ALIVE_ERRS:
                return True
            sel.register(s, selectors.EVENT_WRITE)
        deadline = time.monotonic() + timeout
        while sel.get_map():
            left = deadline - time.monotonic()
            if left <= 0:
                break
            events = sel.select(left)
            if not events:
                break
            for key, _ in events:
                if key.fileobj.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) in ALIVE_ERRS:
                    return True
                sel.unregister(key.fileobj)
        return False
    except OSError:
        return False
    finally:
        sel.close()
        for s in socks:
            s.close()


def probe(ip, timeout):
    return ping(ip, timeout) or tcp_alive(ip, timeout / 2)


def _norm_mac(mac):
    return ":".join(p.zfill(2) for p in re.split(r"[:-]", mac.lower()))


def read_arp():
    """Return {ip: mac} from the OS neighbour table."""
    table = {}
    try:  # Linux
        with open("/proc/net/arp") as f:
            next(f)
            for line in f:
                ip, _, flags, mac, *_ = line.split()
                if flags != "0x0":
                    table[ip] = _norm_mac(mac)
    except OSError:
        pass
    if not table:  # macOS / Windows / Linux without /proc
        try:
            out = subprocess.run(["arp", "-a"], stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL, text=True).stdout
        except FileNotFoundError:
            out = ""
        for ip, mac in re.findall(
                r"(\d+\.\d+\.\d+\.\d+)\D+?([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})", out):
            table[ip] = _norm_mac(mac)
    bad = ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00")
    return {ip: m for ip, m in table.items() if m not in bad and not m.startswith("01:00:5e")}


def local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))  # no packet is sent
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


# --------------------------------------------------------- name resolution
def _qname(name):
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"


def _read_name(buf, off):
    labels, jumped, end = [], False, off
    for _ in range(128):
        n = buf[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:
            if not jumped:
                end = off + 2
            jumped, off = True, ((n & 0x3F) << 8) | buf[off + 1]
            continue
        labels.append(buf[off + 1:off + 1 + n].decode(errors="replace"))
        off += 1 + n
    return ".".join(labels), (end if jumped else off)


def _udp_query(ip, port, pkt, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (ip, port))
        return s.recvfrom(4096)[0]
    except OSError:
        return None
    finally:
        s.close()


def mdns_name(ip, timeout):
    rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    pkt = struct.pack(">6H", random.getrandbits(16), 0, 1, 0, 0, 0) + _qname(rev) + struct.pack(">HH", 12, 1)
    data = _udp_query(ip, 5353, pkt, timeout)
    if not data or len(data) < 12:
        return None
    try:
        qd, an = struct.unpack(">HH", data[4:8])
        off = 12
        for _ in range(qd):
            off = _read_name(data, off)[1] + 4
        for _ in range(an):
            off = _read_name(data, off)[1]
            rtype, _, _, rdlen = struct.unpack(">HHIH", data[off:off + 10])
            off += 10
            if rtype == 12:
                return _read_name(data, off)[0]
            off += rdlen
    except (IndexError, struct.error):
        pass
    return None


def netbios_name(ip, timeout):
    pkt = (struct.pack(">6H", random.getrandbits(16), 0, 1, 0, 0, 0)
           + b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00" + struct.pack(">HH", 0x21, 1))
    data = _udp_query(ip, 137, pkt, timeout)
    if not data or len(data) < 57:
        return None
    try:
        off = _read_name(data, 12)[1] + 10
        count, off = data[off], off + 1
        for _ in range(count):
            name, suffix = data[off:off + 15], data[off + 15]
            flags = struct.unpack(">H", data[off + 16:off + 18])[0]
            if suffix == 0x00 and not flags & 0x8000:  # unique workstation name
                return name.decode(errors="replace").strip()
            off += 18
    except (IndexError, struct.error):
        pass
    return None


def resolve(ip, timeout, me):
    if ip == me:
        return socket.gethostname(), "local"
    try:
        name = socket.gethostbyaddr(ip)[0]
        if name and name != ip:
            return name, "dns"
    except OSError:
        pass
    for fn, src in ((mdns_name, "mdns"), (netbios_name, "netbios")):
        name = fn(ip, timeout)
        if name:
            return name, src
    return "-", ""


# --------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description="Scan a local network for devices and host names.")
    ap.add_argument("network", nargs="?", help="e.g. 192.168.1.0/24 (default: your /24)")
    ap.add_argument("-j", "--jobs", type=int, default=128, help="parallel probes (default 128)")
    ap.add_argument("-t", "--timeout", type=float, default=1.0, help="probe timeout, s (default 1)")
    a = ap.parse_args()

    me = local_ip()
    target = a.network or me
    if not target:
        sys.exit("Can't detect local IP; pass a network, e.g. 192.168.1.0/24")
    if "/" not in target:
        target += "/24"
    try:
        net = ipaddress.ip_network(target, strict=False)
    except ValueError as e:
        sys.exit(f"Bad network: {e}")
    if net.version != 4:
        sys.exit("Only IPv4 is supported")
    hosts = [str(h) for h in net.hosts()] or [str(net.network_address)]
    if len(hosts) > 4096:
        print(f"Warning: {len(hosts)} addresses - this will take a while", file=sys.stderr)

    t0 = time.monotonic()
    print(f"Scanning {net} ({len(hosts)} addresses)...", file=sys.stderr)
    with ThreadPoolExecutor(a.jobs) as ex:
        alive = {ip for ip, ok in zip(hosts, ex.map(lambda ip: probe(ip, a.timeout), hosts)) if ok}

    arp = {ip: m for ip, m in read_arp().items() if ipaddress.ip_address(ip) in net}
    found = alive | set(arp)
    if me and ipaddress.ip_address(me) in net:
        found.add(me)
    found = sorted(found, key=ipaddress.ip_address)

    with ThreadPoolExecutor(min(a.jobs, 64)) as ex:
        names = list(ex.map(lambda ip: resolve(ip, a.timeout, me), found))

    rows = [(ip, arp.get(ip, "(this host)" if ip == me else "-"), n, s)
            for ip, (n, s) in zip(found, names)]
    hdr = ("IP", "MAC", "HOSTNAME", "VIA")
    w = [max(len(str(r[i])) for r in rows + [hdr]) for i in range(3)]
    print(f"{hdr[0]:<{w[0]}}  {hdr[1]:<{w[1]}}  {hdr[2]:<{w[2]}}  {hdr[3]}")
    for r in rows:
        print(f"{r[0]:<{w[0]}}  {r[1]:<{w[1]}}  {r[2]:<{w[2]}}  {r[3]}")
    print(f"\n{len(rows)} device(s) found in {time.monotonic() - t0:.1f}s", file=sys.stderr)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
