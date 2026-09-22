#!/usr/bin/env python3
import os
import re
import ipaddress
import sys
import socket
import struct
import random
from rich.console import Console
from rich.table import Table

current_hostname = socket.gethostname()


def get_dns_from_port53_file():
    filepath = "hosts_port_53"
    if not os.path.isfile(filepath):
        return None
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            # Handle ip:port format or plain ip
            ip = line.split(":")[0]
            try:
                ipaddress.ip_address(ip)
                return ip
            except ValueError:
                continue
    return None


def build_ptr_query(ip):
    """Build a raw DNS PTR query packet for reverse lookup."""
    # Reverse the IP and append .in-addr.arpa
    reversed_ip = ".".join(reversed(ip.split(".")))
    name = reversed_ip + ".in-addr.arpa"

    query_id = random.randint(0, 65535)
    # Header: ID, flags (standard query), QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    header = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0)

    # Encode the QNAME
    qname = b""
    for part in name.split("."):
        encoded = part.encode()
        qname += struct.pack("B", len(encoded)) + encoded
    qname += b"\x00"

    # QTYPE=PTR (12), QCLASS=IN (1)
    question = qname + struct.pack(">HH", 12, 1)

    return header + question, query_id


def parse_ptr_response(data, query_id):
    """Parse a DNS response and extract the PTR record."""
    if len(data) < 12:
        return None

    resp_id, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", data[:12])

    if resp_id != query_id or ancount == 0:
        return None

    # Skip the header (12 bytes)
    offset = 12

    # Skip the question section
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        elif length & 0xC0 == 0xC0:
            offset += 2
            break
        offset += length + 1
    offset += 4  # skip QTYPE and QCLASS

    # Parse the first answer
    def read_name(data, offset):
        labels = []
        while offset < len(data):
            length = data[offset]
            if length == 0:
                offset += 1
                break
            elif length & 0xC0 == 0xC0:
                # Pointer
                pointer = struct.unpack(">H", data[offset:offset+2])[0] & 0x3FFF
                labels.append(read_name(data, pointer)[0])
                offset += 2
                break
            else:
                labels.append(data[offset+1:offset+1+length].decode())
                offset += length + 1
        return ".".join(labels), offset

    # Read answer NAME (may be a pointer)
    if offset >= len(data):
        return None

    _, offset = read_name(data, offset)

    if offset + 10 > len(data):
        return None

    rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", data[offset:offset+10])
    offset += 10

    if rtype != 12:  # PTR
        return None

    ptr_name, _ = read_name(data, offset)
    return ptr_name.rstrip(".")


def reverse_lookup(ip, dns_server, timeout=2):
    """Perform a PTR lookup against a specific DNS server using raw UDP."""
    try:
        packet, query_id = build_ptr_query(ip)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(packet, (dns_server, 53))
        response, _ = sock.recvfrom(512)
        sock.close()
        return parse_ptr_response(response, query_id)
    except Exception:
        return None


def get_hostname(ip, dns_server=None):
    try:
        if dns_server:
            result = reverse_lookup(ip, dns_server)
            return result if result else ""
        else:
            return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def parse_gnmap_files(target_ips=None, target_ports=None):
    hosts_data = {}
    gnmap_files = [f for f in os.listdir(".") if f.endswith(".gnmap")]
    for filename in gnmap_files:
        with open(filename, "r") as f:
            for line in f:
                if line.startswith("Host:") and "Ports:" in line:
                    parts = line.split()
                    ip = parts[1]
                    if target_ips and ip not in target_ips:
                        continue
                    ports_part = line.split("Ports:")[1].strip()
                    ports = ports_part.split(",")
                    host_ports = set()
                    has_target = False
                    for port in ports:
                        port = port.strip()
                        if not port:
                            continue
                        m = re.match(r"(\d+)/open/(\w+)//([^/]*)///?", port)
                        if m:
                            portid, proto, service = m.groups()
                            service = service if service else "unknown"
                            host_ports.add((portid, service))
                            if target_ports and portid in target_ports:
                                has_target = True
                    if target_ports and not has_target:
                        continue
                    if ip not in hosts_data:
                        hosts_data[ip] = set()
                    hosts_data[ip].update(host_ports)
    return hosts_data


def should_exclude(hostname, exhosts):
    if not hostname:
        return False
    if hostname == current_hostname or hostname.split('.')[0] == current_hostname.split('.')[0]:
        return True
    return any(ex in hostname for ex in exhosts)


def generate_lists(hosts_data, prefix, target_ports=None):
    by_port = {}
    for host, entries in hosts_data.items():
        for portid, _ in entries:
            if target_ports and portid not in target_ports:
                continue
            by_port.setdefault(portid, set()).add(host)
    for portid in sorted(by_port, key=int):
        fn = f"{prefix}_port_{portid}"
        with open(fn, "w") as f:
            for ip in sorted(by_port[portid], key=ipaddress.ip_address):
                f.write(ip + "\n")
        print(f"{fn}: {len(by_port[portid])} hosts")


def print_basic(hosts_data, exhosts, target_ports, dns_server=None, no_hostname=False):
    for host, entries in sorted(hosts_data.items(), key=lambda x: ipaddress.ip_address(x[0])):
        hostname = "" if no_hostname else get_hostname(host, dns_server)
        if should_exclude(hostname, exhosts):
            continue
        header = f"{host} {hostname}".strip()
        print(header)
        for portid, service in sorted(entries, key=lambda x: int(x[0])):
            print(f"  {portid}/{service}")
        print()


def print_table(hosts_data, exhosts, dns_server=None, no_hostname=False):
    console = Console()
    table = Table(header_style="bold magenta", show_lines=True)
    table.add_column("HOST", style="cyan", no_wrap=True)
    table.add_column("HOSTNAME", style="white")
    table.add_column("PORTS", style="green")
    table.add_column("SERVICES", style="yellow")

    for host, entries in sorted(hosts_data.items(), key=lambda x: ipaddress.ip_address(x[0])):
        hostname = "" if no_hostname else get_hostname(host, dns_server)
        if should_exclude(hostname, exhosts):
            continue
        entries_sorted = sorted(entries, key=lambda x: int(x[0]))
        ports_str = "\n".join(p for p, _ in entries_sorted)
        services_str = "\n".join(s for _, s in entries_sorted)
        table.add_row(host, hostname, ports_str, services_str)

    console.print(table)


def print_ips_only(hosts_data, exhosts, target_ports, dns_server=None, no_hostname=False):
    for host in sorted(hosts_data.keys(), key=ipaddress.ip_address):
        hostname = "" if no_hostname else get_hostname(host, dns_server)
        if should_exclude(hostname, exhosts):
            continue

        if target_ports:
            open_target_ports = sorted([p for p, _ in hosts_data[host] if p in target_ports], key=int)
            out = f"{host}:{','.join(open_target_ports)}" if open_target_ports else host
        else:
            out = host

        hostname_part = f" ({hostname})" if hostname else ""
        print(out + hostname_part)


def print_allports(hosts_data, exhosts, dns_server=None, no_hostname=False):
    lines = []
    for host, entries in sorted(hosts_data.items(), key=lambda x: ipaddress.ip_address(x[0])):
        hostname = "" if no_hostname else get_hostname(host, dns_server)
        if should_exclude(hostname, exhosts):
            continue
        for portid, _ in sorted(entries, key=lambda x: int(x[0])):
            lines.append(f"{host}:{portid}")
    for line in lines:
        print(line)


if __name__ == "__main__":
    basic = "--basic" in sys.argv
    ips_only = "--ips" in sys.argv
    allports = "--allports" in sys.argv
    no_hostname = "--no-hostname" in sys.argv
    generate = "--generate" in sys.argv

    target_arg = None
    target_ports = None
    exhost_arg = None
    dns_override = None

    i = 1
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg in ("--basic", "--ips", "--allports", "--no-hostname", "--generate"):
            pass
        elif arg == "-p" and i + 1 < len(sys.argv):
            target_ports = set(sys.argv[i + 1].split(","))
            i += 1
        elif arg == "--exhost" and i + 1 < len(sys.argv):
            exhost_arg = sys.argv[i + 1]
            i += 1
        elif arg == "--dns" and i + 1 < len(sys.argv):
            dns_override = sys.argv[i + 1]
            i += 1
        elif not arg.startswith("-") and target_arg is None:
            target_arg = arg
        i += 1

    target_ips = None
    if target_arg:
        if os.path.isfile(target_arg):
            with open(target_arg, "r") as f:
                target_ips = {line.strip() for line in f if line.strip()}
        else:
            target_ips = {target_arg}

    # Auto-detect port filter from filename e.g. hosts_port_445 or hosts_port_445_80
    if target_arg and target_ports is None:
        m = re.search(r'port_(\d+(?:_\d+)*)', os.path.basename(target_arg))
        if m:
            target_ports = set(m.group(1).split("_"))

    hosts = parse_gnmap_files(target_ips, target_ports)

    # Ensure all IPs from the input file are included even if not in any gnmap
    if target_ips:
        for ip in target_ips:
            if ip not in hosts:
                hosts[ip] = set()

    extra_ex = [ex.strip() for ex in exhost_arg.split(",")] if exhost_arg else []
    exhosts = extra_ex

    # Resolve DNS server: CLI flag > hosts_port_53 file > system resolver
    if no_hostname:
        dns_server = None
    elif dns_override:
        dns_server = dns_override
    else:
        dns_server = get_dns_from_port53_file()

    if dns_server:
        console = Console()
        console.print(f"[bold blue][*] Using DNS server: {dns_server}[/bold blue]")

    if hosts:
        if generate:
            prefix = os.path.basename(target_arg) if target_arg else "hosts"
            generate_lists(hosts, prefix, target_ports)
        elif allports:
            print_allports(hosts, exhosts, dns_server, no_hostname)
        elif ips_only:
            print_ips_only(hosts, exhosts, target_ports, dns_server, no_hostname)
        elif basic:
            print_basic(hosts, exhosts, target_ports, dns_server, no_hostname)
        else:
            print_table(hosts, exhosts, dns_server, no_hostname)
