#!/usr/bin/env python3
"""
Simple packet analyzer (educational).
- Uses scapy to sniff packets and print summaries.
- Saves capture to a pcap file if requested.
Run as root/administrator.
"""

import argparse
import signal
import sys
from datetime import datetime
from collections import Counter
from scapy.all import sniff, wrpcap, Packet, IP, IPv6, TCP, UDP, ARP, Ether

# Global state
packet_count = 0
protocol_counter = Counter()
captured_packets = []

def human_summary(pkt: Packet) -> str:
    """Return a short, human-friendly summary of packet."""
    ts = datetime.now().strftime("%H:%M:%S")
    if pkt.haslayer(Ether):
        eth = pkt.getlayer(Ether)
        src_eth = eth.src
        dst_eth = eth.dst
    else:
        src_eth = dst_eth = "N/A"

    if pkt.haslayer(IP):
        ip = pkt.getlayer(IP)
        proto = ip.proto
        src = ip.src
        dst = ip.dst
        if pkt.haslayer(TCP):
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            return f"{ts}  TCP  {src}:{sport} -> {dst}:{dport}  eth={src_eth}->{dst_eth}"
        elif pkt.haslayer(UDP):
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            return f"{ts}  UDP  {src}:{sport} -> {dst}:{dport}  eth={src_eth}->{dst_eth}"
        else:
            return f"{ts}  IP   {src} -> {dst}  proto={proto}  eth={src_eth}->{dst_eth}"
    elif pkt.haslayer(ARP):
        arp = pkt.getlayer(ARP)
        return f"{ts}  ARP  {arp.psrc} ({arp.hwsrc}) -> {arp.pdst} ({arp.hwdst})"
    elif pkt.haslayer(IPv6):
        ip6 = pkt.getlayer(IPv6)
        return f"{ts}  IPv6 {ip6.src} -> {ip6.dst}"
    else:
        return f"{ts}  OTHER  {pkt.summary()}"

def handle_packet(pkt: Packet):
    global packet_count, protocol_counter, captured_packets
    packet_count += 1
    captured_packets.append(pkt)

    # Update protocol counters (simple detection)
    if pkt.haslayer(TCP):
        protocol_counter["TCP"] += 1
    elif pkt.haslayer(UDP):
        protocol_counter["UDP"] += 1
    elif pkt.haslayer(ARP):
        protocol_counter["ARP"] += 1
    elif pkt.haslayer(IP):
        protocol_counter["IP"] += 1
    elif pkt.haslayer(IPv6):
        protocol_counter["IPv6"] += 1
    else:
        protocol_counter["OTHER"] += 1

    # Print summary
    print(human_summary(pkt))

def stop_sniff(signum=None, frame=None):
    # Called on Ctrl+C or signal - prints stats and exits gracefully
    print("\n\nStopping capture...")
    print(f"Total packets captured: {packet_count}")
    print("Protocol counts:")
    for proto, cnt in protocol_counter.most_common():
        print(f"  {proto}: {cnt}")
    # Save to pcap if requested (handled in main)
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser(description="Simple network packet analyzer (educational)")
    parser.add_argument("-i", "--iface", help="Interface to sniff on (default: scapy default)", default=None)
    parser.add_argument("-f", "--filter", help="BPF filter (e.g., 'tcp and port 80')", default="")
    parser.add_argument("-c", "--count", help="Number of packets to capture (0 = infinite)", type=int, default=0)
    parser.add_argument("-w", "--write", help="Write captured packets to pcap file", default="")
    args = parser.parse_args()

    print("Starting packet capture")
    print(f"Interface: {args.iface or '(default)'}  Filter: '{args.filter or 'none'}'  Count: {args.count or 'unlimited'}")
    print("Press Ctrl+C to stop\n")

    # Setup signal handler for graceful termination
    signal.signal(signal.SIGINT, stop_sniff)

    # sniff: store=False to avoid automatic storing (we append manually), prn=callback
    try:
        sniff(iface=args.iface if args.iface else None,
              filter=args.filter if args.filter else None,
              prn=handle_packet,
              store=False if args.write else False,
              count=args.count if args.count > 0 else 0)
    except PermissionError:
        print("Permission error: you must run this script with root/administrator privileges.")
        sys.exit(1)
    except Exception as e:
        print("Error while sniffing:", e)
        sys.exit(1)

    # After capture finished (if count reached), print stats and optionally save
    print("\nCapture finished.")
    print(f"Total packets captured: {packet_count}")
    print("Protocol counts:")
    for proto, cnt in protocol_counter.most_common():
        print(f"  {proto}: {cnt}")

    # Save PCAP if requested (we used captured_packets list)
    if args.write:
        try:
            wrpcap(args.write, captured_packets)
            print(f"Saved captured packets to {args.write}")
        except Exception as e:
            print(f"Failed to write pcap: {e}")

if _name_ == "_main_":
    main()
