#!/usr/bin/python3
try:
   from scapy.all import *
except ModuleNotFoundError as err:
   print(err + ": Scapy")
import sys
import os

path = os.environ['OVS_DIR'] + "/tests/pcap/fuzzy"
pktdump = PcapWriter(path, append=False, sync=True)

for i in range(0, 2000):

   # Generate random protocol bases, use a fuzz() over the combined packet for full fuzzing.
   eth = Ether(src=RandMAC(), dst=RandMAC())
   vlan = Dot1Q()
   ipv4 = IP(src=RandIP(), dst=RandIP())
   ipv6 = IPv6(src=RandIP6(), dst=RandIP6())
   udp = UDP()
   tcp = TCP()

   # IPv4 packets with fuzzing
   pktdump.write(fuzz(eth/ipv4/udp))
   pktdump.write(fuzz(eth/ipv4/tcp))
   pktdump.write(fuzz(eth/vlan/ipv4/udp))
   pktdump.write(fuzz(eth/vlan/ipv4/tcp))

    # IPv6 packets with fuzzing
   pktdump.write(fuzz(eth/ipv6/udp))
   pktdump.write(fuzz(eth/ipv6/tcp))
   pktdump.write(fuzz(eth/vlan/ipv6/udp))
   pktdump.write(fuzz(eth/vlan/ipv6/tcp))