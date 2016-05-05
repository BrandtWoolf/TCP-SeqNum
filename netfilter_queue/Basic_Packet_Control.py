#!/usr/bin/python

from netfilterqueue import NetfilterQueue

def print_and_accept(pkt):
	print pkt
	raw_input("Press Enter to send packet\n")
	pkt.accept()

nfqueue = NetfilterQueue()
nfqueue.bind(1, print_and_accept)
try:
	nfqueue.run()
except KeyboardInterrupt:
	print
