#!/usr/bin/python2.7
import dpkt
import socket
import sys
from dpkt.ip import IP_PROTO_TCP

def main():
    if (len(sys.argv) < 2):
        print "error: need argument"
        sys.exit(1)

    filename = sys.argv[1]
    print "input filename: " + filename
    f = open(filename,'rb')
    pcap = dpkt.pcap.Reader(f) 
    SYN = {}
    ACK = {}
    for ts, buf in pcap:
    	try:
    		#SYN = 0
    		#ACK = 0
    		eth = dpkt.ethernet.Ethernet(buf)
    		ip = eth.data
    		if ip.p != IP_PROTO_TCP:
    			continue
    		tcp = ip.data
    		syn_flag = ( tcp.flags & dpkt.tcp.TH_SYN )
    		ack_flag = ( tcp.flags & dpkt.tcp.TH_ACK )
    		if syn_flag != 0 and ack_flag == 0 :
    			if not SYN.has_key(ip.src):
    				SYN[ip.src] = 0
    			SYN[ip.src] += 1
    		if ack_flag != 0 and syn_flag != 0:
    			if not ACK.has_key(ip.dst):
    				ACK[ip.dst] = 0
    			ACK[ip.dst] += 1
    		#print socket.inet_ntoa(ip.src)
    	except dpkt.dpkt.NeedData:
    		continue
    	except AttributeError:
    		continue
    #print "fixme"
    for key in SYN:
    	if ACK.has_key(key):
    		if SYN[key] > (3*ACK[key]):
    			print socket.inet_ntoa(key)
    	else:
    		print socket.inet_ntoa(key)
    sys.exit(0)


if __name__ == '__main__':
    main()
