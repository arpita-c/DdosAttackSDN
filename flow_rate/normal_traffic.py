#!/usr/bin/env python
import sys
import getopt
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
	return ip



# host IPs start with 10.0.0. the last value entered by user
def gendest(start, end):
    first = 10
    second = 0; third = 0;
    ip = ".".join([str(first),str(second), str(third),str(randrange(start,end))])
    return ip




def main():
    start = 2
    end = 30
    
    #main method
    try:
        opts, args =getopt.getopt(sys.argv[1:],'s:e:',['start=','end='])
    except getopt.GetoptError:
        sys.exit(2)
    
    for opt, arg in opts:
        if opt =='-s':
            start = int(arg)
        elif opt =='-e':
            end = int(arg)
    if start == '':
        sys.exit()
    if end == '':
        sys.exit()

    # open interface eth0 to send packets
    interface = popen('ifconfig | awk \'/eth0/ {print$1}\'').read()

    # send normal traffic to the destination hosts
    for i in xrange(1000):
        # form the packet
        payload = "hello world"
        packets = Ether()/IP(dst=gendest(start,end),src=sourceIPgen())/UDP(dport=80,sport=2)/payload
        print(repr(packets))
        m = 0
        # send packet with the defined interval (seconds)
        while m <= 1000:
            sendp(packets,iface=interface.rstrip(),inter=0.2)
            m +=1

if __name__=="__main__":
    main()
