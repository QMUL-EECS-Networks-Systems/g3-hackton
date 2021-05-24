#!/usr/bin/env python

#from scapy.all import send, IP, ICMP
from scapy.all import *
#from scapy.contrib import roce
import random
import sys
import struct
import time
import random

#dstMAC = "56:2B:95:DB:33:39"
#dstMAC = "b8:ce:f6:61:a0:f6"
#dstMAC = "ff:ff:ff:ff:ff:ff"
#dstMAC = "b8:ce:f6:61:9f:96" #host

#dstMAC = "b8:ce:f6:61:9f:96" #host13
dstMAC = "b8:ce:f6:61:9f:9a" #dpu13

srcIP = "11.11.11.1"
dstIP = "11.11.11.2"

rocev2_port = 4790 #Default RoCEv2=4791


class BTH(Packet):
	name = "Infiniband BTH"
	fields_desc = [
		ByteField("opcode", 0),
		BitField("solicitedEvent", 0, 1),
		BitField("migReq", 0, 1),
		BitField("padCount", 0, 2),
		BitField("transportHeaderVersion", 0, 4),
		XShortField("partitionKey", 0),
		XByteField("reserved1", 0),
		ThreeBytesField("destinationQP", 0),
		BitField("ackRequest", 0, 1),
		BitField("reserved2", 0, 7),
		ThreeBytesField("packetSequenceNumber", 0)
	]

class RETH(Packet):
	name = "RDMA RETH"
	fields_desc = [
		BitField("virtualAddress", 0, 64),
		LongField("rKey", 0),
		IntField("dmaLength", 0)
		
	]

class iCRC(Packet):
	name = "iCRC"
	fields_desc = [
		IntField("iCRC", 0),
		
	]

#Make RDMA write packet with 32bit payload
packetSequenceNumber = 0
def makeRocev2Write(payload=0xdeadbeef, address=0x0):
	global packetSequenceNumber
	partitionKey = 0
	destinationQP = 0
	dmaLength = 32
	virtualAddress = address #Start of buffer
	rKey = 0 #Kinda like the password
	
	iCRC_checksum = 0 #TODO: calculate this? Or ignore?
	
	payload = struct.pack(">I", payload)
	
	packetSequenceNumber = packetSequenceNumber + 1

	pkt = Ether(src="b8:ce:f6:61:a0:f2",dst=dstMAC)
	pkt = pkt/IP(src=srcIP,dst=dstIP,ihl=5,flags=0b010,proto=0x11)
	pkt = pkt/UDP(sport=0xc0de,dport=rocev2_port,chksum=0)
	pkt = pkt/BTH(opcode=0b01010,partitionKey=partitionKey,destinationQP=destinationQP, packetSequenceNumber=packetSequenceNumber) #WRITE-ONLY
	pkt = pkt/RETH(dmaLength=dmaLength,virtualAddress=virtualAddress,rKey=rKey)
	pkt = pkt/Raw(payload)
	pkt = pkt/iCRC(iCRC=iCRC_checksum)
	
	return pkt


def makeIPPacket():
	pkt = Ether(src="b8:ce:f6:61:a0:f2",dst=dstMAC)
	pkt = pkt/IP(src=srcIP,dst=dstIP)
	return pkt


def makeUDPPacket():
	pkt = Ether(src="b8:ce:f6:61:a0:f2",dst=dstMAC)
	pkt = pkt/IP(src=srcIP,dst=dstIP)/UDP()
	return pkt



i = 0
while True:
	i = i + 1
	address = random.randint(0, 2**64-1)
	pkt = makeRocev2Write(payload=i, address=address)
	print("Sending packet", pkt)
	sendp(pkt, iface="p0")
	wrpcap("rocev2_pkt.pcap",pkt)
	time.sleep(1)
