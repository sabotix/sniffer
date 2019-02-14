import socket
import os, sys
import struct
from ctypes import *
from protocols import *
from utils import *



host = sys.argv[1]


def decompress_gzip(buffer):
	try:
		return gzip.decompress(i).decode()
	except:
		return None

def parse_http(buffer):
	raw_headers, body = buffer.split(b"\r\n\r\n", 1)
	header = raw_headers.decode().split("\r\n")
	status = header[0]
	headers = {}

	for i in header[1:]:
		k, v = i.split(":", 1)
		headers.update({k: v})

	return headers, decompress_gzip(body)



def print_data(buffer, http = False):
	if buffer:

		print("""\t\t[DATA]\n\t\t\t{}\n""".format(buffer))


if os.name == "nt":
	socket_protocol = socket.IPPROTO_IP
else:
	socket_protocol = socket.IPPROTO_ICMP

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
sniffer.bind((host, 0))
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

if os.name == "nt":
	sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

try:
	while True:

		raw_buffer = sniffer.recv(65565)
		#raw_buffer=raw_buffer[0]

		ip_header = IP(raw_buffer[0:20])
		offset = ip_header.ihl*4
		if ip_header.get_prortocol() == "TCP":
			tcp_header = TCP(raw_buffer[offset: offset+20])
			if tcp_header.src_port == 80 or tcp_header.dst_port == 80:
				print_data(raw_buffer[offset+20:], http=True)
			else: 
				print_data(raw_buffer[offset+20:])

		if ip_header.get_prortocol() == "UDP":
			udp_header = UDP(raw_buffer[offset: offset+8])
			print_data(raw_buffer[offset+8:])

		if ip_header.get_prortocol() == "ICMP":
			icmp_header = ICMP(raw_buffer[offset: offset+4])
			print_data(raw_buffer[offset+4:])

		if ip_header.get_prortocol() == "IGMP":
			igmp_header = IGMP(raw_buffer[offset: offset + 8])
			print_data(raw_buffer[offset + 8 :])


except KeyboardInterrupt:
	if os.name == "nt":
		sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
	sniffer.close()

