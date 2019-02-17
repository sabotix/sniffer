import struct
import  socket
from ctypes import *
from utils import IP_PROTOCOLS


OP_FLAGS = {0: "not copied", 1: "copied"}
OP_CLASS = {0 : "control", 2 : "debugging and measurement"}

options_names = {
	0: ("end_of_list", None),
	1: ("nop", None),
	2: ("security", "!HHH3B"),
	3: ("loose_source_route", "!BB"),
	4: ("timestamp", "!BBLL"),
	5: ("extended_security", ),
	6: "commercial_security",
	7: "record_route",
	8: "stream_id",
	9: "strict_source_route",
	10: "experimental_measurement",
	11: "mtu_probe",
	12: "mtu_reply",
	13: "flow_control",
	14: "access_control",
	15: "encode",
	16: "imi_traffic_descriptor",
	17: "extended_IP",
	18: "traceroute",
	19: "address_extension",
	20: "router_alert",
	21: "selective_directed_broadcast_mode",
	23: "dynamic_packet_state",
	24: "upstream_multicast_packet",
	25: "quick_start",
	30: "rfc4727_experiment",
}


class IPOptions(BigEndianStructure):
	_fields_ = [
		("flag", c_ubyte, 1),
		("class", c_ubyte, 2),
		("num", c_ubyte, 5)
	]

	def __new__(self, buffer):
		return from_buffer_copy(buffer)

	def __init__(self, buffer):

		pass


class IP(BigEndianStructure):
	_fields_ = [
		("version", c_ubyte, 4),
		("ihl", c_ubyte, 4),
		("tos", c_ubyte),
		("len", c_ushort),
		("id", c_ushort),
		("flags", c_ushort),
		("ttl", c_ubyte),
		("protocol_num", c_ubyte),
		("sum", c_ushort),
		("src", c_ulong),
		("dst", c_ulong)
	]
	
	def __new__(self, socket_buffer=None):
		return self.from_buffer_copy(socket_buffer)
	
	def __init__(self, socket_buffer=None):
		self.src_address = socket.inet_ntoa(struct.pack("!L",self.src))
		self.dst_address = socket.inet_ntoa(struct.pack("!L",self.dst))

		self.show()

	def __repr__(self):
		return "<IP src:{}, dst:{}>".format(self.src_address, self.dst_address)

	def get_prortocol(self):
		return IP_PROTOCOLS.get(self.protocol_num) or self.protocol_num

	def as_dict(self):
		return  (self.version, self.ihl, self.tos, self.len, self.id, self.flags, self.ttl, 
		self.get_prortocol(self.protocol_num), self.sum, self.src_address, self.dst_address)

	def show(self):
		print("[IP]")
		print("""\tVersion: {}\n\tIHL: {}\n\tService: {}\n\tLength: {}
	Identification: {}\n\tFlags: {}\n\tTTL: {}
	Protocol: {}\n\tChecksum: {}\n\tSource: {}\n\tDestination: {}""".format(self.version, self.ihl, self.tos, self.len, self.id, self.flags, self.ttl, 
		self.get_prortocol(), self.sum, self.src_address, self.dst_address))

	def decode_options(self, buffer):
		pass
