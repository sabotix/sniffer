import struct
import  socket
from ctypes import *
from utils import IP_PROTOCOLS


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