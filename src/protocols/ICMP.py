import struct
from ctypes import *


class ICMP(BigEndianStructure):
	_fields_=[
		("type", c_byte),
		("code", c_byte),
		("sum", c_ushort)
	]

	def __new__(self, buffer):
		return self.from_buffer_copy(buffer)


	def __init__(self, buffer):
		self.show()
	
	def __repr__(self):
		return "<ICMP type:{}, code:{}>".format(self.type, self.code)

	def show(self):
		print("""\t\t[ICMP]\n\t\t\tType: {} \n\t\t\tCode: {} \n\t\t\tChecksum: {}""".format(
			self.type, self.code, self.sum))