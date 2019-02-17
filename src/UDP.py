from ctypes import *
import struct

class UDP(BigEndianStructure):
	_fields_ =[
		("src_port", c_ushort),
		("dst_port", c_ushort),
		("len", c_ushort),
		("sum", c_ushort)
	]

	def __new__(self, buffer):
		return self.from_buffer_copy(buffer)

	def __init__(self, buffer):
		self.show()

	def __repr__(self):
		return "<UDP src_port:{}, dst_port:{}>".format(self.src_port, self.dst_port)


	def show(self):
		print("""\t\t[UDP]\n\t\t\tSource Port: {} \n\t\t\tDestination Port: {}
	\t\tLength: {} \n\t\t\tChecksum: {}""".format(
			self.src_port, self.dst_port, self.len, self.sum))