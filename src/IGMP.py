import struct
from ctypes import *


class IGMP(BigEndianStructure):
	_fields_ = [
		 ("type", c_byte),
		 ("max_resp_time", c_byte),
		 ("sum", c_ushort),
		 ("addr", c_ulong)
	]

	def __new__(self, buffer):
		return self.from_buffer_copy(buffer)

	def __repr__(self):
		pass

	def __init__(self, buffer):
		self.show()

	def show(self):
		print("""\t\t[IGMP]\n\t\t\tType: {} \n\t\t\tMax Response Time: {} \n\t\t\tChecksum: {} \n\t\t\tGroup Address: {}""".format(
			self.type, self.max_resp_time, self.sum, self.addr))