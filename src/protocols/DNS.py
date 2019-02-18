from ctypes import *

OPCODE={0: "QUERY", 1: "IQUERY" , 2: "STATUS"}
QR={0: "query", 1:"response"}
RCODE ={
	0:"No error",
	1: "Format error", 
	2: "Server failure", 
	3: "Name Error", 
	4: "Not Implemented",
	5: "Refused"
}


class DNS(BigEndianStructure):
	_fields_=[
		("id", c_ushort),
		("qr", c_ushort, 1),
		("opcode", c_ushort, 4),
		("aa", c_ushort, 1),
		("tc", c_ushort, 1),
		("rd", c_ushort, 1),
		("ra", c_ushort, 1),
		("z", c_ushort, 3),
		("rcode", c_ushort, 4),
		("qdcount", c_ushort),
		("nscount", c_ushort),
		("arcount", c_ushort),
	]

	def __new__(self, buffer):
		return self.from_buffer_copy(buffer)