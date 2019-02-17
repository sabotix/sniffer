import struct
from ctypes import *

# from scapy

TCPOptions = {
	0: ("EOL", None),
	1: ("NOP", None),
	2: ("MSS", "!H"),
	3: ("WScale", "!B"),
	4: ("SAckOK", None),
	5: ("SAck", "!"),
	8: ("Timestamp", "!II"),
	14: ("AltChkSum", "!BH"),
	15: ("AltChkSumOpt", None),
	25: ("Mood", "!p"),
	28: ("UTO", "!H"),
	34: ("TFO", "!II"),
}


class TCP(BigEndianStructure):
	_fields_=[
		("src_port", c_ushort),
		("dst_port", c_ushort),
		("seq_num", c_ulong),
		("ack_num", c_ulong),
		("offset", c_ushort, 4),
		("reserved", c_ushort, 6),
		("urg", c_ushort, 1),
		("ack", c_ushort, 1),
		("psh", c_ushort, 1),
		("rst", c_ushort, 1),
		("syn", c_ushort, 1),
		("fin", c_ushort, 1),
		("window", c_ushort),
		("checksum", c_ushort),
		("urgent", c_ushort),
		#("options", c_ulong),
	]

	def __new__(self, buffer):
		return self.from_buffer_copy(buffer)

	def __init__(self, buffer):
		self.options = []
		self.subpacket= None


	def __repr__(self):
		return "<TCP src_port:{}, dst_port:{}>".format(self.src_port, self.dst_port)

	def as_dict(self):
		return {
			"src_port": self.src_port,
			"dst_port": self.dst_port,
			"seq_num": self.seq_num,
			"ack_num": self.ack_num,
			"offset": self.offset,
			"reserved": self.reserved,
			"urg": self.urg,
			"ack": self.ack,
			"psh": self.psh,
			"rst": self.rst,
			"syn": self.syn,
			"fin": self.fin,
			"window": self.window,
			"checksum": self.checksum,
			"urgent": self.urgent,
		}

	def show(self):
		print("""\t\t[TCP]\n\t\t\tSource Port: {} \n\t\t\tDestination Port: {} \n\t\t\tSequence Number: {} 
	\t\tAcknowledgment Number: {}  \n\t\t\tData Offset: {}  \n\t\t\tURG: {} 
	\t\tACK: {}  \n\t\t\tPSH: {}  \n\t\t\tRST: {}  \n\t\t\tSYN: {}
	\t\tFIN: {}  \n\t\t\tWindow: {}  \n\t\t\tChecksum: {}
	\t\tUrgent Pointer: {} \n\t\t\tOptions: {}""".format(
			self.src_port, self.dst_port, self.seq_num, self.ack_num, 
			self.offset, self.urg, self.ack, self.psh, self.rst, 
			self.syn, self.fin, self.window, self.checksum, self.urgent, self.options))

	def decode_options(self, buffer):
		while len(buffer):
			option_type= struct.unpack("!B", buffer[:1])[0]
			buffer = buffer[1:]
			
			name, fmt = TCPOptions[option_type]
			
			if name == "SAckOK":
				length = struct.unpack("!B", buffer[:1])[0]
				buffer = buffer[1:]
				self.options.append((name,))

			if fmt:
				length = struct.unpack("!B", buffer[:1])[0]
				buffer = buffer[1:]

				if name == "SAck":
					fmt = "{}{}I".format(fmt, int((length - 2)/4))

				values = struct.unpack(fmt, buffer[:length - 2])
				buffer=buffer[struct.calcsize(fmt):]

				self.options.append((name, values))

			else:
				self.options.append((name,))
