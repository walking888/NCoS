# by Liu Sicheng
# mail : liusicheng888@gmail.com

from pox.core import core
from pox.lib.util import initHelper
from pox.lib.util import hexdump
from pox.lib.addresses import parse_cidr, IPAddr, EthAddr

import pox.openflow.libopenflow_01 as of
from pox.openflow.libopenflow_01 import ofp_header, ofp_vendor_base
from pox.openflow.libopenflow_01 import _PAD, _PAD2, _PAD4, _PAD6
from pox.openflow.libopenflow_01 import _unpack, _read, _skip

import struct


NC_VENDOR_ID = 0x00003333

def _init_constants ():
	actions = [
			]
	for i,name in enumerate(actions):
		globals()[name] = i

_init_constants()


def align_eight(l):
	return (l + 7)/8 * 8

class nc_action_init_coding (of.ofp_action_vendor_base):
	def _init (self, kw):
		self.vendor = NC_VENDOR_ID
		self.subtype = NC_INIT_CODING
	
	def _eq (self, other):
		if self.subtype != other.subtype: 
			return False
		return True

	def _pack_body (self):
		p = struct.pack('!H', self.subtype)
		add = align_eight(j) - j
		for i in range(add):
			p += _PAD
		return p

	def _unpack_body (self, raw, offset, avail):
		return offset

	def _body_length (self):
		j = 6 + (self.packet_num + 2) * self.port_num
		return align_eight(j)

	def _show (self, prefix):
		return None
