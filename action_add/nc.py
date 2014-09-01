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
            "NC_NULL",
            "NC_GATHER",
            "NC_INIT_CODING",
            "NC_ENCODE",
            "NC_DECODE",
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
        self.vector_off = 0
        self.buffer_id = 0
        self.packet_num = 0
        self.port_num = 0
        self.packet_len = 0
        self.port_id = []
        self.vector = []
        
        initHelper(self, kw)
    
    def _eq (self, other):
        if self.subtype != other.subtype: 
            return False
        return True

    def _pack_body (self):
        p = struct.pack('!H', self.subtype)
        p += struct.pack("!BBBBH", self.vector_off, self.buffer_id, self.packet_num, \
               self.port_num, self.packet_len)
        for i in range(self.port_num):
            p += struct.pack("!H", self.port_id[i])

        for i in range(self.port_num):
            for j in range(self.packet_num):
                p += struct.pack("!B", self.vector[i][j])
        j = 8 + (2 + self.packet_num) * self.port_num
        add = align_eight(j) - j
        for i in range(add):
            p += _PAD
        return p

    def _unpack_body (self, raw, offset, avail):
        return offset

    def _body_length (self):
        l = 6 + (self.packet_num + 2) * self.port_num
        return align_eight(l)

    def _show (self, prefix):
        return None

class nc_action_encode (of.ofp_action_vendor_base):
    def _init (self, kw):
        self.vendor = NC_VENDOR_ID
        self.subtype = NC_ENCODE
        self.buffer_id = 0
        self.port_num = 0
        self.port_id = 0
        self.buffer_size = 0
        self.output_port = 0
        self.packet_len = 0
        self.packet_num = 0
        self.data = []
        
        initHelper(self, kw)
    
    def _eq (self, other):
        if self.subtype != other.subtype: 
            return False
        return True

    def _pack_body (self):
        p = struct.pack('!H', self.subtype)
        p += struct.pack("!BBHHHHH", self.buffer_id, self.port_num, self.port_id, \
                self.buffer_size, self.output_port, self.packet_len, self.packet_num)
        for i in range(self.packet_num):
            p += struct.pack("!B", self.data[i])

        j = 14 + self.packet_num 
        add = align_eight(j) - j
        for i in range(add):
            p += _PAD
        return p

    def _unpack_body (self, raw, offset, avail):
        return offset

    def _body_length (self):
        l = 12 + self.packet_num
        return align_eight(l)

    def _show (self, prefix):
        return None

class nc_action_decode (of.ofp_action_vendor_base):
    def _init (self, kw):
        self.vendor = NC_VENDOR_ID
        self.subtype = NC_DECODE
        self.buffer_id = 0
        self.packet_num = 0
        self.output_port = 0
        self.packet_len = 0
        self.port_id = 0
        self.buffer_size = 0
        
        initHelper(self, kw)
    
    def _eq (self, other):
        if self.subtype != other.subtype: 
            return False
        return True

    def _pack_body (self):
        p = struct.pack('!H', self.subtype)
        p += struct.pack("!BBHHHH", self.buffer_id, self.packet_num, \
               self.output_port, self.packet_len, self.port_id, self.buffer_size)
        p += _PAD4
        return p

    def _unpack_body (self, raw, offset, avail):
        return offset

    def _body_length (self):
        return 16 

    def _show (self, prefix):
        return None

