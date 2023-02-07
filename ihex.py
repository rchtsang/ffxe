import os
import binascii
import subprocess
from pprint import pprint
from os.path import *
from collections import OrderedDict


class IHexRecord:
    """A Class represenation of an Intel Hex record"""
    
    def __init__(self, srecord : str, base : int =0, up_addr : int =0):
        assert srecord[0] == ':', "record missing start code ':'!"
        s = srecord.strip()
        byte_strs = [s[i:i+2] for i in range(1, len(s), 2)]
        self.byte_cnt = int(byte_strs[0], base=16)
        self.addr     = int(byte_strs[1] + byte_strs[2], base=16)
        self.type     = int(byte_strs[3], base=16)
        self.data     = [int(v, base=16) \
                         for v in byte_strs[4:4+self.byte_cnt]]
        self.checksum = int(byte_strs[-1], base=16)
        self.valid    = self.is_valid()
        self.base     = base
        self.up_addr  = up_addr
        self.abs_addr = self.addr + (base * 16) + (up_addr << 16)
    
    def create_checksum(self):
        bytesum = sum(self.to_ints()[:-1])
        return (~(bytesum & 0xFF) + 1) & 0xFF
    
    def is_valid(self):
        return self.checksum == self.create_checksum()
    
    def __setitem__(self, offset : int, val : int):
        assert offset < self.byte_cnt, \
            f"index out of bounds"
        self.data[offset] = val
        self.checksum = self.create_checksum()
    
    def __repr__(self):
        return ':' + ''.join(['%02X' % b for b in self.to_ints()])
    
    def to_ints(self):
        return [self.byte_cnt, 
                self.addr >> 8, 
                self.addr & 0xFF, 
                self.type] + \
                self.data + \
                [self.checksum]
    
    def is_eof(self):
        return self.__repr__ == ":0000001FF"
        
class IHex:
    """A Class representation of an Intel Hex file
    
    Note: Expects that byte count fields be no larger than 16"""
    
    def __init__(self, path : str):
        self.path = path
        self.record_list = []
        self.data = OrderedDict()
        self.length = 0
        with open(path, 'r') as f:
            base = 0
            up_addr = 0
            for line in f.readlines():
                record = IHexRecord(line, base=base, up_addr=up_addr)
                if record.is_eof():
                    break
                
                self.record_list.append(record)
                
                if record.type == 0:
                    self.data[record.abs_addr] = record

                    # if record.addr + record.byte_cnt > self.length:
                    #     self.length = record.addr + record.byte_cnt
                    self.length += record.byte_cnt
                
                elif record.type == 2:
                    base = int(''.join(['%02x'%v for v in record.data]), base=16)
                
                elif record.type == 4:
                    up_addr = int(''.join(['%02x'%v for v in record.data]), base=16)
                
                    
        self.keys = list(self.data.keys())
        self.keys.sort(reverse=True)
        self.base = self.data[self.keys[-1]].abs_addr
    
    def __getitem__(self, addr : int):
        """Returns the IHexRecord that contains the given address"""
        
        assert addr >= 0 and addr < self.length + self.base, \
            "addr out of bounds"
        
        for key in self.keys:
            if addr >= key:
                return self.data[key]
        raise KeyError("invalid address 0x%04x" % addr)
        
    def __setitem__(self, addr : int, val : int):
        """Sets the byte val at the given addr"""
        
        record = self.__getitem__(addr)
        roffset = addr - record.abs_addr
        record[roffset] = val
    
    def writefile(self, path):
        with open(path, 'w') as f:
            for record in self.record_list:
                f.write(repr(record) + '\r\n')

    @property
    def raw(self):
        """generate the raw binary of the hex file"""
        raw = []
        offset = 0
        for abs_addr, record in self.data.items():
            if offset < abs_addr:
                raw.append(b"\x00" * (abs_addr - offset))
            raw.append(
                b''.join([v.to_bytes(1, 'little') for v in record.data]))

        return b''.join(raw)



