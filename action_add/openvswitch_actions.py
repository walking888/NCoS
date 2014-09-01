#!/usr/bin/env python
import sys
import os
import exceptions

need_add_c_file = [
		'liu_buffer.c',
		'gf256.c',
		'matrix.c',
		]
need_add_h_file = [
		'liu_buffer.h',
		'gf256.h',
		'matrix.h',
		]
need_add_other_file = [
		'muldiv.tab',
		]

def add_datapath_file(path):
	l = need_add_c_file + need_add_h_file + need_add_other_file
	for k in l:
		os.system('cp openvswitch/' + k + ' '+ path + '/datapath/')

def help():
	print "there are two args: ./xxxx.py openvswitch_location"
	raise Exception

print sys.argv
if len(sys.argv) != 2:
	help()
else:
	add_datapath_file(sys.argv[1])
	change_makefile(sys.argv[1])
	change_file(sys.argv[1])
