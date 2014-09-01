#!/usr/bin/env python
import sys
import os
import exceptions

def read_struct(file_path):
	f = open(file_path, 'r')
	a = {}
	a_keys = []
	state = 0
	s = 'null'
	while True:
		line = f.readline()
		if not line: break
		i = line.find('#')
		line = line[:i]
		line.lstrip()
		if len(line) == 0:
			continue
		words = line.split()
		if state == 0:
			if words[0] == 'new':
				a[words[1]] = ({},{},[],[])
				a_keys.append(words[1])
				s = words[1]
			if words[0] == '{':
				state = state + 1
		elif state == 1:
			if words[0] == '}':
				state = state - 1
			else:
				#here is value name and size
				if words[1].isdigit():
					#all is number
					a[s][0][words[0]] = int(words[1])
				else:
					b = words[1].split('*')
					if len(b) > 3:
						print "too many values at " + line
						raise Exception
					a[s][1][words[0]] = [len(b) - 1, int(b[-1])]
					for w in b[:-1]:
						a[s][1][words[0]].append(w)
					a[s][3].append((int(b[-1]), words[0]))
	f.close()
	a['keys'] = a_keys
	for k in a['keys']:
		for k1 in a[k][0].keys():
			a[k][2].append((a[k][0][k1], k1))
		a[k][2].sort()
	return a

def not_changed(s):
	return s
def add_ntohs(s):
	return 'ntohs('+s+')'
def add_ntohl(s):
	return 'ntohl('+s+')'
def add_ntohll(s):
	return 'ntohll('+s+')'
ntohfunction = {1:not_changed, 2:add_ntohs, 4:add_ntohl, 8:add_ntohll}

def add_htons(s):
	return 'htons('+s+')'
def add_htonl(s):
	return 'htonl('+s+')'
def add_htonll(s):
	return 'htonll('+s+')'
htonfunction = {1:not_changed, 2:add_htons, 4:add_htonl, 8:add_htonll}

def get_key_len(a,k,x,ss):
	s = ''
	m = a[k][1][x]
	for i in range(m[0]):
		asd = m[2+i]
		sdf = ntohfunction[a[k][0][asd]](ss + str(asd))
		if i == 0:
			s += sdf
		else:
			s += ' * '+ sdf
	s += ' * ' + str(m[1])
	return s

def get_total_change_len(a, k, ss):
	s = ''
	for (xx, x) in a[k][3]:
		s += get_key_len(a,k,x,ss) + ' + '
	s = s[:-3]
	return s

def ltos(ls):
	p = ''
	for l in ls:
		p += l
	return p

def pox_add_action(a, path):
	f = open('pox/nc_used.py','r')
	w = open(path + '/pox/openflow/nc.py', 'w')
	myline = f.readlines()
	for line in myline[:20]:
		w.write(line)
	w.write('\t\t\t"NC_NULL",\n')
	for k in a['keys']:
		w.write('\t\t\t"NC_'+k.upper()+'",\n')
	for line in myline[20:30]:
		w.write(line)
	for k in a['keys']:
		w.write('class nc_action_' + k +' (of.ofp_action_vendor_base):\n')
		w.write(ltos(myline[31:33]))
		w.write('\t\tself.subtype = NC_'+k.upper() + '\n')
		for (xx,x) in a[k][2]:
			w.write('\t\tself.'+x+' = 0\n')
		for (yy,y) in a[k][3]:
			w.write('\t\tself.'+y+' = []\n')
		w.write(ltos(myline[34:42]))
		p = '!'
		pa = ""
		for (xx,x) in a[k][2]:
			m = a[k][0][x]
			if m == 1:
				c = 'B'
			elif m == 2:
				c = 'H'
			elif m == 4:
				c = 'I'
			elif m == 8:
				c = 'Q'
			p += c
			pa += ', self.'+x
		w.write('\t\t'+'p += struct.pack("' + p + '"'+ pa+')\n')
		for (xx,x) in a[k][3]:
			u = a[k][1][x]
			m = u[1]
			p = 'p += struct.pack("!'
			if m == 1:
				c = 'B'
			elif m == 2:
				c = 'H'
			elif m == 4:
				c = 'I'
			elif m == 8:
				c = 'Q'
			p += c + '", self.'+ x
			if u[0] == 1:
				w.write('\t\tfor i in range(self.'+u[2]+'):\n')
				w.write('\t\t\t'+p+'[i])\n')
			elif u[0] == 2:
				w.write('\t\tfor i in range(self.'+u[3]+'):\n')
				w.write('\t\t\tfor j in range(self.'+u[2]+'):\n')
				w.write('\t\t\t\t'+p+'[i][j])\n')

		p = 'j = 2 + '
		m = 0
		q = ''
		for x in a[k][0].keys():
			m = m + a[k][0][x]
		q += str(m)
		if len(a[k][3]) > 0:
			m = get_total_change_len(a,k,'self.')
			q += ' + ' + m
		w.write('\t\t'+ p + q +'\n')
		w.write(ltos(myline[42:51]))
		w.write('\t\t'+ 'j = ' + q +'\n')
		w.write(ltos(myline[52:56]))
	f.close()
	w.close()

openvswitch_add_tag = ['/* by Liu Sicheng */\n','/* End by Liu Sicheng */\n','#if 0 /* Recover need by Liu Sicheng */\n', '#endif /* End by Liu Sicheng*/\n']

need_user_add = '/* by Liu Sicheng need to add code */\n'

# here s,e is line numbers in vim
# here is [s,e]
END_OF_FILE = 100000
def comment_lines(s,e):
	a = {}
	a[s-1] = openvswitch_add_tag[2]
	a[e] = openvswitch_add_tag[3]
	return a

def insert_lines(p, ls):
	a = {}
	a[p-1] = openvswitch_add_tag[0] + ls + openvswitch_add_tag[1]
	return a

def mix_ins(ins1, ins2):
	for k in ins2.keys():
		if k in ins1.keys():
			ins1[k] += ins2[k]
		else:
			ins1[k] = ins2[k]
	return ins1

def insert_into_file(path, ins):
	f = open(path, 'r')
	lines = f.readlines()
	f.close()
	content = ''
	for i in range(len(lines)):
		if i in ins.keys():
			content += ins[i]
		content += lines[i]
	if END_OF_FILE - 1 in ins.keys():
		content += ins[END_OF_FILE - 1]
	w = open(path, 'w')
	w.write(content)
	w.close()
	
def openvswitch_add_openflow_header(a, path):
	f = open("openvswitch/openflow-nc.h", 'r')
	w = open(path, 'w')
	words_len = {1:'uint8_t',2:'ovs_be16',4:'ovs_be32',8:'ovs_be64'}
	lines = f.readlines()
	ss = ''
	ss += ltos(lines[:21])
	for k in a['keys']:
		ss += '\tNC_'+k.upper()+',\n'
	ss += ltos(lines[21:34])
	for k in a['keys']:
		ss += 'struct nc_action_'+k+' {\n'
		ss += ltos(lines[35:39])
		total = 2
		pad = ['pad1','pad2','pad3', 'pad4']
		for (xx, x) in a[k][2]:
			m = a[k][0][x]
			total += m
			if total != total/m*m:
				# need some pad to fill the hole
				ak = m  + total/m*m - total
				ss += '\t'+words_len[1]+' '+ pad.pop(0)+'['+str(ak)+'];\n'
			ss += '\t'+words_len[m]+' '+x+';\n'
		ak = 8 + total/8*8 -total
		if ak == 8:
			ak = 0
		if len(a[k][3]) != 0:
			ss += '\t'+ words_len[1]+' '+ 'dataasdf['+str(ak)+'];\n'
		elif ak != 0 :
			ss += '\t' + words_len[1] + ' ' + pad.pop(0) + '['+str(ak)+'];\n'
		ss += lines[39]
	ss += lines[40]
	f.close()
	w.write(ss)
	w.close()

def openvswitch_change_openflow_header(a, path):
	ins = insert_lines(23, '#include "openflow/openflow-nc.h"\n')
	insert_into_file(path, ins)

def openvswitch_change_ofp_msgs(a, path):
	ss = ''
	for l1 in open('openvswitch/ofp-msgs.c'):
		ss += l1
	ins = insert_lines(170, ss)
	insert_into_file(path, ins)

def openvswitch_change_ofp_util_def(a, path):
	ss = ''
	ss += '#ifndef NC_ACTION\n'
	ss += '#define NC_ACTION(ENUM, STRUCT, EXTENSIBLE, NAME)\n'
	ss += '#endif\n'
	for k in a['keys']:
		ss += 'NC_ACTION(NC_'+k.upper()+', nc_action_'+k+', '
		if len(a[k][3]) == 0:
			n = '0'
		else :
			n = '1'
		ss += n + ', "nc_'+k+'")\n'
	ss += '#undef NC_ACTION\n'
	ins = insert_lines(END_OF_FILE, ss)
	insert_into_file(path, ins)

def openvswitch_change_ofp_actions_header(a, path):
	f = open('openvswitch/ofp-actions.h','r')
	lines = f.readlines()
	f.close()
	ss = ltos(lines[:45])
	ss = ss[:-1]
	for k in a['keys']:
		ss += '\\\n'
		ss += '\tDEFINE_OFPACT(' + k.upper()+',\tofpact_' + k + ',\t'
		if len(a[k][3]) == 0:
			ss += 'ofpact'
		else:
			ss += 'dataasdf'
		ss += ')\t'
	ss += '\n'
	ss += ltos(lines[45:])
	ins = comment_lines(51,103)
	mix_ins(ins,  insert_lines(104, ss))
	ss = '/* the smae as openvswitch.h but add some head */\n'
	words_len = {1:'uint8_t',2:'uint16_t',4:'uint32_t',8:'uint64_t'}
	pad = ['pad1','pad2','pad3', 'pad4']
	for k in a['keys']:
		ss += 'struct ofpact_' + k + ' {\n'
		ss += '\tstruct ofpact ofpact;\n'
		for (xx, x) in a[k][2]:
			m = a[k][0][x]
			ss += '\t'+words_len[m]+' '+x+';\n'
		if len(a[k][3]) != 0:
			"""
			for (xx, x) in a[k][3]:
				ss += '\t'+ words_len[a[k][1][x][1]] + ' *' + x + ';\n'
			"""
			ss += '\t'+ words_len[1]+' '+ 'dataasdf['+str(0)+'];\n'
		ss += '};\n\n'
	mix_ins(ins, insert_lines(441, ss))
	insert_into_file(path, ins)


def openvswitch_change_ofp_actions(a, path):

	words_len = {1:'uint8_t',2:'uint16_t',4:'uint32_t',8:'uint64_t'}

	ss = '\t} else if (a->vendor.vendor == CONSTANT_HTONL(NC_VENDOR_ID)) {\n'
	ss += '\t\treturn decode_nc_action(a, code);\n'
	ins = insert_lines(228, ss)
	
	f = open('openvswitch/ofp-actions.c')
	lines = f.readlines()
	f.close()
	ss = ltos(lines[:21])
	mix_ins(ins, insert_lines(219, ss))
	
	ss = '#define NC_ACTION(ENUM, STRUCT, EXTENSIBLE, NAME) case OFPUTIL_##ENUM:\n'
	ss += '#include "ofp-util.def"\n'
	ss += '\treturn ofpact_from_nc(a, code, out);\n'
	mix_ins(ins, insert_lines(485, ss))
	
	ss = ''
	for k in a['keys']:
		ss += 'static enum ofperr\n'
		ss += 'nc_' + k + '_from_openflow(const struct nc_action_' + k + ' *nca,\n'
		ss += '\tstruct ofpbuf *out)\n'
		ss += '{\n'
		ss += '\tunsigned int data_len;\n'
		"""
		ss += '\tchar *p;\n'
		ss += '\tint i;\n'
		"""
		ss += '\tstruct ofpact_'+k+' *s = ofpact_put_'+k.upper()+'(out);\n';
		for (xx,x) in a[k][2]:
			ss += '\ts->' + x + ' = ' + ntohfunction[a[k][0][x]]('nca->'+x) + ';\n'
		if len(a[k][3]) > 0:
			ss += '\tdata_len = ' + get_total_change_len(a, k, 'nca->')+';\n'
			ss += '\tofpbuf_put(out, nca->dataasdf, data_len);\n'
			ss += '\ts->ofpact.len += data_len;\n'
			"""
			ss += '\tp = s->dataasdf;\n'
			for (xx, x) in a[k][3]:
				ss += '\ts->'+x+' = p;\n'
				if a[k][1][x][1] == 1:
					ss += '\tp += ' + get_key_len(a,k,x,'s->') + ';\n'
				else:
					if a[k][1][x][0] == 1:
						s = 's->' + a[k][1][x][2]
					elif a[k][1][x][0] == 2:
						s = 's->' + a[k][1][x][2] + '*s->' + a[k][1][x][3]
					else:
						raise Exception
					ss += '\t' + 'for(i=0;i<'+s+';i++,p+='+str(a[k][1][x][1])+'){\n'
					ss += '\t' +'\ts->'+x+'[i] = '+ ntohfunction[a[k][1][x][1]]('*('+words_len[a[k][1][x][1]]+' *)p')+';\n'
					ss += '\t' + '}\n'
			"""
		ss += '\treturn 0;\n'
		ss += '}\n\n'
	ss += 'static enum ofperr\n'
	ss += 'ofpact_from_nc(const union ofp_action *a, enum ofputil_action_code code,\n'
	ss += '\t\t\tstruct ofpbuf *out)\n'
	ss += '{\n'
	ss += '\tenum ofperr error = 0;\n'
	ss += '\tswitch(code) {\n'
	for k in a['keys']:
		ss += '\tcase OFPUTIL_NC_' + k.upper()+':\n'
		ss += '\t\terror = nc_'+k+'_from_openflow((const struct nc_action_' + k + ' *)a, out);\n'
		ss += '\t\tbreak;\n'
	ss += '\t}\n'
	ss += '\treturn error;\n'
	ss += '}\n\n'
	mix_ins(ins, insert_lines(408, ss))
	
	ss = ''
	for k in a['keys']:
		ss += '\tcase OFPACT_'+ k.upper() + ':\n'
	ss += '\t\treturn 0;\n'
	mix_ins(ins, insert_lines(1108, ss))
	'''
	ss = ''
	for k in a['keys']:
		ss += 'static void\n'
		ss += 'ofpact_' + k + '_to_nc(const struct ofpact_'+k+' *a, struct ofpbuf *out)\n'
		ss += '{\n'
		ss += '\tstruct nc_action_' +k +' *tmpnc;\n'
		ss += '\ttmpnc = ofputil_put_NC_'+k.upper()+'(out);\n'
		for (xx,x) in a[k][2]:
			ss += '\ttmpnc->'+x+' = '+ htonfunction[a[k][0][x]]('a->'+x)+';\n'
		if len(a[k][3]) > 0:
			ss += '\tadd_len = ' + get_total_change_len(a, k, 'a->') + ';\n'
			ss += '\tofpbuf_put_zeros(out, ROUND_UP(add_len, OFP_ACTION_ALIGN));\n'
			ss += '\tmemcpy(tmpnc->dataasdf, a->dataasdf, add_len);\n'
			ss += '\ttmpnc->len = htons(sizeof(*tmpnc) + ROUND_UP(add_len, OFP_ACTION_ALIGN);\n'
	ss += 'static void\n'
	ss += 'ofpact_to_nc(const struct ofpact *a, struct ofpbuf *out)\n'
	ss += '{\n'
	ss += '\tswitch (a->type) {\n'
	for k in a['keys']:
		ss += '\tcase OFPACT_' + k.upper() + ':\n'
		ss += '\t\tofpact_' + k +'_to_nc(ofpact_get_'+k.upper()+'(a), out);\n'
		ss += '\t\tbreak;\n'
	ss += '\t}\n'
	ss += '}\n'
	mix_ins(ins, insert_lines(1397,ss))

	ss = ''
	for k in a['keys']:
		ss += '\tcase OFPACT_' + k.upper() + ':\n'
	ss += '\t\tofpact_to_nc(a,out);\n'
	ss += '\t\tbreak;'
	mix_ins(ins, insert_lines(1483,ss))
	'''
	insert_into_file(path, ins)

def openvswitch_change_ofp_util_header(a, path):
	f = open('openvswitch/ofp-util.c.h', 'r')
	lines = f.readlines()
	f.close()
	ss = ltos(lines[26:62])
	for k in a['keys']:
		ss +=' * OFPUTIL_NC_' + k.upper() + '\n'
	ss += ltos(lines[62:])
	ins = insert_lines(520, ss)
	
	mix_ins(ins, comment_lines(521, 561))

	ss = lines[0]
	mix_ins(ins, insert_lines(567,ss))

	ss = lines[1]
	mix_ins(ins, insert_lines(575,ss))

	ss = ltos(lines[2:5])
	mix_ins(ins, insert_lines(606,ss))
	
	insert_into_file(path, ins)
	
def openvswitch_change_ofp_util(a, path):
	f = open('openvswitch/ofp-util.c.h', 'r')
	lines = f.readlines()
	f.close()
	ss = lines[5]
	ins = insert_lines(3701,ss)

	ss = ltos(lines[6:8])
	mix_ins(ins, insert_lines(3732, ss))

	ss = ltos(lines[8:27])
	mix_ins(ins, insert_lines(3773, ss))

	insert_into_file(path, ins)

def openvswitch_change_ofproto_dpif(a, path):
	ss = ''
	for k in a['keys']:
		ss += 'static void\n'
		ss += 'xlate_nc_'+k+'_action(struct action_xlate_ctx *ctx,\n'
		ss += '\t\tconst struct ofpact *a)\n'
		ss += '{\n'
		ss += '\tnl_msg_put_unspec(ctx->odp_actions, OVS_ACTION_ATTR_'+k.upper()+',\n'
		ss += '\t\ta+1, a->len - sizeof(struct ofpact));\n'
		ss += '}\n'
	ins = insert_lines(5441,ss)

	ss = ''
	for k in a['keys']:
		ss += '\t\tcase OFPACT_'+k.upper()+':\n'
		ss += '\t\t\txlate_nc_'+k+'_action(ctx, a);\n'
		ss += '\t\t\tbreak;\n'
	mix_ins(ins, insert_lines(5626,ss))

	insert_into_file(path, ins)

def openvswitch_change_openvswitch_header(a, path):
	words_len = {1:'__u8',2:'__u16',4:'__u32',8:'__u64'}
	ss = ''
	for k in a['keys']:
		ss += 'struct ovs_action_' + k + ' {\n'
		for (xx, x) in a[k][2]:
			ss += '\t' + words_len[a[k][0][x]] + ' ' + x + ';\n'
		if len(a[k][3]) != 0:
			"""
			for (xx, x) in a[k][3]:
				ss += '\t'+ words_len[a[k][1][x][0]] + ' *' + x + ';\n'
			"""
			ss += '\t'+ words_len[1]+' '+ 'dataasdf['+str(0)+'];\n'
		ss += '};\n'
	ins = insert_lines(476, ss)

	ss = ''
	for k in a['keys']:
		ss += '\tOVS_ACTION_ATTR_'+k.upper()+',\n'
	mix_ins(ins, insert_lines(504, ss))

	insert_into_file(path,ins)

def print_actions(a, k, head):
	s = head + 'char debug[2048];\n'
	s += head + 'char asdf[1024];\n'
	s += head + 'int i;\n'
	s += head + 'char *p=nc->dataasdf;\n'
	s += head + 'sprintf(asdf, "nc_' + k +':'
	for (xx,x) in a[k][2]:
		s+= x+'=%d,'
	s = s[:-1] + '"'
	for (xx,x) in a[k][2]:
		s+= ', nc->'+x
	s += ');\n'
	s += head+ 'strcat(debug, asdf);\n'
	for (xx,x) in a[k][3]:
		if a[k][1][x][0] == 1:
			s += head + 'strcat(debug,"nc->'+ x +':");\n'
			s += head + 'nc_print_vector(debug, p, nc->'+a[k][1][x][2]+', '+str(a[k][1][x][1]) + ');\n'
			s += head + 'p += nc->' + a[k][1][x][2] + ' * ' + str(a[k][1][x][1]) + ';\n'
		elif a[k][1][x][0] == 2:
			s += head + 'for(i=0;i<nc->'+a[k][1][x][3]+';i++){\n'
			s += head +'\tnc_print_vector(debug, p, nc->'+a[k][1][x][2]+','+str(a[k][1][x][1]) + ');\n'
			s += head + '\tp += nc->' + a[k][1][x][2] + ' * ' + str(a[k][1][x][1]) + ';\n'
			s += head +'}\n'
		else:
			raise Exception
	s += head + 'printk(KERN_INFO "%s\\n",debug);\n'
	return s

def openvswitch_change_datapath_actions(a, path):
	ss = ''
	f = open('openvswitch/print_nc.c','r')
	lines = f.readlines()
	f.close()
	ss += ltos(lines)
	for k in a['keys']:
		ss += 'static int nc_'+k+'(struct datapath *dp, struct sk_buff *pk, \n'
		ss += '\t\tstruct ovs_action_' + k + ' *nc, bool *keep_skb)\n'
		ss += '{\n'
		ss += need_user_add
		ss += print_actions(a,k,'\t')
		ss += '\treturn 0;\n'
		ss += '}\n'
	ins = insert_lines(485 ,ss)

	ss = ''
	for k in a['keys']:
		ss += '\t\tcase OVS_ACTION_ATTR_'+k.upper()+':\n'
		ss += '\t\t\terr = nc_'+k+'(dp, skb, nla_data(a), &keep_skb);\n'
		ss += '\t\t\tbreak;\n'
	mix_ins(ins, insert_lines(534,ss))

	insert_into_file(path, ins)

def openvswitch_change_datapath_datapath(a, path):
	f = open('openvswitch/datapath.c','r')
	lines = f.readlines()
	f.close()
	ins = comment_lines(827,836)

	ss = ltos(lines)
	ss = ss[:-1]
	for k in a['keys']:
		ss += ',\n'
		ss += '\t\t\t[OVS_ACTION_ATTR_' + k.upper() + '] = '
		if len(a[k][3]) > 0:
			ss += '(u32) - 1'
		else:
			ss += 'sizeof(struct ovs_action_' + k + ') '
	ss += '\n\t\t};\n'
	mix_ins(ins, insert_lines(826, ss))

	ss = ''
	for k in a['keys']:
		ss += '\t\tcase OVS_ACTION_ATTR_'+k.upper()+':\n'
	ss += '\t\t\tbreak;\n'
	mix_ins(ins, insert_lines(886, ss))

	insert_into_file(path, ins)

def automake_change_include_openflow(a, path):
	ins = {}
	ss = '\tinclude/openflow/openflow-nc.h \\\n' 
	ins[5] = ss
	insert_into_file(path, ins)

def automake_clean_include_openflow(path):
	f = open(path, 'r')
	lines = f.readlines()
	f.close()
	content = ''
	i = 0
	for l in lines:
		i += 1
		if i != 6:
			content += l
	w = open(path, 'w')
	w.write(content)
	w.close()



changed_openvswitch_file = {
		openvswitch_change_openflow_header:'/include/openflow/openflow.h',
		openvswitch_change_ofp_msgs:'/lib/ofp-msgs.c',
		openvswitch_change_ofp_util_def:'/lib/ofp-util.def',
		openvswitch_change_ofp_actions_header:'/lib/ofp-actions.h',
		openvswitch_change_ofp_actions:'/lib/ofp-actions.c',
		openvswitch_change_ofp_util_header:'/lib/ofp-util.h',
		openvswitch_change_ofp_util:'/lib/ofp-util.c',
		openvswitch_change_ofproto_dpif:'/ofproto/ofproto-dpif.c',
		openvswitch_change_openvswitch_header:'/include/linux/openvswitch.h',
		openvswitch_change_datapath_actions:'/datapath/actions.c',
		openvswitch_change_datapath_datapath:'/datapath/datapath.c'
		}

changed_openvswitch_automake = {
		automake_change_include_openflow:('/include/openflow/automake.mk',automake_clean_include_openflow)
		}

add_openvswitch_file = {
		openvswitch_add_openflow_header:'/include/openflow/openflow-nc.h'
		}

def openvswitch_add_action(a, path):
	for k in changed_openvswitch_file.keys():
		k(a, path+changed_openvswitch_file[k])
		print 'change_file:' + changed_openvswitch_file[k]
	for k in add_openvswitch_file.keys():
		k(a, path+add_openvswitch_file[k])
	for k in changed_openvswitch_automake.keys():
		k(a, path+changed_openvswitch_automake[k][0])
	return

def clean_openvswitch_file(path, tags):
	f = open(path, 'r')
	lines = f.readlines()
	f.close()
	content = ''
	state = 0
	for l in lines:
		if l in tags:
			i = tags.index(l) + 1
		else :
			i = 0
		if state == 0 and i == 0:
			content += l
		elif state == 2 and i == 0:
			content += l
		if i == 1:
			state = 1
		elif i == 2:
			state = 0
		elif i == 3:
			state = 2
		elif i == 4:
			state = 0
	w = open(path, 'w')
	w.write(content)
	w.close()

def clean_openvswitch(path):
	for k in changed_openvswitch_file.keys():
		clean_openvswitch_file(path+changed_openvswitch_file[k], openvswitch_add_tag)
	for k in add_openvswitch_file.keys():
		os.system('rm '+ path + add_openvswitch_file[k])
	for k in changed_openvswitch_automake.keys():
		changed_openvswitch_automake[k][1](path+changed_openvswitch_automake[k][0])
	return

def help():
	print "please read code carefully!!"
	print "if no wrong is print out and still cannot work, please check whether the file can be written or there"
	print "argv:  action_add.py structure_file [pox|openvswitch] software_location"
	print "argv:  action_add.py clean_ovs software_location"
	print "software_name here is just support 'pox' and 'openvswitch'"
	print "here we just support pox version update at 2013-3-21 commit: 4ffe87c54df687593c70de731c6009cfc3254e1a "
	print "here we just support openvswitch version update at Date:   Tue Feb 26 11:24:20 2013 -0800  commit: a83d19d7581c083b84a611a1bf4286989656f52c"
	raise Exception


print sys.argv
print len(sys.argv)
if len(sys.argv) < 3:
	help()
elif sys.argv[2] == 'pox' and len(sys.argv) == 4:
	a = read_struct(sys.argv[1])
	pox_add_action(a, sys.argv[3])
elif sys.argv[2] == 'openvswitch' and len(sys.argv) == 4:
	a = read_struct(sys.argv[1])
	openvswitch_add_action(a, sys.argv[3])
elif sys.argv[1] == 'clean_ovs' and len(sys.argv) == 3:
	clean_openvswitch(sys.argv[2])
else:
	help()
