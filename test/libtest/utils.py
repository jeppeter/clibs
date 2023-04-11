#! /usr/bin/env python


import logging
import re
import extargsparse
import sys
import os
import json

sys.path.append(os.path.abspath(os.path.dirname(__file__)))
import fileop


def init_propmaps():
	newmaps = dict()
	newmaps['System.Devices.ModelId'] = ('80D81EA6-7473-4B0C-8216-EFC11A2C4C8B',2)
	newmaps['System.Devices.ModelName'] = ('656A3BB3-ECC0-43FD-8477-4AE0404A96CD',8194)
	newmaps['System.Devices.ModelNumber'] = ('656A3BB3-ECC0-43FD-8477-4AE0404A96CD',8195)
	newmaps['System.Devices.FriendlyName'] = ('656A3BB3-ECC0-43FD-8477-4AE0404A96CD',12288)
	newmaps['System.ItemNameDisplay'] = ('B725F130-47EF-101A-A5F1-02608C9EEBAC', 10)
	newmaps['System.Devices.DevNodeStatus'] = ('4340A6C5-93FA-4706-972C-7B648008A5A7',2)
	newmaps['System.Devices.ProblemCode'] = ('4340A6C5-93FA-4706-972C-7B648008A5A7',3)
	newmaps['System.Devices.EjectionRelations'] = ('4340A6C5-93FA-4706-972C-7B648008A5A7',4)
	newmaps['System.Devices.RemovalRelations'] = ('4340A6C5-93FA-4706-972C-7B648008A5A7',5)
	newmaps['System.Devices.PowerRelations'] = ('4340A6C5-93FA-4706-972C-7B648008A5A7',6)
	newmaps['System.Devices.BusRelations'] = ('4340A6C5-93FA-4706-972C-7B648008A5A7',7)
	newmaps['System.Devices.Parent'] = ('4340A6C5-93FA-4706-972C-7B648008A5A7', 8)

	return newmaps

PROP_MAPS = init_propmaps()


def usblist_handler(args,parser):
	fileop.set_logging(args)

	logging.info('will read [%s]'%(args.input))
	sb = fileop.read_file_bytes(args.input)
	logging.info('read over [%s]'%(args.input))
	s = sb.decode('utf-8')
	sarr = re.split('\n',s)
	logging.info('split over [%s]'%(args.input))
	matcharr = []
	if (len(args.subnargs) % 2) != 0:
		raise Exception('need guid index')
	cidx = 0
	dictmaps = []
	while cidx < len(args.subnargs):
		vals = []
		lidx = 0
		guidstr = re.sub('\\-','\\\\-',args.subnargs[cidx])
		indx = fileop.parse_int(args.subnargs[cidx + 1])
		exprstr = '.*property\\[\\{%s\\}\\]\\.\\[0x%x\\].*'%(guidstr,indx)
		logging.info('guidstr [%s] exprstr[%s]'%(guidstr,exprstr))
		guidexpr = re.compile(exprstr,re.I)
		matchexpr = re.compile('nindex\\[([0-9]+)\\]',re.I)
		stopexpr = re.compile('.*nindex\\[.*',re.I)
		propexpr = re.compile('PROP\\s+\\[([^\\]]+)\\]',re.I)
		searchstart = False
		kmaps = dict()
		for l in sarr:
			lidx += 1
			l = l.rstrip('\r')

			if not searchstart:
				if guidexpr.match(l):
					searchstart = True
					curprops = []
					#logging.info('[%d] matched [%s]'%(lidx, l))
					m = matchexpr.findall(l)
					if m is not None and len(m) > 0:
						v = fileop.parse_int(m[0])
						logging.info('[%s][%d] [%d]'%(args.subnargs[cidx],indx, v))
						vals.append(v)
						curidx = v
			else:
				m = propexpr.findall(l)
				if m is not None and len(m) > 0:
					curprops.append(m[0])
				elif stopexpr.match(l):
					searchstart = False
					kmaps['%d'%(curidx)] = curprops
					curprops = []
					if guidexpr.match(l):
						searchstart = True
						curprops = []
						m = matchexpr.findall(l)
						if m is not None and len(m) > 0:
							v = fileop.parse_int(m[0])
							logging.info('[%s][%d] [%d]'%(args.subnargs[cidx],indx, v))
							vals.append(v)
							curidx = v
		cidx += 2
		matcharr.append(vals)
		dictmaps.append(kmaps)

	vals = []
	if len(matcharr) < 2:
		vals = matcharr[0]
	else:
		# first to filter one
		idx = 0
		jdx = 0
		while idx < len(matcharr[0]) and jdx < len(matcharr[1]):
			curi = matcharr[0][idx]
			curj = matcharr[1][jdx]
			if curi > curj:
				jdx += 1
			elif curi < curj:
				idx += 1
			else:
				vals.append(curi)
				idx += 1
				jdx += 1

		isize = 2
		
		while isize < len(matcharr):
			nvals = []

			idx = 0
			jdx = 0
			while idx < len(vals) and jdx < len(matcharr[isize]):
				curi = vals[idx]
				curj = matcharr[isize][jdx]
				if curi > curj:
					jdx += 1
				elif curi < curj:
					idx += 1
				else:
					nvals.append(curi)
					idx += 1
					jdx += 1
			isize += 1
			vals = nvals		

	lidx = 0
	sys.stdout.write('size [%d]\n   '%(len(vals)))
	for l in vals:
		if lidx >= 5:
			sys.stdout.write('\n   ')
			lidx = 0
		sys.stdout.write(' %03s'%(l))
		lidx += 1
	sys.stdout.write('\n')

	isize = 0
	while isize < len(args.subnargs):
		curmaps = dictmaps[isize//2]
		for l in vals:
			k = '%d'%(l)
			if k in curmaps.keys():
				sys.stdout.write('%s=%s\n'%(k,curmaps[k]))
		isize += 2
	sys.exit(0)
	return

def get_guid_prop_value(l,getexpr):
	m = getexpr.findall(l)
	guidprop = None
	propidx = -1
	if m is not None and len(m) > 0 and len(m[0]) > 1:
		guidprop = m[0][0]
		propidx = int(m[0][1],16)
	return guidprop,propidx


def usbprop_handler(args,parser):
	fileop.set_logging(args)
	indx = fileop.parse_int(args.subnargs[0])
	indxexpr = re.compile('.*nindex\\[%d\\].*'%(indx),re.I)
	filterindexexpr = re.compile('.*nindex\\[([0-9]+)\\]',re.I)
	guidpropexprs = []
	if len(args.subnargs) % 2 != 1:
		raise Exception('need propguid or idx')
	cidx = 1
	while cidx < len(args.subnargs):
		guidstr = re.sub('\\-','\\\\-',args.subnargs[cidx])
		indx = fileop.parse_int(args.subnargs[cidx + 1])
		exprstr = '.*property\\[\\{%s\\}\\]\\.\\[0x%x\\].*'%(guidstr,indx)
		logging.info('guidstr [%s] exprstr[%s]'%(guidstr,exprstr))
		guidexpr = re.compile(exprstr,re.I)
		guidpropexprs.append(guidexpr)
		cidx += 2
	guidgetexpr = re.compile('property\\[\\{([^\\}]+)\\}\\]\\.\\[0x([a-f0-9A-F]+)\\]',re.I)
	propexpr = re.compile('PROP\\s+\\[([^\\]]+)\\]',re.I)
	sb = fileop.read_file_bytes(args.input)
	s = sb.decode('utf-8')
	sarr = re.split('\n',s)
	dictmap = dict()
	searchstart = False
	curpropguid = None
	curpropidx = -1
	for l in sarr:
		l = l.rstrip('\r\n')
		if not searchstart:
			if indxexpr.match(l):
				curvals = []
				bmatched = False
				if len(guidpropexprs) > 0:
					for e in guidpropexprs:
						if e.match(l):
							bmatched = True
							curpropguid,curpropidx = get_guid_prop_value(l,guidgetexpr)
							break
				else:
					curpropguid,curpropidx = get_guid_prop_value(l,guidgetexpr)
					bmatched = True
				if bmatched:
					searchstart = True
					curvals = []
		else:
			m = propexpr.findall(l)
			if m is not None and len(m) > 0:
				curvals.append(m[0])
			else:
				m = filterindexexpr.findall(l)
				if m is not None and len(m) > 0:
					dictmap['{%s}[%d]'%(curpropguid,curpropidx)] = curvals
					curpropguid = None
					curpropidx = -1
					curval = fileop.parse_int(m[0])
					searchstart = False
					if curval == indx:
						searchstart = True
						curvals = []
						curpropguid, curpropidx = get_guid_prop_value(l,guidgetexpr)
	for k in dictmap.keys():
		sys.stdout.write('%s=%s\n'%(k,dictmap[k]))
	sys.exit(0)

def main():
    commandline='''
    {
        "input|i" : null,
        "output|o" : null,
        "usblist<usblist_handler>##propguid idx ... to filter usb property##" : {
        	"$" : "+"
        },
        "usbprop<usbprop_handler>##usbindex [propguid] [idx] ... to list usb values##" : {
        	"$" : "+"
        }
    }
    '''
    parser = extargsparse.ExtArgsParse()
    parser.load_command_line_string(commandline)
    fileop.load_log_commandline(parser)
    parser.parse_command_line(None,parser)
    raise Exception('can not reach here')
    return

if __name__ == '__main__':
    main()    