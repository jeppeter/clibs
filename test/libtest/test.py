#! /usr/bin/env python

import extargsparse
import sys
import os
import logging
import re
import shutil
import logging.handlers
import time
import traceback
import socket

def set_logging(args):
	loglvl= logging.ERROR
	if args.verbose >= 3:
		loglvl = logging.DEBUG
	elif args.verbose >= 2:
		loglvl = logging.INFO
	curlog = logging.getLogger(args.lognames)
	#sys.stderr.write('curlog [%s][%s]\n'%(args.logname,curlog))
	curlog.setLevel(loglvl)
	if len(curlog.handlers) > 0 :
		curlog.handlers = []
	formatter = logging.Formatter('%(asctime)s:%(filename)s:%(funcName)s:%(lineno)d<%(levelname)s>\t%(message)s')
	if not args.lognostderr:
		logstderr = logging.StreamHandler()
		logstderr.setLevel(loglvl)
		logstderr.setFormatter(formatter)
		curlog.addHandler(logstderr)

	for f in args.logfiles:
		flog = logging.FileHandler(f,mode='w',delay=False)
		flog.setLevel(loglvl)
		flog.setFormatter(formatter)
		curlog.addHandler(flog)
	for f in args.logappends:		
		if args.logrotate:
			flog = logging.handlers.RotatingFileHandler(f,mode='a',maxBytes=args.logmaxbytes,backupCount=args.logbackupcnt,delay=0)
		else:
			sys.stdout.write('appends [%s] file\n'%(f))
			flog = logging.FileHandler(f,mode='a',delay=0)
		flog.setLevel(loglvl)
		flog.setFormatter(formatter)
		curlog.addHandler(flog)
	return

def load_log_commandline(parser):
	logcommand = '''
	{
		"verbose|v" : "+",
		"logname" : "root",
		"logfiles" : [],
		"logappends" : [],
		"logrotate" : true,
		"logmaxbytes" : 10000000,
		"logbackupcnt" : 2,
		"lognostderr" : false
	}
	'''
	parser.load_command_line_string(logcommand)
	return parser


def listen_handler(args,parser):
	set_logging(args)
	port = int(args.subnargs[0])
	sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	sock.setsockopt( socket.SOL_SOCKET, socket.SO_REUSEADDR, 1 )
	sock.bind(('0.0.0.0',port))
	logging.info('listen on [%s]'%(port))
	sock.listen(5)

	while True:
		try:
			clisock, cliaddr = sock.accept()
			logging.info('come %s'%(repr(cliaddr)))
			clisock.close()
			clisock = None
		except KeyboardInterrupt:
			break
		except:
			logging.warn('%s'%(traceback.format_exc()))

	sys.exit(0)
	return


def main():
	commandline='''
	{
		"listen<listen_handler>## port to listen on port##" : {
			"$" : 1
		}
	}
	'''
	parser = extargsparse.ExtArgsParse()
	parser.load_command_line_string(commandline)
	load_log_commandline(parser)
	parser.parse_command_line(None,parser)
	raise Exception('can not reach here')
	return

if __name__ == '__main__':
	main()