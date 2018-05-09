#! /usr/bin/env python

import extargsparse
import sys
import logging
import importlib
import re
import os


def debug_set_2_args(args,validx,keycls,params):
	if (validx + 1) >= len(params):
		raise Exception('need 2 args')
	value = getattr(args,keycls.optdest,None)
	if value is None:
		value = []
	value.append(params[validx])
	value.append(params[validx+1])
	setattr(args,keycls.optdest,value)
	return 2

def debug_opthelp_set(keycls):
    return 'opthelp function set [%s] default value (%s)'%(keycls.optdest,keycls.value)

def debug_2_jsonfunc(args,keycls,value):
    if not isinstance(value,list):
        raise Exception('not list value')
    if (len(value) % 2) != 0:
        raise Exception('not even sized')
    setvalue = []
    i = 0
    while i < len(value):
        setvalue.append(value[i])
        i += 2
    setattr(args,keycls.optdest,setvalue)
    return

def debug_upper_jsonfunc(args,keycls,value):
    valid = False
    if isinstance(value,str) or (sys.version[0] == '2' and isinstance(value,unicode)) or value is None:
        valid = True
    if not valid :
        raise Exception('not valid string')
    setvalue = None
    if value is not None:
        setvalue = value.upper()
    setattr(args,keycls.optdest,setvalue)
    return


def __get_whole_name(cmdname,subname):
    retname = ''
    if cmdname is not None and len(cmdname) > 0:
        retname += cmdname
        if subname is not None:
            retname += '.'
    if subname is not None:
        retname += subname
    return retname

def quote_string(s):
	rets = ''
	if s is not None:
		for c in s:
			if c in ['\\','"','\'']:
				rets += '\\'
			rets += c
	return rets

def quote_array(arr):
	s = '['
	i = 0
	for c in arr:
		if i > 0:
			s += ','
		s += '"%s"'%(quote_string(c))
		i += 1
	s += ']'
	return s

def __debug_out_int(parser,args,opt):
	s = ''
	s += '%s=%d\n'%(opt.varname,getattr(args,opt.optdest,None))
	return s

def __debug_out_bool(parser,args,opt):
	s = ''
	val = getattr(args,opt.optdest,None)
	if val :
		s += '%s=True\n'%(opt.varname)
	else:
		s += '%s=False\n'%(opt.varname)
	return s

def __debug_out_list(parser,args,opt):
	s = ''
	val = getattr(args,opt.optdest,None)
	if val :
		s += '%s=%s\n'%(opt.varname,quote_array(val))
	else:
		s += '%s=[]\n'%(opt.varname)
	return s

def __debug_out_float(parser,args,opt):
	s = ''
	val = getattr(args,opt.optdest,None)
	s += '%s=%f\n'%(opt.varname,val)
	return s

def __debug_out_string(parser,args,opt):
	s = ''
	val = getattr(args,opt.optdest,None)
	if val is not None:
		s += '%s="%s"\n'%(opt.varname,quote_string(val))
	else:
		s += '%s=NULL\n'%(opt.varname)
	return s

def __debug_out_unicode(parser,args,opt):
	return __debug_out_string(parser,args,opt)

def __debug_out_count(parser,args,opt):
	return __debug_out_int(parser,args,opt)

def __debug_out_long(parser,args,opt):
	return __debug_out_int(parser,args,opt)

def __call_debug_out_function(parser,args,opt):
	funcname = '__debug_out_%s'%(opt.type)
	m = importlib.import_module(__name__)
	funcptr = getattr(m,funcname,None)
	if funcptr is None:
		raise Exception('can not get(%s)'%(funcname))
	return funcptr(parser,args,opt)

def __debug_out_args_inner(argsopt,parser,args,cmdname=None):
	s = ''
	cmdopts = parser.get_cmdopts(cmdname)
	if cmdopts is not None and len(cmdopts) > 0:
		for opt in cmdopts:
			if opt.type == 'args' or opt.type == 'help' or opt.type == 'jsonfile':
				continue
			s += __call_debug_out_function(parser,args,opt)
	subcmds = parser.get_subcommands(cmdname)
	if subcmds is not None and len(subcmds) > 0:
		for c in subcmds:
			curname = __get_whole_name(cmdname,c)
			s += __debug_out_args_inner(argsopt,parser,args,curname)
	return s



def debug_out_args(argsopt,parser,args,params):
	s = ''
	if args.subcommand is not None and len(args.subcommand) > 0:
		s += 'subcommand="%s"\n'%(quote_string(args.subcommand))
		s += 'subnargs=%s\n'%(quote_array(args.subnargs))
	else:
		s += 'subcommand=""\n'
		s += 'args=%s\n'%(quote_array(args.args))
	s += __debug_out_args_inner(argsopt,parser,args,None)
	return s

def read_command_json(inputfile=None):
    s = ''
    fin = sys.stdin
    if inputfile is not None and inputfile!= '-':
        fin = open(inputfile,'r')
    for l in fin:
        s += l
    if fin != sys.stdin:
        fin.close()
    fin = None
    logging.info('read json(%s)'%(s))
    return s

def output_file(s,outputfile=None):
	fout = sys.stdout
	if outputfile is not None and outputfile != '-':
		fout = open(outputfile,'w+a')
	fout.write('%s'%(s))
	if fout != sys.stdout:
		fout.close()
	return



def bindFunction(name,argsopt):
    def call_parseopt(args,ctx):
    	s = 'call handler function[%s]\n'%(call_parseopt.__name__)
    	output_file(s,argsopt.output)
    	return
    call_parseopt.__name__ = name
    m = importlib.import_module('__main__')
    setattr(m,name,call_parseopt)
    return call_parseopt


def __bind_handler_function(argsopt,parser,cmdname=None):
	keycls = parser.get_cmdkey(cmdname)
	if keycls is not None and keycls.function is not None:
		bindFunction(keycls.function,argsopt)
	subcmds = parser.get_subcommands(cmdname)
	if subcmds is not None and len(subcmds) > 0:
		for c in subcmds:
			curname = __get_whole_name(cmdname,c)
			__bind_handler_function(argsopt,parser,curname)
	return
 
def bind_all_handle_function(argsopt,parser):
	__bind_handler_function(argsopt,parser)
	return

def __set_environment_value(argsopt):
	for k in argsopt.environ:
		sarr = re.split('=',k,2)
		logging.info('sarr %s'%(sarr))
		os.environ[sarr[0]] = sarr[1]
	return

def __unset_environment_value(argsopt):
	for k in argsopt.environ:
		sarr = re.split('=',k,2)
		if sarr[0] in os.environ.keys():
			del os.environ[sarr[0]]
	return

def __get_priority(argsopt):
	priority = None
	if len(argsopt.priority) == 0 or (len(argsopt.priority) == 1 and argsopt.priority[0] == 'NONE'):
		pass
	else:
		priority = []
		for c in argsopt.priority:
			if c == 'SUBCMD_JSON' :
				priority.append(extargsparse.SUB_COMMAND_JSON_SET)
			elif c == 'CMD_JSON' :
				priority.append(extargsparse.COMMAND_JSON_SET)
			elif c == 'ENV_SUBCMD_JSON' :
				priority.append(extargsparse.ENV_SUB_COMMAND_JSON_SET)
			elif c == 'ENV_CMD_JSON':
				priority.append(extargsparse.ENV_COMMAND_JSON_SET)
			elif c == 'ENV_CMD' :
				priority.append(extargsparse.ENVIRONMENT_SET)
			elif c == 'NONE':
				break
			else:
				raise Exception('unknown priority (%s)'%(c))
	return priority

def read_file(infile=None):
	s = ''
	fin = sys.stdin
	if infile is not None:
		fin = open(infile,'rb')
	bmode = False
	if 'b' in fin.mode:
		bmode = True
	for l in fin:
		if sys.version[0] == '2' or not bmode:
			s += l
		else:
			s += l.decode(encoding='UTF-8')
	if fin != sys.stdin:
		fin.close()
	fin = None
	return s


def parse_format(argsopt,options,params):
	priority = __get_priority(argsopt)
	optstr = None
	if argsopt.extoptions is not None:
		optstr = read_file(argsopt.extoptions)
	logging.info('optstr (%s)'%(optstr))
	extoptions = extargsparse.ExtArgsOptions(optstr)
	if priority is not None:
		parser = extargsparse.ExtArgsParse(extoptions,priority)
	else:
		parser = extargsparse.ExtArgsParse(extoptions)
	argsopt.parser = parser
	parser.load_command_line_string(options)
	bind_all_handle_function(argsopt,parser)
	# now to make sure of the environment value
	__set_environment_value(argsopt)
	args = parser.parse_command_line(params,argsopt)
	__unset_environment_value(argsopt)
	return debug_out_args(argsopt,parser,args,params)

def set_log_level(args):
    loglvl= logging.ERROR
    if args.verbose >= 3:
        loglvl = logging.DEBUG
    elif args.verbose >= 2:
        loglvl = logging.INFO
    elif args.verbose >= 1 :
        loglvl = logging.WARN
    # we delete old handlers ,and set new handler
    logging.basicConfig(level=loglvl,format='%(asctime)s:%(filename)s:%(funcName)s:%(lineno)d\t%(message)s')
    return


def main():
	commandline='''
	{
		"verbose|v" : "+",
		"output|o" : null,
		"input|i" : null,
		"environ|E" : [],
		"extoptions|O" : null,
		"priority|p## priority set default ([]) value can be SUBCMD_JSON|CMD_JSON|ENV_SUBCMD_JSON|ENV_CMD_JSON|ENV_CMD|NONE##" : [],
		"$" : "*"
	}
	'''
	options = extargsparse.ExtArgsOptions()
	oldextargsloglevel = None
	if 'EXTARGSPARSE_LOGLEVEL' in os.environ.keys():
		oldextargsloglevel = os.environ['EXTARGSPARSE_LOGLEVEL']
		del os.environ['EXTARGSPARSE_LOGLEVEL']
	# we do not accept any other than command line input
	parser = extargsparse.ExtArgsParse(options,[])
	parser.load_command_line_string(commandline)
	args = parser.parse_command_line()
	if oldextargsloglevel is not None:
		os.environ['EXTARGSPARSE_LOGLEVEL'] = oldextargsloglevel
	set_log_level(args)
	options = read_command_json(args.input)
	s = parse_format(args,options,args.args)
	output_file(s,args.output)
	return

if __name__ == '__main__':
	main()