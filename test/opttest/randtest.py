#! /usr/bin/env python


import os
import sys
import json
import random
import logging
import extargsparse
import time

lower_alphabet = 'abcdefghijklmnopqrstuvwxyz'
upper_alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
alphabets = lower_alphabet + upper_alphabet
number_chars = '0123456789'
start_chars =  alphabets
normal_chars = start_chars + number_chars
all_typesname = ['args','list','bool','string','float','int','long','ll','ull','command','prefix','count']
reserved_args = ['subcommand','subnargs','json','nargs','extargs','help','args']

dotchar = '.'
slashchar = '/'
backslashchar = '\\'
spacechar = ' '
lb_char = '('
rb_char = ')'
lB_char = '{'
rB_char = '}'
underscore_char = '_'

help_chars =  normal_chars + dotchar + spacechar + lb_char + rb_char + lB_char + rB_char + underscore_char + slashchar + backslashchar


def __get_tabs_line(fmt,tabs=0):
	s = ' ' * tabs * 4
	s += fmt
	s += '\n'
	return s

class KeyAttr(object):
    def __init__(self):
        self.__obj = dict()
        return

    def __setattr__(self,key,val):
        if not key.startswith('_'):
            self.__obj[key] = val
            return
        self.__dict__[key] = val
        return

    def __getattr__(self,key):
        if not key.startswith('_'):
            if key in self.__obj.keys():
                return self.__obj[key]
            return None
        return self.__dict__[key]

    def __str__(self):
        s = '!'
        for k in self.__obj.keys():
            s += '%s=%s;'%(k,self.__obj[k])
        s += '!'
        return s

    def __repr__(self):
        return self.__str__()


class KeyClass(object):
    def __init__(self):
        self.__obj = dict()
        return

    def __setattr__(self,key,val):
        if not key.startswith('_'):
            self.__obj[key] = val
            return
        self.__dict__[key] = val
        return

    def __getattr__(self,key):
        if not key.startswith('_'):
            if key in self.__obj.keys():
                return self.__obj[key]
            return None
        return self.__dict__[key]

    def __str__(self):
        s = '{'
        for k in self.__obj.keys():
            s += '%s=%s;'%(k,self.__obj[k])
        s += '}'
        return s

    def __repr__(self):
        return self.__str__()

    def __format_opt(self):
    	s = ''
    	if self.shortflag is not None:
    		s += '%s|%s'%(self.flagname,self.shortflag)
    	elif self.type != 'args' and self.flagname != '$':
    		if isinstance(self.value,dict):
	    		s += '$%s'%(self.flagname)
	    	else:
	    		s += '%s'%(self.flagname)
    	else:
    		s += '$'

    	if self.varname is not None:
    		s += '<%s>'%(self.varname)

    	if self.attr is not None:
    		s += '%s'%(self.attr)

    	if self.helpinfo is not None:
    		s += '##%s##'%(self.helpinfo)
    	return s

    def __format_prefix(self):
    	s = ''
    	s += '+%s'%(self.prefix)
    	if self.attr is not None:
    		s += '%s'%(self.attr)
    	if self.helpinfo is not None:
    		s += '##%s##'%(self.helpinfo)
    	return s

    def __format_command(self):
    	s = ''
    	s += self.cmdname

    	if self.function is not None:
    		s += '<%s>'%(self.function)
    	if self.attr is not None:
    		s += '%s'%(self.attr)

    	if self.helpinfo is not None:
    		s += '##%s##'%(self.helpinfo)
    	return s



    def __check_self(self):
    	if self.isflag is not None:
    		if self.flagname == '$':
    			assert(self.shortflag is None)
    		if self.flagname is not None:
    			pass
    		elif self.prefix is not None:
    			pass
    		else:
    			raise Exception('flag not defined')
    	elif self.iscmd is not None:
    		if self.cmdname is not None:
    			pass
    		else:
    			raise Exception('cmd not defined')
    	else:
    		raise Exception('nothing defined')

    def key(self):
    	s = ''
    	self.__check_self()
    	if self.isflag is not None:
    		if self.flagname is not None:
    			s += self.__format_opt()
    		elif self.prefix is not None:
    			s += self.__format_prefix()
    		else:
    			raise Exception('nothing handle for flag set')
    	elif self.iscmd is not None:
    		s += self.__format_command()
    	else:
    		raise Exception('not set cmd')
    	return s

def generate_start_char():
	n = random.randint(0,len(start_chars)-1)
	return start_chars[n]

def generate_alpha_char():
	n = random.randint(0,len(alphabets)-1)
	return alphabets[n]

def generate_normal_char():
	n = random.randint(0,len(normal_chars)-1)
	return normal_chars[n]

def generate_help_char():
	n = random.randint(0,len(help_chars)-1)
	return help_chars[n]

def generate_shortopt():
	n = random.randint(0,len(alphabets)-1)
	return alphabets[n]


def generate_longopt(maxsize):
	numchar = random.randint(2,maxsize)
	s = generate_shortopt()
	i = 1
	while i < numchar:
		s += generate_shortopt()
		i += 1
	return s

def generate_normal_chars(maxsize):
	numchar = random.randint(0,maxsize)
	s = ''
	i = 0
	while i < numchar:
		s += generate_normal_char()
		i += 1
	return s

def generate_helpinfo(maxsize):
	numchar = random.randint(1,maxsize)
	s = ''
	i = 0
	while i < numchar:
		s += generate_help_char()
		i += 1
	return s

def is_ok():
	n = random.randint(0,1)
	if n > 0:
		return True
	return False


def generate_args_member():
	n = random.randint(-3,100)
	if n == -3:
		return '*'
	elif n == -2:
		return '?'
	elif n == -1:
		return '+'
	else:
		return n

def generate_basic_flag():
	keycls = KeyClass()	
	keycls.isflag = True
	keycls.flagname = generate_longopt(32)
	if is_ok():
		keycls.shortflag = generate_shortopt()
	if is_ok():
		keycls.helpinfo = generate_helpinfo(100)
	if is_ok():
		attr = KeyAttr()
		numkeys = random.randint(0,32)
		for k in xrange(numkeys):
			key = generate_longopt(30)
			value = generate_helpinfo(30)
			setattr(attr,key,value)
		keycls.attr = attr
	return keycls

def generate_string():
	keycls = generate_basic_flag()
	keycls.type = 'string'
	numchar = random.randint(0,100)
	if numchar > 0:
		keycls.value = generate_helpinfo(numchar)
	return keycls

def generate_bool():
	keycls = generate_basic_flag()
	keycls.type = 'bool'
	if is_ok():
		keycls.value = True
	else:
		keycls.value = False

	return keycls

def generate_int():
	keycls = generate_basic_flag()
	keycls.type = 'int'
	keycls.value = random.randint(0,0xffffffff)
	return keycls

def generate_ll():
	keycls  = generate_basic_flag()
	keycls.type = 'long'
	if keycls.attr is None:
		keycls.attr = KeyAttr()
	keycls.attr.type = 'll'
	keycls.value = random.randint(-0x7fffffffffffffff,0x7fffffffffffffff)
	return keycls

def generate_ull():
	keycls  = generate_basic_flag()
	keycls.type = 'long'
	if keycls.attr is None:
		keycls.attr = KeyAttr()
	keycls.attr.type = 'ull'
	keycls.value = random.randint(0,0xffffffffffffffff)
	return keycls

def generate_float():
	keycls = generate_basic_flag()
	keycls.type = 'float'
	exps = random.randint(0,50)
	fltval = random.random()
	fltval = fltval * (10 ** exps)
	keycls.value = fltval
	return keycls

def generate_args():
	keycls = KeyClass()
	keycls.flagname = '$'
	keycls.type = 'args'
	keycls.isflag = True
	keycls.value = generate_args_member()
	return keycls


def generate_command():
	keycls = KeyClass()
	keycls.type = 'command'
	keycls.iscmd = True
	keycls.cmdname = generate_longopt(30)
	return keycls

def generate_prefix():
	keycls = KeyClass()
	keycls.type = 'prefix'
	keycls.isflag = True
	keycls.prefix = generate_longopt(30)
	return keycls

def generate_count():
	keycls = generate_basic_flag()
	keycls.type = 'count'
	keycls.value = '+'
	return keycls

def generate_list():
	keycls = generate_basic_flag()
	keycls.type = 'list'
	listval = []
	numlist = random.randint(0,50)
	for i in xrange(numlist):
		listval.append(generate_normal_chars(100))
	keycls.value = listval
	return keycls

def generate_long():
	keycls = generate_basic_flag()
	keycls.type = 'long'
	keycls.value = random.randint(0,0xffffffff)
	return keycls



handle_generate_map = {
	'args' : generate_args,
	'list' : generate_list,
	'bool' : generate_bool,
	'string' : generate_string,
	'float' : generate_float,
	'int' : generate_int,
	'long' : generate_long,
	'll' : generate_ll,
	'ull' : generate_ull,
	'command' : generate_command,
	'prefix' : generate_prefix,
	'count' : generate_count
}



def generate_handle_type():
	n = random.randint(0,len(all_typesname)*10)
	# we should give stop ok
	if n < (len(all_typesname) * 10) :
		return all_typesname[n/10]
	return 'stop'


def __genearet_commands(maxdepths=10,maxcnts=30,tabs=0):
	if maxdepths == 0:
		return []
	keyclss = []
	i = 0
	while i < maxcnts:
		typename = generate_handle_type()
		if typename == 'stop':
			break
		curkey = handle_generate_map[typename]()
		#logging.info('[%s] curkey %s'%(typename,curkey))
		if curkey.type == 'command' or curkey.type == 'prefix':
			curkey.value = __genearet_commands(maxdepths-1,maxcnts,tabs+1)
		#logging.info(__get_tabs_line('[%d][%s]=%s'%(maxdepths,curkey.key(),curkey.value),tabs))
		keyclss.append(curkey)
		i += 1
	if type(keyclss).__name__ != 'list':
		raise Exception('can not be list %s'%(type(keyclss).__name__))
	return keyclss

def generate_commands(maxdeps,maxcnts):
	return __genearet_commands(maxdeps,maxcnts)

class UnicodeEncode(object):
    def __dict_unicode(self,val):
        newdict =dict()
        for k in val.keys():
            newk = self.__encode_unicode(k)
            newv = self.__encode_unicode(val[k])
            newdict[newk] = newv
        return newdict

    def __list_unicode(self,val):
        newlist = []
        for k in val:
            newk = self.__encode_unicode(k)
            newlist.append(newk)
        return newlist

    def __encode_unicode(self,val):
        retval = val
        if sys.version[0]=='2' and isinstance(val,str):
            retval = val.encode('unicode')
        elif isinstance(val,dict):
            retval = self.__dict_unicode(val)
        elif isinstance(val,list):
            retval = self.__list_unicode(val)
        return retval

    def __init__(self,val):
        self.__val = self.__encode_unicode(val)
        return

    def __str__(self):
        return self.__val

    def __repr__(self):
        return self.__val
    def get_val(self):
        return self.__val

def __check_keycls(clss,prefix='',iscmd=True,longopts=[],shortopts=[]):
	hasargs = False
	retcls = []
	subcmds = []
	subprefixs = []
	for curcls in clss:
		if curcls.type == 'args':
			if  iscmd  and not hasargs  :
				retcls.append(curcls)
				hasargs = True
			else:
				logging.warn('args dup in prefix(%s)'%(prefix))
		elif curcls.type != 'command' and curcls.type != 'prefix':
			if curcls.flagname not in reserved_args:
				longopt = ''
				if len(prefix) > 0:
					longopt += prefix
					longopt += '_'
				longopt += curcls.flagname
				longopt = longopt.replace('_','-')
				if longopt not in longopts:
					longopts.append(longopt)
					if curcls.shortflag is not None:
						# check short flag
						if curcls.shortflag not in shortopts:
							shortopts.append(curcls.shortflag)
						else:
							logging.warn('remove dup shortflag %s'%(curcls.shortflag))
							curcls.shortflag = None
					retcls.append(curcls)
				else:
					logging.warn('not insert dup longopt %s(%s)'%(curcls.flagname,longopt))
			else:
				logging.warn('%s in reserved_args'%(curcls.flagname))
		elif curcls.type == 'command':
			if iscmd and curcls.cmdname not in subcmds and curcls.cmdname not in subprefixs and curcls.cmdname not in reserved_args:
				newprefix = ''				
				if len(prefix) > 0:
					newprefix += prefix
					newprefix += '_'
				newprefix += curcls.cmdname
				jsoncmd = newprefix
				jsoncmd = jsoncmd.replace('_','-')
				jsoncmd += '-json'
				if jsoncmd not in longopts:
					longopts.append(jsoncmd)
					valcls,longopts,shortopts = __check_keycls(curcls.value,newprefix,True,longopts,shortopts)
					curcls.value = valcls
					retcls.append(curcls)
					subcmds.append(curcls.cmdname)
				else:
					logging.warn('%s in longopts'%(jsoncmd))
			else:
				logging.warn('command (%s) not in not cmd mode'%(curcls.cmdname))
		elif curcls.type == 'prefix':
			if curcls.prefix not in subprefixs and curcls.prefix not in subcmds and curcls.prefix not in reserved_args:
				newprefix = ''
				if len(prefix) > 0:
					newprefix += prefix
					newprefix += '_'
				newprefix += curcls.prefix
				valcls,longopts,shortopts = __check_keycls(curcls.value,newprefix,False,longopts,shortopts)
				curcls.value = valcls
				retcls.append(curcls)
				subprefixs.append(curcls.prefix)
			else:
				logging.warn('%s in subprefixs (%s)'%(curcls.prefix,subprefixs))
		else:
			logging.error('can not be here')
			assert(0 != 0)
	if type(retcls).__name__ != 'list':
		logging.error('retcls not list (%s)'%(type(retcls).__name__))
	return retcls,longopts,shortopts




def check_keycls(clss):
	longopts = []
	shortopts = []
	# to add json file and help options
	longopts.append('json')	
	longopts.append('help')
	shortopts.append('h')
	retcls,longopts,shortopts= __check_keycls(clss,'',True,longopts,shortopts)
	return retcls

def __make_dict(clss,tabs=0):
	retd = dict()
	if type(clss).__name__ != 'list':
		logging.info(__get_tabs_line('type %s %s'%(type(clss).__name__,clss),tabs))
	for k in clss:
		#logging.info('k (%s)'%(type(k).__name__))
		keyname = k.key()
		val = k.value
		#logging.info(__get_tabs_line('keyname %s'%(keyname),tabs))
		if k.type == 'command' or k.type == 'prefix':
			val = __make_dict(k.value,tabs + 1)
		retd[keyname] = val
	return retd


def make_dict(keycls):
	retcls = check_keycls(keycls)
	retd = __make_dict(retcls)
	return retd

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
	commandline = '''
	{
		"verbose|v" : "+",
		"maxdeps|m" : 10,
		"maxcnt|M" : 20,
		"$" : 0
	}
	'''
	random.seed(time.time())
	parser = extargsparse.ExtArgsParse()
	parser.load_command_line_string(commandline)
	args = parser.parse_command_line()
	set_log_level(args)
	clss = generate_commands(args.maxdeps,args.maxcnt)
	retd = make_dict(clss)
	s = json.dumps(retd)
	sys.stdout.write('%s\n'%(s))
	return

if __name__ == '__main__':
	main()


