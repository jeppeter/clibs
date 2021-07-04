#! /usr/bin/env python

import sys
import os
import extargsparse
import logging
import random
import unittest
import time
import re
import importlib
import inspect


def quote_string(s):
    rets = ''
    sb = 0
    for c in s:
        if c in [ '"']:
            if sb :
                rets += c
            else:
                rets += '\\'
                rets += c
            sb = 0
        elif c == '\\':
            sb = 1
            rets += '\\'
        else:
            sb = 0
            rets += c
    return rets

def val_quote_string(s):
    rets = ''
    sb = 0
    for c in s:
        if c in [ '"']:
            if sb :
                rets += c
            else:
                rets += '\\'
                rets += c
            sb = 0
        elif c == '\\':
            sb = 1
            rets += '\\'
            rets += '\\'
        else:
            sb = 0
            rets += c
    return rets


def __format_tabs_line(fmt,tabs=1):
    s = ' ' * tabs * 4
    s += fmt
    s += '\n'
    return s

class MaxSize(object):
    def __init__(self):
        self.__obj = dict()
        return

    def __setattr__(self,name,val):
        if name.startswith('_'):
            self.__dict__[name] = val
            return
        defval = 1
        if name in self.__obj.keys():
            defval = self.__obj[name]
        if defval <= val:
            self.__obj[name] = (val + 1)
        return

    def __getattr__(self,name,val=None):
        if name.startswith('_'):
            return self.__dict__[name]
        if name not in self.__obj.keys():
            return 1
        return self.__obj[name]

    def __str__(self):
        s = '{'
        for k in self.__obj.keys():
            s += '%s=%s;'%(k,self.__obj[k])
        s += '}'
        return s

keycls_type_switch = {
    'string'   : 'OPT_STRING_TYPE'   ,
    'list'     : 'OPT_LIST_TYPE'     ,
    'count'    : 'OPT_INC_TYPE'      ,
    'float'    : 'OPT_DOUBLE_TYPE'   ,
    'jsonfile' : 'OPT_JSONFILE_TYPE' ,
    'help'     : 'OPT_HELP_TYPE'     ,
    'args'     : 'OPT_ARG_TYPE'
}


def __get_whole_name(cmdname,subname):
    retname = ''
    if cmdname is not None and len(cmdname) > 0:
        retname += cmdname
        if subname is not None:
            retname += '.'
    if subname is not None:
        retname += subname
    return retname

def __get_fmt_wholename(cmdname):
    retname = __get_whole_name(None,cmdname)
    if len(retname) == 0:
        retname = 'main'
    return retname


def __format_fixsize(beforechars,fmt,afterchars):
    s = ''
    for i in range(beforechars):
        s += ' '
    s += fmt
    for i in range(afterchars):
        s += ' '
    return s

def __format_center_align(maxsize,fmt):
    if len(fmt) > maxsize:
        logging.warning('len("%s") > %d'%(fmt,maxsize))
        beforechars = 0
        afterchars = 0
    else:
        beforechars = int((maxsize - len(fmt)) / 2)
        afterchars = maxsize - len(fmt) - beforechars
    return __format_fixsize(beforechars,fmt,afterchars)


def __format_left_align(maxsize,fmt):
    if len(fmt) > maxsize:
        afterchars = 0
        logging.warning('len("%s") > %d'%(fmt,maxsize))
    else:
        afterchars = int(maxsize - len(fmt))
    return __format_fixsize(0,fmt,afterchars)

def __format_right_align(maxsize,fmt):
    if len(fmt) > maxsize:
        beforechars = 0
        logging.warning('len("%s") > %d'%(fmt,maxsize))
    else:
        beforechars = int(maxsize - len(fmt))
    return __format_fixsize(beforechars,fmt,0)

def __get_keycls_opttype(keycls):
    if keycls.type in keycls_type_switch.keys():
        return keycls_type_switch[keycls.type]
    if keycls.type == 'int' or keycls.type == 'long':
        if keycls.attr is not None :
            if keycls.attr.type == 'ull' :
                return 'OPT_ULL_TYPE'
            elif keycls.attr.type == 'll' :
                return 'OPT_LL_TYPE'
        return 'OPT_INT_TYPE'
    elif keycls.type == 'bool':
        if keycls.value :
            return 'OPT_FALSE_TYPE'
        else:
            return 'OPT_TRUE_TYPE'
    raise Exception('can not find type (%s)'%(keycls.type))
    return

keycls_typename_switch = {
    'string'   : 'char*'             ,
    'list'     : 'char**'            ,
    'count'    : 'int'               ,
    'float'    : 'double'            ,
    'bool'     : 'int'
}

def __get_opt_ctypename(keycls):
    if keycls.type in keycls_typename_switch.keys():
        return keycls_typename_switch[keycls.type]
    if keycls.type == 'int':
        if keycls.attr is not None :
            if keycls.attr.type == 'ull' :
                return 'unsigned long long'
            elif keycls.attr.type == 'll' :
                return 'long long'
        return 'int'
    raise Exception('can not find type(%s)'%(keycls.type))
    return 


def __format_name_with_prefix(name,prefix=''):
    s = ''
    if prefix is not None and len(prefix) > 0:
        s = '%s_%s'%(prefix,name)
    else:
        s = '%s'%(name)
    return s


def __get_default_val_struct(parser,structname,prefix,cmdname=None,tabs=0):
    s = ''
    cmdopts = parser.get_cmdopts(cmdname)
    for opt in cmdopts:
        if opt.type == 'list':
            if len(opt.value) != 0:
                s += ' ' * tabs * 4
                s += 'static char* st_%s_defval [] = {\n'%(__format_name_with_prefix(opt.varname,prefix))
                for v in opt.value:
                    s += ' ' * (tabs + 1) * 4
                    s += '"%s",\n'%(v)
                s += ' ' * (tabs + 1) * 4
                s += 'NULL\n'
                s += ' ' * tabs * 4
                s += '};\n'
                s += '\n'
        elif opt.type == 'float':
            s += __format_tabs_line('static float st_%s_defval = %s;'%(__format_name_with_prefix(opt.varname,prefix),opt.value),tabs)
    return s

def __get_value_modify_str(keycls,prefix):
    rets = '(unsigned long long)'
    s = None
    if keycls.type == 'list':
        if len(keycls.value) != 0:
            rets += '((uintptr_t)st_%s_defval)'%(__format_name_with_prefix(keycls.varname,prefix))
            s = rets
    elif keycls.type == 'string' or (sys.version[0] == '2' and keycls.type == 'unicode') :
        if keycls.value is not None:
            #rets += '((uintptr_t)"%s")'%(quote_string(keycls.value))
            rets += '((uintptr_t)"%s")'%(val_quote_string(keycls.value))
            s = rets
    elif keycls.type == 'float':
        rets += '((uintptr_t)&(st_%s_defval))'%(__format_name_with_prefix(keycls.varname,prefix))
        s = rets
    return s


def __get_value_str(keycls,prefix):
    s = '(unsigned long long)'
    if keycls.type == 'list':
        # that is nothing to handle
        s += '0'
    elif keycls.type == 'string' or (sys.version[0] == '2' and keycls.type == 'unicode') :
        s += '((uintptr_t)NULL)'
    elif keycls.type == 'int' or keycls.type == 'long':
        s += '%d'%(keycls.value)
    elif keycls.type == 'float':
        s += '((uintptr_t)NULL)'
    elif keycls.type == 'count':
        s += '0'
    elif keycls.type == 'help' or keycls.type == 'jsonfile':
        s += '((uintptr_t)NULL)'
    elif keycls.type == 'bool':
        if keycls.value:
            s += '1'
        else:
            s += '0'
    elif keycls.type == 'args':
        if keycls.nargs == '*':
            s += 'EXTARGS_NARGS_STAR'
        elif keycls.nargs == '+':
            s += 'EXTARGS_NARGS_PLUS'
        elif keycls.nargs == '?':
            s += 'EXTARGS_NARGS_QUESTION'
        else:
            s += '%s'%(keycls.nargs)
    else:
        raise Exception('can not find [%s] type'%(keycls.type))
    #logging.info('s [%s]'%(s))
    return s

def __get_keycls_optfunc(keycls):
    s = '(opt_func_t)'
    if keycls.attr is not None and keycls.attr.optparse is not None:
        s += '%s'%(keycls.attr.optparse)
    else:
        s += 'NULL'
    return s

def __get_keycls_opthelp(keycls):
    s = '(opt_help_func_t)'
    if keycls.attr is not None and keycls.attr.opthelp is not None:
        s += '%s'%(keycls.attr.opthelp)
    else:
        s += 'NULL'
    return s

def __get_keycls_jsonfunc(keycls):
    s = '(opt_jsonfunc_t)'
    if keycls.attr is not None and keycls.attr.jsonfunc is not None:
        s += '%s'%(keycls.attr.jsonfunc)
    else:
        s += 'NULL'
    return s

def __get_cmd_present_name(parser,cmdname=None,prefix=''):
    cmdkeycls = parser.get_cmdkey(cmdname)
    if cmdkeycls is None:
        raise Exception('can not get (%s) cmdkeycls'%(cmdname))
    presentname = ''
    if len(prefix) > 0:
        presentname += '%s_'%(prefix)
    if cmdkeycls.attr is not None and cmdkeycls.attr.cmdname is not None:
        presentname += cmdkeycls.attr.cmdname
    else:
        if cmdname is not None and len(cmdname) > 0:
            presentname += '%s'%(cmdname)
        else:
            presentname += 'main'
    presentname = presentname.replace('.','_')
    return presentname

def __get_cmd_subcmds(parser,cmdname=None,prefix=''):
    subcmds = parser.get_subcommands(cmdname)
    if (subcmds is not None and len(subcmds) > 0 ):        
        return 'st_%s_subcmds'%(__get_cmd_present_name(parser,cmdname,prefix))
    return 'NULL'

def __get_cmd_cmdstruct(parser,cmdname=None,prefix=''):
    cmdkey = parser.get_cmdkey(cmdname)
    if cmdkey is not None:
        return 'st_%s_cmds'%(__get_cmd_present_name(parser,cmdname,prefix))
    return 'NULL'

def __get_cmd_cmdstruct_comment(parser,cmdname=None,chldname=None,prefix=''):
    if chldname is None:
        return 'endof %s'%(__get_cmd_subcmds(parser,cmdname,prefix))
    else:
        return __get_whole_name(cmdname,chldname)

def __get_cmd_cmdexpr(parser,cmdname=None,prefix=''):
    cmdopts = parser.get_cmdopts(cmdname)
    if cmdopts is None:
        return '""'
    numargs = '*'
    cmdexpr = '"[args] ..."'
    for opt in cmdopts:
        if opt.type == 'args':
            numargs = opt.nargs
            break
    if numargs == '*' or numargs == '+' or numargs == '?':
        if numargs == '+':
            cmdexpr = '"args ..."'
        elif numargs == '?':
            cmdexpr = '"[arg]"'
    else:
        if numargs == 1:
            cmdexpr = '"arg"'
        elif numargs == 0:
            cmdexpr = '""'
    return cmdexpr

def __get_cmd_keycls(parser,cmdname=None):
    return parser.get_cmdkey(cmdname)

def __get_cmd_cmdsize(parser,cmdname=None,prefix=''):
    return '(unsigned int)sizeof(opt_cmd_t)'

def __get_cmd_cmd(parser,cmdname=None,prefix=''):
    keycls = __get_cmd_keycls(parser,cmdname)
    s = '""'
    if keycls is not None and keycls.cmdname is not None and len(keycls.cmdname) > 0 and cmdname is not None and len(cmdname) > 0:
        s = '"%s"'%(keycls.cmdname)
    elif keycls is None:
        s = 'NULL'
    return s

def __get_cmd_cmdhelp(parser,cmdname=None,prefix=''):
    keycls = __get_cmd_keycls(parser,cmdname)
    s = 'NULL'
    if keycls is not None and keycls.helpinfo is not None :
        s = '"%s"'%(keycls.helpinfo)
    elif keycls is None:
        s = 'NULL'
    return s



def __get_cmd_cmdfunc(parser,cmdname=None,prefix=''):
    s = '(cmd_func_t)NULL'
    keycls = __get_cmd_keycls(parser,cmdname)
    if keycls is not None and keycls.function is not None:
        s = '(cmd_func_t)%s'%(keycls.function)
    return s

def __get_cmd_cmdopts(parser,cmdname=None,prefix=''):
    keycls = __get_cmd_keycls(parser,cmdname)
    s = 'NULL'
    if keycls is not None:
        s = 'st_%s_cmdopts'%(__get_cmd_present_name(parser,cmdname,prefix))
    return s


def __get_offset_str(structname,opt,prefix=''):
    if opt.type == 'args' or opt.type == 'help' or opt.type == 'jsonfile':
        return '(int) -1'
    else:
        return 'OPTION_OFFSET(%s,%s)'%(structname,opt.varname)

def __get_opt_optsize(opt=None,structname=None,prefix=''):
    return '(unsigned int)sizeof(opt_help_t)'

def __get_opt_longopt(opt=None,structname=None,prefix=''):
    longopt = '""'
    if opt is not None:
        if opt.type != 'args':
            longopt = '"%s"'%(opt.longopt.replace(opt.longprefix,'',1))
    else:
        longopt = 'NULL'
    return longopt

def __get_opt_shortopt(opt=None,structname=None,prefix=''):
    shortopt = '0x0'
    if opt is not None:
        if opt.type != 'args' and opt.shortflag is not None:
            shortopt = '\'%s\''%(opt.shortflag)
    return shortopt

def __get_opt_argname(opt=None,structname=None,prefix=''):
    argname = 'NULL'
    if opt is not None:
        if opt.needarg:
            argname = '"%s"'%(opt.varname)
    return argname

def __get_opt_helpinfo(opt=None,structname=None,prefix=''):
    helpinfo = 'NULL'
    if opt is not None:
        if opt.helpinfo is not None:
            helpinfo = '"%s"'%(opt.helpinfo)
    return helpinfo

def __get_opt_needargs(opt=None,structname=None,prefix=''):
    needargs='0'
    if opt is not None:
        if opt.needarg:
            needargs = '%d'%(opt.needarg)
    return needargs

def __get_opt_offset(opt=None,structname=None,prefix=''):
    offset = '(int)-1'
    if opt is not None:
        if opt.type == 'args' or opt.type == 'jsonfile':
            offset = '(int) -1'
        elif opt.type == 'help':
            offset = '(int) 0'
        else:
            offset = 'OPTION_OFFSET(%s,%s)'%(structname,opt.varname)
    return offset

def __get_opt_defvalue(opt=None,structname=None,prefix=''):
    defvalue = '(unsigned long long)0'
    if opt is not None:
        defvalue = __get_value_str(opt,prefix)
    return defvalue

def __get_opt_opttype(opt=None,structname=None,prefix=''):
    opttype = 'OPT_NONE_TYPE'
    if opt is not None:
        opttype = __get_keycls_opttype(opt)
    return opttype

def __get_opt_optfunc(opt=None,structname=None,prefix=''):
    optfunc = '(opt_func_t)NULL'
    if opt is not None:
            optfunc = __get_keycls_optfunc(opt)
    return optfunc

def __get_opt_helpfunc(opt=None,structname=None,prefix=''):
    helpfunc = '(opt_help_func_t)NULL'
    if opt is not None:
        helpfunc = __get_keycls_opthelp(opt)
    return helpfunc

def __get_opt_jsonfunc(opt=None,structname=None,prefix=''):
    jsonfunc = '(opt_jsonfunc_t)NULL'
    if opt is not None:
        jsonfunc = __get_keycls_jsonfunc(opt)
    return jsonfunc

opt_member_names = ['optsize','longopt','shortopt','argname','helpinfo','needargs','offset','defvalue','opttype','optfunc','helpfunc','jsonfunc']

def __calculate_opt_member_size(parser,calcsize,structname,prefix,opt=None,membername=None):
    m = importlib.import_module(__name__)
    funcname = '__get_opt_%s'%(membername)
    funcptr = getattr(m,funcname,None)
    if funcptr is None:
        raise Exception('no function %s'%(funcname))
    memstr = funcptr(opt,structname,prefix)
    sizename = '%ssize'%(membername)
    calcsize.__setattr__(sizename,len(memstr))
    setattr(calcsize,sizename,len(memstr))
    return calcsize


def __calculate_cmd_opts_size(parser,calcsize,structname,prefix,opt=None,cmdname=None):
    for m in opt_member_names:
        calcsize = __calculate_opt_member_size(parser,calcsize,structname,prefix,opt,m)
        calcsize.optmembersize = len('m_%s'%(m))
    return calcsize

def __format_opt_member_size(parser,calcsize,structname,prefix,opt=None,membername=None,ended=False):
    s = ''
    m = importlib.import_module(__name__)
    funcname = '__get_opt_%s'%(membername)
    funcptr = getattr(m,funcname,None)
    if funcptr is None:
        raise Exception('no function %s'%(funcname))
    memstr = funcptr(opt,structname,prefix)
    sizename = '%ssize'%(membername)
    maxsize = getattr(calcsize,sizename)
    s += '%s /* %s */'%(__format_left_align(maxsize,memstr),__format_center_align(calcsize.optmembersize,'m_%s'%(membername)))
    if not ended:
        s += ','
    return s



def __format_cmd_opts_size(parser,calcsize,structname,prefix,opt=None,cmdname=None,tabs=1):
    s = ''
    s += ' ' * tabs * 4
    s += '{'
    for m in opt_member_names:
        ended = False
        if m == opt_member_names[-1]:
            ended = True
        s += __format_opt_member_size(parser,calcsize,structname,prefix,opt,m,ended)
    s += '}'
    if opt is not None:
        s += ','
    s += '\n'
    return s

cmd_member_names = ['cmdsize','cmd','cmdexpr','cmdhelp','cmdfunc','cmdopts','subcmds']

def __calculate_cmdstruct_cmd_member_size(parser,structname,prefix,calcsize,cmdname,membername):
    m = importlib.import_module(__name__)
    funcname = '__get_cmd_%s'%(membername)
    funcptr = getattr(m,funcname,None)
    if funcptr is None:
        raise Exception('can not get function %s'%(funcname))
    s = funcptr(parser,cmdname,prefix)
    sizename = '%ssize'%(membername)
    setattr(calcsize,sizename,len(s))
    calcsize.cmdmembersize = len('m_%s'%(membername))
    return calcsize



def __calculate_cmdstruct_cmdopt_size(parser,structname,prefix,cmdname=None,calcsize=None):
    if calcsize is None:
        calcsize = MaxSize()
    for m in cmd_member_names:
        calcsize = __calculate_cmdstruct_cmd_member_size(parser,structname,prefix,calcsize,cmdname,m)
    return calcsize


def __format_cmdstruct_cmd_member_size(parser,structname,prefix,calcsize,cmdname,membername,ended=False):
    s = ''
    m = importlib.import_module(__name__)
    funcname = '__get_cmd_%s'%(membername)
    funcptr = getattr(m,funcname,None)
    if funcptr is None:
        raise Exception('can not get function %s'%(funcname))
    outs = funcptr(parser,cmdname,prefix)
    sizename = '%ssize'%(membername)
    maxsize = getattr(calcsize,sizename,None)
    s += '%s /* %s */'%(__format_left_align(maxsize,outs),__format_center_align(calcsize.cmdmembersize,'m_%s'%(membername)))
    if not ended:
        s += ','
    return s


def __format_cmdstruct_cmdopt_size(parser,structname,prefix,calcsize,cmdname=None,tabs=1):
    s = ' ' * tabs * 4
    s += '{'
    for m in cmd_member_names:
        ended = False
        if m == cmd_member_names[-1]:
            ended = True
        s += __format_cmdstruct_cmd_member_size(parser,structname,prefix,calcsize,cmdname,m,ended)
    s += '}'
    return s

def __get_not_exist_subcmd(parser,cmdname=None):
    subcmds = parser.get_subcommands(cmdname)
    not_exist_subcmd = ''
    if subcmds is None:
        ranname = 'sbcm_%d'%(random.randint(0,0xffffffffffffffff))
    else:
        while True:
            ranname = 'sbcm_%d'%(random.randint(0,0xffffffffffffffff))
            if ranname not in subcmds:
                break   
    if cmdname is not None and len(cmdname) > 0:
        not_exist_subcmd += cmdname
        not_exist_subcmd += '.'
    not_exist_subcmd += ranname
    return not_exist_subcmd


def __calculate_cmdstruct_size(parser,structname,prefix,cmdname=None,calcsize=None):
    if calcsize is None:
        calcsize = MaxSize()
    # to set default value
    calcsize = __calculate_cmd_opts_size(parser,calcsize,structname,prefix,None,cmdname)
    logging.info('cmdname %s'%(cmdname))
    cmdopts = parser.get_cmdopts(cmdname)
    for opt in cmdopts:
        if not opt.isflag:
            continue
        calcsize = __calculate_cmd_opts_size(parser,calcsize,structname,prefix,opt,cmdname)
    calcsize = __calculate_cmdstruct_cmdopt_size(parser,structname,prefix,cmdname,calcsize)
    subcmds = parser.get_subcommands(cmdname)
    for c in subcmds:
        curname = __get_whole_name(cmdname,c)
        calcsize = __calculate_cmdstruct_size(parser,structname,prefix,curname,calcsize)

    not_exist_subcmd = __get_not_exist_subcmd(parser,cmdname)

    if subcmds is not None and  len(subcmds) > 0:
        # we calculate the size of 
        for c in subcmds:
            curname = __get_whole_name(cmdname,c)
            calcsize.cmdstructsize = len(__get_cmd_cmdstruct(parser,curname,prefix))
            calcsize.cmdstructcommentsize = len(__get_cmd_cmdstruct_comment(parser,cmdname,c,prefix))
        calcsize.cmdstructsize = len(__get_cmd_cmdstruct(parser,not_exist_subcmd,prefix))
        calcsize.cmdstructcommentsize = len(__get_cmd_cmdstruct_comment(parser,cmdname,None,prefix))

    # we make default one
    calcsize = __calculate_cmdstruct_cmdopt_size(parser,structname,prefix,not_exist_subcmd,calcsize)
    return calcsize

def __format_cmdstruct_size(parser,calcsize,structname,prefix,cmdname=None,tabs=1):
    subcmds = parser.get_subcommands(cmdname)
    s = ''
    for c in subcmds:
        curname = __get_whole_name(cmdname,c)
        s += __format_cmdstruct_size(parser,calcsize,structname,prefix,curname,tabs)

    # now first we should get the opts
    s += __get_default_val_struct(parser,structname,prefix,cmdname,0)

    cmdopts = parser.get_cmdopts(cmdname)
    s += 'static opt_help_t %s[] = {\n'%(__get_cmd_cmdopts(parser,cmdname,prefix))
    for opt in cmdopts:
        if not opt.isflag:
            continue
        s += __format_cmd_opts_size(parser,calcsize,structname,prefix,opt,cmdname)
    s += __format_cmd_opts_size(parser,calcsize,structname,prefix,None,cmdname)
    s += '};\n'

    s += '\n'   

    not_exist_subcmd = __get_not_exist_subcmd(parser,cmdname)

    # to give the subcommands
    if len(subcmds) > 0:
        s += 'static opt_cmd_t* %s[] = {\n'%(__get_cmd_subcmds(parser,cmdname,prefix))
        for c in subcmds:
            curname = __get_whole_name(cmdname,c)
            subcmd = 'st_%s_subcmds'%(__get_cmd_present_name(parser,curname,prefix))
            s += ' ' * tabs * 4
            s += '%s , /* %s */\n'%(__format_left_align(calcsize.cmdstructsize,__get_cmd_cmdstruct(parser,curname,prefix)),__format_center_align(calcsize.cmdstructcommentsize,__get_cmd_cmdstruct_comment(parser,cmdname,c,prefix)))
        s += ' '*tabs * 4
        s += '%s , /* %s */\n'%(__format_left_align(calcsize.cmdstructsize,__get_cmd_cmdstruct(parser,not_exist_subcmd,prefix)),__format_center_align(calcsize.cmdstructcommentsize,__get_cmd_cmdstruct_comment(parser,cmdname,None,prefix)))
        s += '};\n'
    s += '\n'

    # now to give the cmd
    s += 'static opt_cmd_t %s[] = {\n'%(__get_cmd_cmdstruct(parser,cmdname,prefix))
    s += '%s,\n'%(__format_cmdstruct_cmdopt_size(parser,structname,prefix,calcsize,cmdname,tabs))

    not_exist_subcmd = __get_not_exist_subcmd(parser,cmdname)
    s += '%s\n'%(__format_cmdstruct_cmdopt_size(parser,structname,prefix,calcsize,not_exist_subcmd,tabs))
    s += '};\n'
    s += '\n'
    return s


def __calculate_optstruct_size(parser,structname,prefix,cmdname=None,calcsize=None):
    if calcsize is None:
        calcsize = MaxSize()

    logging.info('cmdname %s'%(cmdname))
    cmdopts = parser.get_cmdopts(cmdname)
    for opt in cmdopts:
        if not opt.isflag or opt.type == 'args' or opt.type == 'help' or opt.type == 'jsonfile' :
            continue
        calcsize.ctypenamesize = len(__get_opt_ctypename(opt))
        calcsize.cvarnamesize = len(opt.varname)
        #logging.info('ctypenamesize %d cvarnamesize %d ( "%s" "%s" )'%(calcsize.ctypenamesize,calcsize.cvarnamesize,__get_opt_ctypename(opt),opt.varname))
    subcmds = parser.get_subcommands(cmdname)
    for c in subcmds:
        curname = __get_whole_name(cmdname,c)
        calcsize = __calculate_optstruct_size(parser,structname,prefix,curname,calcsize)
    return calcsize

def __format_optionstruct_size(parser,calcsize,prefix,cmdname=None,tabs=1,addlist=[]):
    assert(calcsize is not None)
    cmdopts = parser.get_cmdopts(cmdname)
    s = ''
    for opt in cmdopts:
        if not opt.isflag or opt.type == 'args' or opt.type == 'help' or opt.type == 'jsonfile' or opt.varname in addlist :
            continue
        s += ' ' * tabs * 4
        s += '%s %s ;\n'%(__format_left_align(calcsize.ctypenamesize,__get_opt_ctypename(opt)),__format_left_align(calcsize.cvarnamesize,opt.varname))
        # we use this addlist because ,it will not use prefixcmdadded not added this ,so we do not duplicated
        addlist.append(opt.varname)

    subcmds = parser.get_subcommands(cmdname)
    for c in subcmds:
        curname = __get_whole_name(cmdname,c)
        s += __format_optionstruct_size(parser,calcsize,prefix,curname,tabs,addlist)
    return s



def __format_optstruct_string(parser,structname,prefix=''):
    s = ''
    s += 'typedef struct {\n'   
    calcsize = __calculate_optstruct_size(parser,structname,prefix)
    s += __format_optionstruct_size(parser,calcsize,prefix,None,1,[])
    s += '} %s,*p%s;\n'%(structname,structname)
    return s

def __format_cmdstruct_string(parser,structname,prefix):
    s = ''
    calcsize = __calculate_cmdstruct_size(parser,structname,prefix)
    s += __format_cmdstruct_size(parser,calcsize,structname,prefix)
    return s


def __declare_debug_function_string(parser,structname,cmdname=None,declaremem=None):
    if declaremem is None:
        declaremem = dict()

    subcmds = parser.get_subcommands(cmdname)
    if subcmds is not None and len(subcmds) > 0:
        for c in subcmds:
            curname = __get_whole_name(cmdname,c)
            declaremem = __declare_debug_function_string(parser,structname,curname,declaremem)

    cmdopts = parser.get_cmdopts(cmdname)
    if cmdopts is not None and len(cmdopts) > 0:
        for opt in cmdopts:
            if opt.type == 'args' or opt.type == 'jsonfile' or opt.type == 'help':
                continue
            if opt.type == 'list':
                if 'i' not in declaremem.keys():
                    declaremem['i'] = 'int'
    return declaremem


extargs_state_member_dict = {
    'subcommand' : 'string'
}


def __format_debug_bool(parser,ptrname,memname,tabs=1):
    return __format_tabs_line('printf("%s=%%s\\n",%s->%s ? "True" : "False");'%(memname,ptrname,memname),tabs)

def __format_debug_count(parser,ptrname,memname,tabs=1):
    return __format_tabs_line('printf("%s=%%d\\n",%s->%s);'%(memname,ptrname,memname),tabs)

def __format_debug_string(parser,ptrname,memname,tabs=1):
    s = ''
    s += __format_tabs_line('if (%s->%s != NULL){'%(ptrname,memname),tabs)
    s += __format_tabs_line('printf("%s=");'%(memname),tabs + 1)
    s += __format_tabs_line('print_quote_string(%s->%s);'%(ptrname,memname),tabs+1)
    s += __format_tabs_line('printf("\\n");',tabs + 1)
    s += __format_tabs_line('} else {',tabs)
    s += __format_tabs_line('printf("%s=NULL\\n");'%(memname),tabs + 1)
    s += __format_tabs_line('}',tabs)
    return s

def __format_debug_int(parser,ptrname,memname,tabs=1):
    s = ''
    s += __format_tabs_line('printf("%s=%%d\\n",%s->%s);'%(memname,ptrname,memname),tabs)
    return s

def __format_debug_ll(parser,ptrname,memname,tabs=1):
    s = ''
    s += __format_tabs_line('printf("%s=%%lld\\n",%s->%s);'%(memname,ptrname,memname),tabs)
    return s

def __format_debug_ull(parser,ptrname,memname,tabs=1):
    s = ''
    s += __format_tabs_line('printf("%s=%%lld\\n",%s->%s);'%(memname,ptrname,memname),tabs)
    return s

def __format_debug_list(parser,ptrname,memname,tabs=1):
    s = ''
    s += __format_tabs_line('printf("%s=[");'%(memname),tabs);
    s += __format_tabs_line('if (%s->%s != NULL){'%(ptrname,memname),tabs)
    s += __format_tabs_line('for(i=0;;i++){',tabs + 1)
    s += __format_tabs_line('if(%s->%s[i] == NULL){'%(ptrname,memname),tabs + 2)
    s += __format_tabs_line('break;',tabs + 3)
    s += __format_tabs_line('}',tabs + 2)
    s += __format_tabs_line('if (i > 0) {',tabs + 2)
    s += __format_tabs_line('printf(",");',tabs + 3)
    s += __format_tabs_line('}',tabs + 2)
    s += __format_tabs_line('print_quote_string(%s->%s[i]);'%(ptrname,memname),tabs + 2)
    s += __format_tabs_line('}',tabs + 1)
    s += __format_tabs_line('}',tabs)
    s += __format_tabs_line('printf("]\\n");')
    return s

def __format_debug_float(parser,ptrname,memname,tabs=1):
    s = ''
    s += __format_tabs_line('printf("%s=%%f\\n",%s->%s);'%(memname,ptrname,memname),tabs)
    return s

def __format_debug_function_base(parser,ptrname,memname,typename,tabs):
    m = importlib.import_module(__name__)
    funcname = '__format_debug_%s'%(typename)
    funcptr = getattr(m,funcname,None)
    if funcptr is None:
        raise Exception('can not get funcname (%s)'%(funcname))
    return funcptr(parser,ptrname,memname,tabs) 

def __call_debug_function_call(parser,ptrname,opt,tabs):
    typename = opt.type
    if typename == 'int':
        if opt.attr is not None and opt.attr.type in ['ull','ll']:
            typename = opt.attr.type

    return __format_debug_function_base(parser,ptrname,opt.varname,typename,tabs)

def __format_debug_function_inner(parser,ptrname,cmdname=None,tabs=1):
    s = ''
    cmdfmtname = __get_fmt_wholename(cmdname)
    s += __format_tabs_line('',tabs)
    s += __format_tabs_line('/* cmdopts for %s */'%(cmdfmtname),tabs)
    cmdopts = parser.get_cmdopts(cmdname)
    if cmdopts is not None and len(cmdopts) >0:
        for opt in cmdopts:
            if opt.type == 'args' or opt.type == 'jsonfile' or opt.type == 'help':
                continue
            s += __call_debug_function_call(parser,ptrname,opt,tabs)

    subcmds = parser.get_subcommands(cmdname)
    if subcmds is not None and len(subcmds) > 0:
        for c in subcmds:
            curname = __get_whole_name(cmdname,c)
            s += __format_debug_function_inner(parser,ptrname,curname,tabs)
    return s

print_quote_string_function='''
void print_quote_string(const char* string)
{
    char* pcur=(char*)string;
    printf("\\"");

    while(*pcur != 0x0) {
        if (*pcur == '\\\\' || *pcur == '"' || *pcur == '\\'') {
            printf("\\\\");
        }
        printf("%c",*pcur);
        pcur ++;
    }

    printf("\\"");   
    return;
}
'''
def __format_print_quote_string(parser,structname,tabs=1):
    return print_quote_string_function

def __format_debug_holding_args(parser,structname,ptrname,memname,extstateptr,extstatemem,tabs = 1):
    s = ''
    s += __format_tabs_line('if(%s->%s != NULL && (int)strlen(%s->%s) > 0) {'%(extstateptr,extstatemem,extstateptr,extstatemem),tabs)
    s += __format_tabs_line('printf("subnargs=[");',tabs+1)
    s += __format_tabs_line('} else {',tabs)
    s += __format_tabs_line('printf("args=[");',tabs+1)
    s += __format_tabs_line('}',tabs)
    s += __format_tabs_line('if (%s->%s != NULL) {'%(extstateptr,memname),tabs)
    s += __format_tabs_line('for(i=0;;i++){',tabs+1)
    s += __format_tabs_line('if (%s->%s[i] == NULL){'%(extstateptr,memname),tabs + 2)
    s += __format_tabs_line('break;',tabs + 3)
    s += __format_tabs_line('}',tabs + 2)
    s += __format_tabs_line('if (i > 0) {',tabs + 2)
    s += __format_tabs_line('printf(",");',tabs + 3)
    s += __format_tabs_line('}',tabs + 2)
    s += __format_tabs_line('print_quote_string(%s->%s[i]);'%(extstateptr,memname),tabs+2)
    s += __format_tabs_line('}',tabs+1)
    s += __format_tabs_line('}',tabs)
    s += __format_tabs_line('printf("]\\n");',tabs)
    return s

def __format_debug_function(parser,structname,functionname,prefix=''):
    s = ''
    s += __format_print_quote_string(parser,structname)
    declaremem = __declare_debug_function_string(parser,structname) 
    if 'i' not in declaremem.keys():
        declaremem['i'] = 'int'
    s += __format_tabs_line('int %s(int argc,char* argv[],pextargs_state_t pextstate,%s* popt)'%(functionname,structname),0)
    s += __format_tabs_line('{',0)
    for k in declaremem.keys():
        s += __format_tabs_line('%s %s;'%(declaremem[k],k))

    s += __format_tabs_line('argc=argc;')
    s += __format_tabs_line('argv=argv;')

    # make a seperate line
    s += __format_tabs_line('',0)

    for k in sorted(extargs_state_member_dict.keys()):
        s += __format_debug_function_base(parser,'pextstate',k,extargs_state_member_dict[k],1)

    s += __format_debug_holding_args(parser,structname,'pextstate','leftargs','pextstate','subcommand',1)

    # make a seperate line
    s += __format_tabs_line('',0)

    s += __format_debug_function_inner(parser,'popt',None,1)
    s += __format_tabs_line('',0)
    s += __format_tabs_line('return 0;',1)
    s += __format_tabs_line('}',0)
    return s

def __format_free_string(parser,ptrname,memname,tabs=1):
    s = ''
    s += __format_tabs_line('if(%s->%s != NULL){'%(ptrname,memname),tabs)
    s += __format_tabs_line('free(%s->%s);'%(ptrname,memname),tabs + 1)
    s += __format_tabs_line('}',tabs)
    s += __format_tabs_line('%s->%s = NULL;'%(ptrname,memname),tabs)
    return s

def __format_free_list(parser,ptrname,memname,tabs=1):
    s = ''
    s += __format_tabs_line('if (%s->%s != NULL){'%(ptrname,memname),tabs)
    s += __format_tabs_line('for(i=0;;i++){',tabs + 1)
    s += __format_tabs_line('ptmpstr = %s->%s[i];'%(ptrname,memname),tabs + 2)
    s += __format_tabs_line('if(ptmpstr == NULL){',tabs + 2)
    s += __format_tabs_line('break;',tabs + 3)
    s += __format_tabs_line('}',tabs + 2)
    s += __format_tabs_line('free(ptmpstr);',tabs + 2)
    s += __format_tabs_line('%s->%s[i] = NULL;'%(ptrname,memname),tabs + 2)
    s += __format_tabs_line('}',tabs + 1)
    s += __format_tabs_line('free(%s->%s);'%(ptrname,memname),tabs + 1)
    s += __format_tabs_line('}',tabs)
    s += __format_tabs_line('%s->%s = NULL;'%(ptrname,memname),tabs)
    return s

def __format_free_int(parser,ptrname,memname,tabs=1):
    s = ''
    s += __format_tabs_line('%s->%s=0;'%(ptrname,memname),tabs)
    return s

def __format_free_ll(parser,ptrname,memname,tabs=1):
    s = ''
    s += __format_tabs_line('%s->%s=(long long)0LL;'%(ptrname,memname),tabs)
    return s

def __format_free_float(parser,ptrname,memname,tabs=1):
    s = ''
    s += __format_tabs_line('%s->%s=(float)0.0;'%(ptrname,memname),tabs)
    return s

def __format_free_ull(parser,ptrname,memname,tabs=1):
    s = ''
    s += __format_tabs_line('%s->%s=(unsigned long long)0ULL;'%(ptrname,memname),tabs)
    return s

def __format_free_bool(parser,ptrname,memname,tabs=1):
    s = ''
    s += __format_tabs_line('%s->%s=0;'%(ptrname,memname),tabs)
    return s

def __format_free_count(parser,ptrname,memname,tabs=1):
    s = ''
    s += __format_tabs_line('%s->%s=0;'%(ptrname,memname),tabs)
    return s


def __declare_release_string(parser,declaremem):
    return declaremem

def __declare_release_int(parser,declaremem):
    return declaremem

def __declare_release_ull(parser,declaremem):
    return declaremem

def __declare_release_ll(parser,declaremem):
    return declaremem

def __declare_release_count(parser,declaremem):
    return declaremem

def __declare_release_float(parser,declaremem):
    return declaremem

def __declare_release_list(parser,declaremem):
    if 'ptmpstr' not in declaremem.keys():
        declaremem['ptmpstr'] = 'char*'
    if 'i' not in declaremem.keys():
        declaremem['i'] = 'int'
    return declaremem

def __declare_release_bool(parser,declaremem):
    return declaremem


def __call_declare_release_base(parser,opt,declaremem):
    typename = opt.type
    if typename == 'int':
        if opt.attr is not None and opt.attr.type in ['ll','ull']:
            typename = opt.attr.type
    m = importlib.import_module(__name__)
    funcname = '__declare_release_%s'%(typename)
    funcptr = getattr(m,funcname,None)
    if funcptr is None:
        raise Exception('can not get function %s'%(funcname))
    return funcptr(parser,declaremem)

def __declare_release_function_inner(parser,structname,cmdname=None,declaremem=None):
    if declaremem is None:
        declaremem = dict()
    cmdopts = parser.get_cmdopts(cmdname)
    if cmdopts is not None:
        for opt in cmdopts:
            if opt.type == 'help' or opt.type == 'jsonfile' or opt.type=='args':
                continue
            declaremem = __call_declare_release_base(parser,opt,declaremem)

    subcmds = parser.get_subcommands(cmdname)
    if subcmds is not None:
        for c in subcmds:
            curname = __get_whole_name(cmdname,c)
            declaremem = __declare_release_function_inner(parser,structname,curname,declaremem)
    return declaremem

def __format_free_function_base(parser,ptrname,memname,typename,tabs):
    m = importlib.import_module(__name__)
    funcname = '__format_free_%s'%(typename)
    funcptr = getattr(m,funcname,None)
    if funcptr is None:
        raise Exception('can not get funcname (%s)'%(funcname))
    return funcptr(parser,ptrname,memname,tabs)


def __call_release_function_call(parser,ptrname,opt,tabs):
    typename = opt.type
    if typename == 'int':
        if opt.attr is not None and opt.attr.type in ['ull','ll']:
            typename = opt.attr.type
    return __format_free_function_base(parser,ptrname,opt.varname,typename,tabs)


def __format_free_function_inner(parser,ptrname,cmdname=None,tabs=1):
    s = ''
    cmdfmtname = __get_fmt_wholename(cmdname)
    s += __format_tabs_line('',tabs)
    s += __format_tabs_line('/* cmdopts for %s */'%(cmdfmtname),tabs)
    cmdopts = parser.get_cmdopts(cmdname)
    if cmdopts is not None and len(cmdopts) >0:
        cnt = 0
        for opt in cmdopts:
            if opt.type == 'args' or opt.type == 'jsonfile' or opt.type == 'help':
                continue
            if cnt > 0:
                s += __format_tabs_line('',tabs)
            s += __call_release_function_call(parser,ptrname,opt,tabs)
            cnt += 1

    subcmds = parser.get_subcommands(cmdname)
    if subcmds is not None and len(subcmds) > 0:
        for c in subcmds:
            curname = __get_whole_name(cmdname,c)
            s += __format_free_function_inner(parser,ptrname,curname,tabs)
    return s


def __format_free_function(parser,structname,functionname,prefix=''):
    s = ''
    declaremem = __declare_release_function_inner(parser,structname) 
    s += __format_tabs_line('void %s(%s* popt)'%(functionname,structname),0)
    s += __format_tabs_line('{',0)
    for k in declaremem.keys():
        s += __format_tabs_line('%s %s;'%(declaremem[k],k),1)

    # make a seperate line
    s += __format_tabs_line('',0)

    # make a seperate line
    s += __format_tabs_line('',0)

    s += __format_tabs_line('if (popt == NULL) {',1)
    s += __format_tabs_line('return;',2)
    s += __format_tabs_line('}',1)
    s += __format_free_function_inner(parser,'popt',None,1)
    s += __format_tabs_line('',0)
    s += __format_tabs_line('/*this is for popt unused warning disable*/', 1)
    s += __format_tabs_line('if (popt != NULL){', 1)
    s += __format_tabs_line('popt = popt;', 2)
    s += __format_tabs_line('}',1)
    s += __format_tabs_line('return;',1)
    s += __format_tabs_line('}',0)
    return s



def __format_cmdstruct_macro(parser,structname,prefix='',cmdname='',tabs=1):
    s = ''
    subcmds = parser.get_subcommands(cmdname)
    if subcmds is not None and len(subcmds) > 0:
        for c in subcmds:
            curname = __get_whole_name(cmdname,c)
            s += '\n'
            s += __format_cmdstruct_macro(parser,structname,prefix,curname,tabs)
            s += '\n'

    maxlinelen = 1
    curlen = len('#define MOD_%s_MACRO()\\'%(__get_cmd_present_name(parser,cmdname,prefix).upper()))
    if curlen >= maxlinelen:
        maxlinelen = curlen + 1
    curlen = len(__format_tabs_line('do{\\',tabs))
    if curlen >= maxlinelen:
        maxlinelen = curlen + 1
    if subcmds is not None and len(subcmds) > 0:
        for c in subcmds:
            curname = __get_whole_name(cmdname,c)
            curlen = len(__format_tabs_line('MOD_%s_MACRO();\\'%(__get_cmd_present_name(parser,curname,prefix).upper()),tabs+1))
            if curlen >= maxlinelen:
                maxlinelen = curlen + 1
    cmdopts = parser.get_cmdopts(cmdname)
    if cmdopts is not None and len(cmdopts) > 0:
        idx = 0
        maxkeylen = 1
        maxvallen = 1
        for curopt in cmdopts:
            valstr = __get_value_modify_str(curopt,prefix) 
            if valstr is not None:
                keystr = 'st_%s_cmdopts[%d].m_defvalue'%(__get_cmd_present_name(parser,cmdname,prefix),idx)
                if len(keystr) >= maxkeylen:
                    maxkeylen = len(keystr) + 1
                if len(valstr) >= maxvallen:
                    maxvallen = len(valstr) + 1
                curlen = maxkeylen + maxvallen + (tabs + 1) * 4 + 4
                if curlen >= maxlinelen:
                    maxlinelen = curlen + 1
            idx += 1
    curlen = len(__format_tabs_line('} while(0)',tabs))
    if curlen >= maxlinelen:
        maxlinelen = curlen + 1
    curs = '#define MOD_%s_MACRO()'%(__get_cmd_present_name(parser,cmdname,prefix).upper())
    s += __format_left_align(maxlinelen-1,curs)
    s += '\\\n'
    curs = ' ' * 4 * tabs
    curs += 'do{'
    s += __format_left_align(maxlinelen - 1,curs)
    s += '\\\n'
    if subcmds is not None and len(subcmds) > 0:
        for c in subcmds:
            curname = __get_whole_name(cmdname,c)
            curs = ''
            curs += ' ' * 4 * (tabs + 1)
            curs += 'MOD_%s_MACRO();'%(__get_cmd_present_name(parser,curname,prefix).upper())
            s += __format_left_align(maxlinelen - 1,curs)
            s += '\\\n'
    if cmdopts is not None and len(cmdopts) > 0:
        idx = 0
        for curopt in cmdopts:
            valstr = __get_value_modify_str(curopt,prefix) 
            if valstr is not None:
                keystr = 'st_%s_cmdopts[%d].m_defvalue'%(__get_cmd_present_name(parser,cmdname,prefix),idx)
                curs = ' ' * (tabs + 1) * 4
                curs += __format_left_align(maxkeylen,keystr)
                curs += ' = '
                curs += __format_right_align(maxvallen,valstr)
                curs += ';'
                s += __format_left_align(maxlinelen - 1,curs)
                s += '\\\n'
            idx += 1
    curs = ' ' * tabs * 4
    curs += '} while(0)'
    s += __format_left_align(maxlinelen,curs)
    s += '\n'

    return s

def format_optstruct_string(commandline,structname,prefix='',extoptions=None):
    options = extargsparse.ExtArgsOptions(extoptions)
    parser = extargsparse.ExtArgsParse(options)
    parser.load_command_line_string(commandline)
    return __format_optstruct_string(parser,structname,prefix)

def __format_cmdstruct_string_top(commandline,structname,prefix='',extoptions=None):
    options = extargsparse.ExtArgsOptions(extoptions)
    parser = extargsparse.ExtArgsParse(options)
    parser.load_command_line_string(commandline)
    return __format_cmdstruct_string(parser,structname,prefix)


def __format_cmdstruct_macro_top(commandline,structname,prefix='',extoptions=None):
    options = extargsparse.ExtArgsOptions(extoptions)
    parser = extargsparse.ExtArgsParse(options)
    parser.load_command_line_string(commandline)
    s = ''
    s +=  __format_cmdstruct_macro(parser,structname,prefix)

    # now to make the define to redefined
    s += __format_tabs_line('',0)
    s += __format_tabs_line('',0)
    s += __format_tabs_line('#ifdef EXTARGS_PARSE',0)
    s += __format_tabs_line('#undef EXTARGS_PARSE',0)
    s += __format_tabs_line('#endif /*EXTARGS_PARSE*/',0)

    s += __format_tabs_line('',0)
    s += __format_tabs_line('',0)
    s += __format_tabs_line('#ifdef parse_param_smart',0)
    s += __format_tabs_line('#undef parse_param_smart',0)
    s += __format_tabs_line('#endif /*parse_param_smart*/',0)

    # now we should make the new function
    s += __format_tabs_line('int parse_param_smart(int argc, char* argv[], popt_cmd_t pmaincmd, void* popt, pextargs_state_t* ppoutstate, int* pprio,pextargs_options_t pargoptions)',0)
    s += __format_tabs_line('{',0)
    s += __format_tabs_line('MOD_%s_MACRO();'%(__get_cmd_present_name(parser,'',prefix)).upper(),1);
    s += __format_tabs_line('return parse_param_smart_ex(argc,argv,pmaincmd,popt,ppoutstate,pprio,pargoptions);',1)
    s += __format_tabs_line('}',0)

    s += __format_tabs_line('',0)
    s += __format_tabs_line('',0)
    s += __format_tabs_line('#define EXTARGS_PARSE(argc,argv,popt,pextstate) parse_param_smart(argc,argv,st_main_cmds,popt,&(pextstate),NULL,NULL)',0)

    return s

def format_cmdstruct_string(commandline,structname,prefix='',extoptions=None):
    s = ''
    s += __format_cmdstruct_string_top(commandline,structname,prefix,extoptions)
    s += __format_cmdstruct_macro_top(commandline,structname,prefix,extoptions)
    return s

def __format_handler_function_inner(structname,funcname):
    s = ''
    s += __format_tabs_line('',0)
    s += __format_tabs_line('int %s(int argc,char* argv[],pextargs_state_t pextstate,%s* popt)'%(funcname,structname),0)
    s += __format_tabs_line('{',0)
    s += __format_tabs_line('printf("call handler function[%s]\\n");'%(funcname),1)
    s += __format_tabs_line('return 0;',1)
    s += __format_tabs_line('}',0)
    return s


def __format_handler_function(parser,structname,cmdname=None):
    s = ''
    keycls = parser.get_cmdkey(cmdname)
    if keycls is not None and keycls.function is not None:
        s += __format_handler_function_inner(structname ,keycls.function)

    subcmds = parser.get_subcommands(cmdname)
    if subcmds is not None and len(subcmds) > 0:
        for c in subcmds:
            curname = __get_whole_name(cmdname,c)
            s += __format_handler_function(parser,structname,curname)
    return s

def format_handler_function(parser,structname):
    s = ''
    s += __format_handler_function(parser,structname)
    return s

def format_debug_function(commandline,structname,functionname=None,prefix='',extoptions=None):
    if functionname is None:
        functionname = 'debug_extargs_options'
    options = extargsparse.ExtArgsOptions(extoptions)
    parser  = extargsparse.ExtArgsParse(options)
    parser.load_command_line_string(commandline)
    s = ''
    s += format_handler_function(parser,structname)
    s += __format_debug_function(parser,structname,functionname,prefix)
    return s

def format_release_function(commandline,structname,functionname=None,prefix='',extoptions=None):
    if functionname is None:
        functionname = 'release_extargs_options'
    options= extargsparse.ExtArgsOptions(extoptions)
    parser = extargsparse.ExtArgsParse(options)
    parser.load_command_line_string(commandline)
    s = ''
    s += __format_free_function(parser,structname,functionname,prefix)
    return s

def set_log_level(args):
    loglvl= logging.ERROR
    if args.verbose >= 3:
        loglvl = logging.DEBUG
    elif args.verbose >= 2:
        loglvl = logging.INFO
    elif args.verbose >= 1 :
        loglvl = logging.WARN
    # we delete old handlers ,and set new handler
    if logging.root is not None and len(logging.root.handlers) > 0:
        logging.root.handlers = []
    logging.basicConfig(level=loglvl,format='%(asctime)s:%(filename)s:%(funcName)s:%(lineno)d\t%(message)s')
    return

def get_ver_tuple(ver):
    sarr = re.split('\.',ver)
    i = 0
    while i < len(sarr):
        sarr[i] = int(sarr[i])
        i += 1
    return sarr


def check_extargs_version(verleast):
    try:
        vernum = extargsparse.__version__
        leasttuple = get_ver_tuple(verleast)
        vertuple = get_ver_tuple(vernum)
        ok = True
        if vertuple[0] < leasttuple[0]:
            ok = False
        elif vertuple[0] == leasttuple[0]:
            if vertuple[1] < leasttuple[1]:
                ok = False
            elif vertuple[1] == leasttuple[1]:
                if vertuple[2] < leasttuple[2]:
                    ok = False              
        if not ok :
            raise Exception('version %s < %s'%(vernum,verleast))
    except:
        raise Exception('must at lease %s version of extargsparse'%(verleast))
    return


def read_command_json(infile=None):
    s = ''
    fin = sys.stdin
    if infile is not None and infile != '-':
        fin = open(infile,'r')
    for l in fin:
        s += l
    if fin != sys.stdin:
        fin.close()
    fin = None
    logging.info('read json(%s)'%(s))
    return s

def output_file(args,optstruct=None,cmdstruct=None,outfunction=None,freefunc=None):
    if optstruct is None and cmdstruct is None and freefunc is None and outfunction is None:
        logging.warning('nothing to output')
        return

    # now we should give the 

    fin = None
    fout = sys.stdout
    optoutput = False
    cmdoutput = False
    funcoutput = False
    freeoutput = False

    if args.input is not None:
        if args.input != '-':
            fin = open(args.input , 'r')
        else:
            fin = sys.stdin
    if args.output is not None and args.output != '-':
        fout = open(args.output,'w+')

    if fin is not None:
        for l in fin:
            l = l.rstrip('\r\n')
            chgstr = l
            if len(args.cmdpattern) > 0 and cmdstruct is not None:
                chg1 = chgstr
                chgstr = chg1.replace(args.cmdpattern,cmdstruct)
                if chgstr != chg1:
                    cmdoutput = True
            if len(args.optpattern) > 0 and optstruct is not None:
                chg1 = chgstr
                chgstr = chg1.replace(args.optpattern,optstruct)
                if chgstr != chg1:
                    optoutput = True
            if len(args.debugpattern) > 0 and outfunction is not None:
                chg1 = chgstr
                chgstr = chg1.replace(args.debugpattern,outfunction)
                if chgstr != chg1:
                    funcoutput = True
            if len(args.freepattern) > 0 and freefunc is not None:
                chg1 = chgstr
                chgstr = chg1.replace(args.freepattern,freefunc)
                if chgstr != chg1 :
                    freeoutput = True
            fout.write('%s\n'%(chgstr))

    # if we have not replace ,so we should at the end of the output
    if not optoutput and optstruct is not None:
        fout.write('%s'%(optstruct))
        optoutput = True

    if not cmdoutput and cmdstruct is not None:
        fout.write('%s'%(cmdstruct))
        cmdoutput = True

    if not funcoutput and outfunction is not None:
        fout.write('%s'%(outfunction))
        funcoutput = True

    if not freeoutput and freefunc is not None:
        fout.write('%s'%(freefunc))
        freeoutput = True

    if fin is not None and fin != sys.stdin:
        fin.close()
    if fout != sys.stdout:
        fout.close()
    fin = None
    fout = None
    return

def optstruct_handler(args,parser):
    set_log_level(args)
    commandline = read_command_json(args.jsoninput)
    extoptions = None
    if args.optfile is not None:
        extoptions = read_command_json(args.optfile)
    s = format_optstruct_string(commandline,args.structname,args.prefix,extoptions)
    output_file(args,s,None,None)
    sys.exit(0)
    return

def cmdstruct_handler(args,parser):
    set_log_level(args)
    commandline = read_command_json(args.jsoninput)
    extoptions = None
    if args.optfile is not None:
        extoptions = read_command_json(args.optfile)
    s = format_cmdstruct_string(commandline,args.structname,args.prefix,args.extoptions)
    output_file(args,None,s,None)
    sys.exit(0)
    return

def debugfunc_handler(args,parser):
    set_log_level(args)
    commandline = read_command_json(args.jsoninput)
    extoptions = None
    if args.optfile is not None:
        extoptions = read_command_json(args.optfile)
    s = format_debug_function(commandline,args.structname,args.funcname,args.prefix,extoptions)
    output_file(args,None,None,s,None)
    sys.exit(0)
    return

def freefunc_handler(args,parser):
    set_log_level(args)
    commandline = read_command_json(args.jsoninput)
    extoptions = None
    if args.optfile is not None:
        extoptions = read_command_json(args.optfile)
    s = format_release_function(commandline,args.structname,args.releasename,args.prefix,extoptions)
    output_file(args,None,None,None,s)
    sys.exit(0)
    return


def all_handler(args,parser):
    set_log_level(args)
    commandline = read_command_json(args.jsoninput)
    extoptions = None
    if args.optfile is not None:
        extoptions = read_command_json(args.optfile)
    opts = format_optstruct_string(commandline,args.structname,args.prefix,extoptions)
    cmds = format_cmdstruct_string(commandline,args.structname,args.prefix,extoptions)
    debugfuncs = format_debug_function(commandline,args.structname,args.funcname,args.prefix,extoptions)
    freefuncs = format_release_function(commandline,args.structname,args.releasename,args.prefix,extoptions)
    output_file(args,opts,cmds,debugfuncs,freefuncs)
    sys.exit(0)
    return


class debug_coutput_case(unittest.TestCase):
    def setUp(self):
        return

    def tearDown(self):
        return

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass



    def test_A001(self):
        commandline='''
        {
            "verbose|v##increment verbose mode##" : "+",
            "flag|f##flag set##" : false,
            "number|n" : 0,
            "list|l" : ["hello","world"],
            "string|s" : "string_var",
            "$" : {
                "value" : [],
                "nargs" : "*",
                "type" : "string"
            },
            "dep" : {
                "hello" : ""
            },
            "rdep" : {
                "hello" : null
            }

        }
        '''
        logging.info('options (%s)\n'%(format_optstruct_string(commandline,'args_options_t','prefix123')))
        logging.info('declare (%s)\n'%(format_cmdstruct_string(commandline,'args_options_t','prefix123')))
        return

    def test_A002(self):
        commandline= '''
        {
            "verbose|v" : "+",
            "$port|p" : {
                "value" : 3000,
                "type" : "int",
                "nargs" : 1 , 
                "helpinfo" : "port to connect"
            },
            "dep" : {
                "list|l" : [],
                "string|s" : "s_var",
                "$" : "+"
            },
            "rdep" : {
                "list|l" : [],
                "string|s" : "s_rdep",
                "$" : "+"
            }
        }
        '''
        optstr='''
        {
            "cmdprefixadded" : false
        }
        '''
        rets = format_optstruct_string(commandline,'args_options_t','',optstr)
        logging.info('rets (%s)'%(rets))
        listexpr = re.compile('^\s+char\*\*\s+list\s*;.*')
        stringexpr = re.compile('^\s+char\*\s+string\s*;.*')
        listcnt = 0
        stringcnt = 0
        sarr = re.split('\n',rets)
        for l in sarr:
            if listexpr.match(l):
                listcnt += 1
            if stringexpr.match(l):
                stringcnt += 1
        self.assertEqual(listcnt,1)
        self.assertEqual(stringcnt,1)
        return


def test_handler(args,parser):
    set_log_level(args)
    logging.info('test start')
    cmdargs = args.subnargs
    sys.argv[1:] = cmdargs
    unittest.main(verbosity=args.verbose,failfast=args.failfast)
    logging.info('test end')
    sys.exit(0)
    return


def main():
    commandline='''
    {
        "jsoninput|j##input json default stdin##" : null,
        "input|i##input file to get default nothing - for stdin##" : null,
        "output|o##output c file##" : null,
        "verbose|v##verbose mode default(0)##" : "+",
        "cmdpattern|c" : "%EXTARGS_CMDSTRUCT%",
        "optpattern|O" : "%EXTARGS_STRUCT%", 
        "structname|s" : "args_options_t",
        "funcname|F" : "debug_extargs_output",
        "releasename|R" : "release_extargs_output",
        "debugpattern" : "%EXTARGS_DEBUGFUNC%",
        "freepattern" : "%EXTARGS_FREEFUNC%",
        "prefix|p" : "",
        "optfile##ext options to out##" : null,
        "failfast|f" : false,
        "test<test_handler>" : {
            "$" : "*"
        },
        "optstruct<optstruct_handler>" : {
            "$" : 0
        },
        "cmdstruct<cmdstruct_handler>" : {
            "$" : 0
        },
        "debugfunc<debugfunc_handler>" : {
            "$" : 0
        },
        "freefunc<freefunc_handler>" : {
            "$" : 0
        },
        "all<all_handler>" : {
            "$" : 0
        }
    }
    '''
    # first to check whether it is 0.9.8 later
    check_extargs_version('1.0.2')
    options = extargsparse.ExtArgsOptions()
    options.prog = sys.argv[0]
    parser = extargsparse.ExtArgsParse(options)
    parser.load_command_line_string(commandline)
    random.seed(time.time())
    args = parser.parse_command_line(None,parser)
    return


if __name__ == '__main__':
    main()
debugfunc_handler