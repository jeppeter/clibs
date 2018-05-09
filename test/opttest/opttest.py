#! /usr/bin/env python

import os
import sys
import extargsparse
import logging
import platform
import unittest
import tempfile
import subprocess
import re
import inspect
import cmdpack
import shutil
import json


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

def debug_read_callback(rl,ctx):
    rl = rl.rstrip('\r\n')
    ctx.read_line(rl)
    logging.info('read %s'%(rl))
    return

class debug_opttest_case(unittest.TestCase):
    def __get_verbosity(self):
        frame = inspect.currentframe()
        while frame:
            self = frame.f_locals.get('self')
            if isinstance(self, unittest.TestProgram):
                return self.verbosity
            frame = frame.f_back
        return 0        
    def setUp(self):
        self.__readlines = []
        self.__verbose = self.__get_verbosity()
        self.__tempfiles = []
        if getattr(self,'nullfile',None) is None:
            self.nullfile = open(os.devnull,'w+b')
        if getattr(self,'uname0',None) is None:
            self.uname0 = platform.uname()[0].lower()
        # to delete all the environment value
        delkeys = []
        for k in os.environ.keys():
            if k.startswith('EXTARGS_') or k.startswith('DEP_') or k.startswith('RDEP_') or k.startswith('EXTARGSPARSE_'):
                delkeys.append(k)
        for k in delkeys:
            del os.environ[k]
        return

    def __remove_tempfiles(self):
        if 'TEST_RESERVED' not in os.environ.keys():
            for c in self.__tempfiles:
                if os.path.isfile(c):
                    os.remove(c)
                elif os.path.isdir(c):
                    shutil.rmtree(c)
                else:
                    logging.warn('[%s] not support type'%(c))
        self.__tempfiles = []
        return



    def tearDown(self):
        if getattr(self,'nullfile',None) is not None:
            self.nullfile.close()
            self.nullfile = None
        if getattr(self,'uname0',None) is not None:
            self.uname0 = None
        self.__remove_tempfiles()
        return

    def read_line(self,rl):
        self.__readlines.append('%s'%(rl))
        return

    def read_file(self,infile):
        retlines = []
        with open(infile,'r') as fin:
            for l in fin:
                retlines.append(l.rstrip('\r\n'))
        return retlines

    @classmethod
    def setUpClass(cls):
        return

    @classmethod
    def tearDownClass(cls):
        return

    def __write_jsonfile(self,jsonstr,outf=None):
        if outf is None:
            fd,outf = tempfile.mkstemp(suffix='.json',prefix='parse',dir=None,text=True)
            os.close(fd)
        with open(outf,'w') as fout:
            fout.write(jsonstr)
        return outf

    def __running_ok(self,cmd=[]):
        #logging.info('run cmd (%s)'%(cmd))
        stdoutfile=self.nullfile
        stderrfile=subprocess.STDOUT
        if self.__verbose >= 3:
            stdoutfile= None
            stderrfile = None
        if 'STATICLIB' in os.environ.keys():
            logging.info('STATICLIB')
        else:
            logging.info('no STATICLIB')
        subprocess.check_call(cmd,stdout=stdoutfile,stderr=stderrfile)
        #logging.info('runok cmd (%s)'%(cmd))
        return


    def __make_clean(self,optdir=None):
        lastdir = None
        if optdir is None:
            optdir = os.path.dirname(os.path.abspath(__file__))
        uname0 = platform.uname()[0].lower()
        cmds = []
        if uname0 == 'linux':
            cmds.extend(['make','-C',optdir , '-f','makefile','clean'])
        elif uname0 == 'windows':
            lastdir = os.getcwd()
            os.chdir(optdir)
            cmds.extend(['nmake.exe','/f','makefile.win','clean'])
        else:
            raise Exception('platform (%s) not supported'%(uname0))
        try:
            self.__running_ok(cmds)
        finally:
            if lastdir is not None:
                os.chdir(lastdir)
        return

    def __make_opttest(self,optdir=None):
        lastdir = None
        if optdir is None:
            optdir = os.path.dirname(os.path.abspath(__file__))
        uname0 = platform.uname()[0].lower()
        cmds = []
        if uname0 == 'linux':
            cmds.extend(['make','-C',optdir , '-f','makefile','opttest'])
            if 'STATICLIB' in os.environ.keys():
                cmds.append('STATICLIB=1')
        elif uname0 == 'windows':
            lastdir = os.getcwd()
            os.chdir(optdir)
            cmds.extend(['nmake.exe','/f','makefile.win','opttest'])
        else:
            raise Exception('platform (%s) not supported'%(uname0))
        try:
            self.__running_ok(cmds)
        finally:
            if lastdir is not None:
                os.chdir(lastdir)
        return

    def __get_nullfd(self):
        devnullfd = open(os.devnull,'w')
        return devnullfd


    def __call_readlines(self,cmd=[],copyenv=None):
        logging.info('readlines (%s)'%(cmd))
        if copyenv is None:
            copyenv = os.environ.copy()
        retarr = []
        self.__readlines = []
        stderrfile = self.nullfile
        if self.__verbose >= 3:
            stderrfile = None
        p = cmdpack.run_cmd_output(cmd,True,stderrfile,False,copyenv)
        for l in p:
            self.__readlines.append(l.rstrip('\r\n'))
        p = None
        logging.info('readlines (%s)'%(self.__readlines))
        return self.__readlines

    def __append_env(self,env=None):
        envcmds = []
        if env is not None:
            for k in env.keys():
                envcmds.append('-E')
                envcmds.append('%s=%s'%(k,env[k]))
        if len(envcmds) > 0:
            logging.info('envcmds %s'%(envcmds))
        return envcmds

    def __append_priority(self,priority=None):
        priocmds = []
        if priority is not None:
            for k in priority:
                priocmds.append('-p')
                priocmds.append(k)
        if len(priocmds) > 0:
            logging.info('priocmds %s'%(priocmds))
        return priocmds

    def __set_child_environ(self,env=None):
        copyenv = os.environ.copy()
        uname0 = platform.uname()[0].lower()
        if uname0 == 'windows':
            if env is not None:
                for k in env.keys():
                    copyenv[k] = env[k]
        return copyenv

    def __extend_extoptions_cmdline(self,extdict):
        retcmds = []
        if 'screenwidth' in extdict.keys():
            retcmds.append('--screenwidth')
            retcmds.append('%s'%(extdict['screenwidth']))
        if 'parseall' in extdict.keys():
            if not extdict['parseall']:
                retcmds.append('--no-parseall')
        if 'longprefix' in extdict.keys():
            retcmds.append('--longprefix')
            retcmds.append(extdict['longprefix'])
        if 'shortprefix' in extdict.keys():
            retcmds.append('--shortprefix')
            retcmds.append(extdict['shortprefix'])
        if 'jsonlong' in extdict.keys():
            retcmds.append('--jsonlong')
            retcmds.append(extdict['jsonlong'])
        return retcmds

    def __extend_optcmds(self,cmdsdict):
        retcmds = []
        logging.info('cmdsdict (%s)'%(cmdsdict))
        if 'usageout' in cmdsdict.keys():
            retcmds.append('--usageout')
            retcmds.append(cmdsdict['usageout'])
        return retcmds

    def __call_opttest(self,params=[],env=None,priority=None,optdir=None,extoptions=None,opttestcmds=None):
        extdict = dict()
        if extoptions is not None:
            try:
                extdict = json.loads(extoptions)
            except:
                logging.error('can not parse json (%s)'%(extoptions))
                extdict = dict()

        cmdsdict = dict()
        if opttestcmds is not None:
            try:
                cmdsdict = json.loads(opttestcmds)
            except:
                logging.error('can not parse opttestcmds (%s)'%(opttestcmds))
                cmdsdict = dict()

        if optdir is None:
            optdir = os.path.dirname(os.path.abspath(__file__))
        uname0 = platform.uname()[0].lower()
        cmds = []
        copyenv = self.__set_child_environ(env)
        if uname0 == 'linux':
            opttestsh = os.path.join(optdir,'opttest')
            cmds.append(opttestsh)
            cmds.extend(self.__append_env(env))
            cmds.extend(self.__extend_extoptions_cmdline(extdict))
            cmds.extend(self.__append_priority(priority))
            cmds.extend(self.__extend_optcmds(cmdsdict))
            cmds.append('--')
            cmds.extend(params)
        elif uname0 == 'windows':
            opttestexe = os.path.join(optdir,'opttest.exe')
            cmds.append(opttestexe)
            cmds.extend(self.__extend_extoptions_cmdline(extdict))
            cmds.extend(self.__append_priority(priority))
            cmds.extend(self.__extend_optcmds(cmdsdict))
            cmds.append('--')
            cmds.extend(params)
        else:
            raise Exception('platform (%s) not supported'%(uname0))        
        retlines = self.__call_readlines(cmds,copyenv)
        return retlines

    def __get_drmem_output(self,cmd,copyenv=None):
        # not make any output for drmem
        logging.info('call drmem check %s'%(cmd))
        oldextargs_level = None
        if copyenv is None:
            copyenv = os.environ.copy()
        if 'EXTARGSPARSE_LOGLEVEL' in os.environ.keys():
            oldextargs_level = os.environ['EXTARGSPARSE_LOGLEVEL']
            del os.environ['EXTARGSPARSE_LOGLEVEL']
        os.environ['EXTARGSPARSE_LOGLEVEL'] = '0'
        uname0  = platform.uname()[0].lower()
        devnullfd = self.nullfile
        try:
            self.__readlines = []
            p = cmdpack.run_cmd_output(cmd,False,True,False,copyenv)
            for l in p:
                self.__readlines.append(l.rstrip('\r\n'))
            p = None
            retarr = self.__readlines
        finally:
            if oldextargs_level is not None:
                os.environ['EXTARGSPARSE_LOGLEVEL'] = oldextargs_level
            oldextargs_level = None
        return retarr

    def __has_check_bins(self,cmdname):
        pathsarr = re.split(os.pathsep,os.environ['PATH'])
        for c in pathsarr:
            abscmdname = os.path.join(c,cmdname)
            if os.path.exists(abscmdname):
                return True
        return False

    def __get_logdir(self):
        logdir = None
        if 'TMP' in os.environ.keys():
            logdir = os.path.join(os.environ['TMP'],'drmem')
        if logdir is None:
            if 'TEMP' in os.environ.keys():
                logdir = os.path.join(os.environ['TEMP'],'drmem')
        if logdir is None:
            if os.path.isdir('/tmp'):
                logdir = '/tmp/drmem'
            else:
                logdir = os.path.join(os.getcwd(),'drmem')
        if 'DRMEM_LOGDIR' in os.environ.keys():
            logdir = os.environ['DRMEM_LOGDIR']
        if not os.path.isdir(logdir):
            if os.path.exists(logdir):
                raise Exception('%s is not directory'%(logdir))
            try:
                os.makedirs(logdir)
            except:
                if not os.path.isdir(logdir):
                    raise Exception('can not mkdir %s'%(logdir))
        return logdir

    def __check_drmem_results(self,retlines):
        # first to make sure the handle out lines
        dirtoremove = None
        resfile = None
        DRMEM_PREFIX='~~Dr.M~~ '
        dirremoveexpr = re.compile('^%sDetails:\s+(.*)$'%(DRMEM_PREFIX))
        rightfoundexpr = re.compile('^%sNO ERRORS FOUND:$'%(DRMEM_PREFIX))
        ok = False
        for c in retlines:
            c = c.rstrip('\r\n')
            if rightfoundexpr.match(c) :
                ok = True
            elif dirremoveexpr.match(c) : 
                logging.info('find %s'%(c))
                m = dirremoveexpr.findall(c)
                if len(m) > 0:
                    dirtoremove = os.path.dirname(m[0])
                    bname = os.path.basename(dirtoremove)
                    dname = os.path.dirname(dirtoremove)
                    sarr = re.split('\.',bname)
                    if len(sarr) >= 3:
                        resfile = m[0]
                    else:
                        logging.warning('%s not right to remove'%(dirtoremove))
        if not ok :
            # this means that we have found of the file ,so we should 
            if resfile is not None:
                ignoreerrors = 0
                logging.info('resfile [%s]'%(resfile))
                retlines = self.read_file(resfile)
                startexpr = re.compile('^Error #[\d]+:.*')
                ignoreexpr = re.compile('^<memory was allocated before tool took control>$')
                errorfoundexpr = re.compile('^ERRORS FOUND:.*')
                numexpr = re.compile('^\s+([\d]+)\s+unique,.*')
                started = 0
                errorline = ''
                totalerror = 0
                for l in retlines:
                    if errorline == '':
                        if startexpr.match(l):
                            started = 1
                            errorline = l
                    else:
                        if  ignoreexpr.match(l):
                            logging.info('get ignore for [%s]'%(errorline))
                            ignoreerrors += 1
                        errorline = ''
                started = 0
                for l in retlines:
                    if started == 0:
                        if errorfoundexpr.match(l):
                            started = 1
                    else:
                        m = numexpr.findall(l)
                        if m is None or len(m) == 0:
                            started = 0
                            continue
                        logging.info('get error [%s]'%(m[0]))
                        totalerror += int(m[0])
                if totalerror <= ignoreerrors:
                    ok = True
        self.__remove_file_ok(resfile,'resfile',ok)
        self.__remove_dir_ok(dirtoremove,'drmem dump dir',ok)
        return  ok


    def __check_mem(self,params,env=None,priority=None,optdir=None,extoptions=None):
        extdict = dict()
        if extoptions is not None:
            try:
                extdict = json.loads(extoptions)
            except:
                logging.error('can not parse (%s)'%(extoptions))
                extdict = dict()
        if optdir is None:
            optdir = os.path.dirname(os.path.abspath(__file__))
        uname0 = platform.uname()[0].lower()
        cmds = []        
        retlines = []
        copyenv = self.__set_child_environ(env)
        if uname0 == 'linux':
            if not self.__has_check_bins('drmemory'):
                logging.warning('no drmemory in the os to make check memory')
                return
            # no valgrind installed ,so just return
            opttestsh = os.path.join(optdir,'opttest')
            cmds.append('drmemory')
            cmds.append('-logdir')
            cmds.append(self.__get_logdir())
            cmds.append('-check_leaks')
            cmds.append('-batch')
            cmds.append('-show_reachable')
            cmds.append('--')
            cmds.append(opttestsh)
            cmds.extend(self.__append_env(env))
            cmds.extend(self.__extend_extoptions_cmdline(extdict))
            cmds.extend(self.__append_priority(priority))
            cmds.append('--')
            cmds.extend(params)
            retlines = self.__get_drmem_output(cmds,copyenv)
        elif uname0 == 'windows':
            if not self.__has_check_bins('drmemory.exe'):
                logging.warning('no drmemory in the os to make check memory')
                return
            # no valgrind installed ,so just return
            opttestexe = os.path.join(optdir,'opttest.exe')
            cmds.append('drmemory.exe')
            cmds.append('-logdir')
            cmds.append(self.__get_logdir())
            cmds.append('-check_leaks')
            cmds.append('-batch')
            cmds.append('-show_reachable')
            cmds.append('--')
            cmds.append(opttestexe)
            cmds.extend(self.__extend_extoptions_cmdline(extdict))
            cmds.extend(self.__append_priority(priority))
            cmds.append('--')
            cmds.extend(params)
            retlines = self.__get_drmem_output(cmds,copyenv)
        else:
            raise Exception('platform (%s) not supported'%(uname0))        
        logging.debug('get lines (%s)'%(retlines))
        ok = self.__check_drmem_results(retlines)
        self.assertEqual(ok,True)
        return


    def __call_py_debugout(self,jsonfile,params=[],env=None,priority=None,optdir=None,extoptions=None):
        copyenv = self.__set_child_environ(env)
        if optdir is None:
            optdir = os.path.dirname(os.path.abspath(__file__))
        uname0 = platform.uname()[0].lower()
        cmds = []
        outf = None
        if extoptions is not None:
            outf = self.__write_jsonfile(extoptions)
            self.__tempfiles.append(outf)
            logging.info('outf [%s]'%(outf))
        pythonfile = os.path.join(optdir,'debugout.py')
        if uname0 == 'linux' or uname0 == 'windows':
            pythonbin = sys.executable
            if 'PYTHON' in os.environ.keys():
                pythonbin = os.environ['PYTHON']
            cmds.append(pythonbin)
            cmds.append(pythonfile)
            cmds.extend(['-i',jsonfile])
            if uname0 != 'windows':
                cmds.extend(self.__append_env(env))
            if outf is not None:
                cmds.append('--extoptions')
                cmds.append(outf)
            cmds.extend(self.__append_priority(priority))
            cmds.append('--')
            cmds.extend(params)
        else:
            raise Exception('platform (%s) not supported'%(uname0))
        #logging.info('cmds (%s)'%(cmds))
        return self.__call_readlines(cmds,copyenv)

    def __compare_float_output(self,pystr,exestr):
        ok = False
        episilon = 0.00001
        pysarr = re.split('=',pystr,2)
        exsarr = re.split('=',exestr,2)
        if len(pysarr) == len(exsarr) and len(pysarr) == 2:
            if pysarr[0] == exsarr[0]:
                # now get the 
                floatexpr = re.compile('^([0-9]+(\.[0-9]+)?)$')
                pym = floatexpr.findall(pysarr[1])
                exm = floatexpr.findall(exsarr[1])
                if len(pym) > 0 and len(pym[0]) > 0 and len(exm) > 0 and len(exm[0]) > 0:
                    try:
                        pyfloat = float(pym[0][0])
                        exfloat = float(exm[0][0])
                        if (pyfloat - exfloat) < episilon:
                            ok = True
                    except:
                        ok = False
        return ok


    def __compare_outputs(self,exesarr,pysarr):
        self.assertEqual(len(exesarr),len(pysarr))
        i = 0
        while i < len(exesarr):
            exel = exesarr[i].rstrip('\r\n')
            pyl = pysarr[i].rstrip('\r\n')
            ok = False
            if exel == pyl :
                ok = True
            else:
                ok = self.__compare_float_output(pyl,exel)
            if not ok:
                self.assertEqual(exel,pyl)
            i += 1
        return

    def __make_mainc(self,jsonfile,optdir=None,extoptions=None):
        optfile = None
        if optdir is None:
            optdir = os.path.dirname(os.path.abspath(__file__))
        if extoptions is not None:
            optfile = self.__write_jsonfile(extoptions)
        coutputpy = os.path.join(optdir,'..','..','coutput.py')
        maintmplfile = os.path.join(optdir,'main.c.tmpl')
        maincfile = os.path.join(optdir,'main.c')
        pythonbin = sys.executable
        cmds = []
        if 'PYTHON' in os.environ.keys():
            pythonbin = os.environ['PYTHON']
        cmds.append(pythonbin)
        cmds.append(coutputpy)
        if optfile is not None:
            cmds.append('--optfile')
            cmds.append(optfile)
        cmds.extend(['-j',jsonfile,'-i',maintmplfile,'-o',maincfile,'all'])
        self.__running_ok(cmds)
        return optfile

    def __extargs_opttest_out(self,options,params=[],env=None,priority=None,optdir=None,extoptions=None,opttestcmds=None):
        tempf = self.__write_jsonfile(options)
        optfile = None
        self.__make_clean(optdir)
        optfile = self.__make_mainc(tempf,optdir,extoptions)
        self.__make_opttest(optdir)
        opttestouts = self.__call_opttest(params,env,priority,optdir,extoptions,opttestcmds)
        return opttestouts,tempf,optfile



    def __extargs_running(self,options,params=[],env=None,priority=None,optdir=None,extoptions=None,opttestcmds=None):
        tempf = None
        ok = False
        if optdir is None:
            optdir = os.path.dirname(os.path.abspath(__file__))
        tempf = None
        optfile = None
        try:
            opttestouts,tempf,optfile = self.__extargs_opttest_out(options,params,env,priority,optdir,extoptions,opttestcmds)
            debugoutpyouts = self.__call_py_debugout(tempf,params,env,priority,optdir,extoptions)
            logging.info('opttestouts %s'%(opttestouts))
            logging.info('debugoutpyouts %s'%(debugoutpyouts))
            self.__compare_outputs(opttestouts,debugoutpyouts)
            self.__check_mem(params,env,priority,optdir,extoptions)
            ok = True
        finally:
            self.__remove_file_ok(tempf,'tempf',ok)
            self.__remove_file_ok(optfile,'optfile',ok)
        return

    def __remove_file_ok(self,filename,description,ok):
        if filename is not None and ok:
            if os.path.exists(filename):
                os.remove(filename)
        elif filename is not None:
            logging.error('%s %s'%(description,filename))
        return

    def __remove_dir_until_empty(self,dname):
        if os.path.isdir(dname):
            subs = os.listdir(dname)
            for c in subs:
                curc = os.path.join(dname,c)
                self.__remove_dir_until_empty(curc)
            os.rmdir(dname)
        elif os.path.isfile(dname):
            os.remove(dname)
        elif os.path.exists(dname):
            msg = 'unknown type %s'%(dname)
            logging.error(msg)
            raise Exception(msg)
        return

    def __remove_dir_ok(self,dirname,description,ok):
        if dirname is not None and ok:
            self.__remove_dir_until_empty(dirname)
        elif dirname is not None:
            logging.error('%s %s'%(description,dirname))
        return

    def __write_temp_file(self,content):
        fd , tempf = tempfile.mkstemp(suffix='.json',prefix='parse',dir=None,text=True)
        os.close(fd)
        with open(tempf,'w') as f:
            f.write('%s'%(content))
        logging.info('tempf %s'%(tempf))
        return tempf

    def test_A001(self):
        loads = '''
        {
            "verbose|v##increment verbose mode##" : "+",
            "flag|f## flag set##" : false,
            "number|n" : 0,
            "list|l" : [],
            "string|s" : "string_var",
            "$" : {
                "value" : [],
                "nargs" : "*",
                "type" : "string"
            }
        }
        '''
        self.__extargs_running(loads,['-vvvv','-f','-n','30','-l','bar1','-l','bar2','var1','var2'])
        return

    def test_A002(self):
        loads = '''
        {
            "verbose|v" : "+",
            "port|p" : 3000,
            "dep" : {
                "list|l" : [],
                "string|s" : "s_var",
                "$" : "+"
            }
        }
        '''
        self.__extargs_running(loads,['-vvvv','-p','5000','dep','-l','arg1','--dep-list','arg2','cc','dd'])
        return

    def test_A003(self):
        loads = '''
        {
            "verbose|v" : "+",
            "port|p" : 3000,
            "dep" : {
                "list|l" : [],
                "string|s" : "s_var",
                "$" : "+"
            },
            "rdep" : {
                "list|L" : [],
                "string|S" : "s_rdep",
                "$" : 2
            }
        }
        '''
        self.__extargs_running(loads,['-vvvv','-p','5000','rdep','-L','arg1','--rdep-list','arg2','cc','dd'])
        return

    def test_A004(self):
        loads = '''
        {
            "verbose|v" : "+",
            "port|p" : 3000,
            "dep" : {
                "list|l" : [],
                "string|s" : "s_var",
                "$" : "+"
            },
            "rdep" : {
                "list|L" : [],
                "string|S" : "s_rdep",
                "$" : 2
            }
        }
        '''
        self.__extargs_running(loads,['-vvvv','-p','5000','rdep','-L','arg1','--rdep-list','arg2','cc','dd'])
        return

    def test_A005(self):
        commandline = '''
        {
            "verbose|v" : "+",
            "port|p" : 3000,
            "dep<dep_handler>" : {
                "list|l" : [],
                "string|s" : "s_var",
                "$" : "+"
            },
            "rdep" : {
                "list|L" : [],
                "string|S" : "s_rdep",
                "$" : 2
            }
        }
        '''
        self.__extargs_running(commandline,['-p','7003','-vvvvv','dep','-l','foo1','-s','new_var','zz'])
        return

    def test_A006(self):
        commandline='''
            {
                "verbose|v" : "+",
                "port|p!type=ll!" : 6000,
                "variable|V!type=ull!" : 300
            }
        '''
        self.__extargs_running(commandline,['-p','0x6666666632','-V','0x39929299292992'])
        return



    def test_A007(self):
        commandline = '''
        {
            "verbose|v" : "+",
            "port|p+http" : 3000,
            "dep" : {
                "list|l" : [],
                "string|s" : "s_var",
                "$" : "+"
            }
        }
        '''
        self.__extargs_running(commandline,['-vvvv','dep','-l','cc','--dep-string','ee','ww'])
        return

    def test_A008(self):
        commandline = '''
        {
            "verbose|v" : "+",
            "+http" : {
                "port|p" : 3000,
                "visual_mode|V" : false
            },
            "dep" : {
                "list|l" : [],
                "string|s" : "s_var",
                "$" : "+"
            }
        }
        '''
        self.__extargs_running(commandline,['-vvvv','--http-port','9000','--http-visual-mode','dep','-l','cc','--dep-string','ee','ww'])
        return

    def test_A009(self):
        commandline = '''
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
            }
        }
        '''
        self.__extargs_running(commandline,['-vvvv','-p','9000','dep','-l','cc','--dep-string','ee','ww'])
        return

    def test_A010(self):
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
            }
        }
        '''        
        depjsonfile = None
        ok = False
        try:
            fd,depjsonfile = tempfile.mkstemp(suffix='.json',prefix='parse',dir=None,text=True)
            os.close(fd)
            fd = -1
            with open(depjsonfile,'w+') as f:
                f.write('{"list" : ["jsonval1","jsonval2"],"string" : "jsonstring"}\n')

            self.__extargs_running(commandline,['-vvvv','-p','9000','dep','--dep-json',depjsonfile,'--dep-string','ee','ww'])
            ok = True
        finally:
            if depjsonfile is not None and ok:
                os.remove(depjsonfile)
            elif depjsonfile is not None:
                logging.error('depjsonfile %s'%(depjsonfile))
            depjsonfile = None
        return


    def test_A011(self):
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
            }
        }
        '''
        depjsonfile = None
        ok = False
        try:
            fd,depjsonfile = tempfile.mkstemp(suffix='.json',prefix='parse',dir=None,text=True)
            os.close(fd)
            fd = -1
            with open(depjsonfile,'w+') as f:
                f.write('{"list" : ["jsonval1","jsonval2"],"string" : "jsonstring"}\n')

            env = dict()
            env['DEP_JSON'] = depjsonfile
            self.__extargs_running(commandline,['-vvvv','-p','9000','dep','--dep-string','ee','ww'],env)
            ok = True
        finally:
            if depjsonfile is not None and ok :
                os.remove(depjsonfile)
            elif depjsonfile is not None:
                logging.error('depjsonfile %s'%(depjsonfile))
            depjsonfile = None
        return


    def test_A012(self):
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
            }
        }
        '''
        jsonfile = None
        ok = False
        try:
            fd,jsonfile = tempfile.mkstemp(suffix='.json',prefix='parse',dir=None,text=True)
            os.close(fd)
            fd = -1
            f = open(jsonfile,'w+')
            f.write('{"dep":{"list" : ["jsonval1","jsonval2"],"string" : "jsonstring"},"port":6000,"verbose":3}\n')
            f.close()
            f = None
            self.__extargs_running(commandline,['-p','9000','--json',jsonfile,'dep','--dep-string','ee','ww'])
            ok = True
        finally:
            if jsonfile is not None and ok:
                os.remove(jsonfile)
            elif jsonfile is not None:
                logging.error('jsonfile %s'%(jsonfile))
            jsonfile = None
        return

    def test_A013(self):
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
            }
        }
        '''
        jsonfile = None
        ok = False
        try:
            fd,jsonfile = tempfile.mkstemp(suffix='.json',prefix='parse',dir=None,text=True)
            os.close(fd)
            fd = -1
            with open(jsonfile,'w+') as f:
                f.write('{"dep":{"list" : ["jsonval1","jsonval2"],"string" : "jsonstring"},"port":6000,"verbose":3}\n')

            env = dict()
            env['EXTARGSPARSE_JSON'] = jsonfile
            self.__extargs_running(commandline,['-p','9000','dep','--dep-string','ee','ww'],env)
            ok = True
        finally:
            if jsonfile is not None and ok:
                os.remove(jsonfile)
            elif jsonfile is not None:
                logging.error('jsonfile %s'%(jsonfile))
            jsonfile = None
        return


    def test_A014(self):
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
            }
        }
        '''
        jsonfile = None
        depjsonfile = None
        ok = False
        try:
            fd,jsonfile = tempfile.mkstemp(suffix='.json',prefix='parse',dir=None,text=True)
            os.close(fd)
            fd = -1
            fd ,depjsonfile = tempfile.mkstemp(suffix='.json',prefix='parse',dir=None,text=True)
            os.close(fd)
            fd = -1
            with open(jsonfile,'w+') as f:
                f.write('{"dep":{"list" : ["jsonval1","jsonval2"],"string" : "jsonstring"},"port":6000,"verbose":3}\n')
            with open(depjsonfile,'w+') as f:
                f.write('{"list":["depjson1","depjson2"]}\n')

            env = dict()
            env['EXTARGSPARSE_JSON'] = jsonfile
            env['DEP_JSON'] = depjsonfile
            self.__extargs_running(commandline,['-p','9000','dep','--dep-string','ee','ww'],env)
            ok = True
        finally:
            if depjsonfile is not None and ok:
                os.remove(depjsonfile)
            elif depjsonfile is not None:
                logging.error('depjsonfile %s'%(depjsonfile))
            depjsonfile = None
            if jsonfile is not None and ok:
                os.remove(jsonfile)
            elif jsonfile is not None:
                logging.error('jsonfile %s'%(jsonfile))
            jsonfile = None
        return

    def test_A015(self):
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
            }
        }
        '''
        jsonfile = None
        depjsonfile = None
        ok = False
        try:
            fd,jsonfile = tempfile.mkstemp(suffix='.json',prefix='parse',dir=None,text=True)
            os.close(fd)
            fd = -1
            fd ,depjsonfile = tempfile.mkstemp(suffix='.json',prefix='parse',dir=None,text=True)
            os.close(fd)
            fd = -1
            with open(jsonfile,'w+') as f:
                f.write('{"dep":{"list" : ["jsonval1","jsonval2"],"string" : "jsonstring"},"port":6000,"verbose":3}\n')
            with open(depjsonfile,'w+') as f:
                f.write('{"list":["depjson1","depjson2"]}\n')

            env = dict()
            env['DEP_JSON'] = depjsonfile
            self.__extargs_running(commandline,['-p','9000','--json',jsonfile,'dep','--dep-string','ee','ww'],env)
            ok = True
        finally:
            if depjsonfile is not None and ok:
                os.remove(depjsonfile)
            elif depjsonfile is not None:
                logging.error('depjsonfile %s'%(depjsonfile))
            depjsonfile = None
            if jsonfile is not None and ok:
                os.remove(jsonfile)
            elif jsonfile is not None:
                logging.error('jsonfile %s'%(jsonfile))
            jsonfile = None
        return


    def test_A016(self):
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
            }
        }
        '''
        jsonfile = None
        depjsonfile = None
        ok = False
        try:
            depstrval = 'newval'
            depliststr = '["depenv1","depenv2"]'
            fd,jsonfile = tempfile.mkstemp(suffix='.json',prefix='parse',dir=None,text=True)
            os.close(fd)
            fd = -1
            fd ,depjsonfile = tempfile.mkstemp(suffix='.json',prefix='parse',dir=None,text=True)
            os.close(fd)
            fd = -1
            with open(jsonfile,'w+') as f:
                f.write('{"dep":{"list" : ["jsonval1","jsonval2"],"string" : "jsonstring"},"port":6000,"verbose":3}\n')
            with open(depjsonfile,'w+') as f:
                f.write('{"list":["depjson1","depjson2"]}\n')


            env = dict()
            env['EXTARGSPARSE_JSON'] = jsonfile
            env['DEP_JSON'] = depjsonfile
            env['DEP_STRING'] = depstrval
            env['DEP_LIST']= depliststr            
            self.__extargs_running(commandline,['-p','9000','dep','--dep-string','ee','ww'],env)
            ok = True
        finally:
            if depjsonfile is not None and ok:
                os.remove(depjsonfile)
            elif depjsonfile is not None:
                logging.error('depjsonfile %s'%(depjsonfile))
            depjsonfile = None
            if jsonfile is not None and ok:
                os.remove(jsonfile)
            elif jsonfile is not None:
                logging.error('jsonfile %s'%(jsonfile))
            jsonfile = None
        return

    def test_A017(self):
        commandline= '''
        {
            "+dpkg" : {
                "dpkg" : "dpkg"
            },
            "verbose|v" : "+",
            "$port|p" : {
                "value" : 3000,
                "type" : "int",
                "nargs" : 1 , 
                "helpinfo" : "port to connect"
            }
        }
        '''
        self.__extargs_running(commandline,[])
        return

    def test_A018(self):
        commandline= '''
        {
            "+dpkg" : {
                "dpkg" : "dpkg"
            },
            "verbose|v" : "+",
            "rollback|r": true,
            "$port|p" : {
                "value" : 3000,
                "type" : "int",
                "nargs" : 1 , 
                "helpinfo" : "port to connect"
            }
        }
        '''
        self.__extargs_running(commandline,['-vvrvv'])
        return

    def test_A019(self):
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
            }
        }
        '''
        jsonfile = None
        depjsonfile = None
        ok = False
        try:
            depstrval = 'newval'
            depliststr = '["depenv1","depenv2"]'
            fd,jsonfile = tempfile.mkstemp(suffix='.json',prefix='parse',dir=None,text=True)
            os.close(fd)
            fd = -1
            fd ,depjsonfile = tempfile.mkstemp(suffix='.json',prefix='parse',dir=None,text=True)
            os.close(fd)
            fd = -1
            with open(jsonfile,'w+') as f:
                f.write('{"dep":{"list" : ["jsonval1","jsonval2"],"string" : "jsonstring"},"port":6000,"verbose":3}\n')
            with open(depjsonfile,'w+') as f:
                f.write('{"list":["depjson1","depjson2"]}\n')

            env = dict()
            env['EXTARGSPARSE_JSON'] = jsonfile
            env['DEP_JSON'] = depjsonfile
            env['DEP_STRING'] = depstrval
            env['DEP_LIST'] = depliststr

            priority = []
            priority.append('ENV_CMD_JSON')
            priority.append('ENV_CMD')
            priority.append('ENV_SUBCMD_JSON')
            self.__extargs_running(commandline,['-p','9000','dep','--dep-string','ee','ww'],env,priority)
            ok = True
        finally:
            if depjsonfile is not None and ok:
                os.remove(depjsonfile)
            elif depjsonfile is not None:
                logging.error('depjsonfile %s'%(depjsonfile))
            depjsonfile = None
            if jsonfile is not None and ok:
                os.remove(jsonfile)
            elif jsonfile is not None:
                logging.error('jsonfile %s'%(jsonfile))
            jsonfile = None
        return

    def test_A020(self):
        commandline= '''
        {
            "verbose|v" : "+",
            "rollback|R" : true,
            "$port|P" : {
                "value" : 3000,
                "type" : "int",
                "nargs" : 1 , 
                "helpinfo" : "port to connect"
            },
            "dep" : {
                "list|l" : [],
                "string|s" : "s_var",
                "$" : "+"
            }
        }
        '''
        self.__extargs_running(commandline,['-P','9000','--no-rollback','dep','--dep-string','ee','ww'])
        return

    def test_A021(self):
        commandline= '''
        {
            "maxval|m" : 392244922
        }
        '''
        self.__extargs_running(commandline,['-m','0xffcc'])
        return

    def test_A022(self):
        commandline='''
        {
            "verbose|v<m_verbose>" : "+",
            "username|u<m_username>" : null,
            "password|p<m_password>" : null
        }
        '''
        self.__extargs_running(commandline,['-u','Adminitrator','-p','123456'])
        return

    def test_A024(self):
        commandline='''
        {
            "rdep" : {
                "ip" : {
                    "modules" : [],
                    "called" : true,
                    "setname" : null,
                    "$" : 2
                }
            },
            "dep" : {
                "port" : 5000,
                "cc|C" : true
            },
            "verbose|v" : "+"
        }
        '''
        self.__extargs_running(commandline,['rdep','ip','--verbose','--rdep-ip-modules','cc','--rdep-ip-setname','bb','xx','bb'])
        return

    def test_A025(self):
        commandline= '''
        {
            "verbose|v" : "+",
            "+http" : {
                "url|u" : "http://www.google.com",
                "visual_mode|V": false
            },
            "$port|p" : {
                "value" : 3000,
                "type" : "int",
                "nargs" : 1 , 
                "helpinfo" : "port to connect"
            },
            "dep" : {
                "list|l" : [],
                "string|s" : "s_var",
                "$" : "+",
                "ip" : {
                    "verbose" : "+",
                    "list" : [],
                    "cc" : []
                }
            },
            "rdep" : {
                "ip" : {
                    "verbose" : "+",
                    "list" : [],
                    "cc" : []
                }
            }
        }
        '''
        jsonfile = None
        depjsonfile = None
        rdepjsonfile = None
        ok = False
        try:
            depstrval = 'newval'
            depliststr = '["depenv1","depenv2"]'
            httpvmstr = "True"
            fd,jsonfile = tempfile.mkstemp(suffix='.json',prefix='parse',dir=None,text=True)
            os.close(fd)
            fd = -1
            fd ,depjsonfile = tempfile.mkstemp(suffix='.json',prefix='parse',dir=None,text=True)
            os.close(fd)
            fd = -1
            fd,rdepjsonfile = tempfile.mkstemp(suffix='.json',prefix='parse',dir=None,text=True)
            os.close(fd)
            fd = -1
            with open(jsonfile,'w+') as f:
                f.write('{ "http" : { "url" : "http://www.github.com"} ,"dep":{"list" : ["jsonval1","jsonval2"],"string" : "jsonstring"},"port":6000,"verbose":3}\n')
            with open(depjsonfile,'w+') as f:
                f.write('{"list":["depjson1","depjson2"]}\n')
            with open(rdepjsonfile,'w+') as f:
                f.write('{"ip": {"list":["rdepjson1","rdepjson3"],"verbose": 5}}\n')

            env = dict()
            env['EXTARGSPARSE_JSON'] = jsonfile
            env['DEP_JSON'] = depjsonfile
            env['RDEP_JSON'] = rdepjsonfile

            self.__extargs_running(commandline,['-p','9000','rdep','ip','--rdep-ip-verbose','--rdep-ip-cc','ee','ww'],env)
            ok = True            
        finally:
            if depjsonfile is not None and ok:
                os.remove(depjsonfile)
            elif depjsonfile is not None:
                logging.error('depjsonfile %s'%(depjsonfile))
            depjsonfile = None
            if rdepjsonfile is not None and ok:
                os.remove(rdepjsonfile)
            elif rdepjsonfile is not None:
                logging.error('rdepjsonfile %s'%(rdepjsonfile))
            rdepjsonfile = None
            if jsonfile is not None and ok:
                os.remove(jsonfile)
            elif jsonfile is not None:
                logging.error('jsonfile %s'%(jsonfile))
            jsonfile = None
        return


    def test_A031(self):
        inner_command='''
        {
            "verbose|v" : "+",
            "catch|C## to not catch the exception ##" : true,
            "input|i## to specify input default(stdin)##" : null,
            "$caption## set caption (runcommand)##" : "runcommand",
            "test|t##to test mode##" : false,
            "release|R##to release test mode##" : false,
            "$" : "*"
        }
        '''
        self.__extargs_running(inner_command,['--test'])
        return

    def test_A034(self):
        commandline='''
        {
            "dep" : {
                "string|S" : "stringval"
            }
        }
        '''
        depjson = None
        ok = False
        try:
            fd,depjson = tempfile.mkstemp(suffix='.json',prefix='dep',dir=None,text=True)
            os.close(fd)
            with open(depjson,'w') as fout:
                fout.write('{"dep_string":null}')
            self.__extargs_running(commandline,['--json',depjson, 'dep'])
            ok = True
        finally:
            if depjson is not None and ok :
                os.remove(depjson)
            elif depjson is not None:
                logging.error('depjson %s'%(depjson))
            depjson = None
        return

    def test_A035(self):
        commandline = '''
        {
            "float1|f" : 3.633 ,
            "float2" : 6422.22,
            "float3" : 44463.23,
            "verbose|v" : "+"
        }
        '''
        depjsonfile = None
        rdepjsonfile = None
        rdepipjsonfile = None
        jsonfile = None
        ok = False
        try:
            jsonfile = self.__write_temp_file('{"verbose": 30,"float3": 77.1}')
            env = dict()
            env['EXTARGSPARSE_JSON'] = jsonfile
            self.__extargs_running(commandline,['-vvvv','-f','33.21','--json',jsonfile],env)
            ok = True
        finally:
            self.__remove_file_ok(depjsonfile,'depjsonfile',ok)
            self.__remove_file_ok(rdepjsonfile,'rdepjsonfile',ok)
            self.__remove_file_ok(rdepipjsonfile,'rdepipjsonfile',ok)
            self.__remove_file_ok(jsonfile,'jsonfile',ok)
            depjsonfile = None
            rdepjsonfile = None
            rdepipjsonfile = None
            jsonfile = None
        return

    def test_A039(self):
        commandline='''
        {
            "verbose|v" : "+",
            "kernel|K" : "/boot/",
            "initrd|I" : "/boot/",
            "encryptfile|e" : null,
            "encryptkey|E" : null,
            "setupsectsoffset" : 451
        }
        '''
        env = dict()
        env['EXTARGS_VERBOSE'] = '4'
        env['EXTARGS_SETUPSECTSOFFSET'] = '0x612'
        self.__extargs_running(commandline,[],env)
        return

    def test_A041(self):
        commandline_fmt='''
        {
            "countryname|N" : "CN",
            "statename|S" : "ZJ",
            "localityname" : "HZ",
            "organizationname|O" : ["BT"],
            "organizationunitname" : "BT R&D",
            "commonname|C" : "bingte.com",
            "+ssl" : {
                "chain" : true,
                "dir" : "%s",
                "bits" : 4096,
                "md" : "sha256",
                "utf8" : true,
                "name" : "ipxe",
                "days" : 3650,
                "crl-days": 365,
                "emailaddress" : "bt@bingte.com",
                "aia_url" : "http://bingte.com/sec/aia",
                "crl_url" : "http://bingte.com/sec/crl",
                "ocsp_url" : "http://bingte.com/sec/ocsp",
                "dns_url" : ["bingte.com"],
                "excluded_ip" : ["0.0.0.0/0.0.0.0","0:0:0:0:0:0:0:0/0:0:0:0:0:0:0:0"],
                "password|P" : null,
                "copy_extensions" : "none",
                "subca" : false,
                "comment": ""
            }
        }
        '''
        curdir = os.path.abspath(os.path.dirname(__file__))
        curdir = os.path.join(curdir,'certs')
        curdir = curdir.replace('\\','\\\\')
        commandline = commandline_fmt%(curdir)
        jsonfile = None
        ok = False
        try:
            jsonfile = self.__write_jsonfile('{"emailaddress" : "unit@bingte.com","organizationname" : "BT RD","ssl" :{ "dir" : "./certs/bingte","name" : "bingte","subca" : true,"copy_extensions" : "copy","days" : 375,"crl_days" : 30,"bits" : 4096}}')
            self.__extargs_running(commandline,['--json',jsonfile])
            ok = True
        finally:
            self.__remove_file_ok(jsonfile,'jsonfile',ok)
            jsonfile = None
        return

    def test_A042(self):
        commandline='''
        {
            "verbose|v" : "+",
            "kernel|K" : "/boot/",
            "initrd|I" : "/boot/",
            "encryptfile|e" : null,
            "encryptkey|E" : null,
            "setupsectsoffset" : 663,
            "ipxe" : {
                "$" : "+"
            }
        }
        '''
        self.__extargs_running(commandline,['-vvvK','kernel','--initrd','initrd','cc','dd','-E','encryptkey','-e','encryptfile','ipxe'])
        return

    def test_A043(self):
        commandline='''
        {
            "verbose|v" : "+",
            "kernel|K" : "/boot/",
            "initrd|I" : "/boot/",
            "encryptfile|e" : null,
            "encryptkey|E" : null,
            "setupsectsoffset" : 663,
            "ipxe" : {
                "$" : "+"
            }
        }
        '''
        optstr='''
        {
            "parseall" : true,
            "longprefix" : "-",
            "shortprefix" : "-"
        }
        '''
        self.__extargs_running(commandline,['-K','kernel','-initrd','initrd','cc','dd','-E','encryptkey','-e','encryptfile','ipxe'],env=None,priority=None,optdir=None,extoptions=optstr)
        return

    def test_A044(self):
        commandline='''
        {
            "verbose|v" : "+",
            "kernel|K" : "/boot/",
            "initrd|I" : "/boot/",
            "encryptfile|e" : null,
            "encryptkey|E" : null,
            "setupsectsoffset" : 663,
            "ipxe" : {
                "$" : "+"
            }
        }
        '''
        optstr='''
        {
            "parseall" : true,
            "longprefix" : "++",
            "shortprefix" : "+"
        }
        '''
        self.__extargs_running(commandline,['+K','kernel','++initrd','initrd','cc','dd','+E','encryptkey','+e','encryptfile','ipxe'],env=None,priority=None,optdir=None,extoptions=optstr)
        return

    def test_A045(self):
        commandline='''
        {
            "verbose|v" : "+",
            "kernel|K" : "/boot/",
            "initrd|I" : "/boot/",
            "pair|P!optparse=debug_set_2_args!" : [],
            "encryptfile|e" : null,
            "encryptkey|E" : null,
            "setupsectsoffset" : 663,
            "ipxe" : {
                "$" : "+"
            }
        }
        '''
        optstr='''
        {
            "parseall" : true,
            "longprefix" : "++",
            "shortprefix" : "+"
        }
        '''
        self.__extargs_running(commandline,['+K','kernel','++pair','initrd','cc','dd','+E','encryptkey','+e','encryptfile','ipxe'],env=None,priority=None,optdir=None,extoptions=optstr)
        return

    def test_A046(self):
        commandline='''
        {
            "verbose|v" : "+",
            "kernel|K" : "/boot/",
            "initrd|I" : "/boot/",
            "pair|P!optparse=debug_set_2_args;opthelp=debug_opthelp_set!" : [],
            "encryptfile|e" : null,
            "encryptkey|E" : null,
            "setupsectsoffset" : 663,
            "ipxe" : {
                "$" : "+"
            }
        }
        '''
        optstr='''
        {
            "parseall" : true,
            "longprefix" : "++",
            "shortprefix" : "+"
        }
        '''
        tempf = None
        optfile = None
        ok = False
        try:
            retoutlines,tempf,optfile = self.__extargs_opttest_out(commandline,['+h'],env=None,priority=None,optdir=None,extoptions=optstr)
            matchexpr = re.compile('.*opthelp function set \[pair\].*')
            for l in retoutlines:
                if matchexpr.match(l):
                    ok = True
            self.assertEqual(ok,True)
        finally:
            self.__remove_file_ok(tempf,'tempf',ok)
            self.__remove_file_ok(optfile,'optfile',ok)
        return

    def test_A047(self):
        commandline='''
        {
            "verbose|v" : "+",
            "kernel|K" : "/boot/",
            "initrd|I" : "/boot/",
            "pair|P!optparse=debug_set_2_args;opthelp=debug_opthelp_set!" : [],
            "encryptfile|e" : null,
            "encryptkey|E" : null,
            "setupsectsoffset" : 663,
            "ipxe" : {
                "$" : "+"
            }
        }
        '''
        optstr='''
        {
            "parseall" : true,
            "longprefix" : "++",
            "shortprefix" : "+",
            "helplong" : "usage",
            "helpshort" : "?",
            "jsonlong" : "jsonfile"
        }
        '''
        ok = False
        tempf = None
        optfile = None
        try:
            retoutlines,tempf,optfile = self.__extargs_opttest_out(commandline,['++usage'],env=None,priority=None,optdir=None,extoptions=optstr)
            matchexpr = re.compile('^\s+\+\+usage|\+?\s+.*')
            for l in retoutlines:
                if matchexpr.match(l):
                    ok = True
            self.assertEqual(ok,True)
        finally:
            self.__remove_file_ok(tempf,'tempf',ok)
            self.__remove_file_ok(optfile,'optfile',ok)
        return

    def test_A048(self):
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
            }
        }
        '''
        jsonfile = None
        depjsonfile = None
        try:
            depstrval = 'newval'
            depliststr = '["depenv1","depenv2"]'
            deplistval = eval(depliststr)
            jsonfile = self.__write_jsonfile('{"dep":{"list" : ["jsonval1","jsonval2"],"string" : "jsonstring"},"port":6000,"verbose":3}\n')
            depjsonfile = self.__write_jsonfile('{"list":["depjson1","depjson2"]}\n')
            env = dict()
            env['EXTARGSPARSE_JSONFILE'] = jsonfile
            env['DEP_JSONFILE'] = depjsonfile
            env['DEP_STRING'] = depstrval
            env['DEP_LIST'] = depliststr
            optstr='''
            {
                "jsonlong" : "jsonfile"
            }
            '''
            priority = []
            priority.append('ENV_CMD_JSON')
            priority.append('ENV_CMD')
            priority.append('ENV_SUBCMD_JSON')
            self.__extargs_running(commandline,['-p','9000','dep','--dep-string','ee','ww'],env=env,priority=priority,optdir=None,extoptions=optstr)
        finally:
            if depjsonfile is not None:
                os.remove(depjsonfile)
            depjsonfile = None
            if jsonfile is not None:
                os.remove(jsonfile)
            jsonfile = None
        return


    def test_A049(self):
        commandline= '''
        {
            "verbose|v##very long very long very long very long very long very long very long very long very long very long very long very long very long very long very long very long very long very long##" : "+",
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
            }
        }
        '''
        optstr='''
        {
            "screenwidth" : 60
        }
        '''
        tempf = None
        optfile = None
        ok = False
        try:
            retoutlines,tempf,optfile = self.__extargs_opttest_out(commandline,['-h'],env=None,priority=None,optdir=None,extoptions=optstr)
            idx = 0
            overlength = 0
            for c in retoutlines:
                if len(c) > 65 and idx > 0:
                    overlength = 1
                idx += 1
            self.assertEqual(overlength,0)
            self.__remove_file_ok(tempf,'tempf',True)
            self.__remove_file_ok(optfile,'optfile',True)
            tempf = None
            optfile = None
            optstr='''
            {
                "screenwidth" : 80
            }
            '''
            retoutlines,tempf,optfile = self.__extargs_opttest_out(commandline,['-h'],env=None,priority=None,optdir=None,extoptions=optstr)
            idx = 0
            overlength = 0
            for c in retoutlines:
                if len(c) > 65 and idx > 0:
                    overlength = 1
                idx += 1
            self.assertEqual(overlength,1)
            ok = True
        finally:
            self.__remove_file_ok(tempf,'tempf',ok)
            self.__remove_file_ok(optfile,'optfile',ok)
        return


    def test_A050(self):
        commandline= '''
        {
            "verbose|v" : "+",
            "dep" : {
                "list|l" : [],
                "string|s" : "s_var",
                "$" : "+"
            }
        }
        '''
        optstr='''
        {
            "helplong" : "usage",
            "helpshort" : "?",
            "longprefix" : "++",
            "shortprefix" : "+"
        }
        '''
        ok = False
        tempf = None
        optfile = None
        try:
            retoutlines,tempf,optfile = self.__extargs_opttest_out(commandline,['+?'],env=None,priority=None,optdir=None,extoptions=optstr)
            matchexpr = re.compile('^\s+\+\+usage|\+\?\s+to display.*')
            for l in retoutlines:
                if matchexpr.match(l):
                    ok = True
            self.assertEqual(ok,True)
        finally:
            self.__remove_file_ok(tempf,'tempf',ok)
            self.__remove_file_ok(optfile,'optfile',ok)
        return


    def test_A051(self):
        commandline= '''
        {
            "verbose|v" : "+",
            "dep" : {
                "list|l" : [],
                "string|s" : "s_var",
                "$" : "+"
            }
        }
        '''
        optstr = '''
        {
            "helplong" : "usage",
            "helpshort" : null,
            "longprefix" : "++",
            "shortprefix" : "+"
        }
        '''
        ok = False
        tempf = None
        optfile = None
        try:
            retoutlines,tempf,optfile = self.__extargs_opttest_out(commandline,['++usage'],env=None,priority=None,optdir=None,extoptions=optstr)
            matchexpr = re.compile('^\s+\+\+usage\s+to display.*')
            for l in retoutlines:
                if matchexpr.match(l):
                    ok = True
            self.assertEqual(ok,True)
        finally:
            self.__remove_file_ok(tempf,'tempf',ok)
            self.__remove_file_ok(optfile,'optfile',ok)
        return

    def test_A052(self):
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
            }
        }
        '''
        optstr='''
        {
            "nojsonoption" : true,
            "nohelpoption" : true
        }
        '''
        cmdstr='''
        {
            "usageout" : ""
        }
        '''
        ok = False
        jsonfile = None
        depjsonfile = None
        tempf = None
        optfile = None
        try:
            depstrval = 'newval'
            depliststr = '["depenv1","depenv2"]'
            deplistval = eval(depliststr)
            jsonfile = self.__write_jsonfile('{"dep":{"list" : ["jsonval1","jsonval2"],"string" : "jsonstring"},"port":6000,"verbose":3}\n')
            depjsonfile = self.__write_jsonfile('{"list":["depjson1","depjson2"]}\n')
            env = dict()
            env['EXTARGSPARSE_JSONFILE'] = jsonfile
            env['DEP_JSONFILE'] = depjsonfile
            env['DEP_STRING'] = depstrval
            env['DEP_LIST'] = depliststr
            priority = []
            priority.append('ENV_CMD_JSON')
            priority.append('ENV_CMD')
            priority.append('ENV_SUBCMD_JSON')
            retoutlines , tempf,optfile = self.__extargs_opttest_out(commandline,[],env=env,priority=priority,optdir=None,extoptions=optstr,opttestcmds=cmdstr)
            helpexpr = re.compile('^\s+--help.*')
            jsonexpr = re.compile('^\s+--json.*')
            helpfind = False
            jsonfind = False
            self.assertTrue(len(retoutlines) > 0)
            for l in retoutlines:
                if jsonexpr.match(l):
                    jsonfile = True
                if helpexpr.match(l):
                    helpfind = True
            self.assertEqual(helpfind , False)
            self.assertEqual(jsonfind , False)
            self.__extargs_running(commandline,['-p','9000','dep','--dep-string','ee','ww'],env=env,priority=priority,optdir=None,extoptions=optstr)
            ok = True
        finally:
            self.__remove_file_ok(optfile,'optfile',ok)
            self.__remove_file_ok(tempf,'tempf',ok)
            self.__remove_file_ok(jsonfile,'jsonfile',ok)
            self.__remove_file_ok(depjsonfile,'depjsonfile',ok)
        return


    def test_A053(self):
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
        cmdstr='''
        {
            "usageout" : "dep"
        }
        '''
        ok = False
        tempf = None
        optfile = None
        jsonfile = None
        depjsonfile = None
        try:
            depstrval = 'newval'
            depliststr = '["depenv1","depenv2"]'
            deplistval = eval(depliststr)
            jsonfile = self.__write_jsonfile('{"list" : ["jsonval1","jsonval2"],"string" : "jsonstring","port":6000,"verbose":3}\n')
            depjsonfile = self.__write_jsonfile('{"list":["depjson1","depjson2"]}\n')
            env = dict()
            env['EXTARGSPARSE_JSON'] = jsonfile
            env['DEP_JSON'] = depjsonfile
            env['EXTARGS_STRING'] = depstrval
            env['EXTARGS_LIST'] = depliststr
            priority = []
            priority.append('ENV_CMD_JSON')
            priority.append('ENV_CMD')
            priority.append('ENV_SUBCMD_JSON')
            retoutlines , tempf,optfile = self.__extargs_opttest_out(commandline,['oneadd'],env=env,priority=priority,optdir=None,extoptions=optstr,opttestcmds=cmdstr)

            # now it will give no help
            helpexpr = re.compile('^\s+--help.*')
            jsonexpr = re.compile('^\s+--dep-json.*')
            listexpr = re.compile('^\s+--list.*')
            stringexpr = re.compile('^\s+--string.*')
            helpfind = False
            jsonfind = False
            listfind = False
            stringfind = False
            for l in retoutlines:
                if helpexpr.match(l):
                    helpfind = True
                if jsonexpr.match(l):
                    jsonfind = True
                if listexpr.match(l):
                    listfind = True
                if stringexpr.match(l):
                    stringfind = True
            self.assertEqual(helpfind,True)
            self.assertEqual(jsonfind,True)
            self.assertEqual(listfind,True)
            self.assertEqual(stringfind,True)
            self.__remove_file_ok(tempf,'tempf',True)
            self.__remove_file_ok(optfile,'optfile',True)
            tempf = None
            optfile = None

            cmdstr='''
            {
                "usageout" : "rdep"
            }
            '''
            retoutlines , tempf,optfile = self.__extargs_opttest_out(commandline,['oneadd'],env=env,priority=priority,optdir=None,extoptions=optstr,opttestcmds=cmdstr)
            helpexpr = re.compile('^\s+--help.*')
            jsonexpr = re.compile('^\s+--rdep-json.*')
            listexpr = re.compile('^\s+--list.*')
            stringexpr = re.compile('^\s+--string.*')
            helpfind = False
            jsonfind = False
            listfind = False
            stringfind = False
            for l in retoutlines:
                if helpexpr.match(l):
                    helpfind = True
                if jsonexpr.match(l):
                    jsonfind = True
                if listexpr.match(l):
                    listfind = True
                if stringexpr.match(l):
                    stringfind = True
            self.assertEqual(helpfind,True)
            self.assertEqual(jsonfind,True)
            self.assertEqual(listfind,True)
            self.assertEqual(stringfind,True)
            self.__extargs_opttest_out(commandline,['-p','9000','dep','--string','ee','ww'],env=env,priority=priority,optdir=None,extoptions=optstr)
            ok = True
        finally:
            self.__remove_file_ok(optfile,'optfile',ok)
            self.__remove_file_ok(tempf,'tempf',ok)
            self.__remove_file_ok(jsonfile,'jsonfile',ok)
            self.__remove_file_ok(depjsonfile,'depjsonfile',ok)
        return

    def test_A054(self):
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
            }
        }
        '''
        optstr='''
        {
            "jsonlong" : "jsonfile"
        }
        '''
        ok = False
        jsonfile = None
        depjsonfile = None
        try:
            depstrval = 'newval'
            depliststr = '["depenv1","depenv2"]'
            deplistval = eval(depliststr)
            jsonfile = self.__write_jsonfile('{"dep":{"list" : ["jsonval1","jsonval2"],"string" : "jsonstring"},"port":6000,"verbose":3}\n')
            depjsonfile = self.__write_jsonfile('{"list":["depjson1","depjson2"]}\n')
            env = dict()
            env['EXTARGSPARSE_JSONFILE'] = jsonfile
            env['DEP_JSONFILE'] = depjsonfile
            priority = []
            priority.append('ENV_CMD_JSON')
            priority.append('ENV_CMD')
            priority.append('ENV_SUBCMD_JSON')
            env['DEP_STRING'] = depstrval
            env['DEP_LIST'] = depliststr

            self.__extargs_opttest_out(commandline,['--jsonfile',jsonfile,'dep','ww'],env=env,priority=priority,optdir=None,extoptions=optstr)
            ok = True
        finally:
            self.__remove_file_ok(jsonfile,'jsonfile',ok)
            self.__remove_file_ok(depjsonfile,'depjsonfile',ok)
        return


    def test_A055(self):
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
                "list|l!jsonfunc=debug_2_jsonfunc!" : [],
                "string|s!jsonfunc=debug_upper_jsonfunc!" : "s_var",
                "$" : "+"
            }
        }
        '''
        optstr='''
        {
            "jsonlong" : "jsonfile"
        }
        '''
        ok = False
        jsonfile = None
        depjsonfile = None
        try:
            depstrval = 'newval'
            depliststr = '["depenv1","depenv2"]'
            jsonfile = self.__write_jsonfile('{"dep":{"list" : ["jsonval1","jsonval2"],"string" : "jsonstring"},"port":6000,"verbose":3}\n')
            depjsonfile = self.__write_jsonfile('{"list":["depjson1","depjson2"]}\n')

            env = dict()
            env['EXTARGSPARSE_JSONFILE'] = jsonfile
            env['DEP_JSONFILE'] = depjsonfile
            priority = []
            priority.append('ENV_CMD_JSON')
            priority.append('ENV_CMD')
            priority.append('ENV_SUBCMD_JSON')
            env['DEP_STRING'] = depstrval
            env['DEP_LIST'] = depliststr

            self.__extargs_opttest_out(commandline,['--jsonfile',jsonfile,'dep','ww'],env=env,priority=priority,optdir=None,extoptions=optstr)
            ok = True
        finally:
            self.__remove_file_ok(jsonfile,'jsonfile',ok)
            self.__remove_file_ok(depjsonfile,'depjsonfile',ok)
        return

    def test_A057(self):
        commandline='''
        {
            "asn1parse" : {
                "$" : 0,
                "$inform" : null,
                "$in" : null,
                "$out" : null,
                "$noout" : false,
                "$offset" : 0,
                "$length" : -1,
                "$dump" : false,
                "$dlimit" : -1,
                "$oid" : null,
                "$strparse" : 0,
                "$genstr" : null,
                "$genconf" : null
            },
            "ca" : {
                "$" : 0,
                "$config" : null,
                "$name" : null,
                "$in" : null,
                "$ss_cert" : null,
                "$spkac" : null,
                "$infiles" : null,
                "$out" : null,
                "$outdir" : null,
                "$cert" : null,
                "$keyfile" : null,
                "$keyform" : null,
                "$key" : null,
                "$selfsign" : false,
                "$passin" : null,
                "$verbose" : "+",
                "$notext" : false,
                "$startdate" : null,
                "$enddate" : null,
                "$days" : 30,
                "$md" : null,
                "$policy" : null,
                "$preserveDN" : false,
                "$msie_hack" : false,
                "$noemailDN" : false,
                "$batch" : false,
                "$extensions" : null,
                "$extfile" : null,
                "$engine" : null,
                "$subj" : null,
                "$utf8" : false,
                "$multivalue-rdn" : false,
                "$gencrl" : false,
                "$crldays" : 30,
                "$crlhours" : -1,
                "$revoke" : null,
                "$status" : null,
                "$updatedb" : false,
                "$crl_reason" : null,
                "$crl_hold" : null,
                "$crl_compromise" : null,
                "$crl_CA_compromise" : null,
                "$crlexts" : null
            }
        }        
        '''
        extoptions='''
        {
            "longprefix" : "-",
            "shortprefix" : "-",
            "nojsonoption" : true,
            "cmdprefixadded" : false,
            "flagnochange" : true
        }
        '''
        self.__extargs_opttest_out(commandline,['ca','-crl_CA_compromise','eeww'],extoptions=extoptions)
        return


def __init_lib_paths(pathtoload):
    uname0 = platform.uname()[0]
    uname0 = uname0.lower()    
    if uname0 == 'linux':
        libpaths = ''
        if 'LD_LIBRARY_PATH'in os.environ.keys():
            libpaths = os.environ['LD_LIBRARY_PATH']
        if len(libpaths) > 0:
            sarr = re.split(':',libpaths)
        else:
            sarr = []
        logging.info('sarr %s'%(sarr))
        if pathtoload not in sarr:
            logging.info('add %s'%(pathtoload))
            sarr.append(pathtoload)
        i = 0
        libpaths = ''
        for c in sarr:
            if i > 0:
                libpaths += ':'
            libpaths += c
            i +=1
        os.environ['LD_LIBRARY_PATH'] = libpaths
        logging.info('LD_LIBRARY_PATH %s'%(os.environ['LD_LIBRARY_PATH']))
    elif uname0 == 'windows':
        libpaths = ''
        if 'PATH' in os.environ.keys():
            libpaths = os.environ['PATH']
        if len(libpaths) > 0:
            sarr = re.split(';',libpaths)
        else:
            sarr = []
        logging.info('sarr %s'%(sarr))
        if pathtoload not in sarr:
            logging.info('add %s'%(pathtoload))
            sarr.append(pathtoload)
        i = 0
        libpaths = ''
        for c in sarr:
            if i > 0:
                libpaths += ';'
            libpaths += c
            i +=1
        os.environ['PATH'] = libpaths
        logging.info('PATH %s'%(os.environ['PATH']))
    else:
        raise Exception('OS %s not supported now'%(uname0))

def add_drmemory_path(drmemory):
    if not os.path.exists(drmemory):
        raise Exception('%s not exists'%(drmemory))
    path = os.path.dirname(os.path.abspath(drmemory))
    paths = os.environ['PATH']
    oldpaths = re.split(os.pathsep,paths)
    newpaths = oldpaths
    if path not in oldpaths:
        newpaths = [path]
        newpaths.extend(oldpaths)
    elif path != oldpaths[0]:
        oldpaths.remove(path)
        newpaths= [path]
        newpaths.extend(oldpaths)
    os.environ['PATH'] = os.pathsep.join(newpaths)
    return


def main():
    commandline='''
    {
        "verbose|v" : "+",
        "failfast|f" : false,
        "static|s" : false,
        "drmemory|D" : null,
        "reserved|R" : false,
        "$" : "*"
    }
    '''
    oldextargs_level = None
    if 'EXTARGSPARSE_LOGLEVEL' in os.environ.keys():
        oldextargs_level = os.environ['EXTARGSPARSE_LOGLEVEL']
        del os.environ['EXTARGSPARSE_LOGLEVEL']
    parser = extargsparse.ExtArgsParse()
    parser.load_command_line_string(commandline)
    args = parser.parse_command_line()
    if oldextargs_level is not None:
        os.environ['EXTARGSPARSE_LOGLEVEL'] = oldextargs_level
    set_log_level(args)
    unittestargs = []
    unittestargs.extend(args.args)
    if args.verbose >= 3:
        os.environ['MAKEVERBOSE']='1'
    else:
        if 'MAKEVERBOSE' in os.environ.keys():
            del os.environ['MAKEVERBOSE']
    sys.argv[1:] = unittestargs
    # to set the log level
    os.environ['EXTARGSPARSE_LOGLEVEL'] = '%d'%(args.verbose)
    if args.static:
        os.environ['STATICLIB'] = '1'
        logging.info('use static')
    else:
        if 'STATICLIB' in os.environ.keys():
            del os.environ['STATICLIB']
        sopath = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)),'..','..','dynamiclib'))
        __init_lib_paths(sopath)
        logging.info('use dynamic')
    if args.reserved:
       os.environ['TEST_RESERVED']  = '1'
    else:
        if 'TEST_RESERVED' in os.environ.keys():
            del os.environ['TEST_RESERVED']
    if args.drmemory is not None:
        add_drmemory_path(args.drmemory)
    logging.info('running unittest')
    unittest.main(verbosity=args.verbose,failfast=args.failfast)
    return


if __name__ == '__main__':
    main()