#! /usr/bin/env python


import unittest
import extargsparse
import logging
import logging.handlers
import re
import sys
import os
import time
import random

def read_file(infile=None):
    fin = sys.stdin
    if infile is not None:
        fin = open(infile,'r+b')
    rets = ''
    for l in fin:
        s = l
        if 'b' in fin.mode:
            if sys.version[0] == '3':
                s = l.decode('utf-8')
        rets += s

    if fin != sys.stdin:
        fin.close()
    fin = None
    return rets

def read_file_bytes(infile=None):
    fin = sys.stdin
    if infile is not None:
        fin = open(infile,'rb')
    retb = b''
    while True:
        if fin != sys.stdin:
            curb = fin.read(1024 * 1024)
        else:
            curb = fin.buffer.read()
        if curb is None or len(curb) == 0:
            break
        retb += curb
    if fin != sys.stdin:
        fin.close()
    fin = None
    return retb


def write_file(s,outfile=None):
    fout = sys.stdout
    if outfile is not None:
        fout = open(outfile, 'w+b')
    outs = s
    if 'b' in fout.mode:
        outs = s.encode('utf-8')
    fout.write(outs)
    if fout != sys.stdout:
        fout.close()
    fout = None
    return 

def write_file_bytes(sarr,outfile=None):
    fout = sys.stdout
    if outfile is not None:
        fout = open(outfile, 'wb')
    if 'b' not in fout.mode:
        fout.buffer.write(sarr)
    else:        
        fout.write(sarr)
    if fout != sys.stdout:
        fout.close()
    fout = None
    return 


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

class libtest_cases(unittest.TestCase):
    def setUp(self):
        return
    def tearDown(self):
        return

    @classmethod
    def setUpClass(cls):
        return

    @classmethod
    def tearDownClass(cls):
        return


def test_handler(args,parser):
    set_logging(args)
    sys.argv[1:] = args.subnargs
    unittest.main()
    sys.exit(0)
    return

def rand_float(minval,maxval):
    return random.uniform(minval,maxval)

def genranfile_handler(args,parser):
    set_logging(args)
    randsize = 1024
    if len(args.subnargs) > 0:
        randsize = int(args.subnargs[0])
    wbytes = os.urandom(randsize)
    write_file_bytes(wbytes,args.output)
    sys.exit(0)
    return

def pumpfile_handler(args,parser):
    set_logging(args)
    inbytes = read_file_bytes(args.input)
    wlen = 0
    wsize = len(inbytes)
    random.seed(time.time())
    for i in range(len(args.subnargs)):
        clen = 0
        if wlen < wsize:
            clen = int(args.subnargs[i])
            if clen > (wsize - wlen):
                clen = wsize - wlen
            write_file_bytes(inbytes[wlen:(wlen+clen)],args.output)        
            time.sleep(rand_float(0.01,1.1))
        wlen += clen

    if wlen < wsize:
        write_file_bytes(inbytes[wlen:(wsize)],args.output)
        wlen = wsize
    sys.exit(0)
    return


def main():
    commandline='''
    {
        "random|R" : true,
        "output|o" : null,
        "input|i" : null,
        "test<test_handler>" : {
            "$" : "*"
        },
        "genranfile<genranfile_handler>## [randsize] default 1024##" : {
            "$" : "?"
        },
        "pumpfile<pumpfile_handler>## 1bytes ... to make bytes ##" : {
            "$" : "+"
        },
        "outrand<outrand_handler>" : {
            "$" : 0
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