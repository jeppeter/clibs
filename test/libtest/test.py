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
import select

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
    sock.setblocking(0)

    while True:
        try:
            rds = []
            rds.append(sock)
            logging.info('before select')
            retrds , _, _ =  select.select(rds,[],[])
            logging.info('after select')
            if len(retrds) > 0:
                clisock, cliaddr = sock.accept()
                logging.info('come %s'%(repr(cliaddr)))
                clisock.close()
                clisock = None
        except KeyboardInterrupt:
            logging.warn('interrupted')
            break
        except:
            logging.warn('%s'%(traceback.format_exc()))

    sys.exit(0)
    return

def svrwr_handler(args,parser):
    set_logging(args)
    port = int(args.subnargs[0])
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock.setsockopt( socket.SOL_SOCKET, socket.SO_REUSEADDR, 1 )
    sock.bind(('0.0.0.0',port))
    logging.info('listen on [%s]'%(port))
    sock.listen(5)
    sock.setblocking(0)
    wbytes = read_file_bytes(args.subnargs[1])
    clisock = None
    while True:
        try:
            rds = []
            rds.append(sock)
            logging.info('before select')
            retrds , _, _ =  select.select(rds,[],[])
            logging.info('after select')
            if len(retrds) > 0:
                clisock, cliaddr = sock.accept()
                logging.info('come %s'%(repr(cliaddr)))
                wlen = 0
                while wlen < len(wbytes):
                    curlen = len(wbytes) - wlen
                    if curlen > args.block:
                        curlen = args.block
                    clisock.sendto(wbytes[wlen:(wlen+curlen)], clisock.getpeername())
                    wlen += curlen
                    time.sleep(args.interval)
                clisock.close()
                clisock = None
        except KeyboardInterrupt:
            logging.warn('interrupted')
            break
        except:
            if clisock is not None:
                clisock.close()
            clisock = None
            logging.warn('%s'%(traceback.format_exc()))
        
    sys.exit(0)
    return


def svrrd_handler(args,parser):
    set_logging(args)
    port = int(args.subnargs[0])
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock.setsockopt( socket.SOL_SOCKET, socket.SO_REUSEADDR, 1 )
    sock.bind(('0.0.0.0',port))
    logging.info('listen on [%s]'%(port))
    sock.listen(5)
    sock.setblocking(0)
    clisock = None
    while True:
        try:
            rds = []
            rds.append(sock)
            logging.info('before select')
            retrds , _, _ =  select.select(rds,[],[])
            logging.info('after select')
            if len(retrds) > 0:
                clisock, cliaddr = sock.accept()
                logging.info('come %s'%(repr(cliaddr)))
                wlen = 0
                while True:
                    curlen = args.block
                    rbytes, raddr = clisock.recvfrom(curlen)
                    logging.info('read [%d]'%(len(rbytes)))
                    time.sleep(args.interval)
                clisock.close()
                clisock = None
        except KeyboardInterrupt:
            logging.warn('interrupted')
            break
        except:
            if clisock is not None:
                clisock.close()
            clisock = None
            logging.warn('%s'%(traceback.format_exc()))
        
    sys.exit(0)
    return

def cliwr_handler(args,parser):
    set_logging(args)
    port = int(args.subnargs[1])
    host = args.subnargs[0]
    fname = args.subnargs[2]
    wbytes = read_file_bytes(fname)
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    logging.info('connect [%s:%d]'%(host,port))

    sock.connect((host,port))
    wlen = 0
    while wlen < len(wbytes):
        curlen = len(wbytes) - wlen
        if curlen > args.block:
            curlen = args.block
        sock.sendto(wbytes[wlen:(wlen+curlen)], sock.getpeername())
        wlen += curlen
        time.sleep(args.interval)
    sock.close()
    sock = None        
    sys.exit(0)
    return


def main():
    commandline='''
    {
        "interval|I## interval in second##" : 0.1,
        "block|B##every block ##" : 1024,
        "listen<listen_handler>## port to listen on port##" : {
            "$" : 1
        },
        "svrwr<svrwr_handler>## port file ##" : {
            "$" : 2
        },
        "svrrd<svrrd_handler>## port ##" : {
            "$" : 1
        },
        "cliwr<cliwr_handler>## ip port file##" : {
            "$" : 3
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