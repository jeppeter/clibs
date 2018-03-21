#! /usr/bin/env python

import sys
import time

def main():
	i = 0
	for l in sys.stdin:
		l = l.rstrip('\r\n')
		sys.stdout.write('[%d] out [%s]\n'%(i,l))
		sys.stderr.write('[%d] err [%s]\n'%(i,l))		
		time.sleep(0.2)
		sys.stdout.flush()
		sys.stderr.flush()
		i += 1

main()