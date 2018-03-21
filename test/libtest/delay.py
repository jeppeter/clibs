#! /usr/bin/env python

import sys
import time

def main():
	i = 0
	wtime = 0.1
	if len(sys.argv[1:]) > 0:
		try:
			wtime = float(sys.argv[1])
		except:
			wtime = 0.1
	for l in sys.stdin:
		l = l.rstrip('\r\n')
		sys.stdout.write('[%d] out [%s]\n'%(i,l))
		sys.stderr.write('[%d] err [%s]\n'%(i,l))
		if wtime >= 0.1:		
			time.sleep(wtime)
		sys.stdout.flush()
		sys.stderr.flush()
		i += 1

try:
	main()
except:
	pass