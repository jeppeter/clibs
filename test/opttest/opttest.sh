#! /bin/bash

_script_file=`readlink -f $0`
script_dir=`dirname $_script_file`
topdir=`readlink -f $script_dir/../../`

export EXTARGSPARSE_LOGLEVEL=4
LD_LIBRARY_PATH=$topdir/dynamiclib $script_dir/opttest "$@"