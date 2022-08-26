#! /bin/bash

sf=`readlink -f $0`
sd=`dirname $sf`
export LD_LIBRARY_PATH=$sd:/home/bt/sources/libgcrypt/libgcrypt20-1.9.4/src/.libs/:/home/bt/sources/openssl/openssl-3.0.2
$sd/ssltst $@