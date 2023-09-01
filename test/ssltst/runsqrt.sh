#! /bin/bash



export LD_LIBRARY_PATH=/home/bt/source/openssl/:/mnt/zdisk/clibs/dynamiclib
outfile=/mnt/zdisk/bn.txt
simpleout=/mnt/zdisk/bn_simple.txt	
bnrand=/mnt/zdisk/bnrand.bin
bnrand2=/mnt/zdisk/bnrand2.bin
anum=0x543B60ADEEF534924A7A70030D1A404041D7DD115D93BA41AC6EB4A8
pnum=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001
if [ ! -x /mnt/zdisk/clibs/test/ssltst/ssltst ]
then
	pushd $PWD && cd /mnt/zdisk/clibs/test/ssltst && make && popd
fi

/mnt/zdisk/clibs/test/ssltst/ssltst bnmodsqrt $anum $pnum 2>$outfile
python /mnt/zdisk/pylib/utils.py filterlog -i $outfile -o $simpleout python
numbers=`cat $simpleout | grep -e 'random number' | awk '{print $3}' | xargs -I {} echo -n " {}"`
echo "number [$numbers]"
python /mnt/zdisk/pylib/utils.py randwr -o $bnrand2 $numbers
dd if=/dev/urandom of=$bnrand bs=1M count=2
dd if=$bnrand2 of=$bnrand conv=notrunc