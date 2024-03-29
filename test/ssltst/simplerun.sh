#! /bin/bash

mustcompile=0
while [ $# -gt 1 ]
do
	curfile=$1
	shift
	cp /mnt/zdisk/openssl/$curfile /home/bt/source/openssl/$curfile
	mustcompile=1	
done

if [ $mustcompile -ne 0 ]
then
	pushd && cd /home/bt/source/openssl/ && make  && popd
fi

export LD_LIBRARY_PATH=/home/bt/source/openssl/:/mnt/zdisk/clibs/dynamiclib
outfile=/mnt/zdisk/log.txt
simpleout=/mnt/zdisk/log_simple.txt
/mnt/zdisk/clibs/test/ssltst/ssltst ecsignbase /mnt/zdisk/ecpriv.bin 1152 2>$outfile
python /mnt/zdisk/pylib/utils.py filterlog -i $outfile -o $simpleout python
numbers=`cat $simpleout | grep -e 'random number' | awk '{print $3}' | xargs -I {} echo -n " {}"`
echo "number [$numbers]"
python /mnt/zdisk/pylib/utils.py randwr -o /mnt/zdisk/rand2.bin $numbers
dd if=/dev/urandom of=/mnt/zdisk/rand.bin bs=1M count=2
dd if=/mnt/zdisk/rand2.bin of=/mnt/zdisk/rand.bin conv=notrunc