#!/bin/bash

# File name: sinkstart.sh
# Date:      2010-09-08 14:04
# Author:    

aPort=""
sPort=""

usage() {
	echo "Usage: sinkstart.sh -a <authport> -s <sinkport>" \
	1>&2; exit 1;
}

if [ "$#" -le 0 ]
then   # Script needs at least one command-line argument.
	usage
fi  

while getopts "a:s:h" flag
	do
    	case $flag in
		a) aPort=$OPTARG;;
		s) sPort=$OPTARG;;
		h) usage;;
		?) usage;;
	esac
done

./tssinkd \
	--workdir /home/kr/tsense/server/OpenSslServer/ \
	--lockdir /home/kr/tsense/server/OpenSslServer/ \
	--auaddr auth.tsense.sudo.is \
	--auport $aPort \
	--addr sink.tsense.sudo.is \
	--port $sPort 
