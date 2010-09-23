#!/bin/bash

# File name: authstart.sh
# Date:      2010-09-10 11:29
# Author:    

aPort=""
sPort=""

usage() {
	echo "Usage: authstart.sh -a <authport>" \
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
		h) usage;;
		?) usage;;
	esac
done

./tsauthd \
	--workdir /home/kr/tsense/server/OpenSslServer/ \
	--lockdir /home/kr/tsense/server/OpenSslServer/ \
	--addr auth.tsense.sudo.is \
	--port $aPort \
	--siaddr sink.tsense.sudo.is
