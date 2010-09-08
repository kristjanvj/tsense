#!/bin/sh

# File name: sinkstart.sh
# Date:      2010-09-08 14:04
# Author:    

./tssinkd \
	--workdir /home/kr/tsense/server/OpenSslServer/ \
	--lockdir /home/kr/tsense/server/OpenSslServer/ \
	--auaddr auth.tsense.sudo.is \
	--auport 6001 \
	--addr sink.tsense.sudo.is \
	--port 6002
