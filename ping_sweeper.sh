#!/bin/bash 

## simple ping sweep, the & at the end allows multi-threading. 
echo 'Enter The Subnet'
read SUBNET 

echo 'Enter Netcat Port' 
read NC_PORT 
# NC_PORT=80



function getInfo() {
	
}

function pingSweep(){
	for ip in {1..254}
		do ping -c 3 192.168.50.$ip | grep "64 bytes" | cut -d " " -f 4 | tr -d ":" &
			echo "Update Log: " > sweep_log.txt
			date >> sweep_log.txt
	done 
}

function simpleNetworkScan {
	netstat
	ns 
}


function isServerUp {
if [[ $(nc -z localhost ${NC_PORT}) -eq 0 ]]; then
	echo "Tomcat is up"
    echo $(NC_PORT) 
else
	echo "Tomcat is shutdown"
    echo $(NC_PORT) 
fi
}


simpleNetworkScan
pingSweep 
isServerUp


