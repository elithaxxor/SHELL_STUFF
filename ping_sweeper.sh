#!/bin/bash 

## simple ping sweep, the & at the end allows multi-threading. 
echo 'Enter The Subnet'
read SUBNET 

echo 'Enter Netcat Port' 
read NC_PORT 
# NC_PORT=80



function sys_update(){
	sudo apt-get update && sudo apt-get upgrade -y 
	## remove unused dependacncies 
	sudo apt-get autoremove && sudo apt-get autoclean
	apt-get install dnsmasq ## to create multiple small DNSs (or APs) 
	## create log file 
	echo "Update Log: " > apt_log.txt
	date >> apt_log.txt
}



function getInfo() {
	
}

function pingSweep(){
	for ip in {1..254}
		do ping -c 3 192.168.50.$ip | grep "64 bytes" | cut -d " " -f 4 | tr -d ":" &
			echo "Update Log: " > sweep_log.txt
			date >> sweep_log.txt
	done 
}

function simpleNetworkScan() {
	netstat
	netstat -rn
	ns 
}


function isServerUp() {
if [[ $(nc -z localhost ${NC_PORT}) -eq 0 ]]; then
	echo "Tomcat is up"
    echo $(NC_PORT) 
else
	echo "Tomcat is shutdown"
    echo $(NC_PORT) 
fi
}

function timePacketTrip() {
	ping localhost 
	traceroute localhost
}

function createFakeAPs() {
	ifconfig newAP 192.168.50.1/24 up
	cd /etc/hostapd
	nano hostapd.conf
	./hostapd.conf
	
}



simpleNetworkScan
pingSweep 
isServerUp




