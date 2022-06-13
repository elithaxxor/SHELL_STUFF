#!/bin/bash 

## simple ping sweep, the & at the end allows multi-threading. 
echo 'Enter The Subnet'
read SUBNET 


function sys_update(){
	sudo apt-get update && sudo apt-get upgrade -y 
	## remove unused dependacncies 
	sudo apt-get autoremove && sudo apt-get autoclean
	apt-get install dnsmasq ## to create multiple small DNSs (or APs) 
	https://github.com/ChrisMcMStone/wifi-learner

	## create log file 
	apt install infix 

	echo "Update Log: " > apt_log.txt
	date >> apt_log.txt
}



function getInfo() {

	infix -FXZ
	iptables -t mangle -I POSTROUTING 1 -j TTL --ttl-set 66
	tracert localhost 
	

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
	ping localhost -a 
	traceroute localhost
}




#https://cybergibbons.com/security-2/quick-and-easy-fake-wifi-access-point-in-kali/
function createFakeAPs() {
	echo(ipaddr) 
	
	touch hostapd.conf >> 
	 interface=wlan3
	driver=nl80211
	ssid=Kali-MITM
	channel=1
	
	ifconfig newAPdev 192.168.50.1/24 up
	cd /etc/hostapd
	nano hostapd.conf
	./hostapd.conf
	
}



## make fake dns 

# https://cybergibbons.com/security-2/quick-and-easy-fake-wifi-access-point-in-kali/

function makeFakeAPConfigs() {

	sudo apt-get install dnsmasq ## to create multiple dns points
	apt-get install hostapd  ## to get adapter to work as AP 
	mkdir fakeAPConfigs () {
	touch hostapd.conf cat >> 
	 interface=wlan3
	driver=nl80211
	ssid=Kali-MITM
	channel=1


	touch “dnsmasq.conf”
	Echo” ADD THIS TO CONFIG FILE
	interface=wlan3
	dhcp-range=10.0.0.10,10.0.0.250,12h
	dhcp-option=3,10.0.0.1
	dhcp-option=6,10.0.0.1
	server=8.8.8.8
	log-queries
	log-dhcp
	“
	hostapd ./hostapd.conf 

}

function setFakeAProuting () {
	sudo sysctl -w net.ipv4.ip_forward=1
	sudo iptables -P FORWARD ACCEPT
	sudo iptables --table nat -A POSTROUTING -o wlan0 -j MASQUERADE
}




simpleNetworkScan
pingSweep 
isServerUp




