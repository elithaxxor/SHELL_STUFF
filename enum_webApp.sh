#!/bin/sh

#  Script.sh
#  
# regex101.com
# https://github.com/aboul3la/Sublist3r
# http probe
# https://github.com/NicolasSiver/http-probe
#  Created by a-robot on 3/14/22.
# https://www.youtube.com/watch?v=Gaf1Z1bwbpY
# eyewitness
# https://github.com/FortyNorthSecurity/EyeWitness



website = "enter the site here"
express = "https://www.expressvpn.works/clients/linux/expressvpn_3.25.0.13-1_amd64.deb"
_devInfo01 = $(powermetrics)
_devInfo02 = $(Infix -Fxz) 

DIRS=$(ls *.txt)
_broadcast = $(ifconfig | grep broadcast)
_inet = $(ifconfig | grep inet)
_mac = $(ifconfig | grep mac)
_radio_name = $(iw dev | awk) '$1=="Interface"{print $2}'
_ip_addr = $(ip addr) 
_usb = $(lsusb) 
_mac = $(ifconfig | grep mac)

DIRS=$(ls *.txt)
broadcast = $(ifconfig | grep broadcast)





function show_host() {
	echo($_devInfo01) 
	echo($_devInfo02)
	echo($_mac) 
	echo($_inet)
	echo($_ip_addr)
	echo($_usb )
	echo($_mac)

}

function sys_update(){
	sudo apt-get update && sudo apt-get upgrade -y 
	sudo apt-get autoremove && sudo apt-get autoclean -y
	sudo apt install dnsutils -y
	sudo apt install eyewitness -y
	sudo apt install proxychains 
	
		    sudo apt install netcat  -y
	    sudo apt install netstat -
	    apt-get install network-manager -y
	        sudo apt install dnsutils
    sudo apt install nginx 

	echo "Update Log: " > apt_log.txt
	date >> apt_log.txt
}

function setExpress() {
	sudo mkdir /home/EXPRESS && cd /home/EXPRESS 
	curl($express)
		

}



function Get_Clone(){
    echo "Getting Dependencies"
    git clone 'https://github.com/aboul3la/Sublist3r'
    git clone 'https://github.com/NicolasSiver/http-probe'
    git clone 'https://github.com/FortyNorthSecurity/EyeWitness'
    git clone "https://github.com/darkoperator/dnsrecon" 
     
}


function Mkdirs(){
    if [! -d "third_levels"]; then
        mkdir third_levels
    fi
    
    if [! -d "scans"]; then
        mkdir scans
    fi
    
    if [! -d "eyewitness"]; then
        mkdir eyewitness
    fi
}


function getIPfromDNS() 
    $(netcat $website) 
    $(host $website) 
    $(dig $website) 
    $(dnsrecon $website) 
}

function curlSite() {
	mkdir /home/CURLED_WEBSITE && cd /home/CURLED_WEBSITE 
	curl -o $website
	mkdir /home/WGET_WEBSITE && cd /home/WGET_WEBSITE 
	wget $website 
	mkdir /home/HTTPRACK_WEBSITE && cd /home/HTTPRACK_WEBSITE 
	httrack -w $website
	}




# https://dnsdumpster.com/
echo ('enter pass:')
read pass
$(arp-scan -l | grep Raspberry | awk '{print $1}') root $pass


pwd = $(pwd)
echo "starting program"
echo "CWD: ${pwd}"


Get_Clone
Mkdirs


	function enumSubDomains() {
	git clone "https://github.com/FortyNorthSecurity/EyeWitness" 

	wget https://github.com/aboul3la/Sublist3r/archive/master.zip
	unzip master.zip
	./sublist3r.py -d $website
	./EyeWitness.py -f $website --web --proxy-ip 127.0.0.1 --proxy-port 8080 --proxy-type socks5 --timeout 120

	echo "starting sub-domin grab"
	sublist3r -d $1 -o final.txt
	./EyeWitness.py -f final.txt --web --proxy-ip 127.0.0.1 --proxy-port 8080 --proxy-type socks5 --timeout 120

	echo 'compiling 3rd level domain'
	cat domain_list.txt | grep -Po "(\w+\.\w+\.\w+)$" | sort -u >> third-level.txt
	./EyeWitness.py -f domain_list.txt --web --proxy-ip 127.0.0.1 --proxy-port 8080 --proxy-type socks5 --timeout 120
	./EyeWitness.py -f third-level.txt.txt --web --proxy-ip 127.0.0.1 --proxy-port 8080 --proxy-type socks5 --timeout 120


	echo 'Enumerating through domain for [FULL] Sublistings'
	for domain in $(cat third-level.txt);
	    do sublist3r -d $domain -o third_levels/$domain.txt;
		cat third_levels/$domain.txt;
		sort -u >> final.txt;
	 ./EyeWitness.py -f $domain.txt --web --proxy-ip 127.0.0.1 --proxy-port 8080 --proxy-type socks5 --timeout 120

	done

	if [ $# -eq 2 ]; ## to check the amount of paramantes [assed to sys] ## it is stored in $#

	then
	    echo "probing for [domains] 3rd level--[GREP]"
	    cat final.txt | sort -u | grep -v $2 | httprobe -s - p https:443 | sed 's/https\?:\/\///' | tr -d ":443" > probed.txt

	else
	    echo "probing for [domains] , [HTTP-PROBE]"
	    ./EyeWitness.py -f probed.txt --web --proxy-ip 127.0.0.1 --proxy-port 8080 --proxy-type socks5 --timeout 120
	    cat final.txt | sort -u | httprobe -s -p https:443 | sed 's/https\?:\/\///' | tr -d ":443" > probed.txt
	fi
	

}

function openPortScan {
	echo "scanning for open ports"
	nmap -iL probed.txt -T5 -oA scans/port_scan.txt -V

	echo "Eyewitness"
	eyewitness -f $pwd/probed.txt -d $1 --all-protocols
	mv /usr/share/eyewitness/$1 eyewitness/$1
	
	
}


function testSpecificPort {
	NC_PORT=80
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
	tracert localhost
}




