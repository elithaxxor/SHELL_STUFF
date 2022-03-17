#!/bin/sh

#  commands.sh
#  
#
#  Created by a-robot on 3/14/22.
#  
#https://api.wigle.net/


## To add new user 
useradd -r user2 

## basics
iwevent -- to get wireless events
iwgetid - reports curretn essid / ap

### PROXYCHAINS (COVERRING TRACKS) ###
# EDIT CONFIG /ETC/PROXYCHAINS.CONF
sudo apt-get install -y proxychains
proxychains nmap ip/24 
proxychains tor 



### MANGLE TTL 
# WINDOWS 
netsh int ipv4 set glob defaultcurhoplimit=65
netsh int ipv6 set glob defaultcurhoplimit=65
netsh int ipv6 set glob defaultcurhoplimit=128 # <-- RESET BACK TO DEFUALT 

### LINUX (default ttl=64)
iptables -t mangle -I POSTROUTING 1 -j TTL --ttl-set 66



OPEN SSL ENCRYPTION
Private key
openssl genrsa -aes-256-cbc -out macair.key 4096
openssl genrsa -aes-256-cbc -out macair.key 4096
# Public key
openssl rsa -in frank.key -pubout > frankpublic.key
# verification file
### making signed encryption
openssl dgst -sha256 -sign macair.key -out signer verifcation.enc
# to sign
openssl base64 -in signer -out verifcation.enc


##### INTRUSION DETECTION #### 
# Sparrow Wifi # --> 
https://github.com/ghostop14/sparrow-wifi
gpsd -D 2 -N /dev/ttyUSB0 # WARDRIVING --> graphs 
sudo ./sparrow-wifi.py 


### KISMET - FIND ALL THE NETWORK HOST, AND DEVICE MANU

#### TO MIRROR WEBPAGE DATA (EXACT COPY)
sudo apt install httrack webhttrack
httprack -w domain.com



## throw-away email ## 
tempmailer.de 




## lookoups####                                            2 ⚙
proxychains firefox
ike-scan
dnstracer dedicatedglass.com
Nslookup dedicatedglass.com
(to get dns)
Ping -a dedicatedglass.com
tlssled 192.168.50.1                                                    2 ⚙
sslscan -h dedicatedglass.com
Recon-ng                                      2 ⚙
To grab SSL certificates
sslyze --regular website or ip
nslookup IP >> nslookup.txt
http://geoiplookup.net/

#### JOHN THE RIPPER ### 
rar2john $HASHED_FILE
rar2john $HASHED_FILE > hash.txt 
john --format=zip hash.txt 


#### WIRESHARK #### 


#### MANGLED TTYL (FREE WIFI AP ACCESS) ######



#################### AIRMON-NG // SUITE #######################
###############################################################
radio_name = $(iw dev | awk) '$1=="Interface"{print $2}'
sudo airodump-ng wlx0013eff5483f  ## fo rmonitoring 
airodump-ng wlx0013eff5483f --encrypt wep
airodump-ng wlx0013eff5483f -c 11 ## TO BROADCAST ESSID 
airodump-ng wlx0013eff5483f -c 11 & wireshark ## TO BROADCAST ESSID and use wireshark for packet injection 


airodump-ng wlx0013eff5483f --encrypt wep
airodump-ng wlx0013eff5483f -c 11
netdiscover -r 192.168.50.1/24
airodump-ng wlx0013eff5483f --encrypt wep
sudo iwlist wlx0013eff5483f scanning | egrep 'Cell |Encryption|Quality|Last beacon|ESSID'

#### TO GET DEVICES AND DISTANCE
sudo iw dev wlx0013eff5483f scan | egrep "signal:|SSID:" | sed -e "s/\tsignal: //" -e "s/\tSSID: //" | awk '{ORS = (NR % 2 == 0)? "\n" : " "; print}' | sort
##### TO FIND WEP PROTECTION ####
airodump-ng wlx0013eff5483f --encrypt wep
aireplay-ng -0 0 mac -c mac_of_radio radio_name 
airemon-ng start external_radio 6 # the number is the channel  (TO START MONITOR MODE) 
kismet -c radio_name  ## GETS THE MAC ADDRESS 


## send deauth
#1 find mac for router (-a) and client (-c)
netdiscover -r 192.168.50.1/24
aireplay-ng --deauth 90000000 -a F0:2F:74:2C:7E:88 -c 9a:26:55:ed:ef:84 wlo1

###########################
### IFRENAME ### 
ifrename # to rename wireless 
iwevent # display wireless events 
iwgetid # reports current essid 
iwlist # scan savailable aps or essid 
iwspy # monitors iw nodes and records strenght and quality of signal 


##### NMCLI #####
nmcli general status 
nmcli general hostname # get and change sys hostname 
nmcli general permissions # show the permssions available to caller 
nmcli connection show --active 
nmcli modify 

nmcli networking on off # disable network control management 
nmcli networking connectivity 

nmcli radio all   ## show status for all devices 
nmcli radio wwan  ## for tethered devices 
nmcli radio wifi  ## show status for wifi devices 

nmcli device status
nmcli device showstatus
nmcli device showstatus wlan0 
nmcli device wifi connect # connect to near hotspot
nmcli device wifi hotspot # create a wifi hotspot 

wifi-show-password

######### TO DISPLAY AND SHOW USB DEVICES #### 
lspci 
lscpu
lsusb
lsblk
lslo 
lsslcb
lshw 



## to get available ESSID 
sudo iwlist [nic name] scan | grep ESSID 
nmcli dev wifi 



#### TO CREATE CUSTOM AP ### 
wpa_supplicant/hostap 
hostapd # to create AP for wifi sharing 
wpa_supplicant # allows scanning and connection to AP 

#### IP2ROUTER --> File sharing / hosting 
i2prouter start 

### INSTALL ALL KALI DEPENDENCIES 
apt install kali-linux-everything 




############ NMAP #############
#### KEYS ### 
# -A -> OS INFO 
# -sV -> list running svc on port 
# -Pn -> ignore if up / down 
## -Sv  nmap to return open ports and services (specific device)
## -v adds verbosity 
# cd /usr/share/nmap/scripts ## to find nmap vuln scripts 
## nmap -v == add verbosity 
# nmap --reason --> why port is in its state 
# nmap --packet-trace --> shows all send/recv packets 
# nmap --opem xxx.xxx 

#############################
nmap -sV -pN xx # basic nmap scan 
nmap 192.xxx -oX /dir/file.xml ## to output nmap to .xml 
nmap -A -Pn xxx/0/24 # os scan 
nmap -sA xxxx # tcp-ack scan --> unfilterd and filtered ports
nmap -sI zombiehost.com domain.com 
nmap -sW xxx # window scan 

nmap -sV host,com -scrip dns-brute ## chain script 


sudo nmap -sV -Pn -v ns8231.hostgator.com (#port knocking)
Sudo nmap -A -Pn  -v 76.172.85.231
nmap -sI -v google.com 192.168.50.1                                        2 ⚙
nmap -sW -v 192.168.50.1
nmap -sn -v - A--version-intenstity=9 192.168.0.0/24 ## nmap to find who's on Lan (subnet) #####

cd /usr/share/nmap/scripts
nmap --script nmap-vulners/ -sV -sS -Pn -A -v 192.168.50.1/24 --version-intensity=9
nmap -sV --script=vulscan/vulscan.nse 192.168.50.111
nmap --script nmap-vulners/ -sV www.securitytrails.com
nmap --script nmap-vulners/ -sV 11.22.33.44
nmap --script nmap-vulners/,vulscan/ -sV yourwebsite.com
nmap -Pn --script vuln 192.168.1.105
echo "scanning for open ports"
nmap -iL probed.txt -T5 -oA scans/port_scan.txt -V

echo "scanning for open ports"
nmap -iL probed.txt -T5 -oA scans/port_scan.txt -V

nmap -Sn xxx.xxx # ping scan 
nmap -sL # list scan, returns device name 
nmap -Pn # returns oepn ports . devname and mac address
nmap -Sn --traceroute xxx.xx/24 
nmap -Sn # ping scan 
nmap -sL # list scan returns device and if its up or down 
nmap -Pn # returns oepn port, best used with direct IP 
nmap -Sn --traceroute ip/24 
nmap ip.25 -p1-6000 # specify port 
nmap -sV # find the service version 
nmap -sV xxx.xxx --version-intensity=9
nmap -o xxx --oscan-guess 
nmap -A xx.xx version-intensity=9 
nmap -sV -A --script=vulners ip --version intesnsity=9 
nmap -sV -A xxx.xxx --version-intesity=9 

## php vulnerability
nmap -sV --script=http-php-version testphp.vulnweb.com
nmap 192.168.50.1 -oX /home/frank/nmapout.xml
nmap cpanel.dedicatedglass.com/24 -oX /home/frank/nmap.xml
sudo nmap -sP -n 192.168.0.0/24 ## nmap to return mac address
sudo nmap -sV --scripts=vulscan xxxx 



#############################





#### BRUTE FORCE #### PASSWORDS 
## BRUTESPRAY --> requries nmap fiel
apt install brutespray 
brutespray --file nmapout.xml --threads 5
brutespray -file nmapout.xml -t 5 -s ftp
brutespray --file nmapfuad.xml -U names.txt -P milw0rm-dictionary.txt --threads 5
brutespray --file nmapfuad.xml -U /home/frank/names.txt -P /home/frank/milw0rm-dictionary.txt --threads 5

sudo apt install ncrack
ncrack -u users.tx -p passwords.txt 

sudo apt-get install hydra-gtk
sudo apt-get purge hydra-gtk && sudo apt-get autoremove && sudo apt-get autoclean
hydra -L users.txt -P passwords.txt location_pass.txt 
pantor ftp_login host=ip , user=users.txt password- pass.txt 0=users.txt 1=passwords.txt 



## USE CUPS AND THE MENTALIST TOGETHER TO GENERATE CUSTOM PASSWORD LISTS. 
#### USE CUPS TO CREATE PASSWORD LIST WITH GIVEN USER INPUT (NAME, COMPANY BDATE ETC... ) 
git clone https://github.com/Mebus/cupp.git
nano cupp.config
python cupp.py -i
### USE THE MENTALIST (GUI) TO CREATE CUSTOM #'S AND SPECIAL CHARICTERS TO PASSWORD LIST GENERATED FROM CUPP
sudo apt install git python3-setuptools python3-tk
git clone https://github.com/sc0tfree/mentalist
cd mentalist/
sudo python3 setup.py install




###### DEEP OSNIT ### THE HARVESTER #######
## PUBLIC INFO ON BUSINESS NETWORKS 
wigle.net
cd /home/frank/the_harvester
python3 theHarvester.py -d dedicatedglass.com -l 500 -b all


#########  metasploit # ###########
Msfconsole
Search samba_symlink_traversal
Use / dir to exploit
Show options
Set option IP (look for required)
Exploit (to run export)




######## LOCALIZED INFO ######
ALL HARDWARE INFO
Apt install infix
Infix -Fxz

DIRS=$(ls *.txt)
broadcast = $(ifconfig | grep broadcast)
mac = $(ifconfig | grep mac)

######

##### OSNIT #####
Phonenumbers scanner
phoneinfoga scan -n <number>
phoneinfoga scan -n "+1 (555) 444-1212"

# SKIP TRACER (REVERSE-LICENSE LOOKPI)
git clone https://github.com/xillwillx/skiptracer.git skiptracer
cd skiptracer 
pip install -r requirements.txt
python skiptracer.py -l (phone|email|sn|name|plate)
 

######## OSNIT ###########
### Social media accounts#####
Pyhton3 sherlock.py username

online OSNIT
https://api.wigle.net/
https://www.nirsoft.net/ (look thins up, powerful tool)
http://geoiplookup.net/ ### GEO IP LCOATIONS
tracemyip.org
inteltechniques.com 

### to create fake AP ###
https://cybergibbons.com/security-2/quick-and-easy-fake-wifi-access-point-in-kali/
cd
/etc/hostapd
nano hostapd.conf
./hostapd.conf
iwevent

## WIRESHARK CLI ###
tshark -D
tshark -i 2 -i 5 -i 6
tshark -i 2 -i 5 -i 6 > firstWIRE.csv
tshark -i wlx0013eff5483f
tshark -i wlx0013eff5483f -i any (## all interfaces)



### CRACKING WEP / WPA ####
besside-ng en0 -c 6 -b
airodump-ng wlx0013eff5483f --encrypt wep


#### GOOGLE DORKS ###
# TO FIND NONSECURE LINKS ON WEBSERVER
site:dedicatedglass.com inurl:http
# TO DORK FOR LOGFILES
Allintext:password textfile:log after:2018



### WEBSERVER ENUMERATION ###
apt install whatweb ip 
whatweb -4 domain.com 

## to get dns info 
dnsrecon -d domain.com
whatweb domain.com 

python rsf.py 

### TO ENUMERATE SUBDOMAINS sublist3r
wget https://github.com/aboul3la/Sublist3r/archive/master.zip
unzip master.zip
./sublist3r.py -d yourdomain.com
## look thru namesystem for hidden 
sudo apt install dirbuster
	
### WEB BASED VULNS ###
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

python skiptracer.py -l (phone|email|sn|name|plate)
 

## Nikto for webserver vuln scans
git clone https://github.com/sullo/nikto
# Main script is in program/
cd nikto/program
# Run using the shebang interpreter
./nikto.pl -h http://www.example.com
# Run using perl (if you forget to chmod)
#### ONENVAS (NESSUS CLONE) VULN SCAN ### 
apt install openvas 

## ARP SCAN 
echo ('enter pass:')
read pass
$(arp-scan -l | grep Raspberry | awk '{print $1}') root $pass
apt-get update && apt-get install sparta python-requests


## password crackers 
hashcat 
scp <file to upload> <username>@<hostname>:<destination path>
scp -r <directory to upload> <username>@<hostname>:<destination path> # dir scp
echo "put files*.xml" | sftp -p -i ~/.ssh/key_name username@hostname.example #u using relative loc
sftp -b batchfile.txt ~/.ssh/key_name username@hostname.example # using batch in text


### MAC ADDRESS RANDOMIZATION ( CELL PHONES )


######## OPEN SSL #######
# use private key to sign secret.enc. 
openssl genrsa -aes-256-cbc -out newkey.key 4096 # generate pvt key 
openssl rsa -in newkey.key -pubout > public.key # to generate public key 
openssl rsatl --encrypt -inkey private.key -pubout > public.key -pubin -in messsage.txt -out message.enc ## encrypt a file 
openssl rsatl --decrypt -inkey myprivate.key -in message.enc > clear_view.txt 
openssl genrsa -des3 -out another_pvt_key.key 4096 ## to derive anothers public key 

openssl rsautl --decruypt -inkey bob-put.key -in secret.enc > message.txt  # to decrypt mesg
openssl dgst -sha256 -sign private.key -out signer secret.enc
openssl base64 -in signer -out my_signature # to sign ssl 
openssl dgst -sha256 -verify anothers_pub_key.key -signature signer secret.enc 






