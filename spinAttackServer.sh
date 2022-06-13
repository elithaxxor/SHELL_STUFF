address = "root@45.33.39.233"
usr = "elithaxxor"
ipv6 = "2600:3c01::f03c:93ff:fefb:f0f5"
expoits = "https://github.com/elithaxxor/SHELL_STUFF"
hashing = "https://github.com/elithaxxor/shell_hashStuff"
express = "https://86qnr9fs.r.us-east-1.awstrack.me/L0/https:%2F%2Fwww.exp2links2.net%2Fwelcome%3Fsetup_page_token=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0..i7ol6nd7zNRgRZLC0xrpQQ.qohDKmMKM0l7UfeEsXmTUnKLu2wRsywWPyErRSs7egNyGi29EfaYbfTS1xiGFU4QMKhbb5mPosPcxjA0IbIUkI_gQh8kd06w7pfWPTM5km-gHQMn9Lv_UqGX5YNYC-5VIIZZ78v-8R2an8oEu6i1_Xhva2sEvBzC-OkBMeR3eL1aXz6bF_ibFrIaYg1CvtZV.xfnkhDaIcLWJOeBHvl73y-oNPPN_0EuoI8znd2CAnTo%26utm_campaign=your_setup_link%26utm_content=setup_app_button%26utm_medium=email%26utm_source=customer_email%23linux/1/02000000lkl64vp1-hnmgb318-rdsh-drij-dvlq-49q0ekoa9d80-000000/IvETPh3_jgW28TVoC7VGZCvKMXE=273"




function sys_update(){
	sudo apt-get update && sudo apt-get upgrade -y 
	## remove unused dependacncies 
	sudo apt-get autoremove && sudo apt-get autoclean
	## create log file 
	echo "Update Log: " > apt_log.txt
	date >> apt_log.txt
}



function spinAnAttackServer() {
mkdir ~/home/EXPLOITS/
	iptables -t mangle -I POSTROUTING 1 -j TTL --ttl-set 66
	  proxychains ssh -t elithaxxor@lish-fremont.linode.com ubuntu-us-west
	  Git clone https://github.com/elithaxxor/shell_hashStuff
	git clone https://github.com/elithaxxor/SHELL_STUFF/tree/main_pi
	git clone $exploits
	git clone $hashing 
	
  }
  
  function getSysInfo() {
	apt install infix 
	sudo apt-get install ufw
	sudo ufw status > LinsUfwStatus.txt
	sudo service ssh status
	infix -FXZ > LinsInfix 
}


function setupExpress {
sudo mkdir ~/home/EXPRESS/ && cd ~/home/EXPRESS/
curl $express && chmod +777 -R ./

 }
 

function hideMyTracks() {
proxychains firefox
proxychains tor 
proxychains curl ($express) 
iptables -t mangle -I POSTROUTING 1 -j TTL --ttl-set 66

}



function buildFakeAP () {


## make fake dns =
# https://cybergibbons.com/security-2/quick-and-easy-fake-wifi-access-point-in-kali/

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

function runFakeAPRouting () {
	sudo sysctl -w net.ipv4.ip_forward=1
	sudo iptables -P FORWARD ACCEPT
	sudo iptables --table nat -A POSTROUTING -o wlan0 -j MASQUERADE
}


# https://fedingo.com/how-to-install-openssl-in-ubuntu/
function buildOpenSSL() {

	sudo apt install build-essential checkinstall zlib1g-dev -y
	cd /usr/local/src/
	sudo wget https://www.openssl.org/source/openssl-1.1.1c.tar.gz

	sudo tar -xf openssl-1.1.1c.tar.gz
	cd openssl-1.1.1c

	 sudo ./config --prefix=/usr/local/ssl --openssldir=/usr/local/ssl shared zlib
	sudo make
	sudo make test
	sudo make install


	# 6. Configure OpenSSL Shared Libraries
	sudo vi /etc/ld.so.conf.d/openssl-1.1.1c.conf
	## add this line to the config file-->  /usr/local/ssl/lib
	sudo ldconfig -v

# ADD THIS LINE /usr/local/ssl/lib
 
 
	#7. Configure OpenSSL Binary
	sudo mv /usr/bin/c_rehash /usr/bin/c_rehash.backup
	sudo mv /usr/bin/openssl /usr/bin/openssl.backup

	Open environment PATH variable.

	sudo vi /etc/environment
	PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/usr/local/ssl/bin"
	# save and crteate path 
	source /etc/environment
	openssl version -a >> openSSLversion.txt 
}


# https://fedingo.com/how-to-install-openssl-in-ubuntu/
function makesslKeys() {
	### OPEN SSL ENCRYPTION ###
	Private key 
	openssl genrsa -aes-256-cbc -out macair.key 4096
	# Public key 
	openssl rsa -in frank.key -pubout > frankpublic.key 
	# verification file 

	### making signed encryption 
	openssl dgst -sha256 -sign macair.key -out signer verifcation.enc
	# to sign 
	openssl base64 -in signer -out verifcation.enc 
}




  
  

