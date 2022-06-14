#!bin/bin
## This Is for my homeserver, auto installs programs commonly used.
##
#

HOST='192.168.50.1'
USER='frank'
PASS='!'
DIR='~/MOUNTED_EXPLOITS'
SAVE_DIR='/SAVED_FILES'
CWD=$(pwd)
SECONDS=0

set timeout=20


## sets up paramaters for call
    set ip [index $argv 0]
    set user [index $argv 1]
    set pass [index $argv 2]
    set cwd   [index $argv 5]
    set dir [index $argv 4]
    set save_dir [index $argv 5]
read -p "ip/hostname" ip 



function echoBasic() { echo "****************\n" $(which bash) $$ echo$(ip) $$ echo$(user) $$ echo$(pass) $$ echo$(cwd) $$ echo$(dir) "\n" }

function handleDate() {

echo "[!] Current Working On: \n" && echoBasic 
printf "[!]

    echo "[!] Handling Data [!]"
	    date +'FORMAT' ## Time in 12 hr format ###
	    date +'%m/%d/%Y'      ### mm/dd/yyyy ###
	    date +'%r'## Time in 12 hr format ###
	    backup_dir=$(date +'%m/%d/%Y')
	    echo "[${date}]\n Backup dir for today: /nas04/backups/${backup_dir}"
    checkLogging
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
    lsof -i @IP_ADDRESS && lsof -i @HOSTNAME 
	
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



function mountXploits() {
    function handleFiles() {
                 cd /etc/fstab/ &&  ls -al > cifsMountLogs.txt
                 cp cifsMountLogs.txt $SAVE_DIR
    }
        mount.cifs //192.168.50.77/b/ //MOUNTED_EXPLOITS -o user=‘adel a’
        mount -t cifs -o vers=1.0,username=t0b1,password=$pw //server.local/shared/ /media/shared
        handleFiles
}

function scanNetwork {
	netstat
	netstat -rn
	nc
	nmap
}


## add express vpn
function hideMyTracks() {
    proxychains firefox
    proxychains tor
}

function startSSH(){
    quote USER $USER # protecting a command-line parameter from the shell
    quote PASS $PASSWD
    cd $DIR || SERVER_CWD=$(pwd)
    echo $(CWD=$(pwd))
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

function firewallAllAccess() {
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
}

function firewallAllAccess() {
    sudo ufw default allow incoming
    sudo ufw default allow outgoing
}



function sys_update(){
	sudo apt-get update && sudo apt-get upgrade -y
	## remove unused dependacncies
	sudo apt-get autoremove && sudo apt-get autoclean
	## create log file
	echo "Update Log: " > apt_log.txt
	date >> apt_log.txt
}


function StartUp(){
    python -m pip install --upgrade pip
        sudo apt update -y
        sudo apt upgrade -y
        sudo apt dist-upgrade -y
        sudo apt-get install git -y
        sudo apt install proxychains -y

    sudo apt install chrontab -y
        sudo apt install expect -y
        sudo apt install curl -y
        sudo apt install wget -y
        sudo apt install tor -y

  sudo apt install inxi -y
    apt install ipcalc -y
    sudo apt install cifs-utils -y
    apt install mlocate  -y
    apt install locate  -y
    sudo updatedb -y
        sudo apt-get install -y squashfs-tool -y

    sudo apt install dnsutils
    sudo apt install nginx
    sudo apt install netcat  -y
    sudo apt install netstat -
    apt-get install network-manager -y
    systemctl start NetworkManager.service -y  ##starts NMCLI
    systemctl enable NetworkManager.service -y ## sets NMCLI start with system
    sudo updatedb -y
    sudo apt install htop -y ## --HTOP is history with a 'reverse' lookup function.. cmd+r
    sudo apt install dnsutils -y
    sudo apt install eyewitness -y
      apt-get install dnsmasq -y

}

function sysInfo() {

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
    echo $CWD > userInfo.txt
    echo $HOST > userInfo.txt
    echo $USER > userInfo.txt
    echo $DIR >  userInfo.txt

    echo $_broadcast > networkInfo.txt
    echo $_inet > networkInfo.txt
    echo $_mac > networkInfo.txt
    echo $_radio_name > networkInfo.txt
    echo $ip_addr > networkInfo.txt

    echo $_devInfo01 > devInfo.txt
    echo $_devInfo02 devInfo.txt
        handlesysInfo
}

function grabNetworkStats() {
    mkdir ./networkStats && cd ./networkStats
    sudo arp -a > arp-oneTime.txt
    sudo arp-scan -l > arp-scan.txt
    sudo netstat -rn  > netStat.txt
    sudo netstat networkStats.txt
    sudo nc > networkStats.txt

    sudo traceroute > traceResults.txt
        sendTextHome
}


function scanNetwork {
	nmap -
}

function findAllTxt() {
      DIRS=$(ls *.txt) > MasterTextList.txt

}

function sendTextHome() {
    echo"[!] Sending These Guys back Home [!]"
    DIRS=$(ls *.txt) > MasterTextList.txt
        transfer
}


function transfer(){
  if [ $# -eq 0 ];
    then
     echo "No arguments specified.\nUsage:\n transfer <file|directory>\n ... |
     transfer <file_name>">&2;return 1;
  fi;
     if tty -s;
     then file="$1";file_name=$(basename "$file");
  if [ ! -e "$file" ];
       then echo "$file: No such file or directory">&2;
       return 1;
  fi;
       if [ -d "$file" ];then file_name="$file_name.zip";
       (cd "$file"&&zip -r -q - .) |curl --progress-bar --upload-file "-" "https://transfer.sh/$file_name"|tee /dev/null,;
        else cat "$file"|curl --progress-bar --upload-file "-" "https://transfer.sh/$file_name"|tee /dev/null;
  fi;
        else file_name=$1;curl --progress-bar --upload-file "-"
     "https://transfer.sh/$file_name"|tee /dev/null;
  fi;
 }


function sshFileTransfer() {
    scp
      <file to upload> <username>@<hostname>:<destination path>
    scp -r
      <directory to upload> <username>@<hostname>:<destination path> # dir scp
    echo "put files*.xml" | sftp -p -i ~/.ssh/key_name username@hostname.example #u using relative loc
    sftp
      -b batchfile.txt ~/.ssh/key_name username@hostname.example # using batch in text
}


function makeVNC() {
        echo
    "## add the commented below to ~/.vnc/xstartup
    ##!/bin/bash
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

function _broadcastInfo() {
  _broadcast = $(ifconfig | grep broadcast) > date + broadcast.txt && echo _broadcast
  _inet = $(ifconfig | grep inet)
  _mac = $(ifconfig | grep mac)
  _radio_name = $(iw dev | awk) '$1=="Interface"{print $2}'
  _ip_addr = $(ip addr)
  _usb = $(lsusb)
  _mac = $(ifconfig | grep mac)
  _DIRS=$(ls *.txt)
  _devInfo01 = $(powermetrics)
  _devInfo02 = $(Infix -Fxz)

  ## spawn process
  spawn ssh "$user\@ip" "reboot"
  read
  send "$_password\r";


  #interact
}
EOF
