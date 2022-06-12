#!bin/bin
## This Is for my homeserver, auto installs programs commonly used.  
##
##
HOST='192.168.50.1'
USER='frank'
PASS='!'
DIR='./home/MOUNTED_EXPLOITS'
CWD=$(pwd)
set timeout=20



NC_PORT=80
if [[ $(nc -z localhost ${NC_PORT}) -eq 0 ]]; then
	echo "Tomcat is up"
    echo $(NC_PORT) 
else
	echo "Tomcat is shutdown"
    echo $(NC_PORT) 
fi



function scanNetwork {
netstat 
nc 


## sets up paramaters for call 
set ip [index $argv 0]
set user [index $argv 1]
set password [index $argv 2]


## add express vpn 
function hideMyTracks() {
proxychains firefox
}

function startSSH(){
    quote USER $USER # protecting a command-line parameter from the shell
    quote PASS $PASSWD
    cd $DIR || SERVER_CWD=$(pwd)
    echo(CWD=$(pwd))
    
}

function firewallUp() {
echo
sudo ufw logging on
sudo ufw enable
Sudo ufw allow ssh
sudo ufw status
sudo ufw allow http #80
 sudo ufw allow https ##443
 sudo ufw allow 1920:1935/tcp
  sudo ufw allow 1920:1935/udp

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

sys_update 

function StartUp(){
python -m pip install --upgrade pip
sudo apt install chrontab -y
sudo apt install expect -y


    sudo apt update -y
    sudo apt upgrade -y
    sudo apt dist-upgrade -y
    sudo apt-get install git -y
    sudo apt install inxi -y
   sudo apt install proxychains -y
    apt install ipcalc -y
    sudo apt install cifs-utils -y
    apt install mlocate  -y
    apt install locate  -y
    sudo updatedb -y
    
    sudo apt install nginx 
    sudo apt install netcat  -y
    sudo apt install netstat -
    apt-get install network-manager -y
    systemctl start NetworkManager.service  ##starts NMCLI 
    systemctl enable NetworkManager.service ## sets NMCLI start with system 
    sudo updatedb -y
    sudo apt install htop -y ## --HTOP is history with a 'reverse' lookup function.. cmd+r

    sudo apt-get install -y squashfs-tool -y
    Infix -Fxz

}

function sysInfo() {
echo($CWD)
echo($HOST)
echo($USER)
echo($DIR) 
echo($_broadcast)
echo($_inet)
echo($_mac )
echo($_radio_name)
echo($ip_addr)
echo(_devInfo01)
echo($_devInfo02) 
}

function sshFileTransfer() {

    scp <file to upload> <username>@<hostname>:<destination path>
    scp -r <directory to upload> <username>@<hostname>:<destination path> # dir scp
    echo "put files*.xml" | sftp -p -i ~/.ssh/key_name username@hostname.example #u using relative loc
    sftp -b batchfile.txt ~/.ssh/key_name username@hostname.example # using batch in text
}

function grabNetworkStats() {
sudo arp -a
sudo netstat 
sudo nc 
}

function setupRemoteLogin() {

echo
"## add the commented below to ~/.vnc/xstartup
##!/bin/bash
#xrdb $HOME/.Xresources
#startxfce4 &"

mkdir /home/PARSEC/
sudo wget "https://builds.parsecgaming.com/package/parsec-linux.deb"
vncserver -kill :1
mv ~/.vnc/xstartup ~/.vnc/xstartup.bak
nano ~/.vnc/xstartup

}





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



_devInfo01 = $(powermetrics)
_devInfo02 = $(Infix -Fxz) 



# spawn process 
spawn ssh "$user\@ip" "reboot"
send "$password\r";
interact


