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




## sets up paramaters for call 
set ip [index $argv 0]
set user [index $argv 1]
set password [index $argv 2]


function hideMyTracks() {

proxychains firefox
}

function startSSH(){
    quote USER $USER # protecting a command-line parameter from the shell
    quote PASS $PASSWD
    cd $DIR || SERVER_CWD=$(pwd)
    echo(CWD=$(pwd))
}

function StartUp(){
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
    apt-get install network-manager -y
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




DIRS=$(ls *.txt)
_broadcast = $(ifconfig | grep broadcast)
_inet = $(ifconfig | grep inet)
_mac = $(ifconfig | grep mac)
_radio_name = $(iw dev | awk) '$1=="Interface"{print $2}'
_ip_addr = $(ip addr) 
_usb = $(lsusb) 


_devInfo01 = $(powermetrics)
_devInfo02 = $(Infix -Fxz) 



# spawn process 
spawn ssh "$user\@ip" "reboot"
send "$password\r";
interact


