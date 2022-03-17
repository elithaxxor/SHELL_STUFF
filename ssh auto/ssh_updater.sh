#!bin/bin

HOST='192.168.50.1'
USER='frank'
PASS='Hello100!'
DIR='exploits'
CWD=$(pwd)
set timeout=20

echo($CWD)

## sets up paramaters for call 
set ip [index $argv 0]
set user [index $argv 1]
set password [index $argv 2]

function startSSH(){
    quote USER $USER # protecting a command-line parameter from the shell
    quote PASS $PASSWD
    cd $DIR || SERVER_CWD=$(pwd)
    echo(CWD=$(pwd))
}

function StartUp(){
    sudo apt update
    sudo apt upgrade 
    sudo apt dist-upgrade 
    sudo apt-get install git
    apt install infix
    apt install ipcalc
    Infix -Fxz

}


DIRS=$(ls *.txt)
_broadcast = $(ifconfig | grep broadcast)
_inet = $(ifconfig | grep inet)
_mac = $(ifconfig | grep mac)
_radio_name = $(iw dev | awk) '$1=="Interface"{print $2}'

# spawn process 
spawn ssh "$user\@ip" "reboot"
send "$password\r";
interact


scp <file to upload> <username>@<hostname>:<destination path>
scp -r <directory to upload> <username>@<hostname>:<destination path> # dir scp
echo "put files*.xml" | sftp -p -i ~/.ssh/key_name username@hostname.example #u using relative loc
sftp -b batchfile.txt ~/.ssh/key_name username@hostname.example # using batch in text
