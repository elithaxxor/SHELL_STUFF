TO REMOVE ALL SSH 
rm -rf ~/.ssh/*
http://frank:8081/vnc.html?host=frank&port=8081
ssh -L 59000:localhost:5901 -C -N -l frank 192.168.50.18


pyenv install 3.8.9
pyenv shell 3.8.9


npx create-react-app counter  



https://docs.python-requests.org/en/latest/user/authentication/


https://darren.kitchen/


## TO FIND OUT WEBSITE SECIRUITY 


Details
1. Open the web application you would like to check.
2. Open the developer tools. Press F12 if you are on Chrome.
3. Open the "Network" Tab.
4. Open an event.
5. Check the "WWW-Authenticate" under the "Response Header" drop down. Basic:
Oct 14, 2019



To view all devices and drivers: 
inxi -Fxz

sql ibm_db_sa://admin:Hello100!\@localhost:25000/capstone?security=SSL**



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



UBUNTU - NGINX - FIREWALL
sudo ufw status
 sudo ufw allow 80/udp
 sudo ufw allow 80/tcp
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT


 sudo ufw allow 9999/udp
 sudo ufw allow 9999/tcp
sudo iptables -A INPUT -p tcp --dport 9999 -j ACCEPT
sudo iptables -A INPUT -p udp --dport 9999 -j ACCEPT


VNC STUFF
ps -ef | grep vnc
kill -9 <PID of Xvnc Process(es)>
### START VNC 
vncserver -localhost
sudo systemctl start vncserver@1
sudo systemctl status vncserver@1

ssh -L 59000:localhost:5901 -C -N -l frank 192.168.50.18


Opren  port 8081
Plug in oculus 
Mount network drives
Send Alex login info 


VARIOUS SERVER LOGIN: VNC = REMOTE VIEW; FTP = DROPBOX CLIENT, AND WEBSITE = HACKBOX (build not posted) 

\the FT[ server works likeLIKE DROPBOX)put the address in the webbrws and you can post/get files.
Login- frank
pass= hello100


If needed, manually reconnect to the data service in msfconsole using the command:
db_connect --name local-https-data-service --token bb0d96d39dad9e0c081c3b8613035deb1710ebe5cc41d7ce9bd52701b7c2d18ef954dcc20c561b14 --cert /home/frank/.msf4/msf-ws-cert.pem --skip-verify https://localhost:5443

The username and password are credentials for the API account:
https://localhost:5443/api/v1/auth/account

IMPORTANT FIREWALL RULES 	•	sudo apt-get install ufw
sudo ufw allow 20/tcp
sudo ufw allow 21/tcp
sudo ufw allow 990/tcp
sudo ufw allow 40000:50000/tcp
sudo ufw status


MANGLE TTL 
iptables -t mangle -I POSTROUTING 1 -j TTL --ttl-set 66



* sudo apt-get install ufw



To Edit Logging 
sudo nano /etc/rsyslog.conf



TO GET DIR TEXT COLOR BACL
export CLICOLOR=1


SAMA and SYS SYSTEM SERVIECS 
sudo service smbd restart
Update the firewall rules to allow Samba traffic:
sudo ufw allow samba


manage.py"

    * sudo usermod -d /var/www/ftp/myApplication ftpuser
    * 
1. 

    * sudo usermod -d /var/www/ftp/myApplication AWEX
    * 
1. 


$ sudo ln -sf /media/ACER/Users/Me/Folder /mnt/Folder



export PYTHONPATH=/Users/adelal-aali/Documents/CS/PROJECT/django_pythonScripts01/


CONDA VIRTUAL ENV
conda create -n easyocr python=3.8
conda activate easyocr


TO BUILD VENV 
$   cd $YOUR_PROJECT_DIRECTORY
$   virtualenv .venv


TO STAR VENV 
 source .venv/bin/activate



MANGLE TTL FOR UNLIMITED DATA 
iptables -t mangle -I POSTROUTING 1 -j TTL --ttl-set 66


####  TO REINSTALL WIFI ADAPTER ####
git clone "https://github.com/RinCat/RTL88x2BU-Linux-Driver.git" /usr/src/rtl88x2bu-git
sed -i 's/PACKAGE_VERSION="@PKGVER@"/PACKAGE_VERSION="git"/g' /usr/src/rtl88x2bu-git/dkms.conf
dkms add -m rtl88x2bu -v git
dkms autoinstall
modprobe 88x2bu rtw_switch_usb_mode=1 (FOR USB 3.0)

### TO REINSTALL WIFI ADAPTER ##
inxi -Fxz

1. Download https://github.com/cilynx/rtl88x2bu/archive/5.6.1_30362.20181109_COEX20180928-6a6a.zip
2. cd path/to/rtl88x2bu-5.6.1_30362.20181109_COEX20180928-6a6a
3. sudo chmod +x build.sh
4. bash build.sh


TO LIST ALL UBS DEVICE
Lsusb 
LSCPU

python -m pip install tensorflow

https://bazaar.abuse.ch


GitHub access token
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

AssMuncher90!



Go buster- to brute force sub dir and sub domain 
└─# git clone https://github.com/OJ/gobuster.git                            1 ⨯
└─# go get -u github.com/OJ/gobuster && go build                            1 ⨯
└─# ./gobuster -h                                                           1 ⨯

# SHODON API 
O49Ksy1HyForTiu99jJGRk7nJY2JSwvN


https://github.com/orgs/Exploit-install/repositories




https://www.pornhubpremium.com/view_video.php?viewkey=ph5f933c5170a73

To download website 

Kali vnc



################ BERRRY BOOT CONFIGUREATION ##############
sudo apt-get install squashfs-tools
sudo kpartx -av piwizard-pi4-v2.1.4.img      #convert image 

add map loop0p1 (252:5): 0 117187 linear /dev/loop0 1
add map loop0p2 (252:6): 0 3493888 linear /dev/loop0 118784

sudo mount /dev/mapper/loo2p0p2 /mnt
sudo sed -i ‘s/^\/dev\/mmcblk/#\0/g’ /mnt/etc/fstab’
sudo mksquashfs /mnt piwizard-pi4-v2.1.4.img -comp lzo -e lib/modules
sudo umount /mnt
sudo kpartx -d piwizard-pi4-v2.


TO VIEW ALL PCI 
Lspci

To see if software hardware blocking devices 
Rfkill list


Chase word
JewishHobbit100!



MOK MANAGMENT 
UBUNTU SECURE BOOT 
Mokutil —sb-state 

TO DISASBLE SECURE BOOT
Sudo mokutil —disable-validation 



1.4.img




sudo systemctl disable rsyslog.service



Raspberry Pi / PYTHON 

Ssh pi@76.172.85.231


sudo nano crontab -e



TO GET FILES FROM REPOSITORY:: 
git clone https://github.com/elithaxxor/pi_repo.git

To change shells - bash 
cat /etc/shells.
chsh -s /bin/bash


TO GET CURRENT WORKING DIRECTORY 
pwd -p 






TO CONNECT WIRELESS NETWORK TERMINAL 
iwconfig wlan0 essid name key password


# log out of vpn 
# test eterna website
# log bac into vpn
# work on iptabesl unix
# 



TO VIEW IMAGE IN TERMINAL 
apt install imagemagick 
display path/to/picture.png


To check status of app 
sudo service ssh status


SSH CONFIG FILE
 sudo nano /etc/ssh/ssh_config


TO FORCE PYTHON3 INTERPRITER 
nano ~/.bashrc
alias python='python3'




Tar To extract TAR .gz file
tar -zxvf file_name.tar.gz

To extract to specific directory: 
tar -C /myfolder -zxvf file_name.tar.gz 

To extract tar (no .gz)
tar -xvf file_name.tar
sudo apt-get install openjdk-8-jdk





APACHE WEBSITE: 
sudo mkdir /var/www/gci/
cd /etc/apache2/sites-available/
sudo cp 000-default.conf gci.conf (copy virtual host) 
udo nano gci.conf (to edit config file for website - gci) 


### Apache Config ## 
ServerAdmin webmaster@localhost
DocumentRoot /var/www/gci/
  ServerName gci.katz_killz.com

Apache Error Log: 
/var/log/apache2/error.log




TO ALLOW PORTS ON FIREWALL
sudo ufw allow 68:69/udp
sudo ufw allow 22221:22222/udp



TO DIABLE / ENABLE FIREWALL
sudo ufw disable
sudo ufw enable


 To get information on a program PID 
ps -p

TO SSH FILE FROM MAC TO PI 
scp /Users/macbook/Documents/CS/PROJECT/Chatroom/01_chatRoom_client_01.py pi@192.168.50.86:/home/pi/Python_Code

# /etc/default/tftpd-hpa

TFTP_USERNAME="pi"
TFTP_DIRECTORY="/home/pi/FTP_SHARED"
TFTP_ADDRESS="192.168.50.86:69"
TFTP_OPTIONS="--secure --create"

TO ADD NEW USER TO FTP 
echo "newftpuser" | sudo tee -a /etc/vsftpd.user_list



TO RENAME FILE 
mv 01largettest.xz 02largefile.xz

TO RENAME DIRECTORY FOLDER
mv -v directoryold directorynewname





IP TABLES CONFIG: (fire wall) 
/etc/sysconfig/iptables-config

To get network host name of self 
Hostname -f


FSTAB - MOUNT ISSUE 
UUID=FA3C-43D0  /home/frank/RetroPie      vfat    nofail,user,uid=frank,gid=frank 0       2
sudo mount /dev/sda1 /media/usb/

To RESTART PROGRAM APP : 	
sudo service smbd restart



TO ADD DIRECTORY TO SAMBA FILESHARE:: 
Sudo nano /etc/samba/smb.conf
Find [Homes] and add the following: 
[ourfiles]
   comment = Some useful files
   read only = no
   path = /path_to_our_files
   guest ok = no


TO ADD USERS TO SAMBA FILE SHARE;: 
smbpasswd -a frank
smbpasswd -a pi

TO VIEW EXISTING SAMBA USERS: 
pdbedit -w -L


TO ACCESS THE SMB SAMBA  AS SELF: 
smbclient -U pi //frank-berry/pi




FIREEWALL - SSH 
iptables -I INPUT -p tcp --dport 1022 -j ACCEPT
SSH PORT. - Port 1022

FIREWALL FOR APPLICATION 
 sudo ufw allow samba



TO GET SIZE OF CURRENT FOLDER 
du -sh
TO FIND FOLDERES 
sudo du -h --max-depth=1 /

TO FIND LARGERST FILES
du -a -h /home/ | sort -n -r | head -n 20

To find 50 largest fieles 
sudo du -ak | sort -nr | head -50
tree -dh —du -ak 

Build tree of subdirectory: 
sudo tree –f
sudo tree –p (displays permission s


ADD USER ADMIN:
adduser <username> --ingroup sudo

MODIFY USER TO ADMIN GROUP: 
adduser <username> --group admin (??? DOUBLECHECK) 



ANALYZE SUBFOLDERS
tree -dh --du


TO SORT FILES, TOP 50 
sudo du -h | sort -nr | head -50



TO DELETE SUBDIRECTORY ITEMS / PERSERVE FOLDERS. KILL FILE
find /var/myfolder -type f -delete


cdo-release-upgrade
do-release-upgrade


Remove directory, with eeverytihgn in it 
Rm -r



#       /etc/apache2/
#       |-- apache2.conf
#       |       `--  ports.conf
#       |-- mods-enabled
#       |       |-- *.load
#       |       `-- *.conf
#       |-- conf-enabled
#       |       `-- *.conf
#       `-- sites-enabled
#               `-- *.conf
#


Nginx
Vlc
Python3
RetroPie
Ssh
Locate 
Parsec
Steampunk
Vlc



cd /opt/retropie/lib
mv archivefuncs.sh temp
mv inifuncs.sh temp


a2jmidid
 calf-plugins
 qjackctl
 vlc-plugin-jack:arm64
 ladish
 jackd2
 vlc-plugin-jack-dbgsym:arm64
 dphys-swapfile
 puredata-core
 gem
 puredata-extra
 gem-plugin-gmerlin
 gem-plugin-lqt
 python-laditools
 puredata
 gladish
 gem-plugin-magick
 jackd
 gem-plugin-assimp
 laditools
 gem-extra
 gem-plugin-vlc




https://www.youtube.com/watch?v=livu_eAlUT0



TO FIND FAILED SYSTEMCTL 
sudo systemctl list-units | grep -i failed
systemctl list-unit-files --type service -all


TO LIST ALL SYSTEMCTL :
systemctl list-unit-files --type service -all



TO CHANGE SAMBA SETTINGS 
/var/lib/dhcp 




Setup nginx, DDclient, open 
sudo openvpn --config /etc/openvpn/ovpn.conf --daemon

NGINX 
        root /var/www/html;




To test:
Set device 
and set the DNS server to 1.1.1.1, 8.1.1.8.

TO TURN OFF OPENVPN START ON BOOT 
systemctl enable openvpn@example.service, w


hello200!


Finally, in order to route traffic via the Pi, you’ll need to go back to your game console, set-top box (or other device) and change the internet settings. Leave everything in its default setting apart from the Gateway and DNS servers.
Change Gateway to the IP address of your Pi, and set the DNS server to 1.1.1.1, 8.1.1.8.


sudo openvpn --config /etc/openvpn/US.conf


TO MOUNT NETWORK FOLDER 
sudo apt install cifs-utils
sudo mount.cifs //192.168.50.77/a //media/usb1 -o user='adel a2'

/dev/sda1 /media
dphys-swapfile swapon


sudo mount /dev/sda1 /media/usb1/ auto
mount.cifs //192.168.50.111/w/dreamcast /media/usb1/retropie-mount/roms/dreamcast -o user='adela3' 

mount.cifs //192.168.50.111/e/PS1/PS1 /media/usb1/retropie-mount/roms/psx -o user='adela3' 

mount.cifs //192.168.50.77/a/ROMS/psp /media/usb1/retropie-mount/roms/psp -o user='adel a2’ 

mount.cifs //192.168.50.77/a/ROMS/psp /media/usb1/retropie-mount/roms/psp -o user='adel a2’ 

mount.cifs //192.168.50.77/a/ROMS/collections/MAME/roms /media/usb1/retropie-mount/arcade/mame -o user='adel a2’ 

mount.cifs //Adel/a/ROMS/psp /media/usb1/retropie-mount/roms/psp -o user='adel a2’ 


mount.cifs //192.168.50.77/ a/ROMS/mame-libretro 

/a/ROMS/collections/MAME/roms -o user='adel a’ 



#elevator=deadline quiet bootmenutimeout=10 datadev=mmcblk0p2 




https://www.comparitech.com/blog/vpn-privacy/raspberry-pi-vpn/
FIREWALL / ROUTING 
TO CHANGE VPN SETTINGS FOR BOOT 
sudo nano /etc/rc.local



SHARED DRIVES 
Edit FSTAB for automating folder mounting 
sudo mount -a
sudo mount.cifs //192.168.50.77/a /media/shared -o user='adel a2'
sudo mount.cifs //192.168.50.111/w/dreamcast  /home/pi/RetroPie/roms/dreamcast -o user='adela3' password = 'Whatthefuck100!'

sudo mount /dev/sda1 /media


OPN VPN .CONF
Cd /etc/openvpn 
sudo nano US.conf 

Vpn - wiregaurd
Webserver - 

Router 


To bring down interface
ip link set dev <interface> up
ip link set dev <interface> down


Plex Server: 
https://app.plex.tv/desktop/#!/
Alex.a.pascal77@gmail.com
Fuad1968!



sudo ssh pi@76.172.85.231 
If prompted, port 22 

ftp://pi:raspberry@76.172.85.231
If prompted, log in as guest
Or as pi password: raspberry


MAY NEED TO CHANGE TO PIA 
sudo nano /etc/openvpn/login


https://76.172.85.231:8443


NOIP.COM
chicken00killer.ddns.net	76.172.85.231


SWAP 
/etc/dphys-swapfile

FSTAB 
/etc/fstab
dphys-swapfile setup|install|swapon|swapoff|uninstall



PACKAGE MANAGER 
gksudo synaptic

  piwizard-pi4-v2.1.4.img





sudo openvpn us_california.ovpn


VPN:
Wiregaurd:: (reverse vpn) 

OPEN DNS curl -L https://install.pivpn.io | bash


PIA  (ACTUAL VPN)
p2246844
Jk8fCPESHg

TO START NGIX 
Sudo /etc/init.d/nginx start


OPEN VPN
Chicken00killer.com (find URL)
PORT 1194


TO GET CURRENT CLOCK SPEED 
vcgencmd measure_clock arm
watch -n 1 vcgencmd measure_clock arm

INFORMATION ON CPU 
lscpu


To GET SYSTEM / CPU INFO (LOOK INTO PROC)
cat /proc/cpuinfo


To get external ip
dig @resolver4.opendns.com myip.opendns.com +short
To get DNS Server:
grep "nameserver" /etc/resolv.conf


sudo openvpn example.ovpn –daemon 

sudo openvpn us_california.ovpn

	
FTP
Sudo service vsftpd

WEBSERVER:
Ngnix

https://app.plex.tv/desktop/#!/

Pwd
Cd - 
scp (ssh file transfer) 
fdisk
Du -h
Df -h

TO COPY FILES:: 
pbcopy < ~/.ssh/git.pub

Sudo systemctl restart 
Sudo systemctl status 
Sudo systemctl enable (start program every start) 

lxpanelctl restart



Mv to rename file


ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH6uuUNyFVM8NORsXO16f5VcRJuriPryQ+IrSVUN4yyn adel.alaali@icloud.com