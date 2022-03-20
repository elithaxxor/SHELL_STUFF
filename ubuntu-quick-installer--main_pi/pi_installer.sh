#!/bin/bash

BLACK='\e[30m'
RED='\e[31m'
GREEN='\e[32m'
YELLOW='\e[33m'
BLUE='\e[34m'
PURPLE='\e[35m'
CYAN='\e[36m'
WHITE='\e[37m'
NC='\e[0m'

if [ `lsb_release -i | awk '{print $3}'` != Raspbian ]; then
	echo -e "\n${RED}[*] Your distro is not supported\n${NC}"
	exit 1
fi

echo -e "${CYAN}               _                 ___             _              "
echo "              | |__   __ ___  __/ _ \ _ __ _ __ (_)             "
echo "              | '_ \ / _' \ \/ / | | | '__| '_ \| |             "
echo "              | | | | (_| |>  <| |_| | |  | |_) | |             "
echo '              |_| |_|\__,_/_/\_\\___/|_|  | .__/|_|             '
echo "                                          |_|                   "
echo -e "${NC}"
echo -e "${RED}                  === hax0rpi Release 1.2 ===                   ${NC}"
echo -e "${RED}                   codename: Maromota Dorada                   ${NC}"
echo -e "${YELLOW}           A Raspberry Pi Hacker Tools suite by Vay3t           ${NC}"
echo ""
echo "----------------------------------------------------------------"
echo -e "${GREEN}    This installer will load a comprehensive of hacker tools    "
echo "      suite onto your Raspberry Pi. Note that the Raspbian      "
echo "     distribution must be installed onto the SD card before     "
echo -e "     proceeding. See README (if exist) for more information.    ${NC}"
echo ""
echo -e "${CYAN}[>] Press ENTER to continue, CTRL+C to abort.${NC}"
read INPUT
echo ""

# change password
#passwd pi

echo -e "${YELLOW}[!] enable ssh${NC}"
sudo systemctl enable ssh

# secret directory
secret=arsenal
cd
mkdir $secret && cd $secret
echo -e "\n${YELLOW}[+] folder 'secret' created${NC}"

# update system
echo -e "\n${YELLOW}[!] update and upgrade system${NC}"
sudo apt-get update
sudo apt-get dist-upgrade -y

# install from apt-get
echo -e "\n${YELLOW}\n[!] install tools with apt-get${NC}"
sudo apt-get install -y \
	apache2 \
	arp-scan \
	crunch \
	curl \
	dhex \
	dnsmasq \
	dsniff \
	ettercap-text-only \
	git \
	hexedit \
	hostapd \
	hydra \
	iw \
	kismet \
	libimage-exiftool-perl \
	locate \
	macchanger \
	mariadb-client \
	mariadb-server \
	mycli \
	nbtscan \
	netcat \
	netdiscover \
	nmap \
	openvpn \
	php \
	python3-dev \
	python3-pip \
	ruby-full \
	screen \
	smbclient \
	snapd \
	tcpdump \
	tmux \
	tor \
	torsocks \
	tree \
	vim \
	wipe \
	wireless-tools \
	whois;

# install from gems
echo -e "\n${YELLOW}[!] install from gems${NC}"
sudo gem install wpscan bundle evil-winrm

# install from pip
echo -e "\n${YELLOW}[!] install from pip${NC}"
sudo apt install -y libffi-dev
sudo pip3 install exrex sqlmap shodan wafw00f requests beautifulsoup4 scapy proxy.py

# clone repos
echo -e "\n${YELLOW}[!] clone repos${NC}"
git clone https://github.com/Mebus/cupp
git clone https://github.com/drwetter/testssl.sh
git clone https://github.com/m4ll0k/Atlas
git clone https://github.com/commixproject/commix
git clone https://github.com/maurosoria/dirsearch
git clone https://github.com/lgandx/Responder
git clone https://github.com/vulnersCom/nmap-vulners

sudo pip3 install git+https://github.com/byt3bl33d3r/python-Wappalyzer

# frp
wget https://github.com/fatedier/frp/releases/download/v0.33.0/frp_0.33.0_linux_arm.tar.gz
tar zxvf frp_0.33.0_linux_arm.tar.gz
rm frp_0.33.0_linux_arm.tar.gz

# portspoof
git clone https://github.com/drk1wi/portspoof
cd portspoof
./configure
make
sudo make install
cd && cd $secret

# git-dumper
git clone https://github.com/arthaud/git-dumper
cd git-dumper
sudo pip3 install -r requirements.txt
cd && cd $secret

# crackmapexec
git clone --recursive https://github.com/byt3bl33d3r/CrackMapExec
cd CrackMapExec
python3 setup.py install
cd && cd $secret

# photon
git clone https://github.com/s0md3v/Photon
cd Photon
sudo pip3 install -r requirements.txt
cd && cd $secret

# intruder payloads
git clone https://github.com/1N3/IntruderPayloads
cd IntruderPayloads
./install.sh
cd && cd $secret

# massscan
sudo apt-get install git gcc make libpcap-dev
git clone https://github.com/robertdavidgraham/masscan
cd masscan
make -j
sudo make install
cd && cd $secret

# proxychains
git clone https://github.com/rofl0r/proxychains-ng
cd proxychains-ng
./configure --prefix=/usr --sysconfdir=/etc
make -j
sudo make install
sudo make install-config
cd && cd $secret

# rexgen-john
echo -e "\n${YELLOW}[!] install rexgen-john${NC}"
sudo apt-get -y install cmake bison flex libicu-dev
mkdir ~/src
cd ~/src
git clone https://github.com/vay3t/rexgen-john rexgen
cd rexgen
./install.sh
sudo ldconfig
cd && cd $secret

# john
echo -e "\n${YELLOW}[!] install john${NC}"
sudo apt-get -y install git build-essential libssl-dev zlib1g-dev
sudo apt-get -y install yasm pkg-config libgmp-dev libpcap-dev libbz2-dev
git clone https://github.com/magnumripper/JohnTheRipper john
cd john/src
./configure --enable-rexgen && make -s clean && make -sj4
cd && cd $secret

# install sublist3r
echo -e "\n${YELLOW}[!] install Sublist3r${NC}"
git clone https://github.com/aboul3la/Sublist3r
cd Sublist3r
sudo pip3 install -r requirements.txt 
cd && cd $secret


# install theharvester
echo -e "\n${YELLOW}[!] install theharvester${NC}"
git clone https://github.com/laramies/theHarvester
cd theHarvester
sudo pip3 install -r requirements.txt 
cd && cd $secret

# install windows-exploit-suggester
echo -e "\n${YELLOW}[!] install windows-exploit-suggester${NC}"
git clone https://github.com/GDSSecurity/Windows-Exploit-Suggester
cd Windows-Exploit-Suggester
./windows-exploit-suggester.py --update
cd && cd $secret

#install cewl
echo -e "\n${YELLOW}[!] install cewl${NC}"
git clone https://github.com/digininja/CeWL
cd CeWL
bundle install
ruby -W0 ./cewl.rb
cd && cd $secret

# install metasploit
echo -e "\n${YELLOW}[!] install metasploit${NC}"
cd /opt
sudo git clone https://github.com/rapid7/metasploit-framework.git
sudo chown -R `whoami` /opt/metasploit-framework
gem install bundler
bundle install
sudo bash -c 'for MSF in $(ls msf*); do ln -s /opt/metasploit-framework/$MSF /usr/local/bin/$MSF;done'
echo "export PATH=$PATH:/usr/lib/postgresql/11/bin" >> ~/.bashrc
sudo usermod -a -G postgres `whoami`
sudo su - `whoami`
cd /opt/metasploit-framework/
sudo msfupdate
msfdb init
cd && cd $secret


# install aircrack-ng
echo -e "\n${YELLOW}[!] install aircrack-ng${NC}"
sudo apt install -y autoconf automake libtool
sudo apt install -y libssl-dev libgcrypt20-dev libnl-3-dev libnl-genl-3-dev ethtool
wget https://download.aircrack-ng.org/aircrack-ng-1.6.tar.gz
echo "decompress aircrack-ng..."
tar -zxvf aircrack-ng-1.6.tar.gz
rm aircrack-ng-1.6.tar.gz
cd aircrack-ng-1.6
./autogen.sh
make
sudo make install
sudo airodump-ng-oui-update
cd && cd $secret

# instal mdk3
echo -e "\n${YELLOW}[!] install mdk4${NC}"
sudo apt-get install pkg-config libnl-3-dev libnl-genl-3-dev libpcap-dev 
git clone https://github.com/aircrack-ng/mdk4
cd mdk4
make
sudo make install
cd && cd $secret

# install pixie-dust
echo -e "\n${YELLOW}[!] install pixie-dust${NC}"
git clone https://github.com/wiire/pixiewps
cd pixiewps*/
cd src/
make
sudo make install
cd && cd $secret

# install reaver
echo -e "\n${YELLOW}[!] install reaver${NC}"
sudo apt-get -y install build-essential libpcap-dev sqlite3 libsqlite3-dev
git clone https://github.com/t6x/reaver-wps-fork-t6x
cd reaver-wps-fork-t6x*/
cd src/
./configure
make
sudo make install
cd && cd $secret

# install shc
echo -e "\n${YELLOW}[!] install shc${NC}"
git clone https://github.com/neurobin/shc
cd shc
./configure
make
sudo make install
cd && cd $secret

# install ds_store_exp
echo -e "\n${YELLOW}[!] install ds_store_exp${NC}"
git clone https://github.com/lijiejie/ds_store_exp
cd ds_store_exp
sudo pip3 install -r requirements.txt
cd && cd $secret

# install fing
mkdir fing
cd fing
wget https://www.fing.com/images/uploads/general/CLI_Linux_Debian_5.5.2.zip
sudo dpkg -i fing-5.5.2-armhf.deb
cd && cd $secret
rm -rf fing

# install searchsploit
echo -e "\n${YELLOW}[!] install searchsploit${NC}"
sudo git clone https://github.com/offensive-security/exploitdb.git /opt/exploitdb
sed 's|path_array+=(.*)|path_array+=("/opt/exploitdb")|g' /opt/exploitdb/.searchsploit_rc > ~/.searchsploit_rc
sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit

# disable service
echo -e "\n${YELLOW}[!] disable services${NC}"
sudo systemctl disable apache2
sudo systemctl disable bluetooth
sudo systemctl disable dnsmasq
sudo systemctl disable mariadb
sudo systemctl disable postgresql
sudo systemctl disable tor

# update updatedb
echo -e "\n${YELLOW}[!] updatedb${NC}"
sudo updatedb

# need reboot
echo -e "\n${GREEN}[>] Need reboot${NC}"
echo "Please run 'bash post-snap-install.sh' after reboot"

##### more tools
# https://github.com/sensepost/go-out
# https://github.com/ustayready/fireprox
# https://github.com/ssh-mitm/ssh-mitm
# https://github.com/Sjord/jwtcrack
# https://github.com/hahwul/jwt-hack
# https://github.com/aircrack-ng/mdk4
# https://github.com/cathugger/mkp224o
# https://github.com/NickCarneiro/curlconverter
# https://github.com/jamhall/s3rver

# curl -sL https://deb.nodesource.com/setup_14.x | sudo -E bash -
# sudo apt-get install -y nodejs
# sudo npm install yarn -g

# https://github.com/s4vitar/rpcenum
# https://github.com/clarketm/s3recon
# https://github.com/nnposter/nndefaccts
# https://github.com/sharkdp/bat
# https://github.com/shazow/ssh-chat
# https://github.com/sharkdp/hexyl
# https://github.com/bitsadmin/wesng
# https://github.com/gtanner/qrcode-terminal
# https://github.com/evilsocket/ditto
# https://github.com/bettercap/bettercap
# https://github.com/mitmproxy/mitmproxy
# https://github.com/pry0cc/soxy

# https://github.com/s0md3v/Arjun


# https://github.com/SecureAuthCorp/impacket
# https://github.com/byt3bl33d3r/CrackMapExec
# https://github.com/samratashok/nishang
# https://github.com/BC-SECURITY/Empire
# https://github.com/nettitude/PoshC2
