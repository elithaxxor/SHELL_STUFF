!/bin/bash
export DEBIAN_FRONTEND=noninteractive

# secret directory
secret=arsenal
cd
mkdir $secret
cd $secret
echo -e "\n${YELLOW}[+] folder 'secret' created${NC}"

sudo sh -c 'echo "\nDefaults timestamp_timeout=-1">>/etc/sudoers'

# update system
echo -e "\n${YELLOW}[!] update and upgrade system${NC}"
sudo apt-get update
sudo apt-get dist-upgrade -y


##### Repo #####

# install from apt-get
echo -e "\n${YELLOW}\n[!] install tools with apt-get${NC}"
sudo apt-get install -yq \
	adb \
	apache2 \
	apropos \
	arp-scan \
	baobab \
	curl \
	default-jdk \
	default-jre \
	dhex \
	dnsmasq \
	ettercap-text-only \
	evince \
	fastboot \
	filezilla \
	flameshot \
	git \
	hashcat \
	hexedit \
	hexyl \
	hostapd \
	hping3 \
	htop \
	iperf3 \
	iw \
	jq \
	libimage-exiftool-perl \
	libreoffice \
	libreoffice-l10n-es \
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
	prips \
	proxychains4 \
	python3-dev \
	python3-pip \
	ruby-full \
	s3fs \
	screen \
	simplescreenrecorder \
	smbclient \
	snapd \
	tcpdump \
	terminator \
	tmux \
	tor \
	torsocks \
	traceroute \
	tree \
	trickle \
	unrar \
	vim \
	wipe \
	wireless-tools \
	wireshark-qt \
	whois \
	xclip \
	zeal;

# aircrack-ng
sudo apt install -y aircrack-ng mdk4

##### Ruby ######
echo -e "\n${YELLOW}[!] install from gems${NC}"
sudo gem install \
	wpscan \
	bundle \
	evil-winrm \
	pedump;

##### Python #####
sudo pip3 install \
	apkid \
	autopep8 \
	beautifulsoup4 \
	cloudscraper \
	diagrams \
	dnspython \
	dnstwist \
	exrex \
	fastapi \
	Faker \
	festin \
	getsploit \
	glances \
	grip \
	intensio-obfuscator \
	myjwt \
	name-that-hash \
	nfstream \
	nudepy \
	pipreqs \
	pproxy \
	proxy.py \
	pyautogui \
	pyinstaller \
	pyserv \
	python-telegram-bot \
	python-whois \
	requests \
	s3recon \
	scapy \
	search-that-hash \
	shadowsocks \
	shodan \
	slowloris \
	smtp-user-enum \
	sqlmap \
	ssh-mitm \
	sshuttle \
	wafw00f;


##### Snap #####
sudo snap install \
	amass \
	beekeeper-studio \
	binwalk-spirotot \
	brave \
	chromium \
	drawio \
	john-the-ripper \
	jwt-hack \
	leafpad \
	lolcat \
	mycli \
	postman \
	scrcpy \
	vlc;

sudo snap install code --classic
sudo snap install go --classic
sudo snap install netbeans --classic
sudo snap install node --classic
#sudo snap install intellij-idea-community --classic
#sudo snap install pycharm-community --classic

# install chrome
wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
sudo dpkg -i google-chrome-stable_current_amd64.deb
rm -rf google-chrome-stable_current_amd64.deb

# Go tools
curl https://raw.githubusercontent.com/vay3t/hax0rpi/master/post-snap-install.sh | bash


##### Git #####
git clone https://github.com/maurosoria/dirsearch
git clone https://github.com/lgandx/Responder
git clone https://github.com/drwetter/testssl.sh
git clone --recursive https://github.com/evgeni/qifi.git
git clone https://github.com/trustedsec/unicorn
git clone https://github.com/L-codes/Neo-reGeorg
git clone https://github.com/defparam/smuggler
git clone https://github.com/blackarrowsec/mssqlproxy
git clone https://github.com/volatilityfoundation/volatility3
git clone https://github.com/WHK102/htrash
git clone https://github.com/PowerShellMafia/PowerSploit
git clone https://github.com/samratashok/nishang
git clone https://github.com/danielbohannon/Invoke-Obfuscation
git clone https://github.com/nnposter/nndefaccts
git clone https://github.com/CISOfy/lynis
git clone https://github.com/s4vitar/rpcenum
git clone https://github.com/magnumripper/JohnTheRipper john
git clone https://github.com/cujanovic/Open-Redirect-Payloads
git clone https://github.com/trustedsec/hate_crack
git clone https://github.com/Mr-Un1k0d3r/DKMC
git clone https://github.com/cytopia/pwncat
git clone https://github.com/m4ll0k/Atlas
git clone https://github.com/OsandaMalith/IPObfuscator
git clone https://github.com/chrispetrou/EnumSNMP
git clone https://github.com/elithaxxor
git clone https://github.com/nodoraiz/latchHooks
git clone https://github.com/fO-000/bluescan
git clone https://github.com/nodoraiz/droidbox
git clone https://github.com/nodoraiz/substrate-base
git clone https://github.com/nodoraiz/android-hooker
git clone https://github.com/nodoraiz/apkstudio
git clone https://github.com/nodoraiz/jadx
git clone https://github.com/nodoraiz/jadx
git clone https://github.com/nodoraiz/theZoo
git clone https://github.com/nodoraiz/AxmlParserPY
git clone https://github.com/nodoraiz/theZoo
git clone https://github.com/nodoraiz/latchHooks
git clone https://github.com/nodoraiz/AndroidAnalysis
git clone https://github.com/nodoraiz/apk_binder_script
git clone https://github.com/nodoraiz/SMShound
git clone https://github.com/nodoraiz/obfuscar
git clone https://github.com/nodoraiz/mkspoof
git clone https://github.com/nodoraiz/DesktopBruteForcing
git clone https://github.com/nodoraiz/PHP-Shell-Detector

##### Wget #####
wget https://github.com/byt3bl33d3r/CrackMapExec/releases/download/v5.1.1dev/cmedb-ubuntu-latest.zip
wget https://github.com/byt3bl33d3r/CrackMapExec/releases/download/v5.1.1dev/cme-ubuntu-latest.4.zip
wget https://snapshots.mitmproxy.org/6.0.2/mitmproxy-6.0.2-linux.tar.gz
wget https://github.com/EgeBalci/amber/releases/download/v3.1/amber_linux_amd64_3.1.zip
wget https://github.com/BloodHoundAD/BloodHound/releases/download/4.0.2/BloodHound-linux-x64.zip
wget https://github.com/Studio3T/robomongo/releases/download/v1.4.3/robo3t-1.4.3-linux-x86_64-48f7dfd.tar.gz
wget https://github.com/projectdiscovery/nuclei/releases/download/v2.3.4/nuclei_2.3.4_linux_amd64.tar.gz
wget https://github.com/projectdiscovery/proxify/releases/download/v0.0.3/proxify_0.0.3_linux_amd64.tar.gz
wget https://github.com/projectdiscovery/httpx/releases/download/v1.0.5/httpx_1.0.5_linux_amd64.tar.gz
wget https://github.com/projectdiscovery/subfinder/releases/download/v2.4.7/subfinder_2.4.7_linux_amd64.tar.gz
wget https://github.com/icsharpcode/AvaloniaILSpy/releases/download/v7.0-rc1/linux-x64.zip
wget https://github.com/s4n7h0/Halcyon-IDE/releases/download/v2.0.2/Halcyon_IDE_v2.0.2.jar
wget https://github.com/angryip/ipscan/releases/download/3.7.6/ipscan_3.7.6_amd64.deb
wget https://github.com/subhra74/snowflake/releases/download/v1.0.4/snowflake-1.0.4-setup-amd64.deb

##### Install from URL #####

# joplin
wget -O - https://raw.githubusercontent.com/laurent22/joplin/dev/Joplin_install_and_update.sh | bash

# gitjacker
curl -s "https://raw.githubusercontent.com/liamg/gitjacker/master/scripts/install.sh" | sudo bash

##### npm #####
sudo npm install -g yarn
sudo npm install -g elasticdump
#sudo npm install -g curlconverter
sudo npm install -g qrcode-terminal
sudo npm install -g s3rver
sudo npm install -g apk-mitm
sudo yarn global add wappalyzer

##### Git install #####

# snmpwn
git clone https://github.com/hatlord/snmpwn.git
cd snmpwn
sudo bundle install
cd && cd $secret

# enum4linux-ng
git clone https://github.com/cddmp/enum4linux-ng
cd enum4linux-ng
sudo python3 setup.py install
cd && cd $secret

# Sherlock
git clone https://github.com/sherlock-project/sherlock.git
cd sherlock
python3 -m pip install -r requirements.txt
cd && cd $secret

# Photon
git clone https://github.com/s0md3v/Photon.git
cd Photon
sudo pip3 install -r requirements.txt
cd && cd $secret

# Impacket
git clone https://github.com/SecureAuthCorp/impacket
cd impacket
sudo python3 setup.py install
cd && cd $secret

# Sublist3r
git clone https://github.com/aboul3la/Sublist3r
cd Sublist3r
sudo pip3 install -r requirements.txt
cd && cd $secret

# spiderfoot
git clone https://github.com/smicallef/spiderfoot.git
cd spiderfoot
sudo pip3 install -r requirements.txt
cd && cd $secret

# theHarvester
git clone https://github.com/laramies/theHarvester
cd theHarvester
sudo pip3 install -r requirements.txt
cd && cd $secret

# git-dumper
git clone https://github.com/arthaud/git-dumper
cd git-dumper
sudo pip3 install -r requirements.txt
cd && cd $secret

# wesng
git clone https://github.com/bitsadmin/wesng
cd wesng
sudo python3 setup.py install
cd && cd $secret

# RsaCtfTool
git clone https://github.com/Ganapati/RsaCtfTool
cd RsaCtfTool
sudo apt-get install libgmp3-dev libmpc-dev -y
pip3 install -r requirements.txt
cd && cd $secret

# uncompyle6
git clone https://github.com/rocky/python-uncompyle6
cd python-uncompyle6
sudo python3 setup.py install
cd && cd $secret

# smbmap
git clone https://github.com/ShawnDEvans/smbmap
cd smbmap
python3 -m pip install -r requirements.txt
cd && cd $secret

# salamandra
sudo apt-get install rtl-sdr -y
git clone https://github.com/eldraco/Salamandra

# crowbar
git clone https://github.com/galkan/crowbar
cd crowbar/
pip3 install -r requirements.txt
cd && cd $secret

# SSRFmap
git clone https://github.com/swisskyrepo/SSRFmap
cd SSRFmap/
sudo pip3 install -r requirements.txt
cd && cd $secret

# s3viewer
git clone https://github.com/SharonBrizinov/s3viewer
cd s3viewer
python3 -m pip install -r packaging/requirements.txt
cd && cd $secret

# dotdotslash
git clone https://github.com/jcesarstef/dotdotslash
cd dotdotslash
sudo pip3 install -r requirements.txt
cd && cd $secret

# ntlm_theft
git clone https://github.com/Greenwolf/ntlm_theft
cd ntlm_theft
sudo pip3 install xlsxwriter
cd && cd $secret

# jwtcrack
git clone https://github.com/Sjord/jwtcrack
cd jwtcrack
sudo pip3 install -r requirements.txt
cd && cd $secret

# ccat
git clone https://github.com/cisco-config-analysis-tool/ccat
cd ccat
sudo pip3 install -r requirements.txt
cd && cd $secret

# wss
git clone https://github.com/WHK102/wss
cd wss
sudo pip3 install -r requirements.txt
cd && cd $secret

# fing
mkdir finggg
cd finggg
wget https://www.fing.com/images/uploads/general/CLI_Linux_Debian_5.5.2.zip
unzip CLI_Linux_Debian_5.5.2.zip
sudo dpkg -i fing-5.5.2-amd64.deb
cd ..
rm -rf finggg
cd && cd $secret

# searchsploit
sudo git clone https://github.com/offensive-security/exploitdb.git /opt/exploitdb
sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit

# metasploit
wget "https://apt.metasploit.com/$(curl -s https://apt.metasploit.com/ | grep 'amd64.deb' | tail -1 | cut -d '"' -f 2)"
sudo dpkg -i metasploit*.deb
rm metasploit*.deb
cd && cd $secret

# cewl
echo -e "\n${YELLOW}[!] install cewl${NC}"
git clone https://github.com/digininja/CeWL
cd CeWL
bundle install
cd && cd $secret

# intruder payloads
git clone https://github.com/1N3/IntruderPayloads
cd IntruderPayloads
./install.sh
cd && cd $secret

# eaphammer
git clone https://github.com/s0lst1c3/eaphammer

# hcxtools
git clone https://github.com/ZerBea/hcxtools
cd hcxtools
make
sudo make install
cd && cd $secret

# onesixtyone
git clone https://github.com/trailofbits/onesixtyone
cd onesixtyone
make
sudo make install
cd && cd $secret

# 3proxy
git clone https://github.com/z3apa3a/3proxy
cd 3proxy
ln -s Makefile.Linux Makefile
make
sudo make install
cd && cd $secret

# Radamsa
sudo apt-get install gcc make git wget
git clone https://gitlab.com/akihe/radamsa.git && cd radamsa && make && sudo make install
cd && cd $secret

# Sublime text
wget -qO - https://download.sublimetext.com/sublimehq-pub.gpg | sudo apt-key add -
sudo apt-get install apt-transport-https -y
echo "deb https://download.sublimetext.com/ apt/stable/" | sudo tee /etc/apt/sources.list.d/sublime-text.list
sudo apt-get update
sudo apt-get install sublime-text -y

# oletools
git clone https://github.com/decalage2/oletools
cd oletools
sudo python3 setup.py install
cd && cd $secret

# PCredz
git clone https://github.com/lgandx/PCredz
apt install python3-pip -y && sudo apt-get install libpcap-dev -y && pip3 install Cython && pip3 install python-libpcap

# Hydra

sudo apt-get install -y libssl-dev libssh-dev libidn11-dev libpcre3-dev \
                 libgtk2.0-dev libmysqlclient-dev libpq-dev libsvn-dev \
                 firebird-dev libmemcached-dev libgpg-error-dev \
                 libgcrypt11-dev libgcrypt20-dev

git clone https://github.com/vanhauser-thc/thc-hydra
cd thc-hydra
./configure
make
sudo make install
cd && cd $secret

##### Download git release and more

function websocat_install(){
	echo "Installing latest version of websocat"
	latest_version=$(curl -s https://github.com/vi/websocat/releases/ | grep "websocat_" | head -1 | cut -d'/' -f6)
	curl -L "https://github.com/vi/websocat/releases/download/$latest_version/websocat_$(echo $latest_version | sed 's/v//')_newer_amd64.deb" --output "websocat_$(echo $latest_version | sed 's/v//')_newer_amd64.deb"
	sudo dpkg -i "websocat_$(echo $latest_version | sed 's/v//')_newer_amd64.deb"
	rm "websocat_$(echo $latest_version | sed 's/v//')_newer_amd64.deb"
}

function bat_install(){
	echo "Installing latest version of bat"
	latest_version=$(curl -s https://github.com/sharkdp/bat/releases | grep "bat_" | head -1 | cut -d'/' -f6)
	curl -L "https://github.com/sharkdp/bat/releases/download/$latest_version/bat_$(echo $latest_version | sed 's/v//')_amd64.deb" --output "bat_$(echo $latest_version | sed 's/v//')_amd64.deb"
	sudo dpkg -i "bat_$(echo $latest_version | sed 's/v//')_amd64.deb"
	rm "bat_$(echo $latest_version | sed 's/v//')_amd64.deb"
}

function jdgui_install(){
	echo "Installing latest version of JD-GUI"
	latest_version=$(curl -s https://github.com/java-decompiler/jd-gui/releases | grep "jd-gui-" | head -1 | cut -d'/' -f6)
	curl -L "https://github.com/java-decompiler/jd-gui/releases/download/$latest_version/jd-gui-$(echo $latest_version | sed 's/v//').deb" --output "jd-gui-$(echo $latest_version | sed 's/v//').deb"
	sudo dpkg -i "jd-gui-$(echo $latest_version | sed 's/v//').deb"
	rm "jd-gui-$(echo $latest_version | sed 's/v//').deb"
}

function starkiller_install(){
	echo "Installing latest version of Starkiller"
	latest_version=$(curl -s https://github.com/BC-SECURITY/Starkiller/releases | grep "starkiller-" | head -1 | cut -d'/' -f6)
	curl -L "https://github.com/BC-SECURITY/Starkiller/releases/download/$latest_version/starkiller-$(echo $latest_version | sed 's/v//').AppImage" --output "starkiller-$(echo $latest_version | sed 's/v//').AppImage"
	chmod +x "starkiller-$(echo $latest_version | sed 's/v//').AppImage"
}

function burp_download(){
	echo "Downloading latest version of Burpsuite Community"
	latest_version=$(curl "https://portswigger.net/burp/releases/data?previousLastId=-1&lastId=-1&pageSize=10" -s | jq ".ResultSet.Results[].builds" | grep -A5 '"community"' | grep -A4 '"Linux"' | grep Version | cut -d '"' -f 4 | sort -n | tail -1)
	curl -L "https://portswigger.net/burp/releases/download?product=community&version=$latest_version&type=Linux" --output burp.sh
	chmod +x burp.sh
}

function hashcat_download(){
	echo "Downloading latest version of hashcat"
	latest_version=$(curl -s https://github.com/hashcat/hashcat/releases | grep "hashcat-" | head -1 | cut -d'/' -f6)
	curl -L "https://github.com/hashcat/hashcat/releases/download/$latest_version/hashcat-$(echo $latest_version | sed 's/v//').7z" --output "hashcat-$(echo $latest_version | sed 's/v//').7z"
	7z x "hashcat-$(echo $latest_version | sed 's/v//').7z"
	rm "hashcat-$(echo $latest_version | sed 's/v//').7z"
}

function frp_download(){
	echo "Downloading latest version of fast reverse proxy"
	latest_version=$(curl -s https://github.com/fatedier/frp/releases | grep "frp_" | head -1 | cut -d'/' -f6)
	curl -L "https://github.com/fatedier/frp/releases/download/$latest_version/frp_$(echo $latest_version | sed 's/v//')_linux_amd64.tar.gz" --output "frp_$(echo $latest_version | sed 's/v//')_linux_amd64.tar.gz"
	tar xzvf "frp_$(echo $latest_version | sed 's/v//')_linux_amd64.tar.gz"
	rm "frp_$(echo $latest_version | sed 's/v//')_linux_amd64.tar.gz"
}

function powershell_installer(){
	echo "Installing latest version of powershell"
	latest_version="$(curl -s https://github.com/PowerShell/PowerShell/releases | grep powershell_ | cut -d "/" -f6 | grep -E "^v" | head -1)"
	curl -L "https://github.com/PowerShell/PowerShell/releases/download/$latest_version/powershell_$(echo $latest_version | sed 's/v//')-1.ubuntu.20.04_amd64.deb" --output "powershell_$(echo $latest_version | sed 's/v//')-1.ubuntu.20.04_amd64.deb"
	sudo dpkg -i "powershell_$(echo $latest_version | sed 's/v//')-1.ubuntu.20.04_amd64.deb"
	sudo apt install -f
	rm "powershell_$(echo $latest_version | sed 's/v//')-1.ubuntu.20.04_amd64.deb"
}

# run functions
websocat_install
bat_install
jdgui_install
starkiller_install
burp_download
hashcat_download
frp_download


# Install empire
powershell_installer
sudo pip3 install poetry
git clone --recursive https://github.com/BC-SECURITY/Empire.git
cd Empire
sudo ./setup/install.sh
sudo poetry install
cd && cd $secret


# disable service
echo -e "\n${YELLOW}[!] disable services${NC}"
sudo systemctl disable apache2
sudo systemctl disable bluetooth
sudo systemctl disable dnsmasq
sudo systemctl disable mariadb
sudo systemctl disable postgresql
sudo systemctl disable tor


#install_rustbuster() {
#    echo "Installing latest version of Rustbuster"
#    latest_version=`curl -s https://github.com/phra/rustbuster/releases | grep "rustbuster-v" | head -n1 | cut -d'/' -f6`
#    echo "Latest release: $latest_version"
#    mkdir -p /opt/rustbuster
#    wget -qP /opt/rustbuster https://github.com/phra/rustbuster/releases/download/$latest_version/rustbuster-$latest_version-x86_64-unknown-linux-gnu
#    ln -fs /opt/rustbuster/rustbuster-$latest_version-x86_64-unknown-linux-gnu /opt/rustbuster/rustbuster
#    chmod +x /opt/rustbuster/rustbuster
#    echo "Done! Try running"
#    echo "/opt/rustbuster/rustbuster -h"
#}



#install_rustbuster


sudo sed -i '$ d' /etc/sudoers
