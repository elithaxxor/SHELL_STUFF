#!/bin/sh

#  Script.sh
#  
# regex101.com
# https://github.com/aboul3la/Sublist3r
# http probe
# https://github.com/NicolasSiver/http-probe
#  Created by a-robot on 3/14/22.
# https://www.youtube.com/watch?v=Gaf1Z1bwbpY
# eyewitness
# https://github.com/FortyNorthSecurity/EyeWitness



function Get_Clone(){
    echo "Getting Dependencies"
    git clone 'https://github.com/aboul3la/Sublist3r'
    git clone 'https://github.com/NicolasSiver/http-probe'
    git clone 'https://github.com/FortyNorthSecurity/EyeWitness'
}


### TO ENUMERATE SUBDOMAINS sublist3r
wget https://github.com/aboul3la/Sublist3r/archive/master.zip
unzip master.zip
./sublist3r.py -d yourdomain.com

# https://dnsdumpster.com/

echo ('enter pass:')
read pass
$(arp-scan -l | grep Raspberry | awk '{print $1}') root $pass

function Mkdirs(){
    if [! -d "third_levels"]; then
        mkdir third_levels
    fi
    
    if [! -d "scans"]; then
        mkdir scans
    fi
    
    if [! -d "eyewitness"]; then
        mkdir eyewitness
    fi
}



pwd = $(pwd)
echo "starting program"
echo "CWD: ${pwd}"


Get_Clone
Mkdirs


echo "starting sub-domin grab"
sublist3r -d $1 -o final.txt

echo 'compiling 3rd level domain'
cat domain_list.txt | grep -Po "(\w+\.\w+\.\w+)$" | sort -u >> third-level.txt


echo 'Enumerating through doman for [FULL] Sublistings'
for domain in $(cat third-level.txt);
    do sublist3r -d $domain -o third_levels/$domain.txt;
        cat third_levels/$domain.txt;
        sort -u >> final.text;
done

if [ $# -eq 2 ]; ## to check the amount of paramantes [assed to sys] ## it is stored in $#

then
    echo "probing for [domains] 3rd level--[GREP]"
    cat final.txt | sort -u | grep -v $2 | httprobe -s - p https:443 | sed 's/https\?:\/\///' | tr -d ":443" > probed.txt
else
    echo "probing for [domains] , [HTTP-PROBE]"
    cat final.txt | sort -u | httprobe -s -p https:443 | sed 's/https\?:\/\///' | tr -d ":443" > probed.txt
fi


echo "scanning for open ports"
nmap -iL probed.txt -T5 -oA scans/port_scan.txt -V

echo "Eyewitness"
eyewitness -f $pwd/probed.txt -d $1 --all-protocols

mv /usr/share/eyewitness/$1 eyewitness/$1

