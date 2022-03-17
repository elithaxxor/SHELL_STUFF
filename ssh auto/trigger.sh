#!/bin/bash 

echo ('enter pass:')
read pass



#  runs expect script, with the 3 args. 	
expect expect.exp $(arp-scan -l | grep Raspberry | awk '{print $1}') root $pass

sudo apt update
sudo apt upgrade 
apt install infix

DIRS=$(ls *.txt)
broadcast = $(ifconfig | grep broadcast)
mac = $(ifconfig | grep mac)
Infix -Fxz





 

