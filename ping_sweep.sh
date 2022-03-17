#!/bin/bash 


echo "Enter the IP/Submnet" 
read SUBNET 

for ip in $(sec 1 243); 
            do 
            ping -c 1 $SUBNET.$IP 
            echo "pinging **[${ip}]"
done 

