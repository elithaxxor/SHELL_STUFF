#!/bin/bash

echo $(which bash) 
read -p "ip/hostname" ip 
read -p "nikto(y/n)" confirm 
sudo nmap -sC -sV $ip 

if [ "$confirm" == "y"];
then 
	nikto --host $ip 
fi 






