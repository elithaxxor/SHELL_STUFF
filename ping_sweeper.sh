#!/bin/bash 

## simple ping sweep, the & at the end allows multi-threading. 
echo 'Enter The Subnet'
read SUBNET 

function sweep(){
	for ip in {1..254}
		do ping -c 3 192.168.50.$ip | grep "64 bytes" | cut -d " " -f 4 | tr -d ":" &
			echo "Update Log: " > sweep_log.txt
			date >> sweep_log.txt
	done 
}
sweep 
