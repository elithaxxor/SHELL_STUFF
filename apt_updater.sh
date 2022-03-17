#!/bin/bash 

### to run with chrontab 
## run updates 

function sys_update(){
	sudo apt-get update && sudo apt-get upgrade -y 
	## remove unused dependacncies 
	sudo apt-get autoremove && sudo apt-get autoclean
	## create log file 
	echo "Update Log: " > apt_log.txt
	date >> apt_log.txt
}

sys_update 

exit 
