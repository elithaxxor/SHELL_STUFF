#!bin/bash 

echo "john the ripper hash "\n
read HASHED_FILE 

function J_ripper(){
	sudo apt-get update && sudo apt-get upgrade -y 
	sudo apt-get install john -y

	if [-f "$HASHED_FILE"*.rar]
	then
	    echo "${HASHED_FILE} is .rar, starting process!"
	    rar2john $HASHED_FILE
	   	rar2john $HASHED_FILE > hash.txt 
	   	john --format=rar hash.txt

	if [-f "$HASHED_FILE"*.zip]
	then
	    echo "${HASHED_FILE} is .zip, starting process!"
	    zip2john $HASHED_FILE 
	   	zip2john $HASHED_FILE > hash.txt 
	   	john --format=zip hash.txt

	else 
		echo "${HASHED_FILE} not valid with John The Ripper--> .rar or .zip only!"
	fi 
}

J_ripper 


