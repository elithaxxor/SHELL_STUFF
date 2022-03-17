#!bin/bash 

function J_ripper(){
	sudo apt-get update && sudo apt-get upgrade -y 
	sudo apt-get install john -y
	john /etc/shadow

J_ripper 
