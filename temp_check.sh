#!bin/bash 

echo "to check sys temp"

function sys_temp(){
	TEMP_LOC=/sys/class/thermal/thermal_zone0/temp 
	sys_temp=$(cat $TEMP_LOC)
	celcius=$((sys_temp/10000))
	farenheight=$((celcius * 9/5 +32 ))
	cat temp_log.txt
	echo "sys temp C $celcius"
	echo "sys temp F $farenheight"
	echo "Update Log: " > temp_log.txt
	date >> temp_log.txt
	sys_temp >> temp_log.txt
	celcius >> temp_log.txt
	farenheight >> temp_log.txt
}
sys_temp