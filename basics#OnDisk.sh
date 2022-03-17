#!/bin/sh

#  basics.sh
#  
#
#  Created by a-robot on 3/14/22.
#  
#! /bin/bash


## FILE CONDITIONS ###
# -d (True if is a directory)
# -e (true if file exists )
# -f (True if string is a filename)
# -g (True for group ID)
# -r (True if readable)
# -s (True if file is non 0 size)
# -u (True if the file is set)
# -w (True if file is wrtable)
# -x (true if exextuable)
#########



####### THE CUT COMMANDS #####
# -f, --fields    Field-based selection
# -d, --delimiter    Delimiter for field-based selection
# -c, --characters    Character-based selection, delimiter ignored or error
# -s, --only-delimited    Suppress lines with no delimiter characters (printed as-is otherwise)
# --complement    Inverted selection (extract all except specified fields/characters
# --output-delimiter    Specify when it has to be different from the input delimiter
#
###### EXAMPLE ######
# cut -f1,3 # extract first and third tab-delimited field (from stdin)
# cut -f1-3 # extract from first up to third field (ends included)
# cut -f-3 # -3 is interpreted as 1-3
# cut -f2- # 2- is interpreted as from the second to the last
# cut -c1-5,10 # extract from stdin the characters in positions 1,2,3,4,5# ,10
# cut -s -f1 # suppress lines not containing delimiters
# cut --complement -f3 # (GNU cut only) extract all fields except the third
####### EXAMPLE ########


## TO FIND BASH LOCATION ## 
which batch 

### to create update log ### 
echo "Update Log: " > apt_log.txt
date >> apt_log.txt


#vars
name="l337"
FILE='text.txt'
DIR ="DIR"
M_NAMES="FRANK JESSIE GRIMES HOMER"

### SET ## set ootenetial arguemnt sgto potential paramaters
## set ootenetial arguemnt sgto potential paramaters




## FILE MANIPULATION
if [-f "$FILE"]
then
    echo "${FILE} is indeed a file!"
else
    echo "Could not find ${FILE} :["
fi
    
    if [-d "$DIR"]
then
    echo "${DIR} is indeed a file!"
else
    echo "Could not find ${DIR} :["
fi
    
#### FOR LOOP TO MANIPULATE FILE ###
DIRS=$(ls *.txt)
NEW="new"
for DIR in $DIRS
    do
        echo "renaming $DIR to new-$DIR"
        mv $DIR $NEW-$DIR
    done

### READ THROUGH LINE BY LINE
LINE=1
while read -r CURRENT_LINE
    do
        echo "reading lines.. "
        echo "$LINE: $URRENT_LINE"
        ((LINE++))
    done < "./new-1.txt"
        
        
## CREATE FOLDER AND WRITE TO FILE
mkdir hello
touch "hello/world.txt"
echo "hello world" >> "hello/world.txt"
echo "created hello world fioled in hello dir"
######

### to copy variable to new loc
destdir=$(pwd)
    if [ -f "$destdir" ]
    then
    echo "$var" > "$destdir"
    fi


### check if dir exists if not create it 
if [! -d "third_levels"]; then
    mkdir third_levels
fi



echo "starting HTTP-probe [HTTP-REQ]"
cat before_http_probe.txt | sort -u | httprobe -s -p https:443 | sed 's/https\?:\/\///' | tr -d ":443" > probed.txt



### SIMPLE FUNCTION
function hello_world(){
    echo "hello world"
}
hello_world

function say_hello(){
    echo "hello, i am $1, and i am $2"
}
say_hello "frankie" "33"

###########

    
    
## CASE-STATEMENT
read -p "are you over 21 years old? Y/N" ANSWER
case $"ANSWER" in
    [yY] | [yY][eE][sS])
    echo "You can have a beer!"
    ;;
    [nN] | [nN][oO])
    echo "sorry no drinking"
    ;;
    *)
    echo "please enter y/yes or n/no"
    ;;
esac



## TO SET COMMAND OUTPUT TO VAR
 var=$(/path/to/command)
 var=$(/path/to/command arg1 arg2)
var=$(command-name-here)
##### set IS USED TO SET  arguemnt PARAMATERS potential paramaters

set `date`
echo "Today is $1"
echo 


## SIMPLE WHILE LOOP
for S_NAME in $M_NAMES
    do
    echo"hello, ${S_NAME}"
done


### CREATE 4 PASSWORD
for p in $(seq 1-4);
do
  echo 'iterating...'
  openssl rand -base64 48 | cut -c1-$PASS_LEN # string traversal
done


## SORTING
echo -e "apple \nmango \nwatermelon \ncherry \norange \nbanana" > fruits.txt
sort fruits.txt

# sort just numbers
echo -e "45 \n69 \n52 \n21 \n3 \n5 \n78" > scores.txt
sort -n scores.txt

## sorting a versions
echo -e "1.0.0.1 \n 6.2.1.0 \n4.0.0.2" > versions.txt
sort --version-sort --field-separator=. versions.txt

## to find and sort via file extension
find . -iname "*.md" | sort -r


## FIND -- GREP -- ###
######### GREP ############
# Search any line that contains the word in filename on Linux:
grep 'word' filename
# Perform a case-insensitive search for the word ‘bar’ in Linux and Unix:
grep -i 'bar' file1
# Look for all files in the current directory and in all of its subdirectories in Linux for the word ‘httpd’:
grep -R 'httpd' .
# Search and display the total number of times that the string ‘nixcraft’ appears in a file named frontpage.md:
grep -c 'nixcraft' frontpage.md
## BEST TO GREP WHEN WITH SPECIAL CHARS
fgrep 'word-to-search' file.txt
# GREPPING AFTER MAKING FOLDER
cat /etc/passwd | grep -i "boo"

### RECURSIVE GREP - look for a string
grep -r "192.168.1.5" /etc/
## GREP DOES NOT OCNTIAN
grep -v '^root' /etc/passwd
cat /proc/cpuinfo | grep -i 'Model'
dmesg | egrep '(s|h)d[a-z]'
grep -i 'Model' /proc/cpuinfo ### to list CPU info GREP
grep -l 'main' *.c ## to just list names of matching files

GREP_COLOR='1;35' grep --color=always 'vivek' /etc/passwd # GREP COLOR S

### grep special chars
fgrep '[xyz]' filename
grep -F '[xyz]' filename
######### END-GREP ############


##### REMOVALS  ##### [tr]
#### TO REMOVE CHARICTER FROM STR
( | sed 's/h//')
## TR ##
tr [:upper:] [:lower:] # changing str case
tr a-z A-Z #convert from upper to lower
echo linuxhint | tr [:lower:] [:upper:] ## Outpputs all letters in echo to format
cat items.txt ## display all items, will not modify case
tr a-z A-Z < items.txt
echo "Welcome To Linuxhint" | tr [:space:] '\n' # insert charicter
echo "Phone No: 985634854" | tr -cd '0-9' ## remove all letteters and onoyu calculate numeric
echo "The product price 800 dollars" | tr -cd [:digit:] ## remover all non numeric



### displaying multiple items
cat –e SampleFile1 SampleFile2


## to search through a text for specific text and then sort to new
cat domain-test.txt | grep -Po "(\w+\.\w+\.\w+)$" | sort -u >> third-level.txt


#### RUNNING MULTIPEL COMMANDS
cd myfolder; ls   # no matter cd to myfolder successfully, run ls
cd myfolder && ls  # run ls only after cd to myfolder
cd myfolder || ls  # if failed cd to myfolder, `ls` will run
##






#Print
echo hello world!
echo "my name is ${name}"

#User-Input
read -p "Enter your real name " NAME
echo "so your real name is, ${NAME}? or ${name}"
read -p "1 for former, 2 for latter" decision


# conditionals
if [ -z "$decision" ]; ## if var is empty
then
    echo "\$decision is empty... i need to know your name!"
    echo "Please tell me your name.. "
    read real_name
    echo "nice to meet you, ${real_name}"
if ["$decision" == 1]
    echo "pleasure to meet you, ${name}"
else
    echo "your aquantence, ${NAME} is becomming of my existance. thank you so much."
fi



## NMAP 
echo "scanning for open ports"
nmap -iL probed.txt -T5 -oA scans/port_scan.txt -V

## find 
find . -type f - empty 



### TO ENUMERATE SUBDOMAINS sublist3r
wget https://github.com/aboul3la/Sublist3r/archive/master.zip
unzip master.zip
./sublist3r.py -d yourdomain.com



git clone https://github.com/droope/droopescan.git
apt install python-pip
pip install droopscan
pip install -r requirements.txt
./droopescan scan --help



## doopscan to scan vulnrable webservers 
droopscan scan drupal -u URL_HERE
droopscan scan silverstripe -u URL_HERE
./droopescan scan --help
droopescan scan drupal -u example.org
droopescan scan drupal -U list_of_urls.txt
droopescan scan -U list_of_urls.txt


## ARP SCAN 
echo ('enter pass:')
read pass
$(arp-scan -l | grep Raspberry | awk '{print $1}') root $pass




