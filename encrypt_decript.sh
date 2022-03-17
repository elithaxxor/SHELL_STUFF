#!/bin/sh

#  encrypt_decript.sh
#  
#
#  Created by a-robot on 3/14/22.
#  

function main(){
    echo "[ENCYPT and DECRYPTOR] "
/Users/a-robot/Documents/SHELL/trigger.sh    choice="Encrypt Decrypt"
    select option in $choice; do
    if [$REPLY == 1];
        then
        echo "Proceeding with [encrypt]"
        echo "please enter the file name"
        read file;
        gpg -c $file
        pwd
        ls -a -l
        echo "the file has been encypted"
    else
        echo "Proceeding with [decrypt]"
        echo "please enter the file name"
        pwd
        ls -a -l
        read file2;
        gpg -d $file2
        echo "the file has been decrypted"
}

main

