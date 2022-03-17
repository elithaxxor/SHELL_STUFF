#!/bin/bash 


## password generator 
echo "welcom to a my simple password gen useing b64"
read PASS_LEN

for p in $(seq 1 2); 
do
  echo 'iterating...'
  var=$(openssl rand -base64 48 | cut -c1-$PASS_LEN | sed 's/h//') # string traversal 
done 

echo "$var" 

function save_info(){
            #DIR = "pword_dir"
            # mkdir "$DIR" && cd "$DIR";
            destdir=$(pwd)
            echo "saving password to${destdir}"
            touch pass.txt
            # echo "$var" > "$pass.txt"
            destdir=$(pwd)

            if [ -f "$destdir" ]
            then 
            echo "$var" > "$destdir"
            fi
            sudo chmod 755 pass.txt
            echo 'password is saved: ';
            pwd
            
}

save_info





