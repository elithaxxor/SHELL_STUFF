#!/bin/bash
# copyleft-- all wrongs reserved. [elit_haxxor]

###################### [LINUX OR DARWIN]
## Program takes cwd and converts .py specified by users... refactor to *.py if multiple files are invovled. 
## Program is ONLY intended for [CLI] .py programs. 
## Change the args in pyinstaller [found in function py_installer()] to create .exe for [GUI] .py programs
######################

function py_installer() {
    python -m pip install -–upgrade pip
    pip3 install pyinstaller
    pyinstaller --onefile $py_file
    echo '[+] Parsed py_installer function! '

}

echo '[!] --[quick bash to convert .py to .exe]-- '
echo '[!] --[project strictly intended for cli based .py files]-- '
echo '[?] enter the filename to convert '
read py_file
echo '[!]' ${py_file}
cwd=$(pwd)
sudo FILE= "${cwd}/${py_file}"
echo '[+] Converting..'
echo $FILE

if [ -f "$py_file" ];
then
    echo "[+] ${FILE} is indeed a file!"
    py_installer
else
    echo "[-] Could not find ${FILE} :["
fi

