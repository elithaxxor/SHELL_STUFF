source=()
count = 0 
sudo -p
git="git clone "

while IFS= read -r line; do
   source+=("$line")
   #echo $source
   git+=("$source")
   
  localRepoDir=$(echo ${localCodeDir}${source}|cut -d'.' -f1)
  if [ -d $localRepoDir ]; then 	
  		echo -e "Directory $localRepoDir already exits, skipping ...\n"
	else 
		git_command="$git$line"
		echo "[$count] $git_command"
    	eval $git_command
		count=$(($count+1))
fi
	

done <sources.txt


