website="https://darren.kitchen/"

function getIPfromDNS() 
    $(netcat $website) 
    $(host $website) 
    $(dig $website) 
    $(dnsrecon $website) 
}

function stealDarrensSite() {
	mkdir /home/CURLED_WEBSITE && cd /home/CURLED_WEBSITE 
	curl -o $website
	mkdir /home/WGET_WEBSITE && cd /home/WGET_WEBSITE 
	wget $website 
	mkdir /home/HTTPRACK_WEBSITE && cd /home/HTTPRACK_WEBSITE 
	httrack -w $website
	}

getIPfromDNS
stealDarrensSite
