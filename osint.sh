start=$SECONDS
mkdir $1
mkdir $1/osint

# Google Dorking
~/Tools/degoogle_hunter/degoogle_hunter.sh $1 | tee $1/osint/dorks.txt
sed -r -i "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" $1/osint/dorks.txt

# Github Dorking
python3 ~/Tools/GitDorker/GitDorker.py -t $GITHUB_TOKEN -q $1 -p -ri -d ~/Tools/GitDorker/Dorks/alldorksv3.txt | grep "\[+\]" | grep "git" | anew -q $1/osint/gitdorks.txt
sed -r -i "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" $1/osint/gitdorks.txt

# MetadataS Scanning for Public Files
mkdir $1/osint/metafinder
metafinder -d $1 -l 20 -o $1/osint/metafinder -go -bi -ba
mv "$1/osint/metafinder/$1/"*".txt" "$1/osint/"
rm -rf "$1/osint/metafinder/$1" 

# email, user, password leak searching
emailfinder -d $1 | anew -q $1/osint/emailfinder.txt
cat $1/osint/emailfinder.txt | awk 'matched; /^-----------------$/ { matched = 1 }' | anew -q $1/osint/emails.txt
theHarvester -d $1 -b all > $1/osint/harvester.txt
cat $1/osint/harvester.txt | awk '/Emails/,/Hosts/' | sed -e '1,2d' | head -n -2 | sed -e '/Searching /d' -e '/exception has occurred/d' -e '/found:/Q' | anew -q $1/osint/emails.txt
cat $1/osint/harvester.txt | awk '/Users/,/IPs/' | sed -e '1,2d' | head -n -2 | sed -e '/Searching /d' -e '/exception has occurred/d' -e '/found:/Q' | anew -q $1/osint/users.txt
cat $1/osint/harvester.txt | awk '/Links/,/Users/' | sed -e '1,2d' | head -n -2 | sed -e '/Searching /d' -e '/exception has occurred/d' -e '/found:/Q' | anew -q $1/osint/linkedin.txt
h8mail -t $1 -q domain --loose -c ~/Tools/h8mail_config.ini -j $1/osint/h8_results.json
cat $1/osint/h8_results.json | jq -r '.targets[0] | .data[] | .[]' | cut -d '-' -f2 | anew -q $1/osint/h8mail.txt
PWNDB_STATUS=$(timeout 15s curl -Is --socks5-hostname localhost:9050 http://pwndb2am4tzkvold.onion | grep HTTP | cut -d ' ' -f2)
if [ "$PWNDB_STATUS" = 200 ]; then
	cd ~/Tools/pwndb
	python3 pwndb.py --target "@${1}" | sed '/^[-]/d' | anew -q $1/osint/passwords.txt
	cd ~/bugbounty/recon
	sed -r -i "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" $1/osint/passwords.txt
	sed -i '1,2d' $1/osint/passwords.txt
else
	text="${yellow}\n pwndb is currently down :(\n\n Check xjypo5vzgmo7jca6b322dnqbsdnp3amd24ybx26x5nxbusccjkm4pwid.onion${reset}\n"
fi

# Domain Information Gathering (whois, registrant name/email domains)
lynx -dump "https://domainbigdata.com/$1" | tail -n +19 > $1/osint/domain_info_general.txt
if [ -s "$1/osint/domain_info_general.txt" ]; then
	cat $1/osint/domain_info_general.txt | grep '/nj/' | tr -s ' ' ',' | cut -d ',' -f3 > $1/osint/domain_registrant_name.txt
	cat $1/osint/domain_info_general.txt | grep '/mj/' | tr -s ' ' ',' | cut -d ',' -f3 > $1/osint/domain_registrant_email.txt
	cat $1/osint/domain_info_general.txt | grep -E "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | grep "https://domainbigdata.com" | tr -s ' ' ',' | cut -d ',' -f3 > $1/osint/domain_registrant_ip.txt
fi
sed -i -n '/Copyright/q;p' $1/osint/domain_info_general.txt
if [ -s "$1/osint/domain_registrant_name.txt" ]; then
	for line in $(cat $1/osint/domain_registrant_name.txt); do
		lynx -dump $line | tail -n +18 | sed -n '/]domainbigdata.com/q;p' >> $1/osint/domain_info_name.txt && echo -e "\n\n#######################################################################\n\n" >> $1/osint/domain_info_name.txt
	done
fi
if [ -s "$1/osint/domain_registrant_email.txt" ]; then
	for line in $(cat $1/osint/domain_registrant_email.txt); do
		lynx -dump $line | tail -n +18 | sed -n '/]domainbigdata.com/q;p'  >> $1/osint/domain_info_email.txt && echo -e "\n\n#######################################################################\n\n" >> $1/osint/domain_info_email.txt
	done
fi
if [ -s "$1/osint/domain_registrant_ip.txt" ]; then
	for line in $(cat $1/osint/domain_registrant_ip.txt); do
		lynx -dump $line | tail -n +18 | sed -n '/]domainbigdata.com/q;p'  >> $1/osint/domain_info_ip.txt && echo -e "\n\n#######################################################################\n\n" >> $1/osint/domain_info_ip.txt
	done
fi

end=$SECONDS
echo ">>> script duration: $((end-start)) seconds."
