start=$SECONDS

echo "# create target directory"
mkdir $1
mkdir $1/pdkt

echo "### PASSIVE SUBDOMAIN ENUMERATION ###" 
echo "# amass & subfinder subdomain enumeration"
amass enum --passive -d $1 -o $1/amass_pass.txt
subfinder -d $1 -all -o $1/subfinder_pass.txt

echo "# crawl subdomain from internet archives"
timeout 10m gauplus -t 5 -random-agent -subs $1 | unfurl -u domains > $1/gauplus_pass.txt

echo "# crawl subdomain from wayback machine"
timeout 10m waybackurls $1 | unfurl -u domains | sort -u > $1/waybackurls_pass.txt

echo "# extract subdomain from Github"
github-subdomains -d $1 -o $1/github_pass.txt

echo "# get subdomain from Project Sonar Rapid7"
crobat -s $1 > $1/crobat_pass.txt

echo "# check certificate logs transparancy from crt.sh & bufferover.run"
curl -s -k "https://tls.bufferover.run/dns?q=.$1" | jq -r .Results[] | cut -d ',' -f3 | grep -F ".$1" > $1/tls_bufferoverun_pass.txt
curl -s -k "https://dns.bufferover.run/dns?q=.$1" | jq -r '.FDNS_A'[],'.RDNS'[]  | cut -d ',' -f2 | grep -F ".$1" > $1/dns_bufferoverun_pass.txt
python3 ctfr/ctfr.py -d $1 -o $1/ctfr_pass.txt

echo "# oneliner for check from anubis resources"
curl -s -k "https://jldc.me/anubis/subdomains/$1" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sed '/^\./d' > $1/anubis_pass.txt

echo "### ACTIVE SUBDOMAIN ENUMERATION ###"
echo "# generate fresh public DNS resolvers"
rm resolvers.txt
dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 100 -o resolvers.txt

echo "# merge & resolve all passive subdomain"
cat $1/*_pass.txt | anew $1/sub_passive.txt
puredns resolve $1/sub_passive.txt -r resolvers.txt -w $1/sub_passive_act.txt 

echo "# subdomain bruteforcing"
puredns bruteforce wordlist/sub-bruteforce/best-dns-wordlist.txt $1 -r resolvers.txt -w $1/sub_bruteforce_act.txt

echo "# COMBINE all active hosts to subdomains.txt"
cat $1/*_act.txt | uniq | anew $1/subdomains.txt

echo "# subdomain permutation/alteration"
gotator -sub $1/subdomains.txt -perm wordlist/sub-permut-alter/permut-by-six2dez.txt -depth 1 -md | uniq > $1/sub_permutation.txt
puredns resolve $1/sub_permutation.txt -r resolvers.txt -w $1/sub_permutation_act.txt

echo "# merge all active subdomains"
cat $1/*_act.txt | uniq | anew $1/subdomains.txt

echo "# scraping subdomain from all web probed"
cat $1/subdomains.txt | httpx -random-agent -retries 2 -no-color -o $1/sub_web.txt
gospider -S $1/sub_web.txt --js -t 50 -d 3 --sitemap --robots -w -r > $1/sub_gospider.txt
sed -i '/^.\{2048\}./d' $1/sub_gospider.txt
cat $1/sub_gospider.txt | grep -Eo 'https?://[^ ]+' | sed 's/]$//' | unfurl -u domains | grep ".$1$" | sort -u > $1/sub_scrap.txt
puredns resolve $1/sub_scrap.txt -w $1/sub_scrap_act.txt -r resolvers.txt 
cat $1/sub_scrap_act.txt | anew $1/subdomains.txt

echo "# get common port of web host"
COMMON_PORTS_WEB="81,300,591,593,832,981,1010,1311,1099,2082,2095,2096,2480,3000,3128,3333,4243,4567,4711,4712,4993,5000,5104,5108,5280,5281,5601,5800,6543,7000,7001,7396,7474,8000,8001,8008,8014,8042,8060,8069,8080,8081,8083,8088,8090,8091,8095,8118,8123,8172,8181,8222,8243,8280,8281,8333,8337,8443,8500,8834,8880,8888,8983,9000,9001,9043,9060,9080,9090,9091,9200,9443,9502,9800,9981,10000,10250,11371,12443,15672,16080,17778,18091,18092,20720,32000,55440,55672"
unimap --fast-scan -f $1/subdomains.txt --ports $COMMON_PORTS_WEB -q -k --url-output > $1/unimap_common.txt
cat $1/unimap_common.txt | httpx -random-agent -status-code -silent -retries 2 -no-color | cut -d ' ' -f1 | tee $1/sub_web_common.txt

echo "# web screenshoting"
cat $1/sub_web.txt $1/sub_web_common.txt | aquatone -chrome-path /snap/bin/chromium -out $1/aquatone

mv $1/subdomains.txt $1/sub_web.txt $1/sub_web_common.txt $1/pdkt

end=$SECONDS
echo ">>> script duration: $((end-start)) seconds."
