start=$SECONDS
mkdir $1
mkdir $1/nembak
mkdir $1/nembak/fuzzing
mkdir $1/nembak/js
mkdir $1/nembak/portscan

echo "# subdomain takeover"
cat $1/pdkt/sub_web.txt | nuclei -t ~/nuclei-templates/takeovers/ -r resolvers.txt -o $1/nembak/nuclei_subdomain_takeover.txt

echo "# cloud enumeration"
s3scanner scan -f $1/pdkt/subdomains.txt | grep -iv "not_exist" | grep -iv "Warning:" | anew $1/nembak/s3bucket_results.txt
keyword=$(echo $1 | cut -f1 -d".")
python3 ~/Tools/cloud_enum/cloud_enum.py -k $keyword -k $1 -qs -l $1/nembak/cloud_enum.txt
cat $1/nembak/cloud_enum.txt | sed '/^#/d' | sed '/^$/d' > $1/nembak/cloud_results.txt

echo "# favicon enumeration"
cd ~/Tools/fav-up
python3 favUp.py -w $1 -sc -o favicon.json
cat favicon.json | jq -r '.found_ips' | grep -v "not-found" > favicon.txt
sed -i "s/|/\n/g" favicon.txt
mv favicon.txt ~/bugbounty/recon/$1/nembak/favicon.txt
rm -f favicon.json 
cd ~/bugbounty/recon

echo "# port scanning"
resolveDomains -d $1/pdkt/subdomains.txt -t 120 | anew -q $1/nembak/sub_ip.txt
awk '{ print $2 " " $1}' $1/nembak/sub_ip.txt | sort -k2 -n | anew -q $1/nembak/sub_ip_vhost.txt
cat $1/nembak/sub_ip_vhost.txt | cut -d ' ' -f1 | grep -Eiv "^(127|10|169\.154|172\.1[6789]|172\.2[0-9]|172\.3[01]|192\.168)\." | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | anew -q $1/nembak/ip.txt
cat $1/nembak/ip.txt | cf-check | grep -Eiv "^(127|10|169\.154|172\.1[6789]|172\.2[0-9]|172\.3[01]|192\.168)\." | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | anew -q $1/nembak/ip_nowaf.txt
cat $1/nembak/ip_nowaf.txt | sort
for sub in $(cat $1/nembak/ip.txt); do
	shodan host $sub >> $1/nembak/portscan/portscan_passive.txt && echo -e "\n\n#######################################################################\n\n" >> $1/nembak/portscan/portscan_passive.txt
done
sudo nmap --top-ports 200 -sV -n --max-retries 2 -Pn --open -iL $1/nembak/ip_nowaf.txt -oN $1/nembak/portscan/portscan_active.txt -oG $1/nembak/portscan/portscan_active.gnmap

echo "# vulnerability scanning with nuclei"
cat $1/pdkt/sub_web.txt $1/pdkt/sub_web_common.txt | anew -q $1/nembak/allwebs.txt
cat $1/nembak/allwebs.txt | nuclei -t ~/nuclei-templates/ -severity critical -r resolvers.txt -o $1/nembak/nuclei_critical.txt
cat $1/nembak/allwebs.txt | nuclei -t ~/nuclei-templates/ -severity high -r resolvers.txt -o $1/nembak/nuclei_high.txt
cat $1/nembak/allwebs.txt | nuclei -t ~/nuclei-templates/ -severity medium -r resolvers.txt -o $1/nembak/nuclei_medium.txt
cat $1/nembak/allwebs.txt | nuclei -t ~/nuclei-templates/ -severity low -r resolvers.txt -o $1/nembak/nuclei_low.txt
cat $1/nembak/allwebs.txt | nuclei -t ~/nuclei-templates/ -severity info -r resolvers.txt -o $1/nembak/nuclei_info.txt

echo "# fuzzing for content discovery"
interlace -tL $1/nembak/allwebs.txt -threads 10 -c "ffuf -mc all -mc 200 -ac -t 100 -w wordlist/content-discovery/OneListForAll/onelistforall.txt -u  _target_/FUZZ -of csv -o _output_/_cleantarget_.csv" -o $1/nembak/fuzzing
for sub in $(cat $1/nembak/allwebs.txt); do
	sub_out=$(echo $sub | sed -e 's|^[^/]*//||' -e 's|/.*$||')
	cat $1/nembak/fuzzing/${sub_out}.csv | cut -d ',' -f2,5,6 | tr ',' ' ' | awk '{ print $2 " " $3 " " $1}' | tail -n +2 | sort -k1 | anew -q $1/nembak/fuzzing/${sub_out}.txt
	rm -f $1/nembak/fuzzing/${sub_out}.csv 
done

echo "# extract URL & endpoints"
cat $1/nembak/allwebs.txt | waybackurls | anew -q $1/nembak/urls.txt
cat $1/nembak/allwebs.txt | gauplus -t 25 -subs | anew -q $1/nembak/urls.txt
gospider -S $1/nembak/allwebs.txt --js -t 20 -d 2 --sitemap --robots -w -r > $1/nembak/gospider.txt
sed -i '/^.\{2048\}./d' $1/nembak/gospider.txt
cat $1/nembak/gospider.txt | grep -Eo 'https?://[^ ]+' | sed 's/]$//' | grep ".$domain" | anew -q $1/nembak/urls.txt
github-endpoints -q -k -d $1 -t $GITHUB_TOKEN -o $1/nembak/github-endpoints.txt
cat $1/nembak/github-endpoints.txt | anew -q $1/nembak/urls.txt
cat $1/nembak/urls.txt | grep "$1" | grep -Ei "\.(js)" | anew -q $1/nembak/js/urls_js.txt
cat $1/nembak/urls.txt | grep "$1" | grep "=" | qsreplace -a | grep -Eiv "\.(eot|jpg|jpeg|gif|css|tif|tiff|png|ttf|otf|woff|woff2|ico|pdf|svg|txt|js)$" | anew -q $1/nembak/urls2.txt
cat $1/nembak/urls2.txt | urldedupe -s -qs | anew -q $1/nembak/urls_uddup.txt
cat $1/nembak/urls_uddup.txt | anew -q $1/nembak/urls_extract.txt 

echo "# grep vulnerabilities pattern endpoints with GF"
mkdir $1/nembak/gf
gf xss $1/nembak/urls_extract.txt | anew -q $1/nembak/gf/xss.txt
gf ssti $1/nembak/urls_extract.txt | anew -q $1/nembak/gf/ssti.txt
gf ssrf $1/nembak/urls_extract.txt | anew -q $1/nembak/gf/ssrf.txt
gf sqli $1/nembak/urls_extract.txt | anew -q $1/nembak/gf/sqli.txt
gf redirect $1/nembak/urls_extract.txt | anew -q $1/nembak/gf/redirect.txt
cat $1/nembak/gf/ssrf.txt | anew -q $1/nembak/gf/redirect.txt
gf rce $1/nembak/urls_extract.txt | anew -q $1/nembak/gf/rce.txt
gf potential $1/nembak/urls_extract.txt | cut -d ':' -f3-5 | anew -q $1/nembak/gf/potential.txt
cat $1/nembak/urls.txt | grep -Eiv "\.(eot|jpg|jpeg|gif|css|tif|tiff|png|ttf|otf|woff|woff2|ico|pdf|svg|txt|js)$" | unfurl -u format %s://%d%p | anew -q $1/nembak/gf/endpoints.txt
gf lfi $1/nembak/urls_extract.txt | anew -q $1/nembak/gf/lfi.txt

echo "# grep juicy extension in URLs"
ext=("7z" "achee" "action" "adr" "apk" "arj" "ascx" "asmx" "asp" "aspx" "axd" "backup" "bak" "bat" "bin" "bkf" "bkp" "bok" "cab" "cer" "cfg" "cfm" "cfml" "cgi" "cnf" "conf" "config" "cpl" "crt" "csr" "csv" "dat" "db" "dbf" "deb" "dmg" "dmp" "doc" "docx" "drv" "email" "eml" "emlx" "env" "exe" "gadget" "gz" "html" "ica" "inf" "ini" "iso" "jar" "java" "jhtml" "json" "jsp" "key" "log" "lst" "mai" "mbox" "mbx" "md" "mdb" "msg" "msi" "nsf" "ods" "oft" "old" "ora" "ost" "pac" "passwd" "pcf" "pdf" "pem" "pgp" "php" "php3" "php4" "php5" "phtm" "phtml" "pkg" "pl" "plist" "pst" "pwd" "py" "rar" "rb" "rdp" "reg" "rpm" "rtf" "sav" "sh" "shtm" "shtml" "skr" "sql" "swf" "sys" "tar" "tar.gz" "tmp" "toast" "tpl" "txt" "url" "vcd" "vcf" "wml" "wpd" "wsdl" "wsf" "xls" "xlsm" "xlsx" "xml" "xsd" "yaml" "yml" "z" "zip")
for t in "${ext[@]}"; do
	NUMOFLINES=$(cat $1/nembak/urls.txt | grep -Ei "\.(${t})($|\/|\?)" | sort -u | wc -l)
	if [[ ${NUMOFLINES} -gt 0 ]]; then
		echo -e "\n############################\n + ${t} + \n############################\n" >> $1/nembak/urls_ext.txt
		cat $1/nembak/urls.txt | grep -Ei "\.(${t})($|\/|\?)" | anew -q > $1/nembak/urls_ext.txt
	fi
done

echo "# javascript analysis"
cat $1/nembak/js/urls_js.txt | cut -d '?' -f 1 | grep -iE "\.js$" | grep "$1$" | anew -q $1/nembak/js/js_links.txt
cat $1/nembak/js/urls_js.txt | subjs | grep "$1$" | anew -q $1/nembak/js/js_links.txt
cat $1/nembak/js/js_links.txt | httpx -follow-redirects -random-agent -silent -threads 10 -status-code -retries 2 -no-color | grep "[200]" | cut -d ' ' -f1 | anew -q $1/nembak/js/js_livelinks.txt
interlace -tL $1/nembak/js/js_livelinks.txt -threads 10 -c "python3 ~/Tools/LinkFinder/linkfinder.py -d -i _target_ -o cli >> $1/nembak/js/js_endpoints_tmp.txt"	
sed -i '/^\//!d' $1/nembak/js/js_endpoints_tmp.txt
cat $1/nembak/js/js_endpoints_tmp.txt | anew -q $js/js_endpoints.txt
cat $1/nembak/js/js_livelinks.txt | nuclei -silent -t ~/nuclei-templates/exposures/tokens/ -r resolvers.txt -o $1/nembak/js/js_secrets.txt
cat $1/nembak/js/js_livelinks.txt | python3 ~/Tools/getjswords.py | anew -q $1/nembak/dict_words.txt

echo "# generate custom wordlists"
cat $1/nembak/urls.txt | unfurl -u keys | sed 's/[][]//g' | sed 's/[#]//g' | sed 's/[}{]//g' | anew -q $1/nembak/dict_params.txt
cat $1/nembak/urls.txt | unfurl -u values | sed 's/[][]//g' | sed 's/[#]//g' | sed 's/[}{]//g' | anew -q $1/nembak/dict_values.txt
cat $1/nembak/urls.txt | tr "[:punct:]" "\n" | anew -q $1/nembak/dict_words.txt
cat $1/nembak/js/js_endpoints.txt | unfurl -u format %s://%d%p | anew -q $1/nembak/all_paths.txt
cat $1/nembak/urls.txt | unfurl -u format %s://%d%p | anew -q $1/nembak/all_paths.txt

end=$SECONDS
echo ">>> script duration: $((end-start)) seconds."
