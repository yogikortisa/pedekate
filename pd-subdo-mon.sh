#First Run (just one time at first time)
#subfinder -silent -dL input/domains.txt | anew input/subs.txt

#Second Run
while true; do subfinder -dL input/domains.txt -all | anew input/subs.txt | httpx | nuclei -t /root/nuclei-templates/ | notify ; sleep 3600; done
