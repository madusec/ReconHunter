#!/bin/bash

G='\033[1;32m'
R='\033[1;31m'
NC='\033[0m'

if [ "$#" -ne 4 ]; then
  echo -e "You must run the tool like that: ${G}$0 Domain_Name Github_User Censys_API_ID Censys_API_Secret${NC}"
  exit 0
fi

Domain=$1
User=$2
API_ID=$3
API_Secret=$4

echo -e "Target Domain: ${G}$Domain${NC}"
echo -e "Github Username: ${G}$User${NC}"
export GOPATH=$PWD/Tools/gotools
rm -rf Tools SubDomains_Discovery SubDomains_Scanning IP_Scanning Github_Scanning Cloud_Scanning
mkdir Tools SubDomains_Discovery SubDomains_Scanning IP_Scanning Github_Scanning Cloud_Scanning

echo -e "${G}########## Running Step 1 ##########${NC}"

echo -e "${R}Running Sonar Project...${NC}"
go get github.com/cgboal/sonarsearch/crobat > /dev/null 2>&1
Tools/gotools/bin/crobat -s $Domain > SubDomains_Discovery/Sonar_Project.txt

echo -e "${R}Running Amass...${NC}"
go get -v github.com/OWASP/Amass/v3/... > /dev/null 2>&1
Tools/gotools/bin/amass enum -passive -d $Domain > SubDomains_Discovery/Amass.txt

echo -e "${R}Running Subfinder...${NC}"
GO111MODULE=on go get -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder > /dev/null 2>&1
Tools/gotools/bin/subfinder -silent -d $Domain > SubDomains_Discovery/Subfinder.txt

echo -e "${R}Combining the Result (Sonar Project, Amass, Subfinder)...${NC}"
cat SubDomains_Discovery/*.txt | sort -n | uniq > SubDomains_Discovery/Passive_Subdomains.txt

echo -e "${R}Running Subdomains Resolving...${NC}"
go get github.com/OJ/gobuster/v3@latest > /dev/null 2>&1
cat SubDomains_Discovery/Passive_Subdomains.txt | sed "s/.$Domain//g" > tmp
Tools/gotools/bin/gobuster dns -d $Domain -t 10 -w tmp -o tmp1 -q > /dev/null 2>&1
cat tmp1 | cut -d " " -f 2 > SubDomains_Discovery/Resolved_Passive-Subdomains.txt
rm -f tmp tmp1

echo -e "${R}Running Brute Force...${NC}"
wget https://raw.githubusercontent.com/OWASP/Amass/master/examples/wordlists/subdomains.lst -O SubDomains_Discovery/Wordlist_BruteForce.txt -q
Tools/gotools/bin/gobuster dns -d $Domain -t 10 -w SubDomains_Discovery/Wordlist_BruteForce.txt -o tmp -q > /dev/null 2>&1
cat tmp | cut -d " " -f 2 > SubDomains_Discovery/Resolved_BruteForce.txt
rm -f tmp

echo -e "${R}Combining the Result (Passive, BruteForce)...${NC}"
cat SubDomains_Discovery/Resolved_Passive-Subdomains.txt SubDomains_Discovery/Resolved_BruteForce.txt | sort -n | uniq > SubDomains_Discovery/Final_Resolved_Subdomains.txt

#echo "Remove Wildcard..."
#cat 4_all_resolved.txt | while read line; do if [[ $(dig *.$line +short) ]]; then echo $line >> wildcard.txt ;fi; done
#cat 4_all_resolved.txt wildcard.txt 2> /dev/null | sort -n | uniq -u > 4_all_resolved_no_wildcard.txt

#echo -e "${R}Running Altdns...${NC}"
#python2 -m pip install py-altdns
#python2 $(which altdns) -i 4_all_resolved_no_wildcard.txt -o tmp -w words.txt
#cat tmp | sed "s/.$Domain//g" > tmp1
#rm tmp
#Tools/gotools/bin/gobuster dns -d $Domain -t 10 -w tmp1 -o tmp -q
#cat tmp | cut -d " " -f 2 > 5_resolved_altdns.txt
#rm tmp tmp1

#echo -e "${R}Combining the Result...${NC}"
#cat 5_resolved_altdns.txt 4_all_resolved.txt 2> /dev/null | sort -n | uniq > 4_full_resolved.txt

echo -e "${G}########## Running Step 2 ##########${NC}"

echo -e "${R}Running Subdomains Takeover...${NC}"
go get github.com/Ice3man543/SubOver > /dev/null 2>&1
wget https://raw.githubusercontent.com/Ice3man543/SubOver/master/providers.json -q
cat SubDomains_Discovery/Passive_Subdomains.txt SubDomains_Discovery/Final_Resolved_Subdomains.txt | sort -n | uniq > SubDomains_Scanning/Test_Takeover.txt
Tools/gotools/bin/SubOver -l SubDomains_Scanning/Test_Takeover.txt | tee -a SubDomains_Scanning/Result_Takeover.txt
mv providers.json SubDomains_Scanning/Providers.json

echo -e "${R}Running Screenshot Process...${NC}"
GO111MODULE=on go get -v github.com/projectdiscovery/httpx/cmd/httpx > /dev/null 2>&1
cat SubDomains_Discovery/Final_Resolved_Subdomains.txt | Tools/gotools/bin/httpx -title -tech-detect -status-code -title -follow-redirects -threads 5 -timeout 10 | tee -a SubDomains_Scanning/Screenshots.txt

echo -e "${G}########## Running Step 3 ##########${NC}"

echo -e "${R}Running IP Resolving...${NC}"
for line in $(cat SubDomains_Discovery/Final_Resolved_Subdomains.txt); do
host $line | grep "has address" | grep $Domain >> IP_Scanning/IP.txt
done
cat IP.txt | cut -d " " -f 4 | sort -n | uniq > IP_Scanning/Resolved_IPs.txt
echo "Total IP:" $(wc -l IP_Scanning/Resolved_IPs.txt)
rm IP_Scanning/IP.txt

python2 -m pip install censys-command-line > /dev/null 2>&1
echo -e "${R}Running Censys Scan...${NC}"
censys --censys_api_id $API_ID --censys_api_secret $API_Secret --query_type ipv4 "443.https.tls.certificate.parsed.subject.common_name:$Domain or 443.https.tls.certificate.parsed.names:$Domain or 443.https.tls.certificate.parsed.extensions.subject_alt_name.dns_names:$Domain or 443.https.tls.certificate.parsed.subject_dn:$Domain" --fields ip protocols --append false > IP_Scanning/Censys_Result.txt
cat IP_Scanning/Censys_Result.txt | grep ip | cut -d '"' -f 4 | sort -n | uniq > IP_Scanning/Censys_IPs.txt
echo "Total IP:" $(wc -l IP_Scanning/Censys_IPs.txt)

echo -e "${R}Combining the Result (Resolved IPs, Censys IPs)...${NC}"
cat IP_Scanning/Resolved_IPs.txt IP_Scanning/Censys_IPs.txt | sort -n | uniq > IP_Scanning/Final_IPs.txt
echo "Total IP:" $(wc -l IP_Scanning/Final_IPs.txt)

if [[ -z $(which nmap Tools/nmap/nmap) ]]; then
cd Tools
git clone https://github.com/nmap/nmap > /dev/null 2>&1
echo "Installing nmap..."
cd nmap
./configure > /dev/null 2>&1 && make > /dev/null 2>&1
cd ../..
fi
export PATH=$PATH:$PWD/Tools/nmap

echo -e "${R}Running Port Scanning...${NC}"
nmap -iL IP_Scanning/Final_IPs.txt -Pn -p U:53,123,161,T:21,22,23,25,80,110,139,389,443,445,3306,3389 --open -oG IP_Scanning/Result.gnmap > /dev/null 2>&1

cat IP_Scanning/Result.gnmap | grep Ports: | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}|[0-9]+/[a-z]+\|*[a-z]+/[a-z]+" > IP_Scanning/Summary.txt

echo -e "${R}Running the Summary Version...${NC}"
cat IP_Scanning/summary.txt | while read line; do if [[ $line != *"open"* ]]; then echo ""; echo -e "${G}$line${NC}"; else echo $line;fi; done

echo -e "${G}########## Running Step 4 ##########${NC}"

echo -e "${R}Running Github Recon...${NC}"
cd Github_Scanning
# Find the repos owned by the target organization (not forked)
# then clone these repos locally
curl -s https://api.github.com/users/$User/repos | grep 'full_name\|fork"' \
| cut -d " " -f6 | cut -d "/" -f2 | cut -d '"' -f1 | cut -d "," -f1 | \
while read line1; do read line2; echo $line1 $line2; done | \
grep false | cut -d " " -f1 | while read repo;
do echo "Downloading" $repo; git clone https://github.com/$User/$repo > /dev/null 2>&1; done

# check if there is not repository to search
if ! [[ $(find . -type d) == "." ]]; then
# Find sensitive data inside repos using git
for i in ./*/; do
cd $i
git log -p > Commits.txt
cat Commits.txt | grep "api\|key\|user\|uname\|pw\|pass\|mail\|credential\|login\|token\|secret" > ../"$i"_Secrets.txt
cd ..
done
# Find sensitive data inside repos using trufflehog
python3 -m pip install truffleHog > /dev/null 2>&1
for i in ./*/; do
trufflehog --entropy=False --regex $i >> Trufflehog_Secrets.txt;
done
cd ..
fi

echo -e "${G}########## Running Step 6 ##########${NC}"

echo -e "${R}Running Cloud Recon...${NC}"
cd Tools
git clone https://github.com/gwen001/s3-buckets-finder
cd ../Cloud_Scanning
# Download wordlist then apply permutations on it
wget -q https://raw.githubusercontent.com/nahamsec/lazys3/master/common_bucket_prefixes.txt -O Common_Bucket_Prefixes.txt
domain=$(echo $Domain | cut -d "." -f1)
for i in $(cat Common_Bucket_Prefixes.txt); do
for word in {dev,development,stage,s3,staging,prod,production,test}; do
echo $domain-$i-$word >> AWS_Wordlist.txt
echo $domain-$i.$word >> AWS_Wordlist.txt
echo $domain-$i$word >> AWS_Wordlist.txt
echo $domain.$i$word >> AWS_Wordlist.txt
echo $domain.$i-$word >> AWS_Wordlist.txt
echo $domain.$i.$word >> AWS_Wordlist.txt
done; done

# Start the brute force
cd ../Tools/s3-buckets-finder
php s3-buckets-bruteforcer.php --bucket ../../Cloud_Scanning/AWS_Wordlist.txt --verbosity 1
cd ../../
