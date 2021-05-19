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

echo -e "${G}########## Running Step 1 ##########${NC}"

mkdir gotools > /dev/null 2>&1
export GOPATH=$PWD/gotools

echo -e "${R}Running Crobat...${NC}"
go get github.com/cgboal/sonarsearch/crobat > /dev/null 2>&1
gotools/bin/crobat -s $Domain > 1_passive_domains.txt

echo -e "${R}Running Amass...${NC}"
go get -v github.com/OWASP/Amass/v3/... > /dev/null 2>&1
gotools/bin/amass enum -passive -d $Domain >> 1_passive_domains.txt

echo -e "${R}Running Subfinder...${NC}"
GO111MODULE=on go get -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder > /dev/null 2>&1
gotools/bin/subfinder -silent -d $Domain >> 1_passive_domains.txt

echo -e "${R}Combining the Result...${NC}"
cat 1_passive_domains.txt | sort -n | uniq > tmp
mv tmp 1_passive_domains.txt
#cat 1_passive_domains.txt

echo -e "${R}Running Resolving...${NC}"
go get github.com/OJ/gobuster/v3@latest > /dev/null 2>&1
cat 1_passive_domains.txt | sed "s/.$Domain//g" > tmp
gotools/bin/gobuster dns -d $Domain -t 10 -w tmp -o tmp1 -q
cat tmp1 | cut -d " " -f 2 > 2_resolved_passive_domains.txt
rm tmp tmp1

echo -e "${G}########## Running Step 2 ##########${NC}"

echo -e "${R}Running Brute Force...${NC}"
wget https://raw.githubusercontent.com/OWASP/Amass/master/examples/wordlists/subdomains.lst -O words.txt -q
gotools/bin/gobuster dns -d $Domain -t 10 -w words.txt -o tmp -q
cat tmp | cut -d " " -f 2 > 3_resolved_brute_force.txt
rm tmp

echo -e "${R}Combining the Result...${NC}"
cat 3_resolved_brute_force.txt 2_resolved_passive_domains.txt | sort -n | uniq > 4_all_resolved.txt
#cat 4_all_resolved.txt

# Remove Wildcard Domains
cat 4_all_resolved.txt | while read line; do if [[ $(dig *.$line +short) ]]; then echo $line >> tmp ;fi; done
cat 4_all_resolved.txt tmp | sort -n | uniq -u > 4_all_resolved_no_wildcard.txt
rm -f tmp

#python2 -m pip install py-altdns
#echo -e "${R}Running Altdns...${NC}"
#python2 $(which altdns) -i 4_all_resolved_no_wildcard.txt -o tmp -w words.txt
#cat tmp | sed "s/.$Domain//g" > tmp1
#rm tmp
#gotools/bin/gobuster dns -d $Domain -t 10 -w tmp1 -o tmp -q
#cat tmp | cut -d " " -f 2 > 5_resolved_altdns.txt
#rm tmp tmp1

echo -e "${R}Combining the Result...${NC}"
cat 5_resolved_altdns.txt 4_all_resolved.txt | sort -n | uniq > tmp > /dev/null 2>&1
mv tmp 4_all_resolved.txt
#cat 4_all_resolved.txt

echo -e "${G}########## Running Step 3 ##########${NC}"

echo -e "${R}Running Sub-Domains Takeover...${NC}"
go get github.com/Ice3man543/SubOver > /dev/null 2>&1
wget https://raw.githubusercontent.com/Ice3man543/SubOver/master/providers.json -q
cat 1_passive_domains.txt 4_all_resolved.txt | sort -n | uniq > tmp
gotools/bin/SubOver -l tmp
rm tmp providers.json

if [[ -z $(which nmap nmap/nmap) ]]; then
git clone https://github.com/nmap/nmap > /dev/null 2>&1
echo "Installing nmap..."
cd nmap
./configure > /dev/null 2>&1 && make > /dev/null 2>&1
cd ..
fi
export PATH=$PATH:$PWD/nmap

echo -e "${R}Running Screenshot Process...${NC}"
GO111MODULE=on go get -v github.com/projectdiscovery/httpx/cmd/httpx > /dev/null 2>&1
gotools/bin/httpx -title -tech-detect -status-code -title -follow-redirects -threads 5 -timeout 10

echo -e "${G}########## Running Step 4 ##########${NC}"

echo -e "${R}Running IP Resolving...${NC}"
rm -f IP.txt
for line in $(cat 4_all_resolved.txt); do
host $line | grep "has address" | grep $Domain >> IP.txt
done
cat IP.txt | cut -d " " -f 4 | sort -n | uniq > Full_IP.txt
#cat Full_IP.txt
echo "Total IP:" $(wc -l Full_IP.txt)

python2 -m pip install censys-command-line > /dev/null 2>&1
echo -e "${R}Running Censys Scan...${NC}"
censys --censys_api_id $API_ID --censys_api_secret $API_Secret --query_type ipv4 "443.https.tls.certificate.parsed.subject.common_name:$Domain or 443.https.tls.certificate.parsed.names:$Domain or 443.https.tls.certificate.parsed.extensions.subject_alt_name.dns_names:$Domain or 443.https.tls.certificate.parsed.subject_dn:$Domain" --fields ip protocols --append false > censys_result.txt
cat censys_result.txt | grep ip | cut -d '"' -f 4 | sort -n | uniq > censys_IP.txt
#cat censys_IP.txt
echo "Total IP:" $(wc -l censys_IP.txt)

echo -e "${R}Combining the Result...${NC}"
cat Full_IP.txt censys_IP.txt | sort -n | uniq > All_IP.txt
#cat All_IP.txt
echo "Total IP:" $(wc -l All_IP.txt)

# UDP scan needs root privilege -sU
echo -e "${R}Running Port Scanning...${NC}"
nmap -iL All_IP.txt -Pn -p U:53,123,161,T:21,22,23,25,80,110,139,389,443,445,3306,3389 --open -oG result.gnmap > /dev/null 2>&1

cat result.gnmap | grep Ports: | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}|[0-9]+/[a-z]+\|*[a-z]+/[a-z]+" > summary.txt

echo -e "${R}Running the Summary Version...${NC}"
#cat summary.txt | while read line; do if [[ $line != *"open"* ]]; then echo ""; echo -e "${G}$line${NC}"; else echo $line;fi; done

echo -e "${G}########## Running Step 5 ##########${NC}"

echo -e "${R}Running Github Recon...${NC}"
rm -rf github_dirs
mkdir github_dirs
cd github_dirs
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
git log -p > commits.txt
cat commits.txt | grep "api\|key\|user\|uname\|pw\|pass\|mail\|credential\|login\|token\|secret" > secrets.txt
cd ..
done
# Find sensitive data inside repos using trufflehog
rm -f othersecrets.txt
for i in ./*/; do
python3 -m pip install truffleHog > /dev/null 2>&1
trufflehog --entropy=False --regex $i >> othersecrets.txt;
done
cd ..
fi

echo -e "${G}########## Running Step 6 ##########${NC}"

#echo -e "${R}Running Cloud Recon...${NC}"
#git clone https://github.com/gwen001/s3-buckets-finder
#cd s3-buckets-finder
## Download wordlist then apply permutations on it
#wget -q https://raw.githubusercontent.com/nahamsec/lazys3/master/common_bucket_prefixes.txt -O common_bucket_prefixes.txt
#domain=$(echo $Domain | cut -d "." -f1)
#rm -f res.txt
#for i in $(cat common_bucket_prefixes.txt); do
#for word in {dev,development,stage,s3,staging,prod,production,test}; do
#echo $domain-$i-$word >> res.txt
#echo $domain-$i.$word >> res.txt
#echo $domain-$i$word >> res.txt
#echo $domain.$i$word >> res.txt
#echo $domain.$i-$word >> res.txt
#echo $domain.$i.$word >> res.txt
#done; done

## Start the brute force
#php s3-buckets-bruteforcer.php --bucket res.txt --verbosity 1
#cd ..
