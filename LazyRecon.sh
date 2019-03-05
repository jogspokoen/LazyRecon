#!/bin/bash

VERSION="1.3"

TARGET=$1

WORKING_DIR="/opt/lazy_recon"
TOOLS_PATH="$WORKING_DIR/tools"
WORDLIST_PATH="$WORKING_DIR/wordlists"
RESULTS_PATH="$WORKING_DIR/results/$TARGET"
SUB_PATH="$RESULTS_PATH/subdomain"
CORS_PATH="$RESULTS_PATH/cors"
IP_PATH="$RESULTS_PATH/ip"
PSCAN_PATH="$RESULTS_PATH/portscan"
SSHOT_PATH="$RESULTS_PATH/screenshot"
DIR_PATH="$RESULTS_PATH/directory"
SLURP_PATH="$RESULTS_PATH/slurp"
SHODAN_PATH="$RESULTS_PATH/shodan"

RED="\033[1;31m"
GREEN="\033[1;32m"
BLUE="\033[1;36m"
YELLOW="\033[1;33m"
RESET="\033[0m"

displayLogo(){
echo -e "
██╗      █████╗ ███████╗██╗   ██╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██║     ██╔══██╗╚══███╔╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██║     ███████║  ███╔╝  ╚████╔╝ ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██║     ██╔══██║ ███╔╝    ╚██╔╝  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
███████╗██║  ██║███████╗   ██║   ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══  
${RED}v$VERSION${RESET} by ${YELLOW}@CaptMeelo${RESET}
"
}


checkArgs(){
    if [[ $# -eq 0 ]]; then
        echo -e "${RED}[+] Usage:${RESET} $0 <domain>\n"
        exit 1
    fi
}


runBanner(){
    name=$1
    echo -e "${RED}\n[+] Running $name...${RESET}"
}


setupDir(){
    echo -e "${GREEN}--==[ Setting things up ]==--${RESET}"
    echo -e "${RED}\n[+] Creating results directories...${RESET}"
    rm -rf $RESULTS_PATH
    mkdir -p $SUB_PATH $CORS_PATH $IP_PATH $PSCAN_PATH $SSHOT_PATH $DIR_PATH $SLURP_PATH $SHODAN_PATH
    echo -e "${BLUE}[*] $SUB_PATH${RESET}"
    echo -e "${BLUE}[*] $CORS_PATH${RESET}"
    echo -e "${BLUE}[*] $IP_PATH${RESET}"
    echo -e "${BLUE}[*] $PSCAN_PATH${RESET}"
    echo -e "${BLUE}[*] $SSHOT_PATH${RESET}"
    echo -e "${BLUE}[*] $DIR_PATH${RESET}"
    echo -e "${BLUE}[*] $SLURP_PATH${RESET}"
    echo -e "${BLUE}[*] $SHODAN_PATH${RESET}"
}


enumSubs(){
    echo -e "${GREEN}\n--==[ Enumerating subdomains ]==--${RESET}"
    runBanner "Amass"
    ~/go/bin/amass -d $TARGET -o $SUB_PATH/amass.txt

    runBanner "subfinder"
    #~/go/bin/subfinder -w $WORDLIST_PATH/dns_all.txt -d $TARGET -t 50 -b  $TARGET -nW --silent -o $SUB_PATH/subfinder.txt
    ~/go/bin/subfinder -w $WORDLIST_PATH/dns_10k.txt -d $TARGET -t 50 -b  $TARGET -nW --silent -o $SUB_PATH/subfinder.txt

    echo -e "${RED}\n[+] Combining subdomains...${RESET}"
    cat $SUB_PATH/*.txt | sort | awk '{print tolower($0)}' | uniq > $SUB_PATH/final-subdomains.txt
    echo -e "${BLUE}[*] Check the list of subdomains at $SUB_PATH/final-subdomains.txt${RESET}"

    echo -e "${GREEN}\n--==[ Checking for subdomain takeovers ]==--${RESET}"
    runBanner "subjack"
    ~/go/bin/subjack -a -ssl -t 50 -v -c ~/go/src/github.com/haccer/subjack/fingerprints.json -w $SUB_PATH/final-subdomains.txt -o $SUB_PATH/final-takeover.tmp
    cat $SUB_PATH/final-takeover.tmp | grep -v "Not Vulnerable" > $SUB_PATH/final-takeover.txt
    rm $SUB_PATH/final-takeover.tmp
    echo -e "${BLUE}[*] Check subjack's result at $SUB_PATH/final-takeover.txt${RESET}"
}


corsScan(){
    echo -e "${GREEN}\n--==[ Checking CORS configuration ]==--${RESET}"
    runBanner "CORScanner"
    python $TOOLS_PATH/CORScanner/cors_scan.py -v -t 50 -i $SUB_PATH/final-subdomains.txt | tee $CORS_PATH/final-cors.txt
    echo -e "${BLUE}[*] Check the result at $CORS_PATH/final-cors.txt${RESET}"
}


enumIPs(){
    echo -e "${GREEN}\n--==[ Resolving IP addresses ]==--${RESET}"
    runBanner "massdns"
    $TOOLS_PATH/massdns/bin/massdns -r $TOOLS_PATH/massdns/lists/resolvers.txt -q -t A -o S -w $IP_PATH/massdns.raw $SUB_PATH/final-subdomains.txt
    cat $IP_PATH/massdns.raw | grep -e ' A ' |  cut -d 'A' -f 2 | tr -d ' ' > $IP_PATH/massdns.txt
    cat $IP_PATH/*.txt | sort -V | uniq > $IP_PATH/final-ips.txt
    echo -e "${BLUE}[*] Check the list of IP addresses at $IP_PATH/final-ips.txt${RESET}"
}


portScan(){
    echo -e "${GREEN}\n--==[ Port-scanning targets ]==--${RESET}"
    runBanner "masscan"
    sudo $TOOLS_PATH/masscan/bin/masscan -p 1-65535 --rate 10000 --wait 0 --open -iL $IP_PATH/final-ips.txt -oX $PSCAN_PATH/masscan.xml
    xsltproc -o $PSCAN_PATH/final-masscan.html $TOOLS_PATH/nmap-bootstrap.xsl $PSCAN_PATH/masscan.xml
    open_ports=$(cat $PSCAN_PATH/masscan.xml | grep portid | cut -d "\"" -f 10 | sort -n | uniq | paste -sd,)
    echo -e "${BLUE}[*] Masscan Done! View the HTML report at $PSCAN_PATH/final-masscan.html${RESET}"

    runBanner "nmap"
    nmap -sVC -p $open_ports --open -v -T4 -Pn -iL $SUB_PATH/final-subdomains.txt -oX $PSCAN_PATH/nmap.xml
    xsltproc -o $PSCAN_PATH/final-nmap.html $PSCAN_PATH/nmap.xml
    echo -e "${BLUE}[*] Nmap Done! View the HTML report at $PSCAN_PATH/final-nmap.html${RESET}"

    nmap --script http-git2 -p 80,443,8008,8080,8000,9000,5000 -Pn -iL $SUB_PATH/final-subdomains.txt -oX $RESULTS_PATH/nmap-git.xml
    echo -e "${BLUE}[*] Nmap Done! View the HTML report at $RESULTS_PATH/nmap-git.xml${RESET}"
}


visualRecon(){
    echo -e "${GREEN}\n--==[ Taking screenshots ]==--${RESET}"
    runBanner "aquatone"
    cat $SUB_PATH/final-subdomains.txt | ~/go/bin/aquatone -http-timeout 10000 -scan-timeout 300 -ports xlarge -out $SSHOT_PATH/aquatone/
    echo -e "${BLUE}[*] Check the result at $SSHOT_PATH/aquatone/aquatone_report.html${RESET}"
}


bruteDir(){
    echo -e "${GREEN}\n--==[ Bruteforcing directories ]==--${RESET}"
    runBanner "dirsearch"
    echo -e "${BLUE}[*]Creating output directory...${RESET}"
    mkdir -p $DIR_PATH/dirsearch
    for url in $(cat $SSHOT_PATH/aquatone/aquatone_urls.txt); do
        fqdn=$(echo $url | sed -e 's;https\?://;;' | sed -e 's;/.*$;;')
        $TOOLS_PATH/dirsearch/dirsearch.py -b -t 100 -e php,asp,aspx,jsp,html,zip,jar,sql -x 500,503 -r -w $WORDLIST_PATH/fuzz.txt -u $url --plain-text-report=$DIR_PATH/dirsearch/$fqdn.tmp
        if [ ! -s $DIR_PATH/dirsearch/$fqdn.tmp ]; then
            rm $DIR_PATH/dirsearch/$fqdn.tmp
        else
            cat $DIR_PATH/dirsearch/$fqdn.tmp | sort -k 1 -n > $DIR_PATH/dirsearch/$fqdn.txt
            rm $DIR_PATH/dirsearch/$fqdn.tmp
        fi
    done
    echo -e "${BLUE}[*] Check the results at $DIR_PATH/dirsearch/${RESET}"
}

slurp(){
    echo -e "${GREEN}\n--==[ slurp for S3 buckets ]==--${RESET}"
    runBanner "slurp"
    slurp domain --permutations /root/amass/permutations.json -t $TARGET 2>&1 |  grep -vi 'FORBIDDEN' > $SLURP_PATH/slurp.txt
    echo -e "${BLUE}[*] Check the results at $SLURP_PATH/slurp.txt/${RESET}"
}
shodan(){
    echo -e "${GREEN}\n--==[ executing shodan host search ]==--${RESET}"
    runBanner "Shodan"
    for $ip in $(cat $IP_PATH/final-ips.txt); do
        /usr/local/bin/shodan host $ip >> $SHODAN_PATH/shodan.txt;
        echo "\n====\n" >> $SHODAN_PATH/shodan.txt
    done
    
    echo -e "${BLUE}[*] Check the results at $SHODAN_PATH/shodan.txt${RESET}"
}


# Main function
displayLogo
checkArgs $TARGET
setupDir
enumSubs
corsScan
enumIPs
portScan
visualRecon
bruteDir
# slurp
# shodan

echo -e "${GREEN}\n--==[ DONE ]==--${RESET}"
