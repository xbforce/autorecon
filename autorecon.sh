#!/usr/bin/bash


#####################################
# Description
#####################################
# ! autorecon automates tools and techniques to find subdomains.
# ! Users need to make a file containing inscope domains. The Usage would be:
# - kali@kali# ./autorecon inscope_domains.txt

# ! Also users are able to make a list of outscope subdomains to dictate the tool
# ! to exclude those outscope subs. In this case the usage would be:
# - kali@kali# ./autorecon inscope_domains.txt outscope_subdomains.txt


#####################################
# Coding Guideline
#####################################
# ! Separate names by underscore and do not use camelCase.
# ! If names start with some digits separate digits and names with
# hyphen "-", e.g: 01-amass_domain.txt
# ! Do not use abbreviations unless it is clear for anybody without programming knowledge!
# ! Indentation is four spaces.
# ! Use double "[[square brackets]]" for "if" statements.
# ! Put a space between ";" and "then" in if statements.
# ! Put a space between ";" and "do" in for loops.
# ! Use printf instead of echo.
# ! Comments about if, while, for, functions etc should be inside them and not above them.
# ! If you want to comment a line of code temporarily and uncomment it after doing
# some tests, use double sharps "##", single "#" should be used for permanent comments.





function tput_func {
# COLORIZING OUTPUTS
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
POWDER_BLUE=$(tput setaf 153)
BLUE=$(tput setaf 4)
NORMAL=$(tput sgr0)
}
tput_func



timestamp() {
# CURRENT TIME
    date +"%m"/"%d"/"%y"-"%T"
}




if [[ -z "$1" ]]; then
    printf "${POWDER_BLUE}~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~${NORMAL}\n"
    printf "${POWDER_BLUE}               _          _____                      
    /\        | |        |  __ \                     
   /  \  _   _| |_ ___   | |__) |___  ___ ___  _ __  
  / /\ \| | | | __/ _ \  |  _  // _ \/ __/ _ \| '_ \ 
 / ____ \ |_| | || (_) | | | \ \  __/ (_| (_) | | | |
/_/    \_\__,_|\__\___/  |_|  \_\___|\___\___/|_| |_|
${NORMAL}\n"
    printf "${POWDER_BLUE}Twitter: @xbforce	https://github.com/xbforce${NORMAL}\n"
    printf "${POWDER_BLUE}~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~${NORMAL}\n\n"
    # HELP
    printf "${YELLOW}[*]${NORMAL} autorecon automates tools and techniques to find subdomains.\n"
    printf "${YELLOW}[*]${NORMAL} To find all subdomains:\n"
	printf "${YELLOW}[*]${NORMAL} Usage: $0 inscope_domains.txt\n"
    printf "${YELLOW}[*]${NORMAL} To exclude outscope domains:\n"
    printf "${YELLOW}[*]${NORMAL} Usage: $0 inscope_domains.txt outscope_subdomains.txt\n"
	exit 0
fi



exit_code=$!
inscope=$1
outscope=$2



# READ A WORDLIST FROM XBFORCE's GITHUB PAGE.
##subdomain_list=$(curl --silent --url "https://raw.githubusercontent.com/xbforce/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt")
##subdomain_list=$(cat /home/kali/lists/subdomains-top1million-5000.txt)



#################################
# BANNER
#################################
printf "${POWDER_BLUE}~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~${NORMAL}\n"
printf "${POWDER_BLUE}               _          _____                      
    /\        | |        |  __ \                     
   /  \  _   _| |_ ___   | |__) |___  ___ ___  _ __  
  / /\ \| | | | __/ _ \  |  _  // _ \/ __/ _ \| '_ \ 
 / ____ \ |_| | || (_) | | | \ \  __/ (_| (_) | | | |
/_/    \_\__,_|\__\___/  |_|  \_\___|\___\___/|_| |_|
${NORMAL}\n"
printf "${POWDER_BLUE}Twitter: @xbforce	https://github.com/xbforce${NORMAL}\n"
printf "${POWDER_BLUE}~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~${NORMAL}\n\n"

printf "${YELLOW}[!] Depend on the number of inscope domains gathering information may take some \nminutes or some hours, take care of your other jobs while autorecon is running!${NORMAL}\n"
printf "${YELLOW}[!] The output will be saved in '"$inscope""_domains"' directory.${NORMAL}\n"
#################################




printf "\n\nStart at: "
timestamp
printf "\n"



if [[ -d "$inscope""_domains" ]]; then
    touch "$inscope""_domains"/newsubs.txt.bak1
    touch "$inscope""_domains"/newsubs.txt

    touch "$inscope""_domains"/newalives.txt.bak1
    touch "$inscope""_domains"/newalives.txt
    #
    cat "$inscope""_domains"/newsubs.txt >> "$inscope""_domains"/newsubs.txt.bak1
    cat "$inscope""_domains"/newalives.txt >> "$inscope""_domains"/newalives.txt.bak1
    printf "" > "$inscope""_domains"/newsubs.txt
    printf "" > "$inscope""_domains"/newalives.txt
else
    :
fi



for r in $(cat $1); do
    if [[ ! -d "$inscope""_domains" ]]; then
        mkdir "$inscope""_domains" && cd "$inscope""_domains" && mkdir $r && cd $r
    else
        cd "$inscope""_domains"
        if [[ ! -d $r ]]; then
            mkdir $r && cd $r
        else
            cd $r
        fi
    fi



    target_header=$(printf "\n${POWDER_BLUE}************************${NORMAL} "
    printf "${POWDER_BLUE}$r${NORMAL} "
    printf "${POWDER_BLUE}************************${NORMAL}\n"
    timestamp)
    printf "$target_header\n"



    amass_enum=$(amass enum --passive -d $r) &&
    printf '%s\n' "${amass_enum[@]}" > 01-amass_$r.sub &&
    wordcount_amass=$(wc -l < 01-amass_$r.sub)
    if [[ $wordcount_amass == 0 ]]; then
        printf "${RED}[-] ${NORMAL}Not found any subdomain via amass.\n"
    else
        printf "${GREEN}[+] ${NORMAL}Found $wordcount_amass subdomains via amass.\n"
    fi

    sub_finder=$(subfinder -silent -d $r | tee 02-subfinder_$r.sub)
    wordcount_subfinder=$(wc -l < 02-subfinder_$r.sub)
    if [[ $wordcount_subfinder == 0 ]]; then
        printf "${RED}[-] ${NORMAL}Not found any subdomain via subfinder.\n"
    else
        printf "${GREEN}[+] ${NORMAL}Found $wordcount_subfinder subdomains via subfinder.\n"
    fi

    sub_lister=$(sublist3r -d $r -o tmp_sublister_$r.sub &&
    # sed command replaces all "<BR>" characters in the file with a new line.
    cat tmp_sublister_$r.sub | sed 's/<BR>/\n/g' | tee 03-sublister_$r.sub &&
    rm tmp_sublister_$r.sub)
    wordcount_sublister=$(wc -l < 03-sublister_$r.sub)
    if [[ $wordcount_sublister == 0 ]]; then
        printf "${RED}[-] ${NORMAL}Not found any subdomain via sublist3r.\n"
    else
        printf "${GREEN}[+] ${NORMAL}Found $wordcount_sublister subdomains via sublist3r.\n"
    fi

    asset_finder=$(assetfinder -subs-only $r | tee 04-assetfinder_$r.sub)
    wordcount_assetfinder=$(wc -l < 04-assetfinder_$r.sub)
    if [[ $wordcount_assetfinder == 0 ]]; then
        printf "${RED}[-] ${NORMAL}Not found any subdomain via assetfinder.\n"
    else
        printf "${GREEN}[+] ${NORMAL}Found $wordcount_assetfinder subdomains via assetfinder.\n"
    fi



    # GRAB SUBDOMAINS FROM crt.sh
    curl_crt=$(curl -L --silent --max-time 180 --url "https://crt.sh/?q=$r" | grep "<TD>" | grep -v "=" | sed 's/ //g' | sed 's/<\<BR\>>/\n/g' | sed -E -e 's/[</TD>]//g' | sed 's/[*]//' | sed 's/^[.]//' | sed '/^[[:space:]]*$/d' | grep $r > tmp_crt_results_$r.sub &&
    # It can contain some subdomains that are missed in the above command:
    curl -L --silent --max-time 180 --url "https://crt.sh/?q=$r" | grep "<BR>" | sed 's/ //g' | sed 's/<\<BR\>>/\n/g' | sed -E -e 's/[</TD>]//g' | sed 's/[*]//' | sed 's/^[.]//' | sed '/^[[:space:]]*$/d' | grep $r | sort -u -d >> tmp_crt_results_$r.sub &&
    sort -u -d tmp_crt_results_$r.sub > 05-crt_results_$r.sub) &&
    wordcount_tmp_cert=$(wc -l < tmp_crt_results_$r.sub)
    rm tmp_crt_results_$r.sub
    #
    if [[ $wordcount_tmp_cert == 0 ]] || [[ -z $wordcount_tmp_cert ]]; then
        :
    else
        wordcount_cert=$(wc -l < 05-crt_results_$r.sub)
    fi
    #
    if [[ $wordcount_cert == 0 ]] || [[ -z $wordcount_cert ]]; then
        printf "${RED}[-] ${NORMAL}Not found any subdomain via crt.sh\n"
##        printf "${GREEN}[+] ${NORMAL}Brute force starts...\n"
    else
        printf "${GREEN}[+] ${NORMAL}Found $wordcount_cert subdomains via crt.sh\n"
##        printf "${GREEN}[+] ${NORMAL}Brute force starts...\n"
    fi


    function deactive_bf {
    # BRUTEFORCE THE TARGET FOR SUBDOMAINS.
    bruteforce=$(for word in $(cat $random_list); do
        host $word.$r | grep "has address" | cut -d" " -f1 | sort -u &
    done > 06-bruteforce_$r.sub) &&
    wordcount_bruteforce=$(wc -l < 06-bruteforce_$r.sub)
    if [[ $wordcount_bruteforce == 0 ]]; then
        printf "${RED}[-] ${NORMAL}Not found any subdomain via brute forcing.\n"

    else
        printf "${GREEN}[+] ${NORMAL}Found $wordcount_bruteforce subdomains via brute forcing.\n"

    fi
    }


    # ZONE TRANSFER
    zone_transfer=$(for server in $(host -t ns $r | cut -d " " -f4); do
        host -l $r $server | grep "has address" | cut -d " " -f1
    done > 07-zone_transfer_$r.sub) &&
    wordcount_zonetransfer=$(wc -l < 07-zone_transfer_$r.sub)
    if [[ $wordcount_zonetransfer == 0 ]]; then
        printf "${RED}[-] ${NORMAL}Not found any subdomain via zone transfer.\n"
    else
        printf "${GREEN}[+] ${NORMAL}Found $wordcount_zonetransfer subdomains via zone transfer.\n"
    fi



    # CHECK IF THE OUTSCOPE FILE EXIST.
    outscope_check=$(if [[ -f "$2" ]]; then
        # grep command excludes all subdomains.
        sort_subs_one=$(sort -u -d *.sub | grep -vxF -f ../../$2 | sort -u -d > 08-unique_subs_$r.txt)
        wordcount_08_unique=$(wc -l < 08-unique_subs_$r.txt)
        if [[ $wordcount_08_unique == 0 ]]; then
            printf "${RED}[-] ${NORMAL}There is no unique subdomain.\n"
        else
            printf "${GREEN}[+] ${NORMAL}There are $wordcount_08_unique unique subdomains.\n"
        fi
    else
        sort_subs_two=$(sort -u -d *.sub > 08-unique_subs_$r.txt)
        wordcount_08_unique_two=$(wc -l < 08-unique_subs_$r.txt)
        if [[ $wordcount_08_unique_two == 0 ]]; then
            printf "${RED}[-] ${NORMAL}There is no unique subdomain.\n"
        else
            printf "${GREEN}[+] ${NORMAL}There are $wordcount_08_unique_two unique subdomains.\n"
        fi
    fi)



    # REMOVE UNNECESSARY FILES.
    rm 01-amass_$r.sub
    rm 02-subfinder_$r.sub
    rm 03-sublister_$r.sub
    rm 04-assetfinder_$r.sub
    rm 05-crt_results_$r.sub
##    rm 06-bruteforce_$r.sub
    rm 07-zone_transfer_$r.sub



#####################################
# CHECK ALIVE SUBDOMAINS
#####################################

    if [[ -d report_$r ]]; then
        :
    else
        mkdir report_$r
    fi
    #
    if [[ -f report_$r/alive_subdomains_$r.txt ]]; then
        cat report_$r/alive_subdomains_$r.txt | sed 's/https:\/\///' | sed 's/http:\/\///' > tmp_alive_subs_$r.txt
    else
        touch report_$r/alive_subdomains_$r.txt
        cat report_$r/alive_subdomains_$r.txt | sed 's/https:\/\///' | sed 's/http:\/\///' > tmp_alive_subs_$r.txt
    fi

    # TAKE OUT THOSE SUBS WHICH ARE NOT IN alive_subdomains_$r.txt
    grep -a -vxFf tmp_alive_subs_$r.txt 08-unique_subs_$r.txt > 08-tmp_unique_without_alive_$r.txt



    httpx_one=$(httpx -silent -l 08-tmp_unique_without_alive_$r.txt >> 09-httpx_$r.txt) & PIDIOS=$!
    wait $PIDIOS


    sleep 5
    wordcount_09_httpx=$(wc -l < 09-httpx_$r.txt)
    if [[ $wordcount_09_httpx == 0 ]]; then
        printf "${RED}[-] ${NORMAL}Not found any alive subdomain via httpx.\n"
    else
        printf "${GREEN}[+] ${NORMAL}Found $wordcount_09_httpx alive subdomains via httpx.\n"
    fi



################################
# GENERATE REPORTS
################################

    cat 08-unique_subs_$r.txt > report_$r/unique_subdomains_$r.txt
    #
    if [[ -n $wordcount_09_httpulse ]]; then
        num_alive_httpulse_one=$(($wordcount_09_httpulse))
    else
        num_alive_httpulse_one=$(("0"))
    fi
    #
    num_alive_httpx_one=$(($wordcount_09_httpx))
    num_subs_in_src_codes_one=$(($wordcount_11_source_codes))

    append_to_report_wordcount=$(printf "\n${GREEN}************************ $r ************************${NORMAL}\n" > report_$r/full_report_$r.txt)
    printf "amass:		$wordcount_amass\n" >> report_$r/full_report_$r.txt
    printf "subfinder:	$wordcount_subfinder\n" >> report_$r/full_report_$r.txt
    printf "sublist3r:	$wordcount_sublister\n" >> report_$r/full_report_$r.txt
    printf "assetfinder:	$wordcount_assetfinder\n" >> report_$r/full_report_$r.txt
    #
    if [[ $wordcount_cert == 0 ]] || [[ -z $wordcount_cert ]]; then
        printf "cert.sh:	0\n" >> report_$r/full_report_$r.txt
    else
        printf "cert.sh:	$wordcount_cert\n" >> report_$r/full_report_$r.txt
    fi
    #
##    printf "bruteforce:	$wordcount_bruteforce\n" >> report_$r/full_report_$r.txt
    printf "zoneTransfer:	$wordcount_zonetransfer\n" >> report_$r/full_report_$r.txt
    printf "httpx:		$num_alive_httpx_one\n" >> report_$r/full_report_$r.txt
    num_unique_one=$(wc -l < report_$r/unique_subdomains_$r.txt)
    printf "Total number of unique subdomains:$num_unique_one\n" >> report_$r/full_report_$r.txt
    #
    cat 09-httpx_$r.txt >> report_$r/alive_subdomains_$r.txt
    sort -u report_$r/alive_subdomains_$r.txt | sponge report_$r/alive_subdomains_$r.txt
    printf "Total number of alive subdomains: $num_alive_httpx_one\n\n" >> report_$r/full_report_$r.txt



#####################################
# SEND NEW SUBDOMAINS TO newsubs.txt
#####################################

    if [[ -f report_$r/all_subdomains_$r.txt ]]; then
        append_to_report_newsubs_one=$(printf "\n${GREEN}************************ NEW SUBDOMAINS ************************${NORMAL}\n" >> report_$r/full_report_$r.txt)
        grep -a -vxFf report_$r/all_subdomains_$r.txt report_$r/unique_subdomains_$r.txt >> report_$r/full_report_$r.txt
        #
        grep -a -vxFf report_$r/all_subdomains_$r.txt report_$r/unique_subdomains_$r.txt | tee -a report_$r/all_subdomains_$r.txt >> ../newsubs.txt
    #
    else
        touch report_$r/all_subdomains_$r.txt
        append_to_report_newsubs_one=$(printf "\n${GREEN}************************ NEW SUBDOMAINS ************************${NORMAL}\n" >> report_$r/full_report_$r.txt)
        grep -a -vxFf report_$r/all_subdomains_$r.txt report_$r/unique_subdomains_$r.txt >> report_$r/full_report_$r.txt
        #
        grep -a -vxFf report_$r/all_subdomains_$r.txt report_$r/unique_subdomains_$r.txt | tee -a report_$r/all_subdomains_$r.txt >> ../newsubs.txt
    fi
    #
    sort -u -d report_$r/all_subdomains_$r.txt | sponge report_$r/all_subdomains_$r.txt
    #

    cat 09-httpx_$r.txt >> ../newalives.txt



###########################
# REMOVE UNNECESSARY FILES.
###########################

    rm 09-httpx_$r.txt
    #
    rm 08-unique_subs_$r.txt
    rm 08-tmp_unique_without_alive_$r.txt
    rm tmp_alive_subs_$r.txt
    #

    cd ../../



done



printf ""
printf "\nFinished at: "
timestamp
printf "\n"



wait $exit_code

#Written: 01-March-2020
#Author: Bardiya Xhorshidi
