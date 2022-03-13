#!/bin/bash

# Purpose: Add cvss score to CISA exploited vulnerability catalog
# Author: Indeedion
# Source: https://github.com/indeedion/CVESort
# Contact: mengus00@gmail.com
# Usage: ./CVESort.sh, takes no arguments

# print welcome
echo "CVESort 1.0, downloads CISA exploited vulnerabilities catalog and adds cvss scores to file for
easier sorting and overview"

# Gets the corresponding score from nist website
function getScore () {
	SCORE=$(curl -s https://nvd.nist.gov/vuln/detail/$1 | grep "Base Score" | cut -d "/" -f 3 | grep cvssv3 | cut -d ";" -f 6 | cut -d " " -f 1)
}

# Path to csv
CSV_PATH="known_exploited_vulnerabilities.csv"

# Remove old CSV and download new one
if test -f "$CSV_PATH"; then
    rm -f $CSV_PATH
fi
echo "Downloading catalog from CISA.."
wget https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv

#Check that download went well
if ! test -f "$CSV_PATH"; then
    echo "CSV file not found!"
    exit 1
fi
echo "Download OK"

# Parse CVE's to array
CVE=()
CVE=$(cat $CSV_PATH | cut -d "," -f 1)

# Delete old temporary outputfile if present
if test -f "tmpout"; then
    rm -f tmpout
fi

echo "Getting cvss and building new file.."
# loop through csv line by line, get cvss score from nist and create new file
c=0
while read i; do
    if [[ $c == 0 ]]; then	
	line="$i"
	first=$(echo $line | cut -d "," -f 1)
	rest=$(echo $line | cut -d "," -f 2,3,4,5,6,7,8)
	result="$cve,"CVSS3",$rest"
	echo $result >> tmpout
    else
	line="$i"
	cve=$(echo $line | cut -d "," -f 1)
	rest=$(echo $line | cut -d "," -f 2,3,4,5,6,7,8)
	getScore $cve
	size=${#SCORE}
	if [[ $size < 1 ]]; then
		SCORE="NO cvssv3 score available yet"
	else
		SCORE=$(echo $SCORE | tr -s '\n' ' ' | cut -d " " -f 1) 
	fi   
	result="$cve,$SCORE,$rest"
	echo $result
	echo $result >> tmpout
    fi
    (( ++c ))
done < $CSV_PATH

#Replace old file with new
rm -f $CSV_PATH && mv tmpout "$CSV_PATH"

echo "Done!"

