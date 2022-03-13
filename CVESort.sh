#!/bin/bash

# Print usage message
function printUsage () {
	echo "USAGE: ./CVEScore.sh <Path/to/csv>" 
}

# Check for correct number of arguments
if [ "$#" -ne 1 ]; then
	    echo "Illegal number of parameters"
	    printUsage
	    exit 1
fi

# Gets the corresponding score from nist website
function getScore () {
	SCORE=$(curl -s https://nvd.nist.gov/vuln/detail/$1 | grep "Base Score" | cut -d "/" -f 3 | grep cvssv3 | cut -d ";" -f 6 | cut -d " " -f 1)
}

# Patch to csv
CSV_PATH="$1"

# Parse csv to array
CVE=()
CVE=$(cat $1 | cut -d "," -f 1)

# Delete old outputfile if present
if test -f "$PWD/CVEScoreOut.csv"; then
	rm -f CVEScoreOut.csv
fi

# Get scores and write new csv file
for i in ${CVE[@]}; do
	getScore $i
	
	size=${#SCORE}
	if [[ $size < 1 ]]; then
		SCORE="NO cvssv3 score available yet"
	else
		SCORE=$(echo $SCORE | tr -s '\n' ' ' | cut -d " " -f 1) 
		SCORE="$SCORE"
	fi   

	#echo "Checking $1: $SCORE"	
	echo "$i;$SCORE" >> CVEScoreOut.csv
done

