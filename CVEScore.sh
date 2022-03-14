#!/bin/bash

SCORE=$(curl -s https://nvd.nist.gov/vuln/detail/$1 | grep "Base Score" | cut -d "/" -f 3 | grep cvssv3 | cut -d ";" -f 6 | cut -d " " -f 1)

size=${#SCORE}

if [[ $size < 1 ]]; then
	echo "N/A"
else
	SCORE=$(echo $SCORE | tr -s '\n' ' ' | cut -d " " -f 1)
	echo "$SCORE"
fi
