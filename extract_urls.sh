#!/bin/bash


if [ $# -eq 0 ]; then
    paramspider -l scope
    cat results/* >> selected-urls.txt;
else if [ $# -eq 1 ]; then   
    paramspider -d $1;
    cat results/* >> selected-urls.txt;
    else
        echo "run against 'scope' file: bash extract_urls.sh"
        echo "run against single URL: bash extract_urls.sh <url>"
    fi
fi