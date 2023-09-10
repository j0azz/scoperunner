#!/bin/bash

# Check if an argument was provided
if [ $# -ne 1 ]; then
    echo "Usage: $0 <directory_path>"
    exit 1
fi

directory_path="$1"

# Use ls to list the files in the specified directory
# Note: You can customize the ls command options as needed
# For example, to list only files and not directories, use: ls -p | grep -v /
files_list=$(ls "$directory_path")
echo "Listing $directory_path. . ."
echo "" > lists.txt
for file in $files_list; do
    echo "$directory_path/$file" >> lists.txt
done

