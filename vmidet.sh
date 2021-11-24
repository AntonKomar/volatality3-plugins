#!/bin/sh

if [ ! -d "volatility3" ]; then
  echo "Error: ${volatility_dir} not found. Cannot continue."
  exit 1  
fi

if [ -z "$1" ]
    then
        echo "No VM name argument supplied!"
        exit 1
fi

if [ -z "$2" ]
  then
    echo "No time-interval argument supplied!"
    exit 1
fi

name=$1
time_interval=$2
FILE=/mnt/mem

if [ ! -f "$FILE" ]; then
    vmifs name $name /mnt
fi

python3 volatility3/vol.py -f $FILE linux.netcon --time $time_interval

