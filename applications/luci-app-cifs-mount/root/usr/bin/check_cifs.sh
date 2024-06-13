#!/bin/sh

filename=$(basename -- "$0")

if [ $# -lt 1 ] ; then
  echo "usage: $filename [device URL]"
  exit 1;
fi

device="$1"

echo "mount cifs ${device}"

sleep 3;

mounted=$( cat /proc/mounts | grep "${device}" )
if [ -z "${mounted}" ]; then
    echo "${device} not mounted, try again."
    service cifs start
    exit 1;
else
    echo "${device} already mounted"
fi
