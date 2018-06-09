#!/bin/bash
# checkblocks.sh
# Make sure the daemon is not stuck.
# Add the following to the crontab (i.e. sudo crontab -e)
# */30 * * * * ~/.bhash/checkdaemon.sh

previousBlock=$(cat ~/.bhash/blockcount)
currentBlock=$(bhash-cli getblockcount)

bhash-cli getblockcount > ~/.bhash/blockcount

if [ "$previousBlock" == "$currentBlock" ]; then
  sudo systemctl restart bhashd
fi