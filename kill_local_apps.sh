#!/bin/bash
set -e

FILES=./tmp/pids/*.pid
for f in $FILES; do
  echo "Killing $f"
  kill $(cat $f)
  rm -f $f
done
