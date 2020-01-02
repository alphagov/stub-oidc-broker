#!/usr/bin/env bash
set -e

  if [ -f "./tmp/pids/broker1.pid" ]; then
    echo "Killing broker1"
    kill "$(< ./tmp/pids/broker1.pid)"
    rm -f ./tmp/pids/broker1.pid
  fi
