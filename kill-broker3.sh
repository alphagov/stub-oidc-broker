#!/usr/bin/env bash
set -e

  if [ -f "./tmp/pids/broker3.pid" ]; then
    echo "Killing broker3"
    kill "$(< ./tmp/pids/broker3.pid)" || true
    rm -f ./tmp/pids/broker3.pid
  fi
