#!/usr/bin/env bash
set -e

  if [ -f "./tmp/pids/broker2.pid" ]; then
    echo "Killing broker2"
    kill "$(< ./tmp/pids/broker2.pid)" || true
    rm -f ./tmp/pids/broker2.pid
  fi
