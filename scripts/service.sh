#!/usr/bin/env bash
set -e

start_service() {
  local servicename="$1"
  local directory="$2"
  local log="logs/${servicename}_console.log"

  LOGS_DIR=./logs
  if [ ! -d $LOGS_DIR ]; then
    echo -e 'Creating LOGs directory\n'
    mkdir -p $LOGS_DIR
  fi

  startscriptname="startup-${servicename}.sh"
  killscriptname="kill-${servicename}.sh"
  currentdirectory=${PWD}

  pushd ../${directory} > /dev/null

  if [ -f "./tmp/pids/${servicename}.pid" ]; then
  echo -e "About to kill ${servicename} before starting again"
  $(pwd)/${killscriptname}
  fi
  $(pwd)/${startscriptname} >"${currentdirectory}/$log" 2>&1
  echo -e "Starting ${servicename}\n"
  popd > /dev/null
}

