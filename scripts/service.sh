#!/usr/bin/env bash
set -e

check_if_dependencies_are_installed() {
  if ! command -v java >/dev/null 2>&1
  then
    echo "You must install 'java' to run this script" >&2
    exit 1
  elif ! command -v python3 >/dev/null 2>&1
  then
    echo "You must install 'python3' to run this script" >&2
    exit 1
  elif ! command -v ruby >/dev/null 2>&1
  then
    echo "You must install 'ruby' to run this script" >&2
    exit 1
  elif ! command -v node >/dev/null 2>&1
  then
    echo "You must install 'node' to run this script" >&2
    exit 1
  fi
}

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

  if [ ! -d  ../${directory} ]; then
      echo "${directory} does not exist. Use the clone-trustframework-repos.sh to clone the required repos"
      echo "Stopping start-up"
      exit 1
  else
      pushd ../${directory} > /dev/null

      if [ -f "./tmp/pids/${servicename}.pid" ]; then
        echo -e "About to kill ${servicename} before starting again"
        $(pwd)/${killscriptname}
      fi

      $(pwd)/${startscriptname} >"${currentdirectory}/$log" 2>&1
      echo -e "Starting ${servicename}\n"
      popd > /dev/null
  fi
}

