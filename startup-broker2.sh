#!/usr/bin/env bash
set -e

CONFIG_FILE=./stub-oidc-broker.yml

cd "$(dirname "$0")"

LOCAL_IP="$(ipconfig getifaddr en0)"
export REDIS_URI="redis://${LOCAL_IP}:6380"
export APPLICATION_PORT=5510
export STUB_BROKER_URI=http://localhost:5510
export ADMIN_PORT=5511
export IDP_URI=http://localhost:3334
export SCHEME=2
export BRANDING=public
log="logs/broker2_console.log"

./gradlew installDist

  CID=$(docker ps -q -f status=running -f name=clientRedis)
  if [ ! "${CID}" ]; then
      echo "Starting client redis"
      docker run --name clientRedis -d -p 6380:6379 --rm redis
  fi

  LOGS_DIR=./logs
  if [ ! -d $LOGS_DIR ]; then
    echo -e 'Creating LOGs directory\n'
    mkdir -p $LOGS_DIR
  fi

  if [ -f "./tmp/pids/broker2.pid" ]; then
      echo -e "About to kill broker2 before starting again"
      $(pwd)/kill-broker2.sh
  fi

  PID_DIR=./tmp/pids
  if [ ! -d $PID_DIR ]; then
      echo -e 'Creating PIDs directory\n'
      mkdir -p $PID_DIR
  fi

./build/install/stub-oidc-broker/bin/stub-oidc-broker server $CONFIG_FILE &
  echo $! > ./tmp/pids/broker2.pid

echo "Outputting to ${log}"
