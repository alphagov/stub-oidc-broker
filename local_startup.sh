#!/bin/bash
set -e

PID_DIR=./tmp/pids
if [ ! -d $PID_DIR ]; then
  echo 'Creating PIDs directory'
  mkdir -p $PID_DIR
fi

if [ -f ./tmp/pids/broker-1.pid ] && [ `ps -p $(cat ./tmp/pids/broker-1.pid)` ]; then
  echo 'Broker 1 is already running'
else
  echo 'Starting Broker 1'
  ./startup-broker-1.sh &
  echo $! > ./tmp/pids/broker-1.pid
fi
if [ -f ./tmp/pids/broker-2.pid ] && [ `ps -p $(cat ./tmp/pids/broker-2.pid)` ]; then
  echo 'Broker 2 is already running'
else
  echo 'Starting Broker 2'
  ./startup-broker-2.sh &
  echo $! > ./tmp/pids/broker-2.pid
fi

cd ../trust-framework-directory-prototype
if [ -f ./tmp/pids/directory.pid ] && [ `ps -p $(cat ./tmp/pids/directory.pid)` ]; then
  echo 'Directory is already running'
else
  echo 'Starting the Directory'
  ./startup.sh &
  echo $! > ./../stub-oidc-broker/tmp/pids/directory.pid
fi

cd ../middleware-in-the-middle
if [ -f ./tmp/pids/initiator.pid ] && [ `ps -p $(cat ./tmp/pids/initiator.pid)` ]; then
  echo 'Initiator is already running'
else
  echo 'Starting the initiator'
  ./run-local-initiator.sh &
  echo $! > ./../stub-oidc-broker/tmp/pids/initiator.pid
fi
if [ -f ./tmp/pids/receiver.pid ] && [ `ps -p $(cat ./tmp/pids/receiver.pid)` ]; then
  echo 'Receiver is already running'
else
  echo 'Starting the receiver'
  ./run-local-receiver.sh &
  echo $! > ./../stub-oidc-broker/tmp/pids/receiver.pid
fi

cd ../trust-framework-idp
if [ -f ./tmp/pids/idp-1.pid ] && [ `ps -p $(cat ./tmp/pids/idp-1.pid)` ]; then
  echo 'IDP 1 is already running'
else
  echo 'Starting the IDP 1'
  ./startup-1.sh &
  echo $! > ./../stub-oidc-broker/tmp/pids/idp-1.pid
fi
if [ -f ./tmp/pids/idp-2.pid ] && [ `ps -p $(cat ./tmp/pids/idp-2.pid)` ]; then
  echo 'IDP 2 is already running'
else
  echo 'Starting the IDP 2'
  ./startup-2.sh &
  echo $! > ./../stub-oidc-broker/tmp/pids/idp-2.pid
fi

cd ../stub-trustframework-rp
if [ -f ./tmp/pids/rp-1.pid ] && [ `ps -p $(cat ./tmp/pids/rp-1.pid)` ]; then
  echo 'RP 1 is already running'
else
  echo 'Starting the RP 1'
  ./startup-rp-1.sh &
  echo $! > ./../stub-oidc-broker/tmp/pids/rp-1.pid
fi
if [ -f ./tmp/pids/rp-2.pid ] && [ `ps -p $(cat ./tmp/pids/rp-2.pid)` ]; then
  echo 'RP 2 is already running'
else
  echo 'Starting the RP 2'
  ./startup-rp-2.sh &
  echo $! > ./../stub-oidc-broker/tmp/pids/rp-2.pid
fi

cd ../tpp-registration-prototype
if [ -f ./tmp/pids/onboarding.pid ] && [ `ps -p $(cat ./tmp/pids/onboarding.pid)` ]; then
  echo 'Onboarding app is already running'
else
  echo 'Starting the onboarding app'
  ./startup.sh &
  echo $! > ./../stub-oidc-broker/tmp/pids/onboarding.pid
fi

echo 'The Trust Framework is starting. Wait a little while and then visit http://localhost:4410/ or http://localhost:4412/'
echo 'Remember to have at least 1 Broker and 1 IDP registered per scheme via the onboarding app: http://localhost:5000. They need to have the correct local domains in order for it to work.'
echo 'Good luck!'
