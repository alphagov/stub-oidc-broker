#!/bin/bash
set -e

PID_DIR=./tmp/pids
if [ ! -d $PID_DIR ]; then
  echo 'Creating PIDs directory'
  mkdir -p $PID_DIR
fi

if [ -f ./tmp/pids/broker1.pid ] && [ `ps -p $(cat ./tmp/pids/broker1.pid)` ]; then
  echo 'Broker 1 is already running'
else
  echo 'Starting Broker 1'
  ./startup-broker1.sh >"$log" 2>&1 &
  echo $! > ./tmp/pids/broker1.pid
fi
if [ -f ./tmp/pids/broker-2.pid ] && [ `ps -p $(cat ./tmp/pids/broker2.pid)` ]; then
  echo 'Broker 2 is already running'
else
  echo 'Starting Broker 2'
  ./startup-broker2.sh &
  echo $! > ./tmp/pids/broker2.pid
fi

cd ../trust-framework-directory-prototype
if [ -f ./tmp/pids/directory.pid ] && [ `ps -p $(cat ./tmp/pids/directory.pid)` ]; then
  echo 'Directory is already running'
else
  echo 'Starting the Directory'
  ./startup-directory.sh &
  echo $! > ./../stub-oidc-broker/tmp/pids/directory.pid
fi

cd ../middleware-in-the-middle
if [ -f ./tmp/pids/initiator.pid ] && [ `ps -p $(cat ./tmp/pids/initiator.pid)` ]; then
  echo 'Initiator is already running'
else
  echo 'Starting the initiator'
  ./startup-local-initiator.sh &
  echo $! > ./../stub-oidc-broker/tmp/pids/initiator.pid
fi
if [ -f ./tmp/pids/receiver.pid ] && [ `ps -p $(cat ./tmp/pids/receiver.pid)` ]; then
  echo 'Receiver is already running'
else
  echo 'Starting the receiver'
  ./startuo-local-receiver.sh &
  echo $! > ./../stub-oidc-broker/tmp/pids/receiver.pid
fi

cd ../trust-framework-idp
if [ -f ./tmp/pids/idp1.pid ] && [ `ps -p $(cat ./tmp/pids/idp1.pid)` ]; then
  echo 'IDP 1 is already running'
else
  echo 'Starting the IDP 1'
  ./startup-idp1.sh &
  echo $! > ./../stub-oidc-broker/tmp/pids/idp1.pid
fi
if [ -f ./tmp/pids/idp2.pid ] && [ `ps -p $(cat ./tmp/pids/idp2.pid)` ]; then
  echo 'IDP 2 is already running'
else
  echo 'Starting the IDP 2'
  ./startup-idp2.sh &
  echo $! > ./../stub-oidc-broker/tmp/pids/idp2.pid
fi

cd ../stub-trustframework-rp
if [ -f ./tmp/pids/rp1.pid ] && [ `ps -p $(cat ./tmp/pids/rp1.pid)` ]; then
  echo 'RP 1 is already running'
else
  echo 'Starting the RP 1'
  ./startup-rp1.sh &
  echo $! > ./../stub-oidc-broker/tmp/pids/rp1.pid
fi
if [ -f ./tmp/pids/rp2.pid ] && [ `ps -p $(cat ./tmp/pids/rp2.pid)` ]; then
  echo 'RP 2 is already running'
else
  echo 'Starting the RP 2'
  ./startup-rp2.sh &
  echo $! > ./../stub-oidc-broker/tmp/pids/rp2.pid
fi

cd ../tpp-registration-prototype
if [ -f ./tmp/pids/onboarding.pid ] && [ `ps -p $(cat ./tmp/pids/onboarding.pid)` ]; then
  echo 'Onboarding app is already running'
else
  echo 'Starting the onboarding app'
  ./startup-registration.sh &
  echo $! > ./../stub-oidc-broker/tmp/pids/onboarding.pid
fi

echo 'The Trust Framework is starting. Wait a little while and then visit http://localhost:4410/ or http://localhost:4412/'
echo 'Remember to have at least 1 Broker and 1 IDP registered per scheme via the onboarding app: http://localhost:5000. They need to have the correct local domains in order for it to work.'
echo 'Good luck!'
