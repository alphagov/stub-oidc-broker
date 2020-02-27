#!/usr/bin/env bash
set -e

echo "Killing all services"

if [ "$(docker ps -q -f name=clientRedis)" ]; then
      echo "Killing Docker container: clientRedis"
      docker kill clientRedis
fi

pushd ../stub-oidc-broker> /dev/null
./kill-broker1.sh
./kill-broker2.sh
popd > /dev/null

pushd ../stub-trustframework-rp> /dev/null
./kill-rp1.sh
./kill-rp2.sh
popd > /dev/null

pushd ../trust-framework-service-provider-prototype> /dev/null
./kill-tfsp-1.sh
./kill-tfsp-2.sh
popd > /dev/null

pushd ../trust-framework-idp> /dev/null
./kill-idp1.sh
./kill-idp2.sh
./kill-atp1.sh
popd > /dev/null

pushd ../trust-framework-directory-prototype> /dev/null
./kill-directory.sh
popd > /dev/null

pushd ../tpp-registration-prototype> /dev/null
./kill-registration.sh
popd > /dev/null
