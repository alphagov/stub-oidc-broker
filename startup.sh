#!/usr/bin/env bash
set -e

CONFIG_FILE=./stub-oidc-broker.yml

cd "$(dirname "$0")"

LOCAL_IP="$(ipconfig getifaddr en0)"
export REDIS_URI="redis://${LOCAL_IP}:6380"
export SCHEME=1
export BRANDING=private
export REDIS_DATABASE="/1"
export VERIFIABLE_CREDENTIAL_URI=http://localhost:3333

./gradlew installDist

trap "docker container stop clientRedis" EXIT
docker run --name clientRedis -d -p 6380:6379 --rm redis

./build/install/stub-oidc-broker/bin/stub-oidc-broker server $CONFIG_FILE
