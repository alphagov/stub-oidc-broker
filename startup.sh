#!/usr/bin/env bash
set -e

CONFIG_FILE=./stub-oidc-client.yml

cd "$(dirname "$0")"

LOCAL_IP="$(ipconfig getifaddr en0)"
export REDIS_URI="redis://${LOCAL_IP}:6380"

./gradlew installDist

trap "docker container stop clientRedis" EXIT
docker run --name clientRedis -d -p 6380:6379 --rm redis

./build/install/stub-oidc-client/bin/stub-oidc-client server $CONFIG_FILE
