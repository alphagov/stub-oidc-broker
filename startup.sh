#!/usr/bin/env bash
set -e

CONFIG_FILE=./verify-stub-client.yml

cd "$(dirname "$0")"

./gradlew installDist

trap "docker container stop clientRedis" EXIT
docker run --name clientRedis -d -p 6380:6379 --rm redis

./build/install/verify-stub-client/bin/verify-stub-client server $CONFIG_FILE
