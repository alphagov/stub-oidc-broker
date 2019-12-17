#!/usr/bin/env bash
set -e

CONFIG_FILE=./stub-oidc-broker.yml

cd "$(dirname "$0")"

LOCAL_IP="$(ipconfig getifaddr en0)"
export REDIS_URI="redis://${LOCAL_IP}:6381"
export APPLICATION_PORT=5510
export STUB_BROKER_URI=http://localhost:5510
export ADMIN_PORT=5511
export IDP_URI=http://localhost:3334
export SCHEME=2
export BRANDING=public

./gradlew installDist

trap "docker container stop clientRedis1" EXIT
docker run --name clientRedis1 -d -p 6381:6379 --rm redis

./build/install/stub-oidc-broker/bin/stub-oidc-broker server $CONFIG_FILE
