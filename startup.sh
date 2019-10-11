#!/usr/bin/env bash
set -e

CONFIG_FILE=./verify-stub-client.yml

cd "$(dirname "$0")"

./gradlew installDist

./build/install/verify-stub-client/bin/verify-stub-client server $CONFIG_FILE
