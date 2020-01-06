#!/usr/bin/env bash
set -e

source ../stub-oidc-broker/scripts/service.sh

check_if_dependencies_are_installed

start_service broker1 stub-oidc-broker
start_service broker2 stub-oidc-broker

start_service rp1 stub-trustframework-rp
start_service rp2 stub-trustframework-rp

start_service local-initiator middleware-in-the-middle
start_service local-receiver middleware-in-the-middle

start_service directory trust-framework-directory-prototype
start_service registration tpp-registration-prototype

start_service idp1 trust-framework-idp
start_service idp2 trust-framework-idp
