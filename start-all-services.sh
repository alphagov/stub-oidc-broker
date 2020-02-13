#!/usr/bin/env bash
set -e

source ../stub-oidc-broker/scripts/service.sh

check_if_dependencies_are_installed

start_service broker1 stub-oidc-broker
start_service broker2 stub-oidc-broker
start_service broker3 stub-oidc-broker

start_service rp1 stub-trustframework-rp
start_service rp2 stub-trustframework-rp

start_service tfsp-1 trust-framework-service-provider-prototype
start_service tfsp-2 trust-framework-service-provider-prototype

start_service directory trust-framework-directory-prototype
start_service registration tpp-registration-prototype

start_service idp1 trust-framework-idp
start_service idp2 trust-framework-idp
