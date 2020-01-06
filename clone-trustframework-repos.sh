#!/usr/bin/env bash
set -eu
source ../stub-oidc-broker/scripts/functions.sh

cd "$(dirname "$0")/.."

git_protocol=$(check_for_github_ssh)

github_repos="stub-trustframework-rp middleware-in-the-middle trust-framework-directory-prototype tpp-registration-prototype trust-framework-idp"

for repo in $github_repos; do
  clone_if_not_present $repo
done


