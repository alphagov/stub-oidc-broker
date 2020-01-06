#!/usr/bin/env bash
set -eu
source ../stub-oidc-broker/scripts/functions.sh

function clone_if_not_present {
  if [ -d "$1" ]
  then
    echo "$repo already exists. Skipping..."
  else
    if [ "$git_protocol" = "ssh" ]
    then
      git clone "git@github.com:alphagov/$1.git"
    else
      git clone "https://github.com/alphagov/$1"
    fi
  fi
}

cd "$(dirname "$0")/.."

git_protocol=$(check_for_github_ssh)

github_repos="stub-trustframework-rp middleware-in-the-middle trust-framework-directory-prototype tpp-registration-prototype trust-framework-idp"

for repo in $github_repos; do
  clone_if_not_present $repo
done


