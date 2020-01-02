#!/usr/bin/env bash
set -eu

function check_for_github_ssh {
  # Try SSH first (IL2)
  set +e
  ssh -o ConnectTimeout=5 git@github.com 1>/dev/null 2>&1
  ssh_return_code=$?
  set -e
  # return code of 255 indicates timeout, 1 indicates connected ok but command failed. which is good :)
  if [[ $ssh_return_code -eq 1 ]]
  then
    # using echo so we don't look like these are errors
    echo "ssh"
  else
    echo "https"
  fi
}

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


