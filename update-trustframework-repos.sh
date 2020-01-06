#!/usr/bin/env bash
set -eu

source ../stub-oidc-broker/scripts/functions.sh

git_protocol=$(check_for_github_ssh)

cloneRepos=false
while getopts ":c" opt; do
  case $opt in
    c)
      cloneRepos=true
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      ;;
  esac
done

red=`tput setaf 1`
reset=`tput sgr0`

dependencies="stub-oidc-broker stub-trustframework-rp middleware-in-the-middle trust-framework-directory-prototype tpp-registration-prototype trust-framework-idp"

for project in $dependencies; do

	__pushd ../$project
	current_branch=$(git_current_branch)
	echo Updating $project
	if [[ "$current_branch" = master ]]; then
		if [[ $(git status | tail -n1) =~ 'nothing to commit' ]]; then
			git pull --rebase
			repo_status='updated'
		else
			repo_status=$(echo_as_error 'dirty')
		fi
	else
		repo_status=$(echo_as_error "unexpected branch ($current_branch)")
	fi
	echo $project repo: $repo_status
	__popd
	echo
done

echo "Trustframework update complete."
