#!/usr/bin/env bash

if [ "$#" -lt "1" ]; then
  echo "Usage:
  $0 -ct <token>

  -r, --repo                The ci gitlab token.
  -b, --branch              The branch name.
  --exit-code               Determines if the command should fail when the branch does not exist.
  [ -t, --token ]           Use in case that it's requierd.
  [ -u, --user ]            Use in case that it's requierd.
  [ -h, --host ]            The git remote host (Default is 'github.com').
  "
  exit 1
fi

_host='github.com'
_token='token'
_uesr='user'
_ignore_error='true'

# Parsing the user inputs.

while [[ "$#" -gt 0 ]]; do
  case $1 in

  -r|--repo) _repo="$2"
    shift
    shift;;

  -b|--branch) _branch="$2"
    shift
    shift;;

  -h|--host) _host="$2"
    shift
    shift;;

  -t|--token) _token="$2"
    shift
    shift;;

  -u|--uesr) _uesr="$2"
    shift
    shift;;

  --exit-code) _ignore_error="false"
    shift;;

  *)    # unknown option.
    shift;;
  esac
done

if [ "${_repo}" = "" ]; then
    echo "you must specify a repository (--repo)"
    exit 1
fi

if [ "${_branch}" = "" ]; then
    echo "you must specify a branch name (--branch)"
    exit 1
fi


git ls-remote --exit-code --heads "https://${_uesr}:${_token}@${_host}/${_repo}.git" "refs/heads/${_branch}" >> /dev/null \
    && echo 'true' \
    && exit 0

echo 'false'
if [ "${_ignore_error}" = 'false' ]; then
    exit 1
fi
