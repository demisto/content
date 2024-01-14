import requests
import json
import sys
import argparse


def options_handler():
    parser = argparse.ArgumentParser(description='Creates release branch for demisto-sdk.')

    parser.add_argument('-t', '--access_token', help='Github access token', required=True)
    parser.add_argument('-b', '--release_branch_name', help='The name of the release branch', required=True)

    options = parser.parse_args()
    return options


def main():
    options = options_handler()
    print("Preparing to create release branch")

    # get master branch sha value
    url = "https://api.github.com/repos/demisto/demisto-sdk/branches/master"
    response = requests.request("GET", url)

    commit_sha = response.json().get('commit', {}).get('sha')
    if not commit_sha:
        print('Failed to retrieve demisto-sdk master branch')
        print(response.text)
        sys.exit(1)

    # create the release branch
    url = "https://api.github.com/repos/demisto/demisto-sdk/git/refs"

    payload = json.dumps({
      "ref": f"refs/heads/{options.release_branch_name}",
      "sha": commit_sha
    })
    headers = {
      'Content-Type': 'application/json',
      'Authorization': f'Bearer {options.access_token}'
    }

    response = requests.request("POST", url, headers=headers, data=payload, verify=False)
    if response.status_code != 201:
        print('failed to create the release branch')
        print(response.text)
        sys.exit(1)

    print(f"The branch {options.release_branch_name} created successfully!")


if __name__ == "__main__":
    main()
