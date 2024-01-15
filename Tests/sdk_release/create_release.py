import requests
import json
import sys
import argparse


def options_handler():
    parser = argparse.ArgumentParser(description='Creates release branch for demisto-sdk.')

    parser.add_argument('-t', '--access_token', help='Github access token', required=True)
    parser.add_argument('-b', '--release_branch_name', help='The name of the release branch', required=True)
    parser.add_argument('-t', '--release_text', help='Text describing the contents of the release', required=True)

    options = parser.parse_args()
    return options


def main():
    options = options_handler()
    release_text = options.release_text
    release_branch_name = options.release_branch_name
    access_token = options.access_token

    print(f"Preparing to release Demisto SDK version {release_branch_name}")

    url = 'https://api.github.com/repos/demisto/demisto-sdk/releases'
    data = json.dumps({
        'tag_name': f'v{release_branch_name}',
        'name': f'v{release_branch_name}',
        'body': release_text,
        'draft': True, ############# TODO: CHANGE TO False
        'target_commitish': release_branch_name
    })

    headers = {
      'Content-Type': 'application/vnd.github+json',
      'Authorization': f'Bearer {access_token}'
    }

    response = requests.request("POST", url, headers=headers, data=data, verify=False)
    if response.status_code != 201:
        print(f'Failed to crreate release {release_branch_name} for demisto SDK')
        print(response.text)
        sys.exit(1)

    print(f"Demisto SDK v{release_branch_name} released successfully!")


if __name__ == "__main__":
    main()
