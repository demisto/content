import requests
import re
import sys
import argparse
import base64
import json


def options_handler():
    parser = argparse.ArgumentParser(description='Creates release pull request for demisto-sdk.')

    parser.add_argument('-t', '--access_token', help='Github access token', required=True)
    parser.add_argument('-b', '--release_branch_name', help='The name of the release branch', required=True)

    options = parser.parse_args()
    return options


def main():
    options = options_handler()
    access_token = options.access_token
    release_branch_name = options.release_branch_name

    print(f'Preparing to create Pull request to release branch {release_branch_name}')

    headers = {
        'Authorization': f'Bearer {access_token}',
        'accept': 'application/vnd.github+json'
    }

    # get pyproject.toml file sha
    url = f'https://api.github.com/repos/demisto/demisto-sdk/contents/pyproject.toml'
    response = requests.request('GET', url, params={'ref': release_branch_name}, verify=False)
    if response.status_code != 200:
        print(f'Failed to get the pyproject.toml file from branch {release_branch_name}')
        print(response.text)
        sys.exit(1)
    pyproject_sha = response.json().get('sha')

    # get pyproject.toml file content
    url = f'https://raw.githubusercontent.com/demisto/demisto-sdk/{release_branch_name}/pyproject.toml'
    response = requests.request('GET', url, verify=False)
    if response.status_code != 200:
        print(f'Failed to get the pyproject.toml file content from branch {release_branch_name}')
        print(response.text)
        sys.exit(1)
    pyproject_content = response.text

    # get the version changelog
    url = f'https://raw.githubusercontent.com/demisto/demisto-sdk/{release_branch_name}/CHANGELOG.md'
    response = requests.request('GET', url, verify=False)
    if response.status_code != 200:
        print(f'Failed to get the CHANGELOG.md file content from branch {release_branch_name}')
        print(response.text)
        sys.exit(1)
    changelog_content = response.text
    new_changelog_text = changelog_content.replace('## Unreleased', f'## Unreleased\n\n## {release_branch_name}')
    release_changes = new_changelog_text.split(f'## {release_branch_name}\n')[1].split('\n\n')[0]
    release_changes = f'demisto-sdk release changes:\n{release_changes}'

    # update pyproject.toml content with the release version
    file_text = re.sub(r'\nversion = \"(\d+\.\d+\.\d+)\"\n', f'\nversion = "{release_branch_name}"\n', pyproject_content)
    content = bytes(file_text, encoding='utf8')

    # commit pyproject.toml
    data = {
        'message': 'Commit poetry files',
        'content': base64.b64encode(content).decode("utf-8"),
        'branch': release_branch_name,
        'sha': pyproject_sha
    }

    url = 'https://api.github.com/repos/demisto/demisto-sdk/contents/pyproject.toml'
    response = requests.request('PUT', url, data=json.dumps(data), headers=headers, verify=False)
    if response.status_code != 200:
        print(f'Failed to commit the pyproject.toml file')
        print(response.text)
        sys.exit(1)

    # create the release PR
    data = {
        'base': 'master',
        'head': release_branch_name,
        'title': f'demisto-sdk release {release_branch_name}',
        'body': release_changes
    }
    url = 'https://api.github.com/repos/demisto/demisto-sdk/pulls'
    response = requests.request('POST', url, data=json.dumps(data), headers=headers, verify=False)
    if response.status_code != 201:
        print(f'Failed to create pull request for branch {release_branch_name}')
        print(response.text)
        sys.exit(1)

    # get PR ID
    pr_url = response.json().get('html_url')
    print(f'The Pull request created successfully! {pr_url}')


if __name__ == "__main__":
    main()
