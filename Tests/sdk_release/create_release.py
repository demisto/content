import requests
import json
import sys
import argparse
import re
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

REGEX = re.compile(r"^(.*) \[(#\d+)\]\((http.*)\)")


def get_changelog_text(release_branch_name, format='markdown'):
    # get release changelog
    url = f"https://raw.githubusercontent.com/demisto/demisto-sdk/{release_branch_name}/CHANGELOG.md"
    response = requests.request("GET", url, verify=False)
    if response.status_code != 200:
        print(f'Failed to get the CHANGELOG.md file from branch {release_branch_name}')
        print(response.text)
        sys.exit(1)
    file_text = response.text
    release_changes = (
        file_text.split(f"## {release_branch_name}\n")[1].split("\n\n")[0].split("\n")
    )

    # Converting release changes to markdown links
    releases = []
    for change in release_changes:
        try:
            # Ignoring the mypy error because the regex must match
            change_parts = REGEX.match(change).groups()  # type: ignore[union-attr]

            if format == 'markdown':
                releases.append(
                    f"{change_parts[0]} [{change_parts[1]}]({change_parts[2]})"
                )
            elif format == 'slack':
                releases.append(
                    f"{change_parts[0]} <{change_parts[2]}|{change_parts[1]}>"
                )
            else:
                print(f'The format {format} is not supported')
                exit(1)

        except Exception as e:
            print(f'Error parsing change: {e}')
            exit(1)

    return "\n".join(releases)


def options_handler():
    parser = argparse.ArgumentParser(description='Creates release branch for demisto-sdk.')

    parser.add_argument('-t', '--access_token', help='Github access token', required=True)
    parser.add_argument('-b', '--release_branch_name', help='The name of the release branch', required=True)

    options = parser.parse_args()
    return options


def main():
    options = options_handler()
    release_branch_name = options.release_branch_name
    access_token = options.access_token

    print(f"Preparing to release Demisto SDK version {release_branch_name}")

    url = 'https://api.github.com/repos/demisto/demisto-sdk/releases'
    data = json.dumps({
        'tag_name': f'v{release_branch_name}',
        'name': f'v{release_branch_name}',
        'body': get_changelog_text(release_branch_name),
        'draft': True, ############# TODO: CHANGE TO False
        'target_commitish': release_branch_name
    })

    headers = {
      'Content-Type': 'application/vnd.github+json',
      'Authorization': f'Bearer {access_token}'
    }

    response = requests.request("POST", url, headers=headers, data=data, verify=False)
    if response.status_code != 201:
        print(f'Failed to create release {release_branch_name} for demisto SDK')
        print(response.text)
        sys.exit(1)

    print(f"Demisto SDK v{release_branch_name} released successfully!")


if __name__ == "__main__":
    main()
