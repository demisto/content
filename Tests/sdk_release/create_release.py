import requests
import json
import sys
import argparse
import re
import urllib3
from distutils.util import strtobool
from Tests.scripts.utils.log_util import install_logging
from Tests.scripts.utils import logging_wrapper as logging

# Disable insecure warnings
urllib3.disable_warnings()

# regex to split the changelog line to 3 pieces- description, pr number and url
CHANGELOG_REGEX = re.compile(r"^(.*) \[(#\d+)\]\((http.*)\)")


def get_changelog_text(release_branch_name, text_format='markdown'):
    # get release changelog file
    url = f"https://raw.githubusercontent.com/demisto/demisto-sdk/{release_branch_name}/CHANGELOG.md"
    response = requests.request("GET", url, verify=False)
    if response.status_code != requests.codes.ok:
        logging.error(f'Failed to get the CHANGELOG.md file from branch {release_branch_name}')
        logging.error(response.text)
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
            description, pr_number, url = CHANGELOG_REGEX.match(change).groups()  # type: ignore[union-attr]

            if text_format == 'markdown':
                releases.append(
                    f"{description} [{pr_number}]({url})"
                )
            elif text_format == 'slack':
                releases.append(
                    f"{description} <{url}|{pr_number}>"
                )
            else:
                logging.error(f'The format {text_format} is not supported')
                sys.exit(1)

        except Exception as e:
            logging.error(f'Error parsing change: {e}')
            sys.exit(1)

    return "\n".join(releases)


def options_handler():
    parser = argparse.ArgumentParser(description='Creates release branch for demisto-sdk.')

    parser.add_argument('-t', '--access_token', help='Github access token', required=True)
    parser.add_argument('-b', '--release_branch_name', help='The name of the release branch', required=True)
    parser.add_argument('-d', '--is_draft', help='Is draft release', default='FALSE')
    options = parser.parse_args()
    return options


def main():
    install_logging("create_release.log", logger=logging)

    options = options_handler()
    release_branch_name = options.release_branch_name
    access_token = options.access_token
    is_draft = bool(strtobool(options.is_draft))

    if is_draft:
        logging.info(f"Preparing to create draft release for Demisto SDK version {release_branch_name}")
    else:
        logging.info(f"Preparing to release Demisto SDK version {release_branch_name}")

    # release the sdk version
    # The reference can be found here https://docs.github.com/en/rest/releases/releases?apiVersion=2022-11-28#create-a-release
    url = 'https://api.github.com/repos/demisto/demisto-sdk/releases'
    data = json.dumps({
        'tag_name': f'v{release_branch_name}',
        'name': f'v{release_branch_name}',
        'body': get_changelog_text(release_branch_name),
        'draft': is_draft,
        'target_commitish': release_branch_name
    })

    headers = {
        'Content-Type': 'application/vnd.github+json',
        'Authorization': f'Bearer {access_token}'
    }
    response = requests.request("POST", url, headers=headers, data=data, verify=False)
    if response.status_code != requests.codes.created:
        logging.error(f'Failed to create release {release_branch_name} for demisto SDK')
        logging.error(response.text)
        sys.exit(1)

    logging.success(f"Demisto SDK v{release_branch_name} released successfully!")


if __name__ == "__main__":
    main()
