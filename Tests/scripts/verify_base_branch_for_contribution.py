import requests
import sys
import re
from demisto_sdk.commands.common.tools import print_error, print_warning, print_color, LOG_COLORS
from demisto_sdk.commands.common.constants import EXTERNAL_PR_REGEX


def get_base_branch(pr_num):
    """Fetches the base branch name of PR num {pr_num}

    Args:
        pr_num (string): The string representation of the pr number

    Returns:
        string. The name of the base branch of the pr if succeeds, '' otherwise.
    """

    # Disable insecure warnings
    requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

    url = 'https://api.github.com/repos/demisto/content/pulls/{}'.format(pr_num)

    try:
        res = requests.get(url, verify=False)
        res.raise_for_status()
        pr = res.json()
        if pr and isinstance(pr, list) and len(pr) == 1:
            # github usually returns a list of PRs, if not pr is a dict
            pr = pr[0]
        return pr.get('base', {}).get('ref', '')

    except (requests.exceptions.HTTPError, ValueError) as e:
        # If we didn't succeed to fetch pr for any http error / res.json() we raise an error
        # then we don't want the build to fail
        print_warning('Unable to fetch pull request #{0}.\nError: {1}'.format(pr_num, str(e)))
        return ''


def verify_base_branch(pr_num):
    """Checks if the base branch is master or not

    Args:
        pr_num (string): The string representation of the pr number

    Returns:
        True if valid, False otherwise. And attaches the appropriate message to the user.
    """

    print_color('Fetching the base branch of pull request #{}.'.format(pr_num), LOG_COLORS.NATIVE)
    base_branch = get_base_branch(pr_num)
    if base_branch == 'master':
        return 'Cannot merge a contribution directly to master, the pull request reviewer will handle that soon.', False
    else:
        return 'Verified pull request #{} base branch successfully.'.format(pr_num), True


if __name__ == '__main__':
    circle_branch = sys.argv[1]
    pr_numbers_list = re.findall(EXTERNAL_PR_REGEX, circle_branch, re.IGNORECASE)
    if pr_numbers_list:
        pr_number = pr_numbers_list[0]
        msg, is_valid = verify_base_branch(pr_number)
        if is_valid:
            print_color(msg, LOG_COLORS.GREEN)
        else:
            print_error(msg)
            sys.exit(1)
    else:
        print_warning('Unable to fetch pull request.')
