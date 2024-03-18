import os
import re
import sys
import json
import time
import argparse
import requests
import demisto_sdk.commands.common.tools as tools
from Tests.scripts.utils.log_util import install_logging
from Tests.scripts.utils import logging_wrapper as logging

# disable insecure warnings
import urllib3
urllib3.disable_warnings()

PRIVATE_BUILD_INFRA_FOLDERS = ['Tests/private_build', 'Tests/Marketplace']

NON_PRIVATE_BUILD_FILES = ['Tests/Marketplace/landingPage_sections.json',
                           'Tests/Marketplace/validate_landing_page_sections.py',
                           'Tests/Marketplace/Tests/validate_landing_page_sections_test.py']

TRIGGER_BUILD_URL_ON_MASTER = 'https://api.github.com/repos/demisto/content-private/dispatches'
TRIGGER_BUILD_URL_ON_CUSTOM_BRANCH = \
    'https://api.github.com/repos/demisto/content-private/actions/workflows/config.yml/dispatches'
TRIGGER_NIGHTLY_URL = \
    'https://api.github.com/repos/demisto/content-private/actions/workflows/nightly.yml/dispatches'
GET_DISPATCH_WORKFLOWS_URL = 'https://api.github.com/repos/demisto/content-private/actions/runs'
WORKFLOW_HTML_URL = 'https://github.com/demisto/content-private/actions/runs'
GET_WORKFLOW_URL = 'https://api.github.com/repos/demisto/content-private/actions/runs/{:s}/jobs'

PRIVATE_REPO_WORKFLOW_ID_FILE = 'PRIVATE_REPO_WORKFLOW_ID.txt'

GET_WORKFLOWS_MAX_RETRIES = 5

GET_WORKFLOWS_TIMEOUT_THRESHOLD = int(60 * 60 * 2)  # 2 hours


def get_modified_files(branch_name: str = None) -> list[str]:
    """ Gets modified files between master branch and the input branch_name, If the branch_name is empty the method
        compare master branch with the commit sha1 from the environment variable CI_COMMIT_SHA.

    Args:
        branch_name: The branch name to compare with master.

    Returns: A list of modified files.

    """
    if not branch_name:
        branch_name = os.environ.get('CI_COMMIT_SHA')

    files = []
    files_string = tools.run_command(f'git diff --name-only origin/master...{branch_name}')
    for line in files_string.split("\n"):
        if line:
            files.append(line)
    return files


def branch_has_private_build_infra_change(branch_name: str = None) -> bool:
    """ Checks whether the modified files in the branch are private build infrastructure files.

    Args:
        branch_name: The branch name to compare with master.

    Returns: True if private build infrastructure files modified, False otherwise.

    """
    modified_files = get_modified_files(branch_name)
    for infra_file in modified_files:
        if infra_file in NON_PRIVATE_BUILD_FILES:
            continue

        path = os.path.dirname(infra_file)
        for infra_code_dir_path in PRIVATE_BUILD_INFRA_FOLDERS:
            if path.startswith(infra_code_dir_path):
                return True
    return False


def get_dispatch_workflows_ids(github_token: str, branch: str, is_nighty: bool) -> list[int]:
    """ Gets private repo dispatch workflows on the given branch.

    Args:
        github_token: Github bearer token.
        branch: The branch to get the workflows from.
        is_nighty: Is nightly build.

    Returns: A list of workflows ids.

    """

    params = {'branch': branch,
              'event': 'repository_dispatch' if branch == 'master' else 'workflow_dispatch'}

    if is_nighty:
        params = {'branch': branch,
                  'event': 'workflow_dispatch',
                  'name': 'Private repo nightly build'}

    res = requests.get(GET_DISPATCH_WORKFLOWS_URL,
                       headers={'Authorization': f'Bearer {github_token}'},
                       params=params,
                       verify=False)
    if res.status_code != 200:
        logging.error(f'Failed to get private repo workflows, request to '
                      f'{GET_DISPATCH_WORKFLOWS_URL} failed with error: {str(res.content)}')
        sys.exit(1)

    try:
        workflows = json.loads(res.content)
    except ValueError:
        logging.error('Unable to parse private repo workflows response')
        sys.exit(1)

    workflows = workflows.get('workflow_runs', [])
    return [workflow.get('id') for workflow in workflows]


def main():
    install_logging("TriggerPrivateBuild.log", logger=logging)
    # get github token parameter
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('--github-token', help='Github token')
    arg_parser.add_argument('--nightly', help='Is nightly build', action=argparse.BooleanOptionalAction)
    arg_parser.add_argument('--sdk-ref', help='Whether to override the sdk branch')
    arg_parser.add_argument('--slack-channel', help='The slack channel in which to send the notification',
                            default='dmst-build-test')
    arg_parser.add_argument('--artifacts-folder', help='Whether to override the PRIVATE_REPO_WORKFLOW_ID.txt creation location',
                            required=False)
    arg_parser.add_argument(
        '--private-branch-name',
        help='Name of the branch in the private repository, if not provided the default will be master.',
        default='master'
    )
    args = arg_parser.parse_args()

    private_branch_name = args.private_branch_name
    github_token = args.github_token
    is_nightly = args.nightly
    sdk_ref = args.sdk_ref
    slack_channel = args.slack_channel
    artifacts_folder = args.artifacts_folder

    # get branch name
    branches = tools.run_command("git branch")
    branch_name_regex = re.search(r"\* (.*)", branches)
    if branch_name_regex:
        branch_name = branch_name_regex.group(1)

    if not is_nightly and branch_has_private_build_infra_change(branch_name):
        # get the workflows ids before triggering the build
        pre_existing_workflow_ids = get_dispatch_workflows_ids(github_token, private_branch_name, False)

        # trigger private build
        if private_branch_name == 'master':
            trigger_build_url = TRIGGER_BUILD_URL_ON_MASTER
            payload = {
                'event_type': f'Trigger private build from content/{branch_name}',
                'client_payload': {'commit_sha1': branch_name, 'is_infra_build': 'True'}
            }
        else:
            trigger_build_url = TRIGGER_BUILD_URL_ON_CUSTOM_BRANCH
            payload = {
                'ref': private_branch_name,
                'inputs': {
                    'commit_sha1': branch_name,
                    'is_infra_build': 'True'
                }
            }
        logging.info(f'Triggering build for branch {private_branch_name} in content-private repo.')
        res = requests.post(trigger_build_url,
                            headers={'Accept': 'application/vnd.github.everest-preview+json',
                                     'Authorization': f'Bearer {github_token}'},
                            data=json.dumps(payload),
                            verify=False)

        if res.status_code != 204:
            logging.critical(f'Failed to trigger private repo build, request to '
                             f'{trigger_build_url} failed with error: {str(res.content)}')
            sys.exit(1)

    elif is_nightly:
        # get the workflows ids before triggering the nightly build
        pre_existing_workflow_ids = get_dispatch_workflows_ids(github_token, private_branch_name, True)

        payload = {
            'ref': 'master',
            'inputs': {
                'slack_channel': slack_channel
            }
        }
        if sdk_ref:
            payload['inputs']['sdk_ref'] = sdk_ref  # type: ignore
        logging.info('Triggering nightly build for content-private repo')
        res = requests.post(TRIGGER_NIGHTLY_URL,
                            headers={'Accept': 'application/vnd.github.everest-preview+json',
                                     'Authorization': f'Bearer {github_token}'},
                            data=json.dumps(payload),
                            verify=False)

        if res.status_code != 204:
            logging.critical(f'Failed to trigger private repo nightly build, request to '
                             f'{TRIGGER_NIGHTLY_URL} failed with error: {str(res.content)}')
            sys.exit(1)

    else:
        logging.info('Build private repo skipped')
        sys.exit(0)

    # get the workflow id
    workflow_ids_diff = []
    for i in range(GET_WORKFLOWS_MAX_RETRIES):
        # wait 5 seconds and get the workflow ids again
        time.sleep(5)
        workflow_ids_after_dispatch = get_dispatch_workflows_ids(github_token, private_branch_name, is_nightly)

        # compare with the first workflows list to get the current id
        workflow_ids_diff = [x for x in workflow_ids_after_dispatch if x not in pre_existing_workflow_ids]
        if workflow_ids_diff:
            break

    if len(workflow_ids_diff) == 1:
        workflow_id = workflow_ids_diff[0]
        logging.success(f'Private repo build triggered successfully, workflow id: {workflow_id}\n URL:'
                        f' {WORKFLOW_HTML_URL}/{workflow_id}')

        workflow_id_file = PRIVATE_REPO_WORKFLOW_ID_FILE
        if artifacts_folder:
            workflow_id_file = os.path.join(artifacts_folder, PRIVATE_REPO_WORKFLOW_ID_FILE)

        # write the workflow id to text file to use it in get_private_build_status.py
        with open(workflow_id_file, "w") as f:
            f.write(str(workflow_id))
        sys.exit(0)

    else:
        logging.critical('Could not find the private repo workflow')
        sys.exit(1)


if __name__ == "__main__":
    main()
