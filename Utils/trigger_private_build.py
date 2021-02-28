import re
import os
import sys
import json
import time
import argparse
import requests
import logging
import demisto_sdk.commands.common.tools as tools

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

INFRASTRUCTURE_FILES = ['Tests/scripts/validate_premium_packs.sh', 'Tests/scripts/validate_premium_packs.py',
                        'Tests/scripts/validate_index.py']
INFRASTRUCTURE_FOLDERS = ['Tests/private_build', 'Tests/Marketplace']

TRIGGER_BUILD_URL = 'https://api.github.com/repos/demisto/content-private/dispatches'
GET_DISPATCH_WORKFLOWS_URL = 'https://api.github.com/repos/demisto/content-private/actions/runs'
WORKFLOW_HTML_URL = 'https://github.com/demisto/content-private/actions/runs'

PRIVATE_REPO_WORKFLOW_ID_FILE = 'PRIVATE_REPO_WORKFLOW_ID.txt'


def get_modified_files(branch_name):
    files = []
    files_string = tools.run_command("git diff --name-status origin/master...{0}".format(branch_name))
    for line in files_string.split("\n"):
        if line:
            _, file_path = line.split(maxsplit=1)
            if file_path:
                files.append(file_path)
    return files


def is_infrastructure_change(modified_files):
    for file in modified_files:
        if file in INFRASTRUCTURE_FILES:
            return True

        path = os.path.dirname(file)
        for dir_path in INFRASTRUCTURE_FOLDERS:
            if path.startswith(dir_path):
                return True
    return False


def get_dispatch_workflows_ids(bearer_token, branch):
    res = requests.request("GET",
                           GET_DISPATCH_WORKFLOWS_URL,
                           headers={'Authorization': bearer_token},
                           params={'branch': branch, 'event': 'repository_dispatch'},
                           verify=False)
    if res.status_code != 200:
        logging.error(f'Failed to gets private repo workflows, request to '
                      f'{GET_DISPATCH_WORKFLOWS_URL} failed with error: {str(res.content)}')
        sys.exit(1)

    try:
        workflows = json.loads(res.content)
    except ValueError:
        logging.error('Enable to parse private repo workflows response')
        sys.exit(1)

    workflows = workflows.get('workflow_runs', [])
    return [workflow.get('id') for workflow in workflows]


def main():
    # get github_token parameter
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('--github-token', help='Github token')
    args = arg_parser.parse_args()
    bearer_token = 'Bearer ' + args.github_token

    # get branch name
    branches = tools.run_command("git branch")
    branch_name_reg = re.search(r"\* (.*)", branches)
    branch_name = branch_name_reg.group(1)

    files = get_modified_files(branch_name)

    if is_infrastructure_change(files):
        # get the workflows ids before triggering tye build
        workflow_ids = get_dispatch_workflows_ids(bearer_token, 'master')

        # trigger private build
        payload = {'event_type': f'Trigger private build from content/{branch_name}',
                   'client_payload': {'branch': branch_name, 'is_infra_build': 'True'}}

        res = requests.request("POST",
                               TRIGGER_BUILD_URL,
                               headers={'Accept': 'application/vnd.github.everest-preview+json',
                                        'Authorization': bearer_token},
                               data=json.dumps(payload),
                               verify=False)

        if res.status_code != 204:
            logging.error(f'Failed to trigger private repo build, request to '
                          f'{TRIGGER_BUILD_URL} failed with error: {str(res.content)}')
            sys.exit(1)

        # wait 5 seconds and get the workflow ids again
        time.sleep(5)
        workflow_ids_new = get_dispatch_workflows_ids(bearer_token, 'master')

        # compare with the first workflows list to get the current id
        workflow_id = [x for x in workflow_ids_new if x not in workflow_ids]
        if workflow_id:
            workflow_id = workflow_id[0]
            print(f'Build private repo triggered successfully, workflow id: {workflow_id}\n URL:'
                  f' {WORKFLOW_HTML_URL}/{workflow_id}')

            # write the workflow id to text file to use it in get_private_build_status.py
            with open(PRIVATE_REPO_WORKFLOW_ID_FILE, "w") as f:
                f.write(str(workflow_id))
            sys.exit(0)

    else:
        print('Build private repo skipped')
        sys.exit(0)


if __name__ == "__main__":
    main()
