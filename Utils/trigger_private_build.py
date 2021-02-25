import re
import os
import sys
import argparse
import requests
import logging
import json
import time
import demisto_sdk.commands.common.tools as tools

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

INFRASTRUCTURE_FILES = ['Tests/scripts/validate_premium_packs.sh', 'Tests/scripts/validate_premium_packs.py',
                        'Tests/scripts/validate_index.py']

INFRASTRUCTURE_FOLDERS = ['Tests/private_build', 'Tests/Marketplace']

TRIGGER_BUILD_URL = 'https://api.github.com/repos/demisto/content-private/dispatches'
GET_DISPATCH_WORKFLOWS_URL = 'https://api.github.com/repos/demisto/content-private/actions/runs'


def get_changed_files():
    files = []
    branches = tools.run_command("git branch")
    branch_name_reg = re.search(r"\* (.*)", branches)
    branch_name = branch_name_reg.group(1)
    files_string = tools.run_command("git diff --name-status origin/master...{0}".format(branch_name))
    for line in files_string.split("\n"):
        if line:
            _, file_path = line.split(maxsplit=1)
            if file_path:
                files.append(file_path)
    return files


def need_to_trigger_buid(changed_files):
    for file in changed_files:
        if file in INFRASTRUCTURE_FILES:
            return True

        path = os.path.dirname(file)
        for dir in INFRASTRUCTURE_FOLDERS:
            if path.startswith(dir):
                return True
    return False


def get_dispatch_workflows_ids(bearer_token, branch):
    res = requests.request("GET",
                           GET_DISPATCH_WORKFLOWS_URL,
                           headers={'Authorization': bearer_token},
                           params={'branch': branch, 'event': 'repository_dispatch'},
                           verify=False)
    if res.status_code != 200:
        logging.error(
            f'Failed to gets private repo workflows, request to {GET_DISPATCH_WORKFLOWS_URL} failed with error: {str(res.content)}')
        sys.exit(1)

    try:
        workflows = json.loads(res.content)
    except ValueError:
        logging.error('Enable to parse private repo workflows response')
        sys.exit(1)

    workflows = workflows.get('workflow_runs', [])
    return [workflow.get('id') for workflow in workflows]


def main():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('--github-token', help='Github token')
    args = arg_parser.parse_args()

    bearer_token = 'Bearer ' + args.github_token

    files = get_changed_files()
    files = ['Tests/scripts/validate_premium_packs.sh']

    if need_to_trigger_buid(files):
        workflow_ids = get_dispatch_workflows_ids(bearer_token, 'master')

        # trigger private build
        res = requests.request("POST",
                               TRIGGER_BUILD_URL,
                               headers={'Accept': 'application/vnd.github.everest-preview+json', 'Authorization': bearer_token},
                               data='{"event_type":"Trigger build from content"}',
                               verify=False)

        if res.status_code != 204:
            logging.error(f'Failed to trigger private repo build, request to {TRIGGER_BUILD_URL} failed with error: {str(res.content)}')
            sys.exit(1)

        time.sleep(5)

        workflow_ids_new = get_dispatch_workflows_ids(bearer_token, 'master')
        workflow_id = [x for x in workflow_ids_new if x not in workflow_ids]
        if workflow_id:
            workflow_id = workflow_id[0]
            logging.info(f'Build private repo triggered successfully, workflow id: {workflow_id}\n URL:'
                         f' https://github.com/demisto/content-private/actions/runs/{workflow_id}')
            os.environ["PRIVATE_REPO_WORKFLOW_ID"] = str(workflow_id)
            sys.exit(0)

    else:
        logging.info('Build private repo skipped')
        sys.exit(0)


if __name__ == "__main__":
    main()
