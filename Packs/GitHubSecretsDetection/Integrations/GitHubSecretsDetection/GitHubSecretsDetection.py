import demistomock as demisto
from CommonServerPython import *  # noqa: F401

"""GitHubSecretsDetection Integration for Cortex XSOAR (aka Demisto)
"""


import base64
import datetime
import json
import os
import re
import shutil
import subprocess
import traceback
from typing import Dict, List, Tuple

import git
import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(self, github_deploy, git_remote_url, access_token, branch, num_commits, config,
                 verify=False, proxy=False, ok_codes=tuple(), headers=None):
        git_remote_url_tuples = git_remote_url.replace('.git', '').split('/')
        base_url = f'https://{git_remote_url_tuples[2]}/api/v3/repos/{"/".join(git_remote_url_tuples[3:])}'
        if github_deploy == 'GitHub.com':
            base_url = f'https://api.{git_remote_url_tuples[2]}/repos/{"/".join(git_remote_url_tuples[3:])}'
        super().__init__(base_url, verify=verify, proxy=proxy, ok_codes=ok_codes, headers=headers)

        self.git_remote_url = git_remote_url
        if access_token:
            self.git_clone_remote_url = git_remote_url.replace('https://', f'https://{access_token}@')
        else:
            self.git_clone_remote_url = git_remote_url
        self.repo_name = "/".join(git_remote_url_tuples[3:])
        self.access_token = access_token
        self.branch = branch
        self.num_commits = num_commits
        self.api_timeout = 60
        self.working_directory = \
            f"/{str(base64.urlsafe_b64encode('/'.join(git_remote_url_tuples[2:]).encode('utf-8')), 'utf-8')}"
        if len(self.working_directory) > 250:
            return_error(f'working directory name is too long')

        self.file_path_patterns = {}
        self.file_extension_patterns = {}
        self.trufflehog_patterns = {}
        try:
            config = json.loads(config)
            if isinstance(config, dict):
                self.file_path_patterns = config.get("file-path", {})
                self.file_extension_patterns = config.get("file-extension", {})
                self.trufflehog_patterns = config.get("trufflehog", {})
        except Exception as e:
            return_error(f'fail to load config json: {e}')

    def get_remote_branch_head(self):
        """
        Get the head commit hash of a branch remotely
        """
        head = self._http_request(
            method='GET',
            url_suffix=f'/git/refs/heads/{self.branch}',
            timeout=self.api_timeout
        )
        if "object" in head and 'sha' in head['object']:
            return head['object']['sha']
        raise Exception(f'cannot find the git commit hash, response: {head}')


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: Git API client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    try:
        client.get_remote_branch_head()
        return 'ok'
    except Exception as e:
        raise e


def fetch_incidents(client: Client, last_run: Dict[str, str]) -> Tuple[Dict[str, str], List[dict]]:
    """This function retrieves new alerts every interval (default is 1 minute).

    This function has to implement the logic of making sure that incidents are
    fetched only onces and no incidents are missed. By default it's invoked by
    XSOAR every minute. It will use last_run to save the git commit hash of the
    last incident it processed. If last_run is not provided, it should use the
    maximum number of commits to determine where to start.

    :type client: ``Client``
    :param Client: Git API client to use

    :type last_run: ``Optional[Dict[str, str]]``
    :param last_run:
        A dict with a key containing the latest incident git commit hash

    :return:
        A tuple containing two elements:
            next_run (``Dict[str, str]``): Contains the git commit hash that will be
                    used in ``last_run`` on the next fetch.
            incidents (``List[dict]``): List of incidents that will be created in XSOAR

    :rtype: ``Tuple[Dict[str, str], List[dict]]``
    """
    commit = last_run.get('commit', None)
    remote_commit = client.get_remote_branch_head()

    if remote_commit == commit:
        # return early if the commit is the same
        demisto.debug(f'skipping due to the same commit hash: {remote_commit}')
        return last_run, []

    demisto.info(f'different commit hash: {remote_commit} != {commit}')

    # otherwise, we clone the repo with the max depth
    repo = None
    if os.path.exists(client.working_directory):
        repo = git.Repo(client.working_directory)
        repo.remotes.origin.pull()
    else:
        repo = git.Repo.clone_from(client.git_clone_remote_url, client.working_directory)

    repo.git.checkout(client.branch)
    repo.git.reset('--hard', f'origin/{client.branch}')
    hashes = repo.git.log(f'-{client.num_commits}', '--pretty=format:%H').split('\n')

    commits = {}
    for c in list(repo.iter_commits(client.branch, max_count=client.num_commits + 1)):
        commits[c.hexsha] = c

    # if the last commit is in this list, we use it, otherwise we pick the earliest one
    from_commit = commit
    try:
        idx = hashes.index(commit)
        hashes = hashes[:idx]
    except ValueError:
        from_commit = hashes[-1]
        hashes = hashes[:-1]
    latest_commit = repo.heads[client.branch].commit.hexsha

    # write the trufflehog json
    trufflehog_json = '/tmp/trufflehog.json'
    with open(trufflehog_json, 'w') as f:
        f.write(json.dumps(client.trufflehog_patterns))

    # run trufflehog here
    commits_secrets = {}
    cmd = [
        '/usr/local/bin/trufflehog',
        '--regex',
        '--entropy',
        'False',
        '--rules',
        trufflehog_json,
        '--since_commit',
        from_commit,
        '--max_depth',
        str(client.num_commits),
        '--json',
        client.working_directory
    ]
    demisto.info(f'running trufflehog: {" ".join(cmd)}')
    try:
        with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as p:
            for line in p.stdout:
                secret = json.loads(line)
                commit_hash = secret['commitHash']
                if commit_hash not in commits_secrets:
                    commits_secrets[commit_hash] = []
                for stringFound in secret['stringsFound']:
                    commits_secrets[commit_hash].append({
                        'source': 'trufflehog',
                        'date': secret['date'],
                        'path': secret['path'],
                        'type': secret['reason'],
                        'location': stringFound
                    })
    except Exception as e:
        demisto.error(f'error in processing json: {e}')
        return last_run, []

    demisto.info("done running trufflehog")

    if hashes:
        demisto.info(f'running file path check from {hashes[-1]} to {hashes[0]}')
    else:
        demisto.info(f'not running file path check')
    for i in range(len(hashes) - 1, -1, -1):
        commit_hash = hashes[i]
        diff = repo.git.show('--name-only', '--pretty=', commit_hash).split('\n')
        if diff:
            ts = datetime.datetime.fromtimestamp(commits[commit_hash].committed_date).strftime('%Y-%m-%d %H:%M:%S')
            for d in diff:
                if d:
                    matched = False
                    # do the extension check
                    _, extension = os.path.splitext(d)
                    extension = extension.replace('.', '')
                    if extension:
                        extension_patterns = client.file_extension_patterns.get(extension, {})
                        for name, pattern in extension_patterns.items():
                            if re.search(pattern, d, re.IGNORECASE):
                                if commit_hash not in commits_secrets:
                                    commits_secrets[commit_hash] = []
                                commits_secrets[commit_hash].append({
                                    'source': 'file-extension',
                                    'date': ts,
                                    'path': d,
                                    'type': name,
                                    'location': pattern
                                })
                                matched = True
                                break

                    # do the path check
                    if not matched:
                        for name, pattern in client.file_path_patterns.items():
                            if re.search(pattern, d, re.IGNORECASE):
                                if commit_hash not in commits_secrets:
                                    commits_secrets[commit_hash] = []
                                commits_secrets[commit_hash].append({
                                    'source': 'file-path',
                                    'date': ts,
                                    'path': d,
                                    'type': name,
                                    'location': pattern
                                })
                                matched = True
                                break

    demisto.info("done running file path check")

    incidents = []
    for commit_hash, secrets in commits_secrets.items():
        incidents.append({
            'name': f'{client.repo_name}: Git commit {commit_hash[:12]} has {len(secrets)} secrets detected',
            'type': 'GitHub Secret',
            'occurred': datetime.datetime.fromtimestamp(
                commits[commit_hash].committed_date).strftime('%Y-%m-%dT%H:%M:%SZ'),
            'severity': 3,
            'details': f'{len(secrets)} potential secrets or file path violations were detected for the repository '
            + f'{client.repo_name} in the commit {commit_hash}.',
            'CustomFields': {
                'githubsecrets': secrets,
                'githubcommiturl': f'{client.git_remote_url}/commit/{commit_hash}',
                'githubcommitauthorname': commits[commit_hash].author.name,
                'githubcommitauthoremail': commits[commit_hash].author.email
            }
        })

    # Save the next_run as a dict with the last_fetch key to be stored
    next_run = {'commit': latest_commit}
    demisto.info(f'{next_run}')
    return next_run, incidents


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    access_token = demisto.params().get('access_token')
    github_deploy = demisto.params().get('github_deploy')
    git_remote_url = demisto.params().get('git_remote_url')
    branch = demisto.params().get('branch')
    config = demisto.params().get('config', '{}')

    num_commits = 100
    try:
        num_commits = int(demisto.params().get('num_commits', '100'))
    except ValueError:
        return_error('Maximum number of commits to check secrets needs to be an integer')

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        headers = None
        if access_token:
            headers = {
                'Authorization': f'Bearer {access_token}'
            }
        client = Client(
            github_deploy,
            git_remote_url,
            access_token,
            branch,
            num_commits,
            config,
            ok_codes=(200,),
            headers=headers)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif demisto.command() == 'fetch-incidents':
            next_run, incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),  # getLastRun() gets the last run dict
            )
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
