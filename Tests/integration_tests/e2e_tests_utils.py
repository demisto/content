
from pathlib import Path
import subprocess
import sys
import tempfile

import demisto_client
from demisto_sdk.commands.common.tools import (get_demisto_version,
                                              )

class e2e_tests_utils:

    def git_clone_demisto_sdk(destination_folder: str, sdk_git_branch: str = 'master'):
        '''Clone demisto-sdk from GitHub and add it to sys.path
        '''
        git_clone_command = f'git -C {destination_folder} clone -b {sdk_git_branch} --single-branch --depth 1 https://github.com/demisto/demisto-sdk.git'
        print(f' Cloning demisto-sdk with: {git_clone_command}')
        e2e_tests_utils.cli(git_clone_command)
        sys.path.insert(1, f'{destination_folder}/demisto-sdk')

    def cli(command) -> subprocess.CompletedProcess:
        if command:
            run_req = None
            if type(command) == type(''):
                run_req = str(command).split(' ')
            if type(command) == type([]):
                run_req = command
            ret_value: subprocess.CompletedProcess = subprocess.run(run_req)
            ret_value.check_returncode()
            return ret_value


    def connect_to_server(insecure: bool = False):
        verify = (not insecure) if insecure else None  # set to None so demisto_client will use env var DEMISTO_VERIFY_SSL
        client = demisto_client.configure(verify_ssl=verify)
        demisto_version = get_demisto_version(client)
        if demisto_version == "0":
            raise Exception('Could not connect to XSOAR server. Try checking your connection configurations.')
        return client


