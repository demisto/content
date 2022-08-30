from demisto_client.demisto_api.rest import ApiException

from demisto_sdk.commands.download.downloader import Downloader
from demisto_sdk.commands.format.format_module import format_manager
from demisto_sdk.commands.generate_docs import generate_playbook_doc
from demisto_sdk.commands.upload.uploader import Uploader
from demisto_sdk.commands.validate.validate_manager import ValidateManager

from os import path
import random

import e2e_tests_utils

# TODO Create a new git Content branch, and work with that branch. And the end: git checkout master, git reset hard
# TODO Review Ido's doc and see if we missed anything.


def test_e2e_demisto_sdk_flow_playbook_testsuite(tmpdir, insecure: bool = False):
    # Importing TestSuite classes from Demisto-SDK, as they are excluded when pip installing the SDK.
    e2e_tests_utils.cli(f'mkdir {tmpdir}/git')
    e2e_tests_utils.git_clone_demisto_sdk(destination_folder=f'{tmpdir}/git/demisto-sdk', sdk_git_branch='testsuite-playbook')
    from TestSuite.repo import Repo
    from TestSuite.playbook import Playbook

    repo = Repo(tmpdir)

    # TODO Remove the random
    pack_name = 'foo_' + str(random.randint(1, 1000))
    pack = repo.create_pack(name=pack_name)
    playbook_name = 'pb_' + pack_name
    playbook: Playbook = pack.create_playbook(name=playbook_name)
    playbook.create_default_playbook(name=playbook_name)
    assert path.exists(f'{tmpdir}/Packs/{pack_name}/Playbooks/{playbook_name}.yml')

    print(f'Trying to upload playbook from {tmpdir}/Packs/{pack_name}/Playbooks/{playbook_name}.yml')
    Uploader(input=f'{tmpdir}/Packs/{pack_name}/Playbooks/{playbook_name}.yml', insecure=True).upload()

    # Preparing updated pack folder
    e2e_tests_utils.cli(f'mkdir {tmpdir}/Packs/{pack_name}_testsuite')

    print(f'Trying to download the updated playbook from {playbook_name} to {tmpdir}/Packs/{pack_name}_testsuite/Playbooks')
    Downloader(output=f'{tmpdir}/Packs/{pack_name}_testsuite', input=[playbook_name], insecure=True).download()
    assert path.exists(f'{tmpdir}/Packs/{pack_name}_testsuite/Playbooks/{playbook_name}.yml')

    print('Generating docs (creating a readme file)'
          f' for the playbook {tmpdir}/Packs/{pack_name}_testsuite/Playbooks/{playbook_name}.yml'
          )
    generate_playbook_doc.generate_playbook_doc(input_path=f'{tmpdir}/Packs/{pack_name}_testsuite/Playbooks/{playbook_name}.yml')
    assert path.exists(f'{tmpdir}/Packs/{pack_name}_testsuite/Playbooks/{playbook_name}_README.md')

    print(f'Formating playbook {tmpdir}/Packs/{pack_name}_testsuite/Playbooks/{playbook_name}.yml')
    format_manager(input=f'{tmpdir}/Packs/{pack_name}_testsuite/Playbooks/{playbook_name}.yml', assume_yes=True)
    print(f'Validating playbook {tmpdir}/Packs/{pack_name}_testsuite/Playbooks/{playbook_name}.yml')
    ValidateManager(file_path=f'{tmpdir}/Packs/{pack_name}_testsuite/Playbooks/{playbook_name}.yml').run_validation()

    print(f'Uploading updated playbook {tmpdir}/Packs/{pack_name}_testsuite/Playbooks/{playbook_name}.yml')
    Uploader(input=f'{tmpdir}/Packs/{pack_name}/Playbooks/{playbook_name}.yml', insecure=True).upload()


def test_e2e_demisto_sdk_flow_playbook_client(tmpdir, insecure: bool = False):
    # TODO Remove the random
    pack_name = 'foo_' + str(random.randint(1, 1000))
    playbook_name = 'pb_' + str(random.randint(1, 1000))

    demisto_client = e2e_tests_utils.connect_to_server(insecure=insecure)
    body = [
        {
            "name": playbook_name,
            "propagationLabels": [
                "all"
            ],
            "tasks": {
                "0": {
                    "id": "0",
                    "unqiueId": "0",
                    "type": "start",
                    "nextTasks": None,
                    "task": {}
                }
            }
        }
    ]

    header_params = {}
    header_params['Accept'] = 'application/json'  # noqa: E501
    header_params['Accept-Encoding'] = 'gzip, deflate, br'
    header_params['Content-Type'] = 'application/json'

    try:
        demisto_client.api_client.call_api(resource_path='/playbook/save', method='POST',
                                           header_params=header_params,
                                           body=body,
                                           )
    except ApiException as ae:
        print(f'*** Failed to create playbook {playbook_name}, reason: {ae}')
        assert False

    # Preparing updated pack folder
    e2e_tests_utils.cli(f'mkdir -p {tmpdir}/Packs/{pack_name}_client')

    print(f'Trying to download the updated playbook from {playbook_name} to {tmpdir}/Packs/{pack_name}_client/Playbooks')
    Downloader(output=f'{tmpdir}/Packs/{pack_name}_client', input=[playbook_name], insecure=True).download()
    assert path.exists(f'{tmpdir}/Packs/{pack_name}_client/Playbooks/{playbook_name}.yml')

    print('Generating docs (creating a readme file)'
          f' for the playbook {tmpdir}/Packs/{pack_name}_client/Playbooks/{playbook_name}.yml'
          )
    generate_playbook_doc.generate_playbook_doc(input_path=f'{tmpdir}/Packs/{pack_name}_client/Playbooks/{playbook_name}.yml')
    assert path.exists(f'{tmpdir}/Packs/{pack_name}_client/Playbooks/{playbook_name}_README.md')

    print(f'Formating playbook {tmpdir}/Packs/{pack_name}_client/Playbooks/{playbook_name}.yml')
    format_manager(input=f'{tmpdir}/Packs/{pack_name}_client/Playbooks/{playbook_name}.yml', assume_yes=True)
    print(f'Validating playbook {tmpdir}/Packs/{pack_name}_client/Playbooks/{playbook_name}.yml')
    ValidateManager(file_path=f'{tmpdir}/Packs/{pack_name}_client/Playbooks/{playbook_name}.yml').run_validation()

    print(f'Uploading updated playbook {tmpdir}/Packs/{pack_name}_client/Playbooks/{playbook_name}.yml')
    Uploader(input=f'{tmpdir}/Packs/{pack_name}/Playbooks/{playbook_name}.yml', insecure=True).upload()
