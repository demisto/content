
from demisto_sdk.commands.download.downloader import Downloader
from demisto_sdk.commands.format.format_module import format_manager
from demisto_sdk.commands.generate_docs import generate_playbook_doc
from demisto_sdk.commands.upload.uploader import Uploader
from demisto_sdk.commands.validate.validate_manager import ValidateManager

from os import path
import random

import e2e_tests_utils

# TODO Create another test, with a playbook that was created in the server with demisto-py

# TODO Create a new git Content branch, and work with that branch. And the end: git checkout master, git reset hard
# TODO Review Ido's doc and see if we missed anything.

def test_e2e_demisto_sdk_flow_playbook(tmpdir, insecure: bool = False):
    # Importing TestSuite classes from Demisto-SDK
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
    e2e_tests_utils.cli(f'mkdir {tmpdir}/Packs/{pack_name}_updated')

    print(f'Trying to download the updated playbook from {playbook_name} to {tmpdir}/Packs/{pack_name}_updated/Playbooks')
    Downloader(output=f'{tmpdir}/Packs/{pack_name}_updated', input=[playbook_name], insecure=True).download()
    assert path.exists(f'{tmpdir}/Packs/{pack_name}_updated/Playbooks/{playbook_name}.yml')

    print('Generating docs (creating a readme file)'
          f' for the playbook {tmpdir}/Packs/{pack_name}_updated/Playbooks/{playbook_name}.yml'
          )
    generate_playbook_doc.generate_playbook_doc(input_path=f'{tmpdir}/Packs/{pack_name}_updated/Playbooks/{playbook_name}.yml')
    assert path.exists(f'{tmpdir}/Packs/{pack_name}_updated/Playbooks/{playbook_name}_README.md')

    print(f'Formating playbook {tmpdir}/Packs/{pack_name}_updated/Playbooks/{playbook_name}.yml')
    format_manager(input=f'{tmpdir}/Packs/{pack_name}_updated/Playbooks/{playbook_name}.yml',assume_yes=True)
    print(f'Validating playbook {tmpdir}/Packs/{pack_name}_updated/Playbooks/{playbook_name}.yml')
    ValidateManager(file_path=f'{tmpdir}/Packs/{pack_name}_updated/Playbooks/{playbook_name}.yml').run_validation()

    print(f'Uploading updated playbook {tmpdir}/Packs/{pack_name}_updated/Playbooks/{playbook_name}.yml')
    Uploader(input=f'{tmpdir}/Packs/{pack_name}/Playbooks/{playbook_name}.yml', insecure=True).upload()
