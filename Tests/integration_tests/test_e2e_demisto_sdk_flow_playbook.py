import random

import e2e_tests_utils


def test_e2e_demisto_sdk_flow_playbook(tmpdir, insecure: bool = False):
    # Importing TestSuite classes from Demisto-SDK
    e2e_tests_utils.cli(f'mkdir {tmpdir}/git')
    e2e_tests_utils.git_clone_demisto_sdk(destination_folder=f'{tmpdir}/git/demisto-sdk', sdk_git_branch='testsuite-playbook')

    from TestSuite.playbook import Playbook
    from TestSuite.repo import Repo

    repo = Repo(tmpdir)

    pack_name = 'foo_' + str(random.randint(1, 1000))
    pack = repo.create_pack(name=pack_name)
    playbook_name = 'pb_' + pack_name
    playbook: Playbook = pack.create_playbook(name=playbook_name)
    playbook.create_default_playbook(name=playbook_name)

    print(f'Trying to upload playbook from {tmpdir}/Packs/{pack_name}/Playbooks/{playbook_name}.yml')
    e2e_tests_utils.cli(f'demisto-sdk upload --insecure -i {tmpdir}/Packs/{pack_name}/Playbooks/{playbook_name}.yml')

    # Preparing updated pack folder
    e2e_tests_utils.cli(f'mkdir {tmpdir}/Packs/{pack_name}_updated')

    print(f'Trying to download the updated playbook from {playbook_name} to {tmpdir}/Packs/{pack_name}_updated/Playbooks')
    e2e_tests_utils.cli(f'demisto-sdk download --insecure -i {playbook_name} -o {tmpdir}/Packs/{pack_name}_updated')

    print('Generating docs (creating a readme file)'
          f' for the playbook {tmpdir}/Packs/{pack_name}_updated/Playbooks/{playbook_name}.yml'
          )
    e2e_tests_utils.cli(f'demisto-sdk generate-docs -i {tmpdir}/Packs/{pack_name}_updated/Playbooks/{playbook_name}.yml')

    print(f'Formating playbook {tmpdir}/Packs/{pack_name}_updated/Playbooks/{playbook_name}.yml')
    e2e_tests_utils.cli(f'demisto-sdk format -y -i {tmpdir}/Packs/{pack_name}_updated/Playbooks/{playbook_name}.yml')

    print(f'Validating playbook {tmpdir}/Packs/{pack_name}_updated/Playbooks/{playbook_name}.yml')
    e2e_tests_utils.cli('demisto-sdk validate'
                        ' --no-conf-json'
                        f' -i {tmpdir}/Packs/{pack_name}_updated/Playbooks/{playbook_name}.yml'
                        )

    print(f'Uploading updated playbook {tmpdir}/Packs/{pack_name}_updated/Playbooks/{playbook_name}.yml')
    e2e_tests_utils.cli(f'demisto-sdk upload --insecure -i {tmpdir}/Packs/{pack_name}_updated/Playbooks/{playbook_name}.yml')
