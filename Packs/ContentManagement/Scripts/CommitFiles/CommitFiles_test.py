import os
from pathlib import Path

import demistomock as demisto
from CommitFiles import ContentFile
import pytest
from CommonServerPython import *

content_file = ContentFile()
content_file.file_name = 'hello.py'
content_file.file_text = 'hello world!'
content_file.path_to_file = 'Packs/Hi/Integrations/Folder'


def test_does_file_exist(mocker):
    """
    Given:
        - A branch name and a content file.
    When:
        - In order to know if this file already exists in the repository or not
    Then:
        - Returns True if the file exists and false if it doesn't
    """
    from CommitFiles import does_file_exist
    mocker.patch.object(demisto, 'executeCommand', return_value=[])
    flag = does_file_exist('demisto', content_file)
    assert not flag


@pytest.mark.parametrize('does_exist', [True, False])
def test_does_file_exist_azure_devops(mocker, does_exist):
    """
    Given:
        - A branch name and a content file.
    When:
        - In order to know if this file already exists in the repository or not
    Then:
        - Returns True if the file exists and false if it doesn't
    """
    if does_exist:
        mocker.patch("CommitFiles.files_path", [str(Path(content_file.path_to_file, content_file.file_name))])
    from CommitFiles import searched_file_path
    mocker.patch.object(demisto, 'executeCommand', return_value=[{"Type": 1, "Contents": {}}])
    flag = searched_file_path('demisto', content_file)
    assert does_exist == flag


def test_commit_content_item_azure_devops_cant_find_branch(mocker):
    """
    Given:
        - A branch name and a content file.
    When:
        - Committing the files to azure devops
    Then:
        - Ensure Exception is thrown since branch doesn't exist
    """
    from CommitFiles import commit_content_item_azure_devops
    branch_name = 'demisto'
    mocker.patch.object(demisto, 'executeCommand', return_value=[{"Type": 1, "Contents": {}}])
    with pytest.raises(DemistoException) as e:
        commit_content_item_azure_devops(branch_name, content_file, [], [])
    assert e.value.message == "Failed to find a corresponding branch id to the given branch name."


def test_commit_content_item_azure_devops_creating_file(mocker):
    """
    Given:
        - A branch name and a content file
    When:
        - Committing the files to azure devops
    Then:
        - Ensure the last executeCommand (azure-devops-file-create) called with the expected arguments
    """
    from CommitFiles import commit_content_item_azure_devops
    branch_name = 'demisto'
    request = mocker.patch.object(demisto, 'executeCommand', return_value=[{"Type": 1, "Contents":
                                  {"value": [{"name": "demisto", "objectId": "XXXX", "path": "Test"}]}}])
    commit_content_item_azure_devops(branch_name, content_file, [], [])
    request.assert_called_with('azure-devops-file-create', args={'commit_comment': 'hello.py was added.',
                                                                 'file_path': 'Packs/Hi/Integrations/Folder/hello.py',
                                                                 'branch_name': 'demisto', 'file_content': 'hello world!',
                                                                 'branch_id': 'XXXX'})


def test_commit_content_item_azure_devops_updating_file(mocker):
    """
    Given:
        - A branch name and a content file
    When:
        - Committing the files to azure devops
    Then:
        - Ensure the last executeCommand (azure-devops-file-update) called with the expected arguments
    """
    mocker.patch("CommitFiles.files_path", [str(Path(content_file.path_to_file, content_file.file_name))])
    from CommitFiles import commit_content_item_azure_devops
    branch_name = 'demisto'
    request = mocker.patch.object(demisto, 'executeCommand', return_value=[{"Type": 1, "Contents":
                                  {"value": [{"name": "demisto", "objectId": "XXXX", "path": "Test"}]}}])
    commit_content_item_azure_devops(branch_name, content_file, [], [])
    request.assert_called_with('azure-devops-file-update', args={'commit_comment': 'hello.py was updated.',
                                                                 'file_path': 'Packs/Hi/Integrations/Folder/hello.py',
                                                                 'branch_name': 'demisto', 'file_content': 'hello world!',
                                                                 'branch_id': 'XXXX'})


def test_commit_content_item_bitbucket(mocker):
    """
    Given:
        - A branch name and a content file.
    When:
        - Committing the files to bitbucket
    """
    from CommitFiles import commit_content_item_bitbucket
    branch_name = 'demisto'
    expected_args = {
        'message': f'Added {content_file.file_name}',
        'file_name': f'{content_file.path_to_file}/{content_file.file_name}',
        'branch': f'{branch_name}',
        'file_content': f'{content_file.file_text}'
    }
    request = mocker.patch.object(demisto, 'executeCommand')
    commit_content_item_bitbucket(branch_name, content_file, [], [])
    request.assert_called_with('bitbucket-commit-create', args=expected_args)


list_files = [
    {'_links': {
        'git': 'https://api.github.com/repos/SomeUser/content/git/blobs/1111111111111111111111111111111111111111',
        'html': 'https://github.com/SomeUser/content/blob/Hi_2/Packs/Hi/Integrations/Folder/hello.py',
        'self': 'https://api.github.com/repos/SomeUser/content/contents/Packs/Hi/Integrations/Folder/hello.py?ref'
                '=Hi_2'},
     'download_url': 'https://raw.githubusercontent.com/SomeUser/content/Hi_2/Packs/Hi/Integrations/Folder/hello.py',
     'git_url': 'https://api.github.com/repos/SomeUser/content/git/blobs/1111111111111111111111111111111111111111',
     'html_url': 'https://github.com/SomeUser/content/blob/Hi_2/Packs/Hi/Integrations/Folder/hello.py',
     'name': 'hello.py', 'path': 'Packs/Hi/Integrations/Folder/hello.py',
     'sha': '1111111111111111111111111111111111111111',
     'size': 69305,
     'type': 'file',
     'url': 'https://api.github.com/repos/SomeUser/content/contents/Packs/Hi/Integrations/Folder/hello.py?ref=Hi_2'}
]

result = [{'Contents': list_files, 'Type': 3}]


def test_get_file_sha(mocker):
    """
    Given:
        - A branch name, a content file and a command to perform.
    When:
        - In order to get the file sha.
    Then:
        - Returns The file sha.
    """
    from CommitFiles import get_file_sha
    branch_name = 'demisto'
    mocker.patch.object(demisto, 'executeCommand', return_value=result)
    file_sha = get_file_sha(branch_name, content_file, 'Github-list-files')
    expected_sha = list_files[0].get('sha')
    assert expected_sha == file_sha


files = [
    {
        "Size": 2504,
        "SHA1": "fe3c5c440d9a8297c1c6dfdb316bcbbb1c8ded3e",
        "SHA256": "f0820c96cd19894a2a21404d202d87c926e2ff2da9386729d66a6d1ff5b40aad",
        "SHA512": "3b44b3a48b64d3b069a965e00692e80fe0eb69fbd60e574e8aa3a747e33d1a76508a4799"
                  "2e560fbb17ce40ddbbaf2e45fdb4f8b0a6c1dc2deb8a1d7cc417193f",
        "Name": "automation-NewBranchName.yml",
        "SSDeep": "48:onZUdy98RuUQrJ0re9MV3YSxdidyJlwWkWriI21e+JC0x4w6:v7eJkeGlYSZlA60Xx4F",
        "EntryID": "8@47",
        "Info": "yml",
        "Type": "Python script text executable, ASCII text",
        "MD5": "345686298376c84fbf59edfd3da3fda2",
        "Extension": "yml"
    }
]

user = {"email": "admintest@demisto.com",
        "isAway": False,
        "name": "Admin Dude",
        "phone": "+650-123456",
        "roles": ["demisto: [Administrator]"],
        "username": "admin"}


def test_main(mocker):
    """
    Given:
        - A list of files, a branch name, a pack name, a user, a git integration, a comment (optional) and a template to
            a message (optional).
    When:
        - Committing new files to the git integration.
    Then:
        - Returns A CommandResult object with a success message with information about the committed files.
    """
    from CommitFiles import main
    branch_name = "branch"
    pack_name = "BranchNameScript"
    gitIntegration = "Bitbucket"
    incident_url = demisto.demistoUrls().get('investigation')
    expected_pr_body = f'### Pull Request created in Cortex XSOAR\n**Created by:** {user.get("username")} ' \
                       f'({user.get("email")})\n\n**Pack:** {pack_name}\n\n**Branch:** {branch_name}\n\n' \
                       f'**Link to incident in Cortex XSOAR:** {incident_url}\n\n\n\n\n\n---\n\n### New files\n' \
                       f'- NewBranchName.yml\n- NewBranchName.py'
    mocker.patch.object(
        demisto, 'args', return_value={
            'files': files,
            'branch': branch_name,
            'pack': pack_name,
            'user': user,
            'git_integration': gitIntegration
        }
    )
    mock_file = {
        'id': '7@47',
        'path': 'test_data/automation-NewBranchName.yml',
        'name': 'automation-NewBranchName.yml',
    }
    mocker.patch.object(demisto, 'getFilePath', return_value=mock_file)
    mocker.patch.object(demisto, 'executeCommand')
    moc = mocker.patch.object(demisto, 'results')
    main()
    pr_body = moc.call_args.args[0].get('HumanReadable')
    assert expected_pr_body == pr_body
    delete_files()


def delete_files():
    unified_yml_path = os.path.abspath('automation-NewBranchName.yml')
    # new_dir_path = os.path.abspath('CommitFiles/NewBranchName')
    script_path = os.path.abspath('NewBranchName/NewBranchName.py')
    yml_path = os.path.abspath('NewBranchName/NewBranchName.yml')
    if unified_yml_path:
        os.remove(unified_yml_path)
    if script_path:
        os.remove(script_path)
    if yml_path:
        os.remove(yml_path)


def test_commit_new_content_item_gitlab(mocker):
    """
    Given:
        - A branch name and a content file.
    When:
        - Committing the files to gitlab
    """
    from CommitFiles import commit_content_item_gitlab
    branch_name = 'demisto'
    expected_args = {
        'branch': f'{branch_name}',
        'commit_message': f'Added {content_file.file_name}',
        'file_content': f'{content_file.file_text}',
        'file_path': f'{content_file.path_to_file}/{content_file.file_name}'}
    mocker.patch.object(demisto, 'executeCommand')
    mocker.patch('CommitFiles.execute_command', return_value=(True, expected_args))
    commit_content_item_gitlab(branch_name, content_file, [], [])


def test_update_content_item_gitlab(mocker):
    """
    Given:
        - A branch name and a content file.
    When:
        - Committing the files to gitlab
    """
    from CommitFiles import commit_content_item_gitlab
    branch_name = 'demisto'
    expected_str = 'already exists'
    mocker.patch.object(demisto, 'executeCommand')
    mocker.patch('CommitFiles.execute_command', return_value=(True, expected_str))
    commit_content_item_gitlab(branch_name, content_file, [], [])
