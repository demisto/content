import demistomock as demisto
from CommitFiles import ContentFile

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
    commit_content_item_bitbucket(branch_name, content_file)
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
