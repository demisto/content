import demistomock as demisto
from CommitFiles import ContentFile

content_file = ContentFile()
content_file.file_name = 'hello'
content_file.file_text = 'hello world!'
content_file.path_to_file = 'Packs/ContentManagement/Scripts/CommitFiles'


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
