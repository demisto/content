import os
import pytest

from ValidateContent import get_content_modules, adjust_linter_row_and_col


def test_get_content_modules(tmp_path, requests_mock, monkeypatch):
    """
    Given:
        - Content temp dir to copy the modules to

    When:
        - Getting content modules

    Then:
        - Verify content modules exist in the temp content dir
    """
    requests_mock.get(
        'https://raw.githubusercontent.com/demisto/content/master/Packs/Base/Scripts'
        '/CommonServerPython/CommonServerPython.py',
    )
    requests_mock.get(
        'https://raw.githubusercontent.com/demisto/content/master/Packs/Base/Scripts'
        '/CommonServerPowerShell/CommonServerPowerShell.ps1',
    )
    requests_mock.get(
        'https://raw.githubusercontent.com/demisto/content/master/Tests/demistomock/demistomock.py',
    )
    requests_mock.get(
        'https://raw.githubusercontent.com/demisto/content/master/Tests/demistomock/demistomock.ps1',
    )
    requests_mock.get(
        'https://raw.githubusercontent.com/demisto/content/master/tox.ini',
    )
    requests_mock.get(
        'https://raw.githubusercontent.com/demisto/content/master/Tests/scripts/dev_envs/pytest/conftest.py'
    )
    requests_mock.get(
        'https://raw.githubusercontent.com/demisto/content/master/Tests/Marketplace/approved_usecases.json'
    )
    requests_mock.get(
        'https://raw.githubusercontent.com/demisto/content/master/Tests/Marketplace/approved_tags.json'
    )
    cached_modules = tmp_path / 'cached_modules'
    cached_modules.mkdir()
    monkeypatch.setattr('ValidateContent.CACHED_MODULES_DIR', str(cached_modules))
    content_tmp_dir = tmp_path / 'content_tmp_dir'
    content_tmp_dir.mkdir()

    get_content_modules(str(content_tmp_dir))

    assert os.path.isfile(content_tmp_dir / 'Packs/Base/Scripts/CommonServerPython/CommonServerPython.py')
    assert os.path.isfile(content_tmp_dir / 'Packs/Base/Scripts/CommonServerPowerShell/CommonServerPowerShell.ps1')
    assert os.path.isfile(content_tmp_dir / 'Tests/demistomock/demistomock.py')
    assert os.path.isfile(content_tmp_dir / 'Tests/demistomock/demistomock.ps1')
    assert os.path.isfile(content_tmp_dir / 'tox.ini')
    assert os.path.isfile(content_tmp_dir / 'Tests/scripts/dev_envs/pytest/conftest.py')
    assert os.path.isfile(content_tmp_dir / 'Tests/Marketplace/approved_usecases.json')
    assert os.path.isfile(content_tmp_dir / 'Tests/Marketplace/approved_tags.json')


row_and_column_adjustment_test_data = [
    (
        {'message': 'blah'}, {'message': 'blah'}
    ),
    (
        {'message': 'blah', 'row': '1'}, {'message': 'blah', 'row': '1'}
    ),
    (
        {'message': 'blah', 'row': '2'}, {'message': 'blah', 'row': '1'}
    ),
    (
        {'message': 'blah', 'col': '0'}, {'message': 'blah', 'col': '0'}
    ),
    (
        {'message': 'blah', 'col': '1'}, {'message': 'blah', 'col': '0'}
    ),
    (
        {'message': 'blah', 'row': '456'}, {'message': 'blah', 'row': '454'}
    ),
    (
        {'message': 'blah', 'col': '50'}, {'message': 'blah', 'col': '49'}
    ),
    (
        {'message': 'blah', 'row': '30', 'col': '30'}, {'message': 'blah', 'row': '28', 'col': '29'}
    )
]


@pytest.mark.parametrize('original_validation_result,expected_output', row_and_column_adjustment_test_data)
def test_adjust_linter_row_and_col(original_validation_result, expected_output):
    adjust_linter_row_and_col(original_validation_result)
    # after adjustment, the original validation result should match the expected
    assert original_validation_result == expected_output
