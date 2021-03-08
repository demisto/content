import os

from ValidateContent import get_content_modules


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
