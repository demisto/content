import os
from pathlib import Path
import pytest
from _pytest._py.path import LocalPath
from pytest_mock import MockerFixture
from requests_mock import Mocker
import demistomock as demisto
from base64 import b64encode

import ValidateContent
from ValidateContent import (
    CACHED_MODULES_DIR,
    COMMAND_OUTPUT_KEY_ERROR,
    COMMAND_OUTPUT_KEY_LINE,
    COMMAND_OUTPUT_KEY_NAME,
    COMMAND_OUTPUT_PREFIX,
    get_content_modules,
    adjust_linter_row_and_col,
    main,
)


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
    requests_mock.get(
        'https://raw.githubusercontent.com/demisto/content/master/Tests/Marketplace/approved_categories.json'
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
    assert os.path.isfile(content_tmp_dir / 'Tests/Marketplace/approved_categories.json')


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


class TestValidateContent:

    test_invalid_script_path = Path(__file__).parent.resolve() / "test_data" / "automationwitherrors.yml"
    test_valid_script_path = Path(__file__).parent.resolve() / "test_data" / "valid_automation.yml"
    test_contrib_zip_path = Path(__file__).parent.resolve() / "test_data" / \
        "contentpack-6ade7368-803c-4c4b-873c-4a0555c6ca03-Test.zip"
        
    def _setup(
        self,
        mocker: MockerFixture,
        requests_mock: Mocker,
        tmpdir: LocalPath
    ):
        # Set content path to tmp dir
        mocker.patch.dict(os.environ, {"DEMISTO_SDK_CONTENT_PATH": str(tmpdir)})

        # Set tmp dir generated in main
        mocker.patch('tempfile.TemporaryDirectory', lambda: tmpdir)

        # Mock requests for necessary modules
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
        requests_mock.get(
            'https://raw.githubusercontent.com/demisto/content/master/Tests/Marketplace/approved_categories.json'
        )
        cached_modules = os.path.join(str(tmpdir), 'cached_modules')
        mocker.patch.object(ValidateContent, 'CACHED_MODULES_DIR', return_value=cached_modules)

        # Mock request for Docker
        requests_mock.get(
            'https://raw.githubusercontent.com/demisto/dockerfiles/master/docker/deprecated_images.json',
            json=[
                {
                    "created_time_utc": "2022-05-31T17:51:17.226278Z",
                    "image_name": "demisto/aiohttp",
                    "reason": "Use the demisto/py3-tools docker image instead."
                }
            ]
        )

    def test_validate_automation_with_errors(
            self,
            mocker: MockerFixture,
            requests_mock: Mocker,
            tmpdir: LocalPath
    ):
        """
        Test ValidateContent on a script with a SyntaxError.

        Given:
        - A script YML.

        When:
        - The script has a SyntaxError.

        Then:
        - The script results should include an error.
        """

        self._setup(mocker, requests_mock, tmpdir)

        mocker.patch.object(demisto, "args", return_value={
            "filename": self.test_invalid_script_path.name,
            "data": b64encode(self.test_invalid_script_path.read_bytes()),
            "trust_any_certificate": True,
        })

        results = mocker.patch.object(demisto, 'results')
        main()

        assert results.called
        assert len(results.call_args[0][0]["EntryContext"][COMMAND_OUTPUT_PREFIX]) == 1
        assert results.call_args[0][0]["EntryContext"][COMMAND_OUTPUT_PREFIX][0][COMMAND_OUTPUT_KEY_NAME] \
            == self.test_invalid_script_path.stem
        assert results.call_args[0][0]["EntryContext"][COMMAND_OUTPUT_PREFIX][0][COMMAND_OUTPUT_KEY_LINE] == "41"
        assert "unterminated string literal" in \
            results.call_args[0][0]["EntryContext"][COMMAND_OUTPUT_PREFIX][0][COMMAND_OUTPUT_KEY_ERROR]

    # FIXME this test currently fails because https://jira-dc.paloaltonetworks.com/browse/CIAC-10138
    @pytest.mark.xfail
    def test_validate_automation_no_errors(
        self,
        mocker: MockerFixture,
        requests_mock: Mocker,
        tmpdir: LocalPath
    ):
        """
        Test ValidateContent on a valid script.

        Given:
        - A script YML.

        When:
        - The script is valid.

        Then:
        - The script results should not have any errors
        """

        self._setup(mocker, requests_mock, tmpdir)

        mocker.patch.object(demisto, "args", return_value={
            "filename": self.test_valid_script_path.name,
            "data": b64encode(self.test_valid_script_path.read_bytes()),
            "trust_any_certificate": True,
        })

        results = mocker.patch.object(demisto, 'results')
        main()

        assert results.called
        assert len(results.call_args[0][0]["EntryContext"][COMMAND_OUTPUT_PREFIX]) == 1
        assert results.call_args[0][0]["EntryContext"][COMMAND_OUTPUT_PREFIX][0][COMMAND_OUTPUT_KEY_NAME] \
            == self.test_invalid_script_path.stem
        assert results.call_args[0][0]["EntryContext"][COMMAND_OUTPUT_PREFIX][0][COMMAND_OUTPUT_KEY_LINE] == "41"
        assert "unterminated string literal" in \
            results.call_args[0][0]["EntryContext"][COMMAND_OUTPUT_PREFIX][0][COMMAND_OUTPUT_KEY_ERROR]

    def test_validate_valid_script(self):
        pass

    def test_validate_invalid_script(self):
        pass

    def test_validate_valid_playbook(self):
        pass

    def test_validate_invalid_playbook(self):
        pass

    def test_validate_zip(self):
        """
        Test ValidateContent on a valid contribution zip.
        """

    def test_validate_zip_with_errors(self):
        """
        Test ValidateContent on a invalid contribution zip.
        """
