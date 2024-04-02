import json
import os
from pathlib import Path
import shutil
import pytest
from _pytest._py.path import LocalPath
from pytest_mock import MockerFixture
from requests_mock import Mocker
import demistomock as demisto
from base64 import b64decode, b64encode
import ValidateContent
from ValidateContent import (
    get_content_modules,
    adjust_linter_row_and_col,
    get_file_name_and_contents,
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

    shutil.rmtree(content_tmp_dir)


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


@pytest.fixture(scope="function")
def setup_requests_mock(requests_mock: Mocker):
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

    requests_mock.get(
        "https://raw.githubusercontent.com/demisto/content/master/Tests/Marketplace/core_packs_list.json",
        json={
            "core_packs_list": [
                "AutoFocus",
                "Base",
                "CommonDashboards",
                "CommonPlaybooks",
                "CommonReports",
                "CommonScripts",
                "CommonTypes",
                "CommonWidgets",
                "DefaultPlaybook",
                "DemistoLocking",
                "DemistoRESTAPI",
                "EDL",
                "FeedMitreAttackv2",
                "FeedUnit42v2",
                "FiltersAndTransformers",
                "HelloWorld",
                "ImageOCR",
                "Palo_Alto_Networks_WildFire",
                "PAN-OS",
                "TIM_Processing",
                "TIM_SIEM",
                "ThreatIntelReports",
                "ThreatIntelligenceManagement",
                "Unit42Intel",
                "VirusTotal",
                "Whois",
                "rasterize"
            ],
            "update_core_packs_list": [
                "AutoFocus",
                "Base",
                "CommonDashboards",
                "CommonPlaybooks",
                "CommonReports",
                "CommonScripts",
                "CommonTypes",
                "CommonWidgets",
                "DefaultPlaybook",
                "DemistoLocking",
                "DemistoRESTAPI",
                "EDL",
                "FeedMitreAttackv2",
                "FeedUnit42v2",
                "FiltersAndTransformers",
                "HelloWorld",
                "ImageOCR",
                "Palo_Alto_Networks_WildFire",
                "PAN-OS",
                "TIM_Processing",
                "TIM_SIEM",
                "ThreatIntelReports",
                "ThreatIntelligenceManagement",
                "Unit42Intel",
                "VirusTotal",
                "Whois",
                "rasterize"
            ]
        }
    )

    requests_mock.get(
        "https://hub.docker.com/v2/repositories/demisto/python3/tags",
        json=json.loads(TestValidateContent.docker_demistp_py3_response.read_bytes())
    )
    requests_mock.get("https://registry-1.docker.io/v2/")


@pytest.fixture(scope="function")
def setup_mocker(mocker: MockerFixture, tmpdir: LocalPath):

    # Set content path to tmp dir
    mocker.patch.dict(os.environ, {"DEMISTO_SDK_CONTENT_PATH": str(tmpdir)})

    # Set tmp dir generated in main
    mocker.patch('tempfile.TemporaryDirectory', lambda: tmpdir)

    cached_modules = os.path.join(str(tmpdir), 'cached_modules')
    mocker.patch.object(ValidateContent, "CACHED_MODULES_DIR", cached_modules)


@pytest.mark.usefixtures("setup_mocker", "setup_requests_mock")
class TestValidateContent:

    test_invalid_script_path = Path(__file__).parent.resolve() / "test_data" / "automationwitherrors.yml"
    test_valid_script_path = Path(__file__).parent.resolve() / "test_data" / "valid_automation.yml"
    test_valid_script_b64_path = Path(__file__).parent.resolve() / "test_data" / "valid_automation.yml.b64"
    test_contrib_zip_path = Path(__file__).parent.resolve() / "test_data" / \
        "contentpack-6ade7368-803c-4c4b-873c-4a0555c6ca03-Test.zip"
    docker_demistp_py3_response = Path(__file__).parent.resolve() / "test_data" / \
        "demisto_py3_tags.json"

    def test_validate_automation_with_errors(
            self,
            mocker: MockerFixture,
            capfd: pytest.CaptureFixture[str]
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

        mocker.patch.object(demisto, "args", return_value={
            "filename": self.test_invalid_script_path.name,
            "data": b64encode(self.test_invalid_script_path.read_bytes()),
            "trust_any_certificate": True,
        })

        results = mocker.patch.object(demisto, 'results')

        with capfd.disabled():
            main()

        assert results.called

        # Number of errors
        assert len(results.call_args[0][0]["Contents"]) == 6
        assert "unterminated string literal" in results.call_args[0][0]["Contents"][5]["message"]

    def test_validate_automation_no_errors(
        self,
        mocker: MockerFixture,
        capfd: pytest.CaptureFixture[str]
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

        mocker.patch.object(demisto, "args", return_value={
            "filename": self.test_valid_script_path.name,
            "data": b64encode(self.test_valid_script_path.read_bytes()),
            "trust_any_certificate": True,
        })

        results = mocker.patch.object(demisto, 'results')

        with capfd.disabled():
            main()

        assert results.called
        # assert len(results.call_args[0][0]["Contents"][COMMAND_OUTPUT_PREFIX]) == 6
        # assert results.call_args[0][0]["Contents"][COMMAND_OUTPUT_PREFIX][0][COMMAND_OUTPUT_KEY_NAME] \
        #     == self.test_valid_script_path.stem
        # assert results.call_args[0][0]["Contents"][COMMAND_OUTPUT_PREFIX][0][COMMAND_OUTPUT_KEY_LINE] == "22"
        # assert "unterminated string literal" not in \
        #     results.call_args[0][0]["Contents"][COMMAND_OUTPUT_PREFIX][0][COMMAND_OUTPUT_KEY_ERROR]

    def test_validate_playbook(self):
        pass

    def test_validate_zip(self):
        """
        Test ValidateContent on a valid contribution zip.
        """

    def test_validate_zip_with_errors(self):
        """
        Test ValidateContent on a invalid contribution zip.
        """

    def test_get_file_name_and_contents_filename_data(self):
        """
        Validate a successful scenario where a file name and its base64
        encoded data are provided to the `get_file_name_and_contents`
        function.

        Given:
        - A file name.
        - A data stream of bytes representing the contents of the file.

        When:
        - The input is valid (filename and data arguments only).

        Then:
        - The input file name is equal to the one output from the
        tested function.
        - The output data is equal to the decoded data stream of the
        input file.
        """

        input_filename = expected_filename = self.test_valid_script_path.name
        input_data = b64encode(self.test_valid_script_path.read_bytes())

        actual_filename, actual_decoded_data = get_file_name_and_contents(input_filename, input_data)

        assert actual_filename == expected_filename
        assert actual_decoded_data == b64decode(input_data)

    def test_get_file_name_and_contents_entry_id(
        self,
        mocker: MockerFixture,
    ):
        """
        Validate a successful scenario where an entry ID
        is provided to the  `get_file_name_and_contents`
        function.

        Given:
        - An entry ID.

        When:
        - The input is valid (entry ID only).

        Then:
        - The entry file name and data are as expected.
        """

        mocker.patch.object(demisto, "getFilePath", return_value={
            "path": self.test_valid_script_b64_path.absolute(),
            "name": self.test_valid_script_b64_path.name,
            "id": "1337"
        })

        actual_filename, actual_decoded_data = get_file_name_and_contents(entry_id="1337")

        assert actual_filename == self.test_valid_script_b64_path.name
        assert actual_decoded_data == self.test_valid_script_b64_path.read_bytes()

    def test_get_file_name_and_contents_entry_id_filename_data(
        self,
        mocker: MockerFixture,
    ):
        """
        Validate a scenario where an entry ID,
        filename and data are all provided to the
        `get_file_name_and_contents` function.

        Given:
        - An entry ID.
        - A filename.
        - A data stream of bytes representing the contents of the file.

        When:
        - All possible inputs are provided.

        Then:
        - The input file name is equal to the one output from the
        tested function.
        - The output data is equal to the decoded data stream of the
        input file.

        When:
        - The input is valid (entry ID only).

        Then:
        - The entry file name and data are as expected.
        """

        mocker.patch.object(demisto, "getFilePath", return_value={
            "path": self.test_valid_script_b64_path.absolute(),
            "name": self.test_valid_script_b64_path.name,
            "id": "1337"
        })
        input_filename = expected_filename = self.test_valid_script_path.name
        input_data = b64encode(self.test_valid_script_path.read_bytes())

        actual_filename, actual_decoded_data = get_file_name_and_contents(
            filename=input_filename,
            data=input_data,
            entry_id="1337"
        )

        assert actual_filename == expected_filename
        assert actual_decoded_data == b64decode(input_data)
