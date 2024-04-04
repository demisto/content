import os
from pathlib import Path
import shutil
import pytest
from pytest_mock import MockerFixture
import demistomock as demisto
from base64 import b64decode, b64encode
from ValidateContent import (
    get_content_modules,
    adjust_linter_row_and_col,
    get_file_name_and_contents,
    prepare_single_content_item_for_validation,
)
from demisto_sdk.commands.common.constants import (
    PACKS_PACK_META_FILE_NAME,
    PACKS_FOLDER,
    BASE_PACK,
    SCRIPTS_DIR,
    SCRIPTS_README_FILE_NAME
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


class CommonTestResources:
    valid_script_path = Path(__file__).parent.resolve() / "test_data" / "valid_automation.yml"
    invalid_script_path = Path(__file__).parent.resolve() / "test_data" / "automationwitherrors.yml"
    invalid_yml_script_path = Path(__file__).parent.resolve() / "test_data" / "invalid_script_yml.yml"
    valid_script_b64_path = Path(__file__).parent.resolve() / "test_data" / "valid_automation.yml.b64"
    valid_playbook_path = Path(__file__).parent.resolve() / "test_data" / "valid_pb.yml"
    contrib_zip_path = Path(__file__).parent.resolve() / "test_data" / \
        "contentpack-6ade7368-803c-4c4b-873c-4a0555c6ca03-Test.zip"


class TestPrepareForValidation:
    """
    Test class for the following methods:
    - `prepare_single_content_item_for_validation`
    - `prepare_content_pack_for_validation`
    """

    def _setup(self, tmp_path: Path):

        Path(tmp_path, PACKS_FOLDER, BASE_PACK).mkdir(parents=True)
        Path(tmp_path, PACKS_FOLDER, BASE_PACK, PACKS_PACK_META_FILE_NAME).touch()

    def test_valid_script(self, tmp_path: Path):
        """
        Test a valid script preparation.

        Given:
        - A script.

        When:
        - The script is valid.

        Then:
        - The output path is as expected.
        - The input script file is removed.
        """

        self._setup(tmp_path)

        script_name = "ValidAutomation"
        input_filename = CommonTestResources.valid_script_path.name
        input_bytes = CommonTestResources.valid_script_path.read_bytes()

        actual_output_path, _ = prepare_single_content_item_for_validation(
            filename=input_filename,
            data=input_bytes,
            tmp_directory=str(tmp_path)
        )

        assert actual_output_path == Path(tmp_path, PACKS_FOLDER, BASE_PACK, SCRIPTS_DIR, script_name)
        assert actual_output_path.exists()
        assert Path(actual_output_path, f"{script_name}.yml").exists()
        assert Path(actual_output_path, f"{script_name}.py").exists()
        assert Path(actual_output_path, SCRIPTS_README_FILE_NAME).exists()
        assert not Path(tmp_path, input_filename).exists()

    def test_invalid_script(self, tmp_path: Path):
        """
        Test an invalid script preparation.

        Given:
        - A script.

        When:
        - The script is invalid.

        Then:
        - The output path is as expected.
        - The input script file is removed.
        """

        self._setup(tmp_path)

        script_name = "Automationwitherrors"
        input_filename = CommonTestResources.invalid_script_path.name
        input_bytes = CommonTestResources.invalid_script_path.read_bytes()

        actual_output_path, _ = prepare_single_content_item_for_validation(
            filename=input_filename,
            data=input_bytes,
            tmp_directory=str(tmp_path)
        )

        assert actual_output_path == Path(tmp_path, PACKS_FOLDER, BASE_PACK, SCRIPTS_DIR, script_name)
        assert actual_output_path.exists()
        assert Path(actual_output_path, f"{script_name}.yml").exists()
        assert Path(actual_output_path, f"{script_name}.py").exists()
        assert Path(actual_output_path, SCRIPTS_README_FILE_NAME).exists()
        assert not Path(tmp_path, input_filename).exists()

    def test_invalid_yml_script(self, tmp_path: Path):
        """
        Test an invalid script preparation.

        Given:
        - A script.

        When:
        - The script is not valid YML.

        Then:
        - A `ValueError` is raised.
        """

        self._setup(tmp_path)

        input_filename = CommonTestResources.invalid_yml_script_path.name
        input_bytes = CommonTestResources.invalid_yml_script_path.read_bytes()

        with pytest.raises(
            ValueError,
            match=f"Could not parse file type from file '{os.path.join(str(tmp_path), input_filename)}'"
        ):
            prepare_single_content_item_for_validation(
                filename=input_filename,
                data=input_bytes,
                tmp_directory=str(tmp_path)
            )

    def test_valid_playbook(self, tmp_path: Path):
        """
        Test a valid playbook preparation.

        Given:
        - A playbook.

        When:
        - The playbook is valid.

        Then:
        - A `NotImplementedError` is raised.
        """

        self._setup(tmp_path)

        input_filename = CommonTestResources.valid_playbook_path.name
        input_bytes = CommonTestResources.valid_playbook_path.read_bytes()

        with pytest.raises(
            NotImplementedError,
            match="Validation for file type 'playbook' is not supported"
        ):
            prepare_single_content_item_for_validation(
                filename=input_filename,
                data=input_bytes,
                tmp_directory=str(tmp_path)
            )

    def test_non_existing_dir(self):
        """
        Test what happens when a non-existing directory
        is provided to `prepare_single_content_item_for_validation`.

        Given:
        - A directory.

        When:
        - The the directory doesn't exist.

        Then:
        - A `FileNotFoundError` is raised.
        """

        input_filename = CommonTestResources.valid_playbook_path.name
        input_bytes = CommonTestResources.valid_playbook_path.read_bytes()
        input_dir = '/non/existing/dir'

        with pytest.raises(
            FileNotFoundError,
            match=f"The directory '{input_dir}' doesn't exist"
        ):
            prepare_single_content_item_for_validation(
                filename=input_filename,
                data=input_bytes,
                tmp_directory=input_dir
            )


class TestFilenameContents:
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

        input_filename = expected_filename = CommonTestResources.valid_script_path.name
        input_data = b64encode(CommonTestResources.valid_script_path.read_bytes())

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
            "path": CommonTestResources.valid_script_b64_path.absolute(),
            "name": CommonTestResources.valid_script_b64_path.name,
            "id": "1337"
        })

        actual_filename, actual_decoded_data = get_file_name_and_contents(entry_id="1337")

        assert actual_filename == CommonTestResources.valid_script_b64_path.name
        assert actual_decoded_data == CommonTestResources.valid_script_b64_path.read_bytes()

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
            "path": CommonTestResources.valid_script_b64_path.absolute(),
            "name": CommonTestResources.valid_script_b64_path.name,
            "id": "1337"
        })
        input_filename = expected_filename = CommonTestResources.valid_script_path.name
        input_data = b64encode(CommonTestResources.valid_script_path.read_bytes())

        actual_filename, actual_decoded_data = get_file_name_and_contents(
            filename=input_filename,
            data=input_data,
            entry_id="1337"
        )

        assert actual_filename == expected_filename
        assert actual_decoded_data == b64decode(input_data)
