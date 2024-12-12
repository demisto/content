import json
import os
import tempfile
import zipfile
import git
import pytest

from ValidateContent import CONTENT_REPO_URL, get_extracted_code_filepath, get_file_name_and_contents, get_pack_name, read_json_results, read_pre_commit_results, read_validate_results, run_validate, setup_content_dir, setup_content_repo, strip_ansi_codes, extract_hook_id, extract_file_and_line, get_skipped_hooks, DEFAULT_ERROR_PATTERN


# def test_get_content_modules(tmp_path, requests_mock, monkeypatch):
#     """
#     Given:
#         - Content temp dir to copy the modules to

#     When:
#         - Getting content modules

#     Then:
#         - Verify content modules exist in the temp content dir
#     """
#     requests_mock.get(
#         'https://raw.githubusercontent.com/demisto/content/master/Packs/Base/Scripts'
#         '/CommonServerPython/CommonServerPython.py',
#     )
#     requests_mock.get(
#         'https://raw.githubusercontent.com/demisto/content/master/Packs/Base/Scripts'
#         '/CommonServerPowerShell/CommonServerPowerShell.ps1',
#     )
#     requests_mock.get(
#         'https://raw.githubusercontent.com/demisto/content/master/Tests/demistomock/demistomock.py',
#     )
#     requests_mock.get(
#         'https://raw.githubusercontent.com/demisto/content/master/Tests/demistomock/demistomock.ps1',
#     )
#     requests_mock.get(
#         'https://raw.githubusercontent.com/demisto/content/master/tox.ini',
#     )
#     requests_mock.get(
#         'https://raw.githubusercontent.com/demisto/content/master/Tests/scripts/dev_envs/pytest/conftest.py'
#     )
#     requests_mock.get(
#         'https://raw.githubusercontent.com/demisto/content/master/Config/approved_usecases.json'
#     )
#     requests_mock.get(
#         'https://raw.githubusercontent.com/demisto/content/master/Config/approved_tags.json'
#     )
#     requests_mock.get(
#         'https://raw.githubusercontent.com/demisto/content/master/Config/approved_categories.json'
#     )
#     cached_modules = tmp_path / 'cached_modules'
#     cached_modules.mkdir()
#     monkeypatch.setattr('ValidateContent.CACHED_MODULES_DIR', str(cached_modules))
#     content_tmp_dir = tmp_path / 'content_tmp_dir'
#     content_tmp_dir.mkdir()

#     get_content_modules(str(content_tmp_dir))

#     assert os.path.isfile(content_tmp_dir / 'Packs/Base/Scripts/CommonServerPython/CommonServerPython.py')
#     assert os.path.isfile(content_tmp_dir / 'Packs/Base/Scripts/CommonServerPowerShell/CommonServerPowerShell.ps1')
#     assert os.path.isfile(content_tmp_dir / 'Tests/demistomock/demistomock.py')
#     assert os.path.isfile(content_tmp_dir / 'Tests/demistomock/demistomock.ps1')
#     assert os.path.isfile(content_tmp_dir / 'tox.ini')
#     assert os.path.isfile(content_tmp_dir / 'Tests/scripts/dev_envs/pytest/conftest.py')
#     assert os.path.isfile(content_tmp_dir / 'Config/approved_usecases.json')
#     assert os.path.isfile(content_tmp_dir / 'Config/approved_tags.json')
#     assert os.path.isfile(content_tmp_dir / 'Config/approved_categories.json')


# row_and_column_adjustment_test_data = [
#     (
#         {'message': 'blah'}, {'message': 'blah'}
#     ),
#     (
#         {'message': 'blah', 'row': '1'}, {'message': 'blah', 'row': '1'}
#     ),
#     (
#         {'message': 'blah', 'row': '2'}, {'message': 'blah', 'row': '1'}
#     ),
#     (
#         {'message': 'blah', 'col': '0'}, {'message': 'blah', 'col': '0'}
#     ),
#     (
#         {'message': 'blah', 'col': '1'}, {'message': 'blah', 'col': '0'}
#     ),
#     (
#         {'message': 'blah', 'row': '456'}, {'message': 'blah', 'row': '454'}
#     ),
#     (
#         {'message': 'blah', 'col': '50'}, {'message': 'blah', 'col': '49'}
#     ),
#     (
#         {'message': 'blah', 'row': '30', 'col': '30'}, {'message': 'blah', 'row': '28', 'col': '29'}
#     )
# ]


# @pytest.mark.parametrize('original_validation_result,expected_output', row_and_column_adjustment_test_data)
# def test_adjust_linter_row_and_col(original_validation_result, expected_output):
#     adjust_linter_row_and_col(original_validation_result)
#     # after adjustment, the original validation result should match the expected
#     assert original_validation_result == expected_output


def test_strip_ansi_codes():
    ansi_text = "\033[31mRed text\033[0m"
    assert strip_ansi_codes(ansi_text) == "Red text"

def test_extract_hook_id():
    output = "Running hook: check-ast\n- hook id: check-ast\nAn error occurred"
    assert extract_hook_id(output) == "check-ast"
    assert extract_hook_id("No hook id here") is None

def test_extract_file_and_line():
    output = "Packs/TmpPack/Scripts/MyScript/MyScript.py:10:5: E302 expected 2 blank lines, found 1"
    pattern_obj = DEFAULT_ERROR_PATTERN
    result = extract_file_and_line(output, pattern_obj)
    assert result == [{'file': 'Packs/TmpPack/Scripts/MyScript/MyScript.py', 'line': '10', 'column': '5', 'details': 'E302 expected 2 blank lines, found 1'}]

def test_get_skipped_hooks():
    skipped_hooks = get_skipped_hooks()
    assert isinstance(skipped_hooks, list)
    assert 'validate-deleted-files' in skipped_hooks
    assert 'xsoar-lint' in skipped_hooks

def test_get_pack_name():
    with tempfile.NamedTemporaryFile(suffix='.zip') as tmp_file:
        with zipfile.ZipFile(tmp_file.name, 'w') as zf:
            zf.writestr('metadata.json', json.dumps({"name": "TestPack"}))
        assert get_pack_name(tmp_file.name) == "TestPack"

def test_get_extracted_code_filepath():
    class MockExtractor:
        def __init__(self):
            self.get_output_path = lambda: "/tmp/output"
            self.base_name = "TestScript"
            self.file_type = "integration"
            self.yml_data = {"script": {"type": "python"}}

    extractor = MockExtractor()
    assert get_extracted_code_filepath(extractor) == "/tmp/output/TestScript.py"

def test_run_validate(mocker):
    mock_validate_manager = mocker.patch('ValidateContent.ValidateManager')
    mock_validate_manager.return_value.run_validations.return_value = 0
    
    assert run_validate("/path/to/validate", "/path/to/output.json") == 0
    mock_validate_manager.assert_called_once()

def test_read_json_results(tmp_path):
    json_file = tmp_path / "test_results.json"
    json_file.write_text(json.dumps([{"test": "result1"}, {"test": "result2"}]))
    
    results = read_json_results(json_file)
    assert len(results) == 2
    assert all(item["file_name"] == "test_results" for item in results)

def test_read_validate_results(tmp_path):
    json_file = tmp_path / "validate_results.json"
    json_file.write_text(json.dumps([{
        "validations": [
            {"file path": "test.yml", "error code": "E001", "message": "Test error"}
        ]
    }]))
    
    results = read_validate_results(json_file)
    assert len(results) == 1
    assert results[0].filePath.endswith("test.yml")
    assert results[0].errorType == "E001"

def test_read_pre_commit_results(tmp_path):
    pre_commit_dir = tmp_path / "pre-commit-output"
    pre_commit_dir.mkdir()
    (pre_commit_dir / "test_output.json").write_text(json.dumps([{
        "stdout": "- hook id: xsoar-lint\nPacks/TmpPack/Scripts/MyScript/MyScript.py:15:10: F841 local variable 'unused_var' is assigned to but never used",
        "file_name": "xsoar-lint"
    }]))
    
    results = read_pre_commit_results(pre_commit_dir)
    assert len(results) == 1
    assert results[0].linter == "xsoar-lint"
    assert results[0].filePath == "Packs/TmpPack/Scripts/MyScript/MyScript.py"

def test_setup_content_repo(tmp_path):
    repo = setup_content_repo(str(tmp_path))
    assert isinstance(repo, git.Repo)
    assert "master" in repo.heads
    assert repo.remotes.origin.url == CONTENT_REPO_URL

def test_get_file_name_and_contents(mocker):
    mocker.patch('demisto.getFilePath', return_value={'path': '/tmp/test.txt', 'name': 'test.txt'})
    mocker.patch('builtins.open', mocker.mock_open(read_data=b'test content'))
    
    filename, contents = get_file_name_and_contents(entry_id="entry123")
    assert filename == "test.txt"
    assert contents == b'test content'

def test_setup_content_dir(tmp_path, mocker):
    mocker.patch('ValidateContent.CONTENT_DIR_PATH', str(tmp_path))
    mocker.patch('ValidateContent.setup_content_repo')
    mocker.patch('ValidateContent.get_file_name_and_contents', return_value=('test.yml', b'test: content'))
    mocker.patch('ValidateContent.prepare_single_content_item_for_validation', return_value=('/path/to/validate', {}))
    mocker.patch('ValidateContent.get_content_modules')
    
    result = setup_content_dir('test.yml', 'dGVzdDogY29udGVudA==', None)
    assert result == '/path/to/validate'
