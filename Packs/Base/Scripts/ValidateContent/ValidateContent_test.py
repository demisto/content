import json
import os
import tempfile
import zipfile
from unittest.mock import MagicMock, mock_open, patch
import git
import pytest
import json
import zipfile
import pytest
from unittest import mock
from io import BytesIO
from ValidateContent import get_pack_name, BRANCH_MASTER
from ValidateContent import resolve_entity_type, CONTENT_REPO_URL, HOOK_ID_TO_PATTERN, get_extracted_code_filepath, \
    get_file_name_and_contents, get_pack_name, read_json_results, read_pre_commit_results, read_validate_results, run_validate, \
    setup_content_dir, setup_content_repo, strip_ansi_codes, extract_hook_id, parse_pre_commit_output, get_skipped_hooks, \
    DEFAULT_ERROR_PATTERN

import demistomock as demisto  # noqa: F401


def create_mock_zip_file_with_metadata(metadata_content):
    """
    Helper function to create a mock zip file with metadata.json

    Args:
        metadata_content:

    Returns:
        mock_zip: a mock zip file with metadata.json containing metadata_content.
    """

    mock_zip = mock.MagicMock()
    mock_metadata_file = BytesIO(json.dumps(metadata_content).encode('utf-8'))

    def mock_open(name, *args, **kwargs):
        if name == 'metadata.json':
            return mock_metadata_file
        raise KeyError(f"No such file: {name}")

    mock_zip.open = mock_open
    return mock_zip


def test_strip_ansi_codes():
    ansi_text = "\033[31mRed text\033[0m"
    assert strip_ansi_codes(ansi_text) == "Red text"


def test_extract_hook_id():
    output = "Running hook: check-ast\n- hook id: check-ast\nAn error occurred"
    assert extract_hook_id(output) == "check-ast"
    assert extract_hook_id("No hook id") is None


def test_parse_pre_commit_output_check_ast():
    output = """check python ast.........................................................Failed
- hook id: check-ast
- exit code: 1

Packs/TmpPack/Integrations/HelloWorldTest/HelloWorldTest.py: failed parsing with CPython 3.11.10:

 Traceback (most recent call last):
 File "/root/.cache/pre-commit/repopc0svvoh/py_env-python3.11/lib/python3.11/site-packages/pre_commit_hooks/check_ast.py", line 21, in main
 ast.parse(f.read(), filename=filename)
 File "/usr/local/lib/python3.11/ast.py", line 50, in parse
 return compile(source, filename, mode, flags,
 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 File "Packs/TmpPack/Integrations/HelloWorldTest/HelloWorldTest.py", line 1413
 elif command == 'hello
 ^
 SyntaxError: unterminated string literal (detected at line 1413)"""

    pattern_obj = HOOK_ID_TO_PATTERN['check-ast']
    result = parse_pre_commit_output(output, pattern_obj)
    assert result == [{'file': 'Packs/TmpPack/Integrations/HelloWorldTest/HelloWorldTest.py', 'line': '1413'}]


def test_parse_pre_commit_output_mypy():
    output = """mypy-py3.11..............................................................Failed
- hook id: mypy
- exit code: 1

Packs/TAXIIServer/Integrations/TAXII2Server/TAXII2Server.py:791: error: Name
"greet" is not defined  [name-defined]
        greet(inp)
        ^
Packs/TAXIIServer/Integrations/TAXII2Server/TAXII2Server.py:791: error: Name
"inp" is not defined  [name-defined]
        greet(inp)
              ^
Packs/TAXIIServer/Integrations/TAXII2Server/TAXII2Server.py:794: error: Name
"by" is not defined  [name-defined]
        by({'arrrr': 'rrrrra', 'rrrraa': 'rapapapu'})
        ^
Found 3 errors in 1 file (checked 1 source file)"""
    pattern_obj = HOOK_ID_TO_PATTERN['mypy']
    result = parse_pre_commit_output(output, pattern_obj)
    assert result == [
        {
            'file': 'Packs/TAXIIServer/Integrations/TAXII2Server/TAXII2Server.py',
            'line': '791',
            'details': '''Name
"greet" is not defined  [name-defined]
        greet(inp)
        ^'''
        },
        {
            'file': 'Packs/TAXIIServer/Integrations/TAXII2Server/TAXII2Server.py',
            'line': '791',
            'details': '''Name
"inp" is not defined  [name-defined]
        greet(inp)
              ^'''
        },
        {
            'file': 'Packs/TAXIIServer/Integrations/TAXII2Server/TAXII2Server.py',
            'line': '794',
            'details': '''Name
"by" is not defined  [name-defined]
        by({'arrrr': 'rrrrra', 'rrrraa': 'rapapapu'})
        ^'''
        }
    ]


def test_resolve_entity_type():
    assert resolve_entity_type("Packs/SomePack/Integrations/SomeIntegration") == "integration"
    assert resolve_entity_type("Packs/SomePack/Scripts/SomeScript") == "script"
    assert resolve_entity_type("Packs/SomePack/Playbooks/SomePlaybook") == "playbook"
    assert resolve_entity_type("Packs/SomePack/TestPlaybooks/SomeTestPlaybook") == "testplaybook"
    assert resolve_entity_type("Packs/SomePack/") == "contentpack"


# def test_get_pack_name():
#     # Mock JSON metadata as bytes
#     mock_metadata = json.dumps({"name": "TestPack"}).encode("utf-8")
#
#     # Create a mock for the file-like object returned by `open`
#     mock_file = MagicMock()
#     mock_file.read.return_value = mock_metadata
#
#     # Mock the ZipFile object and its `open` method
#     mock_zipfile = MagicMock()
#     mock_zipfile.open.return_value = mock_file
#
#     # Patch `zipfile.ZipFile` to return the mocked ZipFile object
#     with patch("zipfile.ZipFile", return_value=mock_zipfile):
#         pack_name = get_pack_name("dummy_path.zip")
#         assert pack_name == "TestPack"

# @patch("git.Repo")
# @patch("os.listdir")
# def test_setup_content_repo_initial_commit(mocker):
#     # Mocks and expected behaviors
#     mocker.patch.object(demisto, "debug")
#
#     # mock_content_repo = MagicMock()
#     # mock_repo.init.return_value = mock_content_repo
#     # mock_content_repo.head.is_valid.return_value = False  # Simulate no commits in the repo
#     # mock_listdir.return_value = ["file1", "file2"]
#     #
#     # # Call the function
#     # content_path = "/dummy/content/path"
#     # result = setup_content_repo(content_path)
#     #
#     # # Assertions
#     # mock_repo.init.assert_called_once_with(content_path)
#     # demisto.debug.assert_called_with(f'main created content_repo {os.listdir(content_path)=}')
#     # mock_content_repo.index.commit.assert_called_once_with("Initial commit")
#     # mock_content_repo.create_remote.assert_called_once_with('origin', CONTENT_REPO_URL)
#     # mock_content_repo.remotes.origin.fetch.assert_called_once_with('master', depth=1)
#     # mock_content_repo.create_head.assert_called_once_with(BRANCH_MASTER)
    # mock_content_repo.heads.master.checkout.assert_called_once()
    # assert result == mock_content_repo

