import json
from unittest import mock
from io import BytesIO
from ValidateContent import (resolve_entity_type, HOOK_ID_TO_PATTERN, get_pack_name,
                             strip_ansi_codes, extract_hook_id, parse_pre_commit_output)

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
    assert extract_hook_id("No hook id") == ''


def test_parse_pre_commit_output_check_ast():
    output = """check python ast.........................................................Failed
- hook id: check-ast
- exit code: 1

Packs/TmpPack/Integrations/HelloWorldTest/HelloWorldTest.py: failed parsing with CPython 3.11.10:

 Traceback (most recent call last):
 File "/root/.cache/pre-commit/repopc0svvoh/py_env-python3.11/lib/python3.11/site-packages/pre_commit_hooks/check_ast.py",
  line 21, in main
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


def test_get_pack_name_success(mocker):
    """
    Given:
        A valid zip file path with a metadata.json file containing a pack name.
    When:
        Calling get_pack_name with the zip file path.
    Then:
        The function should return the correct pack name from the metadata.json file.
    """
    mock_metadata = {'name': 'TestPack'}
    mock_metadata_json = json.dumps(mock_metadata)

    mock_zipfile = mocker.MagicMock()
    mock_metadata_file = mocker.MagicMock()
    mock_metadata_file.read.return_value = mock_metadata_json
    # Simulate behaviour of nested context managers.
    mock_zipfile.__enter__.return_value.open.return_value.__enter__.return_value = mock_metadata_file

    mocker.patch('zipfile.ZipFile', return_value=mock_zipfile)

    result = get_pack_name('test_pack.zip')

    assert result == 'TestPack'


def test_get_pack_name_no_name(mocker):
    """
    Given:
        A valid zip file path with a metadata.json file that doesn't contain a pack name.
    When:
        Calling get_pack_name with the zip file path.
    Then:
        The function should return 'TmpPack' as the default pack name.
    """
    mock_metadata = {}
    mock_metadata_json = json.dumps(mock_metadata)
    mock_debug = mocker.patch.object(demisto, "error")

    mock_zipfile = mocker.MagicMock()
    mock_metadata_file = mocker.MagicMock()
    mock_metadata_file.read.return_value = mock_metadata_json
    mock_zipfile.__enter__.return_value.open.return_value.__enter__.return_value = mock_metadata_file

    mocker.patch('zipfile.ZipFile', return_value=mock_zipfile)

    result = get_pack_name('test_pack.zip')

    assert result == 'TmpPack'
    mock_debug.assert_called_once_with('Could not find pack name in metadata.json')

#
# def test_run_validate_success(mocker):
#     """
#     Given:
#         A valid path to validate and a JSON output file path.
#     When:
#         run_validate is called with these parameters.
#     Then:
#         The function should return an exit code of 0, indicating successful validation.
#     """
#     mocker.patch('ValidateContent.ResultWriter')
#     mocker.patch('ValidateContent.ConfigReader')
#     mocker.patch('ValidateContent.Initializer')
#     mock_validate_manager = mocker.patch('ValidateContent.ValidateManager')
#     mock_validate_manager.return_value.run_validations.return_value = 0
#
#     result = run_validate('/path/to/validate', 'output.json')
#
#     assert result == 0


# #
# from ValidateContent import prepare_single_content_item_for_validation

# def test_prepare_single_content_item_for_validation_json(mocker):
#     """
#     Given:
#         A JSON file is provided for validation.
#     When:
#         The prepare_single_content_item_for_validation function is called.
#     Then:
#         The function returns the correct file path for a JSON file.
#     """
#     mocker.patch('os.makedirs')
#     mocker.patch.object(Path, 'write_text')
#     mocker.patch('Packs.Base.Scripts.ValidateContent.ValidateContent.find_type', return_value=None)
#
#     file_name = 'contentpack-0df6ea5a-7b29-4107-8614-6706fa6d23e7-mypackbarry.zip'
#     data = b'XYZ'
#     packs_path = "/tmp/content/Packs"
#     path_to_validate = prepare_single_content_item_for_validation(file_name, data, packs_path)
#
#     assert path_to_validate == '/tmp/content/Packs/TmpPack/Integrations/'
#
# def test_prepare_single_content_item_for_validation_yaml(mocker):
#     """
#     Given:
#         A YAML file is provided for validation.
#     When:
#         The prepare_single_content_item_for_validation function is called.
#     Then:
#         The function returns the correct output path after extracting to package format.
#     """
#     mocker.patch('os.path.join', return_value='/tmp/TmpPack/Integrations')
#     mocker.patch('os.makedirs')
#     mocker.patch.object(Path, 'write_text')
#     mocker.patch('Packs.Base.Scripts.ValidateContent.ValidateContent.find_type', return_value=mocker.Mock(value='integration'))
#     mocker.patch('Packs.Base.Scripts.ValidateContent.ValidateContent.ContributionConverter')
#     mocker.patch('Packs.Base.Scripts.ValidateContent.ValidateContent.demisto')
#     mocker.patch('Packs.Base.Scripts.ValidateContent.ValidateContent.YmlSplitter')
#
#     mock_extractor = mocker.Mock()
#     mock_extractor.get_output_path.return_value = '/tmp/TmpPack/Integrations/extracted'
#     mocker.patch('Packs.Base.Scripts.ValidateContent.ValidateContent.YmlSplitter', return_value=mock_extractor)
#
#     result = prepare_single_content_item_for_validation('test.yml', b'key: value', '/tmp')
#     assert result == '/tmp/TmpPack/Integrations/extracted'
#
# def test_prepare_single_content_item_for_validation_playbook(mocker):
#     """
#     Given:
#         A playbook file is provided for validation.
#     When:
#         The prepare_single_content_item_for_validation function is called.
#     Then:
#         The function returns the correct file path for a playbook file.
#     """
#     mocker.patch('os.path.join', return_value='/tmp/TmpPack/Playbooks')
#     mocker.patch('os.makedirs')
#     mocker.patch.object(Path, 'write_text')
#     mocker.patch('Packs.Base.Scripts.ValidateContent.ValidateContent.find_type', return_value=mocker.Mock(value='playbook'))
#     mocker.patch('Packs.Base.Scripts.ValidateContent.ValidateContent.ContributionConverter')
#     mocker.patch('Packs.Base.Scripts.ValidateContent.ValidateContent.demisto')
#     mocker.patch('Packs.Base.Scripts.ValidateContent.ValidateContent.FileType.PLAYBOOK', mocker.Mock(value='playbook'))
#
#     result = prepare_single_content_item_for_validation('test-playbook.yml', b'id: playbook1', '/tmp')
#     assert result == '/tmp/TmpPack/Playbooks/test-playbook.yml'
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
