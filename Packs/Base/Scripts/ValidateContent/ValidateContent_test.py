import json
from unittest import mock
from io import BytesIO
from ValidateContent import (ValidationResult, read_validate_results, resolve_entity_type,
                             HOOK_ID_TO_PATTERN, get_pack_name, strip_ansi_codes, extract_hook_id, parse_pre_commit_output)
import demistomock as demisto


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

    mock_zipfile = mocker.MagicMock()
    mock_metadata_file = mocker.MagicMock()
    mock_metadata_file.read.return_value = mock_metadata_json
    mock_zipfile.__enter__.return_value.open.return_value.__enter__.return_value = mock_metadata_file

    mocker.patch('zipfile.ZipFile', return_value=mock_zipfile)
    mock_error = mocker.patch.object(demisto, 'error')

    result = get_pack_name('test_pack.zip')
    assert result == 'TmpPack'
    mock_error.assert_called_with('Could not find pack name in metadata.json')


def test_read_validate_results(tmp_path):
    """
    Given:
        A temporary JSON file with validation results.
    When:
        Calling read_validate_results with the path to this file.
    Then:
        The function should return a list of ValidationResult objects.
    """
    json_file = tmp_path / "validation_results.json"
    json_file.write_text(json.dumps([{
        "validations": [{
            "file path": "Packs/TestPack/Scripts/TestScript/TestScript.yml",
            "error code": "ST001",
            "message": "Test error message"
        }]
    }]))

    results = read_validate_results(json_file)

    assert len(results) == 1
    assert isinstance(results[0], ValidationResult)
    assert results[0].filePath.endswith("Packs/TestPack/Scripts/TestScript/TestScript.yml")
    assert results[0].errorCode == "ST001"
    assert results[0].message == "Test error message"
