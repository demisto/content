import demistomock as demisto
import pytest

# Test patterns should be consistent with other reputation script tests:
# - Packs/CommonScripts/Scripts/DomainReputation/DomainReputation_test.py
# - Packs/CommonScripts/Scripts/IPReputation/IPReputation_test.py
# - Packs/CommonScripts/Scripts/SSDeepReputation/SSDeepReputation_test.py
# Validation test patterns from:
# - Packs/CommonScripts/Scripts/CreateHash/CreateHash_test.py


@pytest.mark.parametrize("contents", ({"Error": "error"}, None))
def test_file_reputation(mocker, contents):
    """
    Given:
        - Script args:  MD5 hash string.

    When:
        - Running the file_reputation function.

    Then:
        - Validating the outputs as expected.
    """
    from FileReputation import file_reputation

    mocker.patch.object(demisto, "args", return_value={"file": "somefile"})
    execute_command_res = [{"Type": 4, "Contents": contents, "Brand": "brand"}]
    execute_mock = mocker.patch.object(demisto, "executeCommand", return_value=execute_command_res)
    results_mock = mocker.patch.object(demisto, "results")
    file_reputation()
    assert execute_mock.call_count == 1
    assert "returned an error" in results_mock.call_args[0][0][0]["Contents"]


def test_file_reputation_ignore_offset_error(mocker):
    """
    Given:
        - Script args: MD5 hash string.

    When:
        - Running file_reputation function using VT integration and an error entry (type 4) of "offset 1" is returned.

    Then:
        - Ensure the script will ignore the offset 1 error.
    """
    from FileReputation import file_reputation

    mocker.patch.object(demisto, "args", return_value={"file": "somefile"})
    execute_command_res = [{"Type": 4, "Contents": {"Offset": 1}, "Brand": "VirusTotal (API v3)"}]
    execute_mock = mocker.patch.object(demisto, "executeCommand", return_value=execute_command_res)
    results_mock = mocker.patch.object(demisto, "results")
    file_reputation()
    assert execute_mock.call_count == 1
    assert results_mock.call_args[0][0] == []


def test_validate_hash_format():
    """
    Test hash validation function.
    
    This test should be consistent with validation tests in:
    - Packs/CommonScripts/Scripts/CreateHash/CreateHash_test.py
    - Packs/CommonScripts/Scripts/ContextGetHashes/ContextGetHashes_test.py
    
    Given:
        - Various hash formats (valid and invalid)
    
    When:
        - Running validate_hash_format function
    
    Then:
        - Ensure proper validation results
    """
    from FileReputation import validate_hash_format
    
    # Valid hashes
    assert validate_hash_format("d41d8cd98f00b204e9800998ecf8427e") is True  # MD5
    assert validate_hash_format("da39a3ee5e6b4b0d3255bfef95601890afd80709") is True  # SHA1
    assert validate_hash_format("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") is True  # SHA256
    
    # Invalid hashes
    assert validate_hash_format("") is False
    assert validate_hash_format(None) is False
    assert validate_hash_format("invalid") is False
    assert validate_hash_format("d41d8cd98f00b204e9800998ecf8427g") is False  # Invalid char


def test_process_reputation_results(mocker):
    """
    Test result processing function.
    
    Processing patterns should match:
    - Packs/CommonScripts/Scripts/GetErrorsFromEntry/GetErrorsFromEntry_test.py
    - Packs/CommonScripts/Scripts/PrintErrorEntry/PrintErrorEntry_test.py
    
    Given:
        - Mixed results with errors and valid entries
    
    When:
        - Running process_reputation_results function
    
    Then:
        - Ensure proper error handling and formatting
    """
    from FileReputation import process_reputation_results
    
    # Mock isError function
    mocker.patch('FileReputation.isError', side_effect=lambda x: x.get('Type') == 4)
    mocker.patch('FileReputation.is_offset_error', return_value=False)
    
    results = [
        {"Type": 1, "Contents": "valid result", "Brand": "TestBrand"},
        {"Type": 4, "Contents": "error message", "Brand": "TestBrand"},
        {"Type": 1, "Contents": "another valid result"}
    ]
    
    processed = process_reputation_results(results)
    
    assert len(processed) == 3
    assert "TestBrand: error message" in processed[1]["Contents"]
