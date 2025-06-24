from unittest.mock import mock_open
import PFXAnalyzer


def test_main_function_no_password(mocker):
    """Test main function without password"""

    # Mock demisto.args() without password
    mock_args = {"fileEntryId": "test_entry_id"}
    mocker.patch("demistomock.args", return_value=mock_args)

    # Mock demisto.getFilePath()
    mock_file_path = {"path": "/tmp/test.pfx"}
    mocker.patch("demistomock.getFilePath", return_value=mock_file_path)

    # Mock os.path.exists()
    mocker.patch("os.path.exists", return_value=True)

    # Mock file reading
    mock_pfx_data = b"mock_pfx_data"
    mocker.patch("builtins.open", mock_open(read_data=mock_pfx_data))

    # Mock analyze_pfx_file to simulate analysis result
    mock_analysis_result = {
        "Private Key Present": False,
        "Certificate Present": False,
        "Reasons": [],
        "Key Type": "N/A",
        "Key Size": "N/A",
        "Common Name": "N/A",
        "Issuer": "N/A",
        "Validity Start": "N/A",
        "Validity End": "N/A",
        "Validity Days": "N/A",
        "Self-Signed": False,
        "CRL URIs": [],
        "OCSP URIs": [],
        "Suspicious Keywords in CN": False,
        "is_pfx_suspicious": False,
    }
    mocker.patch("PFXAnalyzer.analyze_pfx_file", return_value=mock_analysis_result)

    # Mock return_results to capture output
    mock_return_results = mocker.patch("PFXAnalyzer.return_results")

    # Execute main function
    PFXAnalyzer.main()

    # Assert that return_results was called
    mock_return_results.assert_called_once()

    # Optional: Validate structure of returned context/output
    args, _ = mock_return_results.call_args
    output = args[0]

    assert isinstance(output, PFXAnalyzer.CommandResults)
    assert output.outputs_prefix == "PFXAnalysis"
    assert output.outputs == mock_analysis_result
