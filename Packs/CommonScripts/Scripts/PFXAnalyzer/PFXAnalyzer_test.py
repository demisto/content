from unittest.mock import mock_open
import PFXAnalyzer


def test_main_function_success(mocker):
    """Test main function with successful PFX analysis"""
    # Mock demisto.args()
    mock_args = {"fileEntryId": "test_entry_id", "pfxPassword": "test_password"}
    mocker.patch("demistomock.args", return_value=mock_args)

    # Mock demisto.getFilePath()
    mock_file_path = {"path": "/tmp/test.pfx"}
    mocker.patch("demistomock.getFilePath", return_value=mock_file_path)

    # Mock os.path.exists()
    mocker.patch("os.path.exists", return_value=True)

    # Mock file reading
    mock_pfx_data = b"mock_pfx_data"
    mocker.patch("builtins.open", mock_open(read_data=mock_pfx_data))

    # Mock the analyze_pfx_file function
    mock_analysis_result = {
        "Private Key Present": True,
        "Key Type": "RSA",
        "Key Size": 2048,
        "Certificate Present": True,
        "Common Name": "test.com",
        "Issuer": "DigiCert",
        "Trusted Issuer": True,
        "Reasons": ["Private key is present"],
    }
    mocker.patch("PFXAnalyzer.analyze_pfx_file", return_value=mock_analysis_result)

    # Mock demisto output functions
    mock_return_outputs = mocker.patch("PFXAnalyzer.return_outputs")
    mock_debug = mocker.patch("demistomock.debug")

    # Call main function
    PFXAnalyzer.main()

    # Assertions
    mock_debug.assert_called_once()
    mock_return_outputs.assert_called_once()

    # Verify the call arguments
    call_args = mock_return_outputs.call_args
    readable_output = call_args[0][0]
    context_output = call_args[0][1]

    assert "## PFX Analysis Results" in readable_output
    assert "**Private Key Present:** True" in readable_output
    assert "**Key Type:** RSA" in readable_output
    assert context_output == {"PFXAnalysis": mock_analysis_result}


def test_main_function_missing_file_entry_id(mocker):
    """Test main function with missing fileEntryId argument"""
    # Mock demisto.args() with missing fileEntryId
    mock_args = {"pfxPassword": "test_password"}
    mocker.patch("demistomock.args", return_value=mock_args)

    # Mock demisto output functions
    mock_return_error = mocker.patch("PFXAnalyzer.return_error")

    # Call main function
    PFXAnalyzer.main()

    # Verify error was returned
    mock_return_error.assert_called_once()
    error_message = mock_return_error.call_args[0][0]
    assert "fileEntryId argument is missing" in error_message


def test_main_function_file_not_found(mocker):
    """Test main function with file not found"""
    # Mock demisto.args()
    mock_args = {"fileEntryId": "test_entry_id"}
    mocker.patch("demistomock.args", return_value=mock_args)

    # Mock demisto.getFilePath()
    mock_file_path = {"path": "/tmp/nonexistent.pfx"}
    mocker.patch("demistomock.getFilePath", return_value=mock_file_path)

    # Mock os.path.exists() to return False
    mocker.patch("os.path.exists", return_value=False)

    # Mock demisto output functions
    mock_return_error = mocker.patch("PFXAnalyzer.return_error")

    # Call main function
    PFXAnalyzer.main()

    # Verify error was returned
    mock_return_error.assert_called_once()
    error_message = mock_return_error.call_args[0][0]
    assert "File not found at" in error_message


def test_main_function_pfx_analysis_error(mocker):
    """Test main function with PFX analysis error"""
    # Mock demisto.args()
    mock_args = {"fileEntryId": "test_entry_id", "pfxPassword": "wrong_password"}
    mocker.patch("demistomock.args", return_value=mock_args)

    # Mock demisto.getFilePath()
    mock_file_path = {"path": "/tmp/test.pfx"}
    mocker.patch("demistomock.getFilePath", return_value=mock_file_path)

    # Mock os.path.exists()
    mocker.patch("os.path.exists", return_value=True)

    # Mock file reading
    mock_pfx_data = b"mock_pfx_data"
    mocker.patch("builtins.open", mock_open(read_data=mock_pfx_data))

    # Mock analyze_pfx_file to raise an exception
    mocker.patch(
        "PFXAnalyzer.analyze_pfx_file",
        side_effect=ValueError("Unable to parse .pfx file: Bad password"),
    )

    # Mock demisto output functions
    mock_return_error = mocker.patch("PFXAnalyzer.return_error")

    # Call main function
    PFXAnalyzer.main()

    # Verify error was returned
    mock_return_error.assert_called_once()
    error_message = mock_return_error.call_args[0][0]
    assert "PFX Analysis failed" in error_message
    assert "Unable to parse .pfx file" in error_message


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

    # Mock the analyze_pfx_file function
    mock_analysis_result = {
        "Private Key Present": False,
        "Certificate Present": False,
        "Reasons": [],
    }
    mocker.patch("PFXAnalyzer.analyze_pfx_file", return_value=mock_analysis_result)

    # Mock demisto output functions
    mock_return_outputs = mocker.patch("PFXAnalyzer.return_outputs")

    # Call main function
    PFXAnalyzer.main()

    # Verify analyze_pfx_file was called with None password
    PFXAnalyzer.analyze_pfx_file.assert_called_once_with(mock_pfx_data, None)
    mock_return_outputs.assert_called_once()


def test_main_function_exception_handling(mocker):
    """Test main function with general exception handling"""
    # Mock demisto.args()
    mock_args = {"fileEntryId": "test_entry_id"}
    mocker.patch("demistomock.args", return_value=mock_args)

    # Mock demisto.getFilePath() to raise an exception
    mocker.patch("demistomock.getFilePath", side_effect=Exception("Unexpected error"))

    # Mock demisto output functions
    mock_return_error = mocker.patch("PFXAnalyzer.return_error")

    # Call main function
    PFXAnalyzer.main()

    # Verify error was returned
    mock_return_error.assert_called_once()
    error_message = mock_return_error.call_args[0][0]
    assert "PFX Analysis failed" in error_message
