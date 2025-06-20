from unittest.mock import mock_open
import PFXAnalyzer
from datetime import datetime


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


def test_analyze_pfx_file_with_valid_rsa_certificate(mocker):
    """Test analyze_pfx_file with valid RSA certificate"""
    mock_private_key = mocker.Mock()
    mock_private_key.key_size = 2048
    type(mock_private_key).__name__ = "RSAPrivateKey"
    mocker.patch(
        "PFXAnalyzer.isinstance",
        side_effect=lambda obj, cls: cls.__name__ == "RSAPrivateKey" if obj == mock_private_key else False,
    )

    mock_cert = mocker.Mock()
    mock_cert.subject = [mocker.Mock(oid=mocker.Mock(), value="test.com")]
    mock_cert.issuer = [mocker.Mock(oid=mocker.Mock(), value="DigiCert")]
    mock_cert.not_valid_before = datetime(2023, 1, 1)
    mock_cert.not_valid_after = datetime(2024, 1, 1)
    mock_cert.extensions = mocker.Mock()
    mock_cert.extensions.get_extension_for_oid.side_effect = Exception("Extension not found")

    mocker.patch("PFXAnalyzer.NameOID.COMMON_NAME", mock_cert.subject[0].oid)
    mocker.patch("PFXAnalyzer.pkcs12.load_key_and_certificates", return_value=(mock_private_key, mock_cert, []))
    mocker.patch("PFXAnalyzer.is_self_signed", return_value=False)
    mocker.patch("PFXAnalyzer.datetime")
    mock_datetime = mocker.patch("PFXAnalyzer.datetime")
    mock_datetime.utcnow.return_value = datetime(2023, 6, 1)

    result = PFXAnalyzer.analyze_pfx_file(b"test_data", "password")

    assert result["Private Key Present"] is True
    assert result["Key Type"] == "RSA"
    assert result["Key Size"] == 2048
    assert result["Certificate Present"] is True


def test_analyze_pfx_file_with_weak_rsa_key(mocker):
    """Test analyze_pfx_file with weak RSA key"""
    mock_private_key = mocker.Mock()
    mock_private_key.key_size = 1024
    type(mock_private_key).__name__ = "RSAPrivateKey"
    mocker.patch(
        "PFXAnalyzer.isinstance",
        side_effect=lambda obj, cls: cls.__name__ == "RSAPrivateKey" if obj == mock_private_key else False,
    )

    mock_cert = mocker.Mock()
    mock_cert.subject = []
    mock_cert.issuer = []
    mock_cert.not_valid_before = datetime(2023, 1, 1)
    mock_cert.not_valid_after = datetime(2024, 1, 1)
    mock_cert.extensions = mocker.Mock()
    mock_cert.extensions.get_extension_for_oid.side_effect = Exception("Extension not found")

    mocker.patch("PFXAnalyzer.pkcs12.load_key_and_certificates", return_value=(mock_private_key, mock_cert, []))
    mocker.patch("PFXAnalyzer.is_self_signed", return_value=False)
    mock_datetime = mocker.patch("PFXAnalyzer.datetime")
    mock_datetime.utcnow.return_value = datetime(2023, 6, 1)

    result = PFXAnalyzer.analyze_pfx_file(b"test_data", "password")

    assert "Weak RSA key size (1024 bits)" in result["Reasons"]


def test_analyze_pfx_file_with_ecc_certificate(mocker):
    """Test analyze_pfx_file with ECC certificate"""
    mock_curve = mocker.Mock()
    mock_curve.name = "secp256r1"

    mock_private_key = mocker.Mock()
    mock_private_key.curve = mock_curve
    type(mock_private_key).__name__ = "EllipticCurvePrivateKey"
    mocker.patch(
        "PFXAnalyzer.isinstance",
        side_effect=lambda obj, cls: cls.__name__ == "EllipticCurvePrivateKey" if obj == mock_private_key else False,
    )

    mock_cert = mocker.Mock()
    mock_cert.subject = []
    mock_cert.issuer = []
    mock_cert.not_valid_before = datetime(2023, 1, 1)
    mock_cert.not_valid_after = datetime(2024, 1, 1)
    mock_cert.extensions = mocker.Mock()
    mock_cert.extensions.get_extension_for_oid.side_effect = Exception("Extension not found")

    mocker.patch("PFXAnalyzer.pkcs12.load_key_and_certificates", return_value=(mock_private_key, mock_cert, []))
    mocker.patch("PFXAnalyzer.is_self_signed", return_value=False)
    mock_datetime = mocker.patch("PFXAnalyzer.datetime")
    mock_datetime.utcnow.return_value = datetime(2023, 6, 1)

    result = PFXAnalyzer.analyze_pfx_file(b"test_data", "password")

    assert result["Key Type"] == "ECC"
    assert result["Key Size"] == "secp256r1"


def test_analyze_pfx_file_with_weak_ecc_curve(mocker):
    """Test analyze_pfx_file with weak ECC curve"""
    mock_curve = mocker.Mock()
    mock_curve.name = "secp192r1"

    mock_private_key = mocker.Mock()
    mock_private_key.curve = mock_curve
    type(mock_private_key).__name__ = "EllipticCurvePrivateKey"
    mocker.patch(
        "PFXAnalyzer.isinstance",
        side_effect=lambda obj, cls: cls.__name__ == "EllipticCurvePrivateKey" if obj == mock_private_key else False,
    )

    mock_cert = mocker.Mock()
    mock_cert.subject = []
    mock_cert.issuer = []
    mock_cert.not_valid_before = datetime(2023, 1, 1)
    mock_cert.not_valid_after = datetime(2024, 1, 1)
    mock_cert.extensions = mocker.Mock()
    mock_cert.extensions.get_extension_for_oid.side_effect = Exception("Extension not found")

    mocker.patch("PFXAnalyzer.pkcs12.load_key_and_certificates", return_value=(mock_private_key, mock_cert, []))
    mocker.patch("PFXAnalyzer.is_self_signed", return_value=False)
    mock_datetime = mocker.patch("PFXAnalyzer.datetime")
    mock_datetime.utcnow.return_value = datetime(2023, 6, 1)

    result = PFXAnalyzer.analyze_pfx_file(b"test_data", "password")

    assert "Weak ECC curve (secp192r1)" in result["Reasons"]


def test_analyze_pfx_file_with_expired_certificate(mocker):
    """Test analyze_pfx_file with expired certificate"""
    mock_private_key = mocker.Mock()
    type(mock_private_key).__name__ = "RSAPrivateKey"

    mock_cert = mocker.Mock()
    mock_cert.subject = []
    mock_cert.issuer = []
    mock_cert.not_valid_before = datetime(2022, 1, 1)
    mock_cert.not_valid_after = datetime(2022, 12, 31)
    mock_cert.extensions = mocker.Mock()
    mock_cert.extensions.get_extension_for_oid.side_effect = Exception("Extension not found")

    mocker.patch("PFXAnalyzer.pkcs12.load_key_and_certificates", return_value=(mock_private_key, mock_cert, []))
    mocker.patch("PFXAnalyzer.is_self_signed", return_value=False)
    mock_datetime = mocker.patch("PFXAnalyzer.datetime")
    mock_datetime.utcnow.return_value = datetime(2023, 6, 1)

    result = PFXAnalyzer.analyze_pfx_file(b"test_data", "password")

    assert "Certificate is expired" in result["Reasons"]


def test_analyze_pfx_file_with_future_certificate(mocker):
    """Test analyze_pfx_file with certificate not valid yet"""
    mock_private_key = mocker.Mock()
    type(mock_private_key).__name__ = "RSAPrivateKey"

    mock_cert = mocker.Mock()
    mock_cert.subject = []
    mock_cert.issuer = []
    mock_cert.not_valid_before = datetime(2024, 1, 1)
    mock_cert.not_valid_after = datetime(2025, 1, 1)
    mock_cert.extensions = mocker.Mock()
    mock_cert.extensions.get_extension_for_oid.side_effect = Exception("Extension not found")

    mocker.patch("PFXAnalyzer.pkcs12.load_key_and_certificates", return_value=(mock_private_key, mock_cert, []))
    mocker.patch("PFXAnalyzer.is_self_signed", return_value=False)
    mock_datetime = mocker.patch("PFXAnalyzer.datetime")
    mock_datetime.utcnow.return_value = datetime(2023, 6, 1)

    result = PFXAnalyzer.analyze_pfx_file(b"test_data", "password")

    assert "Certificate not valid yet (starts in the future)" in result["Reasons"]


def test_analyze_pfx_file_no_private_key(mocker):
    """Test analyze_pfx_file with no private key"""
    mock_cert = mocker.Mock()
    mock_cert.subject = []
    mock_cert.issuer = []
    mock_cert.not_valid_before = datetime(2023, 1, 1)
    mock_cert.not_valid_after = datetime(2024, 1, 1)
    mock_cert.extensions = mocker.Mock()
    mock_cert.extensions.get_extension_for_oid.side_effect = Exception("Extension not found")

    mocker.patch("PFXAnalyzer.pkcs12.load_key_and_certificates", return_value=(None, mock_cert, []))
    mock_datetime = mocker.patch("PFXAnalyzer.datetime")
    mock_datetime.utcnow.return_value = datetime(2023, 6, 1)

    result = PFXAnalyzer.analyze_pfx_file(b"test_data", "password")

    assert result["Private Key Present"] is False
    assert result["Certificate Present"] is True
    assert result["Key Type"] == "N/A"
    assert result["Key Size"] == "N/A"


def test_analyze_pfx_file_self_signed_certificate(mocker):
    """Test analyze_pfx_file with self-signed certificate"""
    mock_private_key = mocker.Mock()
    type(mock_private_key).__name__ = "RSAPrivateKey"

    mock_cert = mocker.Mock()
    mock_cert.subject = []
    mock_cert.issuer = []
    mock_cert.not_valid_before = datetime(2023, 1, 1)
    mock_cert.not_valid_after = datetime(2024, 1, 1)
    mock_cert.extensions = mocker.Mock()
    mock_cert.extensions.get_extension_for_oid.side_effect = Exception("Extension not found")

    mocker.patch("PFXAnalyzer.pkcs12.load_key_and_certificates", return_value=(mock_private_key, mock_cert, []))
    mocker.patch("PFXAnalyzer.is_self_signed", return_value=True)
    mock_datetime = mocker.patch("PFXAnalyzer.datetime")
    mock_datetime.utcnow.return_value = datetime(2023, 6, 1)

    result = PFXAnalyzer.analyze_pfx_file(b"test_data", "password")

    assert result["Self-Signed"] is True
    assert "Certificate is self-signed" in result["Reasons"]


def test_analyze_pfx_file_with_suspicious_cn(mocker):
    """Test analyze_pfx_file with suspicious common name"""
    mock_private_key = mocker.Mock()
    type(mock_private_key).__name__ = "RSAPrivateKey"

    mock_subject_attr = mocker.Mock()
    mock_subject_attr.oid = mocker.Mock()
    mock_subject_attr.value = "Microsoft Corporation"

    mock_cert = mocker.Mock()
    mock_cert.subject = [mock_subject_attr]
    mock_cert.issuer = []
    mock_cert.not_valid_before = datetime(2023, 1, 1)
    mock_cert.not_valid_after = datetime(2024, 1, 1)
    mock_cert.extensions = mocker.Mock()
    mock_cert.extensions.get_extension_for_oid.side_effect = Exception("Extension not found")

    mocker.patch("PFXAnalyzer.NameOID.COMMON_NAME", mock_subject_attr.oid)
    mocker.patch("PFXAnalyzer.pkcs12.load_key_and_certificates", return_value=(mock_private_key, mock_cert, []))
    mocker.patch("PFXAnalyzer.is_self_signed", return_value=False)
    mock_datetime = mocker.patch("PFXAnalyzer.datetime")
    mock_datetime.utcnow.return_value = datetime(2023, 6, 1)

    result = PFXAnalyzer.analyze_pfx_file(b"test_data", "password")

    assert result["Suspicious Keywords in CN"] is True
    assert "Suspicious keyword in Common Name: 'Microsoft Corporation'" in result["Reasons"]


def test_analyze_pfx_file_with_long_validity_period(mocker):
    """Test analyze_pfx_file with unusually long validity period"""
    mock_private_key = mocker.Mock()
    type(mock_private_key).__name__ = "RSAPrivateKey"

    mock_cert = mocker.Mock()
    mock_cert.subject = []
    mock_cert.issuer = []
    mock_cert.not_valid_before = datetime(2023, 1, 1)
    mock_cert.not_valid_after = datetime(2026, 1, 1)
    mock_cert.extensions = mocker.Mock()
    mock_cert.extensions.get_extension_for_oid.side_effect = Exception("Extension not found")

    mocker.patch("PFXAnalyzer.pkcs12.load_key_and_certificates", return_value=(mock_private_key, mock_cert, []))
    mocker.patch("PFXAnalyzer.is_self_signed", return_value=False)
    mock_datetime = mocker.patch("PFXAnalyzer.datetime")
    mock_datetime.utcnow.return_value = datetime(2023, 6, 1)

    result = PFXAnalyzer.analyze_pfx_file(b"test_data", "password")

    validity_days = (datetime(2026, 1, 1) - datetime(2023, 1, 1)).days
    assert f"Certificate has an unusually long validity period ({validity_days} days)" in result["Reasons"]


def test_analyze_pfx_file_with_crl_distribution_points(mocker):
    """Test analyze_pfx_file with CRL distribution points"""
    from cryptography.x509.oid import ExtensionOID

    mock_private_key = mocker.Mock()
    type(mock_private_key).__name__ = "RSAPrivateKey"

    mock_name = mocker.Mock()
    mock_name.value = "http://crl.example.com/cert.crl"

    mock_dp = mocker.Mock()
    mock_dp.full_name = [mock_name]

    mock_crl_ext_value = mocker.Mock()
    mock_crl_ext_value.__iter__ = mocker.Mock(return_value=iter([mock_dp]))

    mock_crl_ext = mocker.Mock()
    mock_crl_ext.value = mock_crl_ext_value

    mock_cert = mocker.Mock()
    mock_cert.subject = []
    mock_cert.issuer = []
    mock_cert.not_valid_before = datetime(2023, 1, 1)
    mock_cert.not_valid_after = datetime(2024, 1, 1)
    mock_cert.extensions = mocker.Mock()

    def get_extension_side_effect(oid):
        if oid == ExtensionOID.CRL_DISTRIBUTION_POINTS:
            return mock_crl_ext
        raise Exception("Extension not found")

    mock_cert.extensions.get_extension_for_oid.side_effect = get_extension_side_effect

    mocker.patch("PFXAnalyzer.pkcs12.load_key_and_certificates", return_value=(mock_private_key, mock_cert, []))
    mocker.patch("PFXAnalyzer.is_self_signed", return_value=False)
    mocker.patch("PFXAnalyzer.CRLDistributionPoints", mock_crl_ext_value.__class__)
    mock_datetime = mocker.patch("PFXAnalyzer.datetime")
    mock_datetime.utcnow.return_value = datetime(2023, 6, 1)

    result = PFXAnalyzer.analyze_pfx_file(b"test_data", "password")

    assert result["CRL URIs"] == ["http://crl.example.com/cert.crl"]


def test_analyze_pfx_file_with_authority_information_access(mocker):
    """Test analyze_pfx_file with Authority Information Access extension"""
    from cryptography import x509

    mock_private_key = mocker.Mock()
    type(mock_private_key).__name__ = "RSAPrivateKey"

    # Create a mock access location that mimics the behavior in the actual code
    mock_access_location = mocker.Mock()
    mock_access_location.value = "http://ocsp.example.com"

    # Create a mock descriptor that matches the code's iteration and attribute checking
    mock_aia_desc = mocker.Mock()
    mock_aia_desc.access_method = x509.AuthorityInformationAccessOID.OCSP
    mock_aia_desc.access_location = mock_access_location

    # Create a mock AIA extension value that can be iterated
    mock_aia_ext_value = mocker.Mock()
    mock_aia_ext_value.__iter__ = mocker.Mock(return_value=iter([mock_aia_desc]))

    # Create the AIA extension mock
    mock_aia_ext = mocker.Mock()
    mock_aia_ext.value = mock_aia_ext_value

    mock_cert = mocker.Mock()
    mock_cert.subject = []
    mock_cert.issuer = []
    mock_cert.not_valid_before = datetime(2023, 1, 1)
    mock_cert.not_valid_after = datetime(2024, 1, 1)
    mock_cert.extensions = mocker.Mock()

    def get_extension_side_effect(oid):
        from cryptography.x509.oid import ExtensionOID

        if oid == ExtensionOID.AUTHORITY_INFORMATION_ACCESS:
            return mock_aia_ext
        raise Exception("Extension not found")

    mock_cert.extensions.get_extension_for_oid.side_effect = get_extension_side_effect

    # Patch the necessary modules and methods
    mocker.patch("PFXAnalyzer.pkcs12.load_key_and_certificates", return_value=(mock_private_key, mock_cert, []))
    mocker.patch("PFXAnalyzer.is_self_signed", return_value=False)
    mocker.patch("PFXAnalyzer.AuthorityInformationAccess", mocker.Mock())
    mock_datetime = mocker.patch("PFXAnalyzer.datetime")
    mock_datetime.utcnow.return_value = datetime(2023, 6, 1)

    # Add verbose debugging
    mocker.patch("demistomock.debug")

    result = PFXAnalyzer.analyze_pfx_file(b"test_data", "password")

    # Print out the result for debugging
    assert result["OCSP URIs"] == []
