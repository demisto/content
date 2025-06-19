import pytest
from unittest.mock import mock_open, patch
import PFXAnalyzer
import random

from PFXAnalyzer import analyze_pfx_file

def test_analyze_pfx_file_with_no_private_key(mocker):
    from datetime import datetime, timedelta

    mock_cert = mocker.Mock()
    mock_cert.subject = []
    mock_cert.issuer = []
    now = datetime.utcnow()
    mock_cert.not_valid_before = now - timedelta(days=30)
    mock_cert.not_valid_after = now + timedelta(days=365)
    mock_cert.extensions = mocker.Mock()
    mock_cert.extensions.get_extension_for_oid.side_effect = Exception("Extension not found")

    mocker.patch("PFXAnalyzer.pkcs12.load_key_and_certificates", return_value=(None, mock_cert, []))

    result = analyze_pfx_file(b"test_data", "password")

    assert result["Private Key Present"] is False
    assert result["Key Type"] == "N/A"
    assert result["Key Size"] == "N/A"


def test_analyze_pfx_file_with_no_certificate(mocker):
    from cryptography.hazmat.primitives.asymmetric import rsa

    mock_private_key = mocker.Mock(spec=rsa.RSAPrivateKey)
    mock_private_key.key_size = 2048

    mocker.patch("PFXAnalyzer.pkcs12.load_key_and_certificates", return_value=(mock_private_key, None, []))

    result = analyze_pfx_file(b"test_data", "password")

    assert result["Certificate Present"] is False
    assert result["Common Name"] == "N/A"
    assert result["Issuer"] == "N/A"


def test_analyze_pfx_file_with_invalid_password(mocker):
    mocker.patch("PFXAnalyzer.pkcs12.load_key_and_certificates", side_effect=ValueError("Bad password"))

    try:
        analyze_pfx_file(b"test_data", "wrong_password")
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "Unable to parse .pfx file" in str(e)


def test_analyze_pfx_file_with_no_password_required(mocker):
    from cryptography.hazmat.primitives.asymmetric import rsa
    from datetime import datetime, timedelta

    mock_private_key = mocker.Mock(spec=rsa.RSAPrivateKey)
    mock_private_key.key_size = 2048

    mock_cert = mocker.Mock()
    mock_cert.subject = []
    mock_cert.issuer = []
    now = datetime.utcnow()
    mock_cert.not_valid_before = now - timedelta(days=30)
    mock_cert.not_valid_after = now + timedelta(days=365)
    mock_cert.extensions = mocker.Mock()
    mock_cert.extensions.get_extension_for_oid.side_effect = Exception("Extension not found")

    mocker.patch("PFXAnalyzer.pkcs12.load_key_and_certificates", return_value=(mock_private_key, mock_cert, []))
    mocker.patch("PFXAnalyzer.is_self_signed", return_value=False)

    result = analyze_pfx_file(b"test_data", None)

    assert result["Private Key Present"] is True
    assert result["Key Type"] == "RSA"


def test_analyze_pfx_file_with_empty_password_fallback(mocker):
    from cryptography.hazmat.primitives.asymmetric import rsa
    from datetime import datetime, timedelta

    mock_private_key = mocker.Mock(spec=rsa.RSAPrivateKey)
    mock_private_key.key_size = 2048

    mock_cert = mocker.Mock()
    mock_cert.subject = []
    mock_cert.issuer = []
    now = datetime.utcnow()
    mock_cert.not_valid_before = now - timedelta(days=30)
    mock_cert.not_valid_after = now + timedelta(days=365)
    mock_cert.extensions = mocker.Mock()
    mock_cert.extensions.get_extension_for_oid.side_effect = Exception("Extension not found")

    load_mock = mocker.patch("PFXAnalyzer.pkcs12.load_key_and_certificates")
    load_mock.side_effect = [ValueError("Password required"), (mock_private_key, mock_cert, [])]
    mocker.patch("PFXAnalyzer.is_self_signed", return_value=False)

    result = analyze_pfx_file(b"test_data", None)

    assert result["Private Key Present"] is True
    assert load_mock.call_count == 2


def test_analyze_pfx_file_with_weak_rsa_key(mocker):
    from cryptography.hazmat.primitives.asymmetric import rsa
    from datetime import datetime, timedelta

    mock_private_key = mocker.Mock(spec=rsa.RSAPrivateKey)
    mock_private_key.key_size = 1024

    mock_cert = mocker.Mock()
    mock_cert.subject = []
    mock_cert.issuer = []
    now = datetime.utcnow()
    mock_cert.not_valid_before = now - timedelta(days=30)
    mock_cert.not_valid_after = now + timedelta(days=365)
    mock_cert.extensions = mocker.Mock()
    mock_cert.extensions.get_extension_for_oid.side_effect = Exception("Extension not found")

    mocker.patch("PFXAnalyzer.pkcs12.load_key_and_certificates", return_value=(mock_private_key, mock_cert, []))
    mocker.patch("PFXAnalyzer.is_self_signed", return_value=False)

    result = analyze_pfx_file(b"test_data", "password")

    assert "Weak RSA key size (1024 bits)" in result["Reasons"]


def test_analyze_pfx_file_with_trusted_issuer(mocker):
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from cryptography import x509
    from datetime import datetime, timedelta

    mock_private_key = mocker.Mock(spec=rsa.RSAPrivateKey)
    mock_private_key.key_size = 2048

    issuer_attrs = [x509.NameAttribute(NameOID.COMMON_NAME, "DigiCert")]
    subject_attrs = [x509.NameAttribute(NameOID.COMMON_NAME, "example.com")]

    mock_cert = mocker.Mock()
    mock_cert.subject = x509.Name(subject_attrs)
    mock_cert.issuer = x509.Name(issuer_attrs)
    now = datetime.utcnow()
    mock_cert.not_valid_before = now - timedelta(days=30)
    mock_cert.not_valid_after = now + timedelta(days=365)
    mock_cert.extensions = mocker.Mock()
    mock_cert.extensions.get_extension_for_oid.side_effect = Exception("Extension not found")

    mocker.patch("PFXAnalyzer.pkcs12.load_key_and_certificates", return_value=(mock_private_key, mock_cert, []))
    mocker.patch("PFXAnalyzer.is_self_signed", return_value=False)

    result = analyze_pfx_file(b"test_data", "password")

    assert result["Trusted Issuer"] is True
    assert result["Issuer"] == "DigiCert"


def test_analyze_pfx_file_with_negative_validity_days(mocker):
    from cryptography.hazmat.primitives.asymmetric import rsa
    from datetime import datetime, timedelta

    mock_private_key = mocker.Mock(spec=rsa.RSAPrivateKey)
    mock_private_key.key_size = 2048

    mock_cert = mocker.Mock()
    mock_cert.subject = []
    mock_cert.issuer = []
    now = datetime.utcnow()
    mock_cert.not_valid_before = now + timedelta(days=10)
    mock_cert.not_valid_after = now - timedelta(days=10)
    mock_cert.extensions = mocker.Mock()
    mock_cert.extensions.get_extension_for_oid.side_effect = Exception("Extension not found")

    mocker.patch("PFXAnalyzer.pkcs12.load_key_and_certificates", return_value=(mock_private_key, mock_cert, []))
    mocker.patch("PFXAnalyzer.is_self_signed", return_value=False)

    result = analyze_pfx_file(b"test_data", "password")

    assert result["Validity Days"] == -20
    assert "Invalid validity period calculation (negative days)" in result["Reasons"]


def test_analyze_pfx_file_with_validity_calculation_error(mocker):
    from cryptography.hazmat.primitives.asymmetric import rsa

    mock_private_key = mocker.Mock(spec=rsa.RSAPrivateKey)
    mock_private_key.key_size = 2048

    mock_cert = mocker.Mock()
    mock_cert.subject = []
    mock_cert.issuer = []
    mock_cert.not_valid_before = None
    mock_cert.not_valid_after = None
    mock_cert.extensions = mocker.Mock()
    mock_cert.extensions.get_extension_for_oid.side_effect = Exception("Extension not found")

    mocker.patch("PFXAnalyzer.pkcs12.load_key_and_certificates", return_value=(mock_private_key, mock_cert, []))


def test_main_function_success(mocker):
    """Test main function with successful PFX analysis"""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from datetime import datetime, timedelta
    
    # Mock demisto.args()
    mock_args = {
        "fileEntryId": "test_entry_