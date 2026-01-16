from unittest.mock import mock_open
import PFXAnalyzer


def test_main_function_no_password(mocker):
    mock_args = {"fileEntryId": "test_entry_id"}
    mocker.patch("demistomock.args", return_value=mock_args)
    mocker.patch("demistomock.getFilePath", return_value={"path": "/tmp/test.pfx"})
    mocker.patch("os.path.exists", return_value=True)
    mocker.patch("builtins.open", mock_open(read_data=b"mock_pfx_data"))

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
    mock_return = mocker.patch("PFXAnalyzer.return_results")

    PFXAnalyzer.main()

    mock_return.assert_called_once()
    args, _ = mock_return.call_args
    result = args[0]
    assert isinstance(result, PFXAnalyzer.CommandResults)
    assert result.outputs_prefix == "PFXAnalysis"
    assert result.outputs == mock_analysis_result


def test_check_strong_suspicion_combined():
    output = {"Self-Signed": True, "Common Name": "Google Root", "Suspicious Keywords in CN": True, "is_pfx_suspicious": False}
    reasons = []
    PFXAnalyzer.check_strong_suspicion(output, reasons)
    assert output["is_pfx_suspicious"] is True
    assert "High-risk indicator" in reasons[0]


def test_check_strong_suspicion_individual_flags():
    output = {"Self-Signed": True, "Common Name": "MyCert", "Suspicious Keywords in CN": False, "is_pfx_suspicious": False}
    reasons = []
    PFXAnalyzer.check_strong_suspicion(output, reasons)
    assert output["is_pfx_suspicious"] is False
    assert "self-signed" in reasons[0]


def test_analyze_common_name_suspicious():
    pfx_output = {"Common Name": "Adobe Secure CA"}
    reasons = []
    PFXAnalyzer.analyze_common_name(pfx_output, reasons)
    assert pfx_output["Suspicious Keywords in CN"] is True


def test_analyze_common_name_non_suspicious():
    pfx_output = {"Common Name": "MyCert"}
    reasons = []
    PFXAnalyzer.analyze_common_name(pfx_output, reasons)
    assert pfx_output.get("Suspicious Keywords in CN", False) is False


def test_analyze_private_key_rsa():
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    output = {
        "Private Key Present": False,
        "Key Type": "",
        "Key Size": "",
    }
    reasons = []
    PFXAnalyzer.analyze_private_key(key, output, reasons)
    assert output["Private Key Present"] is True
    assert output["Key Type"] == "RSA"
    assert output["Key Size"] == 2048
    assert "Private key is present" in reasons


def test_initialize_pfx_output_structure():
    output = PFXAnalyzer.initialize_pfx_output()
    assert isinstance(output, dict)
    expected_keys = [
        "Private Key Present",
        "Key Type",
        "Key Size",
        "Certificate Present",
        "Common Name",
        "Issuer",
        "Validity Start",
        "Validity End",
        "Validity Days",
        "Self-Signed",
        "CRL URIs",
        "OCSP URIs",
        "Suspicious Keywords in CN",
        "Reasons",
        "is_pfx_suspicious",
    ]
    for key in expected_keys:
        assert key in output
