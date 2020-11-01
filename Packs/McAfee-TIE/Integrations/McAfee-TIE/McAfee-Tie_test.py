import demistomock as demisto
import importlib
import pytest

valid_private_key = """-----BEGIN PRIVATE KEY-----
This is a vaild Private Key
-----END PRIVATE KEY-----"""

valid_certificate = """-----BEGIN CERTIFICATE-----
This is a valid Certificate
-----END CERTIFICATE-----"""

invalid_private_key = r"\private\key\path.key"

invalid_certificate = """""-----BEGIN CERTIFICATE REQUEST-----
This is a valid Certificate
-----END CERTIFICATE REQUEST-----"""

spaces_in_certificate = """    -----BEGIN CERTIFICATE-----
This is a valid Certificate
-----END CERTIFICATE-----   """


def test_validate_certificate_format(mocker):
    mcafee_tie = importlib.import_module("McAfee-TIE")

    # Invalid private Key
    valid_params = {'private_key': invalid_private_key,
                    'cert_file': valid_certificate,
                    'broker_ca_bundle': valid_certificate}
    mocker.patch.object(demisto, "params", return_value=valid_params)

    with pytest.raises(SystemExit):
        mcafee_tie.validate_certificates_format()

    # Invalid cert file
    valid_params = {'private_key': valid_private_key,
                    'cert_file': invalid_certificate,
                    'broker_ca_bundle': valid_certificate}
    mocker.patch.object(demisto, "params", return_value=valid_params)
    with pytest.raises(SystemExit):
        mcafee_tie.validate_certificates_format()

    # Invalid broker_ca_bundle
    valid_params = {'private_key': valid_private_key,
                    'cert_file': valid_certificate,
                    'broker_ca_bundle': invalid_certificate}
    mocker.patch.object(demisto, "params", return_value=valid_params)
    with pytest.raises(SystemExit):
        mcafee_tie.validate_certificates_format()

    # Everything is valid + spaces
    valid_params = {'private_key': valid_private_key,
                    'cert_file': valid_certificate,
                    'broker_ca_bundle': spaces_in_certificate}
    mocker.patch.object(demisto, "params", return_value=valid_params)
    mcafee_tie.validate_certificates_format()
