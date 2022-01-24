import demistomock as demisto
import importlib
import pytest
from dxltieclient import TieClient

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


def test_safe_get_file_reputation_returned_exception(mocker):
    """
    Given:
        - tie client and hash parameter
    When:
        - The tie client returns some exception
    Then:
        - Raise error
    """
    with pytest.raises(Exception):
        mcafee_tie = importlib.import_module("McAfee-TIE")
        tie_client = TieClient(None)
        hash_param = {'test': 'test'}

        mocker.patch.object(tie_client, "get_file_reputation", side_effect=Exception())
        mcafee_tie.safe_get_file_reputation(tie_client, hash_param)


def test_safe_get_file_reputation_returned_rep(mocker):
    """
    Given:
        - tie client and hash parameter
    When:
        - The tie client returns reputation
    Then:
        - return the reputation
    """
    mcafee_tie = importlib.import_module("McAfee-TIE")
    tie_client = TieClient(None)
    hash_param = {'test': 'test'}

    mocker.patch.object(tie_client, "get_file_reputation", return_value='test_value')
    assert mcafee_tie.safe_get_file_reputation(tie_client, hash_param)

