import demistomock as demisto
import io
import json
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


def util_load_json(path: str):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


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
        - Print to log and return None object
    """
    mcafee_tie = importlib.import_module("McAfee-TIE")
    tie_client = TieClient(None)
    hash_param = {'test': 'test'}

    mocker.patch.object(tie_client, "get_file_reputation", side_effect=Exception())
    assert not mcafee_tie.safe_get_file_reputation(tie_client, hash_param)


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


def test_set_file_reputation_invalid():
    """
    Given:
        - Tie client and an invalid trust_level argument
    When:
        - The function set_file_reputation is called to set a new reputation for the specified file
    Then:
        - Throw an exception in response to the invalid trust_level argument
    """
    mcafee_tie = importlib.import_module("McAfee-TIE")
    tie_client = TieClient(None)
    with pytest.raises(Exception) as e:
        mcafee_tie.set_file_reputation(hashes=['hash1', 'hash2'],
                                       tie_client=tie_client,
                                       trust_level='invalid_trust_level',
                                       filename='',
                                       comment='')
    assert 'Illegal argument trust_level' in str(e)


def test_set_file_reputation_valid(mocker):
    """
    Given:
        - Tie client and a valid trust_level argument
    When:
        - The function set_file_reputation is called to set a new reputation for the specified file
    Then:
        - Return a string that indicates the success of the command
    """
    mcafee_tie = importlib.import_module("McAfee-TIE")
    tie_client = TieClient(None)
    mocker.patch.object(mcafee_tie, 'get_trust_level_key', return_value='trust_level_key')
    mocker.patch.object(mcafee_tie, 'get_hash_type_key', return_value='hash_type_key')
    mocker.patch.object(tie_client, 'set_file_reputation', return_value='test_value')
    result = mcafee_tie.set_file_reputation(hashes=['hash1', 'hash2'],
                                            tie_client=tie_client,
                                            trust_level='valid_trust_level',
                                            filename='',
                                            comment='')
    assert 'Successfully set files reputation' in result


def test_file_references(mocker):
    """
    Given:
        - Tie client and a list of hashes representing files
    When:
        - The function file_references is called to retrieve the references of the given files
    Then:
        - Assert that the parsed raw result is of the correct form
    """
    from CommonServerPython import Common
    mcafee_tie = importlib.import_module("McAfee-TIE")
    tie_client = TieClient(None)
    raw_response = util_load_json('test_data/file_references.json')
    mocker.patch.object(mcafee_tie, 'get_hash_type_key', return_value='hash_type_key')
    mocker.patch.object(tie_client, 'get_file_first_references', side_effect=[raw_response['hash_file1'],
                                                                              raw_response['hash_file2']])
    table1 = mcafee_tie.references_to_human_readable(raw_response['hash_file1'])  # TODO Don't forget to add test for this func
    table2 = mcafee_tie.references_to_human_readable(raw_response['hash_file2'])
    context_data1 = {'References': table1}
    context_data2 = {'References': table2}
    mocker.patch.object(mcafee_tie, 'references_to_human_readable', side_effect=[table1, table2])
    mocker.patch.object(mcafee_tie, 'get_file_instance', return_value=Common.File(dbot_score=None))
    result = mcafee_tie.file_references(hashes=['hash1', 'hash2'], tie_client=tie_client)
    assert context_data1 == result[0].outputs and context_data2 == result[1].outputs
