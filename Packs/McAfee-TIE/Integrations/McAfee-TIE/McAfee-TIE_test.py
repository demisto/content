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
        - Tie client and hash parameter
    When:
        - The tie client returns some exception when running get_file_reputation
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
        - Tie client and hash parameter
    When:
        - The tie client returns reputation
    Then:
        - Return the reputation and not None
    """
    mcafee_tie = importlib.import_module("McAfee-TIE")
    tie_client = TieClient(None)
    hash_param = {'test': 'test'}

    mocker.patch.object(tie_client, "get_file_reputation", return_value='test_value')
    assert mcafee_tie.safe_get_file_reputation(tie_client, hash_param)


def test_set_files_reputation_invalid():
    """
    Given:
        - Tie client and an invalid trust_level argument
    When:
        - The function set_file_reputation is called to set a new Enterprise reputation for the specified file
    Then:
        - Throw an exception in response to the invalid trust_level argument
    """
    mcafee_tie = importlib.import_module("McAfee-TIE")
    tie_client = TieClient(None)
    with pytest.raises(Exception) as e:
        mcafee_tie.set_files_reputation(hashes=['hash1', 'hash2'],
                                        tie_client=tie_client,
                                        trust_level='invalid_trust_level',
                                        filename='',
                                        comment='')
    assert 'Illegal argument trust_level' in str(e)


def test_set_files_reputation_valid(mocker):
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
    result = mcafee_tie.set_files_reputation(hashes=['hash1', 'hash2'],
                                             tie_client=tie_client,
                                             trust_level='valid_trust_level',
                                             filename='',
                                             comment='')
    assert 'Successfully set files reputation' in result


QUERY_LIMIT_CASES = [
    (
        {'query_limit': -30}
    ),
    (
        {'query_limit': 10000}  # A number larger than the maximum
    ),
    (
        {'query_limit': 0}
    ),
]


@pytest.mark.parametrize('params', QUERY_LIMIT_CASES)
def test_files_references_invalid_query_limit(params):
    """
    Given:
        - Tie client and a list of hashes representing files
    When:
        - The function file_references is called to retrieve the references of the given files
    Then:
        - Throw an exception in response to the invalid query_limit value
    """
    mcafee_tie = importlib.import_module("McAfee-TIE")
    tie_client = TieClient(None)
    with pytest.raises(Exception) as e:
        mcafee_tie.files_references(hashes=['hash1', 'hash2'],
                                    tie_client=tie_client,
                                    query_limit=params['query_limit'])
    assert 'Query limit must not exceed' in str(e) or 'Query limit must not be zero or negative' in str(e)


def test_files_references(mocker):
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
    file_hash1 = 'hash1'
    file_hash2 = 'hash2'
    query_limit = mcafee_tie.MAX_QUERY_LIMIT
    raw_response = util_load_json('test_data/files_references/raw_result.json')
    parsed_results = util_load_json('test_data/files_references/parsed_results.json')

    file_hash1_parsed_res = parsed_results[file_hash1]
    file_hash2_parsed_res = parsed_results[file_hash2]

    context_data1 = {'Hash': file_hash1, 'References': file_hash1_parsed_res}
    context_data2 = {'Hash': file_hash2, 'References': file_hash2_parsed_res}

    mocker.patch.object(mcafee_tie, 'get_hash_type_key', return_value='hash_type_key')
    mocker.patch.object(mcafee_tie, 'references_to_human_readable', side_effect=[file_hash1_parsed_res,
                                                                                 file_hash2_parsed_res])
    mocker.patch.object(mcafee_tie, 'get_file_instance', return_value=Common.File(dbot_score=None))
    mocker.patch.object(tie_client, 'get_file_first_references', side_effect=[raw_response[file_hash1],
                                                                              raw_response[file_hash2]])
    result = mcafee_tie.files_references(hashes=[file_hash1, file_hash2],
                                         tie_client=tie_client,
                                         query_limit=query_limit)
    assert context_data1 == result[0].outputs and context_data2 == result[1].outputs


def test_files_reputations(mocker):
    """
    Given:
        - Tie client and a list of hashes representing files
    When:
        - The function files_reputations is called to retrieve the reputations of the given files
    Then:
        - Assert that the parsed raw result is of the correct form
    """
    mcafee_tie = importlib.import_module("McAfee-TIE")
    tie_client = TieClient(None)
    raw_response = util_load_json('test_data/files_reputations/raw_result.json')
    parsed_results = util_load_json('test_data/files_reputations/parsed_results.json')

    file_hash1_raw_response = raw_response['hash1']
    file_hash2_raw_response = raw_response['hash2']
    file_hash3_raw_response = raw_response['hash3']
    mocker.patch.object(mcafee_tie, 'safe_get_file_reputation', side_effect=[file_hash1_raw_response['reputations'],
                                                                             file_hash2_raw_response['reputations'],
                                                                             file_hash3_raw_response['reputations']])
    expected_command_results = [parsed_results['hash1'], parsed_results['hash2'], parsed_results['hash3']]
    results = mcafee_tie.files_reputations(hashes=[file_hash1_raw_response['hash'],
                                                   file_hash2_raw_response['hash'],
                                                   file_hash3_raw_response['hash']],
                                           tie_client=tie_client,
                                           reliability='C - Fairly reliable')
    for (exp_command_res, result) in zip(expected_command_results, results):
        to_context = result.to_context()
        assert exp_command_res.get('HumanReadable') == to_context.get('HumanReadable')
        assert exp_command_res.get('EntryContext') == to_context.get('EntryContext')


def test_files_reputations_empty(mocker):
    """
    Given:
        - Tie client and a list of hashes representing files
    When:
        - The function files_reputations is called to retrieve the reputations of the given files
    Then:
        - Assert that the parsed empty raw result is of the correct form
    """
    mcafee_tie = importlib.import_module("McAfee-TIE")
    tie_client = TieClient(None)
    raw_response = util_load_json('test_data/files_reputations/raw_result_empty.json')
    parsed_results = util_load_json('test_data/files_reputations/parsed_results_empty.json')
    file_hash_raw_response = raw_response['hash1']
    mocker.patch.object(mcafee_tie, 'safe_get_file_reputation', return_value=None)
    results = mcafee_tie.files_reputations(hashes=[file_hash_raw_response['hash']],
                                           tie_client=tie_client,
                                           reliability='C - Fairly reliable')
    to_context = results[0].to_context()
    expected_command_results = parsed_results['hash1']
    assert expected_command_results.get('HumanReadable') == to_context.get('HumanReadable')
    assert expected_command_results.get('EntryContext') == to_context.get('EntryContext')


HASHES = [
    (
        {'hash': 'hash1'}
    ),
    (
        {'hash': 'hash2'}
    ),
]


@pytest.mark.parametrize('params', HASHES)
def test_references_to_human_readable(params):
    """
    Given:
        - Raw result from the API that represents the references of a hash
    When:
        - The function references_to_human_readable is called to convert the raw response to human readable data
    Then:
        - Assert that the parsed raw result is of the correct form
    """
    mcafee_tie = importlib.import_module("McAfee-TIE")
    raw_response = util_load_json('test_data/files_references/raw_result.json')
    file_hash = params['hash']
    result = mcafee_tie.references_to_human_readable(raw_response[file_hash])
    parsed_results = util_load_json('test_data/files_references/parsed_results.json')
    assert parsed_results[file_hash] == result
