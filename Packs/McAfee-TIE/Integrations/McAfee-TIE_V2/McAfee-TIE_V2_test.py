from unittest.mock import patch
import io
import json
import importlib
import pytest


def util_load_json(path: str):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_safe_get_file_reputation_returned_exception(mocker):
    """
    Given:
        - TIE client and hash parameter
    When:
        - The TIE client returns some exception when running get_file_reputation
    Then:
        - Validate that we print to log and return None object
    """
    mcafee_tie = importlib.import_module('McAfee-TIE_V2')
    hash_param = {'test': 'test'}
    with patch('dxltieclient.TieClient') as mock_tie_client:
        tie_client = mock_tie_client.return_value
        mocker.patch.object(tie_client, 'get_file_reputation', side_effect=Exception())
        assert not mcafee_tie.safe_get_file_reputation(tie_client, hash_param)


def test_safe_get_file_reputation_returned_rep(mocker):
    """
    Given:
        - TIE client and hash parameter
    When:
        - The TIE client returns reputation
    Then:
        - Validate that we return the reputation and not None object
    """
    mcafee_tie = importlib.import_module('McAfee-TIE_V2')
    hash_param = {'test': 'test'}
    with patch('dxltieclient.TieClient') as mock_tie_client:
        tie_client = mock_tie_client.return_value
        mocker.patch.object(tie_client, 'get_file_reputation', return_value='test_value')
        assert mcafee_tie.safe_get_file_reputation(tie_client, hash_param)


def test_set_files_reputation_invalid():
    """
    Given:
        - TIE client and an invalid trust_level argument
    When:
        - The function set_file_reputation is called to set a new Enterprise reputation for the specified file
    Then:
        - Validate that an exception is thrown in response to the invalid trust_level argument
    """
    mcafee_tie = importlib.import_module('McAfee-TIE_V2')
    with patch('dxltieclient.TieClient') as mock_tie_client:
        tie_client = mock_tie_client.return_value
        with pytest.raises(Exception) as e:
            mcafee_tie.set_files_reputation_command(hashes=['hash1', 'hash2'],
                                                    tie_client=tie_client,
                                                    trust_level='invalid_trust_level',
                                                    filename='',
                                                    comment='')
        assert 'Illegal argument trust_level' in str(e)


def test_set_files_reputation_valid(mocker):
    """
    Given:
        - TIE client and a valid trust_level argument
    When:
        - The function set_file_reputation is called to set a new reputation for the specified file
    Then:
        - Validate the contect of the Command Result that is returned from the function
    """
    mcafee_tie = importlib.import_module('McAfee-TIE_V2')
    mocker.patch.object(mcafee_tie, 'get_trust_level_key', return_value='trust_level_key')
    mocker.patch.object(mcafee_tie, 'get_hash_type_key', return_value='hash_type_key')
    with patch('dxltieclient.TieClient') as mock_tie_client:
        tie_client = mock_tie_client.return_value
        mocker.patch.object(tie_client, 'set_file_reputation', return_value='test_value')
        result = mcafee_tie.set_files_reputation_command(hashes=['hash1', 'hash2'],
                                                         tie_client=tie_client,
                                                         trust_level='valid_trust_level',
                                                         filename='',
                                                         comment='')
        assert 'Successfully set files reputation' in result.readable_output


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
        - TIE client and a list of hashes representing files
    When:
        - The function file_references is called to retrieve the references of the given files
    Then:
        - Validate that an exception is thrown in response to the invalid query_limit value
    """
    mcafee_tie = importlib.import_module('McAfee-TIE_V2')
    with patch('dxltieclient.TieClient') as mock_tie_client:
        tie_client = mock_tie_client.return_value
        with pytest.raises(Exception) as e:
            mcafee_tie.files_references_command(hashes=['hash1', 'hash2'],
                                                tie_client=tie_client,
                                                query_limit=params['query_limit'])
        assert 'Query limit must not exceed' in str(e) or 'Query limit must not be zero or negative' in str(e)


REFERENCES_HUMAN_READABLE_CASES = [
    (
        [
            {
                "agentGuid": "0c906be0-224c-45d4-8e6f-bc89da69d268",
                "date": 1508081600445
            },
            {
                "agentGuid": "{3a6f574a-3e6f-436d-acd4-bcde336b054d}",
                "date": 1475873692
            },
        ],
        [
            {
                "Date": "2017-10-15 18:33:20",
                "AgentGuid": "0c906be0-224c-45d4-8e6f-bc89da69d268"
            },
            {
                "Date": "2016-10-07 23:54:52",
                "AgentGuid": "3a6f574a-3e6f-436d-acd4-bcde336b054d"
            },
        ]
    ),
]


@pytest.mark.parametrize('raw_result, expected_parsed_res', REFERENCES_HUMAN_READABLE_CASES)
def test_references_to_human_readable(raw_result, expected_parsed_res):
    """
    Given:
        - Raw result from the API that represents the references of a hash
    When:
        - The function references_to_human_readable is called to convert the raw response to human readable data
    Then:
        - Assert that the parsed raw result is of the correct form
    """
    mcafee_tie = importlib.import_module('McAfee-TIE_V2')
    result = mcafee_tie.references_to_human_readable(raw_result)
    assert expected_parsed_res == result


FILE_REFERENCES_CASES = [
    (
        {'hashes': ['hash1', 'hash2']},
        [
            [
                {
                    'agentGuid': '0c906be0-224c-45d4-8e6f-bc89da69d268',
                    'date': 1508081600445
                },
                {
                    'agentGuid': '{68125cd6-a5d8-11e6-348e-000c29663178}',
                    'date': 1478626172
                },
            ],
            [
                {
                    'agentGuid': '{3a6f574a-3e6f-436d-acd4-bcde336b054d}',
                    'date': 1475873692
                },
                {
                    'agentGuid': '70be2ee9-7166-413b-b03e-64a48f6ab6c8',
                    'date': 1508081651295
                },
            ]

        ],
        [
            {
                'Hash': 'hash1',
                'References': [{'Date': '2017-10-15 18:33:20',
                               'AgentGuid': '0c906be0-224c-45d4-8e6f-bc89da69d268'},
                               {'Date': '2016-11-08 19:29:32',
                               'AgentGuid': '68125cd6-a5d8-11e6-348e-000c29663178'},
                               ]

            },
            {
                'Hash': 'hash2',
                'References': [{'Date': '2016-10-07 23:54:52',
                               'AgentGuid': '3a6f574a-3e6f-436d-acd4-bcde336b054d'},
                               {'Date': '2017-10-15 18:34:11',
                                'AgentGuid': '70be2ee9-7166-413b-b03e-64a48f6ab6c8'},
                               ]

            },
        ],
    ),
    (
        {'hashes': ['hash1']},
        [[]],
        [None]
    )
]


@pytest.mark.parametrize('params, raw_result, expected_parsed_results', FILE_REFERENCES_CASES)
def test_files_references(mocker, params, raw_result, expected_parsed_results):
    """
    Given:
        - TIE client and a list of hashes representing files
    When:
        - The function file_references is called to retrieve the references of the given files
    Then:
        - Assert that the parsed raw result is of the correct form
    """
    from CommonServerPython import Common
    mcafee_tie = importlib.import_module('McAfee-TIE_V2')
    query_limit = mcafee_tie.MAX_QUERY_LIMIT

    mocker.patch.object(mcafee_tie, 'get_hash_type_key', return_value='hash_type_key')
    mocker.patch.object(mcafee_tie, 'get_file_instance', return_value=Common.File(dbot_score=None))
    with patch('dxltieclient.TieClient') as mock_tie_client:
        tie_client = mock_tie_client.return_value
        mocker.patch.object(tie_client, 'get_file_first_references', side_effect=raw_result)
        results = mcafee_tie.files_references_command(hashes=params['hashes'],
                                                      tie_client=tie_client,
                                                      query_limit=query_limit)
        for (exp_parsed_res, result) in zip(expected_parsed_results, results):
            assert exp_parsed_res == result.outputs


def test_files_reputations(mocker):
    """
    Given:
        - TIE client and a list of hashes representing files
    When:
        - The function files_reputations is called to retrieve the reputations of the given files
    Then:
        - Assert that the parsed raw result is of the correct form
    """
    raw_responses = util_load_json('test_data/files_reputations/raw_result.json')
    parsed_results = util_load_json('test_data/files_reputations/parsed_results.json')
    validate_parsed_files_reputations(mocker=mocker, raw_responses=raw_responses, parsed_results=parsed_results)


def test_files_reputations_empty(mocker):
    """
    Given:
        - TIE client and a list of hashes representing files
    When:
        - The function files_reputations is called to retrieve the reputations of the given files
    Then:
        - Assert that the parsed empty raw result is of the correct form
    """
    raw_responses = util_load_json('test_data/files_reputations/raw_result_empty.json')
    parsed_results = util_load_json('test_data/files_reputations/parsed_results_empty.json')
    validate_parsed_files_reputations(mocker=mocker, raw_responses=raw_responses, parsed_results=parsed_results)


def validate_parsed_files_reputations(mocker, raw_responses, parsed_results):
    """
        This functions recieves the raw responses that mock the output of the API call get_file_reputation,
        and also the expected parsed results that mock the output of the function files_reputations, then
        validates if the returned values from the function is what we expect.
    """
    mcafee_tie = importlib.import_module('McAfee-TIE_V2')
    mocker.patch.object(mcafee_tie, 'safe_get_file_reputation', side_effect=raw_responses['raw_results'])
    expected_command_results = parsed_results['parsed_results']
    with patch('dxltieclient.TieClient') as mock_tie_client:
        tie_client = mock_tie_client.return_value
        results = mcafee_tie.files_reputations_command(hashes=raw_responses['hashes'],
                                                       tie_client=tie_client,
                                                       reliability='C - Fairly reliable')
        for (exp_command_res, result) in zip(expected_command_results, results):
            to_context = result.to_context()
            assert exp_command_res.get('HumanReadable') == to_context.get('HumanReadable')
            assert exp_command_res.get('EntryContext') == to_context.get('EntryContext')
