import os
import json
import demistomock as demisto
from tempfile import mkdtemp
from Anomali_ThreatStream_v2 import main, file_name_to_valid_string, get_file_reputation, \
    REPUTATION_COMANDS, THRESHOLDS_FROM_PARAM, Client
from CommonServerPython import *
import emoji
import pytest


def util_load_json(path):
    with open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def mock_client():
    return Client(
        base_url='',
        use_ssl=False,
        default_threshold='high',
        reliability='B - Usually reliable'
    )


def http_request_with_approval_mock(req_type, suffix, params, data=None, files=None):
    return {
        'success': True,
        'import_session_id': params,
        'data': data,
    }


def http_request_without_approval_mock(req_type, suffix, params, data=None, files=None, json=None, text_response=None):
    return {
        'success': True,
        'import_session_id': 1,
        'files': files
    }


package_500_error = {
    'import_type': 'url',
    'import_value': 'www.demisto.com',
}

expected_output_500 = {
    'Contents': {
        'data': {
            'classification': 'Private',
            'confidence': 50,
            'severity': 'low',
            'threat_type': 'exploit',
            'url': 'www.demisto.com'
        },
        'import_session_id': {
            'api_key': None,
            'username': None
        },
        'success': True
    },
    'ContentsFormat': 'json',
    'EntryContext': {
        'ThreatStream.Import.ImportID': {
            'api_key': None,
            'datatext': 'www.demisto.com',
            'username': None
        }
    },
    'HumanReadable': 'The data was imported successfully. The ID of imported job '
                     "is: {'datatext': 'www.demisto.com', 'username': None, "
                     "'api_key': None}",
    'Type': 1
}

mock_objects = {"objects": [{"srcip": "8.8.8.8", "itype": "mal_ip", "confidence": 50},
                            {"srcip": "1.1.1.1", "itype": "apt_ip"}]}

expected_import_json = {'objects': [{'srcip': '8.8.8.8', 'itype': 'mal_ip', 'confidence': 50},
                                    {'srcip': '1.1.1.1', 'itype': 'apt_ip'}],
                        'meta': {'classification': 'private', 'confidence': 30, 'allow_unresolved': False}}


def test_ioc_approval_500_error(mocker):
    mocker.patch.object(Client, 'http_request', side_effect=http_request_with_approval_mock)
    mocker.patch.object(demisto, 'args', return_value=package_500_error)
    mocker.patch.object(demisto, 'command', return_value='threatstream-import-indicator-with-approval')
    mocker.patch.object(demisto, 'results')

    main()
    results = demisto.results.call_args[0]

    assert results[0]['Contents']['data'] == expected_output_500['Contents']['data']


def test_emoji_handling_in_file_name():
    file_names_package = ['Fwd for you 😍', 'Hi all', '', '🐝🤣🇮🇱👨🏽‍🚀🧟‍♂🧞‍♂🧚🏼‍♀', '🧔🤸🏻‍♀🥩🧚😷🍙👻']

    for file_name in file_names_package:
        demojized_file_name = file_name_to_valid_string(file_name)
        assert demojized_file_name == emoji.demojize(file_name)
        assert not emoji.emoji_count(file_name_to_valid_string(demojized_file_name))


def test_import_ioc_without_approval(mocker):
    tmp_dir = mkdtemp()
    file_name = 'test_file.txt'
    file_obj = {
        'name': file_name,
        'path': os.path.join(tmp_dir, file_name)
    }
    with open(file_obj['path'], 'w') as f:
        json.dump(mock_objects, f)
    http_mock = mocker.patch.object(Client, 'http_request', side_effect=http_request_without_approval_mock)
    mocker.patch.object(demisto, 'args', return_value={'file_id': 1, 'classification': 'private',
                                                       'allow_unresolved': 'no', 'confidence': 30})
    mocker.patch.object(demisto, 'command', return_value='threatstream-import-indicator-without-approval')
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'getFilePath', return_value=file_obj)

    main()
    results = demisto.results.call_args[0]

    assert results[0]['Contents']
    assert expected_import_json == http_mock.call_args[1]['json']


SHA_256_FILE_HASH = '178ba564b39bd07577e974a9b677dfd86ffa1f1d0299dfd958eb883c5ef6c3e1'
SHA_512_FILE_HASH = '665564674b6b4a7a3a69697221acef98ee5ca3664ce6b370059cb7d3b0942589556e5a9d69d83d038339535ea4ced2d4d' \
                    '300e07013a16'


@pytest.mark.parametrize('file_hash, expected_result_file_path, raw_response_file_path', [
    (SHA_256_FILE_HASH,
     'test_data/file_256_context.json',
     'test_data/file_256_response.json'),
    (SHA_512_FILE_HASH,
     'test_data/file_512_context.json',
     'test_data/file_512_response.json')
])
def test_get_file_reputation(mocker, file_hash, expected_result_file_path, raw_response_file_path):
    expected_result = util_load_json(expected_result_file_path)
    raw_response = util_load_json(raw_response_file_path)
    mocker.patch('Anomali_ThreatStream_v2.search_indicator_by_params', return_value=raw_response)
    mocker.patch.object(demisto, 'results')

    client = mock_client()
    get_file_reputation(client, file_hash, 'active')
    context = demisto.results.call_args_list[0][0][0].get('EntryContext')

    assert context == expected_result


"""
    Happy path:
        1. thresholds for each IOC from command and param
        2. inactive flag from command and param
    Edge cases:
        1. no confidence in the response - consider 0
"""


@pytest.mark.parametrize(
    argnames='confidence, threshold, exp_dbot_score',
    argvalues=[(20, None, Common.DBotScore.GOOD),
               (30, None, Common.DBotScore.SUSPICIOUS),
               (70, None, Common.DBotScore.BAD),
               (30, 50, Common.DBotScore.GOOD),
               (60, 50, Common.DBotScore.BAD),
               (70, 80, Common.DBotScore.GOOD),
               (20, 10, Common.DBotScore.BAD)])
def test_ioc_reputation_with_thresholds_in_command(mocker, confidence, threshold, exp_dbot_score):
    """
    Given
        - Various thresholds levels

    When
        - Run the reputation commands

    Then
        - Validate the dbot score was rated according to the threshold
         and Malicious key defined for the generic reputation in case confidence > theshold
    """

    # prepare

    test_indicator = dict(confidence=confidence, value='test_ioc', asn='', meta=dict(registrant_name='test'))
    mocker.patch.object(demisto, 'results')
    mocker.patch('Anomali_ThreatStream_v2.search_indicator_by_params', return_value=test_indicator)

    for ioc in REPUTATION_COMANDS:
        ioc_arg_name = ioc if ioc != 'threatstream-email-reputation' else 'email'
        mocker.patch.object(demisto, 'args', return_value={ioc_arg_name: 'test_ioc', 'threshold': threshold})
        mocker.patch.object(demisto, 'command', return_value=ioc)

        # run
        main()

        # validate
        entry_context = demisto.results.call_args[0][0]['EntryContext']
        assert entry_context[Common.DBotScore.CONTEXT_PATH][0]['Score'] == exp_dbot_score
        if exp_dbot_score == Common.DBotScore.BAD and ioc_arg_name != 'email':  # email is not a generic reputation
            assert 'Malicious' in json.dumps(entry_context)


@pytest.mark.parametrize(argnames='threshold_in_command, threshold_in_params, exp_dbot_score',
                         argvalues=[(None, None, Common.DBotScore.SUSPICIOUS),
                                    (50, None, Common.DBotScore.BAD),
                                    (None, 50, Common.DBotScore.BAD),
                                    (60, 40, Common.DBotScore.GOOD),
                                    (40, 60, Common.DBotScore.BAD)])
def test_ioc_reputation_with_thresholds_in_instance_param(mocker,
                                                          threshold_in_command,
                                                          threshold_in_params,
                                                          exp_dbot_score):
    """
    Given
        - Thresholds levels defined for each ioc in the instance params and confidence are 55

    When
        - Run the reputation commands

    Then
        - Validate the dbot score was rated according to the threshold in the command
         and only if not defined in the command will rate according the instance param
    """

    # prepare

    test_indicator = dict(confidence=55,
                          value='test_ioc',
                          asn='test_asn',
                          org='test_org',
                          tlp='test_tlp',
                          country='test_country',
                          meta=dict(registrant_name='test', maltype='test_maltype'))
    mocker.patch.object(demisto, 'results')
    mocker.patch('Anomali_ThreatStream_v2.search_indicator_by_params', return_value=test_indicator)

    for ioc in ['ip', 'domain', 'file', 'url']:
        mocker.patch.object(demisto, 'args', return_value={ioc: 'test_ioc', 'threshold': threshold_in_command})
        mocker.patch.object(demisto, 'command', return_value=ioc)
        THRESHOLDS_FROM_PARAM[ioc] = threshold_in_params
        mocker.patch.object(demisto, 'params', return_value={f'{ioc}_threshold': threshold_in_params})

        # run
        main()

        # validate
        entry_context = demisto.results.call_args[0][0]['EntryContext']
        assert entry_context[Common.DBotScore.CONTEXT_PATH][0]['Score'] == exp_dbot_score
        if exp_dbot_score == Common.DBotScore.BAD:
            assert 'Malicious' in json.dumps(entry_context)


@pytest.mark.parametrize(argnames='include_inactive, exp_status_param',
                         argvalues=[('true', 'active,inactive'), ('false', 'active')])
def test_get_active_and_inactive_ioc(mocker, include_inactive, exp_status_param):
    """
        Given
            - The Include inactive results flag is true/false

        When
            - Run the reputation commands

        Then
            - Validate inactive result returned/not returned
        """

    # prepare
    mocker.patch('Anomali_ThreatStream_v2.search_indicator_by_params', return_value=None)
    mocker.patch.object(demisto, 'params', return_value={'include_inactive': include_inactive})

    for ioc in ['ip', 'domain', 'file', 'url']:
        mocker.patch.object(demisto, 'command', return_value=ioc)
        mocker.patch.object(demisto, 'args', return_value={ioc: 'test_ioc'})

        # run
        main()

    # validate
    import Anomali_ThreatStream_v2
    assert Anomali_ThreatStream_v2.search_indicator_by_params.call_args[0][1]['status'] == exp_status_param


def test_no_confidence_in_result_iox(mocker):
    """
    Given
        - Indicator form ThreatStream without confidence value

    When
        - Run the reputation command

    Then
        - Validate the DbotScore was set to 1
    """

    # prepare
    test_indicator = dict(value='test_ioc', asn='', meta=dict(registrant_name='test'))
    mocker.patch.object(demisto, 'results')
    mocker.patch('Anomali_ThreatStream_v2.search_indicator_by_params', return_value=test_indicator)

    for ioc in REPUTATION_COMANDS:
        ioc_arg_name = ioc if ioc != 'threatstream-email-reputation' else 'email'
        mocker.patch.object(demisto, 'args', return_value={ioc_arg_name: 'test_ioc'})
        mocker.patch.object(demisto, 'command', return_value=ioc)

        # run
        main()

        # validate
        entry_context = demisto.results.call_args[0][0]['EntryContext']
        assert entry_context[Common.DBotScore.CONTEXT_PATH][0]['Score'] == Common.DBotScore.GOOD
