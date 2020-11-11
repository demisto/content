import os
import json
import demistomock as demisto
from tempfile import mkdtemp
from Anomali_ThreatStream_v2 import main, file_name_to_valid_string

import emoji


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
    mocker.patch('Anomali_ThreatStream_v2.http_request', side_effect=http_request_with_approval_mock)
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
    http_mock = mocker.patch('Anomali_ThreatStream_v2.http_request', side_effect=http_request_without_approval_mock)
    mocker.patch.object(demisto, 'args', return_value={'file_id': 1, 'classification': 'private',
                                                       'allow_unresolved': 'no', 'confidence': 30})
    mocker.patch.object(demisto, 'command', return_value='threatstream-import-indicator-without-approval')
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'getFilePath', return_value=file_obj)

    main()
    results = demisto.results.call_args[0]

    assert results[0]['Contents']
    assert expected_import_json == http_mock.call_args[1]['json']
