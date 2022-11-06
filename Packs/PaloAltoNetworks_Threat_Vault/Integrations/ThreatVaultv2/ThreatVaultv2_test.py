from CommonServerPython import *
import pytest
import json

from ThreatVaultv2 import Client, threat_batch_search_command, release_note_get_command, threat_signature_get_command, \
    threat_search_command, file_command, cve_command, pagination, parse_resp_by_type, resp_to_hr, extract_rn_from_html_to_json, \
    parse_incident


@pytest.mark.parametrize(
    'command, demisto_args, expected_results',
    [
        (
            threat_batch_search_command,
            {'id': '123', 'md5': '52463745'},
            'There can only be one argument from the following list in the command -> [id, md5, sha256, name]'
        ),
        (
            threat_batch_search_command,
            {},
            'One of following arguments is required -> [id, sha256, md5, name]'
        ),
        (
            release_note_get_command,
            {'version': '20.7'},
            'The following arguments are required -> [type, version]'
        ),
        (
            threat_signature_get_command,
            {},
            'One of following arguments is required -> [signature_id, sha256, md5]'
        ),
        (
            threat_search_command,
            {},
            ('One of following arguments is required -> [cve, vendor, signature-name, type,'
             ' from-release-version, from-release-date, release-date, release-version]')
        ),
        (
            threat_search_command,
            {'cve': 'test', 'from-release-date': 'test'},
            ('When using a release date range in a query, it must be used with the following two arguments ->'
             '[from-release-date, to-release-date]')
        ),
        (
            threat_search_command,
            {'cve': 'test', 'from-release-version': 'test'},
            ('When using a release version range in a query, it must be used with the following two arguments ->'
             '[from-release-version, to-release-version]')
        ),
        (
            threat_search_command,
            {'cve': 'test', 'release-date': 'test', 'release-version': 'test'},
            ('There can only be one argument from the following list in the command ->'
             '[release-date, release-version]')
        ),
        (
            threat_search_command,
            {'cve': 'test', 'release-date': 'test', 'from-release-date': 'test', 'to-release-date': 'test'},
            ('When using a release version range or a release date range in a query'
             'it is not possible to use with the following arguments -> [release-date, release-version]')
        ),
        (
            threat_search_command,
            {'cve': 'test', 'from-release-version': 'test', 'to-release-version': 'test',
             'from-release-date': 'test', 'to-release-date': 'test'},
            'from-release-version and from-release-date cannot be used together.'
        )
    ]
)
def test_commands_failure(command, demisto_args, expected_results):

    client = ''

    with pytest.raises(Exception) as e:
        command(client, demisto_args)
    assert expected_results in str(e)


@pytest.mark.parametrize(
    'cmd, demisto_args, expected_readable_output, expected_indicator',
    [
        (
            file_command,
            {'file': '1234567890'},
            'Hash 1234567890 antivirus reputation is unknown to Threat Vault.',
            Common.File
        ),
        (
            cve_command,
            {'cve': '1234567890'},
            'CVE 1234567890 vulnerability reputation is unknown to Threat Vault.',
            None
        ),
        (
            threat_signature_get_command,
            {'signature_id': '123456'},
            '123456 reputation is unknown to Threat Vault.',
            None
        ),
        (
            release_note_get_command,
            {'type': '123456', 'version': '2222'},
            '2222 release note not found.',
            None
        ),
        (
            threat_search_command,
            {'cve': '123'},
            '123 reputation is unknown to Threat Vault.',
            None
        )
    ]
)
def test_commands_with_not_found(mocker, cmd, demisto_args, expected_readable_output, expected_indicator):

    client = Client(
        api_key='test',
        verify=False,
        proxy=False,
        reliability='E - Unreliable'
    )

    mocker.patch.object(client, 'antivirus_signature_get_request', side_effect=Exception('Error in API call [404] - Not Found'))
    mocker.patch.object(client, 'release_notes_get_request', side_effect=Exception('Error in API call [404] - Not Found'))
    mocker.patch.object(client, 'threat_search_request', side_effect=Exception('Error in API call [404] - Not Found'))

    results = cmd(client, demisto_args)

    if expected_indicator:
        assert isinstance(results[0].indicator, expected_indicator)
    if isinstance(results, list):
        assert results[0].readable_output == expected_readable_output
    else:
        assert results.readable_output == expected_readable_output


@pytest.mark.parametrize('page, page_size, limit, expected_result', [
    (
        5,
        100,
        None,
        (500, 100)
    ),
    (
        None,
        None,
        100,
        (0, 100)
    )
])
def test_pagination(page, page_size, limit, expected_result):

    results = pagination(page, page_size, limit)
    assert results[0] == expected_result[0]
    assert results[1] == expected_result[1]


@pytest.mark.parametrize(
    'resp, expanded, expected_results',
    [
        (
            {"data": {"vulnerability": [{"id": "test", "name": "test", "description": "test"}]}},
            True,
            ['ThreatVault.Vulnerability']
        ),
        (
            {
                "data": {
                    "antivirus": [{"id": "test", "name": "test", "description": "test"}],
                    "vulnerability": [{"id": "test", "name": "test", "description": "test"}]
                }
            },
            False,
            ['ThreatVault.Antivirus', "ThreatVault.Vulnerability"]
        ),
        (
            {
                "data": {
                    "antivirus": [{"id": "test", "name": "test", "description": "test"}],
                    "vulnerability": [{"id": "test", "name": "test", "description": "test"}],
                    "fileformat": [{"id": "test", "name": "test", "description": "test"}],
                    "spyware": [{"id": "test", "name": "test", "description": "test"}]
                }
            },
            False,
            ['ThreatVault.Antivirus', "ThreatVault.Spyware", "ThreatVault.Vulnerability", "ThreatVault.Fileformat"]
        )
    ]
)
def test_parse_resp_by_type(mocker, resp, expanded, expected_results):

    mocker.patch('ThreatVaultv2.resp_to_hr', return_value={})

    results = parse_resp_by_type(response=resp, expanded=expanded)
    for i in range(len(expected_results)):
        assert results[i].outputs_prefix == expected_results[i]


RESP_TO_HR_ARGS = [
    (
        {
            "vulnerability": [
                {
                    "id": "test",
                    "name": "test",
                    "description": "test",
                }
            ]
        },
        'vulnerability',
        False,
        14
    ),
    (
        {
            "fileformat": [
                {
                    "id": "test",
                    "name": "test",
                    "description": "test",
                }
            ]
        },
        'fileformat',
        False,
        13
    ),
    (
        {
            "file": [
                {
                    "id": "test",
                    "name": "test",
                    "description": "test",
                }
            ]
        },
        'file',
        False,
        8
    ),
    (
        {
            "file": [
                {
                    "id": "test",
                    "name": "test",
                    "description": "test",
                }
            ]
        },
        'file',
        True,
        15
    ),
    (
        {
            "antivirus": [
                {
                    "id": "test",
                    "name": "test",
                    "description": "test",
                }
            ]
        },
        'antivirus',
        False,
        9
    ),
    (
        {
            "spyware": [
                {
                    "id": "test",
                    "name": "test",
                    "description": "test",
                }
            ]
        },
        'spyware',
        False,
        12
    ),
    (
        {
            "release_notes":
                {
                    "id": "test",
                    "name": "test",
                    "description": "test",
                }
        },
        'release_notes',
        False,
        14
    ),
    (
        {
            "test": [
                {
                    "id": "test",
                    "name": "test",
                    "description": "test",
                }
            ]
        },
        'test',
        False,
        0
    )
]


@pytest.mark.parametrize('resp, type_, extra, expected', RESP_TO_HR_ARGS)
def test_resp_to_hr(resp, type_, extra, expected):

    result = resp_to_hr(resp, type_, extra)
    assert len(result.keys()) == expected


FILE_COMMAND_ARGS = [
    (
        {'file': 'xxxxzzzzaaaaxxxxzzzzaaaaxxxxzzzzaaaaxxxxzzzzaaaaxxxxzzzzaaaaxxxx'},
        [{"data": {
            "fileinfo": [
                {
                    "filetype": "test",
                    "sha256": "xxxxzzzzaaaaxxxxzzzzaaaaxxxxzzzzaaaaxxxxzzzzaaaaxxxxzzzzaaaaxxxx",
                    "sha1": "test",
                    "md5": "test",
                    "size": "test",
                    "type": "test",
                    "family": "test",
                    "platform": "test",
                    "wildfire_verdict": "unknown",
                    "create_time": "test",
                    "signatures": {
                        "antivirus": [
                            {
                                "name": "test",
                                "severity": "test",
                                "type": "test",
                                "subtype": "test",
                                "description": "test",
                                "action": "",
                                "id": "test",
                                "create_time": "test",
                                "status": "test",
                                "related_sha256_hashes": [
                                    "test"
                                ],
                                "release": {
                                    "antivirus": {
                                        "first_release_version": "test",
                                        "first_release_time": "test",
                                        "last_release_version": "test",
                                        "last_release_time": "test"
                                    }
                                }
                            }
                        ]
                    }
                }
            ]
        }}],
        {
            'sha256': ['xxxxzzzzaaaaxxxxzzzzaaaaxxxxzzzzaaaaxxxxzzzzaaaaxxxxzzzzaaaaxxxx'],
            'md5': ['test'],
            'readable_output': ['### Hash xxxxzzzzaaaaxxxxzzzzaaaaxxxxzzzzaaaaxxxxzzzzaaaaxxxxzzzzaaaaxxxx antivirus reputation:']
        }
    ),
    (
        {'file': 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'},
        [{"data": {
            "fileinfo": [
                {
                    "filetype": "test",
                    "sha256": "test",
                    "sha1": "test",
                    "md5": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                    "size": "test",
                    "type": "test",
                    "family": "test",
                    "platform": "test",
                    "wildfire_verdict": "unknown",
                    "create_time": "test",
                    "signatures": {
                        "antivirus": [
                            {
                                "name": "test",
                                "severity": "test",
                                "type": "test",
                                "subtype": "test",
                                "description": "test",
                                "action": "",
                                "id": "test",
                                "create_time": "test",
                                "status": "test",
                                "related_sha256_hashes": [
                                    "test"
                                ],
                                "release": {
                                    "antivirus": {
                                        "first_release_version": "test",
                                        "first_release_time": "test",
                                        "last_release_version": "test",
                                        "last_release_time": "test"
                                    }
                                }
                            }
                        ]
                    }
                }
            ]
        }}],
        {
            'sha256': ['test'],
            'md5': ['xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'],
            'readable_output': ['### Hash xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx antivirus reputation:']
        }
    ),
    (
        {'file': 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx,xxxxzzzzaaaaxxxxzzzzaaaaxxxxzzzzaaaaxxxxzzzzaaaaxxxxzzzzaaaaxxxx'},
        [
            {"data": {
                "fileinfo": [
                    {
                        "filetype": "test",
                        "sha256": "test",
                        "sha1": "test",
                        "md5": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                        "size": "test",
                        "type": "test",
                        "family": "test",
                        "platform": "test",
                        "wildfire_verdict": "unknown",
                        "create_time": "test",
                        "signatures": {
                            "antivirus": [
                                {
                                    "name": "test",
                                    "severity": "test",
                                    "type": "test",
                                    "subtype": "test",
                                    "description": "test",
                                    "action": "",
                                    "id": "test",
                                    "create_time": "test",
                                    "status": "test",
                                    "related_sha256_hashes": [
                                        "test"
                                    ],
                                    "release": {
                                        "antivirus": {
                                            "first_release_version": "test",
                                            "first_release_time": "test",
                                            "last_release_version": "test",
                                            "last_release_time": "test"
                                        }
                                    }
                                }
                            ]
                        }
                    }
                ]
            }},
            {"data": {
                "fileinfo": [
                    {
                        "filetype": "test",
                        "sha256": "xxxxzzzzaaaaxxxxzzzzaaaaxxxxzzzzaaaaxxxxzzzzaaaaxxxxzzzzaaaaxxxx",
                        "sha1": "test",
                        "md5": "test",
                        "size": "test",
                        "type": "test",
                        "family": "test",
                        "platform": "test",
                        "wildfire_verdict": "unknown",
                        "create_time": "test",
                        "signatures": {
                            "antivirus": [
                                {
                                    "name": "test",
                                    "severity": "test",
                                    "type": "test",
                                    "subtype": "test",
                                    "description": "test",
                                    "action": "",
                                    "id": "test",
                                    "create_time": "test",
                                    "status": "test",
                                    "related_sha256_hashes": [
                                        "test"
                                    ],
                                    "release": {
                                        "antivirus": {
                                            "first_release_version": "test",
                                            "first_release_time": "test",
                                            "last_release_version": "test",
                                            "last_release_time": "test"
                                        }
                                    }
                                }
                            ]
                        }
                    }
                ]
            }}
        ],
        {
            'sha256': ['test', 'xxxxzzzzaaaaxxxxzzzzaaaaxxxxzzzzaaaaxxxxzzzzaaaaxxxxzzzzaaaaxxxx'],
            'md5': ['xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx', 'test'],
            'readable_output': [
                '### Hash xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx antivirus reputation:',
                '### Hash xxxxzzzzaaaaxxxxzzzzaaaaxxxxzzzzaaaaxxxxzzzzaaaaxxxxzzzzaaaaxxxx antivirus reputation:'
            ]
        }
    )
]


@pytest.mark.parametrize('args, resp, expected_results', FILE_COMMAND_ARGS)
def test_file_command(mocker, args, resp, expected_results):

    client = Client(
        api_key='test',
        verify=False,
        proxy=False,
        reliability='E - Unreliable'
    )
    mocker.patch.object(client, 'antivirus_signature_get_request', side_effect=resp)
    results = file_command(client, args)

    for i in range(len(results)):
        assert results[i].indicator.sha256 == expected_results['sha256'][i]
        assert results[i].indicator.md5 == expected_results['md5'][i]
        assert expected_results['readable_output'][i] in results[i].readable_output


CVE_COMMAND_ARGS = [
    (
        {'cve': 'CVE-2011-1272'},
        [{
            "data": {
                "vulnerability": [
                    {
                        "id": "test",
                        "name": "test",
                        "description": "test",
                        "category": "test",
                        "min_version": "test",
                        "max_version": "",
                        "severity": "test",
                        "default_action": "test",
                        "cve": [
                            "CVE-2011-1272"
                        ],
                        "vendor": [
                            "test"
                        ],
                        "reference": [
                            "test"
                        ],
                        "status": "test",
                        "details": {
                            "change_data": "test"
                        },
                        "ori_release_version": "test",
                        "latest_release_version": "test",
                        "ori_release_time": "test",
                        "latest_release_time": "test"
                    }
                ]
            }
        }],
        {
            'id': ['CVE-2011-1272'],
            'readable_output': ['CVE CVE-2011-1272 vulnerability reputation:']
        }
    ),
    (
        {'cve': 'CVE-2011-1272,CVE-2011-1272'},
        [
            {
                "data": {
                    "vulnerability": [
                        {
                            "id": "test",
                            "name": "test",
                            "description": "test",
                            "category": "test",
                            "min_version": "test",
                            "max_version": "",
                            "severity": "test",
                            "default_action": "test",
                            "cve": [
                                "CVE-2011-1272"
                            ],
                            "vendor": [
                                "test"
                            ],
                            "reference": [
                                "test"
                            ],
                            "status": "test",
                            "details": {
                                "change_data": "test"
                            },
                            "ori_release_version": "test",
                            "latest_release_version": "test",
                            "ori_release_time": "test",
                            "latest_release_time": "test"
                        }
                    ]
                }
            },
            {
                "data": {
                    "vulnerability": [
                        {
                            "id": "test",
                            "name": "test",
                            "description": "test",
                            "category": "test",
                            "min_version": "test",
                            "max_version": "",
                            "severity": "test",
                            "default_action": "test",
                            "cve": [
                                "CVE-2011-1272"
                            ],
                            "vendor": [
                                "test"
                            ],
                            "reference": [
                                "test"
                            ],
                            "status": "test",
                            "details": {
                                "change_data": "test"
                            },
                            "ori_release_version": "test",
                            "latest_release_version": "test",
                            "ori_release_time": "test",
                            "latest_release_time": "test"
                        }
                    ]
                }
            }
        ],
        {
            'id': ['CVE-2011-1272', 'CVE-2011-1272'],
            'readable_output': [
                'CVE CVE-2011-1272 vulnerability reputation:',
                'CVE CVE-2011-1272 vulnerability reputation:'
            ]
        }
    )
]


@pytest.mark.parametrize('args, resp, expected_results', CVE_COMMAND_ARGS)
def test_cve_command(mocker, args, resp, expected_results):

    client = Client(
        api_key='test',
        verify=False,
        proxy=False,
        reliability='E - Unreliable'
    )
    mocker.patch.object(client, 'antivirus_signature_get_request', side_effect=resp)
    results = cve_command(client, args)

    for i in range(len(results)):
        assert results[i].indicator.id == expected_results['id'][i]
        assert expected_results['readable_output'][i] in results[i].readable_output


@pytest.mark.parametrize(
    'args, expected_results',
    [
        (
            {'sha256': 'test'},
            {
                'result': 'file',
                'call_hashes_command': 1,
                'call_ids_command': 0,
                'args': {
                    'file': 'test',
                    'sha256': 'test',
                    'extra': True
                }
            }
        ),
        (
            {'md5': 'test'},
            {
                'result': 'file',
                'call_hashes_command': 1,
                'call_ids_command': 0,
                'args': {
                    'file': 'test',
                    'md5': 'test',
                    'extra': True
                }
            }
        ),
        (
            {'sha256': 'test,test1', 'md5': 'test2'},
            {
                'result': 'file',
                'call_hashes_command': 1,
                'call_ids_command': 0,
                'args': {
                    'file': 'test,test1,test2',
                    'sha256': 'test,test1',
                    'md5': 'test2',
                    'extra': True
                }
            }
        ),
        (
            {'signature_id': 'test,test1'},
            {
                'result': 'ids',
                'call_hashes_command': 0,
                'call_ids_command': 2,
                'args': {
                    'signature_id': 'test,test1',
                    'file': '',
                    'extra': True
                }
            }
        ),
    ]
)
def test_threat_signature_get_command(mocker, args, expected_results):

    client = Client(
        api_key='test',
        verify=False,
        proxy=False,
        reliability='E - Unreliable'
    )
    call_hashes_command = mocker.patch('ThreatVaultv2.file_command', return_value=['file'])
    call_ids_command = mocker.patch.object(client, 'antivirus_signature_get_request', return_value='ids')
    mocker.patch('ThreatVaultv2.parse_resp_by_type', return_value=['ids'])
    results = threat_signature_get_command(client, args)

    assert results[0] == expected_results['result']
    assert call_hashes_command.call_count == expected_results['call_hashes_command']
    assert call_ids_command.call_count == expected_results['call_ids_command']
    assert args == expected_results['args']


@pytest.mark.parametrize(
    'args, expected_results',
    [
        (
            {'type': 'test', 'version': 'test'},
            {'prefix': 'ThreatVault.ReleaseNote', 'readable_output': 'Release notes:'}
        )
    ]
)
def test_release_note_get_command(mocker, args, expected_results):

    client = Client(
        api_key='test',
        verify=False,
        proxy=False,
        reliability='E - Unreliable'
    )

    mocker.patch.object(client, 'release_notes_get_request', return_value={'data': []})
    mocker.patch('ThreatVaultv2.resp_to_hr', return_value={'release_notes': 'test'})
    results = release_note_get_command(client, args)

    assert results.outputs_prefix == expected_results['prefix']
    assert expected_results['readable_output'] in results.readable_output


@pytest.mark.parametrize(
    'args, mocking, expected_args, expected_results',
    [
        (
            {'id': '123'},
            ['ids'],
            {'value': '123', 'type': 'id'},
            'ids'
        )
    ]
)
def test_threat_batch_search_command(mocker, args, mocking, expected_args, expected_results):

    client = Client(
        api_key='test',
        verify=False,
        proxy=False,
        reliability='E - Unreliable'
    )

    call_request = mocker.patch.object(client, 'threat_batch_search_request', return_value='')
    mocker.patch('ThreatVaultv2.parse_resp_by_type', return_value=mocking)
    results = threat_batch_search_command(client, args)

    assert results[0] == expected_results
    assert expected_args['value'] in call_request.call_args_list[0][1]['value']
    assert expected_args['type'] in call_request.call_args_list[0][1]['arg']


@pytest.mark.parametrize(
    'args, expected_results',
    [
        (
            {'cve': '123'},
            {'cve': '123', 'offset': 0}
        ),
        (
            {'cve': '123', 'release-date': 'test'},
            {'cve': '123', 'offset': 0, 'releaseDate': 'test'}
        ),
        (
            {'cve': '123', 'from-release-date': 'test', 'to-release-date': 'test'},
            {'cve': '123', 'offset': 0, 'fromReleaseDate': 'test', 'toReleaseDate': 'test'}
        ),
        (
            {'signature-name': '123', 'page': '2', 'page_size': '100'},
            {'name': '123', 'offset': 200, 'limit': 100}
        )
    ]
)
def test_threat_search_command(mocker, args, expected_results):

    client = Client(
        api_key='test',
        verify=False,
        proxy=False,
        reliability='E - Unreliable'
    )

    call_request = mocker.patch.object(client, 'threat_search_request', return_value={'data': []})
    mocker.patch('ThreatVaultv2.parse_resp_by_type', return_value=['test'])
    threat_search_command(client, args)

    assert call_request.call_args_list[0][1]['args'] == expected_results


@pytest.mark.parametrize(
    'html_input, expected_results',
    [
        (
            'test_data/html_test_data.txt',
            ('(10/13/22) We intend to release new placeholder App-IDs for several new OT/ICS App-IDs'
             ' as part of the update scheduled for October 18, 2022. We then plan to activate these new App-IDs'
             ' (Rockwell-ThinManager, SEL acSELerator RTAC, BACnet, ToolsNet Open Protocol, Ethernet Powerlink,'
             ' sick-sopas-webserver, and IEEE 61850 R-SV) with the new App-IDs content update scheduled for January 17,'
             ' 2023. Be sure to review this article for details. ')
        )
    ]
)
def test_extract_rn_from_html_to_json(html_input, expected_results):

    with open(html_input, 'r') as f:
        html_rns = f.read()

        json_rns = extract_rn_from_html_to_json(html_rns)

    assert json_rns
    assert expected_results in json_rns[0]['Release Note']


@pytest.mark.parametrize(
    'incident_input',
    [
        (
            'test_data/incident_test_data.json'
        )
    ]
)
def test_parse_incident(mocker, incident_input):

    with open(incident_input, 'r', encoding="utf-8") as f:
        inciden = json.load(f)

    results = parse_incident(inciden)

    assert 'file_type' not in results['data'][0]['release_notes']
    assert results['data'][0]['Source name'] == 'THREAT VAULT - RELEASE NOTES'
