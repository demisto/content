import demistomock as demisto


""" API RAW RESULTS """

MACHINE_OUTPUTS = {
    "status": "SUCCESS",
    "message": "",
    "data": {
        "evidenceMap": {
            "reportedByAntiMalwareEvidence": 1
        },
        "resultIdToElementDataMap": {
            "-1879720569.-2277552225461983666": {
                "isMalicious": 'false',
                "suspicionCount": 1,
                "malopPriority": 'null',
                "elementValues": {
                    "ownerMachine": {
                        "totalValues": 1,
                        "totalSuspicious": 0,
                        "guessedTotal": 0,
                        "totalMalicious": 0,
                        "elementValues": [
                            {
                                "guid": "-1879720555.1198775089551512345",
                                "hasSuspicions": 'false',
                                "elementType": "Machine",
                                "name": "desktop-p0m5vad",
                                "hasMalops": 'false'
                            }
                        ]
                    },
                    "self": {
                        "totalValues": 1,
                        "totalSuspicious": 1,
                        "guessedTotal": 0,
                        "totalMalicious": 0,
                        "elementValues": [
                            {
                                "guid": "-1879720555.-2277552225461966666",
                                "hasSuspicions": 'true',
                                "elementType": "File",
                                "name": "bdata.bin",
                                "hasMalops": 'false'
                            }
                        ]
                    }
                },
                "malicious": 'false',
                "filterData": {
                    "sortInGroupValue": "-1879720569.-2277552225461983666",
                    "groupByValue": "FileHashRuntime:0.4272124792099163455 "  # disable-secrets-detection
                },
                "suspicions": {
                    "reportedByAntiMalwareSuspicion": 1576499740291
                },
                "labelsIds": 'null',
                "suspect": 'true',
                "guidString": "-1879720569.-2277552225461983666",
                "simpleValues": {
                    "reportedByAntiMalwareEvidence": {
                        "totalValues": 1,
                        "values": [
                            "av_detected"
                        ]
                    },
                    "classificationDetectionName": {
                        "totalValues": 1,
                        "values": [
                            "Trojan.Agent.CHHT"
                        ]
                    },
                    "ownerMachine.isActiveProbeConnected": {
                        "totalValues": 1,
                        "values": [
                            "false"
                        ]
                    },
                    "correctedPath": {
                        "totalValues": 1,
                        "values": [
                            "c:\\windows\\temp\\sb-sim-temp-yavwth\\sb_11243939_bs_7jtkho\\bdata.bin"  # disable-secrets-detection
                        ]
                    },
                    "ownerMachine.osVersionType": {
                        "totalValues": 1,
                        "values": [
                            "Windows_10"
                        ]
                    },
                    "md5String": {
                        "totalValues": 1,
                        "values": [
                            "4778901e54f55d54435b2626923054a8"
                        ]
                    },
                    "sha1String": {
                        "totalValues": 1,
                        "values": [
                            "984e5a25910edafd1234c0f51c6f2d779530451d"
                        ]
                    },
                    "isSuspicious": {
                        "totalValues": 1,
                        "values": [
                            "true"
                        ]
                    },
                    "productType": {
                        "totalValues": 1,
                        "values": [
                            "NONE"
                        ]
                    },
                    "elementDisplayName": {
                        "totalValues": 1,
                        "values": [
                            "bdata.bin"
                        ]
                    },
                    "extensionType": {
                        "totalValues": 1,
                        "values": [
                            "APPLICATION_DATA"
                        ]
                    },
                    "maliciousClassificationType": {
                        "totalValues": 1,
                        "values": [
                            "av_detected"
                        ]
                    }
                }
            }
        },
        "pathResultCounts": [
            {
                "featureDescriptor": {
                    "elementInstanceType": "File",
                    "featureName": 'null'
                },
                "count": 1
            }
        ],
        "queryLimits": {
            "groupingFeature": {
                "elementInstanceType": "File",
                "featureName": "fileHash"
            },
            "totalResultLimit": 10000,
            "perGroupLimit": 100,
            "sortInGroupFeature": 'null',
            "perFeatureLimit": 100
        },
        "queryTerminated": 'false',
        "totalPossibleResults": 1,
        "suspicionsMap": {
            "reportedByAntiMalwareSuspicion": {
                "firstTimestamp": 1576499740291,
                "potentialEvidence": [
                    "reportedByAntiMalwareEvidence"
                ],
                "totalSuspicions": 1
            }
        },
        "guessedPossibleResults": 0
    }
}


FILE_OUTPUTS = {
    "resultIdToElementDataMap": {
        "1899624463.3738670480412115128": {
            "isMalicious": 'false',
            "suspicionCount": 1,
            "malopPriority": 'null',
            "elementValues": {
                "ownerMachine": {
                    "totalValues": 1,
                    "totalSuspicious": 0,
                    "guessedTotal": 0,
                    "totalMalicious": 0,
                    "elementValues": [
                        {
                            "guid": "1899624444.1198775089551234567",
                            "hasSuspicions": 'false',
                            "elementType": "Machine",
                            "name": "desktop-p0m5vad",
                            "hasMalops": 'false'
                        }
                    ]
                }
            },
            "malicious": 'false',
            "filterData": {
                "sortInGroupValue": "1899624463.3738670480412115128",
                "groupByValue": "FileHashRuntime:0.4272124792099163455 "  # disable-secrets-detection
            },
            "suspicions": {
                "reportedByAntiMalwareSuspicion": 1573393767860
            },
            "labelsIds": 'null',
            "suspect": 'true',
            "guidString": "1899624444.1198775089551234567",
            "simpleValues": {
                "sha1String": {
                    "totalValues": 1,
                    "values": [
                        "984e5a25910edafd4567c0f51c6f2d779530451d"
                    ]
                },
                "elementDisplayName": {
                    "totalValues": 1,
                    "values": [
                        "bdata.bin"
                    ]
                },
                "correctedPath": {
                    "totalValues": 1,
                    "values": [
                        "c:\\windows\\temp\\sb-sim-temp-ymrc7u\\sb_5313555_bs_jwnggm\\bdata.bin"  # disable-secrets-detection
                    ]
                },
                "md5String": {
                    "totalValues": 1,
                    "values": [
                        "4778901e54f55d54435b2626123456a8"
                    ]
                },
                "maliciousClassificationType": {
                    "totalValues": 1,
                    "values": [
                        "av_detected"
                    ]
                }
            }
        }
    }
}


def test_login_failed(requests_mock, mocker):
    """
    Given:
        - Cybereason instance with invalid credentials

    When:
        - Running test module

    Then:
        - Ensure an indicative error is returned that authorization failed
    """
    login_failed_html = """<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Cybereason | Login</title>
    <base href="/">

    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="icon" href="favicon.ico">
<link rel="shortcut icon" href="favicon.ico"><link href="public/vendors_c29907a62751511cc002.css" rel="stylesheet"><link href="public/login_62faa8ec0f21f2d2949f.css" rel="stylesheet"></head>  # noqa: E501
<body class="cbr-theme-dark">
    <app-login></app-login>
<script type="text/javascript" src="public/vendors_c29907a62751511cc002.js"></script><script type="text/javascript" src="public/login_62faa8ec0f21f2d2949f.js"></script></body>  # noqa: E501
</html>
""".encode('utf-8')
    mocker.patch.object(demisto, 'params', return_value={
        'server': 'http://server',
        'credentials': {
            'identifier': 'username',
            'password': 'password'
        },
        'proxy': True
    })
    mocker.patch.object(demisto, 'command', return_value='test-module')
    return_error_mock = mocker.patch('Cybereason.return_error')
    requests_mock.post('http://server/login.html', content=login_failed_html)
    requests_mock.post('http://server/rest/visualsearch/query/simple', content=login_failed_html)
    requests_mock.get('http://server/logout')
    from Cybereason import main
    main()
    assert return_error_mock.call_count == 1
    err_msg = return_error_mock.call_args[0][0]
    assert 'Failed to process the API response. Authentication failed, verify the credentials are correct.' in err_msg


params = {
    'server': 'https://integration.cybereason.net:8443',
    'credentials': {'credentials': {'sshkey': 'shelly'}},
    'proxy': True}


def test_query_file(mocker):
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={'file_hash': '4778901e54f55d54435b2626923054a8'})
    mocker.patch('Cybereason.client_certificate', side_effect=lambda: None, autospec=False)
    mocker.patch('Cybereason.get_file_machine_details', return_value=MACHINE_OUTPUTS)
    mocker.patch('Cybereason.query_file', return_value=FILE_OUTPUTS)
    mocker.patch.object(demisto, 'results')
    import Cybereason
    Cybereason.query_file_command()
    result = demisto.results.call_args[0]

    assert result[0]['ContentsFormat'] == 'json'
    assert 'Cybereason file query results' in result[0]['HumanReadable']
    assert result[0]['EntryContext']['Cybereason.File(val.MD5 && val.MD5===obj.MD5 || val.SHA1 && '
                                     'val.SHA1===obj.SHA1)'][0]['Machine'] == 'desktop-p0m5vad'
