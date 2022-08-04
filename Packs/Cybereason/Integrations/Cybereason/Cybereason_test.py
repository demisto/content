from CommonServerPython import *
import json
import io
import demistomock as demisto
from test_files.responses_raw_data import malop_processes_raw_response, is_probe_connected_raw_response,\
    query_processes_raw_response, query_connections_raw_response, isolate_machine_raw_response, unisolate_machine_raw_response,\
    query_malops_raw_response, update_malop_status_raw_response, prevent_output_raw_response, unprevent_output_raw_response,\
    query_domain_raw_response, query_user_raw_response, available_remediation_actions_raw_response,\
    fetch_file_progress_raw_response, fetch_scan_status_raw_response, malware_query_raw_data


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


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


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


def test_query_file(client, args, mocker):
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={'file_hash': '4778901e54f55d54435b2626923054a8'})
    mocker.patch('Cybereason.client_certificate', side_effect=lambda: None, autospec=False)
    mocker.patch('Cybereason.get_file_machine_details', return_value=MACHINE_OUTPUTS)
    mocker.patch('Cybereason.query_file', return_value=FILE_OUTPUTS)
    mocker.patch.object(demisto, 'results')
    import Cybereason
    from Cybereason import Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)

    Cybereason.query_file_command(client, args)
    result = demisto.results.call_args[0]

    assert result[0]['ContentsFormat'] == 'json'
    assert 'Cybereason file query results' in result[0]['HumanReadable']
    assert result[0]['EntryContext']['Cybereason.File(val.MD5 && val.MD5===obj.MD5 || val.SHA1 && '
                                     'val.SHA1===obj.SHA1)'][0]['Machine'] == 'desktop-p0m5vad'


def test_malop_processes_command(client, args, mocker):
    from Cybereason import malop_processes_command
    from Cybereason import Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)

    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={"malopGuids": ["11.-6236127207710541535"]})
    raw_response = json.loads(malop_processes_raw_response)
    mocker.patch("Cybereason.malop_processes", return_value=raw_response)
    mocker.patch.object(demisto, 'results')
    malop_processes_command(client, args)
    result = demisto.results.call_args[0]

    assert result[0].get('ContentsFormat', '') == 'json'
    assert 'Cybereason Malop Processes' in result[0].get('HumanReadable', '')
    assert dict_safe_get(result[0], ['EntryContext', 'Process'], [])[0].get('Name', '') == 'bdata.bin'
    assert dict_safe_get(result[0], ['EntryContext', 'Process'], [])[0].get('SHA1', '') ==\
        'f56238da9fbfa3864d443a85bb80743bd2415682'


def test_is_probe_connected_command(client, args, mocker):
    from Cybereason import is_probe_connected_command
    from Cybereason import Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)

    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={"machine": ["desktop-vg9ke2u"]})
    raw_response = json.loads(is_probe_connected_raw_response)
    mocker.patch("Cybereason.is_probe_connected", return_value=raw_response)
    mocker.patch.object(demisto, 'results')
    is_probe_connected_command(client, args)
    result = demisto.results.call_args[0]

    assert result[0].get('ContentsFormat', '') == 'json'
    assert 'is probe connected' in result[0].get('HumanReadable', '')
    assert result[0]['EntryContext']['Cybereason.Machine'][0]['Name'] == 'desktop-vg9ke2u'


def test_query_processes_command(client, args, mocker):
    from Cybereason import query_processes_command
    from Cybereason import Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)

    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={"machine": ["desktop-vg9ke2u"], "hasOutgoingConnection": "true"})
    raw_response = json.loads(query_processes_raw_response)
    mocker.patch("Cybereason.query_processes", return_value=raw_response)
    mocker.patch.object(demisto, 'results')
    query_processes_command(client, args)
    result = demisto.results.call_args[0]

    assert result[0].get('ContentsFormat', '') == 'json'
    assert 'query processes' in result[0].get('HumanReadable', '')
    assert result[0]['EntryContext']['Process'][0]['SHA1'] == "1f912d4bec338ef10b7c9f19976286f8acc4eb97"


def test_query_connections_command(client, args, mocker):
    from Cybereason import query_connections_command
    from Cybereason import Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)

    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={"ip": ["192.168.1.103"]})
    raw_response = json.loads(query_connections_raw_response)
    mocker.patch("Cybereason.query_connections", return_value=raw_response)
    mocker.patch.object(demisto, 'results')
    query_connections_command(client, args)
    result = demisto.results.call_args[0]

    assert result[0].get('ContentsFormat', '') == 'json'
    assert 'query connections' in result[0].get('HumanReadable', '')
    assert result[0]['EntryContext']['Connection'][0]['ServerAddress'] == "192.168.1.103"


def test_isolate_machine_command(client, args, mocker):
    from Cybereason import isolate_machine_command
    from Cybereason import Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)

    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={"machine": ["desktop-vg9ke2u"]})
    raw_response = json.loads(isolate_machine_raw_response)
    mocker.patch("Cybereason.isolate_machine", return_value=raw_response)
    mocker.patch.object(demisto, 'results')
    isolate_machine_command(client, args)
    result = demisto.results.call_args[0]

    assert result[0].get('ContentsFormat', '') == 'json'
    assert 'isolate machine' in result[0].get('HumanReadable', '')
    assert result[0]['EntryContext']['Cybereason']['IsIsolated'] == "true"
    assert result[0]['EntryContext']['Cybereason']['Machine'] == "desktop-vg9ke2u"


def test_unisolate_machine_command(client, args, mocker):
    from Cybereason import unisolate_machine_command
    from Cybereason import Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)

    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={"machine": ["desktop-vg9ke2u"]})
    raw_response = json.loads(unisolate_machine_raw_response)
    mocker.patch("Cybereason.unisolate_machine", return_value=raw_response)
    mocker.patch.object(demisto, 'results')
    unisolate_machine_command(client, args)
    result = demisto.results.call_args[0]

    assert result[0].get('ContentsFormat', '') == 'json'
    assert 'unisolate machine' in result[0].get('HumanReadable', '')
    assert result[0]['EntryContext']['Cybereason']['IsIsolated'] == "false"
    assert result[0]['EntryContext']['Cybereason']['Machine'] == "desktop-vg9ke2u"


def test_query_malops_command(client, args, mocker):
    from Cybereason import query_malops_command
    from Cybereason import Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)

    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={})
    raw_response = json.loads(query_malops_raw_response)
    mocker.patch("Cybereason.query_malops", return_value=raw_response)
    mocker.patch.object(demisto, 'results')
    query_malops_command(client, args)
    result = demisto.results.call_args[0]

    assert result[0].get('ContentsFormat', '') == 'json'
    assert 'query malops' in result[0].get('HumanReadable', '')
    assert result[0]['EntryContext']['Cybereason']['Malops'][0]['GUID'] == "11.3651150229438589171"


def test_update_malop_status_command(client, args, mocker):
    from Cybereason import update_malop_status_command
    from Cybereason import Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)

    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={"malopGuid": "11.-7780537507363356527", "status": "To Review"})
    raw_response = json.loads(update_malop_status_raw_response)
    mocker.patch("Cybereason.update_malop_status", return_value=raw_response)
    mocker.patch.object(demisto, 'results')
    update_malop_status_command(client, args)
    result = demisto.results.call_args[0]

    assert result[0].get('ContentsFormat', '') == 'json'
    assert 'Successfully updated malop status' in result[0].get('HumanReadable', '')
    assert result[0]['EntryContext']['Cybereason']['Malops']['GUID'] == "11.-7780537507363356527"
    assert result[0]['EntryContext']['Cybereason']['Malops']['Status'] == "To Review"


def test_prevent_file_command(client, args, mocker):
    from Cybereason import prevent_file_command
    from Cybereason import Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)

    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={"md5": "fc61fdcad5a9d52a01bd2d596f2c92b9"})
    raw_response = json.loads(prevent_output_raw_response)
    mocker.patch("Cybereason.prevent_file", return_value=raw_response)
    mocker.patch.object(demisto, 'results')
    prevent_file_command(client, args)
    result = demisto.results.call_args[0]

    assert result[0].get('ContentsFormat', '') == 'json'
    assert 'File prevented successfully' in result[0].get('HumanReadable', '')
    assert result[0]['EntryContext']['Process']['MD5'] == "fc61fdcad5a9d52a01bd2d596f2c92b9"
    assert result[0]['EntryContext']['Process']['Prevent'] == "true"


def test_unprevent_file_command(client, args, mocker):
    from Cybereason import unprevent_file_command
    from Cybereason import Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)

    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={"md5": "fc61fdcad5a9d52a01bd2d596f2c92b9"})
    raw_response = json.loads(unprevent_output_raw_response)
    mocker.patch("Cybereason.unprevent_file", return_value=raw_response)
    mocker.patch.object(demisto, 'results')
    unprevent_file_command(client, args)
    result = demisto.results.call_args[0]

    assert result[0].get('ContentsFormat', '') == 'json'
    assert 'File unprevented successfully' in result[0].get('HumanReadable', '')
    assert result[0]['EntryContext']['Process']['MD5'] == "fc61fdcad5a9d52a01bd2d596f2c92b9"
    assert result[0]['EntryContext']['Process']['Prevent'] == "false"


def test_query_domain_command(client, args, mocker):
    from Cybereason import query_domain_command
    from Cybereason import Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)

    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={"domain": "www2.bing.com"})
    raw_response = json.loads(query_domain_raw_response)
    mocker.patch("Cybereason.query_domain", return_value=raw_response)
    mocker.patch.object(demisto, 'results')
    query_domain_command(client, args)
    result = demisto.results.call_args[0]

    assert result[0].get('ContentsFormat', '') == 'json'
    assert result[0]['Cybereason']['Domain']['Name'] == "www2.bing.com"


def test_query_user_command(client, args, mocker):
    from Cybereason import query_user_command
    from Cybereason import Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={"username": "desktop-vg9ke2u\\prase"})
    raw_response = json.loads(query_user_raw_response)
    mocker.patch("Cybereason.query_user", return_value=raw_response)
    mocker.patch.object(demisto, 'results')
    query_user_command(client, args)
    result = demisto.results.call_args[0]

    assert result[0].get('ContentsFormat', '') == 'json'
    assert 'Query user' in result[0].get('HumanReadable', '')
    assert result[0]['Cybereason']['User']['Username'] == "desktop-vg9ke2u\\prase"


def test_available_remediation_actions_command(client, args, mocker, requests_mock):
    from Cybereason import available_remediation_actions_command
    from Cybereason import Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={"malopGuid": "11.-7780537507363356527"})
    raw_response = json.loads(available_remediation_actions_raw_response)
    requests_mock.get("https://integration.cybereason.net:8443/rest/detection/custom-remediation", json=raw_response)
    available_remediation_actions_command(client, args)
    result = demisto.results.call_args[0]

    assert result[0].get('ContentsFormat', '') == 'json'
    assert 'available remediation actions' in result[0].get('HumanReadable', '')
    assert result[0]['data'][0]['machineId'] == "-1845090846.1198775089551518743"
    assert result[0]['data'][0]['malopId'] == "11.-7780537507363356527"


def test_start_fetchfile_command(client, args, mocker):
    from Cybereason import start_fetchfile_command, Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={"malopGuid": "11.-7780537507363356527", "userName": "admin"})
    start_fetchfile_command(client, args)
    result = demisto.results.call_args[0]
    assert 'Successfully started fetching file for the given malop' in result[0].get('HumanReadable', '')


def test_fetchfile_progress_command(client, args, mocker):
    from Cybereason import fetchfile_progress_command, Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={"malopGuid": "11.-7780537507363356527"})
    raw_response = json.loads(fetch_file_progress_raw_response)
    mocker.patch("Cybereason.fetchfile_progress_command", return_value=raw_response)
    mocker.patch.object(demisto, 'results')
    fetchfile_progress_command(client, args)
    result = demisto.results.call_args[0]

    assert result[0].get('ContentsFormat', '') == 'json'
    assert 'fetchfile progress' in result[0].get('HumanReadable', '')
    assert result[0]['Download']['progress']['MalopID'] == "11.-7780537507363356527"
    assert result[0]['Download']['progress']['batchID'][0] == "-796720096"


def test_download_fetchfile_command(client, args, mocker):
    from Cybereason import download_fetchfile_command, Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={"batchID": "-1044817479"})
    raw_response = json.loads(fetch_file_progress_raw_response)
    mocker.patch("Cybereason.download_fetchfile", return_value=raw_response)
    mocker.patch.object(demisto, 'results')
    download_fetchfile_command(client, args)
    result = demisto.results.call_args[0]
    assert result[0].get('ContentsFormat', '') == 'json'
    assert 'downloaded fetch file' in result[0].get('HumanReadable', '')
    assert result[0]['File']['SHA1'] == "9d5ef11989f0294929b572fdd4be2aefae94810d"
    assert result[0]['File']['MD5'] == "753ce5f6014c7cd549f751752978d4cf"


def test_close_fetchfile_command(client, args, mocker):
    from Cybereason import close_fetchfile_command, Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={"batchID": "-796720096"})
    close_fetchfile_command(client, args)
    result = demisto.results.call_args[0]
    assert 'Successfully aborts a file download operation that is in progress' in result[0].get('HumanReadable', '')


def test_archive_sensor_command(client, args, mocker):
    from Cybereason import archive_sensor_command, Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={
        "sensorID": "5e77883de4b0575ddcf824ef:PYLUMCLIENT_INTEGRATION_EC2AMAZ-4CTUN1V_123CC99CA7E5",
        "archiveReason": "Archive this Sensor"})
    archive_sensor_command(client, args)
    result = demisto.results.call_args[0]
    assert 'Sensor archive status: Failed Actions: 0. Succeeded Actions: 1' in result[0].get('HumanReadable', '')


def test_unarchive_sensor_command(client, args, mocker):
    from Cybereason import unarchive_sensor_command, Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={
        "sensorID": "5e77883de4b0575ddcf824ef:PYLUMCLIENT_INTEGRATION_EC2AMAZ-4CTUN1V_123CC99CA7E5",
        "archiveReason": "Unarchive this Sensor"})
    unarchive_sensor_command(client, args)
    result = demisto.results.call_args[0]
    assert 'Sensor unarchive status: Failed Actions: 0. Succeeded Actions: 1' in result[0].get('HumanReadable', '')


def test_delete_sensor_command(client, args, mocker):
    from Cybereason import delete_sensor_command, Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={
        "sensorID": "5e77883de4b0575ddcf824ef:PYLUMCLIENT_INTEGRATION_EC2AMAZ-4CTUN1V_123CC99CA7E5"})
    delete_sensor_command(client, args)
    result = demisto.results.call_args[0]
    assert 'Sensor deleted successfully' in result[0].get('HumanReadable', '')


def test_quarantine_file_command(client, args, mocker):
    from Cybereason import quarantine_file_command, Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={
        "machine": "desktop-vg9ke2u",
        "malopGuid": "11.-7780537507363356527",
        "targetId": "-1845090846.-1424333057657783286",
        "userName": "admin",
        "comment": "Quarantine the File",
        "timeout": 60})
    quarantine_file_command(client, args)
    result = demisto.results.call_args[0]
    assert 'Quarantine file remediation action status is: SUCCESS' in result[0].get('HumanReadable', '')


def test_unquarantine_file_command(client, args, mocker):
    from Cybereason import unquarantine_file_command, Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={
        "machine": "desktop-vg9ke2u",
        "malopGuid": "11.-7780537507363356527",
        "targetId": "-1845090846.-1424333057657783286",
        "userName": "admin",
        "comment": "Unquarantine the File",
        "timeout": 60})
    unquarantine_file_command(client, args)
    result = demisto.results.call_args[0]
    assert 'Unquarantine file remediation action status is: SUCCESS' in result[0].get('HumanReadable', '')


def test_block_file_command(client, args, mocker):
    from Cybereason import block_file_command, Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={
        "machine": "desktop-vg9ke2u",
        "malopGuid": "11.-7780537507363356527",
        "targetId": "-1845090846.-1424333057657783286",
        "userName": "admin",
        "comment": "Unquarantine the File",
        "timeout": 60})
    block_file_command(client, args)
    result = demisto.results.call_args[0]
    assert 'Block file remediation action status is: SUCCESS' in result[0].get('HumanReadable', '')


def test_kill_process_command(client, args, mocker):
    from Cybereason import kill_process_command, Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={
        "machine": "desktop-vg9ke2u",
        "malopGuid": "11.-7780537507363356527",
        "targetId": "-1845090846.-1424333057657783286",
        "userName": "admin",
        "comment": "Kill the Process"})
    kill_process_command(client, args)
    result = demisto.results.call_args[0]
    assert 'Kill process remediation action status is: SUCCESS' in result[0].get('HumanReadable', '')


def test_get_sensor_id_command(client, args, mocker):
    from Cybereason import get_sensor_id_command, Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={"machine": ['desktop-vg9ke2u']})
    get_sensor_id_command(client, args)
    result = demisto.results.call_args[0]
    assert 'Sensor ID for the machine desktop-vg9ke2u is: \
        5e77883de4b0575ddcf824ef:PYLUMCLIENT_INTEGRATION_DESKTOP-VG9KE2U_0800273ADC2F' in result[0].get('HumanReadable', '')


def test_fetch_scan_status_command(client, args, mocker):
    from Cybereason import fetch_scan_status_command, Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={"batchID": "-1112786456"})
    raw_response = json.loads(fetch_scan_status_raw_response)
    mocker.patch("Cybereason.fetch_scan_status_command", return_value=raw_response)
    mocker.patch.object(demisto, 'results')
    fetch_scan_status_command(client, args)
    result = demisto.results.call_args[0]
    assert result[0].get('ContentsFormat', '') == 'json'
    assert 'Fetch scan status' in result[0].get('HumanReadable', '')
    assert result[0]['actionType'] == "SchedulerScan"
    assert result[0]['startTime'] == "1652279731232"


def test_start_host_scan_command(client, args, mocker):
    from Cybereason import start_host_scan_command, Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={
        "sensorID": "5e77883de4b0575ddcf824ef:PYLUMCLIENT_INTEGRATION_DESKTOP-VG9KE2U_0800273ADC2F",
        "scanType": "FULL"})
    start_host_scan_command(client, args)
    result = demisto.results.call_args[0]
    assert 'Scanning initiation successful. Batch ID: -1112786456' in result[0].get('HumanReadable', '')


def test_malware_query_command(client, args, mocker):
    from Cybereason import malware_query_command, Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={
        "limit": "5",
        "needsAttention": "True",
        "status": "Done",
        "type": "KnownMalware",
        "timestamp": "1582206286000"})
    raw_response = json.loads(malware_query_raw_data)
    mocker.patch("Cybereason.malware_query_command", return_value=raw_response)
    mocker.patch.object(demisto, 'results')
    malware_query_command(client, args)
    result = demisto.results.call_args[0]
    assert result[0].get('ContentsFormat', '') == 'json'
    assert 'Malware query' in result[0].get('HumanReadable', '')
    assert result[0]['data']['hasMoreResults'] == "false"
    assert result[0]['status'] == "SUCCESS"


def test_unsuspend_process_command(client, args, mocker):
    from Cybereason import unsuspend_process_command, Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={
        "machine": "desktop-vg9ke2u",
        "malopGuid": "11.-7780537507363356527",
        "targetId": "-1845090846.-1424333057657783286",
        "userName": "admin",
        "comment": "Unsuspend Process"})
    unsuspend_process_command(client, args)
    result = demisto.results.call_args[0]
    assert 'Unsuspend process remediation action status is: SUCCESS' in result[0].get('HumanReadable', '')


def test_kill_prevent_unsuspend_command(client, args, mocker):
    from Cybereason import kill_prevent_unsuspend_command, Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={
        "machine": "desktop-vg9ke2u",
        "malopGuid": "11.-7780537507363356527",
        "targetId": "-1845090846.-1424333057657783286",
        "userName": "admin",
        "comment": "Kill Prevent",
        "timeout": "30"})
    kill_prevent_unsuspend_command(client, args)
    result = demisto.results.call_args[0]
    assert 'Kill prevent unsuspend remediation action status is: SUCCESS' in result[0].get('HumanReadable', '')


def test_delete_registry_key_command(client, args, mocker):
    from Cybereason import delete_registry_key_command, Client
    HEADERS = {'Content-Type': 'application/json', 'Connection': 'close'}
    client = Client(
        base_url="https://integration.cybereason.net:8443",
        verify=False,
        headers=HEADERS,
        proxy=True)
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'args', return_value={
        "machine": "desktop-vg9ke2u",
        "malopGuid": "11.-7780537507363356527",
        "targetId": "-1845090846.-1424333057657783286",
        "userName": "admin",
        "comment": "Remove the registry key",
        "timeout": "30"})
    delete_registry_key_command(client, args)
    result = demisto.results.call_args[0]
    assert 'Delete registry key remediation action status is: SUCCESS' in result[0].get('HumanReadable', '')
