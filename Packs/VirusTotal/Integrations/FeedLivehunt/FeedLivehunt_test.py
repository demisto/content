import demistomock as demisto
from FeedLivehunt import Client, fetch_indicators_command, get_indicators_command, main
from unittest.mock import call

MOCK_VT_RESPONSE = {
    "data": [
        {
            "attributes": {
                "type_description": "Win32 EXE",
                "tlsh": "T155069E15A6D82B64E7F35FB2217B871007797E45885B929E1660A04F0C33F5CDEB2F29",
                "vhash": "036046651d6510b8z201cpz31zd025z",
                "exiftool": {
                    "MIMEType": "application/octet-stream",
                    "Subsystem": "Windows GUI",
                    "MachineType": "Intel 386 or later, and compatibles",
                    "TimeStamp": "2010:11:20 09:03:08+00:00",
                    "FileType": "Win32 EXE",
                    "PEType": "PE32",
                    "CodeSize": "36864",
                    "LinkerVersion": "6.0",
                    "ImageFileCharacteristics": "No relocs, Executable, No line numbers, No symbols, 32-bit",
                    "FileTypeExtension": "exe",
                    "InitializedDataSize": "3682304",
                    "SubsystemVersion": "4.0",
                    "ImageVersion": "0.0",
                    "OSVersion": "4.0",
                    "EntryPoint": "0x9a16",
                    "UninitializedDataSize": "0"
                },
                "trid": [
                    {
                        "file_type": "Win32 Executable MS Visual C++ (generic)",
                        "probability": 38.8
                    },
                    {
                        "file_type": "Microsoft Visual C++ compiled executable (generic)",
                        "probability": 20.5
                    },
                    {
                        "file_type": "Win64 Executable (generic)",
                        "probability": 13.0
                    },
                    {
                        "file_type": "Win32 Dynamic Link Library (generic)",
                        "probability": 8.1
                    },
                    {
                        "file_type": "Win16 NE executable (generic)",
                        "probability": 6.2
                    }
                ],
                "creation_date": 1290243788,
                "names": [
                    "6a650da84adf6e3356227cc8890a9ee7.virus"
                ],
                "last_modification_date": 1635959808,
                "type_tag": "peexe",
                "times_submitted": 1,
                "total_votes": {
                    "harmless": 0,
                    "malicious": 0
                },
                "size": 3723264,
                "popular_threat_classification": {
                    "vhash_cluster_name": [
                        "forgiving",
                        "unhealthful",
                        "swordsmanship"
                    ],
                    "suggested_threat_label": "trojan.wannacry/wannacryptor",
                    "popular_threat_category": [
                        {
                            "count": 23,
                            "value": "trojan"
                        },
                        {
                            "count": 21,
                            "value": "ransomware"
                        }
                    ],
                    "popular_threat_name": [
                        {
                            "count": 10,
                            "value": "wannacry"
                        },
                        {
                            "count": 7,
                            "value": "wannacryptor"
                        },
                        {
                            "count": 6,
                            "value": "wannacrypt"
                        }
                    ]
                },
                "authentihash": "7adeabbcb861b786990dab55a6030a8b56ea2a2df7b2e38e09b6b3de747ce0f7",
                "last_submission_date": 1635952526,
                "meaningful_name": "6a650da84adf6e3356227cc8890a9ee7.virus",
                "downloadable": True,
                "sha256": "9ceef6e3194cb4babe53863b686a012be4a1b368aca7c108df80b77adb5a1c25",
                "type_extension": "exe",
                "tags": [
                    "peexe",
                    "cve-2017-0147",
                    "exploit"
                ],
                "last_analysis_date": 1635952526,
                "unique_sources": 1,
                "first_submission_date": 1635952526,
                "sha1": "f13339bc7527261c3552cc37c619f33ca04c1321",
                "ssdeep": "12288:GwbLgPluCtgQbaIMu7L5NVErCA4z2g6rTcbckPU82900Ve7zw+K+D85SQeuB8:VbLgdrgDdmMSirYbcMNgef0Xk+8",
                "bloom": "eNozqDA0oC2glvlGBqOAjsBiNAhGwSgYisBkkGb10SJlJAEAAXSRWA==\n",
                "packers": {
                    "PEiD": "Microsoft Visual C++"
                },
                "md5": "6a650da84adf6e3356227cc8890a9ee7",
                "pe_info": {
                    "imphash": "9ecee117164e0b870a53dd187cdd7174",
                },
                "magic": "PE32 executable for MS Windows (GUI) Intel 80386 32-bit",
                "last_analysis_stats": {
                    "harmless": 0,
                    "type-unsupported": 5,
                    "suspicious": 0,
                    "confirmed-timeout": 0,
                    "timeout": 0,
                    "failure": 0,
                    "malicious": 60,
                    "undetected": 9
                },
                "reputation": 0
            },
            "type": "file",
            "id": "9ceef6e3194cb4babe53863b686a012be4a1b368aca7c108df80b77adb5a1c25",
        },
    ],
}


def test_fetch_indicators_command(mocker):
    client = Client('https://fake')
    mocker.patch.object(
        client,
        'get_api_indicators',
        return_value=MOCK_VT_RESPONSE
    )

    indicators = fetch_indicators_command(client, None, [], 1, None)

    fields = indicators[0]['fields']

    assert len(indicators) == 1
    assert fields['md5'] == '6a650da84adf6e3356227cc8890a9ee7'
    assert fields['sha1'] == 'f13339bc7527261c3552cc37c619f33ca04c1321'
    assert fields['sha256'] == '9ceef6e3194cb4babe53863b686a012be4a1b368aca7c108df80b77adb5a1c25'
    assert fields['ssdeep'] == '12288:GwbLgPluCtgQbaIMu7L5NVErCA4z2g6rTcbckPU82900Ve7zw+K+D85SQeuB8:VbLgdrgDdmMSirYbcMNgef0Xk+8'
    assert fields['fileextension'] == 'exe'
    assert fields['filetype'] == 'peexe'
    assert fields['imphash'] == '9ecee117164e0b870a53dd187cdd7174'
    assert fields['firstseenbysource'] == 1635952526
    assert fields['lastseenbysource'] == 1635952526
    assert fields['creationdate'] == 1290243788
    assert fields['updateddate'] == 1635959808
    assert fields['detectionengines'] == 69
    assert fields['positivedetections'] == 60
    assert fields['displayname'] == '6a650da84adf6e3356227cc8890a9ee7.virus'
    assert fields['name'] == '6a650da84adf6e3356227cc8890a9ee7.virus'
    assert fields['size'] == 3723264


def test_get_indicators_command(mocker):
    client = Client('https://fake')
    mocker.patch.object(
        client,
        'get_api_indicators',
        return_value=MOCK_VT_RESPONSE
    )

    params = {
        'tlp_color': None,
        'feedTags': [],
    }

    args = {
        'limit': 1,
        'filter': None,
    }

    result = get_indicators_command(client, params, args)

    assert len(result.raw_response) == 1


def test_main_manual_command(mocker):
    params = {
        'tlp_color': None,
        'feedTags': [],
        'credentials': {'password': 'xxx'},
    }

    args = {
        'limit': 7,
        'filter': 'Wannacry',
    }

    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='vt-livehunt-get-indicators')
    mocker.patch.object(demisto, 'args', return_value=args)
    get_api_indicators_mock = mocker.patch.object(Client,
                                                  'get_api_indicators',
                                                  return_value=MOCK_VT_RESPONSE)

    main()

    assert get_api_indicators_mock.call_args == call('tag:"Wannacry"', 7)


def test_main_default_command(mocker):
    params = {
        'tlp_color': None,
        'feedTags': [],
        'credentials': {'password': 'xxx'},
        'limit': 7,
        'filter': 'Wannacry',
    }

    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='fetch-indicators')
    get_api_indicators_mock = mocker.patch.object(Client,
                                                  'get_api_indicators',
                                                  return_value=MOCK_VT_RESPONSE)

    Client.set_last_run()  # Emulate previous execution with saving last run

    main()

    assert get_api_indicators_mock.call_args == call(f'tag:"Wannacry" {Client.get_last_run()}', 7)


def test_main_test_command(mocker):
    params = {
        'credentials': {'password': 'xxx'}
    }

    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='test-module')
    get_api_indicators_mock = mocker.patch.object(Client,
                                                  'get_api_indicators',
                                                  return_value=MOCK_VT_RESPONSE)

    main()

    assert get_api_indicators_mock.call_count == 1
