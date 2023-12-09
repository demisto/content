import json
from MalwationAIMA import Client
import demistomock as demisto

BASE_URL = 'https://test.com'

client = Client(base_url=BASE_URL,
                verify=False,
                proxy=False,
                headers={
                    'Authentication': 'Bearer some_api_key'
                })

AIMA_SCAN_RESPONSE = {
    "message": "File successfully uploaded, now you can track your submissions progress from "
               "/checkSubmissionStatus/2661ca6d-8989-45b1-b912-203fa2c60a21 or "
               "/getSubmission/2661ca6d-8989-45b1-b912-203fa2c60a21",
    "uuid": "2661ca6d-8989-45b1-b912-203fa2c60a21",
    "link": "https://aima.malwation.com/submission/2661ca6d-8989-45b1-b912-203fa2c60a21"
}

AIMA_SCAN_RESULT = '''{
    "submission": {
        "file_info": {
            "hashes": {
                "md5": "6ac062d21f08f139d9f3d1e335e72e22",
                "sha1": "9e967a759e894a83c4b693e81c031d7214a8e699",
                "sha256": "564154a2e3647318ca40a5ffa68d06b1bd40b606cae1d15985e3d15097b512cd"
            },
            "original_name": "Kraken.exe",
            "status_id": 5,
            "isPublic": false,
            "tags": [
                "analysed"
            ],
            "submission_date": "25.02.2022 16:49:26",
            "level": "Malicious"
        },
        "uuid": "35b7d3f9-79e2-4d65-9a5a-01badcafc782",
        "metafields": {
            "environment": "Windows 7 x64",
            "work_path": "Desktop",
            "timeout": "2",
            "mouse_simulation": false,
            "config_extractor": false,
            "https_inspection": false,
            "full_memory_dump": false,
            "enable_net": false
        },
        "resultURL": "https://aima.malwation.com/submission/35b7d3f9-79e2-4d65-9a5a-01badcafc782/report/overview"
    },
    "submissionLevel": "Malicious",
    "statusID": 5,
    "status": "Finished"
}'''

MAV_SCAN_RESPONSE = {
    "message": "File successfully uploaded ea08526e-be42-4ca5-b3e2-2a2e278da2f9.exe",
    "uid": "ea08526e-be42-4ca5-b3e2-2a2e278da2f9"
}

STATIC_SCAN_RESPONSE = {
    "message": "File successfully uploaded ea08526e-be42-4ca5-b3e2-2a2e278da2f9.exe",
    "uid": "ea08526e-be42-4ca5-b3e2-2a2e278da2f9"
}

MAV_SCAN_RESULT = {
    "scan_results": [
        {
            "Engine1": {
                "infected": "false"
            }
        },
        {
            "Engine2": {
                "infected": "true"
            }
        },
        {
            "Engine3": {
                "infected": "true",
                "name": "malware"
            }
        }

    ],
    "detection": "2",
    "status": "malicious"
}

STATIC_SCAN_RESULT = '''{
    "Score": [
        "Suspicious",
        "6.32"
    ],
    "File Info": {
        "Filename": "fb194ccc2992c2949541d967c2e0d4d14cc95049087cc9a89b76e85a1bd12a64.exe",
        "Filesize": "127.50 KB",
        "MD5": "c916be78c2c7705084ec93aa536955ad",
        "SHA1": "e549f37404220e1be52ad6d23a62ba91b66d598b",
        "SHA256": "fb194ccc2992c2949541d967c2e0d4d14cc95049087cc9a89b76e85a1bd12a64",
        "SSDEEP": "1536:9r6sFY5eejw7xEx0vxEaqhIDImJ0b/6EKEcFpiOWBLD/tn0Kcl:9r68cK7xy0vxihIDImJ0bC77wB3VnbY",
        "MIME Type": "application/x-dosexec",
        "File Type": "PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows",
        "Entropy": "5.81"
    },
    "Checksum": false,
    "HasOverlay": false,
    "File Header": {
        "Machine": "IMAGE_FILE_MACHINE_I386",
        "Number of Sections": 3,
        "TimeDateStamp": "Sep 03 2021 18:03:53",
        "Pointer to Symbol Table": 0,
        "Number of Symbols": 0,
        "Size of Optional Header": "224 bytes",
        "Characteristics": 258
    },
    "Imphash": "f34d5f2d4577ed6d9ceec516c1f5a744",
    "Imports": {
        "mscoree.dll": [
            {
                "address": "0x402000",
                "name": "_CorExeMain",
                "blacklist": false
            }
        ]
    },
    "Exports": null,
    "Sections": [
        {
            "Name": ".text",
            "Virtual Address": "0x2000",
            "Virtual Size": "0x1e654",
            "Raw Size": "0x1e800",
            "Entropy": "5.82",
            "MD5": "9156435bfbb4b37eedd339607096f2af"
        },
        {
            "Name": ".rsrc",
            "Virtual Address": "0x22000",
            "Virtual Size": "0x1077",
            "Raw Size": "0x1200",
            "Entropy": "4.86",
            "MD5": "a423593c987ffa8998c959f2412129f2"
        },
        {
            "Name": ".reloc",
            "Virtual Address": "0x24000",
            "Virtual Size": "0xc",
            "Raw Size": "0x200",
            "Entropy": "0.08",
            "MD5": "42bbc02695d421e6b2eb55c3c54ff7fe"
        }
    ],
    "Resources": [
        {
            "Name": "RT_VERSION",
            "Size": "892.00 B",
            "Offset": "0x000220a0",
            "Type": "data",
            "Lang": "LANG_NEUTRAL",
            "Sublang": "SUBLANG_NEUTRAL",
            "SHA256": "490fdec38fc44d7532cf20175c3679773df3321dab28de967cab68862db5b073",
            "Entropy": "3.43"
        },
        {
            "Name": "RT_MANIFEST",
            "Size": "3.09 KB",
            "Offset": "0x0002241c",
            "Type": "XML 1.0 document, UTF-8 Unicode (with BOM) text, with CRLF line terminators",
            "Lang": "LANG_NEUTRAL",
            "Sublang": "SUBLANG_NEUTRAL",
            "SHA256": "51ac86fb532fb5883231be4ef7538255e6875d63fa62c8035d72f4d65c0ec114",
            "Entropy": "5.01"
        }
    ],
    "Debug Info": null,
    "Strings": [
        {
            "value": "L!This program cannot be run in DOS mode.",
            "hint": null,
            "blacklist": false
        }
    ],
    "ATTCK": {},
    "MBC": {},
    "CAPABILITY": {
        "executable/pe/section/rsrc": [
            "contain a resource (.rsrc) section"
        ],
        "internal/limitation/file": [
            "(internal) dotnet file limitation"
        ],
        "runtime/dotnet": [
            "compiled to the .NET platform"
        ]
    },
    "Matched YARA rules": [
        "IP",
        "NETexecutableMicrosoft",
        "contains_base64"
    ],
    "Analysis Time": 4.741647481918335
}'''


def test_cap_mav_get_submission(requests_mock):
    from MalwationAIMA import cap_mav_get_submission

    mock_response = MAV_SCAN_RESULT
    requests_mock.get('https://test.com/mav/filestatus/dumb_uid', json=mock_response)

    args = {
        'uuid': 'dumb_uid'
    }

    response = cap_mav_get_submission(client, args)

    assert response.outputs['CAP.Mav(val.Job_ID == obj.Job_ID)']['SCORE'] == mock_response['status']
    assert response.outputs['CAP.Mav(val.Job_ID == obj.Job_ID)']['COUNT'] == mock_response['detection']
    assert response.outputs['CAP.Mav(val.Job_ID == obj.Job_ID)']['DETECTIONS'] == mock_response['scan_results']


def test_cap_mav_upload_sample(mocker, requests_mock):
    from MalwationAIMA import cap_mav_upload_sample

    mock_response = MAV_SCAN_RESPONSE
    mocker.patch.object(demisto, 'getFilePath',
                        return_value={'id': id, 'path': './test_data/cap_mav_scan_response.json',
                                      'name': 'cap_mav_scan_response.json'})
    requests_mock.post('https://test.com/mav/upload', json=mock_response)

    args = {
        'entry_id': 'dumb_file_entry_id'
    }

    response = cap_mav_upload_sample(client, args)

    assert response.outputs['CAP.Mav(val.Job_ID == obj.Job_ID)']['UUID'] == mock_response["uid"]


def test_cap_static_get_submission(requests_mock):
    from MalwationAIMA import cap_static_get_submission

    mock_response = json.loads(STATIC_SCAN_RESULT)
    requests_mock.get('https://test.com/capstatic/filestatus/dumb_uid', json=mock_response)

    args = {
        'uuid': 'dumb_uid'
    }

    response = cap_static_get_submission(client, args)

    assert response.outputs['CAP.Static(val.Job_ID == obj.Job_ID)']['SCORE'] == mock_response['Score'][0]


def test_cap_static_upload_sample(mocker, requests_mock):
    from MalwationAIMA import cap_static_upload_sample

    mock_response = STATIC_SCAN_RESPONSE
    mocker.patch.object(demisto, 'getFilePath',
                        return_value={'id': id, 'path': './test_data/cap_static_scan_response.json',
                                      'name': 'cap_static_scan_response.json'})
    requests_mock.post('https://test.com/capstatic/upload', json=mock_response)

    args = {
        'entry_id': 'dumb_file_entry_id'
    }

    response = cap_static_upload_sample(client, args)

    assert response.outputs['CAP.Static(val.Job_ID == obj.Job_ID)']['UUID'] == mock_response["uid"]


def test_aima_get_result(requests_mock):
    from MalwationAIMA import aima_get_result

    mock_response = json.loads(AIMA_SCAN_RESULT)
    requests_mock.get('https://test.com/customer/getSubmission/dumb_uid', json=mock_response)

    args = {
        'uuid': 'dumb_uid'
    }

    response = aima_get_result(client, args)

    assert response.outputs['AIMA.Result(val.Job_ID == obj.Job_ID)']['LEVEL'] == mock_response['submissionLevel']


def test_aima_upload_sample(mocker, requests_mock):
    from MalwationAIMA import aima_upload_sample

    mock_response = AIMA_SCAN_RESPONSE
    mocker.patch.object(demisto, 'getFilePath',
                        return_value={'id': id, 'path': './test_data/aima_scan_response.json',
                                      'name': 'aima_scan_response.json'})
    requests_mock.post('https://test.com/customer/addSubmission', json=mock_response)

    args = {
        'entry_id': 'dumb_file_entry_id',
        'environment': 'win7x64',
        'isPublic': 'No',
        "work_path": "desktop",
        "timeout": '2',
        "mouse_simulation": 'false',
        "config_extractor": 'false',
        "https_inspection": 'false',
        "full_memory_dump": 'false',
        "enable_net": 'false'
    }

    response = aima_upload_sample(client, args)

    assert response.outputs['AIMA.Analysis(val.Job_ID == obj.Job_ID)']['UUID'] == mock_response['uuid']
