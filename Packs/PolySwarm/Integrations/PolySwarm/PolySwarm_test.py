import pytest
from mock import patch, mock_open

import demistomock as demisto

from PolySwarm import PolyswarmConnector, POLYSWARM_URL_RESULTS

TEST_SCAN_UUID = 'eda6fbd6-b1c6-4e97-8126-01f936460fe5'
TEST_SCAN_DOMAIN = 'domain-test.com'
TEST_SCAN_IP = '0.0.0.0'
TEST_SCAN_URL = 'https://url-test.com'
TEST_HASH_FILE = '939adb211c3bcf76b84b2417e1d39248994e21d48a3d7eddca87bb76d6c31cc3'
TEST_ENTRY_ID = 'XXXXX'

MOCK_API_URL = 'http://polyswarm-fake-api.com'

MOCK_PARAMS = {'api_key': 'XXXXXXXXXXXXXXXXXXXXXXXXXX',
               'base_url': MOCK_API_URL,
               'polyswarm_community': 'polyswarm_community'}

MOCK_FILE_INFO = {'name': 'MaliciousFile.exe', 'path': '/path/MaliciousFile.exe'}

MOCK_SCAN_JSON_RESPONSE = {'result': TEST_SCAN_UUID}

MOCK_LOOKUP_JSON_RESPOSE = {'result': {
    "files": [
        {
            "assertions": [
                {
                    "author": "0",
                    "bid": 500000000000000000,
                    "engine": "N",
                    "mask": True,
                    "metadata": {
                        "malware_family": "",
                        "scanner": {
                            "environment": {
                                "architecture": "AMD64",
                                "operating_system": "Windows"
                            },
                            "signatures_version": "0.14.32.16015|1568318271000",
                            "vendor_version": "1.0.134.90395",
                            "version": "0.1.0"
                        }
                    },
                    "verdict": False
                },
                {
                    "author": "0",
                    "bid": 500000000000000000,
                    "engine": "T",
                    "mask": True,
                    "metadata": {
                        "malware_family": "",
                        "scanner": {
                            "environment": {
                                "architecture": "x86_64",
                                "operating_system": "Linux"
                            },
                            "vendor_version": "4.1",
                            "version": "0.1.0"
                        }
                    },
                    "verdict": False
                },
                {
                    "author": "0",
                    "bid": 500000000000000000,
                    "engine": "A",
                    "mask": True,
                    "metadata": {
                        "malware_family": "TrojanBanker",
                        "scanner": {
                            "environment": {
                                "architecture": "AMD64",
                                "operating_system": "Windows"
                            }
                        },
                        "type": "zip"
                    },
                    "verdict": True
                },
                {
                    "author": "0",
                    "bid": 500000000000000000,
                    "engine": "Nucleon",
                    "mask": True,
                    "metadata": {
                        "malware_family": "",
                        "scanner": {
                            "environment": {
                                "architecture": "x86_64",
                                "operating_system": "Linux"
                            },
                            "vendor_version": "",
                            "version": "0.1.0"
                        }
                    },
                    "verdict": False
                },
                {
                    "author": "0",
                    "bid": 41250000000000000,
                    "engine": "X",
                    "mask": True,
                    "metadata": {
                        "malware_family": "",
                        "scanner": {
                            "environment": {
                                "architecture": "AMD64",
                                "operating_system": "Windows"
                            },
                            "vendor_version": "1",
                            "version": "0.2.0"
                        }
                    },
                    "verdict": False
                },
                {
                    "author": "0",
                    "bid": 500000000000000000,
                    "engine": "K",
                    "mask": True,
                    "metadata": {
                        "malware_family": "",
                        "scanner": {
                            "environment": {
                                "architecture": "AMD64",
                                "operating_system": "Windows"
                            },
                            "signatures_version": "11.66.31997|12/Sep/2019",
                            "vendor_version": "1",
                            "version": "0.2.0"
                        }
                    },
                    "verdict": False
                },
                {
                    "author": "0",
                    "bid": 500000000000000000,
                    "engine": "0",
                    "mask": True,
                    "metadata": {
                        "malware_family": "",
                        "scanner": {
                            "environment": {
                                "architecture": "x86_64",
                                "operating_system": "Linux"
                            },
                            "signatures_version": "",
                            "vendor_version": "drweb-ctl 11.1.2.1907091642\n",
                            "version": "0.3.0"
                        }
                    },
                    "verdict": True
                },
                {
                    "author": "0",
                    "bid": 500000000000000000,
                    "engine": "I",
                    "mask": True,
                    "metadata": {
                        "malware_family": "Trojan.AndroidOS.Agent",
                        "scanner": {
                            "environment": {
                                "architecture": "x86_64",
                                "operating_system": "Linux"
                            },
                            "signatures_version": "09.10.2019 12:19:44 (102008)",
                            "vendor_version": "0",
                            "version": "0.2.0"
                        }
                    },
                    "verdict": True
                },
                {
                    "author": "0",
                    "bid": 500000000000000000,
                    "engine": "L",
                    "mask": True,
                    "metadata": {
                        "malware_family": "",
                        "scanner": {
                            "environment": {
                                "architecture": "AMD64",
                                "operating_system": "Windows"
                            }
                        }
                    },
                    "verdict": True
                },
                {
                    "author": "0",
                    "bid": 500000000000000000,
                    "engine": "Z",
                    "mask": True,
                    "metadata": {
                        "malware_family": "",
                        "scanner": {
                            "environment": {
                                "architecture": "x86_64",
                                "operating_system": "Linux"
                            },
                            "vendor_version": "1.1",
                            "version": "0.1.0"
                        }
                    },
                    "verdict": False
                },
                {
                    "author": "0",
                    "bid": 500000000000000000,
                    "engine": "C",
                    "mask": True,
                    "metadata": {
                        "malware_family": "",
                        "scanner": {
                            "environment": {
                                "architecture": "x86_64",
                                "operating_system": "Linux"
                            },
                            "vendor_version": "C"
                        }
                    },
                    "verdict": False
                },
                {
                    "author": "0",
                    "bid": 500000000000000000,
                    "engine": "T",
                    "mask": True,
                    "metadata": {
                        "malware_family": "",
                        "scanner": {
                            "environment": {
                                "architecture": "AMD64",
                                "operating_system": "Windows"
                            },
                            "vendor_version": "2018.11.28.1",
                            "version": "0.1.0"
                        }
                    },
                    "verdict": False
                },
                {
                    "author": "0",
                    "bid": 500000000000000000,
                    "engine": "Q",
                    "mask": True,
                    "metadata": {
                        "malware_family": "",
                        "scanner": {
                            "environment": {
                                "architecture": "AMD64",
                                "operating_system": "Windows"
                            }
                        }
                    },
                    "verdict": False
                },
                {
                    "author": "0",
                    "bid": 500000000000000000,
                    "engine": "R",
                    "mask": True,
                    "metadata": {
                        "malware_family": "Malware.Strealer/Android!8.5B3",
                        "scanner": {
                            "environment": {
                                "architecture": "x86_64",
                                "operating_system": "Linux"
                            }
                        }
                    },
                    "verdict": True
                },
                {
                    "author": "0",
                    "bid": 500000000000000000,
                    "engine": "J",
                    "mask": True,
                    "metadata": {
                        "malware_family": "",
                        "scanner": {
                            "environment": {
                                "architecture": "AMD64",
                                "operating_system": "Windows"
                            },
                            "signatures_version": "",
                            "vendor_version": "16.0.100 ",
                            "version": "0.2.0"
                        }
                    },
                    "verdict": False
                },
                {
                    "author": "0",
                    "bid": 500000000000000000,
                    "engine": "Q",
                    "mask": True,
                    "metadata": {
                        "malware_family": "",
                        "scanner": {
                            "environment": {
                                "architecture": "AMD64",
                                "operating_system": "Windows"
                            },
                            "signatures_version": "09 September, 2019",
                            "version": "0.1.0"
                        }
                    },
                    "verdict": False
                },
                {
                    "author": "0",
                    "bid": 325000000000000000,
                    "engine": "V",
                    "mask": True,
                    "metadata": {
                        "malware_family": "",
                        "scanner": {
                            "environment": {
                                "architecture": "x86_64",
                                "operating_system": "Linux"
                            },
                            "version": "0.1.0"
                        }
                    },
                    "verdict": True
                }
            ],
            "bounty_guid": "534f72db-2dcb-48f3-be3f-4cf9fd1b224b",
            "bounty_status": "Awaiting arbitration.",
            "failed": False,
            "filename": "939adb211c3bcf76b84b2417e1d39248994e21d48a3d7eddca87bb76d6c31cc3",
            "hash": "939adb211c3bcf76b84b2417e1d39248994e21d48a3d7eddca87bb76d6c31cc3",
            "result": "null",
            "size": 1974989,
            "submission_guid": "313f58e0-76b1-4652-9b67-d1ef46a8911e",
            "votes": [],
            "window_closed": True
        }
    ],
    "forced": False,
    "permalink": "https://polyswarm.network/scan/results/313f58e0-76b1-4652-9b67-d1ef46a8911e",
    "status": "OK",
    "uuid": "313f58e0-76b1-4652-9b67-d1ef46a8911e"
}
}

MOCK_SEARCH_JSON_RESPONSE = {
    "result": [
        {
            "first_seen": "Mon, 16 Sep 2019 21:57:26 GMT",
            "extended_type": "Zip archive data",
            "sha256": "sha256",
            "artifact_instances": [
                {
                    "community": "lima",
                    "country": "ES",
                    "bounty_id": "5333178496563012",
                    "submitted": "Mon, 16 Sep 2019 21:57:26 GMT",
                    "id": "10030645235184960",
                    "consumer_guid": "null",
                    "name": "fakegps.apk",
                    "bounty_result": {
                        "uuid": "eda6fbd6-b1c6-4e97-8126-01f936460fe5",
                        "files": [
                            {
                                "bounty_status": "Bounty Settled",
                                "filename": "fakegps.apk",
                                "failed": False,
                                "size": 459632,
                                "votes": [
                                    {
                                        "arbiter": "0",
                                        "vote": False
                                    },
                                    {
                                        "arbiter": "0",
                                        "vote": False
                                    },
                                    {
                                        "arbiter": "0",
                                        "vote": True
                                    }
                                ],
                                "bounty_guid": "c21cba7a-43c8-452d-a1bd-c30ce21f66e9",
                                "submission_guid": "eda6fbd6-b1c6-4e97-8126-01f936460fe5",
                                "hash": "hash",
                                "window_closed": True,
                                "assertions": [
                                    {
                                        "mask": True,
                                        "author": "0",
                                        "metadata": {
                                            "scanner": {
                                                "vendor_version": "1",
                                                "environment": {
                                                    "operating_system": "Windows",
                                                    "architecture": "AMD64"
                                                },
                                                "version": "0.2.0"
                                            },
                                            "malware_family": ""
                                        },
                                        "bid": 412500000000000000,
                                        "verdict": False
                                    },
                                    {
                                        "verdict": False,
                                        "author": "0",
                                        "metadata": {
                                            "scanner": {
                                                "vendor_version": "",
                                                "version": "0.1.0",
                                                "environment": {
                                                    "architecture": "x86_64",
                                                    "operating_system": "Linux"
                                                }
                                            },
                                            "malware_family": ""
                                        },
                                        "bid": 500000000000000000,
                                        "mask": True
                                    },
                                    {
                                        "verdict": True,
                                        "mask": True,
                                        "bid": 500000000000000000,
                                        "metadata": {
                                            "scanner": {
                                                "vendor_version": "2",
                                                "signatures_version": "11.63.31830|26/Aug/2019",
                                                "version": "0.2.0",
                                                "environment": {
                                                    "architecture": "AMD64",
                                                    "operating_system": "Windows"
                                                }
                                            },
                                            "malware_family": "Spyware ( 0054a7d61 )"
                                        },
                                        "author": "0"
                                    },
                                    {
                                        "verdict": True,
                                        "mask": True,
                                        "author": "0",
                                        "metadata": {
                                            "scanner": {
                                                "environment": {
                                                    "architecture": "x86_64",
                                                    "operating_system": "Linux"
                                                }
                                            },
                                            "malware_family": "Virus"
                                        },
                                        "bid": 500000000000000000
                                    },
                                    {
                                        "mask": True,
                                        "bid": 500000000000000000,
                                        "author": "0",
                                        "metadata": {
                                            "scanner": {
                                                "vendor_version": "4.1",
                                                "version": "0.1.0",
                                                "environment": {
                                                    "operating_system": "Linux",
                                                    "architecture": "x86_64"
                                                }
                                            },
                                            "malware_family": "Android.Malware.Spyware"
                                        },
                                        "verdict": True
                                    },
                                    {
                                        "mask": True,
                                        "author": "0",
                                        "metadata": {
                                            "scanner": {
                                                "vendor_version": "ClamAV 0.100.3/25574/Mon Sep 16 08:25:07 2019\n",
                                                "environment": {
                                                    "operating_system": "Linux",
                                                    "architecture": "x86_64"
                                                }
                                            },
                                            "malware_family": ""
                                        },
                                        "bid": 500000000000000000,
                                        "verdict": False
                                    },
                                    {
                                        "metadata": {
                                            "scanner": {
                                                "vendor_version": "16.0.100 ",
                                                "signatures_version": "",
                                                "version": "0.2.0",
                                                "environment": {
                                                    "operating_system": "Windows",
                                                    "architecture": "AMD64"
                                                }
                                            },
                                            "malware_family": ""
                                        },
                                        "author": "0",
                                        "bid": 500000000000000000,
                                        "mask": True,
                                        "verdict": False
                                    },
                                    {
                                        "mask": True,
                                        "author": "0",
                                        "metadata": {
                                            "scanner": {
                                                "version": "0.2.0",
                                                "environment": {
                                                    "operating_system": "Linux",
                                                    "architecture": "x86_64"
                                                },
                                                "vendor_version": "1",
                                                "signatures_version": "16.09.2019 18:19:06 (101938)"
                                            },
                                            "malware_family": "Trojan.AndroidOS.Agent"
                                        },
                                        "bid": 500000000000000000,
                                        "verdict": True
                                    },
                                    {
                                        "bid": 500000000000000000,
                                        "author": "0",
                                        "metadata": {
                                            "malware_family": "",
                                            "type": "zip",
                                            "scanner": {
                                                "environment": {
                                                    "operating_system": "Windows",
                                                    "architecture": "AMD64"
                                                }
                                            }
                                        },
                                        "mask": True,
                                        "verdict": True
                                    },
                                    {
                                        "verdict": True,
                                        "metadata": {
                                            "scanner": {
                                                "vendor_version": "drweb-ctl 11.1.2.1907091642\n",
                                                "signatures_version": "",
                                                "version": "0.3.0",
                                                "environment": {
                                                    "operating_system": "Linux",
                                                    "architecture": "x86_64"
                                                }
                                            },
                                            "malware_family": "infected with Android.Backdoor.687.origin"
                                        },
                                        "author": "0",
                                        "bid": 500000000000000000,
                                        "mask": True
                                    },
                                    {
                                        "mask": True,
                                        "author": "0",
                                        "metadata": {
                                            "malware_family": "",
                                            "scanner": {
                                                "version": "0.1.0",
                                                "environment": {
                                                    "architecture": "x86_64",
                                                    "operating_system": "Linux"
                                                }
                                            }
                                        },
                                        "bid": 412500000000000000,
                                        "verdict": False
                                    },
                                    {
                                        "mask": True,
                                        "author": "0",
                                        "metadata": {
                                            "scanner": {
                                                "environment": {
                                                    "operating_system": "Windows",
                                                    "architecture": "AMD64"
                                                }
                                            },
                                            "malware_family": ""
                                        },
                                        "bid": 500000000000000000,
                                        "verdict": False
                                    },
                                    {
                                        "mask": True,
                                        "metadata": {
                                            "scanner": {
                                                "environment": {
                                                    "operating_system": "Windows",
                                                    "architecture": "AMD64"
                                                }
                                            },
                                            "malware_family": ""
                                        },
                                        "author": "0",
                                        "bid": 500000000000000000,
                                        "verdict": True
                                    },
                                    {
                                        "mask": True,
                                        "metadata": {
                                            "malware_family": "",
                                            "scanner": {
                                                "vendor_version": "1.1",
                                                "version": "0.1.0",
                                                "environment": {
                                                    "operating_system": "Linux",
                                                    "architecture": "x86_64"
                                                }
                                            }
                                        },
                                        "author": "0",
                                        "bid": 500000000000000000,
                                        "verdict": False
                                    },
                                    {
                                        "verdict": False,
                                        "mask": True,
                                        "metadata": {
                                            "malware_family": "",
                                            "scanner": {
                                                "version": "0.3.0",
                                                "environment": {
                                                    "operating_system": "Linux",
                                                    "architecture": "x86_64"
                                                },
                                                "vendor_version": "1.2.9"
                                            }
                                        },
                                        "author": "0",
                                        "bid": 500000000000000000
                                    },
                                    {
                                        "mask": True,
                                        "bid": 500000000000000000,
                                        "author": "0",
                                        "metadata": {
                                            "scanner": {
                                                "vendor_version": "2018.11.28.1",
                                                "version": "0.1.0",
                                                "environment": {
                                                    "operating_system": "Windows",
                                                    "architecture": "AMD64"
                                                }
                                            },
                                            "malware_family": ""
                                        },
                                        "verdict": False
                                    }
                                ],
                                "result": True
                            }
                        ],
                        "permalink": "https://polyswarm.network/scan/results/2521926f-0997-4a01-9f91-617a6ee2097a",
                        "status": "Bounty Settled",
                        "artifact_type": "FILE"
                    },
                    "artifact_id": "4881202378792140"
                }
            ],
            "md5": "ac92258ff3395137dd590af36ca2d8c9",
            "sha1": "20983fae703dd0d0b26eef39ac8f222050a8aeec",
            "id": "4881202378792140",
            "mimetype": "application/zip",
            "artifact_metadata": {
                "strings": {
                    "urls": [
                        "com.app",
                        "A.ma"
                    ],
                    "domains": [
                        "com.app",
                        "A.ma"
                    ],
                    "ipv6": [],
                    "ipv4": []
                },
                "hash": {
                    "ssdeep": "g",
                    "tlsh": "tlsh",
                    "sha512": "98a8854cfd69ea9a5fc60d5966fba5e7e1b60afe114e4abafeeed4310f8fa661bbbf51c2b19694b181",
                    "sha1": "20983fae703dd0d0b26eef39ac8f222050a8aeec",
                    "md5": "ac92258ff3395137dd590af36ca2d8c9",
                    "sha3_256": "1131836a552a439036ed164590f9c3908c642fb6250e65a5bd3bd34fe6618f32",
                    "sha3_512": "sha3_215",
                    "sha256": "sha256"
                }
            }
        }
    ],
    "status": "OK"
}


def test_polyswarm_get_report(mocker, requests_mock):
    mocker.patch.object(demisto, 'params',
                        return_value=MOCK_PARAMS)

    polyswarm = PolyswarmConnector()

    param = {'scan_uuid': TEST_SCAN_UUID}

    path_url_lookup = '/consumer/{polyswarm_community}/uuid/{uuid}'. \
        format(polyswarm_community=demisto.params().get('polyswarm_community'),
               uuid=param['scan_uuid'])

    requests_mock.get(MOCK_API_URL + path_url_lookup,
                      json=MOCK_LOOKUP_JSON_RESPOSE)

    results = polyswarm.get_report(param)

    assert results['Contents']['Positives'] == '6'
    assert results['Contents']['Total'] == '17'
    assert results['Contents']['Scan_UUID'] == TEST_SCAN_UUID
    assert results['Contents']['Permalink'] == POLYSWARM_URL_RESULTS + '/' + TEST_SCAN_UUID
    assert results['Contents']['Artifact'] == TEST_SCAN_UUID


def test_domain(mocker, requests_mock):
    mocker.patch.object(demisto, 'params',
                        return_value=MOCK_PARAMS)

    polyswarm = PolyswarmConnector()

    param = {'domain': TEST_SCAN_DOMAIN}

    path_url_scan = '/consumer/{polyswarm_community}'. \
        format(polyswarm_community=demisto.params().get('polyswarm_community'))

    requests_mock.post(MOCK_API_URL + path_url_scan,
                       json=MOCK_SCAN_JSON_RESPONSE)

    path_url_lookup = '/consumer/{polyswarm_community}/uuid/{uuid}'. \
        format(polyswarm_community=demisto.params().get('polyswarm_community'),
               uuid=TEST_SCAN_UUID)

    requests_mock.get(MOCK_API_URL + path_url_lookup,
                      json=MOCK_LOOKUP_JSON_RESPOSE)

    results = polyswarm.url_reputation(param, 'domain')

    assert results['Contents']['Positives'] == '6'
    assert results['Contents']['Total'] == '17'
    assert results['Contents']['Scan_UUID'] == TEST_SCAN_UUID
    assert results['Contents']['Permalink'] == POLYSWARM_URL_RESULTS + '/' + TEST_SCAN_UUID
    assert results['Contents']['Artifact'] == TEST_SCAN_DOMAIN


def test_ip(mocker, requests_mock):
    mocker.patch.object(demisto, 'params',
                        return_value=MOCK_PARAMS)

    polyswarm = PolyswarmConnector()

    param = {'ip': TEST_SCAN_IP}

    path_url_scan = '/consumer/{polyswarm_community}'. \
        format(polyswarm_community=demisto.params().get('polyswarm_community'))

    requests_mock.post(MOCK_API_URL + path_url_scan,
                       json=MOCK_SCAN_JSON_RESPONSE)

    path_url_lookup = '/consumer/{polyswarm_community}/uuid/{uuid}'. \
        format(polyswarm_community=demisto.params().get('polyswarm_community'),
               uuid=TEST_SCAN_UUID)

    requests_mock.get(MOCK_API_URL + path_url_lookup,
                      json=MOCK_LOOKUP_JSON_RESPOSE)

    results = polyswarm.url_reputation(param, 'ip')

    assert results['Contents']['Positives'] == '6'
    assert results['Contents']['Total'] == '17'
    assert results['Contents']['Scan_UUID'] == TEST_SCAN_UUID
    assert results['Contents']['Permalink'] == POLYSWARM_URL_RESULTS + '/' + TEST_SCAN_UUID
    assert results['Contents']['Artifact'] == TEST_SCAN_IP


def test_url_scan(mocker, requests_mock):
    mocker.patch.object(demisto, 'params',
                        return_value=MOCK_PARAMS)

    polyswarm = PolyswarmConnector()

    param = {'url': TEST_SCAN_URL}

    path_url_scan = '/consumer/{polyswarm_community}'. \
        format(polyswarm_community=demisto.params().get('polyswarm_community'))

    requests_mock.post(MOCK_API_URL + path_url_scan,
                       json=MOCK_SCAN_JSON_RESPONSE)

    path_url_lookup = '/consumer/{polyswarm_community}/uuid/{uuid}'. \
        format(polyswarm_community=demisto.params().get('polyswarm_community'),
               uuid=TEST_SCAN_UUID)

    requests_mock.get(MOCK_API_URL + path_url_lookup,
                      json=MOCK_LOOKUP_JSON_RESPOSE)

    results = polyswarm.url_reputation(param, 'url')

    assert results['Contents']['Positives'] == '6'
    assert results['Contents']['Total'] == '17'
    assert results['Contents']['Scan_UUID'] == TEST_SCAN_UUID
    assert results['Contents']['Permalink'] == POLYSWARM_URL_RESULTS + '/' + TEST_SCAN_UUID
    assert results['Contents']['Artifact'] == TEST_SCAN_URL


def test_url(mocker, requests_mock):
    mocker.patch.object(demisto, 'params',
                        return_value=MOCK_PARAMS)

    polyswarm = PolyswarmConnector()

    param = {'url': TEST_SCAN_URL}

    path_url_scan = '/consumer/{polyswarm_community}'. \
        format(polyswarm_community=demisto.params().get('polyswarm_community'))

    requests_mock.post(MOCK_API_URL + path_url_scan,
                       json=MOCK_SCAN_JSON_RESPONSE)

    path_url_lookup = '/consumer/{polyswarm_community}/uuid/{uuid}'. \
        format(polyswarm_community=demisto.params().get('polyswarm_community'),
               uuid=TEST_SCAN_UUID)

    requests_mock.get(MOCK_API_URL + path_url_lookup,
                      json=MOCK_LOOKUP_JSON_RESPOSE)

    results = polyswarm.url_reputation(param, 'url')

    assert results['Contents']['Positives'] == '6'
    assert results['Contents']['Total'] == '17'
    assert results['Contents']['Scan_UUID'] == TEST_SCAN_UUID
    assert results['Contents']['Permalink'] == POLYSWARM_URL_RESULTS + '/' + TEST_SCAN_UUID
    assert results['Contents']['Artifact'] == TEST_SCAN_URL


def test_file_rescan(mocker, requests_mock):
    mocker.patch.object(demisto, 'params',
                        return_value=MOCK_PARAMS)

    polyswarm = PolyswarmConnector()

    param = {'hash': TEST_HASH_FILE}

    path_rescan = '/consumer/{polyswarm_community}/rescan/{hash_type}/{hash}'. \
        format(polyswarm_community=demisto.params().get('polyswarm_community'),
               hash_type='sha256', hash=TEST_HASH_FILE)

    requests_mock.post(MOCK_API_URL + path_rescan,
                       json=MOCK_SCAN_JSON_RESPONSE)

    path_url_lookup = '/consumer/{polyswarm_community}/uuid/{uuid}'. \
        format(polyswarm_community=demisto.params().get('polyswarm_community'),
               uuid=TEST_SCAN_UUID)

    requests_mock.get(MOCK_API_URL + path_url_lookup,
                      json=MOCK_LOOKUP_JSON_RESPOSE)

    results = polyswarm.rescan_file(param)

    assert results['Contents']['Positives'] == '6'
    assert results['Contents']['Total'] == '17'
    assert results['Contents']['Scan_UUID'] == TEST_SCAN_UUID
    assert results['Contents']['Permalink'] == POLYSWARM_URL_RESULTS + '/' + TEST_SCAN_UUID
    assert results['Contents']['Artifact'] == TEST_HASH_FILE


def test_file_scan(mocker, requests_mock):
    mocker.patch.object(demisto, 'params',
                        return_value=MOCK_PARAMS)

    mocker.patch.object(demisto, 'getFilePath',
                        return_value=MOCK_FILE_INFO)

    polyswarm = PolyswarmConnector()

    param = {'entryID': TEST_ENTRY_ID}

    path_detonate_file = '/consumer/{polyswarm_community}'. \
        format(polyswarm_community=demisto.params().get('polyswarm_community'))

    requests_mock.post(MOCK_API_URL + path_detonate_file,
                       json=MOCK_SCAN_JSON_RESPONSE)

    path_url_lookup = '/consumer/{polyswarm_community}/uuid/{uuid}'. \
        format(polyswarm_community=demisto.params().get('polyswarm_community'),
               uuid=TEST_SCAN_UUID)

    requests_mock.get(MOCK_API_URL + path_url_lookup,
                      json=MOCK_LOOKUP_JSON_RESPOSE)

    with patch("__builtin__.open", mock_open(read_data="data")):
        results = polyswarm.detonate_file(param)

    assert results['Contents']['Positives'] == '6'
    assert results['Contents']['Total'] == '17'
    assert results['Contents']['Scan_UUID'] == TEST_SCAN_UUID
    assert results['Contents']['Permalink'] == POLYSWARM_URL_RESULTS + '/' + TEST_SCAN_UUID
    assert results['Contents']['Artifact'] == TEST_ENTRY_ID


def test_get_file(mocker, requests_mock):
    mocker.patch.object(demisto, 'params',
                        return_value=MOCK_PARAMS)

    polyswarm = PolyswarmConnector()

    param = {'hash': TEST_HASH_FILE}

    path_get_file = '/download/{hash_type}/{hash}'. \
        format(hash_type='sha256',
               hash=TEST_HASH_FILE)

    requests_mock.get(MOCK_API_URL + path_get_file,
                      text='bin data response')

    results = polyswarm.get_file(param)

    assert results['File'] == TEST_HASH_FILE


MOCK_PARAMS_TEST_FILE = [
    ({'hash': TEST_HASH_FILE}),
    ({'file': TEST_HASH_FILE}),
]


@pytest.mark.parametrize('param', MOCK_PARAMS_TEST_FILE)
def test_file(mocker, requests_mock, param):
    mocker.patch.object(demisto, 'params',
                        return_value=MOCK_PARAMS)

    polyswarm = PolyswarmConnector()

    path_search_hash = '/search?hash={hash}&type={hash_type}&with_instances=true'. \
        format(hash=TEST_HASH_FILE, hash_type='sha256')

    requests_mock.get(MOCK_API_URL + path_search_hash,
                      json=MOCK_SEARCH_JSON_RESPONSE)

    results = polyswarm.file_reputation(param)

    assert results['Contents']['Positives'] == '7'
    assert results['Contents']['Total'] == '16'
    assert results['Contents']['Scan_UUID'] == TEST_SCAN_UUID
    assert results['Contents']['Permalink'] == POLYSWARM_URL_RESULTS + '/' + TEST_SCAN_UUID
    assert results['Contents']['Artifact'] == TEST_HASH_FILE
