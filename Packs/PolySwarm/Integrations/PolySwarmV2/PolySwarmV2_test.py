import demistomock as demisto

from PolySwarmV2 import PolyswarmConnector

TEST_SCAN_UUID = "95039375646493045"
TEST_SCAN_DOMAIN = ["domain-test.com"]
TEST_SCAN_IP = ["0.0.0.0"]
TEST_SCAN_URL = ["https://url-test.com"]
TEST_HASH_FILE = "939adb211c3bcf76b84b2417e1d39248994e21d48a3d7eddca87bb76d6c31cc3"
TEST_ENTRY_ID = "XXXXX"

MOCK_API_URL = "https://api.polyswarm.network/v2"

POLYSWARM_URL_RESULTS = f"https://polyswarm.network/scan/results/file/{TEST_HASH_FILE}"
POLYSWARM_COMMUNITY = "default"

MOCK_PARAMS = {"api_key": "XXXXXXXXXXXXXXXXXXXXXXXXXX", "base_url": MOCK_API_URL, "polyswarm_community": POLYSWARM_COMMUNITY}

MOCK_FILE_INFO = {"name": "MaliciousFile.exe", "path": "/path/MaliciousFile.exe"}

MOCK_SCAN_JSON_RESPONSE = {"result": TEST_SCAN_UUID}

MOCK_LOOKUP_JSON_ID = {
    "result": {  # noqa
        "artifact_id": "46901361048229692",  # noqa
        "assertions": [],
        "community": "default",
        "country": "ES",
        "created": "2021-04-21T16:33:35.329972",
        "detections": {"benign": 0, "malicious": 0, "total": 0},
        "extended_type": "ASCII text, with no line terminators",
        "failed": False,
        "filename": "939adb211c3bcf76b84b2417e1d39248994e21d48a3d7eddca87bb76d6c31cc3",
        "first_seen": "2021-04-21T16:33:35.329972",
        "id": "95039375646493045",
        "last_scanned": False,
        "last_seen": False,
        "md5": "7d54c8c22816e3faa42182139ca4826d",
        "metadata": [],
        "mimetype": "text/plain",
        "polyscore": False,
        "result": False,
        "sha1": "0853fe86bd78b70d662929c517f0d1724ea17d6e",
        "sha256": "939adb211c3bcf76b84b2417e1d39248994e21d48a3d7eddca87bb76d6c31cc3",
        "size": 64,
        "type": "URL",
        "votes": [],
        "window_closed": True,
    },
    "status": "OK",
}

MOCK_SEARCH_JSON_RESPONSE = {
    "has_more": False,  # noqa
    "limit": 50,
    "offset": "gAAAAABggEYSeVVonqsiq8avwkJ6GOJWjHnbMRnMAFXxz330OazXwec3CDe7vLhluF3pAE7AWKbx2B3LRDJfSvRJoO7SJrwlcA==",
    "result": [
        {  # noqa
            "artifact_id": "21138709956985595",  # noqa
            "assertions": [
                {  # noqa
                    "author": "0xb9b1FA288F7b1867AEF6C044CDE12ab2De252113",  # noqa
                    "author_name": "xxx",
                    "bid": "325000000000000000",
                    "engine": {},
                    "mask": True,  # noqa
                    "metadata": {
                        "malware_family": "",  # noqa
                        "scanner": {
                            "environment": {  # noqa
                                "architecture": "x86_64",  # noqa
                                "operating_system": "Linux",
                            },
                            "version": "0.1.0",
                        },
                    },
                    "verdict": True,
                },
                {
                    "author": "0xA9306463DC64Df02EE4f9eCecc60d947F93Fd9E3",  # noqa
                    "author_name": "0xA9306463DC64Df02EE4f9eCecc60d947F93Fd9E3",
                    "bid": "500000000000000000",
                    "engine": {
                        "description": False,  # noqa
                        "name": "0xA9306463DC64Df02EE4f9eCecc60d947F93Fd9E3",
                    },
                    "mask": True,
                    "metadata": {
                        "malware_family": "",  # noqa
                        "scanner": {
                            "environment": {  # noqa
                                "architecture": "AMD64",  # noqa
                                "operating_system": "Windows",
                            },
                            "signatures_version": "09 September, 2019",
                            "version": "0.1.0",
                        },
                    },
                    "verdict": False,
                },
                {
                    "author": "0xA605715C448f4a2319De2ad01F174cA9c440C4Eb",  # noqa
                    "author_name": "xxx",
                    "bid": "500000000000000000",
                    "engine": {},
                    "mask": True,
                    "metadata": {
                        "malware_family": "",  # noqa
                        "scanner": {
                            "environment": {  # noqa
                                "architecture": "AMD64",  # noqa
                                "operating_system": "Windows",
                            },
                            "vendor_version": "16.0.100 ",
                            "version": "0.2.0",
                        },
                    },
                    "verdict": False,
                },
                {
                    "author": "0xE2911b3c44a0C50b4D0Cfe537a0c1a8b992F6aD0",  # noqa
                    "author_name": "xxx",
                    "bid": "500000000000000000",
                    "engine": {},
                    "mask": True,
                    "metadata": {
                        "malware_family": "Malware.Strealer/Android!8.5B3",  # noqa
                        "scanner": {
                            "environment": {  # noqa
                                "architecture": "x86_64",  # noqa
                                "operating_system": "Linux",
                            }
                        },
                    },
                    "verdict": True,
                },
                {
                    "author": "0x45b94B4AFE4E4B5Bd7f70B84919fba20f1FAfB3f",  # noqa
                    "author_name": "xxx",
                    "bid": "500000000000000000",
                    "engine": {},
                    "mask": True,
                    "metadata": {
                        "malware_family": "",  # noqa
                        "scanner": {
                            "environment": {  # noqa
                                "architecture": "AMD64",  # noqa
                                "operating_system": "Windows",
                            }
                        },
                    },
                    "verdict": False,
                },
                {
                    "author": "0x1EdF29c0977aF06215032383F93deB9899D90118",  # noqa
                    "author_name": "xxx",
                    "bid": "500000000000000000",
                    "engine": {},
                    "mask": True,
                    "metadata": {
                        "malware_family": "",  # noqa
                        "scanner": {
                            "environment": {  # noqa
                                "architecture": "AMD64",  # noqa
                                "operating_system": "Windows",
                            },
                            "vendor_version": "2018.11.28.1",
                            "version": "0.1.0",
                        },
                    },
                    "verdict": False,
                },
                {
                    "author": "0x3750266F07E0590aA16e55c32e08e48878010f8f",  # noqa
                    "author_name": "xxx",
                    "bid": "500000000000000000",
                    "engine": {},
                    "mask": True,
                    "metadata": {
                        "malware_family": "",  # noqa
                        "scanner": {
                            "environment": {  # noqa
                                "architecture": "x86_64",  # noqa
                                "operating_system": "Linux",
                            },
                            "vendor_version": "\n",
                        },
                    },
                    "verdict": False,
                },
                {
                    "author": "0xdCc9064325c1aa24E08182676AD23B3D78b39E05",  # noqa
                    "author_name": "xxx",
                    "bid": "500000000000000000",
                    "engine": {},
                    "mask": True,
                    "metadata": {
                        "malware_family": "",  # noqa
                        "scanner": {
                            "environment": {  # noqa
                                "architecture": "x86_64",  # noqa
                                "operating_system": "Linux",
                            },
                            "vendor_version": "1.1",
                            "version": "0.1.0",
                        },
                    },
                    "verdict": False,
                },
                {
                    "author": "0xbec683492f5D509e119fB1B60543A1Ca595e0Df9",  # noqa
                    "author_name": "xxx",
                    "bid": "500000000000000000",
                    "engine": {},
                    "mask": True,
                    "metadata": {
                        "malware_family": "Trojan.AndroidOS.Basbanke.C!c",  # noqa
                        "scanner": {
                            "environment": {  # noqa
                                "architecture": "AMD64",  # noqa
                                "operating_system": "Windows",
                            }
                        },
                    },
                    "verdict": True,
                },
                {
                    "author": "0x7839aB10854505aBb712F10D1F66d45F359e6c89",  # noqa
                    "author_name": "xxx",
                    "bid": "500000000000000000",
                    "engine": {},
                    "mask": True,
                    "metadata": {
                        "malware_family": "Trojan.AndroidOS.Agent",  # noqa
                        "scanner": {
                            "environment": {  # noqa
                                "architecture": "x86_64",  # noqa
                                "operating_system": "Linux",
                            },
                            "signatures_version": "09.10.2019 12:19:44 (102008)",
                            "vendor_version": "5.2.9.0",
                            "version": "0.2.0",
                        },
                    },
                    "verdict": True,
                },
                {
                    "author": "0xBAFcaF4504FCB3608686b40eB1AEe09Ae1dd2bc3",  # noqa
                    "author_name": "xxx",
                    "bid": "500000000000000000",
                    "engine": {},
                    "mask": True,
                    "metadata": {
                        "malware_family": "Android.Banker.3074",  # noqa
                        "scanner": {
                            "environment": {  # noqa
                                "architecture": "x86_64",  # noqa
                                "operating_system": "Linux",
                            },
                            "signatures_version": "9828B5A94B943A707D4D994C9880A6B0, 2019-Oct-09 11:49:49",
                            "vendor_version": "7.00.41.07240",
                            "version": "0.3.0",
                        },
                    },
                    "verdict": True,
                },
                {
                    "author": "0xbE0B3ec289aaf9206659F8214c49D083Dc1a9E17",  # noqa
                    "author_name": "xxx",
                    "bid": "500000000000000000",
                    "engine": {},
                    "mask": True,
                    "metadata": {
                        "malware_family": "",  # noqa
                        "scanner": {
                            "environment": {  # noqa
                                "architecture": "AMD64",  # noqa
                                "operating_system": "Windows",
                            },
                            "signatures_version": "11.66.31997, 12-Sep-2019",
                            "vendor_version": "15.2.0.42",
                            "version": "0.2.0",
                        },
                    },
                    "verdict": False,
                },
                {
                    "author": "0x59Af39803354Bd08971Ac8e7C6dB7410a25Ab8DA",  # noqa
                    "author_name": "0x59Af39803354Bd08971Ac8e7C6dB7410a25Ab8DA",
                    "bid": "412500000000000000",
                    "engine": {
                        "description": False,  # noqa
                        "name": "0x59Af39803354Bd08971Ac8e7C6dB7410a25Ab8DA",
                    },
                    "mask": True,
                    "metadata": {
                        "malware_family": "",  # noqa
                        "scanner": {
                            "environment": {  # noqa
                                "architecture": "AMD64",  # noqa
                                "operating_system": "Windows",
                            },
                            "vendor_version": "3.0.2.0",
                            "version": "0.2.0",
                        },
                    },
                    "verdict": False,
                },
                {
                    "author": "0x80Ed773972d8BA0A4FacF2401Aca5CEba52F76dc",  # noqa
                    "author_name": "xxx",
                    "bid": "500000000000000000",
                    "engine": {},
                    "mask": True,
                    "metadata": {
                        "malware_family": "",  # noqa
                        "scanner": {
                            "environment": {  # noqa
                                "architecture": "x86_64",  # noqa
                                "operating_system": "Linux",
                            },
                            "vendor_version": "",
                            "version": "0.1.0",
                        },
                    },
                    "verdict": False,
                },
                {
                    "author": "0x10A9eE8552f2c6b2787B240CeBeFc4A4BcB96f27",  # noqa
                    "author_name": "xxx",
                    "bid": "500000000000000000",
                    "engine": {},
                    "mask": True,
                    "metadata": {
                        "malware_family": "TrojanBanker:Android/Basbanke.89a6a78a",  # noqa
                        "scanner": {
                            "environment": {  # noqa
                                "architecture": "AMD64",  # noqa
                                "operating_system": "Windows",
                            }
                        },
                        "type": "zip",
                    },
                    "verdict": True,
                },
                {
                    "author": "0xF598F7dA0D00D9AD21fb00663a7D62a19D43Ea61",  # noqa
                    "author_name": "xxx",
                    "bid": "500000000000000000",
                    "engine": {},
                    "mask": True,
                    "metadata": {
                        "malware_family": "Android.PUA.General",  # noqa
                        "scanner": {
                            "environment": {  # noqa
                                "architecture": "x86_64",  # noqa
                                "operating_system": "Linux",
                            },
                            "vendor_version": "4.1",
                            "version": "0.1.0",
                        },
                    },
                    "verdict": False,
                },
                {
                    "author": "0x2b4C240B376E5406C5e2559C27789d776AE97EFD",  # noqa
                    "author_name": "xxx",
                    "bid": "500000000000000000",
                    "engine": {},
                    "mask": True,
                    "metadata": {
                        "malware_family": "",  # noqa
                        "scanner": {
                            "environment": {  # noqa
                                "architecture": "AMD64",  # noqa
                                "operating_system": "Windows",
                            },
                            "signatures_version": "0.14.32.16015",
                            "vendor_version": "1.0.134.90395",
                            "version": "0.1.0",
                        },
                    },
                    "verdict": False,
                },
            ],
            "community": "lima",  # noqa
            "country": "",
            "created": "2019-10-09T14:15:28.001984",
            "detections": {
                "benign": 11,  # noqa
                "malicious": 6,
                "total": 17,
            },
            "extended_type": "Zip archive data, at least v2.0 to extract",
            "failed": False,
            "filename": "939adb211c3bcf76b84b2417e1d39248994e21d48a3d7eddca87bb76d6c31cc3",
            "first_seen": "2019-10-05T11:17:29.691675",
            "id": "21138709956985595",
            "last_scanned": "2019-10-09T14:15:28.001984",
            "last_seen": "2019-10-09T14:15:28.001984",
            "md5": "d37852c7a538bd645963c25a7f94283e",
            "metadata": [
                {  # noqa
                    "created": "2019-10-05T11:18:20.219300",  # noqa
                    "tool": "hash",
                    "tool_metadata": {
                        "md5": "d37852c7a538bd645963c25a7f94283e",
                        "sha1": "b5ec0329009d22d214ce7b44d2904d92da6030ae",
                        "sha256": "939adb211c3bcf76b84b2417e1d39248994e21d48a3d7eddca87bb76d6c31cc3",
                        "sha3_256": "9911fdc965ee428f463e44b6668961cb935ba20825ece7e07784ae0bf6785f73",
                        "sha3_512": "a68d635db7aafd4af47caf60cef096023872d6e098984e4c24807d2534ce1e0dec5b8c76d913d96e24fccd44f98f649aead27c8d64cf86eab2c17bce7275544e",  # noqa
                        "sha512": "0e4ae37d6104cf8b11e9708e56f811164f12eb4cf8e6260c361a669d897d6753c5e1f019515aa13cc6d4efe5cd2aed915bb6b649fa422391eb0a152fea66c0fc",  # noqa
                        "ssdeep": "49152:H/9Y3F9hNLDXvCGm458G+2ddIrmo67Kkqoyg5Fxs:f9CrXXvjDyqGrmo6Tqo1zxs",
                        "tlsh": "0a952353f6b5e817d932c03220411636a52b6d28db42f64f390977ad28fbdfc8b866d4",
                    },
                },
                {
                    "created": "2019-10-05T11:24:12.432267",  # noqa
                    "tool": "strings",
                    "tool_metadata": {
                        "domains": [  # noqa
                            "",  # noqa
                            "9.sk",
                            "B.lc",
                            "t.kw",
                            "j.gg",
                        ],
                        "ipv4": [],
                        "ipv6": [],
                        "urls": [],
                    },
                },
            ],
            "mimetype": "application/zip",
            "polyscore": 0.9919836349832458,
            "result": False,
            "sha1": "b5ec0329009d22d214ce7b44d2904d92da6030ae",
            "sha256": "939adb211c3bcf76b84b2417e1d39248994e21d48a3d7eddca87bb76d6c31cc3",
            "size": 1974989,
            "type": "FILE",
            "votes": [],
            "window_closed": True,
        }
    ],
    "status": "OK",
}

MOCK_SCAN_JSON_RESPONSE = {
    "result": {  # noqa
        "artifact_id": "91008671523384195",  # noqa
        "assertions": [  # noqa
            {  # noqa
                "author": "0xE0FA6fEfe5F1A4985b42B5Da31231269c360e5E5",  # noqa
                "author_name": "xxx",
                "bid": "1000000000000000000",  # noqa
                "engine": {},
                "mask": True,  # noqa
                "metadata": {
                    "malware_family": "",  # noqa
                    "scanner": {
                        "environment": {  # noqa
                            "architecture": "x86_64",  # noqa
                            "operating_system": "Linux",  # noqa
                        },  # noqa
                        "vendor_version": "",
                        "version": "0.1.1",  # noqa
                    },  # noqa
                },
                "verdict": True,
            },
            {
                "author": "0x51Ea707B45B3AB0EcEAf28b0Ad990FA2014e4E0E",  # noqa
                "author_name": "xxx",
                "bid": "1000000000000000000",
                "engine": {},
                "mask": True,  # noqa
                "metadata": {
                    "malware_family": ""  # noqa
                },
                "verdict": False,
            },
            {
                "author": "0x8434434991A61dAcE1544a7FC1B0F8d83523B778",  # noqa
                "author_name": "xxx",
                "bid": "1000000000000000000",
                "engine": {  # noqa
                },
                "mask": True,  # noqa
                "metadata": {
                    "malware_family": "",  # noqa
                    "scanner": {
                        "environment": {  # noqa
                            "architecture": "x86_64",  # noqa
                            "operating_system": "Linux",
                        },
                        "vendor_version": "",
                        "version": "0.2.0",
                    },  # noqa
                },
                "verdict": False,
            },
        ],
        "community": "default",
        "country": "ES",
        "created": "2021-04-21T17:47:45.031479",
        "detections": {
            "benign": 3,  # noqa
            "malicious": 0,
            "total": 3,  # noqa
        },
        "extended_type": "ASCII text, with no line terminators",
        "failed": False,
        "filename": "",
        "first_seen": "2021-04-21T17:47:45.031479",
        "id": "91008671523384195",
        "last_scanned": "2021-04-21T17:47:45.031479",
        "last_seen": "2021-04-21T17:47:45.031479",
        "md5": "99999ebcfdb78df077ad2727fd00969f",
        "metadata": [
            {  # noqa
                "created": "2019-08-02T03:18:57.278529",  # noqa
                "tool": "hash",
                "tool_metadata": {
                    "md5": "99999ebcfdb78df077ad2727fd00969f",  # noqa
                    "sha1": "72fe95c5576ec634e214814a32ab785568eda76a",
                    "sha256": "939adb211c3bcf76b84b2417e1d39248994e21d48a3d7eddca87bb76d6c31cc3",
                    "sha3_256": "1d04c6a0de45640841f5ad06644830e9535e4221315abdae55c898e340c0bd85",
                    "sha3_512": "b3d73fde21923feef7be13e0793059c8c5eecea46794ae452e3d57d058ea02322b1aa573b420fb0ca4ecda6c6d7b0f3618b12ecc43250b3e79d9e74958c7fccc",  # noqa
                    "sha512": "f50de615027afe3f1e9a3c9bc71c085d5c71a55413a70cd134328b51fd14188832848673726981a686fd6f2de3b9c24ee90e466b7589800f83d19520cd23d13d",  # noqa
                    "ssdeep": "3:N8r3uK:2LuK",
                    "tlsh": "",
                },
            },
            {
                "created": "2019-06-25T11:03:29.989789",  # noqa
                "tool": "strings",
                "tool_metadata": {  # noqa
                    "domains": [  # noqa
                    ],
                    "ipv4": [],
                    "ipv6": [],
                    "urls": [],
                },
            },
            {
                "created": "2019-11-13T00:10:36.646018",  # noqa
                "tool": "scan",
                "tool_metadata": {
                    "countries": [  # noqa
                        "CN",  # noqa
                        "ES",  # noqa
                        "JP",
                        "PR",
                        "US",  # noqa
                    ],
                    "detections": {
                        "benign": 1206,  # noqa
                        "total": 1263,
                        "unknown": 1,
                    },
                    "first_scan": {
                        "0x0457C40dBA29166c1D2485F93946688C1FC6Cc58": {  # noqa
                            "assertion": "benign",  # noqa
                            "metadata": {
                                "malware_family": "",  # noqa
                                "scanner": {
                                    "environment": {  # noqa
                                        "architecture": "AMD64",  # noqa
                                        "operating_system": "Windows",
                                    }
                                },
                            },
                        },
                        "0x59Af39803354Bd08971Ac8e7C6dB7410a25Ab8DA": {
                            "assertion": "benign",  # noqa
                            "metadata": {
                                "malware_family": "",  # noqa
                                "scanner": {
                                    "environment": {  # noqa
                                        "architecture": "AMD64",  # noqa
                                        "operating_system": "Windows",
                                    },
                                    "vendor_version": "3.0.2.0",
                                    "version": "0.2.0",
                                },
                            },
                        },
                        "0x7c6A9f9f9f1a67774999FF0e26ffdBa2c9347eeB": {
                            "assertion": "benign",  # noqa
                            "metadata": {
                                "malware_family": "",  # noqa
                                "scanner": {
                                    "environment": {  # noqa
                                        "architecture": "x86_64",  # noqa
                                        "operating_system": "Linux",
                                    }
                                },
                            },
                        },
                        "0xA4815D9b8f710e610E8957F4aD13F725a4331cbB": {
                            "assertion": "benign",  # noqa
                            "metadata": {
                                "malware_family": "",  # noqa
                                "scanner": {
                                    "environment": {  # noqa
                                        "architecture": "x86_64",  # noqa
                                        "operating_system": "Linux",
                                    }
                                },
                            },
                        },
                        "xxx1": {
                            "assertion": "benign",  # noqa
                            "metadata": {
                                "malware_family": "",  # noqa
                                "scanner": {
                                    "environment": {  # noqa
                                        "architecture": "AMD64",  # noqa
                                        "operating_system": "Windows",
                                    }
                                },
                                "type": "ignore",
                            },
                        },
                        "xxx2": {
                            "assertion": "benign",  # noqa
                            "metadata": {
                                "malware_family": "",  # noqa
                                "scanner": {
                                    "environment": {  # noqa
                                        "architecture": "x86_64",  # noqa
                                        "operating_system": "Linux",
                                    },
                                    "vendor_version": "\n",
                                },
                            },
                        },
                        "xxx3": {
                            "assertion": "benign",  # noqa
                            "metadata": {
                                "malware_family": "",  # noqa
                                "scanner": {
                                    "environment": {  # noqa
                                        "architecture": "AMD64",  # noqa
                                        "operating_system": "Windows",
                                    },
                                    "vendor_version": "16.0.100 ",
                                    "version": "0.2.0",
                                },
                            },
                        },
                        "xxx4": {
                            "assertion": "benign",  # noqa
                            "metadata": {
                                "malware_family": "",  # noqa
                                "scanner": {
                                    "environment": {  # noqa
                                        "architecture": "AMD64",  # noqa
                                        "operating_system": "Windows",
                                    },
                                    "signatures_version": "11.51.31290, 20-Jun-2019",
                                    "vendor_version": "15.2.0.41",
                                    "version": "0.2.0",
                                },
                            },
                        },
                        "xxx5": {
                            "assertion": "benign",  # noqa
                            "metadata": {
                                "malware_family": "",  # noqa
                                "scanner": {
                                    "environment": {  # noqa
                                        "architecture": "AMD64",  # noqa
                                        "operating_system": "Windows",
                                    },
                                    "signatures_version": "0.14.30.15269",
                                    "vendor_version": "1.0.134.90385",
                                    "version": "0.1.0",
                                },
                            },
                        },
                        "xxx6": {
                            "assertion": "benign",  # noqa
                            "metadata": {
                                "malware_family": "",  # noqa
                                "scanner": {
                                    "environment": {  # noqa
                                        "architecture": "x86_64",  # noqa
                                        "operating_system": "Linux",
                                    }
                                },
                            },
                        },
                        "artifact_instance_id": 75886037698659906,
                    },
                    "first_seen": "2019-06-25T01:53:43.954091+00:00",
                    "last_seen": "2020-01-17T23:35:52.662846+00:00",
                    "latest_scan": {
                        "xxx": {  # noqa
                            "assertion": "benign",  # noqa
                            "metadata": {
                                "malware_family": "",  # noqa
                                "scanner": {
                                    "environment": {  # noqa
                                        "architecture": "x86_64",  # noqa
                                        "operating_system": "Linux",
                                    }
                                },
                            },
                        },
                        "xxx1": {
                            "assertion": "benign",  # noqa
                            "metadata": {
                                "malware_family": "",  # noqa
                                "scanner": {
                                    "environment": {  # noqa
                                        "architecture": "x86_64",  # noqa
                                        "operating_system": "Linux",
                                    },
                                    "vendor_version": "",
                                    "version": "0.1.0",
                                },
                            },
                        },
                        "xxx2": {
                            "assertion": "benign",  # noqa
                            "metadata": {
                                "malware_family": "",  # noqa
                                "scanner": {
                                    "environment": {  # noqa
                                        "architecture": "x86_64",  # noqa
                                        "operating_system": "Linux",
                                    },
                                    "vendor_version": "",
                                    "version": "0.1.0",
                                },
                            },
                        },
                        "xxx3": {
                            "assertion": "benign",  # noqa
                            "metadata": {
                                "malware_family": "",  # noqa
                                "scanner": {
                                    "environment": {  # noqa
                                        "architecture": "x86_64",  # noqa
                                        "operating_system": "Linux",
                                    },
                                    "vendor_version": "",
                                    "version": "0.1.0",
                                },
                            },
                        },
                        "xxx4": {
                            "assertion": "benign",  # noqa
                            "metadata": {
                                "malware_family": "",  # noqa
                                "scanner": {
                                    "environment": {  # noqa
                                        "architecture": "x86_64",  # noqa
                                        "operating_system": "Linux",
                                    },
                                    "version": "0.3.0",
                                },
                            },
                        },
                        "xxx5": {
                            "assertion": "benign",  # noqa
                            "metadata": {
                                "malware_family": "",  # noqa
                                "scanner": {
                                    "environment": {  # noqa
                                        "architecture": "x86_64",  # noqa
                                        "operating_system": "Linux",
                                    },
                                    "vendor_version": "1.1",
                                    "version": "0.1.0",
                                },
                            },
                        },
                        "artifact_instance_id": 49856473932287041,
                    },
                    "mimetype": {
                        "extended": "ASCII text, with no line terminators",  # noqa
                        "mime": "text/plain",
                    },
                    "url": [],
                },
            },
        ],
        "mimetype": "text/plain",
        "polyscore": 0.12,
        "result": False,
        "sha1": "72fe95c5576ec634e214814a32ab785568eda76a",
        "sha256": "939adb211c3bcf76b84b2417e1d39248994e21d48a3d7eddca87bb76d6c31cc3",
        "size": 18,
        "type": "URL",
        "votes": [],
        "window_closed": True,
    },
    "status": "OK",
}


def test_reputation(mocker, requests_mock):
    mocker.patch.object(demisto, "debug", return_value=None)

    def run_test(param, scan_uuid):
        mocker.patch.object(demisto, "params", return_value=MOCK_PARAMS)

        polyswarm = PolyswarmConnector()

        path_url_scan = "/consumer/submission/{polyswarm_community}".format(
            polyswarm_community=demisto.params().get("polyswarm_community")
        )

        requests_mock.post(MOCK_API_URL + path_url_scan, json=MOCK_LOOKUP_JSON_ID)

        path_url_lookup = "/consumer/submission/{polyswarm_community}/{uuid}".format(
            polyswarm_community=demisto.params().get("polyswarm_community"), uuid=TEST_SCAN_UUID
        )

        requests_mock.get(MOCK_API_URL + path_url_lookup, json=MOCK_SCAN_JSON_RESPONSE)

        results = polyswarm.url_reputation(param, list(param.keys())[0])
        results = results[0].to_context()
        assert results["Contents"]["Positives"] == "1"
        assert results["Contents"]["Total"] == "3"
        assert results["Contents"]["Scan_UUID"] == scan_uuid[0]
        assert results["Contents"]["Permalink"] == POLYSWARM_URL_RESULTS
        assert results["Contents"]["Artifact"] == scan_uuid[0]

    # test Domain scan reputation
    param = {"domain": TEST_SCAN_DOMAIN}
    run_test(param, TEST_SCAN_DOMAIN)

    # test IP scan reputation
    param = {"ip": TEST_SCAN_IP}
    run_test(param, TEST_SCAN_IP)

    # test URL scan reputation
    param = {"url": TEST_SCAN_URL}
    run_test(param, TEST_SCAN_URL)


def test_polyswarm_get_report(mocker, requests_mock):
    mocker.patch.object(demisto, "debug", return_value=None)

    mocker.patch.object(demisto, "params", return_value=MOCK_PARAMS)

    polyswarm = PolyswarmConnector()

    param = {"scan_uuid": TEST_HASH_FILE}

    path_url_lookup = f"/search/hash/sha256?hash={TEST_HASH_FILE}"
    requests_mock.get(MOCK_API_URL + path_url_lookup, json=MOCK_SEARCH_JSON_RESPONSE)

    results = polyswarm.get_report(param["scan_uuid"])
    results = results[0].to_context()

    assert results["Contents"]["Positives"] == "6"
    assert results["Contents"]["Total"] == "17"
    assert results["Contents"]["Scan_UUID"] == TEST_HASH_FILE
    assert results["Contents"]["Permalink"] == POLYSWARM_URL_RESULTS
    assert results["Contents"]["Artifact"] == TEST_HASH_FILE


def test_file_rescan(mocker, requests_mock):
    mocker.patch.object(demisto, "debug", return_value=None)

    mocker.patch.object(demisto, "params", return_value=MOCK_PARAMS)

    polyswarm = PolyswarmConnector()

    param = {"hash": TEST_HASH_FILE}

    path_rescan = "/consumer/submission/{polyswarm_community}/rescan/{hash_type}/{hash}".format(
        polyswarm_community=demisto.params().get("polyswarm_community"), hash_type="sha256", hash=TEST_HASH_FILE
    )

    requests_mock.post(MOCK_API_URL + path_rescan, json=MOCK_LOOKUP_JSON_ID)

    path_url_lookup = "/consumer/submission/{polyswarm_community}/{uuid}".format(
        polyswarm_community=demisto.params().get("polyswarm_community"), uuid=TEST_SCAN_UUID
    )

    requests_mock.get(MOCK_API_URL + path_url_lookup, json=MOCK_SCAN_JSON_RESPONSE)

    results = polyswarm.rescan_file(param["hash"])
    results = results[0].to_context()

    assert results["Contents"]["Positives"] == "1"
    assert results["Contents"]["Total"] == "3"
    assert results["Contents"]["Scan_UUID"] == TEST_HASH_FILE
    assert results["Contents"]["Permalink"] == POLYSWARM_URL_RESULTS
    assert results["Contents"]["Artifact"] == TEST_HASH_FILE


def test_file_scan(mocker, requests_mock):
    mocker.patch.object(demisto, "debug", return_value=None)

    mocker.patch.object(demisto, "params", return_value=MOCK_PARAMS)

    mocker.patch.object(demisto, "getFilePath", return_value=MOCK_FILE_INFO)

    polyswarm = PolyswarmConnector()

    param = {"entryID": TEST_ENTRY_ID}

    path_detonate_file = "/consumer/submission/{polyswarm_community}".format(
        polyswarm_community=demisto.params().get("polyswarm_community")
    )

    requests_mock.post(MOCK_API_URL + path_detonate_file, json=MOCK_LOOKUP_JSON_ID)

    path_url_lookup = "/consumer/submission/{polyswarm_community}/{uuid}".format(
        polyswarm_community=demisto.params().get("polyswarm_community"), uuid=TEST_SCAN_UUID
    )

    requests_mock.get(MOCK_API_URL + path_url_lookup, json=MOCK_SCAN_JSON_RESPONSE)

    open_mock = mocker.mock_open(read_data="data")
    mocker.patch("builtins.open", open_mock)

    results = polyswarm.detonate_file(param["entryID"])
    results = results.to_context()

    assert results["Contents"]["Positives"] == "1"
    assert results["Contents"]["Total"] == "3"
    assert results["Contents"]["Scan_UUID"] == TEST_HASH_FILE
    assert results["Contents"]["Permalink"] == POLYSWARM_URL_RESULTS
    assert results["Contents"]["Artifact"] == TEST_HASH_FILE


def test_get_file(mocker, requests_mock):
    mocker.patch.object(demisto, "debug", return_value=None)

    mocker.patch.object(demisto, "params", return_value=MOCK_PARAMS)

    polyswarm = PolyswarmConnector()

    param = {"hash": TEST_HASH_FILE}

    path_get_file = "/download/{hash_type}/{hash}".format(hash_type="sha256", hash=TEST_HASH_FILE)

    requests_mock.get(MOCK_API_URL + path_get_file, text="bin data response")

    results = polyswarm.get_file(param["hash"])

    assert results["File"] == TEST_HASH_FILE


def test_file(mocker, requests_mock):
    mocker.patch.object(demisto, "debug", return_value=None)

    mocker.patch.object(demisto, "params", return_value=MOCK_PARAMS)

    polyswarm = PolyswarmConnector()

    param = {"hash": TEST_HASH_FILE}

    path_search_hash = "/search/hash/sha256?hash={hash}".format(hash=TEST_HASH_FILE)

    requests_mock.get(MOCK_API_URL + path_search_hash, json=MOCK_SEARCH_JSON_RESPONSE)

    results = polyswarm.file_reputation(param["hash"])
    results = results[0].to_context()

    assert results["Contents"]["Positives"] == "6"
    assert results["Contents"]["Total"] == "17"
    assert results["Contents"]["Scan_UUID"] == TEST_HASH_FILE
    assert results["Contents"]["Permalink"] == POLYSWARM_URL_RESULTS
    assert results["Contents"]["Artifact"] == TEST_HASH_FILE
