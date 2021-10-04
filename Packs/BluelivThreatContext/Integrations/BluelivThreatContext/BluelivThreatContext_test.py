import demistomock as demisto
from BluelivThreatContext import Client, blueliv_threatActor, blueliv_campaign, blueliv_malware, blueliv_indicatorIp, \
    blueliv_indicatorFqdn, blueliv_indicatorCs, blueliv_attackPattern, blueliv_tool, \
    blueliv_signature, blueliv_cve


def test_blueliv_threatActor(mocker, requests_mock):
    blueliv_response = {
        "data": {
            "attributes": {
                "active": True,
                "aliases": [
                    "Vendetta"
                ],
                "country_name": "Italy",
                "created_at": "2020-06-10T11:23:22.584500Z",
                "description": "Vendetta is a threat actor based on Italy or Turkey discovered in April 2020",
                "first_seen": "2020-04-01T00:00:00Z",
                "ioc_link": "https://tctrustoylo.blueliv.com/api/v1/threat-actor/232/ioc/",
                "last_seen": "2020-06-15T00:00:00Z",
                "modus_operandi": "Vendetta uses well designed phishing campaigns to target businessuals. ",
                "name": "Vendetta",
                "objective": "This threat actor appears to be focused on stealing informatio using.",
                "references": [
                    {
                        "link": "https://blog.360totalsecurity.com/en/vendetta-new-threat-actor-from-europe/",
                        "title": "Vendetta-new threat actor from Europe"
                    },
                    {
                        "link": "https://business.blogthinkbig.com/vendetta-group-covid-19-phishing-emails/",
                        "title": "Vendetta Group and the COVID-19 Phishing Emails"
                    }
                ],
                "sophistication": "intermediate",
                "tlp": "white",
                "types": [
                    "hacker"
                ],
                "updated_at": "2020-06-16T08:57:08.536868Z",
                "uuid": None
            },
            "id": "232",
            "links": {
                "self": "https://tctrustoylo.blueliv.com/api/v1/threat-actor/232/"
            },
            "relationships": {
                "attack_patterns": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/threat-actor/232/attack-pattern/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/threat-actor/232/relationships/attack-pattern/"
                    },
                    "meta": {"count": 0}
                },
                "campaigns": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/threat-actor/232/campaign/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/threat-actor/232/relationships/campaign/"
                    },
                    "meta": {"count": 0}
                },
                "country": {
                    "data": {
                        "id": "108",
                        "type": "Country"
                    },
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/country/108/"
                    }
                },
                "cves": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/threat-actor/232/cve/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/threat-actor/232/relationships/cve/"
                    },
                    "meta": {"count": 0}
                },
                "fqdns": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/threat-actor/232/fqdn/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/threat-actor/232/relationships/fqdn/"
                    },
                    "meta": {"count": 0}
                },
                "ips": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/threat-actor/232/ip/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/threat-actor/232/relationships/ip/"
                    },
                    "meta": {"count": 0}
                },
                "malware": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/threat-actor/232/malware/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/threat-actor/232/relationships/malware/"
                    },
                    "meta": {"count": 0}
                },
                "milestones": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/threat-actor/232/milestone/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/threat-actor/232/relationships/milestone/"
                    },
                    "meta": {"count": 0}
                },
                "online_services": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/threat-actor/232/online-service/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/threat-actor/232/relationships/online-service/"
                    },
                    "meta": {"count": 0}
                },
                "signatures": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/threat-actor/232/signature/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/threat-actor/232/relationships/signature/"
                    },
                    "meta": {"count": 0}
                },
                "targets": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/threat-actor/232/target/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/threat-actor/232/relationships/target/"
                    },
                    "meta": {"count": 0}
                },
                "threat_types": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/threat-actor/232/threat-type/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/threat-actor/232/relationships/threat-type/"
                    },
                    "meta": {"count": 0}
                },
                "tools": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/threat-actor/232/tool/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/threat-actor/232/relationships/tool/"
                    },
                    "meta": {"count": 0}
                }
            },
            "type": "ThreatActor"
        }
    }
    mocker.patch.object(demisto, 'results')
    requests_mock.register_uri('POST', 'https://tctrustoylo.blueliv.com/api/v2/gateway', json=blueliv_response)

    client = Client(base_url='https://tctrustoylo.blueliv.com/api/v2', verify=False)
    args = {"threatActor_id": 232}
    blueliv_threatActor(client, args)

    results = demisto.results.call_args[0][0]

    entry_context = results.get('EntryContext', {})
    ind = entry_context.get('BluelivThreatContext.threatActor(val.name && val.id == obj.id)', {})
    assert demisto.get(ind, "sophistication") == "intermediate"
    assert str(demisto.get(ind, "lastSeen")) == "2020-06-15T00:00:00Z"


def test_blueliv_campaign(mocker, requests_mock):
    blueliv_response = {
        "data": {
            "attributes": {
                "created_at": "2020-05-28T21:24:11.307288Z",
                "description": "\u003cp\u003eA distribution campaign for the GRANDOREIRO banking Trojan.",
                "first_seen": "2020-04-16T00:00:00Z",
                "ioc_link": "https://tctrustoylo.blueliv.com/api/v1/campaign/152/ioc/",
                "last_seen": "2020-05-28T00:00:00Z",
                "name": "2020 Grandoreiro campaign against banks in LATAM, Portugal and Spain",
                "tlp": "white",
                "updated_at": "2020-05-28T23:58:36.883515Z",
                "uuid": None
            },
            "id": "152",
            "links": {
                "self": "https://tctrustoylo.blueliv.com/api/v1/campaign/152/"
            },
            "relationships": {
                "attack_patterns": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/campaign/152/attack-pattern/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/campaign/152/relationships/attack-pattern/"
                    },
                    "meta": {"count": 0}
                },
                "botnets": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/campaign/152/botnet/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/campaign/152/relationships/botnet/"
                    },
                    "meta": {"count": 0}
                },
                "cves": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/campaign/152/cve/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/campaign/152/relationships/cve/"
                    },
                    "meta": {"count": 0}
                },
                "fqdns": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/campaign/152/fqdn/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/campaign/152/relationships/fqdn/"
                    },
                    "meta": {"count": 0}
                },
                "ips": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/campaign/152/ip/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/campaign/152/relationships/ip/"
                    },
                    "meta": {"count": 0}
                },
                "malware": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/campaign/152/malware/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/campaign/152/relationships/malware/"
                    },
                    "meta": {"count": 0}
                },
                "signatures": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/campaign/152/signature/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/campaign/152/relationships/signature/"
                    },
                    "meta": {"count": 0}
                },
                "threat_actor": {
                    "data": {
                        "id": "226",
                        "type": "ThreatActor"
                    },
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/threat-actor/226/"
                    }
                },
                "tools": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/campaign/152/tool/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/campaign/152/relationships/tool/"
                    },
                    "meta": {"count": 0}
                }
            },
            "type": "Campaign"
        }
    }

    mocker.patch.object(demisto, 'results')
    requests_mock.register_uri('POST', 'https://tctrustoylo.blueliv.com/api/v2/gateway', json=blueliv_response)

    client = Client(base_url='https://tctrustoylo.blueliv.com/api/v2', verify=False)
    args = {"campaign_id": 152}
    blueliv_campaign(client, args)

    results = demisto.results.call_args[0][0]

    entry_context = results.get('EntryContext', {})
    ind = entry_context.get('BluelivThreatContext.campaign(val.id && val.id == obj.id)', {})
    assert demisto.get(ind, "name") == "2020 Grandoreiro campaign against banks in LATAM, Portugal and Spain"
    assert demisto.get(ind, "threatActorId") == "226"


def test_blueliv_malware(mocker, requests_mock):
    blueliv_response = {
        "data": {
            "attributes": {
                "analysis_date": "2020-06-15T16:30:22.770000Z",
                "analysis_delivered_date": "2020-06-15T16:22:00.220000Z",
                "analysis_signatures": [
                    "Signature severity - Informative",
                    "Signature severity - Malicious"
                ],
                "analysis_status": "FINISHED_SUCCESSFULLY",
                "at_afapi": True,
                "behaviors": [],
                "buffers": False,
                "cerberus": 0.9645,
                "created_at": "2020-06-15T16:27:20.074884Z",
                "created_at_afapi": "2020-06-15T16:21:38.209000Z",
                "dropped": False,
                "file_type": "PE",
                "first_seen": "2020-06-15T16:21:38.209000Z",
                "has_c_and_c": False,
                "has_network": True,
                "has_other_urls": False,
                "hash": "ad53660b6d7e8d2ed14bd59b39e1f265148e3c6818a494cce906e749976bade1",
                "ioa": {
                    "attack_patterns": [
                        {
                            "id": "T1022",
                            "name": "Data Encrypted"
                        },
                       {
                            "id": "T1093",
                            "name": "Process Hollowing"
                        }
                    ],
                    "certificates": [],
                    "connections": {
                        "tcp": [],
                        "tcp_dead": [
                            "25.20.116.113:957",
                            "103.143.173.25:80"
                        ],
                        "udp": []
                    },
                    "domain": [],
                    "email": [],
                    "host": [
                        "25.20.116.113",
                        "103.143.173.25"
                    ],
                    "ip": [
                        "25.20.116.113",
                        "103.143.173.25",
                        "192.168.56.102"
                    ],
                    "metadata": {
                        "crc32": {
                            "original": "B7CACEE9",
                            "unpacked": {}
                        },
                        "file_type": {
                            "original": "PE32 executable (GUI) Intel 80386, for MS Windows",
                            "unpacked": {}
                        },
                        "names": {
                            "author": [],
                            "common_name": [],
                            "company_name": None,
                            "country": [],
                            "creator": [],
                            "internal_name": None,
                            "legal_copyright": None,
                            "legal_trademarks": None,
                            "locality": [],
                            "organization": [],
                            "organizational_unit": [],
                            "original_filename": None,
                            "private_build": None,
                            "producer": [],
                            "product_name": None,
                            "special_build": None,
                            "subject": [],
                            "title": []
                        },
                        "pe_imphash": "e5b4359a3773764a372173074ae9b6bd",
                        "pe_timestamp": "2012-06-07 17:59:53",
                        "peid_signatures": [],
                        "postal_code": None,
                        "signing_date": "",
                        "ssdeep": {
                            "original": "12288:f9HFJ9rJxRX1uVVjoaWSoynxdO1FxuVVjfFoynPaVBUR8f+kN10EBO",
                            "unpacked": {}
                        }
                    },
                    "mutex": [
                        "DCPERSFWBP",
                        "DC_MUTEX-K5CAEA3",
                        "Local\\MSCTF.Asm.MutexDefault1"
                    ],
                    "path": {
                        "filepaths": {
                            "directory_created": [
                                "C:\\Users\\Administrator\\AppData\\Local\\Microsoft\\Windows\\Caches"
                            ],
                            "directory_enumerated": [],
                            "directory_queried": [
                                "C:\\Users\\Administrator",
                                "C:\\Users"
                            ],
                            "directory_removed": [],
                            "dll_loaded": [
                                "kernel32",
                                "OLEACC.dll"
                            ],
                            "file_copied": [
                                "C:\\Users\\Administrator\\Documents\\MSDCSC\\msdcsc.exe"
                            ],
                            "file_created": [
                                "C:\\Windows\\System32\\oleaccrc.dll",
                                "C:\\Users\\Administrator\\AppData\\Local\\Microsoft\\Windows\\Caches\\cversions.1.db"
                            ],
                            "file_deleted": [],
                            "file_exists": [
                                "C:\\Windows\\System32\\oleaccrc.dll",
                                "C:\\Users\\Administrator\\Documents\\MSDCSC"
                            ],
                            "file_moved": [],
                            "file_opened": [
                                "C:\\Windows\\System32\\oleaccrc.dll",
                                "C:\\Users\\Administrator\\AppData\\Local\\Microsoft\\Windows\\Caches\\cversions.1.db"
                            ],
                            "file_read": [
                                "C:\\Users\\desktop.ini",
                                "C:\\Users\\Administrator\\Documents\\desktop.ini"
                            ],
                            "file_written": []
                        },
                        "pdb_path": []
                    },
                    "ports": {
                        "tcp": [],
                        "tcp_dead": [
                            80,
                            957
                        ],
                        "udp": []
                    },
                    "process_name": [
                        "msdcsc.exe",
                        "sXPFvH.exe",
                        "notepad.exe"
                    ],
                    "registry": [],
                    "regkeys": {
                        "regkey_created": [
                            "HKEY_CURRENT_USER\\Software"
                        ],
                        "regkey_deleted": [],
                        "regkey_enumerated": [
                            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\CTF\\TIP"
                        ],
                        "regkey_opened": [
                            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\CTF\\",
                            "HKEY_CURRENT_USER\\Software\\DC2_USERS"
                        ],
                        "regkey_read": [
                            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\SQMClient\\Windows\\DisabledProcesses\\21082CA9",
                            "HKEY_CURRENT_USER\\Keyboard Layout\\Toggle\\Language Hotkey"
                        ],
                        "regkey_written": [
                            "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\MicroUpdate",
                            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\UserInit"
                        ]
                    },
                    "url": [
                        "http://uk.ask.com/favicon.ico",
                        "http://www.priceminister.com/"
                    ],
                    "yara": {
                        "generic": [],
                        "memory": [
                            "darkcomet_memory_1",
                            "darkcomet_memory_3"
                        ],
                        "misc": {
                            "crypto": [
                                "RIPEMD160_Constants",
                                "SHA1_Constants"
                            ],
                            "misc": [
                                "dbgdetect_funcs_ig"
                            ],
                            "packer": [
                                "MinGW_1",
                                "borland_delphi"
                            ]
                        },
                        "pre_analysis": [],
                        "url": []
                    }
                },
                "ioc_link": "https://tctrustoylo.blueliv.com/api/v1/malware/ioc/",
                "last_risk_scoring": "2020-06-15T16:48:42.527191Z",
                "last_seen": "2020-06-23T23:52:30.123694Z",
                "malfind": False,
                "malicious_category": 2,
                "md5": "36a40cc55e2ffe7d44d007c6e37afd7f",
                "memory": False,
                "metadata": {},
                "number_properties": 0,
                "pcap": "https://tctrustoylo.blueliv.com/api/v1/malware//pcap/",
                "priority_at_afapi": 3,
                "proc_memory": False,
                "properties": [],
                "report": "https://tctrustoylo.blueliv.com/api/v1/malware/report/",
                "risk": 7,
                "sample": "https://tctrustoylo.blueliv.com/api/v1/malware/sample/",
                "scans_link": "https://tctrustoylo.blueliv.com/api/v1/malware/ad536nrichment/scans/",
                "seen_at_analyzer": False,
                "sha1": "5c0be68316ce77584a7b966ff40e7d61a8a98055",
                "sha256": "ad53660b6d7e8d2ed14bd59b39e1f265148e3c6818a494cce906e749976bade1",
                "sha512": "e7ebf12d5dc0900faafa73d090b62c1ce583858606217d935981bf3d51dbd6e63eefd67b10391b7a3073cc6",
                "slugs_tags": [],
                "sources_representation": [
                    "virustotalAPI"
                ],
                "subtype": "DARKCOMET",
                "target": False,
                "tlp": "white",
                "types_names": [
                    "DARKCOMET"
                ],
                "updated_at": "2020-06-23T23:52:30.137745Z",
                "updated_at_afapi": "2020-06-15T16:30:33.293000Z",
                "uuid": None,
                "version": "none",
                "vt_matches": [
                    "darkkomet",
                    "fynloski",
                    "genmalicious"
                ]
            },
            "id": "59770710",
            "links": {
                "self": "https://tctrustoylo.blueliv.com/api/v1/malware/6e749976bade1/"
            },
            "relationships": {
                "campaigns": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/malware/a49976bade1/campaign/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/malware/ad51/relationships/campaign/"
                    },
                    "meta": {"count": 0}
                },
                "crime_servers": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/malware/ad53660-server/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/malware/ad53660b6d7e8dhips/crime-server/"
                    },
                    "meta": {"count": 0}
                },
                "fqdns": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/malware/ad53660b6d7eqdn/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/malware/ad53660b6d7e8d2ed14bd59b39e1n/"
                    },
                    "meta": {"count": 0}
                },
                "ips": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/malware/ad53660b6d7e8d2ed14bd59/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/malware/ad53660b6d7e8d2ed14bd59b39e/"
                    },
                    "meta": {"count": 0}
                },
                "signatures": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/malware/ad53660b6d7e8d2ed1re/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/malware/ad53660b6d7e8d2ed14bonships/signature/"
                    },
                    "meta": {"count": 0}
                },
                "solr_type": {
                    "data": {
                        "id": "62",
                        "type": "ThreatType"
                    },
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/threat-type/DARKCOMET/"
                    }
                },
                "sources": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/malware/ad53660b6d7e8d2rce/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/malware/ad53660b6d7e8d2ed14bd59b39e1f2ce/"
                    },
                    "meta": {"count": 0}
                },
                "sparks": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/malware/ad53660b6d7e8d2ed14bd51/spark/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/malware/ad53614bde1/relationships/spark/"
                    },
                    "meta": {"count": 0}
                },
                "tags": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/malware/ad5376bade1/tag/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/malware/ad53660b6976bade1/relationships/tag/"
                    },
                    "meta": {"count": 0}
                },
                "threat_actors": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/malware/ad53660bade1/threat-actor/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/malware/ad53660b6eat-actor/"
                    },
                    "meta": {"count": 0}
                },
                "types": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/malware/ad53660b6976bade1/type/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/malware/ad53660b6d7e8d2edtionships/threat-type/"
                    },
                    "meta": {"count": 0}
                }
            },
            "type": "Malware"
        }
    }

    mocker.patch.object(demisto, 'results')
    requests_mock.register_uri('POST', 'https://tctrustoylo.blueliv.com/api/v2/gateway', json=blueliv_response)

    client = Client(base_url='https://tctrustoylo.blueliv.com/api/v2', verify=False)
    args = {"hash_id": 59770710}
    blueliv_malware(client, args)

    results = demisto.results.call_args[0][0]

    entry_context = results.get('EntryContext', {})
    ind = entry_context.get('BluelivThreatContext.malware(val.id && val.id == obj.id)', {})
    assert ind.get("hash.sha1") == "5c0be68316ce77584a7b966ff40e7d61a8a98055"
    assert demisto.get(ind, "fileType") == "PE"


def test_blueliv_indicatorIp(mocker, requests_mock):
    blueliv_response = {
        "data": {
            "attributes": {
                "address": "103.76.228.28",
                "asn_number": "394695",
                "asn_owner": "PDR",
                "at_afapi": False,
                "created_at": "2019-05-03T09:57:46.834135Z",
                "created_at_afapi": None,
                "first_seen": "2019-04-11T04:12:09.830000Z",
                "history_link": "https://tctrustoylo.blueliv.com/api/v1/ip/103.76.228.28/history/",
                "ioc_link": "https://tctrustoylo.blueliv.com/api/v1/ip/103.76.228.28/ioc/",
                "last_risk_scoring": "2020-06-15T15:17:47.624936Z",
                "last_seen": "2020-06-18T23:36:37Z",
                "latitude": 20,
                "longitude": 77,
                "passive_dns_link": "https://tctrustoylo.blueliv.com/api/v1/ip/103.76.228.28/enrichment/passive-dns/",
                "risk": 4,
                "slugs_tags": [],
                "tlp": "amber",
                "updated_at": "2020-06-18T21:47:29.968912Z",
                "updated_at_afapi": None,
                "virus_total_link": "https://tctrustoylo.blueliv.com/api/v1/ip/103.76.228.28/enrichment/virus-total/",
                "whois_link": "https://tctrustoylo.blueliv.com/api/v1/ip/103.76.228.28/enrichment/whois/"
            },
            "id": "70236228",
            "links": {"self": "https://tctrustoylo.blueliv.com/api/v1/ip/103.76.228.28/"},
            "relationships": {
                "bots": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/ip/103.76.228.28/bot/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/ip/103.76.228.28/relationships/bot/"
                    },
                    "meta": {"count": 0}
                },
                "campaigns": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/ip/103.76.228.28/campaign/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/ip/103.76.228.28/relationships/campaign/"
                    },
                    "meta": {"count": 0}
                },
                "country": {
                    "data": {"id": "103", "type": "Country"},
                    "links": {"related": "https://tctrustoylo.blueliv.com/api/v1/country/103/"}
                },
                "fqdns": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/ip/103.76.228.28/fqdn/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/ip/103.76.228.28/relationships/fqdn/"
                    },
                    "meta": {"count": 0}
                },
                "signatures": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/ip/103.76.228.28/signature/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/ip/103.76.228.28/relationships/signature/"
                    },
                    "meta": {"count": 0}
                },
                "sparks": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/ip/103.76.228.28/spark/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/ip/103.76.228.28/relationships/spark/"
                    },
                    "meta": {"count": 0}
                },
                "tags": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/ip/103.76.228.28/tag/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/ip/103.76.228.28/relationships/tag/"
                    },
                    "meta": {"count": 0}
                },
                "threat_actors": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/ip/103.76.228.28/threat-actor/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/ip/103.76.228.28/relationships/threat-actor/"
                    },
                    "meta": {"count": 0}
                }
            },
            "type": "IP"
        }
    }

    mocker.patch.object(demisto, 'results')
    requests_mock.register_uri('POST', 'https://tctrustoylo.blueliv.com/api/v2/gateway', json=blueliv_response)

    client = Client(base_url='https://tctrustoylo.blueliv.com/api/v2', verify=False)
    args = {"IP": "103.76.228.28"}
    blueliv_indicatorIp(client, args)

    results = demisto.results.call_args[0][0]

    entry_context = results.get('EntryContext', {})
    ind = entry_context.get('BluelivThreatContext.indicator(val.ipName && val.ipName == obj.ipName)', {})
    assert str(demisto.get(ind, "countryId")) == "103"
    assert str(demisto.get(ind, "ipName")) == "1037622828"


def test_blueliv_indicatorFqdn(mocker, requests_mock):
    blueliv_response = {
        "data": {
            "attributes": {
                "active_dns_link": "https://tctrustoylo.blueliv.com/api/v1/fqdn/rayanmarketing.com/enrichment/dns/",
                "created_at": "2018-08-07T22:41:25.933804Z",
                "domain": "rayanmarketing.com",
                "first_seen": "2018-08-07T22:41:25.933689Z",
                "history_link": "https://tctrustoylo.blueliv.com/api/v1/fqdn/rayanmarketing.com/history/",
                "ioc_link": "https://tctrustoylo.blueliv.com/api/v1/fqdn/rayanmarketing.com/ioc/",
                "last_risk_scoring": "2020-07-02T11:34:14.339528Z",
                "last_seen": "2018-08-07T22:41:25.933696Z",
                "passive_dns_link": "https://tctrustoylo.blueliv.com/m/enrichment/passive-dns/",
                "risk": 2.5,
                "slugs_tags": [],
                "tlp": "white",
                "updated_at": "2020-07-02T11:34:14.339963Z",
                "virus_total_link": "https://tctrustoylo.blueliv.com/api/v1/frichment/virus-total/",
                "whois_link": "https://tctrustoylo.blueliv.com/api/v1/fqdn/rayanmarketing.com/enrichment/whois/"
            },
            "id": "5783887",
            "links": {
                "self": "https://tctrustoylo.blueliv.com/api/v1/fqdn/rayanmarketing.com/"
            },
            "relationships": {
                "campaigns": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/fqdn/rayanmarketing.com/campaign/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/fqdn/rayanmarketing.com/relampaign/"
                    },
                    "meta": {"count": 0}
                },
                "crime_servers": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/fqdn/rayanmarketing.com/crime-server/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/fqdn/rayanmarketing.cops/crime-server/"
                    },
                    "meta": {"count": 0}
                },
                "ips": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/fqdn/rayanmarketing.com/ip/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/fqdn/rayanmarketing.com/relationships/ip/"
                    },
                    "meta": {"count": 0}
                },
                "signatures": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/fqdn/rayanmarketing.com/signature/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/fqdn/rayanmarketionships/signature/"
                    },
                    "meta": {"count": 0}
                },
                "sparks": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/fqdn/rayanmarketing.com/spark/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/fqdn/rayanmarketing.com/relationships/spark/"
                    },
                    "meta": {"count": 0}
                },
                "tags": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/fqdn/rayanmarketing.com/tag/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/fqdn/rayanmarketing.com/relationships/tag/"
                    },
                    "meta": {"count": 0}
                },
                "threat_actors": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/fqdn/rayanmarketing.com/threat-actor/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/fqdn/ing.com/relationships/threat-actor/"
                    },
                    "meta": {"count": 0}
                }
            },
            "type": "FQDN"
        }
    }

    mocker.patch.object(demisto, 'results')
    requests_mock.register_uri('POST', 'https://tctrustoylo.blueliv.com/api/v2/gateway', json=blueliv_response)

    client = Client(base_url='https://tctrustoylo.blueliv.com/api/v2', verify=False)
    args = {"FQDN_id": 5783887}
    blueliv_indicatorFqdn(client, args)

    results = demisto.results.call_args[0][0]

    entry_context = results.get('EntryContext', {})
    ind = entry_context.get('BluelivThreatContext.indicator(val.id && val.id == obj.id)', {})
    assert demisto.get(ind, "lastSeen") == "2018-08-07T22:41:25.933696Z"
    assert demisto.get(ind, "risk") == "2.5"


def test_blueliv_indicatorCs(mocker, requests_mock):
    blueliv_response = {
        "data": {
            "attributes": {
                "at_feed": True,
                "at_free_feed": True,
                "bots_count": 0,
                "confidence": 1,
                "created_at": "2020-06-15T17:02:40.327300Z",
                "created_at_afapi": "2020-06-15T16:46:06.119000Z",
                "credentials_count": 0,
                "credit_cards_count": 0,
                "crime_server_url": "http://saveback.xyz/asdfgh35546fhwJYGvdfgsadsg/login.php",
                "false_positive_modification_time": "2020-06-15T17:02:38.524874Z",
                "first_seen": "2020-06-15T16:44:25Z",
                "ioc_link": "https://tctrustoylo.blueliv.com/api/v1/crime-server/6626263/ioc/",
                "is_false_positive": False,
                "last_log_timestamp": None,
                "last_risk_scoring": "2020-06-15T17:14:36.146566Z",
                "last_seen": "2020-06-15T17:02:21.737000Z",
                "main_type": "c_and_c",
                "risk": 4,
                "scans_link": "https://tctrustoylo.blueliv.com/api/v1/crime-server/6626263/enrichment/scans/",
                "service_scans": {},
                "slugs_tags": [],
                "status": "offline",
                "subtype_name": "ANUBIS",
                "target_status": None,
                "tlp": "amber",
                "updated_at": "2020-06-19T09:35:04.675771Z",
                "updated_at_afapi": "2020-06-15T17:02:21.737000Z"
            },
            "id": "6626263",
            "links": {
                "self": "https://tctrustoylo.blueliv.com/api/v1/crime-server/6626263/"
            },
            "relationships": {
                "fqdn": {
                    "data": {
                        "id": "9633658",
                        "type": "FQDN"
                    },
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/fqdn/saveback.xyz/"
                    }
                },
                "malware": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/crime-server/6626263/malware/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/crime-server/6626263/relationships/malware/"
                    },
                    "meta": {"count": 0}
                },
                "sources": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/crime-server/6626263/source/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/crime-server/6626263/relationships/source/"
                    },
                    "meta": {"count": 0}
                },
                "sparks": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/crime-server/6626263/spark/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/crime-server/6626263/relationships/spark/"
                    },
                    "meta": {"count": 0}
                },
                "subtype": {
                    "data": {
                        "id": "7458",
                        "type": "ThreatType"
                    },
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/threat-type/ANUBIS/"
                    }
                },
                "tags": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/crime-server/6626263/tag/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/crime-server/6626263/relationships/tag/"
                    },
                    "meta": {"count": 0}
                },
                "vendor_analysis": {
                    "meta": {
                        "count": []
                    }
                }
            },
            "type": "CrimeServer"
        }
    }

    mocker.patch.object(demisto, 'results')
    requests_mock.register_uri('POST', 'https://tctrustoylo.blueliv.com/api/v2/gateway', json=blueliv_response)

    client = Client(base_url='https://tctrustoylo.blueliv.com/api/v2', verify=False)
    args = {"CS_id": 6626263}
    blueliv_indicatorCs(client, args)

    results = demisto.results.call_args[0][0]

    entry_context = results.get('EntryContext', {})
    ind = entry_context.get('BluelivThreatContext.indicator(val.id && val.id == obj.id)', {})
    assert demisto.get(ind, "fqdnId") == "9633658"
    assert demisto.get(ind, "status") == "offline"


def test_blueliv_attackPattern(mocker, requests_mock):
    blueliv_response = {
        "data": {
            "attributes": {
                "attack_phases": {},
                "attacker_skills_or_knowledge_required": [],
                "capec_id": None,
                "created_at": "2018-12-24T23:00:02.352087Z",
                "description": "Adversaries may attempt to get a listing of local system or domain accounts.",
                "name": "Account Discovery",
                "prerequisites": [],
                "purposes": [],
                "references": [],
                "related_vulnerabilities": [],
                "related_weaknesses": [],
                "severity": "Medium",
                "solutions_and_mitigations": [],
                "tlp": "white",
                "updated_at": "2018-12-24T23:00:02.352102Z",
                "uuid": "72b74d71-8169-42aa-92e0-e7b04b9f5a08"
            },
            "id": "686",
            "links": {
                "self": "https://tctrustoylo.blueliv.com/api/v1/attack-pattern/686/"
            },
            "relationships": {
                "campaigns": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/attack-pattern/686/campaign/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/attack-pattern/686/relationships/campaign/"
                    },
                    "meta": {"count": 0}
                },
                "cves": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/attack-pattern/686/cve/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/attack-pattern/686/relationships/cve/"
                    },
                    "meta": {"count": 0}
                },
                "signatures": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/attack-pattern/686/signature/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/attack-pattern/686/relationships/signature/"
                    },
                    "meta": {"count": 0}
                },
                "threat_actors": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/attack-pattern/686/threat-actor/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/attack-pattern/686/relationships/threat-actor/"
                    },
                    "meta": {"count": 0}
                }
            },
            "type": "AttackPattern"
        }
    }

    mocker.patch.object(demisto, 'results')
    requests_mock.register_uri('POST', 'https://tctrustoylo.blueliv.com/api/v2/gateway', json=blueliv_response)

    client = Client(base_url='https://tctrustoylo.blueliv.com/api/v2', verify=False)
    args = {"attackPattern_id": 686}
    blueliv_attackPattern(client, args)

    results = demisto.results.call_args[0][0]

    entry_context = results.get('EntryContext', {})
    ind = entry_context.get('BluelivThreatContext.attackPattern(val.id && val.id == obj.id)', {})
    assert demisto.get(ind, "name") == "Account Discovery"
    assert demisto.get(ind, "serverity") == "Medium"


def test_blueliv_tool(mocker, requests_mock):
    blueliv_response = {
        "data": {
            "attributes": {
                "created_at": "2020-02-26T14:35:55.698486Z",
                "description": "\u003cp\u003eACEHASH is a credential theft/password hash dumping utility.",
                "discovery_date": None,
                "first_seen": "2012-12-01T00:00:00Z",
                "last_seen": "2019-12-01T00:00:00Z",
                "name": "ACEHASH",
                "references": [
                    {
                        "link": "https://content.fireeye.com/apt-41/rpt-apt41",
                        "title": "Double Dragon: APT41, a dual espionage and cyber crime operation"
                    }
                ],
                "targeted_platforms": [],
                "tlp": "white",
                "updated_at": "2020-02-26T14:35:55.698549Z",
                "uuid": None,
                "version": ""
            },
            "id": "532",
            "links": {
                "self": "https://tctrustoylo.blueliv.com/api/v1/tool/532/"
            },
            "relationships": {
                "campaigns": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/tool/532/campaign/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/tool/532/relationships/campaign/"
                    },
                    "meta": {"count": 0}
                },
                "cves": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/tool/532/cve/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/tool/532/relationships/cve/"
                    },
                    "meta": {"count": 0}
                },
                "signatures": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/tool/532/signature/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/tool/532/relationships/signature/"
                    },
                    "meta": {"count": 0}
                },
                "threat_actors": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/tool/532/threat-actor/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/tool/532/relationships/threat-actor/"
                    },
                    "meta": {"count": 0}
                }
            },
            "type": "Tool"
        }
    }
    mocker.patch.object(demisto, 'results')
    requests_mock.register_uri('POST', 'https://tctrustoylo.blueliv.com/api/v2/gateway', json=blueliv_response)

    client = Client(base_url='https://tctrustoylo.blueliv.com/api/v2', verify=False)
    args = {"tool_id": 532}
    blueliv_tool(client, args)

    results = demisto.results.call_args[0][0]

    entry_context = results.get('EntryContext', {})
    ind = entry_context.get('BluelivThreatContext.tool(val.id && val.id == obj.id)', {})
    assert demisto.get(ind, "name") == "ACEHASH"
    assert demisto.get(ind, "lastSeen") == "2019-12-01T00:00:00Z"


def test_blueliv_signature(mocker, requests_mock):
    blueliv_response = {
        "data": {
            "attributes": {
                "created_at": "2020-06-15T02:11:21.962302Z",
                "name": "ET TROJAN DonotGroup Staging Domain in DNS Query (sid 2030333)",
                "references": [],
                "sid": 2030333,
                "signature": "alert udp $HOME_NET any -\u003e any 53 (m depth:1; ack_target C_at 2020_06_12;)",
                "status": "enabled",
                "tlp": "white",
                "type": "snort",
                "updated_at": "2020-06-15T02:11:21.962364Z",
                "version": 2
            },
            "id": "84458",
            "links": {
                "self": "https://tctrustoylo.blueliv.com/api/v1/signature/84458/"
            },
            "relationships": {
                "attack_patterns": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/signature/84458/attack-pattern/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/signature/84458/relationships/attack-pattern/"
                    },
                    "meta": {"count": 0}
                },
                "campaigns": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/signature/84458/campaign/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/signature/84458/relationships/campaign/"
                    },
                    "meta": {"count": 0}
                },
                "cves": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/signature/84458/cve/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/signature/84458/relationships/cve/"
                    },
                    "meta": {"count": 0}
                },
                "fqdns": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/signature/84458/fqdn/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/signature/84458/relationships/fqdn/"
                    },
                    "meta": {"count": 0}
                },
                "ips": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/signature/84458/ip/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/signature/84458/relationships/ip/"
                    },
                    "meta": {"count": 0}
                },
                "malware": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/signature/84458/malware/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/signature/84458/relationships/malware/"
                    },
                    "meta": {"count": 0}
                },
                "threat_actors": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/signature/84458/threat-actor/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/signature/84458/relationships/threat-actor/"
                    },
                    "meta": {"count": 0}
                },
                "threat_types": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/signature/84458/threat-type/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/signature/84458/relationships/threat-type/"
                    },
                    "meta": {"count": 0}
                },
                "tools": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/signature/84458/tool/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/signature/84458/relationships/tool/"
                    },
                    "meta": {"count": 0}
                }
            },
            "type": "Signature"
        }
    }

    mocker.patch.object(demisto, 'results')
    requests_mock.register_uri('POST', 'https://tctrustoylo.blueliv.com/api/v2/gateway', json=blueliv_response)

    client = Client(base_url='https://tctrustoylo.blueliv.com/api/v2', verify=False)
    args = {"signature_id": 84458}
    blueliv_signature(client, args)

    results = demisto.results.call_args[0][0]

    entry_context = results.get('EntryContext', {})
    ind = entry_context.get('BluelivThreatContext.signature(val.id && val.id == obj.id)', {})
    assert demisto.get(ind, "type") == "snort"
    assert demisto.get(ind, "updatedAt") == "2020-06-15T02:11:21.962364Z"


def test_blueliv_cve(mocker, requests_mock):
    blueliv_response = {
        "data": {
            "attributes": {
                "bl_score": 96,
                "created_at": "2020-02-26T01:12:25.635599Z",
                "cvss": {
                    "v2": {
                        "accessComplexity": "LOW",
                        "accessVector": "NETWORK",
                        "authentication": "NONE",
                        "availabilityImpact": "COMPLETE",
                        "baseScore": 10,
                        "confidentialityImpact": "COMPLETE",
                        "integrityImpact": "COMPLETE",
                        "vectorString": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
                        "version": "2.0"
                    },
                    "v3": None
                },
                "description": "OpenSMTPD before 6.6.4 allows remote code execution because of an out-s read in.",
                "exploits": [
                    {
                        "author": "Qualys Corporation",
                        "date": "2020-02-26",
                        "id": None,
                        "name": "OpenSMTPD \u003c 6.6.3p1 - Local Privilege Escalation + Remote Code Execution",
                        "platform": "openbsd",
                        "port": "",
                        "type": "remote",
                        "url": "https://github.com/offensive-security/exploitdb/blo/openbsd/remote/48140.c"
                    }
                ],
                "ioc_link": "https://tctrustoylo.blueliv.com/api/v1/cve/CVE-2020-8794/ioc/",
                "microsoft_bulletins": [],
                "name": "CVE-2020-8794",
                "num_crime_servers": 0,
                "num_malware": 0,
                "platforms": [
                    {
                        "id": "cpe:2.3:a:opensmtpd:opensmtpd:*:*:*:*:*:*:*:*",
                        "title": "cpe:2.3:a:opensmtpd:opensmtpd:*:*:*:*:*:*:*:*"
                    }
                ],
                "published_at": "2020-02-25T17:15:00Z",
                "references": [
                    {
                        "id": "https://www.openbsd.org/security.html",
                        "type": "MISC",
                        "url": "https://www.openbsd.org/security.html"
                    },
                    {
                        "id": "https://www.openwall.com/lists/oss-security/2020/02/24/5",
                        "type": "MISC",
                        "url": "https://www.openwall.com/lists/oss-security/2020/02/24/5"
                    },
                    {
                        "id": "[oss-security] 20200226 Re: LPE and RCE in OpenSMTPD's default install (CVE-2020-8794)",
                        "type": "MLIST",
                        "url": "http://www.openwall.com/lists/oss-security/2020/02/26/1"
                    },
                    {
                        "id": "DSA-4634",
                        "type": "DEBIAN",
                        "url": "https://www.debian.org/security/2020/dsa-4634"
                    },
                    {
                        "id": "20200227 LPE and RCE in OpenSMTPD's default install (CVE-2020-8794)",
                        "type": "FULLDISC",
                        "url": "http://seclists.org/fulldisclosure/2020/Feb/32"
                    },
                    {
                        "id": "[oss-security] 20200301 Re: LPE and RCE in OpenSMTPD's default install (CVE-2020-8794)",
                        "type": "MLIST",
                        "url": "http://www.openwall.com/lists/oss-security/2020/03/01/1"
                    },
                    {
                        "id": "[oss-security] 20200301 Re: LPE and RCE in OpenSMTPD's default install (CVE-2020-8794)",
                        "type": "MLIST",
                        "url": "http://www.openwall.com/lists/oss-security/2020/03/01/2"
                    },
                    {
                        "id": "http://packetstormsecurity.com/files/156633/OpenSMRead-Local-Privilege-Escalation.html",
                        "type": "MISC",
                        "url": "http://packetstormsecurity.com/files/156633/OpenSMTPDivilege-Escalation.html"
                    }
                ],
                "score": 10,
                "tags_slugs": [],
                "updated_at": "2020-03-09T15:17:41.667962Z",
                "uuid": None
            },
            "id": "139511",
            "links": {
                "self": "https://tctrustoylo.blueliv.com/api/v1/cve/CVE-2020-8794/"
            },
            "relationships": {
                "attack_patterns": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/cve/CVE-2020-8794/attack-pattern/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/cve/CVE-2020-8794/relationships/attackattern/"
                    },
                    "meta": {"count": 0}
                },
                "campaigns": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/cve/CVE-2020-8794/campaign/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/cve/CVE-2020-8794/relationships/campaigns/"
                    },
                    "meta": {"count": 0}
                },
                "crime_servers": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/cve/CVE-2020-8794/crime-server/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/cve/CVE-2020-8794/relationships/crime-server/"
                    },
                    "meta": {"count": 0}
                },
                "malware": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/cve/CVE-2020-8794/malware/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/cve/CVE-2020-8794/relationships/malware/"
                    },
                    "meta": {"count": 0}
                },
                "mentions": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/cve/CVE-2020-8794/mention/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/cve/CVE-2020-8794/relationships/mentions/"
                    },
                    "meta": {"count": 0}
                },
                "signatures": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/cve/CVE-2020-8794/signature/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/cve/CVE-2020-8794/relationships/signature/"
                    },
                    "meta": {"count": 0}
                },
                "sparks": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/cve/CVE-2020-8794/spark/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/cve/CVE-2020-8794/relationships/spark/"
                    },
                    "meta": {"count": 0}
                },
                "tags": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/cve/CVE-2020-8794/tag/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/cve/CVE-2020-8794/relationships/tags/"
                    },
                    "meta": {"count": 0}
                },
                "threat_actors": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/cve/CVE-2020-8794/threat-actor/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/cve/CVE-2020-8794/relationships/threat-actors/"
                    },
                    "meta": {"count": 0}
                },
                "tools": {
                    "links": {
                        "related": "https://tctrustoylo.blueliv.com/api/v1/cve/CVE-2020-8794/tool/",
                        "self": "https://tctrustoylo.blueliv.com/api/v1/cve/CVE-2020-8794/relationships/tools/"
                    },
                    "meta": {"count": 0}
                }
            },
            "type": "CVE"
        }
    }

    mocker.patch.object(demisto, 'results')
    requests_mock.register_uri('POST', 'https://tctrustoylo.blueliv.com/api/v2/gateway', json=blueliv_response)

    client = Client(base_url='https://tctrustoylo.blueliv.com/api/v2', verify=False)
    args = {"CVE": "CVE-2020-8794"}
    blueliv_cve(client, args)

    results = demisto.results.call_args[0][0]

    entry_context = results.get('EntryContext', {})
    ind = entry_context.get('BluelivThreatContext.cve(val.id && val.id == obj.id)', {})
    assert demisto.get(ind, "updatedAt") == "2020-03-09T15:17:41.667962Z"
    assert str(demisto.get(ind, "score")) == "10"
