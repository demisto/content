from DomainToolsSetIndicatorTable.set_indicator_table_data import main
from CommonServerPython import *


def test_set_indicator_table(mocker):
    def execute_command(name, args=None):
        if name == 'CalculateAge':
            return [
                {
                    'Contents': {'age': 8}
                }
            ]
        elif name == 'CalculateIndicatorReputation':
            return [
                {
                    'Contents': {'reputation': 'Good'}
                }
            ]

    create_date = (datetime.now() - timedelta(days=8)).strftime('%Y-%m-%d')
    domaintools_data = {
        'Name': 'demisto.com',
        'Hosting': {
            'IPAddresses': [
                {
                    'address': {
                        'value': '104',
                        'count': 122
                    },
                    'asn': [
                        {
                            'value': 15169,
                            'count': 13952015
                        }
                    ],
                    'country_code': {
                        'value': 'us',
                        'count': 305300756
                    },
                    'isp': {
                        'value': 'Google LLC',
                        'count': 12313137
                    }
                }
            ],
            'IPCountryCode': 'us',
            'MailServers': [
                {
                    'host': {
                        'value': 'ma',
                        'count': 13
                    },
                    'domain': {
                        'value': 'pphosted.com',
                        'count': 90571
                    },
                    'ip': [
                        {
                            'value': '67',
                            'count': 10
                        }
                    ],
                    'priority': 10
                },
                {
                    'host': {
                        'value': 'mb',
                        'count': 12
                    },
                    'domain': {
                        'value': 'pphosted.com',
                        'count': 90571
                    },
                    'ip': [
                        {
                            'value': '1',
                            'count': 9
                        }
                    ],
                    'priority': 10
                }
            ],
            'SPFRecord': 'v=spf1 mx include:spf.protection.outlook.com include:spf.autopilothq.com',
            'NameServers': [
                {
                    'host': {
                        'value': 'pns31.cloudns.net',
                        'count': 11071
                    },
                    'domain': {
                        'value': 'cloudns.net',
                        'count': 227290
                    },
                    'ip': [
                        {
                            'value': '185',
                            'count': 15798
                        }
                    ]
                },
                {
                    'host': {
                        'value': 'pns32.cloudns.net',
                        'count': 10594
                    },
                    'domain': {
                        'value': 'cloudns.net',
                        'count': 227290
                    },
                    'ip': [
                        {
                            'value': '185',
                            'count': 15276
                        }
                    ]
                },
                {
                    'host': {
                        'value': 'pns33.cloudns.net',
                        'count': 10037
                    },
                    'domain': {
                        'value': 'cloudns.net',
                        'count': 227290
                    },
                    'ip': [
                        {
                            'value': '18',
                            'count': 12976
                        }
                    ]
                },
                {
                    'host': {
                        'value': 'pns34.cloudns.net',
                        'count': 10008
                    },
                    'domain': {
                        'value': 'cloudns.net',
                        'count': 227290
                    },
                    'ip': [
                        {
                            'value': '185',
                            'count': 12705
                        }
                    ]
                }
            ],
            'SSLCertificate': [
                {
                    'hash': {
                        'value': '7fed20410a1eb258c540f9c08ac7d361a9abd505',
                        'count': 1
                    },
                    'subject': {
                        'value': 'CN=www.demisto.com',
                        'count': 1
                    },
                    'organization': {
                        'value': '',
                        'count': 0
                    },
                    'email': []
                },
                {
                    'hash': {
                        'value': '36cbf4ec8b46e8baadaf4a9895d7dec7af7f138e',
                        'count': 1
                    },
                    'subject': {
                        'value': 'CN=demisto.com',
                        'count': 1
                    },
                    'organization': {
                        'value': '',
                        'count': 0
                    },
                    'email': []
                }
            ],
        },
        'Identity': {
            'SOAEmail': ['cloudns.net'],
            'SSLCertificateEmail': [],
            'EmailDomains': ['cloudns.net', 'namecheap.com', 'whoisguard.com'],
            'AdditionalWhoisEmails': [
                {
                    'value': 'namecheap.com',
                    'count': 18465843
                }
            ],
        },
        'Analytics': {
            'ProximityRiskScore': 65,
            'ThreatProfileRiskScore': {
                'RiskScore': 66
            }
        },
        'Registration': {
            'CreateDate': create_date
        }
    }

    mocker.patch.object(demisto, 'args', return_value={'domaintools_data': domaintools_data})
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    mocker.patch.object(demisto, 'results')

    main()
    assert demisto.results.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0]['Type'] == entryTypes['note']
    assert results[0]['ContentsFormat'] == formats['json']
    assert results[0]['Contents'] == {}
    assert results[0]['HumanReadable'] == 'Data for demisto.com enriched.'
    assert results[0]['EntryContext'] == {}
