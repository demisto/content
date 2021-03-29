import datetime

import Whois
import demistomock as demisto
import pytest
import subprocess
import time
import tempfile
import sys

from CommonServerPython import DBotScoreReliability


def assert_results_ok():
    assert demisto.results.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0] == 'ok'


def test_test_command(mocker):
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'command', return_value='test-module')
    Whois.main()
    assert_results_ok()


@pytest.mark.parametrize(
    'query,expected',
    [("app.paloaltonetwork.com", "paloaltonetwork.com"),
     ("test.this.google.co.il", "google.co.il"),
     ("app.XSOAR.test", "app.XSOAR.test")]
)
def test_get_domain_from_query(query, expected):
    from Whois import get_domain_from_query
    assert get_domain_from_query(query) == expected


def test_socks_proxy_fail(mocker):
    mocker.patch.object(demisto, 'params', return_value={'proxy_url': 'socks5://localhost:1180'})
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(demisto, 'results')
    with pytest.raises(SystemExit) as err:
        Whois.main()
    assert err.type == SystemExit
    assert demisto.results.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert "Couldn't connect with the socket-server" in results[0]['Contents']


def test_socks_proxy(mocker, request):
    mocker.patch.object(demisto, 'params', return_value={'proxy_url': 'socks5h://localhost:9980'})
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(demisto, 'results')
    tmp = tempfile.TemporaryFile('w+')
    microsocks = './test_data/microsocks_darwin' if 'darwin' in sys.platform else './test_data/microsocks'
    process = subprocess.Popen([microsocks, "-p", "9980"], stderr=subprocess.STDOUT, stdout=tmp)

    def cleanup():
        process.kill()

    request.addfinalizer(cleanup)
    time.sleep(1)
    Whois.main()
    assert_results_ok()
    tmp.seek(0)
    assert 'connected to' in tmp.read()  # make sure we went through microsocks


TEST_QUERY_RESULT_INPUT = [
    (
        {'contacts': {'admin': None, 'billing': None, 'registrant': None, 'tech': None},
         'raw': ['NOT FOUND\n>>> Last update of WHOIS database: 2020-05-07T13:55:34Z <<<']},
        'rsqupuo.info',
        DBotScoreReliability.B,
        False
    ),
    (
        {'contacts': {'admin': None, 'billing': None, 'registrant': None, 'tech': None},
         'raw': ['No match for "BLABLA43213422342AS.COM".>>> Last update of whois database: 2020-05-20T08:39:17Z <<<']},
        "BLABLA43213422342AS.COM",
        DBotScoreReliability.B, False
    ),
    (
        {'status': ['clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)'],
         'updated_date': [datetime.datetime(2019, 9, 9, 8, 39, 4)],
         'contacts': {'admin': {'country': 'US', 'state': 'CA', 'name': 'Google LLC'},
                      'tech': {'organization': 'Google LLC', 'state': 'CA', 'country': 'US'},
                      'registrant': {'organization': 'Google LLC', 'state': 'CA', 'country': 'US'}, 'billing': None},
         'nameservers': ['ns1.google.com', 'ns4.google.com', 'ns3.google.com', 'ns2.google.com'],
         'expiration_date': [datetime.datetime(2028, 9, 13, 0, 0), datetime.datetime(2028, 9, 13, 0, 0)],
         'emails': ['abusecomplaints@markmonitor.com', 'whoisrequest@markmonitor.com'],
         'raw': ['Domain Name: google.com\nRegistry Domain ID: 2138514_DOMAIN_COM-VRSN'],
         'creation_date': [datetime.datetime(1997, 9, 15, 0, 0)], 'id': ['2138514_DOMAIN_COM-VRSN']},
        'google.com',
        DBotScoreReliability.B,
        True
    ),
    (
        {'contacts': {'admin': None, 'billing': None, 'registrant': None, 'tech': None}},
        'rsqupuo.info',
        DBotScoreReliability.B,
        False
    ),
    (
        {'status': ['clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)'],
         'updated_date': [datetime.datetime(2019, 9, 9, 8, 39, 4)],
         'contacts': {'admin': {'country': 'US', 'state': 'CA', 'name': 'Google LLC'},
                      'tech': {'organization': 'Google LLC', 'state': 'CA', 'country': 'US'},
                      'registrant': {'organization': 'Google LLC', 'state': 'CA', 'country': 'US'}, 'billing': None},
         'nameservers': ['ns1.google.com', 'ns4.google.com', 'ns3.google.com', 'ns2.google.com'],
         'expiration_date': [datetime.datetime(2028, 9, 13, 0, 0), datetime.datetime(2028, 9, 13, 0, 0)],
         'emails': ['abusecomplaints@markmonitor.com', 'whoisrequest@markmonitor.com'],
         'raw': 'Domain Name: google.com\nRegistry Domain ID: 2138514_DOMAIN_COM-VRSN',
         'creation_date': [datetime.datetime(1997, 9, 15, 0, 0)], 'id': ['2138514_DOMAIN_COM-VRSN']},
        'google.com',
        DBotScoreReliability.B,
        True
    ),
    (
        {'status': ['clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)'],
         'updated_date': [datetime.datetime(2019, 9, 9, 8, 39, 4)],
         'contacts': {'admin': {'country': 'US', 'state': 'CA', 'name': 'Google LLC'},
                      'tech': {'organization': 'Google LLC', 'state': 'CA', 'country': 'US'},
                      'registrant': {'organization': 'Google LLC', 'state': 'CA', 'country': 'US'}, 'billing': None},
         'nameservers': ['ns1.google.com', 'ns4.google.com', 'ns3.google.com', 'ns2.google.com'],
         'expiration_date': [datetime.datetime(2028, 9, 13, 0, 0), datetime.datetime(2028, 9, 13, 0, 0)],
         'emails': ['abusecomplaints@markmonitor.com', 'whoisrequest@markmonitor.com'],
         'raw': {'data': 'Domain Name: google.com\nRegistry Domain ID: 2138514_DOMAIN_COM-VRSN'},
         'creation_date': [datetime.datetime(1997, 9, 15, 0, 0)], 'id': ['2138514_DOMAIN_COM-VRSN']},
        'google.com',
        DBotScoreReliability.B,
        True
    ),
    (
        {'contacts': {'admin': None, 'billing': None, 'registrant': None, 'tech': None},
         'raw': {'data': 'Domain Name: google.com\nRegistry Domain ID: 2138514_DOMAIN_COM-VRSN'}},
        'rsqupuo.info',
        DBotScoreReliability.B,
        True
    ),
]


@pytest.mark.parametrize('whois_result, domain, reliability, expected', TEST_QUERY_RESULT_INPUT)
def test_query_result(whois_result, domain, reliability, expected):
    from Whois import create_outputs
    md, standard_ec, dbot_score = create_outputs(whois_result, domain, reliability)
    assert standard_ec['Whois']['QueryResult'] == expected
    assert dbot_score.get('DBotScore(val.Indicator && val.Indicator == obj.Indicator && val.Vendor == obj.Vendor && '
                          'val.Type == obj.Type)').get('Reliability') == 'B - Usually reliable'


def test_ip_command(mocker):
    """
    Given:
        - IP addresses

    When:
        - running the IP command

    Then:
        - Verify the result is as expected
        - Verify support list of IPs
    """
    from Whois import ip_command
    mocker.patch.object(Whois, 'get_whois_ip', return_value=IP_OUTPUT)
    result = ip_command(['4.4.4.4', '4.4.4.4'], DBotScoreReliability.B)
    assert len(result) == 2
    assert result[0].outputs_prefix == 'Whois.IP'
    assert result[0].outputs.get('query') == '4.4.4.4'
    assert result[0].indicator.to_context() == {'DBotScore': {'Indicator': '4.4.4.4',
                                                              'Reliability': 'B - Usually reliable',
                                                              'Score': 0,
                                                              'Type': 'ip',
                                                              'Vendor': 'Whois'},
                                                'IP(val.Address && val.Address == obj.Address)': {
                                                    'ASN': '3356',
                                                    'Address': '4.4.4.4',
                                                    'FeedRelatedIndicators': {
                                                        'description': None,
                                                        'type': 'IP',
                                                        'value': '4.4.0.0/16'},
                                                    'Geo': {'Country': 'US'},
                                                    'Organization': {'Name': 'LEVEL3, US'}
                                                }}


IP_OUTPUT = {
    "asn": "3356",
    "asn_cidr": "4.0.0.0/9",
    "asn_country_code": "US",
    "asn_date": "1992-12-01",
    "asn_description": "LEVEL3, US",
    "asn_registry": "arin",
    "entities": [
        "LVLT"
    ],
    "network": {
        "cidr": "4.4.0.0/16",
        "country": "",
        "end_address": "4.4.255.255",
        "events": [
            {
                "action": "last changed",
                "actor": "",
                "timestamp": "2010-09-28T06:37:41-04:00"
            },
            {
                "action": "registration",
                "actor": "",
                "timestamp": "2010-09-28T06:37:41-04:00"
            }
        ],
        "handle": "NET-4-4-0-0-1",
        "ip_version": "v4",
        "links": [
            "https://rdap.arin.net/registry/ip/4.4.0.0",
            "https://whois.arin.net/rest/net/NET-4-4-0-0-1",
            "https://rdap.arin.net/registry/ip/4.0.0.0/9"
        ],
        "name": "LVLT-STATIC-4-4-16",
        "notices": [
            {
                "description": "By using the ARIN RDAP/Whois service, you are agreeing to the RDAP/Whois Terms of Use",
                "links": [
                    "https://www.arin.net/resources/registry/whois/tou/"
                ],
                "title": "Terms of Service"
            },
            {
                "description": "If you see inaccuracies in the results, please visit: ",
                "links": [
                    "https://www.arin.net/resources/registry/whois/inaccuracy_reporting/"
                ],
                "title": "Whois Inaccuracy Reporting"
            },
            {
                "description": "Copyright 1997-2021, American Registry for Internet Numbers, Ltd.",
                "links": "",
                "title": "Copyright Notice"
            }
        ],
        "parent_handle": "NET-4-0-0-0-1",
        "raw": "",
        "remarks": [
            {
                "description": "This space is statically assigned",
                "links": "",
                "title": "Registration Comments"
            }
        ],
        "start_address": "4.4.0.0",
        "status": [
            "active"
        ],
        "type": "ALLOCATION"
    },
    "nir": "",
    "objects": {
        "APL7-ARIN": {
            "contact": {
                "address": [
                    {
                        "type": "",
                        "value": "1025 Eldorado Blvd.\nBroomfield\nCO\n80021\nUnited States"
                    }
                ],
                "email": [
                    {
                        "type": "",
                        "value": "ipaddressing@level3.com"
                    },
                    {
                        "type": "",
                        "value": "ipadmin@centurylink.com"
                    }
                ],
                "kind": "group",
                "name": "ADMIN POC LVLT",
                "phone": [
                    {
                        "type": [
                            "work",
                            "voice"
                        ],
                        "value": "+1-877-453-8353"
                    }
                ],
                "role": "",
                "title": ""
            },
            "entities": "",
            "events": [
                {
                    "action": "last changed",
                    "actor": "",
                    "timestamp": "2020-08-11T13:55:04-04:00"
                },
                {
                    "action": "registration",
                    "actor": "",
                    "timestamp": "2003-01-28T16:00:44-05:00"
                }
            ],
            "events_actor": "",
            "handle": "APL7-ARIN",
            "links": [
                "https://rdap.arin.net/registry/entity/APL7-ARIN",
                "https://whois.arin.net/rest/poc/APL7-ARIN"
            ],
            "notices": [
                {
                    "description": "By using the ARIN RDAP/Whois service, you are agreeing to the RDAP/Whois Terms of Use",
                    "links": [
                        "https://www.arin.net/resources/registry/whois/tou/"
                    ],
                    "title": "Terms of Service"
                },
                {
                    "description": "If you see inaccuracies in the results, please visit: ",
                    "links": [
                        "https://www.arin.net/resources/registry/whois/inaccuracy_reporting/"
                    ],
                    "title": "Whois Inaccuracy Reporting"
                },
                {
                    "description": "Copyright 1997-2021, American Registry for Internet Numbers, Ltd.",
                    "links": "",
                    "title": "Copyright Notice"
                }
            ],
            "raw": "",
            "remarks": "",
            "roles": [
                "administrative"
            ],
            "status": [
                "validated"
            ]
        },
        "APL8-ARIN": {
            "contact": {
                "address": [
                    {
                        "type": "",
                        "value": "1025 Eldorado Blvd.\nBroomfield\nCO\n80021\nUnited States"
                    }
                ],
                "email": [
                    {
                        "type": "",
                        "value": "security@level3.com"
                    },
                    {
                        "type": "",
                        "value": "abuse@level3.com"
                    }
                ],
                "kind": "group",
                "name": "Abuse POC LVLT",
                "phone": [
                    {
                        "type": [
                            "work",
                            "voice"
                        ],
                        "value": "+1-877-453-8353"
                    }
                ],
                "role": "",
                "title": ""
            },
            "entities": "",
            "events": [
                {
                    "action": "last changed",
                    "actor": "",
                    "timestamp": "2005-12-07T13:48:26-05:00"
                },
                {
                    "action": "registration",
                    "actor": "",
                    "timestamp": "2003-01-28T16:00:44-05:00"
                }
            ],
            "events_actor": "",
            "handle": "APL8-ARIN",
            "links": [
                "https://rdap.arin.net/registry/entity/APL8-ARIN",
                "https://whois.arin.net/rest/poc/APL8-ARIN"
            ],
            "notices": [
                {
                    "description": "By using the ARIN RDAP/Whois service, you are agreeing to the RDAP/Whois Terms of Use",
                    "links": [
                        "https://www.arin.net/resources/registry/whois/tou/"
                    ],
                    "title": "Terms of Service"
                },
                {
                    "description": "If you see inaccuracies in the results, please visit: ",
                    "links": [
                        "https://www.arin.net/resources/registry/whois/inaccuracy_reporting/"
                    ],
                    "title": "Whois Inaccuracy Reporting"
                },
                {
                    "description": "Copyright 1997-2021, American Registry for Internet Numbers, Ltd.",
                    "links": "",
                    "title": "Copyright Notice"
                }
            ],
            "raw": "",
            "remarks": [
                {
                    "description": "The information for this POC has been reported to be invalid. ARIN has attempted to obtain updated data, but has been unsuccessful. To provide current contact information, please e-mail hostmaster@arin.net.",
                    "links": "",
                    "title": "Registration Comments"
                },
                {
                    "description": "ARIN has attempted to validate the data for this POC, but has received no response from the POC since 2010-06-08",
                    "links": "",
                    "title": "Unvalidated POC"
                }
            ],
            "roles": [
                "abuse"
            ],
            "status": ""
        },
        "IPADD5-ARIN": {
            "contact": {
                "address": [
                    {
                        "type": "",
                        "value": "1025 Eldorado Blvd\nBroomfield\nCO\n80021\nUnited States"
                    }
                ],
                "email": [
                    {
                        "type": "",
                        "value": "ipaddressing@level3.com"
                    }
                ],
                "kind": "group",
                "name": "ipaddressing",
                "phone": [
                    {
                        "type": [
                            "work",
                            "voice"
                        ],
                        "value": "+1-877-453-8353"
                    }
                ],
                "role": "",
                "title": ""
            },
            "entities": "",
            "events": [
                {
                    "action": "last changed",
                    "actor": "",
                    "timestamp": "2019-08-28T08:24:13-04:00"
                },
                {
                    "action": "registration",
                    "actor": "",
                    "timestamp": "2012-01-26T11:21:30-05:00"
                }
            ],
            "events_actor": "",
            "handle": "IPADD5-ARIN",
            "links": [
                "https://rdap.arin.net/registry/entity/IPADD5-ARIN",
                "https://whois.arin.net/rest/poc/IPADD5-ARIN"
            ],
            "notices": [
                {
                    "description": "By using the ARIN RDAP/Whois service, you are agreeing to the RDAP/Whois Terms of Use",
                    "links": [
                        "https://www.arin.net/resources/registry/whois/tou/"
                    ],
                    "title": "Terms of Service"
                },
                {
                    "description": "If you see inaccuracies in the results, please visit: ",
                    "links": [
                        "https://www.arin.net/resources/registry/whois/inaccuracy_reporting/"
                    ],
                    "title": "Whois Inaccuracy Reporting"
                },
                {
                    "description": "Copyright 1997-2021, American Registry for Internet Numbers, Ltd.",
                    "links": "",
                    "title": "Copyright Notice"
                }
            ],
            "raw": "",
            "remarks": "",
            "roles": [
                "technical"
            ],
            "status": [
                "validated"
            ]
        },
        "LVLT": {
            "contact": {
                "address": [
                    {
                        "type": "",
                        "value": "1025 Eldorado Blvd.\nBroomfield\nCO\n80021\nUnited States"
                    }
                ],
                "email": "",
                "kind": "org",
                "name": "Level 3 Communications, Inc.",
                "phone": "",
                "role": "",
                "title": ""
            },
            "entities": [
                "NOCSU27-ARIN",
                "APL7-ARIN",
                "IPADD5-ARIN",
                "APL8-ARIN"
            ],
            "events": [
                {
                    "action": "last changed",
                    "actor": "",
                    "timestamp": "2020-08-11T14:21:01-04:00"
                },
                {
                    "action": "registration",
                    "actor": "",
                    "timestamp": "1998-05-22T00:00:00-04:00"
                }
            ],
            "events_actor": "",
            "handle": "LVLT",
            "links": [
                "https://rdap.arin.net/registry/entity/LVLT",
                "https://whois.arin.net/rest/org/LVLT"
            ],
            "notices": "",
            "raw": "",
            "remarks": [
                {
                    "description": "ADDRESSES WITHIN THIS BLOCK ARE NON-PORTABLE ANY ISP ANNOUNCING PORTIONS WITHIN OUR RANGES SHOULD NOT RELY ON PRESENTED LOA'S UNLESS THOSE RANGES ARE ALSO ANNOUNCED TO A CENTURYLINK ASN.\n\nAll abuse reports MUST include: \n* src IP \n* dest IP (your IP) \n* dest port \n* Accurate date/timestamp and timezone of activity \n* Intensity/frequency (short log extracts) \n* Your contact details (phone and email) \nWithout these we will be unable to identify the correct owner of the IP address at that point in time.\n\nFor subpoena or court order please fax 844.254.5800 or refer to our Law Enforcement Support page http://www.centurylink.com/static/Pages/AboutUs/Legal/LawEnforcement/",
                    "links": "",
                    "title": "Registration Comments"
                }
            ],
            "roles": [
                "registrant"
            ],
            "status": ""
        },
        "NOCSU27-ARIN": {
            "contact": {
                "address": [
                    {
                        "type": "",
                        "value": "1025 Eldorado Blvd\nBroomfield\nCO\n80021\nUnited States"
                    }
                ],
                "email": [
                    {
                        "type": "",
                        "value": "noc.coreip@level3.com"
                    }
                ],
                "kind": "group",
                "name": "NOC Support",
                "phone": [
                    {
                        "type": [
                            "work",
                            "voice"
                        ],
                        "value": "+1-877-453-8353"
                    }
                ],
                "role": "",
                "title": ""
            },
            "entities": "",
            "events": [
                {
                    "action": "last changed",
                    "actor": "",
                    "timestamp": "2016-11-19T05:13:31-05:00"
                },
                {
                    "action": "registration",
                    "actor": "",
                    "timestamp": "2012-01-30T18:00:30-05:00"
                }
            ],
            "events_actor": "",
            "handle": "NOCSU27-ARIN",
            "links": [
                "https://rdap.arin.net/registry/entity/NOCSU27-ARIN",
                "https://whois.arin.net/rest/poc/NOCSU27-ARIN"
            ],
            "notices": [
                {
                    "description": "By using the ARIN RDAP/Whois service, you are agreeing to the RDAP/Whois Terms of Use",
                    "links": [
                        "https://www.arin.net/resources/registry/whois/tou/"
                    ],
                    "title": "Terms of Service"
                },
                {
                    "description": "If you see inaccuracies in the results, please visit: ",
                    "links": [
                        "https://www.arin.net/resources/registry/whois/inaccuracy_reporting/"
                    ],
                    "title": "Whois Inaccuracy Reporting"
                },
                {
                    "description": "Copyright 1997-2021, American Registry for Internet Numbers, Ltd.",
                    "links": "",
                    "title": "Copyright Notice"
                }
            ],
            "raw": "",
            "remarks": [
                {
                    "description": "ARIN has attempted to validate the data for this POC, but has received no response from the POC since 2017-11-18",
                    "links": "",
                    "title": "Unvalidated POC"
                }
            ],
            "roles": [
                "noc"
            ],
            "status": ""
        }
    },
    "query": "4.4.4.4",
    "raw": ""
}