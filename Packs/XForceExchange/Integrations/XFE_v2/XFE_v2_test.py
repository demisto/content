from XFE_v2 import Client, ip_command, url_command, cve_get_command, \
    cve_search_command, file_command, whois_command
from CommonServerPython import outputPaths

DBOT_SCORE_KEY = 'DBotScore(val.Indicator == obj.Indicator && val.Vendor == obj.Vendor)'

MOCK_BASE_URL = 'https://www.this-is-a-fake-url.com'
MOCK_API_KEY = 'FAKE-API-KEY'
MOCK_PASSWORD = 'FAKE-PASSWORD'

MOCK_IP = '8.8.8.8'
MOCK_URL = 'https://www.google.com'
MOCK_CVE = 'CVE-2014-2601'
MOCK_HASH = '474B9CCF5AB9D72CA8A333889BBB34F0'
MOCK_HASH_NO_FAMILY = '55d2ad612f36aebf2184f138d37ba1a16b774627fbbafd737425731369efd010'
MOCK_HOST = 'google.com'
MOCK_CVE_QUERY = 'hello'

MOCK_IP_RESP = {
    "ip": "8.8.8.8",
    "history": [
        {
            "created": "2012-03-22T07:26:00.000Z",
            "reason": "Regional Internet Registry",
            "geo": {
                "country": "United States",
                "countrycode": "US"
            },
            "ip": "8.0.0.0/8",
            "categoryDescriptions": {},
            "reasonDescription": "One of the five RIRs announced a (new) location mapping of the IP.",
            "score": 1,
            "cats": {}
        }],
    "subnets": [
        {
            "created": "2018-04-24T06:22:00.000Z",
            "reason": "Regional Internet Registry",
            "reason_removed": True,
            "asns": {
                "3356": {
                    "removed": True,
                    "cidr": 8
                }
            },
            "ip": "8.0.0.0",
            "categoryDescriptions": {},
            "reasonDescription": "One of the five RIRs announced a (new) location mapping of the IP.",
            "score": 1,
            "cats": {},
            "subnet": "8.0.0.0/8"
        }
    ],
    "cats": {},
    "geo": {
        "country": "United States",
        "countrycode": "US"
    },
    "DBotScore(val.Indicator == obj.Indicator && val.Vendor == obj.Vendor)": {
        "Indicator": "8.8.8.8",
        "Type": "ip",
        "Vendor": "XFE",
        "Score": 1,
        "Reliability": "C - Fairly reliable"
    },
    "score": 1,
    "reason": "Regional Internet Registry",
    "reasonDescription": "One of the five RIRs announced a (new) location mapping of the IP.",
    "categoryDescriptions": {},
    "tags": []
}
MOCK_INVALID_IP_RESP = {
    'ip': '8.8.8.8',
    'history': [],
    'subnets': [],
    'cats': {},
    'score': 1,
    'tags': []
}

MOCK_URL_RESP = {
    "result": {
        "url": "https://www.google.com",
        "cats": {
            "Search Engines / Web Catalogs / Portals": True
        },
        "score": 1,
        "categoryDescriptions": {
            "Search Engines / Web Catalogs / Portals": "This category contains search engines."
        }
    },
    "associated": [
        {
            "url": "google.com",
            "cats": {
                "Search Engines / Web Catalogs / Portals": True
            },
            "score": 1,
            "categoryDescriptions": {
                "Search Engines / Web Catalogs / Portals": "This category contains search engines,"
            }
        },
        {
            "url": "www.google.com",
            "cats": {
                "Search Engines / Web Catalogs / Portals": True
            },
            "score": 1,
            "categoryDescriptions": {
                "Search Engines / Web Catalogs / Portals": "This category contains search engines,"
            }
        }
    ],
    "DBotScore(val.Indicator == obj.Indicator && val.Vendor == obj.Vendor)": {
        "Indicator": "https://www.google.com",
        "Type": "url",
        "Vendor": "XFE",
        "Score": 1,
        "Reliability": "C - Fairly reliable"
    },
    "tags": []
}

MOCK_CVE_RESP = [
    {
        "type": "vulnerability",
        "xfdbid": 92744,
        "updateid": 0,
        "variant": "single",
        "title": "HP Integrated Lights-Out 2 Heartbleed denial of service",
        "description": "HP Integrated Lights-Out 2 (iLO 2) is vulnerable to a denial of service,",
        "risk_level": 7.8,
        "cvss": {
            "version": "2.0",
            "authentication": "None",
            "access_vector": "Network",
            "access_complexity": "Low",
            "confidentiality_impact": "None",
            "integrity_impact": "None",
            "availability_impact": "Complete",
            "remediation_level": "Official Fix"
        },
        "temporal_score": 5.8,
        "remedy": "Refer to HPSBHF03006 for patch, upgrade or suggested workaround information. See References.",
        "remedy_fmt": "<P>Refer to HPSBHF03006 for patch, upgrade or suggested workaround information.</P>",
        "reported": "2014-04-24T00:00:00Z",
        "tagname": "hp-ilo-cve20142601-dos",
        "stdcode": [
            "BID-67054",
            "SA58224",
            "CVE-2014-2601"
        ],
        "platforms_affected": [
            "HP Integrated Lights-Out 2 (iLO2) 2.23"
        ],
        "exploitability": "Unproven",
        "consequences": "Denial of Service",
        "references": [
            {
                "link_target": "https://h20564.www2.hp.com",
                "link_name": "HPSBHF03006",
                "description": "HP Integrated Lights-Out 2 (iLO 2) Denial of Service"
            },
            {
                "link_target": "http://www.securityfocus.com/bid/67054",
                "link_name": "BID-67054",
                "description": "HP Integrated Lights-Out CVE-2014-2601 Remote Denial of Service Vulnerability"
            },
            {
                "link_target": "http://secunia.com/advisories/58224",
                "link_name": "SA58224",
                "description": "HP Integrated Lights-Out 2 Denial of Service Vulnerability"
            },
            {
                "link_target": "http://cve.mitre.org",
                "link_name": "CVE-2014-2601",
                "description": "The server in HP Integrated Lights-Out 2"
            }
        ],
        "report_confidence": "Confirmed",
        "uuid": "7d71d8e3856c692cb73c4b7daf1c21ce"
    }
]

MOCK_RECENT_CVE_RESP = [
    {
        "type": "vulnerability",
        "xfdbid": 174800,
        "updateid": 83006,
        "inserted": True,
        "variant": "single",
        "title": "Resim Ara plugin for WordPress cross-site scripting",
        "description": "Resim Ara plugin for WordPress is vulnerable to cross-site scripting,",
        "risk_level": 6.1,
        "cvss": {
            "version": "3.0",
            "privilegesrequired": "None",
            "userinteraction": "Required",
            "scope": "Changed",
            "access_vector": "Network",
            "access_complexity": "Low",
            "confidentiality_impact": "Low",
            "integrity_impact": "Low",
            "availability_impact": "None",
            "remediation_level": "Unavailable"
        },
        "temporal_score": 5.9,
        "remedy": "No remedy available as of January 20, 2020.",
        "remedy_fmt": "<P>No remedy available as of January 20, 2020.</P>",
        "reported": "2020-01-16T00:00:00Z",
        "tagname": "resimara-unknown-xss",
        "platforms_affected": [
            "WordPress Resim Ara plugin for WordPress 1.0"
        ],
        "platforms_dependent": [
            "WordPress WordPress"
        ],
        "exploitability": "High",
        "consequences": "Cross-Site Scripting",
        "references": [
            {
                "link_target": "https://packetstormsecurity.com/files/155980",
                "link_name": "Packet Storm Security [01-16-2020]",
                "description": "WordPress Resim ara 1.0 Cross Site Scripting"
            },
            {
                "link_target": "https://wordpress.org/plugins/resim-ara/",
                "link_name": "WordPress Plugin Directory",
                "description": "resim-ara"
            }
        ],
        "signatures": [
            {
                "coverage": "Cross_Site_Scripting",
                "coverage_date": "2008-11-11T00:00:00Z"
            }
        ],
        "report_confidence": "Reasonable"
    }
]

MOCK_HASH_RESP = {
    "malware": {
        "origins": {
            "emails": {

            },
            "CnCServers": {
                "rows": [
                    {
                        "type": "CnC",
                        "md5": "474B9CCF5AB9D72CA8A333889BBB34F0",
                        "domain": "pc-guard.net",
                        "firstseen": "2014-10-20T23:19:00Z",
                        "lastseen": "2014-10-20T23:19:00Z",
                        "ip": "61.255.239.86",
                        "count": 483,
                        "schema": "http",
                        "filepath": "v.html",
                        "origin": "CnC",
                        "uri": "http://pc-guard.net/v.html"
                    }
                ],
                "count": 1
            },
            "downloadServers": {

            },
            "subjects": {

            },
            "external": {
                "source": "reversingLabs",
                "firstSeen": "2014-12-09T06:10:00Z",
                "lastSeen": "2018-12-16T20:55:00Z",
                "malwareType": "Trojan",
                "platform": "Win32",
                "detectionCoverage": 43,
                "family": [
                    "badur"
                ]
            }
        },
        "type": "md5",
        "md5": "0x474B9CCF5AB9D72CA8A333889BBB34F0",
        "hash": "0x474B9CCF5AB9D72CA8A333889BBB34F0",
        "created": "2014-10-20T23:19:00Z",
        "family": [
            "tsunami"
        ],
        "familyMembers": {
            "tsunami": {
                "count": 61
            }
        },
        "risk": "high"
    },
    "tags": [

    ]
}

HASH_RESP_NO_FAMILY = {
    'malware': {
        'origins': {
            'external': {
                'source': 'reversingLabs',
                'firstSeen': '2021-08-02T21:59:46Z',
                'lastSeen': '2021-08-16T04:35:50Z',
                'detectionCoverage': 0,
                'family': None
            }
        },
        'type': 'sha256',
        'sha256': '0x55D2AD612F36AEBF2184F138D37BA1A16B774627FBBAFD737425731369EFD010',
        'hash': '0x55D2AD612F36AEBF2184F138D37BA1A16B774627FBBAFD737425731369EFD010',
        'risk': 'low'
    }
}

MOCK_HOST_RESP = {
    "createdDate": "1997-09-15T07:00:00.000Z",
    "updatedDate": "2019-09-09T15:39:04.000Z",
    "expiresDate": "2028-09-13T07:00:00.000Z",
    "contactEmail": "abusecomplaints@markmonitor.com",
    "registrarName": "MarkMonitor, Inc.",
    "contact": [
        {
            "type": "registrant",
            "organization": "Google LLC",
            "country": "United States"
        }
    ],
    "extended": {
        "createdDate": "1997-09-15T07:00:00.000Z",
        "updatedDate": "2019-09-09T15:39:04.000Z",
        "expiresDate": "2028-09-13T07:00:00.000Z",
        "contactEmail": "abusecomplaints@markmonitor.com",
        "registrarName": "MarkMonitor, Inc.",
        "contact": [
            {
                "type": "registrant",
                "organization": "Google LLC",
                "country": "United States"
            }
        ]
    }
}

MOCK_CVE_SEARCH_RESP = {'total_rows': 1,
                        'bookmark': 'g1AAAAMHeJzLYWBg4MhgTmFQTUlKzi9KdUhJstDLTMrVrUjLL0pONTAw1EvOyS9NScwr0ctLLckBKmdKZ',
                        'rows': [{'type': 'vulnerability',
                                  'xfdbid': 161573,
                                  'updateid': 66943,
                                  'inserted': True,
                                  'variant': 'single',
                                  'title': 'wolfSSL DoPreSharedKeys function buffer overflow',
                                  'description': 'wolfSSL is vulnerable to a buffer overflow.',
                                  'risk_level': 9.8,
                                  'cvss': {'version': '3.0',
                                           'privilegesrequired': 'None',
                                           'userinteraction': 'None',
                                           'scope': 'Unchanged',
                                           'access_vector': 'Network',
                                           'access_complexity': 'Low',
                                           'confidentiality_impact': 'High',
                                           'integrity_impact': 'High',
                                           'availability_impact': 'High',
                                           'remediation_level': 'Official Fix'},
                                  'temporal_score': 8.5,
                                  'remedy': 'Refer to wolfssl GIT Repository for patch.',
                                  'remedy_fmt': 'Refer to wolfssl GIT Repository for patch',
                                  'reported': '2019-05-15T00:00:00Z',
                                  'tagname': 'wolfssl-cve201911873-bo',
                                  'stdcode': ['CVE-2019-11873'],
                                  'platforms_affected': ['wolfSSL wolfSSL 4.0.0'],
                                  'exploitability': 'Unproven',
                                  'consequences': 'Gain Access',
                                  'references': [{
                                      'link_target': 'https://www.telekom.com/en/corporate-responsibility',
                                      'link_name': 'Telekom Web site',
                                      'description': 'Critical remote buffer overflow vulnerability in wolfSSL library'},
                                      {'link_target': 'https://github.com/wolfSSL/wolfssl/pull/2239',
                                       'link_name': 'wolfssl GIT Repository',
                                       'description': 'add sanity check on length of PSK identity #2239'},
                                      {'link_target': '',
                                       'link_name': 'CVE-2019-11873',
                                       'description': 'wolfSSL 4.0.0 has a Buffer Overflow.'}],
                                  'report_confidence': 'Confirmed'}]}


def test_ip(requests_mock):
    """
    Given: Arguments for ip command

    When: The server response is complete

    Then: validates the outputs

    """
    requests_mock.get(f'{MOCK_BASE_URL}/ipr/{MOCK_IP}', json=MOCK_IP_RESP)

    client = Client(MOCK_BASE_URL, MOCK_API_KEY, MOCK_PASSWORD, True, False)
    args = {
        'ip': MOCK_IP
    }
    _, outputs, _ = ip_command(client, args)

    assert outputs[outputPaths['ip']][0]['Address'] == MOCK_IP
    assert outputs[DBOT_SCORE_KEY][0] == MOCK_IP_RESP[DBOT_SCORE_KEY]


def test_ip_with_invalid_resp(requests_mock):
    """
    Given: Arguments for ip command

    When: The server response is not complete and some data fields are empty

    Then: validates the outputs

    """
    requests_mock.get(f'{MOCK_BASE_URL}/ipr/{MOCK_IP}', json=MOCK_INVALID_IP_RESP)

    client = Client(MOCK_BASE_URL, MOCK_API_KEY, MOCK_PASSWORD, True, False)
    args = {
        'ip': MOCK_IP
    }
    md, outputs, reports = ip_command(client, args)

    assert outputs[outputPaths['ip']][0]['Address'] == MOCK_IP
    assert reports[0] == {'ip': '8.8.8.8', 'history': [], 'subnets': [], 'cats': {}, 'score': 1, 'tags': []}
    assert md == """### X-Force IP Reputation for: 8.8.8.8
https://exchange.xforce.ibmcloud.com/ip/8.8.8.8
|Reason|Score|
|---|---|
| Reason not found. | 1 |
"""


def test_url(requests_mock):
    requests_mock.get(f'{MOCK_BASE_URL}/url/{MOCK_URL}', json=MOCK_URL_RESP)

    client = Client(MOCK_BASE_URL, MOCK_API_KEY, MOCK_PASSWORD, True, False)
    args = {
        'url': MOCK_URL
    }
    result = url_command(client, args)

    assert result[0].indicator.url == MOCK_URL
    assert result[0].indicator.dbot_score.indicator == MOCK_URL_RESP[DBOT_SCORE_KEY]['Indicator']
    assert result[0].indicator.dbot_score.score == MOCK_URL_RESP[DBOT_SCORE_KEY]['Score']
    assert result[0].indicator.dbot_score.reliability == MOCK_URL_RESP[DBOT_SCORE_KEY]['Reliability']


def test_get_cve(requests_mock):
    requests_mock.get(f'{MOCK_BASE_URL}/vulnerabilities/search/{MOCK_CVE}', json=MOCK_CVE_RESP)

    client = Client(MOCK_BASE_URL, MOCK_API_KEY, MOCK_PASSWORD, True, False)
    args = {
        'cve_id': MOCK_CVE
    }
    _, outputs, _ = cve_get_command(client, args)

    assert outputs[outputPaths['cve']][0]['ID'] == MOCK_CVE
    assert outputs[DBOT_SCORE_KEY][0]['Indicator'] == MOCK_CVE, 'The indicator is not matched'
    assert outputs[DBOT_SCORE_KEY][0]['Type'] == 'cve', 'The indicator type should be cve'
    assert 1 <= outputs[DBOT_SCORE_KEY][0]['Score'] <= 3, 'Invalid indicator score range'
    assert outputs[DBOT_SCORE_KEY][0]['Reliability'] == 'C - Fairly reliable'


def test_cve_latest(requests_mock):
    requests_mock.get(f'{MOCK_BASE_URL}/vulnerabilities', json=MOCK_RECENT_CVE_RESP)

    client = Client(MOCK_BASE_URL, MOCK_API_KEY, MOCK_PASSWORD, True, False)
    _, outputs, _ = cve_search_command(client, {})
    assert len(outputs[outputPaths['cve']]) == 1, 'CVE output length should be 1'


def test_file(requests_mock):
    """
     Given:
         - A hash.
     When:
         - When running the file command.
     Then:
         - Validate that the file outputs are created properly
         - Validate that the DbotScore outputs are created properly
     """
    dbot_score_key = 'DBotScore(val.Indicator && val.Indicator == obj.Indicator &&' \
                     ' val.Vendor == obj.Vendor && val.Type == obj.Type)'
    requests_mock.get(f'{MOCK_BASE_URL}/malware/{MOCK_HASH}', json=MOCK_HASH_RESP)

    client = Client(MOCK_BASE_URL, MOCK_API_KEY, MOCK_PASSWORD, True, False)
    outputs = file_command(client, {'file': MOCK_HASH})[0].to_context()['EntryContext']
    file_key = next(filter(lambda k: 'File' in k, outputs.keys()), 'File')

    assert outputs[file_key][0].get('MD5', '') == MOCK_HASH, 'The indicator value is wrong'
    assert outputs[dbot_score_key][0]['Indicator'] == MOCK_HASH, 'The indicator is not matched'
    assert outputs[dbot_score_key][0]['Type'] == 'file', 'The indicator type should be file'
    assert 1 <= outputs[dbot_score_key][0]['Score'] <= 3, 'Invalid indicator score range'


def test_file__no_family(requests_mock):
    """
    Given:
        - Hash with results that have family set to None

    When:
        - Running the file commandd

    Then:
        - Ensure the Relationships object is empty
    """
    requests_mock.get(f'{MOCK_BASE_URL}/malware/{MOCK_HASH_NO_FAMILY}', json=HASH_RESP_NO_FAMILY)

    client = Client(MOCK_BASE_URL, MOCK_API_KEY, MOCK_PASSWORD, True, False)
    outputs = file_command(client, {'file': MOCK_HASH_NO_FAMILY})[0].to_context()
    assert not outputs['Relationships']


def test_file_connections(requests_mock):
    """
     Given:
         - A hash.
     When:
         - When running the file command.
     Then:
         - Validate that the relationships are crated correctly
     """
    requests_mock.get(f'{MOCK_BASE_URL}/malware/{MOCK_HASH}', json=MOCK_HASH_RESP)

    client = Client(MOCK_BASE_URL, MOCK_API_KEY, MOCK_PASSWORD, True, False)
    relations = file_command(client, {'file': MOCK_HASH})[0].relationships[0].to_context()
    assert relations.get('Relationship') == 'related-to'
    assert relations.get('EntityA') == MOCK_HASH
    assert relations.get('EntityAType') == 'File'
    assert relations.get('EntityB') == 'badur'
    assert relations.get('EntityBType') == 'STIX Malware'


def test_whois(requests_mock):
    requests_mock.get(f'{MOCK_BASE_URL}/whois/{MOCK_HOST}', json=MOCK_HOST_RESP)

    client = Client(MOCK_BASE_URL, MOCK_API_KEY, MOCK_PASSWORD, True, False)
    _, outputs, _ = whois_command(client, {'host': MOCK_HOST})

    whois_result = outputs['XFE.Whois(obj.Host==val.Host)']

    assert whois_result['Host'] == MOCK_HOST, 'The host from output is different'
    assert isinstance(whois_result['Contact'], list), 'Contact information should be list'


def test_cve_search(requests_mock):
    requests_mock.get(f'{MOCK_BASE_URL}/vulnerabilities/fulltext?q={MOCK_CVE_QUERY}', json=MOCK_CVE_SEARCH_RESP)

    client = Client(MOCK_BASE_URL, MOCK_API_KEY, MOCK_PASSWORD, True, False)
    _, outputs, _ = cve_search_command(client, {'q': MOCK_CVE_QUERY})

    assert outputs['XFE.CVESearch']['TotalRows'] == len(outputs[outputPaths['cve']]), 'Mismatch rows and outputs'
