from XForceExchange import Client, ip_command, url_command, cve_search_command, cve_latest_command

MOCK_BASE_URL = 'https://www.this-is-a-fake-url.com'
MOCK_API_KEY = 'FAKE-API-KEY'
MOCK_PASSWORD = 'FAKE-PASSWORD'

MOCK_IP = '8.8.8.8'
MOCK_URL = 'https://www.google.com'
MOCK_CVE = 'CVE-2014-2601'

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
    "score": 1,
    "reason": "Regional Internet Registry",
    "reasonDescription": "One of the five RIRs announced a (new) location mapping of the IP.",
    "categoryDescriptions": {},
    "tags": []
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
                "link_target": "https://h20564.www2.hp.com/portal/site/hpsc/public/kb/docDisplay?docId=emr_na-c04244787",
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
                "link_target": "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-2601",
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


def test_ip(requests_mock):
    requests_mock.get(MOCK_BASE_URL + f'/ipr/{MOCK_IP}', json=MOCK_IP_RESP)

    client = Client(MOCK_BASE_URL, MOCK_API_KEY, MOCK_PASSWORD, True, False)
    args = {
        'ip': MOCK_IP
    }
    _, outputs, _ = ip_command(client, args)
    assert outputs['IP(obj.Address==val.Address)']['Address'] == MOCK_IP


def test_url(requests_mock):
    requests_mock.get(MOCK_BASE_URL + f'/url/{MOCK_URL}', json=MOCK_URL_RESP)

    client = Client(MOCK_BASE_URL, MOCK_API_KEY, MOCK_PASSWORD, True, False)
    args = {
        'url': MOCK_URL
    }
    _, outputs, _ = url_command(client, args)
    assert outputs['URL(obj.Data==val.Data)']['Data'] == MOCK_URL


def test_cve_search(requests_mock):
    requests_mock.get(MOCK_BASE_URL + f'/vulnerabilities/search/{MOCK_CVE}', json=MOCK_CVE_RESP)

    client = Client(MOCK_BASE_URL, MOCK_API_KEY, MOCK_PASSWORD, True, False)
    args = {
        'cve_id': MOCK_CVE
    }
    _, outputs, _ = cve_search_command(client, args)
    assert outputs['CVE(obj.ID==val.ID)']['ID'] == MOCK_CVE


def test_cve_latest(requests_mock):
    requests_mock.get(MOCK_BASE_URL + f'/vulnerabilities', json=MOCK_RECENT_CVE_RESP)

    client = Client(MOCK_BASE_URL, MOCK_API_KEY, MOCK_PASSWORD, True, False)
    _, outputs, _ = cve_latest_command(client, {})
