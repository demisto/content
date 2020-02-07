from Expanse import main, parse_response
import demistomock as demisto
import json

TEST_IP = "74.142.119.130"
TEST_API_KEY = "123456789123456789"
TEST_DOMAIN = "atlas.enron.com"


def http_request_mock(method, endpoint, params=None, token=False):
    ''' make api call '''

    if endpoint == 'IdToken':
        r = MOCK_TOKEN_RESPONSE

    elif endpoint == 'assets/domains':
        r = MOCK_DOMAIN_RESPONSE

    elif endpoint == 'ip-range':
        r = MOCK_IP_RESPONSE

    elif endpoint == 'events':
        r = MOCK_EVENTS

    return parse_response(r)


def test_fetch_incidents(mocker, requests_mock):
    mocker.patch.object(demisto, 'params', return_value={'api_key': TEST_API_KEY})
    mocker.patch('Expanse.http_request', side_effect=http_request_mock)
    mocker.patch.object(demisto, 'command', return_value='fetch-incidents')
    mocker.patch.object(demisto, 'results')
    main()
    results = demisto.results.call_args[0]
    r = json.loads(results[0]['Contents'])
    # print(r[0])
    assert r[0]['name'] == "NTP_SERVER on 203.215.173.113:123/UDP"
    assert r[0]['severity'] == 1


def test_ip(mocker, requests_mock):
    mocker.patch.object(demisto, 'params', return_value={'api_key': TEST_API_KEY})
    mocker.patch.object(demisto, 'args', return_value={'ip': TEST_IP})
    mocker.patch('Expanse.http_request', side_effect=http_request_mock)
    mocker.patch.object(demisto, 'command', return_value='ip')
    mocker.patch.object(demisto, 'results')
    main()
    results = demisto.results.call_args[0]
    assert results[0]['Contents']['search'] == TEST_IP
    assert results[0]['EntryContext']['DBotScore']['Type'] == 'ip'
    assert results[0]['EntryContext']['IP(val.Address == obj.Address)']['Address'] == TEST_IP


def test_domain(mocker, requests_mock):
    mocker.patch.object(demisto, 'args', return_value={'domain': TEST_DOMAIN})
    mocker.patch('Expanse.http_request', side_effect=http_request_mock)
    mocker.patch.object(demisto, 'command', return_value='domain')
    mocker.patch.object(demisto, 'results')
    main()
    results = demisto.results.call_args[0]
    assert results[0]['Contents']['domain'] == TEST_DOMAIN
    assert results[0]['EntryContext']['DBotScore']['Type'] == 'url'
    assert results[0]['EntryContext']['Domain(val.Name == obj.Name)']['Name'] == TEST_DOMAIN


MOCK_TOKEN_RESPONSE = {
    'token': '123456789abcdefg'
}
MOCK_IP_RESPONSE = {
    "data": [
        {
            "id": "b0f025ab-5e6c-4300-a68e-bd127d97e201",
            "created": "2019-08-02",
            "modified": "2019-09-04",
            "ipVersion": "4",
            "startAddress": "74.142.119.128",
            "endAddress": "74.142.119.135",
            "businessUnits": [
                {
                    "id": "6b73ef6c-b230-3797-b321-c4a340169eb7",
                    "name": "Acme Latex Supply"
                }
            ],
            "annotations": {
                "tags": [],
                "additionalNotes": "",
                "pointsOfContact": []
            },
            "severityCounts": [
                {
                    "type": "CRITICAL",
                    "count": 2
                },
                {
                    "type": "ROUTINE",
                    "count": 2
                },
                {
                    "type": "WARNING",
                    "count": 4
                }
            ],
            "attributionReasons": [
                {
                    "reason": "This parent range is attributed via IP network registration ..."
                }
            ],
            "relatedRegistrationInformation": [
                {
                    "handle": "NET-74-142-119-128-1",
                    "startAddress": "74.142.119.128",
                    "endAddress": "74.142.119.135",
                    "ipVersion": "4",
                    "country": "None",
                    "name": "NET-74-142-119-128-1",
                    "parentHandle": "NET-74-142-0-0-1",
                    "whoisServer": "whois.arin.net",
                    "updatedDate": "2019-08-02",
                    "remarks": "",
                    "registryEntities": [
                        {
                            "id": "0165fc31-502d-3a77-8a47-2f2520888a60",
                            "handle": "CC-3517",
                            "address": "6399 S. Fiddler's Green Circle\nGreenwood Village\nCO\n80111\nUnited States          ",
                            "email": "",
                            "events": [
                                {
                                    "action": "last changed",
                                    "actor": False,
                                    "date": "2018-11-27T15:23:50-05:00",
                                    "links": "[]"
                                },
                                {
                                    "action": "registration",
                                    "actor": False,
                                    "date": "2018-10-10T11:22:33-04:00",
                                    "links": "[]"
                                }
                            ],
                            "firstRegistered": False,
                            "formattedName": "Charter Communications Inc",
                            "lastChanged": False,
                            "org": "",
                            "phone": "",
                            "remarks": "Legacy Time Warner Cable IP Assets",
                            "statuses": "",
                            "relatedEntityHandles": [
                                "IPADD1-ARIN",
                                "ABUSE10-ARIN"
                            ],
                            "roles": [
                                "registrant"
                            ]
                        },
                        {
                            "id": "33c2c1bb-43e0-3a8d-94e6-81f800aa1786",
                            "handle": "IPADD1-ARIN",
                            "address": "6399 S Fiddlers Green Circle\nGreenwood Village\nCO\n80111\nUnited States",
                            "email": "ipaddressing@chartercom.com",
                            "events": [
                                {
                                    "action": "last changed",
                                    "actor": False,
                                    "date": "2018-10-10T13:09:53-04:00",
                                    "links": "[]"
                                },
                                {
                                    "action": "registration",
                                    "actor": False,
                                    "date": "2002-09-10T11:10:50-04:00",
                                    "links": "[]"
                                }
                            ],
                            "firstRegistered": False,
                            "formattedName": "IPAddressing",
                            "lastChanged": False,
                            "org": "IPAddressing",
                            "phone": "+1-314-288-3111",
                            "remarks": "IP Addressing is used for corporate IP allocation and administration ...",
                            "statuses": "validated",
                            "relatedEntityHandles": [],
                            "roles": [
                                "technical",
                                "administrative"
                            ]
                        },
                        {
                            "id": "49e585f7-0e2b-30df-acb0-2a4c45f4654f",
                            "handle": "ABUSE10-ARIN",
                            "address": "13820 Sunrise Valley Drive\nHerndon\nVA\n20171\nUnited States          ",
                            "email": "abuse@rr.com",
                            "events": [
                                {
                                    "action": "last changed",
                                    "actor": False,
                                    "date": "2016-07-28T13:11:35-04:00",
                                    "links": "[]"
                                },
                                {
                                    "action": "registration",
                                    "actor": False,
                                    "date": "2002-08-25T14:28:44-04:00",
                                    "links": "[]"
                                }
                            ],
                            "firstRegistered": False,
                            "formattedName": "Abuse",
                            "lastChanged": False,
                            "org": "Abuse",
                            "phone": "+1-703-345-3416",
                            "remarks": "ARIN has attempted to validate the data ...",
                            "statuses": "",
                            "relatedEntityHandles": [],
                            "roles": [
                                "abuse"
                            ]
                        },
                        {
                            "id": "736dbbcf-977e-301a-8705-c6a9ebff83fe",
                            "handle": "C07162769",
                            "address": "2064 KILLIAN RD\nAKRON\nOH\n44312\nUnited States          ",
                            "email": "",
                            "events": [
                                {
                                    "action": "last changed",
                                    "actor": False,
                                    "date": "2018-10-25T21:53:06-04:00",
                                    "links": "[]"
                                },
                                {
                                    "action": "registration",
                                    "actor": False,
                                    "date": "2018-10-25T21:53:06-04:00",
                                    "links": "[]"
                                }
                            ],
                            "firstRegistered": False,
                            "formattedName": "KILLIAN LATEX, INC",
                            "lastChanged": False,
                            "org": "",
                            "phone": "",
                            "remarks": "",
                            "statuses": "",
                            "relatedEntityHandles": [
                                "CC-3517",
                                "IPADD1-ARIN",
                                "ABUSE10-ARIN"
                            ],
                            "roles": [
                                "registrant"
                            ]
                        }
                    ]
                }
            ],
            "locationInformation": [
                {
                    "ip": "74.142.119.130",
                    "geolocation": {
                        "latitude": 41.0433,
                        "longitude": -81.5239,
                        "city": "AKRON",
                        "regionCode": "OH",
                        "countryCode": "US"
                    }
                }
            ],
            "rangeSize": 8,
            "responsiveIpCount": 1,
            "rangeIntroduced": "2019-08-02",
            "customChildRanges": []
        }
    ],
    "pagination": {
        "next": False,
        "prev": False
    },
    "meta": {
        "totalCount": 1
    }
}

MOCK_DOMAIN_RESPONSE = {
    "data": [
        {
            'id': '74384207-e542-3c52-895f-68a1539defdd',
            'dateAdded': '2020-01-04T04:57:48.580Z',
            'domain': 'atlas.enron.com',
            'tenant': {
                'id': '04b5140e-bbe2-3e9c-9318-a39a3b547ed5',
                'name': 'VanDelay Industries',
                'tenantId': '04b5140e-bbe2-3e9c-9318-a39a3b547ed5'
            },
            'businessUnits': [
                {
                    'id': '04b5140e-bbe2-3e9c-9318-a39a3b547ed5',
                    'name': 'VanDelay Industries',
                    'tenantId': '04b5140e-bbe2-3e9c-9318-a39a3b547ed5'
                }
            ],
            'providers': [
                {
                    'id': 'Other',
                    'name': 'Other'
                }
            ],
            'firstObserved': '2020-01-02T09:30:00.374Z',
            'lastObserved': '2020-01-02T09:30:00.374Z',
            'hasLinkedCloudResources': False,
            'sourceDomain': 'enron.com',
            'whois': [
                {
                    'domain': 'enron.com',
                    'registryDomainId': None,
                    'updatedDate': '2015-07-29T16:20:56Z',
                    'creationDate': '1995-10-10T04:00:00Z',
                    'registryExpiryDate': '2019-10-10T04:00:00Z',
                    'reseller': None,
                    'registrar':
                        {
                            'name': 'GoDaddy.com, LLC',
                            'whoisServer': 'whois.godaddy.com',
                            'url': None,
                            'ianaId': None,
                            'registrationExpirationDate': None,
                            'abuseContactEmail': None,
                            'abuseContactPhone': None
                        },
                    'domainStatuses': [
                        'clientDeleteProhibited clientRenewProhibited clientTransferProhibited clientUpdateProhibited'],
                    'nameServers': ['NS73.DOMAINCONTROL.COM', 'NS74.DOMAINCONTROL.COM'],
                    'registrant': {
                        'name': 'Registration Private',
                        'organization': 'Domains By Proxy, LLC',
                        'street': 'DomainsByProxy.com|14455 N. Hayden Road',
                        'city': 'Scottsdale',
                        'province': 'Arizona',
                        'postalCode': '85260',
                        'country': 'UNITED STATES',
                        'phoneNumber': '14806242599',
                        'phoneExtension': '',
                        'faxNumber': '14806242598',
                        'faxExtension': '',
                        'emailAddress': 'ENRON.COM@domainsbyproxy.com',
                        'registryId': None},
                    'admin': {
                        'name': 'Registration Private',
                        'organization': 'Domains By Proxy, LLC',
                        'street': 'DomainsByProxy.com|14455 N. Hayden Road',
                        'city': 'Scottsdale',
                        'province': 'Arizona',
                        'postalCode': '85260',
                        'country': 'UNITED STATES',
                        'phoneNumber': '14806242599',
                        'phoneExtension': '',
                        'faxNumber': '14806242598',
                        'faxExtension': '',
                        'emailAddress': 'ENRON.COM@domainsbyproxy.com',
                        'registryId': None},
                    'tech': {
                        'name': None,
                        'organization': None,
                        'street': None,
                        'city': None,
                        'province': None,
                        'postalCode': None,
                        'country': None,
                        'phoneNumber': None,
                        'phoneExtension': None,
                        'faxNumber': None,
                        'faxExtension': None,
                        'emailAddress': None,
                        'registryId': None},
                    'dnssec': None
                }
            ],
            'isCollapsed': False,
            'lastSampledIp': '192.64.147.150',
            'details': {
                'recentIps': [],
                'cloudResources': []
            },
            'lastSubdomainMetadata': None,
            'dnsResolutionStatus': ['HAS_DNS_RESOLUTION'],
            'serviceStatus': ['NO_ACTIVE_SERVICE', 'NO_ACTIVE_CLOUD_SERVICE', 'NO_ACTIVE_ON_PREM_SERVICE']
        },
    ]
}
MOCK_EVENTS = {
    "meta": {
        "dataAvailable": True
    },
    "pagination": {
        "next": False
    },
    "data": [
        {
            'eventType': 'ON_PREM_EXPOSURE_APPEARANCE',
            'eventTime': '2020-02-05T00:00:00Z',
            'businessUnit': {
                'id': 'a1f0f39b-f358-3c8c-947b-926887871b88',
                'name': 'VanDelay Import-Export'
            },
            'payload': {
                '_type': 'ExposurePayload',
                'id': 'b0acfbc5-4d55-3fdb-9155-4927eab91218',
                'exposureType': 'NTP_SERVER',
                'ip': '203.215.173.113',
                'port': 123,
                'portProtocol': 'UDP',
                'exposureId': '6bedf636-5b6a-3b47-82a5-92b511c0649b',
                'domainName': None,
                'scanned': '2020-02-05T00:00:00Z',
                'geolocation': {
                    'latitude': 33.7,
                    'longitude': 73.17,
                    'city': 'ISLAMABAD',
                    'regionCode': '',
                    'countryCode':
                        'PK'
                },
                'configuration': {
                    '_type': 'NtpServerConfiguration',
                    'response': {
                        'ntp': {
                            'leapIndicator': 0,
                            'mode': 4,
                            'poll': 4,
                            'precision': -19,
                            'stratum': 5,
                            'delay': 0,
                            'dispersion': 22,
                            'version': 4,
                            'originateTime': '2004-11-24T15:12:11.444Z',
                            'receiveTime': '2020-02-05T14:25:08.963Z',
                            'updateTime': '2020-02-05T14:25:01.597Z',
                            'transmitTime': '2020-02-05T14:25:08.963Z',
                            'reference': {
                                'ref_ip': {
                                    'reference': {
                                        'ipv4': '127.127.1.1'
                                    }
                                }
                            },
                            'extentionData': None,
                            'keyIdentifier': None,
                            'messageDigest': None
                        }
                    }
                },
                'severity': 'ROUTINE',
                'tags': {
                    'ipRange': ['untagged']
                },
                'providers': ['InternallyHosted'],
                'certificatePem': None,
                'remediationStatuses': []
            },
            'id': 'b4a1e2e6-165a-31a5-9e6a-af286adc3dcd'
        }

    ]
}
