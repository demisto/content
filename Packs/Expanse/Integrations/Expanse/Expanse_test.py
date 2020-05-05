from Expanse import main
import demistomock as demisto
import json

TEST_IP = "74.142.119.130"
TEST_API_KEY = "123456789123456789"
TEST_DOMAIN = "base2.pets.com"


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

    elif endpoint == 'behavior/risky-flows':
        r = MOCK_BEHAVIOR

    elif endpoint == 'assets/certificates':
        r = MOCK_CERTIFICATE_RESPONSE

    return r


def http_request_mock_missing(method, endpoint, params=None, token=False):
    if endpoint == 'ip-range':
        r = MOCK_IP_EMPTY_RESPONSE
    return r


def test_fetch_incidents(mocker):
    mocker.patch.object(demisto, 'params', return_value={
        'api_key': TEST_API_KEY,
        'first_run': '7'
    })
    mocker.patch('Expanse.http_request', side_effect=http_request_mock)
    mocker.patch.object(demisto, 'command', return_value='fetch-incidents')
    mocker.patch.object(demisto, 'results')
    main()
    results = demisto.results.call_args[0]
    r = json.loads(results[0]['Contents'])
    assert r[0]['name'] == "NTP_SERVER on 203.215.173.113:123/UDP"
    assert r[0]['severity'] == 1


def test_fetch_incidents_with_behavior(mocker):
    mocker.patch.object(demisto, 'params', return_value={
        'api_key': TEST_API_KEY,
        'first_run': '7',
        'behavior': True
    })
    mocker.patch('Expanse.http_request', side_effect=http_request_mock)
    mocker.patch.object(demisto, 'command', return_value='fetch-incidents')
    mocker.patch.object(demisto, 'results')
    main()
    results = demisto.results.call_args[0]
    r = json.loads(results[0]['Contents'])
    assert r[0]['name'] == "NTP_SERVER on 203.215.173.113:123/UDP"
    assert r[0]['severity'] == 1


def test_ip(mocker):
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
    assert results[0]['EntryContext']['IP(val.Address == obj.Address)']['Geo']['Location'] == "41.0433:-81.5239"


def test_ip_missing_values(mocker):
    mocker.patch.object(demisto, 'params', return_value={'api_key': TEST_API_KEY})
    mocker.patch.object(demisto, 'args', return_value={'ip': TEST_IP})
    mocker.patch('Expanse.http_request', side_effect=http_request_mock_missing)
    mocker.patch.object(demisto, 'command', return_value='ip')
    mocker.patch.object(demisto, 'results')
    main()
    results = demisto.results.call_args[0]
    assert results[0]['EntryContext']['IP(val.Address == obj.Address)']['Geo'].get('Location') is None


def test_domain(mocker):
    mocker.patch.object(demisto, 'args', return_value={'domain': TEST_DOMAIN})
    mocker.patch('Expanse.http_request', side_effect=http_request_mock)
    mocker.patch.object(demisto, 'command', return_value='domain')
    mocker.patch.object(demisto, 'results')
    main()
    results = demisto.results.call_args[0]
    assert results[0]['Contents']['domain'] == TEST_DOMAIN
    assert results[0]['EntryContext']['DBotScore']['Type'] == 'url'
    assert results[0]['EntryContext']['Domain(val.Name == obj.Name)']['Name'] == TEST_DOMAIN


def test_certificate(mocker):
    mocker.patch.object(demisto, 'args', return_value={'common_name': TEST_DOMAIN})
    mocker.patch('Expanse.http_request', side_effect=http_request_mock)
    mocker.patch.object(demisto, 'command', return_value='expanse-get-certificate')
    mocker.patch.object(demisto, 'results')
    main()
    results = demisto.results.call_args[0]
    assert results[0]['EntryContext']['Expanse.Certificate(val.SearchTerm == obj.SearchTerm)']['CommonName'] == TEST_DOMAIN


def test_behavior(mocker):
    mocker.patch.object(demisto, 'args', return_value={'ip': TEST_IP, 'start_time': '2020-03-28T00:00:00.000Z'})
    mocker.patch('Expanse.http_request', side_effect=http_request_mock)
    mocker.patch.object(demisto, 'command', return_value='expanse-get-behavior')
    mocker.patch.object(demisto, 'results')
    main()
    results = demisto.results.call_args[0]
    assert results[0]['EntryContext']['Expanse.Behavior(val.SearchTerm == obj.SearchTerm)']['SearchTerm'] == TEST_IP
    assert results[0]['EntryContext']['Expanse.Behavior(val.SearchTerm == obj.SearchTerm)']['ExternalAddresses'] \
        == '169.255.204.27'


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
MOCK_IP_EMPTY_RESPONSE = {
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
            'domain': 'base2.pets.com',
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
MOCK_BEHAVIOR = {
    "meta": {
        "totalCount": 1
    },
    "pagination": {
        "next": False
    },
    "data": [
        {
            "id": "705092a5-d139-3e48-bbad-42539cc14304",
            "tenantBusinessUnitId": "04b5140e-bbe2-3e9c-9318-a39a3b547ed5",
            "businessUnit": {
                "id": "6b73ef6c-b230-3797-b321-c4a340169eb7",
                "name": "Acme Latex Supply"
            },
            "riskRule": {
                "id": "02b6c647-65f4-4b69-b4b0-64af34fd1b29",
                "name": "Connections to and from Blacklisted Countries",
                "description": "Connections to and from Blacklisted Countries \
                (Belarus, Côte d'Ivoire, Cuba, Democratic Republic of the Congo, \
                    Iran, Iraq, Liberia, North Korea, South Sudan, Sudan, Syria, Zimbabwe)",
                "additionalDataFields": "[]"
            },
            "internalAddress": "74.142.119.130",
            "internalPort": 443,
            "externalAddress": "169.255.204.27",
            "externalPort": 43624,
            "flowDirection": "INBOUND",
            "acked": True,
            "protocol": "TCP",
            "externalCountryCodes": [
                "CD"
            ],
            "internalCountryCodes": [
                "CN"
            ],
            "externalCountryCode": "CD",
            "internalCountryCode": "CN",
            "internalExposureTypes": [
                "HttpServer"
            ],
            "internalDomains": [
                "base2.pets.com"
            ],
            "internalTags": {
                "ipRange": []
            },
            "observationTimestamp": "2020-03-22T23:44:31.506Z",
            "created": "2020-03-23T02:28:00.336449Z"
        }
    ]
}
MOCK_CERTIFICATE_RESPONSE = {
    "data": [{
        "id": "1079d791-79f6-3122-a965-980471a244e8",
        "tenant": {
            "id": "04b5140e-bbe2-3e9c-9318-a39a3b547ed5",
            "name": "VanDelay Industries",
            "tenantId": "04b5140e-bbe2-3e9c-9318-a39a3b547ed5"
        },
        "businessUnits": [
            {
                "id": "04b5140e-bbe2-3e9c-9318-a39a3b547ed5",
                "name": "VanDelay Industries",
                "tenantId": "04b5140e-bbe2-3e9c-9318-a39a3b547ed5"
            }
        ],
        "dateAdded": "2019-11-21T09:15:02.271281Z",
        "firstObserved": None,
        "lastObserved": None,
        "providers": [
            {
                "id": "Unknown",
                "name": "None"
            }
        ],
        "certificate": {
            "md5Hash": "Jr8RiLR4OfFslz9VmELI9g==",
            "id": "26bf1188-b478-39f1-ac97-3f559842c8f6",
            "issuer": "C=GB,ST=Greater Manchester,L=Salford,O=COMODO CA Limited,CN=COMODO RSA \
            Organization Validation Secure Server CA",
            "issuerAlternativeNames": "",
            "issuerCountry": "GB",
            "issuerEmail": None,
            "issuerLocality": "Salford",
            "issuerName": "COMODO RSA Organization Validation Secure Server CA",
            "issuerOrg": "COMODO CA Limited",
            "issuerOrgUnit": None,
            "issuerState": "Greater Manchester",
            "publicKey": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0/zl9UD5ylG59/MtZpU0NWT3zrT5uRFUU2FgOoiZOZ9MklZqm+HHV+e3lTHrx+\
            5JlAccfS8lkVdvJIrOAGe9Py5S2Ir6rCUmJMrWCpmEXE5clrifMjg1PA4ueVlcYkNnNK5oHhGMa6WhVXQlA9YK2e9i4KMdqXA1WzPRpvgz32oARBSHv3KWl5W\
            JacbFj9seobIyGcqeyZEQaIJoE0tbLRi2qy0KShLf9+Uc7mQnNFwD8Y8Zqo96zE65c5+NctwKteYMs2XMFXtJ5sknALFrwbvsYZfUxXn/glgSU+v5jQUcyCNr\
            GcevhZHW3D9Ia2mymbfKfszUVMRl/Fpi3EmxHwIDAQAB",
            "publicKeyAlgorithm": "RSA",
            "publicKeyRsaExponent": 65537,
            "signatureAlgorithm": "SHA256withRSA",
            "subject": "C=US,PostalCode=60179,ST=Illinois,L=Hoffman Estates,O=Sears Brands LLC,OU=eCommerce Development,OU=Multi-Domain \
            SSL,CN=base2.pets.com",
            "subjectAlternativeNames": "base3.pets.com,base4.pets.com",
            "subjectCountry": "US",
            "subjectEmail": None,
            "subjectLocality": "Hoffman Estates",
            "subjectName": "base2.pets.com",
            "subjectOrg": "Sears Brands LLC",
            "subjectOrgUnit": "eCommerce Development,Multi-Domain SSL",
            "subjectState": "Illinois",
            "serialNumber": "145397449086924134621453997645674717378",
            "validNotBefore": "2016-03-22T00:00:00Z",
            "validNotAfter": "2018-03-22T23:59:59Z",
            "version": "3",
            "publicKeyBits": 2048,
            "pemSha256": "8OLAalY9ZOgYCD6yQJWyGNXZrWl9bugv-S3AGlIQi84=",
            "pemSha1": "DN3fXmU-IR3C6l1CTISAlgpvGFA=",
            "publicKeyModulus": "d3fce5f540f9ca51b9f7f32d6695343564f7ceb4f9b911545361603a8899399f4c92566a9be1c757e7b79531ebc7ee4994071c7\
            d2f2591576f248ace0067bd3f2e52d88afaac252624cad60a99845c4e5c96b89f3238353c0e2e79595c62436734ae681e118c6ba5a155742503d60ad9ef6\
            2e0a31da970355b33d1a6f833df6a00441487bf729697958969c6c58fdb1ea1b23219ca9ec99110688268134b5b2d18b6ab2d0a4a12dff7e51cee6427345\
            c03f18f19aa8f7acc4eb9739f8d72dc0ab5e60cb365cc157b49e6c92700b16bc1bbec6197d4c579ff82581253ebf98d051cc8236b19c7af8591d6dc3f486\
            b69b299b7ca7eccd454c465fc5a62dc49b11f",
            "publicKeySpki": "U_pBSH73cx7BWHRuE3UZvYkONJ8s694ziYTHbLVgtis="
        },
        "commonName": "base2.pets.com",
        "properties": [
            "EXPIRED"
        ],
        "hasLinkedCloudResources": False,
        "certificateAdvertisementStatus": [
            "NO_CERTIFICATE_ADVERTISEMENT"
        ],
        "serviceStatus": [
            "NO_ACTIVE_SERVICE",
            "NO_ACTIVE_CLOUD_SERVICE",
            "NO_ACTIVE_ON_PREM_SERVICE"
        ],
        "details": {
            "recentIps": [],
            "cloudResources": []
        }
    }]
}
