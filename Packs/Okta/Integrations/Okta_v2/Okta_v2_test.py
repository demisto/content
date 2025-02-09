from unittest.mock import MagicMock, patch
from Okta_v2 import Client, get_user_command, get_group_members_command, create_user_command, \
    verify_push_factor_command, get_groups_for_user_command, get_user_factors_command, get_logs_command, \
    get_zone_command, list_zones_command, update_zone_command, list_users_command, create_zone_command, \
    create_group_command, assign_group_to_app_command, get_after_tag, delete_limit_param, set_password_command, apply_zone_updates
import pytest
import json
import requests_mock

client = Client(base_url="demisto.com", api_token="XXX")

user_data = {
    "id": "TestID",
    "status": "PROVISIONED",
    "created": "2020-02-19T08:18:20.000Z",
    "activated": "2020-02-20T11:44:43.000Z",
    "statusChanged": "2020-02-20T11:45:24.000Z",
    "lastLogin": "2020-02-23T11:45:24.000Z",
    "lastUpdated": "2020-02-20T11:45:24.000Z",
    "passwordChanged": "2020-02-19T08:18:21.000Z",
    "type": {
        "id": "oty66lckcvDyVcGzS0h7"
    },
    "profile": {
        "firstName": "test",
        "lastName": "this",
        "mobilePhone": 'null',
        "city": "Tel-Aviv",
        "displayName": "test1",
        "secondEmail": "test@this.com",
        "login": "test@this.com",
        "email": "test@this.com",
        "manager": "manager",
        "managerEmail": "manager@test.com"
    },
    "credentials": {
        "provider": {
            "type": "OKTA",
            "name": "OKTA"
        }
    },
    "_links": {
    }
}
factors_data = [
    {
        "id": "mblpt21nffaaN5F060h7",
        "factorType": "sms",
        "provider": "OKTA",
        "vendorName": "OKTA",
        "status": "PENDING_ACTIVATION",
        "created": "2020-02-18T11:48:16.000Z",
        "lastUpdated": "2020-02-18T11:48:16.000Z",
        "profile": {
            "phoneNumber": "+12025550191"
        },
        "_links": {}
    },
    {
        "id": "uftpt24kdrDJ7fDOq0h7",
        "factorType": "token:software:totp",
        "provider": "GOOGLE",
        "vendorName": "GOOGLE",
        "status": "PENDING_ACTIVATION",
        "created": "2020-02-18T11:45:14.000Z",
        "lastUpdated": "2020-02-18T11:45:14.000Z",
        "profile": {
            "credentialId": "woo@demisto.com"
        },
        "_links": {}
    },
    {
        "id": "opfpt1joeaArlg27g0h7",
        "factorType": "push",
        "provider": "OKTA",
        "vendorName": "OKTA",
        "status": "PENDING_ACTIVATION",
        "created": "2020-02-18T11:45:03.000Z",
        "lastUpdated": "2020-02-18T11:45:03.000Z",
        "_links": {
            "self": {},
            "poll": {},
            "user": {}
        },
        "_embedded": {
            "activation": {
                "factorResult": "TIMEOUT",
                "_links": {}
            }
        }
    }
]
group_data = [
    {
        "id": "00g66lckcsAJpLcNc0h7",
        "created": "2016-04-12T15:01:50.000Z",
        "lastUpdated": "2016-04-12T15:01:50.000Z",
        "lastMembershipUpdated": "2020-02-19T09:01:32.000Z",
        "objectClass": [
            "okta:user_group"
        ],
        "type": "BUILT_IN",
        "profile": {
            "name": "Everyone",
            "description": "All users in your organization"
        },
        "_links": {}
    }
]
verify_push_factor_response = {
    "factorResult": "WAITING",
    "profile": {
        "credentialId": "test@this.com",
        "deviceType": "SmartPhone_IPhone",
        "keys": [
            {
                "kty": "EC",
                "use": "sig",
                "kid": "default",
                "x": "3Y53lDoQYwzzVbjsbsPnqOnVaotIrVByQh5Sa-RwOHQ",
                "y": "0zHY_y9rVh-bq_-lR-MrmzNtUZrrIMbTrsjtxUyUT2Q",
                "crv": "P-256"
            }
        ],
        "name": "iPhone (5)",
        "platform": "IOS",
        "version": "13.1.3"
    },
    "expiresAt": "2020-02-24T11:37:08.000Z",
    "_links": {
        "cancel": {
            "href": "https://test.com/api/v1/users/TestID/factors/FactorID/transactions/TransactionID",
            "hints": {
                "allow": [
                    "DELETE"
                ]
            }
        },
        "poll": {
            "href": "https://test.com/api/v1/users/TestID/factors/FactorID/transactions/TransactionID",
            "hints": {
                "allow": [
                    "GET"
                ]
            }
        }
    }
}
polling_response_success = {
    "factorResult": "SUCCESS"
}
polling_response_rejected = {
    "factorResult": "REJECTED",
    "_links": {
        "verify": {
            "href": "https://test.com/api/v1/users/TestID/factors/FactorID/verify",
            "hints": {
                "allow": [
                    "POST"
                ]
            }
        },
        "factor": {}
    }
}
create_user_response = {
    "id": "00ub0oNGTSWTBKOLGLNR",
    "status": "STAGED",
    "created": "2013-07-02T21:36:25.344Z",
    "activated": '',
    "statusChanged": '',
    "lastLogin": '',
    "lastUpdated": "2013-07-02T21:36:25.344Z",
    "passwordChanged": "2013-07-02T21:36:25.344Z",
    "profile": {
        "firstName": "Testush",
        "lastName": "Test",
        "email": "test@this.com",
        "login": "test@this.com",
        "mobilePhone": "555-415-1337"
    },
    "credentials": {
        "password": {},
        "provider": {
            "type": "OKTA",
            "name": "OKTA"
        }
    },
    "_links": {
        "activate": {
            "href": "https://test.com/api/v1/users/TestID/lifecycle/activate"
        },
        "self": {
            "href": "https://test.com/api/v1/users/TestID"
        }
    }
}
create_group_response = {
    "id": "00g3q8tjdyoOw6fJE1d7",
    "created": "2022-05-20T14:59:29.000Z",
    "lastUpdated": "2022-05-20T14:59:29.000Z",
    "lastMembershipUpdated": "2022-05-20T14:59:29.000Z",
    "objectClass": ["okta:user_group"],
    "type": "OKTA_GROUP",
    "profile": {
        "name": "TestGroup",
        "description": "Test Group Description"
    },
    "_links": {
        "logo": [{
            "name": "medium",
            "href": "https://op3static.oktacdn.com/assets/img/logos/groups/odyssey/okta-medium.png",
            "type": "image/png"
        },
            {
                "name": "large",
                "href": "https://op3static.oktacdn.com/assets/img/logos/groups/odyssey/okta-large.png",
                "type": "image/png"
            }],
        "users": {"href": "https://test.com/api/v1/groups/00g3q8tjdyoOw6fJE1d7/users"},
        "apps": {"href": "https://test.com/api/v1/groups/00g3q8tjdyoOw6fJE1d7/apps"}
    }
}
assign_group_to_app_response = {
    "id": "00g3q8tjdyoOw6fJE1d7",
    "lastUpdated": "2022-05-20T16:01:16.000Z",
    "priority": 5,
    "profile": {},
    "_links": {
        "app": {
            "href": "https://test.com/api/v1/apps/0oa3ik9908vngPiMB1d7"
        },
        "self": {
            "href": "https://test.com/api/v1/apps/0oa3ik9908vngPiMB1d7/groups/00g3q8tjdyoOw6fJE1d7"
        },
        "group": {
            "href": "https://test.com/api/v1/groups/00g3q8tjdyoOw6fJE1d7"
        }
    }
}
group_members = [
    {
        "id": "TestID1",
        "status": "ACTIVE",
        "created": "2016-04-12T15:01:52.000Z",
        "activated": '',
        "statusChanged": "2020-02-12T15:05:06.000Z",
        "lastLogin": "2020-02-24T11:40:36.000Z",
        "lastUpdated": "2020-02-24T11:42:22.000Z",
        "passwordChanged": "2020-02-24T11:40:08.000Z",
        "type": {
            "id": "oty66lckcvDyVcGzS0h7"
        },
        "profile": {
            "firstName": "Test1",
            "lastName": "Test1",
            "primaryPhone": "8888888888",
            "mobilePhone": "",
            "secondEmail": "",
            "department": "everyone,admin,bla",
            "login": "test@this.com",
            "email": "test@this.com"
        },
        "credentials": {
            "password": {},
            "recovery_question": {
                "question": "born city"
            },
            "provider": {
                "type": "OKTA",
                "name": "OKTA"
            }
        },
        "_links": {}
    },
    {
        "id": "TestID2",
        "status": "STAGED",
        "created": "2018-07-24T20:20:04.000Z",
        "activated": '',
        "statusChanged": '',
        "lastLogin": '',
        "lastUpdated": "2018-07-24T20:20:04.000Z",
        "passwordChanged": '',
        "type": {
            "id": "oty66lckcvDyVcGzS0h7"
        },
        "profile": {
            "firstName": "Test2",
            "lastName": "Test2",
            "mobilePhone": '',
            "secondEmail": "",
            "login": "john@doe.com",
            "email": "john@doe.com"
        },
        "credentials": {
            "provider": {
                "type": "OKTA",
                "name": "OKTA"
            }
        },
        "_links": {}
    },
    {
        "id": "TestID3",
        "status": "PROVISIONED",
        "created": "2018-07-31T12:48:33.000Z",
        "activated": "2020-02-19T12:33:20.000Z",
        "statusChanged": "2020-02-19T12:33:20.000Z",
        "lastLogin": '',
        "lastUpdated": "2020-02-19T12:33:20.000Z",
        "passwordChanged": "2020-02-06T13:32:56.000Z",
        "type": {
            "id": "oty66lckcvDyVcGzS0h7"
        },
        "profile": {
            "firstName": "test",
            "lastName": "that",
            "manager": "MegaTester",
            "mobilePhone": '',
            "city": "TLV",
            "displayName": "alsotest",
            "secondEmail": "woo@demisto.com",
            "login": "woo@demisto.com",
            "email": "woo@demisto.com",
            "employeeNumber": "123427"
        },
        "credentials": {
            "provider": {
                "type": "OKTA",
                "name": "OKTA"
            }
        },
        "_links": {}
    }
]
logs = [
    {
        "actor": {
            "id": "UserTestID1",
            "type": "User",
            "alternateId": "soso@demisto.com",
            "displayName": "Test1 Testush",
            "detailEntry": ''
        },
        "client": {
            "userAgent": {
                "rawUserAgent": "python-requests/2.22.0",
                "os": "Windows",
                "browser": "Chrome"
            },
            "zone": "null",
            "device": "Computer",
            "id": '',
            "ipAddress": "8.8.8.8",
            "geographicalContext": {
                "city": "Tel Aviv",
                "state": "Tel Aviv",
                "country": "Israel",
                "postalCode": '',
                "geolocation": {
                    "lat": 32.0678,
                    "lon": 34.7647
                }
            }
        },
        "authenticationContext": {
            "authenticationProvider": '',
            "credentialProvider": '',
            "credentialType": '',
            "issuer": '',
            "interface": '',
            "authenticatio'nStep": 0,
            "externalSessionId": "trsGDHiJe2ISM2GneNwg_tIWw"
        },
        "displayMessage": "Add user to application membership",
        "eventType": "application.user_membership.add",
        "outcome": {
            "result": "SUCCESS",
            "reason": ''
        },
        "published": "2020-02-18T11:23:05.066Z",
        "securityContext": {
            "asNumber": '',
            "asOrg": '',
            "isp": '',
            "domain": '',
            "isProxy": ''
        },
        "severity": "INFO",
        "debugContext": {
            "debugData": {
                "requestId": "XkvJGFsS6hsPnC7KoFliVAAABzI",
                "requestUri": "/api/v1/users",
                "threatSuspected": "false",
                "url": "/api/v1/users?activate=true"
            }
        },
        "legacyEventType": "app.generic.provision.assign_user_to_app",
        "transaction": {
            "type": "WEB",
            "id": "XkvJGFsS6hsPnC7KoFliVAAABzI",
            "detail": {}
        },
        "uuid": "081c84f9-5241-11ea-ad7c-6125e916db06",
        "version": "0",
        "request": {
            "ipChain": [
                {
                    "ip": "8.8.8.8",
                    "geographicalContext": {
                        "city": "Tel Aviv",
                        "state": "Tel Aviv",
                        "country": "Israel",
                        "postalCode": '',
                        "geolocation": {
                            "lat": 32.0678,
                            "lon": 34.7647
                        }
                    },
                    "version": "V4",
                    "source": ''
                }
            ]
        },
        "target": [
            {
                "id": "UserTestID2",
                "type": "AppUser",
                "alternateId": "momo@demisto.com",
                "displayName": "Test 1 that",
                "detailEntry": ''
            },
            {
                "id": "0oabfkvxe1npBRdow0h7",
                "type": "AppInstance",
                "alternateId": "Demisto-SAML-OKTA",
                "displayName": "Demisto-SAML-OKTA",
                "detailEntry": ''
            },
            {
                "id": "00upt1h0w93PALT9v0h7",
                "type": "User",
                "alternateId": "momo@demisto.com",
                "displayName": "Test 1 that",
                "detailEntry": ''
            }
        ]
    },
    {
        "actor": {
            "id": "UserTestID2",
            "type": "User",
            "alternateId": "TestID2@demisto.com",
            "displayName": "Testush2 test",
            "detailEntry": ''
        },
        "client": {
            "userAgent": {
                "rawUserAgent": "python-requests/2.22.0",
                "os": "Unknown",
                "browser": "UNKNOWN"
            },
            "zone": "null",
            "device": "Unknown",
            "id": '',
            "ipAddress": "8.8.8.8",
            "geographicalContext": {
                "city": "Tel Aviv",
                "state": "Tel Aviv",
                "country": "Israel",
                "postalCode": '',
                "geolocation": {
                    "lat": 32.0678,
                    "lon": 34.7647
                }
            }
        },
        "authenticationContext": {
            "authenticationProvider": '',
            "credentialProvider": '',
            "credentialType": '',
            "issuer": '',
            "interface": '',
            "authenticationStep": 0,
            "externalSessionId": "trsGDHiJe2ISM2GneNwg_tIWw"
        },
        "displayMessage": "Add user to application membership",
        "eventType": "application.user_membership.add",
        "outcome": {
            "result": "SUCCESS",
            "reason": ''
        },
        "published": "2020-02-18T11:23:04.791Z",
        "securityContext": {
            "asNumber": '',
            "asOrg": '',
            "isp": '',
            "domain": '',
            "isProxy": ''
        },
        "severity": "INFO",
        "debugContext": {
            "debugData": {
                "requestId": "XkvJGFsS6hsPnC7KoFliVAAABzI",
                "requestUri": "/api/v1/users",
                "threatSuspected": "false",
                "url": "/api/v1/users?activate=true"
            }
        },
        "legacyEventType": "app.generic.provision.assign_user_to_app",
        "transaction": {
            "type": "WEB",
            "id": "XkvJGFsS6hsPnC7KoFliVAAABzI",
            "detail": {}
        },
        "uuid": "07f28ec5-5241-11ea-ad7c-6125e916db06",
        "version": "0",
        "request": {
            "ipChain": [
                {
                    "ip": "127.0.0.1",
                    "geographicalContext": {
                        "city": "Tel Aviv",
                        "state": "Tel Aviv",
                        "country": "Israel",
                        "postalCode": '',
                        "geolocation": {
                            "lat": 32.0678,
                            "lon": 34.7647
                        }
                    },
                    "version": "V4",
                    "source": ''
                }
            ]
        },
        "target": [
            {
                "id": "0uapt1h0wbuz8uWvb0h7",
                "type": "AppUser",
                "alternateId": "momo@demisto.com",
                "displayName": "Test 1 that",
                "detailEntry": ''
            },
            {
                "id": "0oabe0e2jruaQccDf0h7",
                "type": "AppInstance",
                "alternateId": "ShrikSAML",
                "displayName": "ShrikSAML",
                "detailEntry": ''
            },
            {
                "id": "00upt1h0w93PALT9v0h7",
                "type": "User",
                "alternateId": "momo@demisto.com",
                "displayName": "Test 1 that",
                "detailEntry": ''
            }
        ]
    }]

okta_zone = {
    "_links": {
        "deactivate": {
            "hints": {
                "allow": [
                    "POST"
                ]
            },
            "href": "https://dev-530328.oktapreview.com/api/v1/zones/nzoqsmcx1qWYJ6wYF7q0/lifecycle/deactivate"
        },
        "self": {
            "hints": {
                "allow": [
                    "GET",
                    "PUT",
                    "DELETE"
                ]
            },
            "href": "https://dev-530328.oktapreview.com/api/v1/zones/nzoqsmcx1qWYJ6wYF7q0"
        }
    },
    "created": "2020-04-06T22:23:12.000Z",
    "gateways": [
        {
            "type": "CIDR",
            "value": "4.5.3.2/16"
        },
        {
            "type": "CIDR",
            "value": "1.2.1.2/32"
        }
    ],
    "id": "nzoqsmcx1qWYJ6wYF7q0",
    "lastUpdated": "2020-05-15T05:13:06.000Z",
    "name": "Test Zone",
    "proxies": None,
    "status": "ACTIVE",
    "system": False,
    "type": "IP"
}

LOGS = [
    {'mock_log1': 'mock_value1'},
    {'mock_log2': 'mock_value2'},
    {'mock_log3': 'mock_value3'}
]


def util_load_json(path: str):
    """
    Utility to load json data from a local folder.
    """
    with open(path, encoding='utf-8') as file:
        return json.loads(file.read())


@pytest.mark.parametrize(
    # Write and define the expected
    "args ,expected_context, expected_readable",
    [
        ({"userId": "TestID", "username": "", "verbose": 'false'},
         {'ID': 'TestID', 'Username': 'test@this.com', 'DisplayName': 'test this', 'Email': 'test@this.com',
          'Status': 'PROVISIONED', 'Type': 'Okta', 'Created': "2020-02-19T08:18:20.000Z",
          'Activated': "2020-02-20T11:44:43.000Z",
          'StatusChanged': "2020-02-20T11:45:24.000Z",
          'PasswordChanged': "2020-02-19T08:18:21.000Z", "Manager": "manager", "ManagerEmail": "manager@test.com"},
         'test@this.com'),
        ({"userId": "", "username": "test@this.com", "verbose": 'true'},
         {'ID': 'TestID', 'Username': 'test@this.com', 'DisplayName': 'test this', 'Email': 'test@this.com',
          'Status': 'PROVISIONED', 'Type': 'Okta', 'Created': "2020-02-19T08:18:20.000Z",
          'Activated': "2020-02-20T11:44:43.000Z",
          'StatusChanged': "2020-02-20T11:45:24.000Z",
          'PasswordChanged': "2020-02-19T08:18:21.000Z", "Manager": "manager", "ManagerEmail": "manager@test.com"},
         'Additional Data'),
    ]
)
def test_get_user_command(mocker, args, expected_context, expected_readable):
    mocker.patch.object(client, 'get_user', return_value=user_data)
    readable, outputs, _ = get_user_command(client, args)
    assert outputs.get('Account(val.ID && val.ID === obj.ID)')[0] == expected_context
    assert expected_readable in readable


def test_get_user_command_not_found_user(mocker):
    """
        Given:
       - Username.

       When:
       - running get_user_command.

       Then:
       - Ensure that no exception was raised, and assert the readable output.
    """
    args = {"username": "test@this.com"}
    mocker.patch.object(client, 'get_user', side_effect=Exception('Error in API call [404] - Not found'))
    readable, _, _ = get_user_command(client, args)
    assert 'User test@this.com was not found.' in readable


@pytest.mark.parametrize(
    # Write and define the expected
    "args ,expected_context, expected_readable",
    [
        ({"userId": "TestID", "username": "", "verbose": 'false'},
         {'ID': 'TestID', 'Username': 'test@this.com', 'DisplayName': 'test this', 'Email': 'test@this.com',
          'Status': 'PROVISIONED', 'Type': 'Okta', 'Created': "2020-02-19T08:18:20.000Z",
          'Activated': "2020-02-20T11:44:43.000Z",
          'StatusChanged': "2020-02-20T11:45:24.000Z",
          'PasswordChanged': "2020-02-19T08:18:21.000Z", "Manager": "manager", "ManagerEmail": "manager@test.com"},
         'test@this.com'),
        ({"userId": "", "username": "test@this.com", "verbose": 'true'},
         {'ID': 'TestID', 'Username': 'test@this.com', 'DisplayName': 'test this', 'Email': 'test@this.com',
          'Status': 'PROVISIONED', 'Type': 'Okta', 'Created': "2020-02-19T08:18:20.000Z",
          'Activated': "2020-02-20T11:44:43.000Z",
          'StatusChanged': "2020-02-20T11:45:24.000Z",
          'PasswordChanged': "2020-02-19T08:18:21.000Z", "Manager": "manager", "ManagerEmail": "manager@test.com"},
         'Additional Data'),
    ]
)
def test_list_user_command(mocker, args, expected_context, expected_readable):
    mocker.patch.object(client, 'list_users', return_value=(user_data, "123dasu23c"))
    readable, outputs, _ = list_users_command(client, args)
    assert outputs.get('Account(val.ID && val.ID == obj.ID)')[0] == expected_context
    assert expected_readable in readable
    assert "tag: 123dasu23c" in readable


@pytest.mark.parametrize("args", [({"userId": "TestID", "username": "", "verbose": 'false'})])
def test_after_key_list_user_command(mocker, args):
    """
    Given
    - args.

    When
    - Running list_users command.

    Then
    - Validate that since there's no more results to show, there's no tag key in the readable output.
    """
    mocker.patch.object(client, 'list_users', return_value=(user_data, None))
    readable, _, _ = list_users_command(client, args)
    assert "tag:" not in readable


@pytest.mark.parametrize("url, expected_after_tag",
                         [("https://dev-725178.oktapreview.com/api/v1/users?limit=10&after=qazwsx123",
                           "qazwsx123")])
def test_get_after_tag_function(url, expected_after_tag):
    """
    Given
    - url.
    When
    - Running get_after_tag function.

    Then
    - Validate that tag was extracted correctly.
    """
    after_tag = get_after_tag(url)
    assert expected_after_tag == after_tag


@pytest.mark.parametrize("url, expected_url",
                         [("https://dev-725178.oktapreview.com/api/v1/users?limit=10&after=qazwsx123",
                           "https://dev-725178.oktapreview.com/api/v1/users?after=qazwsx123")])
def test_delete_limit_param_function(url, expected_url):
    """
    Given
    - url.
    When
    - Running delete_limit_param function.

    Then
    - Ensure that the limit param was deleted.
    """
    modified_url = delete_limit_param(url)
    assert expected_url == modified_url


@pytest.mark.parametrize(
    "args ,expected_context",
    [
        ({"userId": "TestID"}, {'ID': 'uftpt24kdrDJ7fDOq0h7', 'FactorType': 'token:software:totp', 'Provider': 'GOOGLE',
                                'Status': 'PENDING_ACTIVATION', 'Profile': {'credentialId': 'woo@demisto.com'}}),
        ({"username": "test@this.com"},
         {'ID': 'uftpt24kdrDJ7fDOq0h7', 'FactorType': 'token:software:totp', 'Provider': 'GOOGLE',
          'Status': 'PENDING_ACTIVATION', 'Profile': {'credentialId': 'woo@demisto.com'}}),

    ]
)
def test_get_user_factors_command(mocker, args, expected_context):
    mocker.patch.object(client, 'get_user_id', return_value='TestID')
    mocker.patch.object(client, 'get_user_factors', return_value=factors_data)
    readable, outputs, _ = get_user_factors_command(client, args)
    assert expected_context == outputs.get('Account(val.ID && val.ID === obj.ID)').get('Factor')[1]
    assert outputs.get('Account(val.ID && val.ID === obj.ID)').get('ID') == args.get('userId') or 'TestID'


@pytest.mark.parametrize("args", [{'username': 'test@this.com'}])
def test_get_groups_for_user_command(mocker, args):
    expected_context = {'ID': '00g66lckcsAJpLcNc0h7',
                        'Created': "2016-04-12T15:01:50.000Z",
                        'ObjectClass': ["okta:user_group"],
                        'LastUpdated': '2016-04-12T15:01:50.000Z',
                        'LastMembershipUpdated': "2020-02-19T09:01:32.000Z",
                        'Type': "BUILT_IN", 'Name': "Everyone",
                        'Description': "All users in your organization"}
    mocker.patch.object(client, 'get_user_id', return_value='TestID')
    mocker.patch.object(client, 'get_groups_for_user', return_value=group_data)
    _, outputs, _ = get_groups_for_user_command(client, args)
    assert outputs.get('Account(val.ID && val.ID === obj.ID)').get('Group')[0] == expected_context
    assert outputs.get('Account(val.ID && val.ID === obj.ID)').get('ID') == 'TestID'


@pytest.mark.parametrize(
    "args, polling_response, result",
    [({'userId': 'TestID', 'factorId': 'FactorID'}, polling_response_rejected, 'REJECTED'),
     ({'userId': 'TestID', 'factorId': 'FactorID'}, polling_response_success, 'SUCCESS')])
def test_verify_push_factor_command(mocker, args, polling_response, result):
    mocker.patch.object(client, 'verify_push_factor', return_value=verify_push_factor_response)
    mocker.patch.object(client, 'poll_verify_push', return_value=polling_response)
    _, outputs, _ = verify_push_factor_command(client, args)
    assert outputs.get('Account(val.ID && val.ID === obj.ID)').get('ID') == 'TestID'
    assert outputs.get('Account(val.ID && val.ID === obj.ID)').get('VerifyPushResult') == result


@pytest.mark.parametrize(
    "args",
    [({'firstName': 'Testush',
       'lastName': 'Test',
       'email': 'test@this.com',
       'login': 'test@this.com',
       'password': 'Aa123456'})])
def test_create_user_command(mocker, args):
    mocker.patch.object(client, 'create_user', return_value=create_user_response)
    readable, outputs, _ = create_user_command(client, args)
    assert 'STAGED' in readable
    assert outputs.get('Account(val.ID && val.ID === obj.ID)')[0].get('Status') == 'STAGED'


@pytest.mark.parametrize(
    "args",
    [({'name': 'TestGroup',
       'description': 'Test Group Description'})])
def test_create_group_command(mocker, args):
    mocker.patch.object(client, 'create_group', return_value=create_group_response)
    readable, outputs, _ = create_group_command(client, args)
    assert outputs.get('OktaGroup(val.ID && val.ID === obj.ID)')[0].get('Type') == 'OKTA_GROUP'


@pytest.mark.parametrize(
    "args",
    [({'groupName': 'TestGroup',
       'appName': 'TestApp'})])
def test_assign_group_to_app_command(mocker, args):
    mocker.patch.object(client, 'get_group_id', return_value='00g3q8tjdyoOw6fJE1d7')
    mocker.patch.object(client, 'get_app_id', return_value='a456appid654')
    mocker.patch.object(client, 'assign_group_to_app', return_value=assign_group_to_app_response)
    readable, outputs, _ = assign_group_to_app_command(client, args)
    assert _.get('id') == '00g3q8tjdyoOw6fJE1d7'


@pytest.mark.parametrize(
    "args, expected",
    [
        ({'groupId': 'Test Group', 'limit': 5},
         {'ID': 'TestID2', 'Username': 'john@doe.com', 'DisplayName': 'Test2 Test2',
          'Email': 'john@doe.com', 'Status': 'STAGED', 'Type': 'Okta', 'Created': "2018-07-24T20:20:04.000Z"})
    ])
def test_get_group_members_command(mocker, args, expected):
    mocker.patch.object(client, 'get_group_members', return_value=group_members)
    readable, outputs, _ = get_group_members_command(client, args)
    assert 'Test Group' in readable
    assert expected == outputs.get('Account(val.ID && val.ID === obj.ID)')[1]


def test_get_logs_command(mocker):
    mocker.patch.object(client, 'get_logs', return_value=logs)
    readable, outputs, _ = get_logs_command(client, {})
    assert logs == outputs.get('Okta.Logs.Events(val.uuid && val.uuid === obj.uuid)')
    assert 'Unknown browser on Unknown OS Unknown device' in readable
    assert 'Chrome on Windows Computer' in readable


@pytest.mark.parametrize(
    "args",
    [
        ({'zoneID': 'nzoqsmcx1qWYJ6wYF7q0'})
    ])
def test_get_zone_command(mocker, args):
    mocker.patch.object(client, 'get_zone', return_value=okta_zone)
    readable, outputs, _ = get_zone_command(client, args)
    assert 'Test Zone' in readable
    assert outputs.get('Okta.Zone(val.id && val.id === obj.id)').get('id', '') == 'nzoqsmcx1qWYJ6wYF7q0'


def test_list_zones_command(mocker):
    mocker.patch.object(client, 'list_zones', return_value=okta_zone)
    readable, outputs, _ = list_zones_command(client, {})
    assert 'Test Zone' in readable
    assert outputs.get('Okta.Zone(val.id && val.id === obj.id)').get('id', '') == 'nzoqsmcx1qWYJ6wYF7q0'


@pytest.mark.parametrize(
    "args",
    [
        ({'zoneID': 'nzoqsmcx1qWYJ6wYF7q0', 'zoneName': 'NewZoneName'})
    ])
def test_update_zone_command(mocker, args):
    my_okta_zone = okta_zone
    my_okta_zone['name'] = 'NewZoneName'
    mocker.patch.object(client, 'get_zone', return_value=okta_zone)
    mocker.patch.object(client, 'update_zone', return_value=my_okta_zone)
    readable, outputs, _ = update_zone_command(client, args)
    assert outputs.get('Okta.Zone(val.id && val.id === obj.id)').get('name', '') == 'NewZoneName'


@pytest.mark.parametrize(
    "args",
    [
        ({'gateway_ips': '8.8.8.8', 'name': 'NewZoneName'})
    ])
def test_create_zone_command(mocker, args):
    my_okta_zone = okta_zone
    my_okta_zone['name'] = 'NewZoneName'
    mocker.patch.object(client, 'create_zone', return_value=okta_zone)
    readable, outputs, _ = create_zone_command(client, args)
    assert outputs.get('Okta.Zone(val.id && val.id === obj.id)').get('name', '') == 'NewZoneName'


EXPEXTED_LOGS_RESULT = \
    [
        {
            "Actor": "dummy name (User)",
            "ActorAlternaneId": "example",
            "EventInfo": "Remove user from group membership",
            "EventOutcome": "SUCCESS",
            "EventSeverity": "INFO",
            "Client": "Unknown browser on Unknown OS Unknown device",
            "RequestIP": "8.8.8.8",
            "ChainIP": [
                "8.8.8.8"
            ],
            "Targets": "test this (User)\ntest1 (UserGroup)\n",
            "Time": "12/13/2021, 01:47:08"
        },
        {
            "Actor": "dummy name (User)",
            "ActorAlternaneId": "example",
            "EventInfo": "Remove user from group membership",
            "EventOutcome": "SUCCESS",
            "EventSeverity": "INFO",
            "Client": "Unknown browser on Unknown OS Unknown device",
            "RequestIP": "8.8.8.8",
            "ChainIP": [],
            "Targets": "test this (User)\ntest1 (UserGroup)\n",
            "Time": "12/13/2021, 01:47:08"
        }
    ]


def test_get_readable_logs():
    logs_raw_response = util_load_json('test_data/get_logs_response.json')
    result = client.get_readable_logs(logs_raw_response)
    assert len(result) == 2
    assert result == EXPEXTED_LOGS_RESULT


def test_set_password_command():
    client = Client(base_url='https://demisto.com', api_token="XXX")
    with requests_mock.Mocker() as m:
        m.get('https://demisto.com/api/v1/users?filter=profile.login eq "test"', json=[{'id': '1234'}])
        mock_request = m.post('https://demisto.com/api/v1/users/1234', json={'passwordChanged': '2020-03-26T13:57:13.000Z'})

        result = set_password_command(client, {'username': 'test', 'password': 'a1b2c3'})

    assert result[0] == 'test password was last changed on 2020-03-26T13:57:13.000Z'
    assert mock_request.last_request.text == '{"credentials": {"password": {"value": "a1b2c3"}}}'


def test_set_temp_password_command():
    client = Client(base_url='https://demisto.com', api_token="XXX")
    with requests_mock.Mocker() as m:
        m.get('https://demisto.com/api/v1/users?filter=profile.login eq "test"', json=[{'id': '1234'}])
        m.post('https://demisto.com/api/v1/users/1234', json={'passwordChanged': '2023-03-22T10:15:26.000Z'})
        m.post('https://demisto.com/api/v1/users/1234/lifecycle/expire_password?tempPassword=true',
               json={"tempPassword": "cAn5N3gx"})

        result = set_password_command(client, {'username': 'test', 'password': 'a1b2c3', 'temporary_password': 'true'})
    expected_results = "test password was last changed on 2023-03-22T10:15:26.000Z\n" \
                       "### Okta Temporary Password\n|tempPassword|\n|---|\n| cAn5N3gx |\n"
    assert result[0] == expected_results


def mock_get_paged_results(url_suffix='', query_params=None, max_limit=None):
    if max_limit:
        return LOGS[:max_limit]
    else:
        return LOGS


LOGS_WITH_LIMIT = [
    (None, 3),
    (1, 1),
    (3, 3),
    (1001, 3)
]


@pytest.mark.parametrize('limit, logs_amount', LOGS_WITH_LIMIT)
def test_get_logs_command_with_limit(mocker, requests_mock, limit, logs_amount):
    """
    Given:
        - An Okta IAM client object.
    When:
        - Calling function okta-get-logs
        - Events should come in two batches of two events in the first batch, and one event in the second batch.
    Then:
        - Ensure three events are returned in incident the correct format.
    """
    from Okta_v2 import get_logs_command

    client = Client(base_url='https://demisto.com', api_token="XXX")
    mocker.patch.object(Client, 'get_paged_results', side_effect=mock_get_paged_results)
    mocker.patch.object(Client, 'get_readable_logs', side_effect=mock_get_paged_results)
    requests_mock.get(f"https://demisto.com/api/v1/logs?limit={limit}", json=LOGS[:limit])
    args = {'limit': limit}
    readable, outputs, raw_response = get_logs_command(client=client, args=args)
    assert len(outputs.get('Okta.Logs.Events(val.uuid && val.uuid === obj.uuid)')) == logs_amount


def test_expire_password_with_revoke_session():
    """
    Given:
        - A client object with mocked methods for getting user ID, revoking a session, and formatting the user context.
        - Arguments for expire_password_command with username, hide_password set to False, and revoke_session set to True.
    When:
        - Calling expire_password_command with revoke_session set to True.
    Then:
        - Ensure the revoke_session method is called.
        - Ensure the response includes the correct tempPassword and user context.
        - Ensure the readable output is formatted as expected.
    """
    from Okta_v2 import expire_password_command
    client = MagicMock()
    args = {
        'username': 'test_user',
        'hide_password': 'False',
        'revoke_session': 'True'
    }

    client.get_user_id.return_value = 'user123'
    client.revoke_session.return_value = {'tempPassword': 'test_password'}
    client.get_users_context.return_value = {'ID': 'user123'}

    readable_output, outputs, raw_response = expire_password_command(client, args)

    client.revoke_session.assert_called_once_with('user123')
    assert 'Account(val.ID && val.ID === obj.ID)' in outputs
    assert outputs['Account(val.ID && val.ID === obj.ID)']['ID'] == 'user123'
    assert 'test_password' in raw_response['tempPassword']
    assert readable_output == '### Okta Expired Password\n|tempPassword|\n|---|\n| test_password |\n'


def test_expire_password_without_revoke_session():
    """
    Given:
        - Arguments for expire_password_command with username, hide_password set to False, and revoke_session set to False.
    When:
        - Calling expire_password_command.
    Then:
        - Ensure the expire_password method is called.
        - Ensure the response includes the correct tempPassword and user context.
        - Ensure the readable output is formatted as expected.
    """
    from Okta_v2 import expire_password_command
    client = MagicMock()
    args = {
        'username': 'test_user',
        'hide_password': 'False',
        'revoke_session': 'False'
    }

    client.get_user_id.return_value = 'user123'
    client.expire_password.return_value = {'tempPassword': 'test_password'}
    client.get_users_context.return_value = {'ID': 'user123'}

    readable_output, outputs, raw_response = expire_password_command(client, args)

    client.expire_password.assert_called_once_with('user123', args)
    assert 'Account(val.ID && val.ID === obj.ID)' in outputs
    assert outputs['Account(val.ID && val.ID === obj.ID)']['ID'] == 'user123'
    assert 'test_password' in raw_response['tempPassword']
    assert readable_output == '### Okta Expired Password\n|tempPassword|\n|---|\n| test_password |\n'


def test_hide_password():
    """
    Given:
        - Arguments for expire_password_command with username, hide_password set to True, and revoke_session set to False.
    When:
        - Calling expire_password_command.
    Then:
        - Ensure the tempPassword in the response is hidden.
        - Ensure the readable output is formatted to indicate the password is hidden.
    """
    from Okta_v2 import expire_password_command
    client = MagicMock()
    args = {
        'username': 'test_user',
        'hide_password': 'True',
        'revoke_session': 'False'
    }

    client.get_user_id.return_value = 'user123'
    client.expire_password.return_value = {'tempPassword': 'test_password'}
    client.get_users_context.return_value = {'ID': 'user123'}

    readable_output, outputs, raw_response = expire_password_command(client, args)

    assert raw_response['tempPassword'] == 'Output removed by user. hide_password argument set to True'
    assert readable_output == ('### Okta Expired Password\n|tempPassword|\n|---|\n| Output removed by user. '
                               'hide_password argument set to True |\n')


def test_show_password():
    """
    Given:
        - Arguments for expire_password_command with username, hide_password set to False, and revoke_session set to False.
    When:
        - Calling expire_password_command.
    Then:
        - Ensure the tempPassword in the response is shown.
        - Ensure the readable output displays the tempPassword.
    """
    from Okta_v2 import expire_password_command
    client = MagicMock()
    args = {
        'username': 'test_user',
        'hide_password': 'False',
        'revoke_session': 'False'
    }

    client.get_user_id.return_value = 'user123'
    client.expire_password.return_value = {'tempPassword': 'test_password'}
    client.get_users_context.return_value = {'ID': 'user123'}

    readable_output, outputs, raw_response = expire_password_command(client, args)

    assert raw_response['tempPassword'] == 'test_password'
    assert readable_output == '### Okta Expired Password\n|tempPassword|\n|---|\n| test_password |\n'


def test_missing_username_and_user_id():
    """
    Given:
        - Arguments for expire_password_command with hide_password and revoke_session but no username or user ID.
    When:
        - Calling expire_password_command without providing a username or user ID.
    Then:
        - Ensure an exception is raised indicating that either a username or user ID must be provided.
    """
    from Okta_v2 import expire_password_command
    client = MagicMock()
    args = {
        'hide_password': 'False',
        'revoke_session': 'False'
    }

    client.get_user_id.return_value = None

    try:
        expire_password_command(client, args)
    except Exception as e:
        assert "You must supply either 'Username' or 'userId" in str(e)


@patch.object(Client, 'http_request')
def test_revoke_session(mock_http_request):
    """
    Given:
        - A valid user ID.
    When:
        - Calling revoke_session with a user ID.
    Then:
        - Ensure http_request is called with the correct method, URL, and parameters.
    """
    user_id = "12345"
    expected_uri = f'/api/v1/users/{user_id}/lifecycle/expire_password_with_temp_password'
    expected_params = {"revokeSessions": 'true'}
    client.revoke_session(user_id)
    mock_http_request.assert_called_once_with(
        method="POST",
        url_suffix=expected_uri,
        params=expected_params
    )


def test_apply_zone_update_override():
    """
    Given: empty ZoneObeject
    When: apply_zone_updates is called with "OVERRIDE" update type and specific gatewayIPs and proxyIPs,
    Then: the zoneObject should be updated with the provided data.
    """
    zoneObject = {}
    updated_zone = apply_zone_updates(zoneObject, "TestZone", ["192.168.1.1", "10.0.0.0-10.0.0.10"],
                                      ["10.0.0.1", "192.168.1.0-192.168.1.5"], "OVERRIDE")
    assert updated_zone == {
        "name": "TestZone",
        "gateways": [{"type": "CIDR", "value": "192.168.1.1/32"}, {"type": "RANGE", "value": "10.0.0.0-10.0.0.10"}],
        "proxies": [{"type": "CIDR", "value": "10.0.0.1/32"}, {"type": "RANGE", "value": "192.168.1.0-192.168.1.5"}]
    }


def test_apply_zone_update_append_with_range():
    """
    Given: zoneObject already with some gateways,
    When: apply_zone_updates is called with "APPEND" update type and IP ranges,
    Then: the new gateways with IP ranges should be appended to the existing ones in the zoneObject.
    """
    zoneObject = {"gateways": [{"type": "CIDR", "value": "192.168.1.1/32"}]}
    updated_zone = apply_zone_updates(zoneObject, "NewZone", ["192.168.1.2-192.168.1.10"], ["10.0.0.1", "10.0.0.2-10.0.0.5"],
                                      "APPEND")
    assert updated_zone == {
        "name": "NewZone",
        "gateways": [{"type": "CIDR", "value": "192.168.1.1/32"}, {"type": "RANGE", "value": "192.168.1.2-192.168.1.10"}],
        "proxies": [{"type": "CIDR", "value": "10.0.0.1/32"}, {"type": "RANGE", "value": "10.0.0.2-10.0.0.5"}]
    }
