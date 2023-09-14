from Okta_v2 import Client, get_user_command, get_group_members_command, create_user_command, \
    verify_push_factor_command, get_groups_for_user_command, get_user_factors_command, get_logs_command, \
    get_zone_command, list_zones_command, update_zone_command, list_users_command, create_zone_command, \
    create_group_command, assign_group_to_app_command, get_after_tag, delete_limit_param, set_password_command
import pytest
import json
import io
import requests_mock


client = Client(base_url="demisto.com")

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


def util_load_json(path: str):
    """
    Utility to load json data from a local folder.
    """
    with io.open(path, mode='r', encoding='utf-8') as file:
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
    assert 'TestID' == outputs.get('Account(val.ID && val.ID === obj.ID)').get('ID')


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
    assert 'nzoqsmcx1qWYJ6wYF7q0' == outputs.get('Okta.Zone(val.id && val.id === obj.id)').get('id', '')


def test_list_zones_command(mocker):
    mocker.patch.object(client, 'list_zones', return_value=okta_zone)
    readable, outputs, _ = list_zones_command(client, {})
    assert 'Test Zone' in readable
    assert 'nzoqsmcx1qWYJ6wYF7q0' == outputs.get('Okta.Zone(val.id && val.id === obj.id)').get('id', '')


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
    assert 'NewZoneName' == outputs.get('Okta.Zone(val.id && val.id === obj.id)').get('name', '')


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
    assert 'NewZoneName' == outputs.get('Okta.Zone(val.id && val.id === obj.id)').get('name', '')


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
    client = Client('https://demisto.com')
    with requests_mock.Mocker() as m:
        m.get('https://demisto.com/users?filter=profile.login eq "test"', json=[{'id': '1234'}])
        mock_request = m.post('https://demisto.com/users/1234', json={'passwordChanged': '2020-03-26T13:57:13.000Z'})

        result = set_password_command(client, {'username': 'test', 'password': 'a1b2c3'})

    assert result[0] == 'test password was last changed on 2020-03-26T13:57:13.000Z'
    assert mock_request.last_request.text == '{"credentials": {"password": {"value": "a1b2c3"}}}'


def test_set_temp_password_command():
    client = Client('https://demisto.com')
    with requests_mock.Mocker() as m:
        m.get('https://demisto.com/users?filter=profile.login eq "test"', json=[{'id': '1234'}])
        m.post('https://demisto.com/users/1234', json={'passwordChanged': '2023-03-22T10:15:26.000Z'})
        m.post('https://demisto.com/users/1234/lifecycle/expire_password', json={})

        result = set_password_command(client, {'username': 'test', 'password': 'a1b2c3', 'temporary_password': 'true'})

    assert result[0] == 'test password was last changed on 2023-03-22T10:15:26.000Z'
