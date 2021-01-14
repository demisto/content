from unittest import mock

import demistomock as demisto


INTSIGHTS_PARAMS = {
    'server': 'https://api.test.com',
    'proxy': 'no_proxy',
    'credentials': {
        'identifier': "some_id",
        'password': 'some_password'
    }
}


@mock.patch.object(demisto, "results")
def test_add_comment(mocker_results, mocker):
    mocker.patch.object(demisto, 'command', return_value='intsights-test-action')
    mocker.patch.object(demisto, 'params', return_value=INTSIGHTS_PARAMS)
    comment = 'Test Comment'
    mocker.patch.object(demisto, 'args', return_value={
        'alert-id': '5e7b0b5620d02a00085ab21e',
        'comment': comment
    })

    import IntSightsV2

    mock.patch('IntSightsV2.http_request', mock.Mock())
    IntSightsV2.add_comment()
    assert(comment == mocker_results.call_args[0][0]['Contents']['Comment'])


@mock.patch.object(demisto, "results")
def test_add_tag(mocker_results, mocker):
    mocker.patch.object(demisto, 'command', return_value='intsights-test-action')
    mocker.patch.object(demisto, 'params', return_value=INTSIGHTS_PARAMS)
    mocker.patch.object(demisto, 'args', return_value={
        'alert-id': '5e7b0b5620d02a00085ab21e',
        'tag-name': 'Test Tag'
    })

    import IntSightsV2

    tag_id = '1234'
    with mock.patch('IntSightsV2.http_request', mock.Mock()) as mock_http_response:
        mock_http_response.return_value = {
            'Details': {
                'Tags': [
                    {
                        'Name': 'Test Tag',
                        '_id': tag_id
                    }
                ]
            }
        }
        IntSightsV2.add_tag()
        assert(tag_id == mocker_results.call_args[0][0]['Contents']['Tags']['ID'])


@mock.patch.object(demisto, "results")
def test_get_alert_takedown_status(mocker_results, mocker):
    mocker.patch.object(demisto, 'command', return_value='intsights-test-action')
    mocker.patch.object(demisto, 'params', return_value=INTSIGHTS_PARAMS)
    mocker.patch.object(demisto, 'args', return_value={'alert-id': '5e7b0b5620d02a00085ab21e'})

    import IntSightsV2

    mock.patch('IntSightsV2.http_request', mock.Mock())
    IntSightsV2.get_alert_takedown_status()
    assert('TakedownStatus' in mocker_results.call_args[0][0]['Contents'] and not None)


@mock.patch.object(demisto, "results")
def test_ask_analyst(mocker_results, mocker):
    mocker.patch.object(demisto, 'command', return_value='intsights-test-action')
    mocker.patch.object(demisto, 'params', return_value=INTSIGHTS_PARAMS)
    question = 'What is the status?'
    mocker.patch.object(demisto, 'args', return_value={'alert-id': '5e7b0b5620d02a00085ab21e', 'question': question})

    import IntSightsV2

    mock.patch('IntSightsV2.http_request', mock.Mock())
    IntSightsV2.ask_analyst()
    assert(question == mocker_results.call_args[0][0]['Contents']['Question'])


@mock.patch.object(demisto, "results")
def test_close_alert(mocker_results, mocker):
    mocker.patch.object(demisto, 'command', return_value='intsights-test-action')
    mocker.patch.object(demisto, 'params', return_value=INTSIGHTS_PARAMS)
    reason = 'Solved Internally'
    mocker.patch.object(demisto, 'args', return_value={'alert-id': '5e7b0b5620d02a00085ab21e', 'reason': reason})

    import IntSightsV2

    mock.patch('IntSightsV2.http_request', mock.Mock())
    IntSightsV2.close_alert()
    assert(reason == mocker_results.call_args[0][0]['Contents']['Closed']['Reason'])


@mock.patch.object(demisto, "results")
def test_get_alert_image(mocker_results, mocker):
    mocker.patch.object(demisto, 'command', return_value='intsights-test-action')
    mocker.patch.object(demisto, 'params', return_value=INTSIGHTS_PARAMS)
    image_id = '123456789'
    mocker.patch.object(demisto, 'args', return_value={'image-id': image_id})

    import IntSightsV2

    mock.patch('IntSightsV2.http_request', mock.Mock())
    IntSightsV2.get_alert_image()
    assert(image_id + '-image.jpeg' == mocker_results.call_args[0][0]['File'])


@mock.patch.object(demisto, "results")
def test_takedown_request(mocker_results, mocker):
    mocker.patch.object(demisto, 'command', return_value='intsights-test-action')
    mocker.patch.object(demisto, 'params', return_value=INTSIGHTS_PARAMS)
    alert_id = '123456789'
    mocker.patch.object(demisto, 'args', return_value={'alert-id': alert_id})

    import IntSightsV2

    mock.patch('IntSightsV2.http_request', mock.Mock())
    IntSightsV2.takedown_request()
    assert(alert_id == mocker_results.call_args[0][0]['Contents']['ID'])


@mock.patch.object(demisto, "results")
def test_get_ioc_blocklist_status(mocker_results, mocker):
    mocker.patch.object(demisto, 'command', return_value='intsights-test-action')
    mocker.patch.object(demisto, 'params', return_value=INTSIGHTS_PARAMS)
    alert_id = '123456789'
    mocker.patch.object(demisto, 'args', return_value={'alert-id': alert_id})

    import IntSightsV2

    mock_response = {
        "Value": "example.com",
        "Status": "Sent"
    }
    with mock.patch('IntSightsV2.http_request', mock.Mock()) as mock_http_response:
        mock_http_response.return_value = [mock_response]
        IntSightsV2.get_ioc_blocklist_status()
        assert(mock_response in mocker_results.call_args[0][0]['Contents'])


@mock.patch.object(demisto, "results")
def test_search_for_ioc(mocker_results, mocker):
    mocker.patch.object(demisto, 'command', return_value='intsights-test-action')
    mocker.patch.object(demisto, 'params', return_value=INTSIGHTS_PARAMS)
    value = 'test_value'
    mocker.patch.object(demisto, 'args', return_value={'value': value})

    import IntSightsV2

    mock_response = {
        "Value": value,
        "Type": "Domains",
        "Severity": {
            "Value": "High"
        },
        "Whitelist": "false",
        "FirstSeen": "2020-01-01T20:01:27.344Z",
        "LastSeen": "2020-01-30T16:18:51.148Z",
        "LastUpdate": "2020-02-21T23:00:51.268Z",
        "Sources": [
            {
                "Name": "AlienVault OTX",
                "ConfidenceLevel": 3
            }
        ],
        "Tags": [
            "MyTag_1"
        ],
        "SystemTags": [
            "Phishing"
        ]
    }
    with mock.patch('IntSightsV2.http_request', mock.Mock()) as mock_http_response:
        mock_http_response.return_value = mock_response
        IntSightsV2.search_for_ioc()
        assert(value == mocker_results.call_args[0][0]['Contents']['Value'])


@mock.patch.object(demisto, "results")
def test_remove_tag(mocker_results, mocker):
    mocker.patch.object(demisto, 'command', return_value='intsights-test-action')
    mocker.patch.object(demisto, 'params', return_value=INTSIGHTS_PARAMS)
    tag_id = '12345'
    mocker.patch.object(demisto, 'args', return_value={'alert-id': '5e7b0b5620d02a00085ab21e', 'tag-id': tag_id})

    import IntSightsV2

    mock.patch('IntSightsV2.http_request', mock.Mock())
    IntSightsV2.remove_tag()
    assert(tag_id == mocker_results.call_args[0][0]['Contents']['Tags']['ID'])


@mock.patch.object(demisto, "results")
def test_request_for_ioc_enrichment(mocker_results, mocker):
    mocker.patch.object(demisto, 'command', return_value='intsights-test-action')
    mocker.patch.object(demisto, 'params', return_value=INTSIGHTS_PARAMS)
    value = "test_value.com"

    mocker.patch.object(demisto, 'args', return_value={'value': value})

    import IntSightsV2

    mock_response = {
        "OriginalValue": value,
        "Status": "Done",
        "Data": {
            "Value": "securitywap.com",
            "Type": "Domains",
            "IsKnownIoc": "false",
            "Whitelisted": "false",
            "Tags": [],
            "SystemTags": [],
            "Sources": [],
            "Severity": {
                "Value": "Low"
            },
            "RelatedMalwares": [],
            "RelatedThreatActors": [],
            "DnsRecords": [
                {
                    "Value": "a.sinkhole.yourtrap.com.",
                    "Type": "CNAME",
                    "FirstResolved": "2017-06-10T04:44:48.000Z",
                    "LastResolved": "2019-06-09T15:08:50.000Z"
                },
            ],
            "Subdomains": [
                "www"
            ],
            "Whois": {
                "Current": {
                    "RegistrationDetails": {
                        "CreatedDate": "2017-06-09T10:47:02.000Z",
                        "UpdatedDate": "2018-06-09T10:47:02.000Z",
                        "ExpiresDate": "2019-06-09T10:47:02.000Z",
                        "Statuses": [],
                        "NameServers": [
                            "NS1.STAR-DOMAIN.JP",
                            "NS2.STAR-DOMAIN.JP",
                            "NS3.STAR-DOMAIN.JP"
                        ]
                    },
                    "RegistrantDetails": [
                        {
                            "Organization": "Netowl,Inc.",
                            "Name": "Star Domain",
                            "Email": "some_email",
                            "Telephone": "81752568553",
                            "Fax": "",
                            "City": "Kyoto",
                            "State": "Kyoto",
                            "Country": "JAPAN"
                        }
                    ]
                },
                "History": [
                    {
                        "RegistrationDetails": {
                            "CreatedDate": "2017-06-09T10:47:02.000Z",
                            "ExpiresDate": "2018-06-09T10:47:02.000Z",
                            "Statuses": [
                                "clientTransferProhibited"
                            ],
                            "NameServers": [
                                "NS1.STAR-DOMAIN.JP",
                                "NS2.STAR-DOMAIN.JP",
                                "NS3.STAR-DOMAIN.JP"
                            ]
                        },
                        "RegistrantDetails": [
                            {
                                "Organization": "Netowl,Inc.",
                                "Name": "Star Domain",
                                "Email": "some_email",
                                "Telephone": "81752568553",
                                "Fax": "",
                                "City": "Kyoto",
                                "State": "Kyoto",
                                "Country": "JAPAN"
                            },
                        ]
                    }
                ]
            },
            "Resolutions": [
                {
                    "ResolvedIpAddress": "some_ip",
                    "Location": "JP",
                    "ASN": "17506",
                    "Operator": "ARTERIA Networks Corporation",
                    "FirstResolved": "2015-07-29T18:46:24.000Z",
                    "LastResolved": "2016-08-02T01:12:51.000Z"
                }
            ]
        }
    }
    with mock.patch('IntSightsV2.http_request', mock.Mock()) as mock_http_response:
        mock_http_response.return_value = mock_response
        IntSightsV2.request_for_ioc_enrichment()
        assert(mock_response['OriginalValue'] == mocker_results.call_args[0][0]['Contents']['OriginalValue'])


@mock.patch.object(demisto, "results")
def test_send_mail(mocker_results, mocker):
    mocker.patch.object(demisto, 'command', return_value='intsights-test-action')
    mocker.patch.object(demisto, 'params', return_value=INTSIGHTS_PARAMS)

    alert_id = '5e7b0b5620d02a00085ab21e'
    mocker.patch.object(demisto, 'args', return_value={
        'alert-id': alert_id,
        'emails': ['me@domain.com', 'you@domain.com'],
        'content': 'API Question'
    })

    import IntSightsV2

    mock.patch('IntSightsV2.http_request', mock.Mock())
    IntSightsV2.send_mail()
    assert(alert_id == mocker_results.call_args[0][0]['Contents']['ID'])


@mock.patch.object(demisto, "results")
def test_unassign_alert(mocker_results, mocker):
    mocker.patch.object(demisto, 'command', return_value='intsights-test-action')
    mocker.patch.object(demisto, 'params', return_value=INTSIGHTS_PARAMS)

    alert_id = '5e7b0b5620d02a00085ab21e'
    mocker.patch.object(demisto, 'args', return_value={
        'alert-id': alert_id
    })

    import IntSightsV2

    mock.patch('IntSightsV2.http_request', mock.Mock())
    IntSightsV2.unassign_alert()
    assert(alert_id == mocker_results.call_args[0][0]['Contents']['ID'])


@mock.patch.object(demisto, "results")
def test_change_severity(mocker_results, mocker):
    mocker.patch.object(demisto, 'command', return_value='intsights-test-action')
    mocker.patch.object(demisto, 'params', return_value=INTSIGHTS_PARAMS)

    severity = 'Low'
    mocker.patch.object(demisto, 'args', return_value={
        'alert-id': '5e7b0b5620d02a00085ab21e',
        'severity': 'Low'
    })

    import IntSightsV2

    mock.patch('IntSightsV2.http_request', mock.Mock())
    IntSightsV2.change_severity()
    assert(severity == mocker_results.call_args[0][0]['Contents']['Severity'])


@mock.patch.object(demisto, "results")
def test_update_ioc_blocklist_status(mocker_results, mocker):
    mocker.patch.object(demisto, 'command', return_value='intsights-test-action')
    mocker.patch.object(demisto, 'params', return_value=INTSIGHTS_PARAMS)

    alert_id = '5e7b0b5620d02a00085ab21e'
    mocker.patch.object(demisto, 'args', return_value={
        'alert-id': alert_id,
        'type': 'Domains',
        'value': 'example.com',
        'blocklist-status': 'Sent'
    })

    import IntSightsV2

    mock.patch('IntSightsV2.http_request', mock.Mock())
    IntSightsV2.update_ioc_blocklist_status()
    assert(alert_id == mocker_results.call_args[0][0]['Contents']['ID'])


def get_mssp_sub_accounts_http_response(method, path, **kwargs):
    if path == 'public/v1/account/used-assets':
        return {
            "AssetsLimit": 10,
            "AssetsCount": 1
        }
    elif path == 'public/v1/mssp/customers':
        return [
            {
                "_id": "123456789",
                "CompanyName": "Example",
                "Status": "Enabled"
            }
        ]
    else:
        return None


@mock.patch('IntSightsV2.http_request')
def run_mocked_https_request(mocked_http_request, action, side_effect=None, return_value=None):
    if side_effect:
        mocked_http_request.side_effect = side_effect
    else:
        mocked_http_request.return_value = side_effect

    action()


@mock.patch.object(demisto, "results")
def test_get_mssp_sub_accounts(mocker_results, mocker):
    INTSIGHTS_PARAMS['mssp_sub_account_id'] = '123456789'

    mocker.patch.object(demisto, 'command', return_value='intsights-test-action')
    mocker.patch.object(demisto, 'params', return_value=INTSIGHTS_PARAMS)

    import IntSightsV2

    run_mocked_https_request(
        action=IntSightsV2.get_mssp_sub_accounts,
        side_effect=get_mssp_sub_accounts_http_response
    )
    assert(10 == mocker_results.call_args[0][0]['Contents'][0]['AssetsLimit'])


@mock.patch.object(demisto, "results")
def test_get_iocs(mocker_results, mocker):
    mocker.patch.object(demisto, 'command', return_value='intsights-test-action')
    mocker.patch.object(demisto, 'params', return_value=INTSIGHTS_PARAMS)
    value = 'test_value'
    mocker.patch.object(demisto, 'args', return_value={'value': value})

    import IntSightsV2

    mock_response = {
        "Value": value,
        "Type": "Domains",
        "Severity": {
            "Value": "High"
        },
        "Whitelist": "false",
        "FirstSeen": "2020-01-01T20:01:27.344Z",
        "LastSeen": "2020-01-30T16:18:51.148Z",
        "LastUpdate": "2020-02-21T23:00:51.268Z",
        "Sources": [
            {
                "Name": "AlienVault OTX",
                "ConfidenceLevel": 3
            }
        ],
        "Tags": [
            "MyTag_1"
        ],
        "SystemTags": [
            "Phishing"
        ]
    }

    with mock.patch('IntSightsV2.http_request', mock.Mock()) as mock_http_response:
        mock_http_response.return_value = mock_response
        IntSightsV2.search_for_ioc()
        assert(value == mocker_results.call_args[0][0]['Contents']['Value'])


def get_alerts_http_response(method, path, **kwargs):
    if path == 'public/v1/data/alerts/get-complete-alert/123456789':
        return {
            "_id": "123456789",
            "Assets": [
                {
                    "Type": "CompanyNames",
                    "Value": "Name"
                }
            ],
            "Assignees": [],
            "Details": {
                "Type": "Phishing",
                "SubType": "RegisteredSuspiciousDomain",
                "Title": "Alert's title",
                "Description": "Alert's description",
                "Severity": "High",
                "Images": [
                    "5b1576593a21b34c6d6e6195"
                ],
                "Source": {
                    "Type": "WHOIS servers",
                    "URL": "http://example.com",
                    "Email": "",
                    "NetworkType": "ClearWeb",
                    "Date": "2018-01-10T00:00:00.000Z"
                },
                "Tags": [
                    {
                        "CreatedBy": "API",
                        "Name": "Phishing",
                        "_id": "5acda9f68602ef0006b1b593"
                    }
                ],
                "RelatedIocs": [
                    "example.com"
                ]
            },
            "FoundDate": "2018-01-01T20:01:27.344Z",
            "UpdateDate": "2019-01-01T20:01:27.344Z",
            "TakedownStatus": "NotSent",
            "IsClosed": "false",
            "IsFlagged": "false"
        }
    elif path == 'public/v1/data/alerts/alerts-list':
        return [
            '123456789'
        ]
    else:
        return None


@mock.patch.object(demisto, "results")
def test_get_alerts(mocker_results, mocker):
    mocker.patch.object(demisto, 'command', return_value='intsights-test-action')
    mocker.patch.object(demisto, 'params', return_value=INTSIGHTS_PARAMS)

    import IntSightsV2

    alert_id = '123456789'
    run_mocked_https_request(
        action=IntSightsV2.get_alerts,
        side_effect=get_alerts_http_response
    )
    assert(alert_id == mocker_results.call_args[0][0]['Contents'][0]['ID'])


@mock.patch.object(demisto, "results")
def test_get_alert_by_id(mocker_results, mocker):
    mocker.patch.object(demisto, 'command', return_value='intsights-test-action')
    mocker.patch.object(demisto, 'params', return_value=INTSIGHTS_PARAMS)
    mocker.patch.object(demisto, 'args', return_value={'alert-id': '5e7b0b5620d02a00085ab21e'})

    import IntSightsV2

    complete_alert = {
        "_id": "5b154ceb3a21b34c6d6e6194",
        "Assets": [
            {
                "Type": "CompanyNames",
                "Value": "Name"
            }
        ],
        "Assignees": [],
        "Details": {
            "Type": "Phishing",
            "SubType": "RegisteredSuspiciousDomain",
            "Title": "Alert's title",
            "Description": "Alert's description",
            "Severity": "High",
            "Images": [
                "5b1576593a21b34c6d6e6195"
            ],
            "Source": {
                "Type": "WHOIS servers",
                "URL": "http://example.com",
                "Email": "",
                "NetworkType": "ClearWeb",
                "Date": "2018-01-10T00:00:00.000Z"
            },
            "Tags": [
                {
                    "CreatedBy": "API",
                    "Name": "Phishing",
                    "_id": "5acda9f68602ef0006b1b593"
                }
            ],
            "RelatedIocs": [
                "example.com"
            ]
        },
        "FoundDate": "2018-01-01T20:01:27.344Z",
        "UpdateDate": "2019-01-01T20:01:27.344Z",
        "TakedownStatus": "NotSent",
        "IsClosed": "false",
        "IsFlagged": "false"
    }
    with mock.patch('IntSightsV2.http_request', mock.Mock()) as mock_http_response:
        mock_http_response.return_value = complete_alert

        mock.patch('IntSightsV2.http_request', mock.Mock())
        IntSightsV2.get_alert_by_id()
        assert(complete_alert['_id'] == mocker_results.call_args[0][0]['Contents']['ID'])


@mock.patch.object(demisto, "results")
def test_get_alert_activity(mocker_results, mocker):
    mocker.patch.object(demisto, 'command', return_value='intsights-test-action')
    mocker.patch.object(demisto, 'params', return_value=INTSIGHTS_PARAMS)
    mocker.patch.object(demisto, 'args', return_value={'alert-id': '5e7b0b5620d02a00085ab21e'})

    import IntSightsV2

    activity = {
        "Type": "AlertRead",
        "Initiator": "5b1641983a21b34c6d6e6197",
        "CreatedDate": "2018-01-01T13:09:39.305Z",
        "UpdateDate": "2018-01-01T13:09:39.305Z",
        "_id": "5e7b0b5620d02a00085ab21e",
        "AdditionalInformation": {
            "RemediationBlocklistUpdate": [],
            "AskTheAnalyst": {
                "Replies": []
            },
            "Mail": {
                "Replies": []
            }
        },
        "ReadBy": [
            "5b1641983a21b34c6d6e6897"
        ],
        "SubTypes": []
    }

    with mock.patch('IntSightsV2.http_request', mock.Mock()) as mock_http_response:
        mock_http_response.return_value = [
            {
                'ID': '5e7b0b5620d02a00085ab21e',
                'Activities': [
                    activity
                ]
            }
        ]

        IntSightsV2.get_alert_activity()
        assert('Activities' in mocker_results.call_args[0][0]['Contents'][0])


@mock.patch.object(demisto, "results")
def test_assign_alert(mocker_results, mocker):
    mocker.patch.object(demisto, 'command', return_value='intsights-test-action')
    mocker.patch.object(demisto, 'params', return_value=INTSIGHTS_PARAMS)
    mocker.patch.object(demisto, 'args', return_value={
        'alert-id': '5e7b0b5620d02a00085ab21e',
        'assignee-email': 'email@domain.com',
        'is-mssp-optional': 'false'
    })

    import IntSightsV2

    assignee_id = '12345'
    with mock.patch('IntSightsV2.http_request', mock.Mock()) as mock_http_response:
        mock_http_response.return_value = [
            {
                "Email": "email@domain.com",
                "_id": assignee_id
            }
        ]
        IntSightsV2.assign_alert()
        assert(assignee_id == mocker_results.call_args[0][0]['Contents']['Assignees.AssigneeID'])
