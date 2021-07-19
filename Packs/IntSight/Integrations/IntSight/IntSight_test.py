from mock import Mock, patch
import pytest
import demistomock as demisto


INTSIGHTS_PARAMS = {
    'server': 'https://api.test.com',
    'proxy': 'no_proxy',
    'insecure': True,
    'credentials': {
        'identifier': "some_id",
        'password': 'some_password'
    }
}


@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
@patch.object(demisto, "results")
def test_add_comment(mocker_results, mocker):
    mocker.patch.object(demisto, 'command', return_value='intsights-test-action')
    mocker.patch.object(demisto, 'params', return_value=INTSIGHTS_PARAMS)
    comment = 'Test Comment'
    mocker.patch.object(demisto, 'args', return_value={
        'alert-id': '5e7b0b5620d02a00085ab21e',
        'comment': comment
    })

    import IntSight

    patch('IntSight.http_request', Mock())
    IntSight.add_comment()
    assert(comment == mocker_results.call_args[0][0]['Contents']['Comment'])


@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
@patch.object(demisto, "results")
def test_add_tag(mocker_results, mocker):
    mocker.patch.object(demisto, 'command', return_value='intsights-test-action')
    mocker.patch.object(demisto, 'params', return_value=INTSIGHTS_PARAMS)
    mocker.patch.object(demisto, 'args', return_value={
        'alert-id': '5e7b0b5620d02a00085ab21e',
        'tag-name': 'Test Tag'
    })

    import IntSight

    tag_id = '1234'
    with patch('IntSight.http_request', Mock()) as mock_http_response:
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
        IntSight.add_tag()
        assert(tag_id == mocker_results.call_args[0][0]['Contents']['Tags']['ID'])


@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
@patch.object(demisto, "results")
def test_get_alert_takedown_status(mocker_results, mocker):
    mocker.patch.object(demisto, 'command', return_value='intsights-test-action')
    mocker.patch.object(demisto, 'params', return_value=INTSIGHTS_PARAMS)
    mocker.patch.object(demisto, 'args', return_value={'alert-id': '5e7b0b5620d02a00085ab21e'})

    import IntSight

    patch('IntSight.http_request', Mock())
    IntSight.get_alert_takedown_status()
    assert('TakedownStatus' in mocker_results.call_args[0][0]['Contents'] and not None)


@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
@patch.object(demisto, "results")
def test_ask_analyst(mocker_results, mocker):
    mocker.patch.object(demisto, 'command', return_value='intsights-test-action')
    mocker.patch.object(demisto, 'params', return_value=INTSIGHTS_PARAMS)
    question = 'What is the status?'
    mocker.patch.object(demisto, 'args', return_value={'alert-id': '5e7b0b5620d02a00085ab21e', 'question': question})

    import IntSight

    patch('IntSight.http_request', Mock())
    IntSight.ask_analyst()
    assert(question == mocker_results.call_args[0][0]['Contents']['Question'])


@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
@patch.object(demisto, "results")
def test_close_alert(mocker_results, mocker):
    mocker.patch.object(demisto, 'command', return_value='intsights-test-action')
    mocker.patch.object(demisto, 'params', return_value=INTSIGHTS_PARAMS)
    reason = 'Solved Internally'
    mocker.patch.object(demisto, 'args', return_value={'alert-id': '5e7b0b5620d02a00085ab21e', 'reason': reason})

    import IntSight

    patch('IntSight.http_request', Mock())
    IntSight.close_alert()
    assert(reason == mocker_results.call_args[0][0]['Contents']['Closed']['Reason'])


@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
@patch.object(demisto, "results")
def test_get_alert_image(mocker_results, mocker):
    mocker.patch.object(demisto, 'command', return_value='intsights-test-action')
    mocker.patch.object(demisto, 'params', return_value=INTSIGHTS_PARAMS)
    image_id = '123456789'
    mocker.patch.object(demisto, 'args', return_value={'image-id': image_id})

    import IntSight

    patch('IntSight.http_request', Mock())
    IntSight.get_alert_image()
    assert(image_id + '-image.jpeg' == mocker_results.call_args[0][0]['File'])


@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
@patch.object(demisto, "results")
def test_takedown_request(mocker_results, mocker):
    mocker.patch.object(demisto, 'command', return_value='intsights-test-action')
    mocker.patch.object(demisto, 'params', return_value=INTSIGHTS_PARAMS)
    alert_id = '123456789'
    mocker.patch.object(demisto, 'args', return_value={'alert-id': alert_id})

    import IntSight

    patch('IntSight.http_request', Mock())
    IntSight.takedown_request()
    assert(alert_id == mocker_results.call_args[0][0]['Contents']['ID'])


@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
@patch.object(demisto, "results")
def test_get_ioc_blocklist_status(mocker_results, mocker):
    mocker.patch.object(demisto, 'command', return_value='intsights-test-action')
    mocker.patch.object(demisto, 'params', return_value=INTSIGHTS_PARAMS)
    alert_id = '123456789'
    mocker.patch.object(demisto, 'args', return_value={'alert-id': alert_id})

    import IntSight

    mock_response = {
        "Value": "example.com",
        "Status": "Sent"
    }
    with patch('IntSight.http_request', Mock()) as mock_http_response:
        mock_http_response.return_value = [mock_response]
        IntSight.get_ioc_blocklist_status()
        assert(mock_response in mocker_results.call_args[0][0]['Contents'])


@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
@patch.object(demisto, "results")
def test_search_for_ioc(mocker_results, mocker):
    mocker.patch.object(demisto, 'command', return_value='intsights-test-action')
    mocker.patch.object(demisto, 'params', return_value=INTSIGHTS_PARAMS)
    value = 'test_value'
    mocker.patch.object(demisto, 'args', return_value={'value': value})

    import IntSight

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
    with patch('IntSight.http_request', Mock()) as mock_http_response:
        mock_http_response.return_value = mock_response
        IntSight.search_for_ioc()
        assert(value == mocker_results.call_args[0][0]['Contents']['Value'])


@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
@patch.object(demisto, "results")
def test_remove_tag(mocker_results, mocker):
    mocker.patch.object(demisto, 'command', return_value='intsights-test-action')
    mocker.patch.object(demisto, 'params', return_value=INTSIGHTS_PARAMS)
    tag_id = '12345'
    mocker.patch.object(demisto, 'args', return_value={'alert-id': '5e7b0b5620d02a00085ab21e', 'tag-id': tag_id})

    import IntSight

    patch('IntSight.http_request', Mock())
    IntSight.remove_tag()
    assert(tag_id == mocker_results.call_args[0][0]['Contents']['Tags']['ID'])


@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
@patch.object(demisto, "results")
def test_request_for_ioc_enrichment(mocker_results, mocker):
    mocker.patch.object(demisto, 'command', return_value='intsights-test-action')
    mocker.patch.object(demisto, 'params', return_value=INTSIGHTS_PARAMS)
    value = "test_value.com"

    mocker.patch.object(demisto, 'args', return_value={'value': value})

    import IntSight

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
    with patch('IntSight.http_request', Mock()) as mock_http_response:
        mock_http_response.return_value = mock_response
        IntSight.request_for_ioc_enrichment()
        assert(mock_response['OriginalValue'] == mocker_results.call_args[0][0]['Contents']['OriginalValue'])


@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
@patch.object(demisto, "results")
def test_send_mail(mocker_results, mocker):
    mocker.patch.object(demisto, 'command', return_value='intsights-test-action')
    mocker.patch.object(demisto, 'params', return_value=INTSIGHTS_PARAMS)

    alert_id = '5e7b0b5620d02a00085ab21e'
    mocker.patch.object(demisto, 'args', return_value={
        'alert-id': alert_id,
        'emails': ['me@domain.com', 'you@domain.com'],
        'content': 'API Question'
    })

    import IntSight

    patch('IntSight.http_request', Mock())
    IntSight.send_mail()
    assert(alert_id == mocker_results.call_args[0][0]['Contents']['ID'])


@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
@patch.object(demisto, "results")
def test_unassign_alert(mocker_results, mocker):
    mocker.patch.object(demisto, 'command', return_value='intsights-test-action')
    mocker.patch.object(demisto, 'params', return_value=INTSIGHTS_PARAMS)

    alert_id = '5e7b0b5620d02a00085ab21e'
    mocker.patch.object(demisto, 'args', return_value={
        'alert-id': alert_id
    })

    import IntSight

    patch('IntSight.http_request', Mock())
    IntSight.unassign_alert()
    assert(alert_id == mocker_results.call_args[0][0]['Contents']['ID'])


@patch.object(demisto, "results")
def test_change_severity(mocker_results, mocker):
    mocker.patch.object(demisto, 'command', return_value='intsights-test-action')
    mocker.patch.object(demisto, 'params', return_value=INTSIGHTS_PARAMS)

    severity = 'Low'
    mocker.patch.object(demisto, 'args', return_value={
        'alert-id': '5e7b0b5620d02a00085ab21e',
        'severity': 'Low'
    })

    import IntSight

    patch('IntSight.http_request', Mock())
    IntSight.change_severity()
    assert(severity == mocker_results.call_args[0][0]['Contents']['Severity'])


@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
@patch.object(demisto, "results")
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

    import IntSight

    patch('IntSight.http_request', Mock())
    IntSight.update_ioc_blocklist_status()
    assert(alert_id == mocker_results.call_args[0][0]['Contents']['ID'])


@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
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


@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
@patch('IntSight.http_request')
def run_mocked_https_request(mocked_http_request, action, side_effect=None, return_value=None):
    if side_effect:
        mocked_http_request.side_effect = side_effect
    else:
        mocked_http_request.return_value = side_effect

    action()


@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
@patch.object(demisto, "results")
def test_get_mssp_sub_accounts(mocker_results, mocker):
    INTSIGHTS_PARAMS['mssp_sub_account_id'] = '123456789'

    mocker.patch.object(demisto, 'command', return_value='intsights-test-action')
    mocker.patch.object(demisto, 'params', return_value=INTSIGHTS_PARAMS)

    import IntSight

    run_mocked_https_request(
        action=IntSight.get_mssp_sub_accounts,
        side_effect=get_mssp_sub_accounts_http_response
    )
    assert(10 == mocker_results.call_args[0][0]['Contents'][0]['AssetsLimit'])


@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
@patch.object(demisto, "results")
def test_get_iocs(mocker_results, mocker):
    mocker.patch.object(demisto, 'command', return_value='intsights-test-action')
    mocker.patch.object(demisto, 'params', return_value=INTSIGHTS_PARAMS)
    value = 'test_value'
    mocker.patch.object(demisto, 'args', return_value={'value': value})

    import IntSight

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

    with patch('IntSight.http_request', Mock()) as mock_http_response:
        mock_http_response.return_value = mock_response
        IntSight.search_for_ioc()
        assert(value == mocker_results.call_args[0][0]['Contents']['Value'])


@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
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


@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
@patch.object(demisto, "results")
def test_get_alerts(mocker_results, mocker):
    mocker.patch.object(demisto, 'command', return_value='intsights-test-action')
    mocker.patch.object(demisto, 'params', return_value=INTSIGHTS_PARAMS)

    import IntSight

    alert_id = '123456789'
    run_mocked_https_request(
        action=IntSight.get_alerts,
        side_effect=get_alerts_http_response
    )
    assert(alert_id == mocker_results.call_args[0][0]['Contents'][0]['ID'])


@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
@patch.object(demisto, "results")
def test_get_alert_by_id(mocker_results, mocker):
    mocker.patch.object(demisto, 'command', return_value='intsights-test-action')
    mocker.patch.object(demisto, 'params', return_value=INTSIGHTS_PARAMS)
    mocker.patch.object(demisto, 'args', return_value={'alert-id': '5e7b0b5620d02a00085ab21e'})

    import IntSight

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
    with patch('IntSight.http_request', Mock()) as mock_http_response:
        mock_http_response.return_value = complete_alert

        patch('IntSight.http_request', Mock())
        IntSight.get_alert_by_id()
        assert(complete_alert['_id'] == mocker_results.call_args[0][0]['Contents']['ID'])


@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
@patch.object(demisto, "results")
def test_get_alert_activity(mocker_results, mocker):
    mocker.patch.object(demisto, 'command', return_value='intsights-test-action')
    mocker.patch.object(demisto, 'params', return_value=INTSIGHTS_PARAMS)
    mocker.patch.object(demisto, 'args', return_value={'alert-id': '5e7b0b5620d02a00085ab21e'})

    import IntSight

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

    with patch('IntSight.http_request', Mock()) as mock_http_response:
        mock_http_response.return_value = [
            {
                'ID': '5e7b0b5620d02a00085ab21e',
                'Activities': [
                    activity
                ]
            }
        ]

        IntSight.get_alert_activity()
        assert('Activities' in mocker_results.call_args[0][0]['Contents'][0])


@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
@patch.object(demisto, "results")
def test_assign_alert(mocker_results, mocker):
    mocker.patch.object(demisto, 'command', return_value='intsights-test-action')
    mocker.patch.object(demisto, 'params', return_value=INTSIGHTS_PARAMS)
    mocker.patch.object(demisto, 'args', return_value={
        'alert-id': '5e7b0b5620d02a00085ab21e',
        'assignee-email': 'email@domain.com',
        'is-mssp-optional': 'false'
    })

    import IntSight

    assignee_id = '12345'
    with patch('IntSight.http_request', Mock()) as mock_http_response:
        mock_http_response.return_value = [
            {
                "Email": "email@domain.com",
                "_id": assignee_id
            }
        ]
        IntSight.assign_alert()
        assert(assignee_id == mocker_results.call_args[0][0]['Contents']['Assignees.AssigneeID'])
