import json
import pytest
from unittest.mock import patch
import demistomock as demisto

params = {
    "api_endpoint": "https://notexisting.gem.security/api/v1",
    "client_id": "client_id",
    "client_secret": "client_secret",
    "firstFetch": True,
    "max_fetch": "10",
}

mock_auth_token = "mock_auth_token"


@pytest.fixture(autouse=True)
def set_mocks(mocker):
    mocker.patch.object(demisto, 'params', return_value=params)


test_fetch_incidents_data = [
    {"id": "00000000-0000-0000-0000-000000000000",
     "type": "Threat",
     "link": "A link",
     "title": "A title",
     "description": "A description",
     "metadata": {
         "title": "A title",
         "events": [

         ],
         "account": "123456789012",
         "alert_id": "00000000-0000-0000-0000-000000000000",
         "severity": 6,
         "timeframe": {
             "start": "2023-03-09T12:41:33.000000",
             "end": "2023-03-09T12:41:33.000000"
         },

         "attributes": {},
         "created_at": "2023-03-09T12:41:33.000000",
         "description": "A description",
         "main_entity": {
             "id": "an id",
             "type": "ExternalUser"
         },
         "account_name": "test account",
         "cloud_provider": "aws",
     },
     "event_datetime": "2023-03-09T12:41:33.000000",
     "created": "2023-03-09T12:41:33.000000",
     "severity": 8,
     "account": {
         "name": "123456789012",
         "display_name": "test account",
         "cloud_provider": "aws"
     }
     }
]


@patch('Gem.GemClient._generate_token', return_value=mock_auth_token)
@patch('Gem.BaseClient._http_request', return_value=test_fetch_incidents_data)
def test_fetch_incidents(_http_request, _generate_token):
    from Gem import fetch_threats, init_client
    client = init_client(params)
    last_run, incidents = fetch_threats(client, max_results=1, last_run={}, first_fetch_time="3 days")
    assert json.loads(incidents[0]['rawJSON']) == test_fetch_incidents_data[0]


test_get_threat_details_data = {
    "id": "00000000-0000-0000-0000-000000000000",
    "type": "Threat",
    "link": "A link",
    "title": "A title",
    "description": "A description",
    "event_datetime": "2023-03-09T12:41:33.000000",
    "event": {
        "alert_id": "00000000-0000-0000-0000-000000000000",
        "alert_source": "Gem",
        "threat_id": "11111111-1111-1111-1111-111111111111",
        "created_at": "2023-03-09T12:41:33.000000",
        "secondary_entities": [
            {
                "id": "Example RDS",
                "type": "rds_cluster",
                "metadata": {
                    "name": "Example RDS",
                    "region": None,
                    "account_id": None,
                    "context_from_event": None,
                    "arn_id": "Example RDS"
                },
                "name": "Example RDS",
                "cloud_provider": "aws"
            }
        ],
        "timeframe": {
            "start": "2023-03-09T12:41:33.000000",
            "end": "2023-03-09T12:41:33.000000"
        },
        "events": [],
        "events_total_count": 0,
        "attributes": {
            "bucket_name": "collected-data"
        },
        "main_entity": {
            "id": "Example IAM",
            "type": "iam_user",
            "metadata": {
                "name": "Example IAM",
                "region": "global",
                "account_id": None,
                "context_from_event": None,
                "arn_id": "Example IAM",
                "access_key": None,
                "user_name": "Example IAM"
            },
            "name": "Example IAM",
            "cloud_provider": "aws"
        },
        "ttp_id": "AWS/DefenseEvasion:S3/PublicAccessBlockPolicyModified"
    },
    "account": {
        "name": "123456789012",
        "display_name": "test account",
        "cloud_provider": "aws"
    },
    "severity": 5,
    "severity_text": "Medium"
}


@patch('Gem.GemClient._generate_token', return_value=mock_auth_token)
@patch('Gem.BaseClient._http_request', return_value=test_get_threat_details_data)
def test_get_threat_details(_http_request, _generate_token):
    from Gem import get_threat_details, init_client
    client = init_client(params)
    args = {
        "threat_id": "11111111-1111-1111-1111-111111111111"
    }
    res = get_threat_details(client, args)
    assert res.outputs == test_get_threat_details_data


test_list_threats_data = {'count': 1, 'next': None, 'previous': None, 'results': [test_get_threat_details_data]}


@patch('Gem.GemClient._generate_token', return_value=mock_auth_token)
@patch('Gem.BaseClient._http_request', return_value=test_list_threats_data)
def test_list_threats(_http_request, _generate_token):
    from Gem import list_threats, init_client
    client = init_client(params)
    args = {
        "time_start": "2024-03-01",
        "time_end": "2024-03-02"
    }
    res = list_threats(client, args)
    assert res.outputs == test_list_threats_data['results']


test_get_alert_details_data = {
    "alert_context": {
        "alert_id": "00000000-0000-0000-0000-000000000000",
        "title": "A title",
        "timeframe_start": "2023-03-09T12:41:33.000000",
        "timeframe_end": "2023-03-09T12:41:33.000000",
        "severity": 6,
        "resolved": False,
        "description": "A description",
        "description_template": "A description",
        "general_cloud_provider": "aws",
        "cloud_provider": "aws",
        "status": "open",
        "mitre_techniques": [
            {
                "technique_name": "A technique",
                "id": "1111"
            }
        ],
        "ttp_id": "WS/DefenseEvasion:S3/PublicAccessBlockPolicyModified",
        "account_db_id": "8",
        "alert_source": "GemDetection",
        "alert_source_id": None,
        "alert_source_url": None,
        "created_at": "2024-01-29T13:35:49.417627Z"
    },
    "triage_configuration": {
        "analysis": "",
        "entities": [
            {
                "id": "Example IAM",
                "type": "iam_user",
                "metadata": {
                    "name": "Example IAM",
                    "region": "global",
                    "account_id": None,
                    "context_from_event": None,
                    "arn_id": "Example IAM",
                    "access_key": None,
                    "user_name": "Example IAM"
                },
                "resource_id": None,
                "is_main_entity": False,
                "is_secondary_entity": True,
                "activity_by_provider": {},
                "cloud_provider": "aws"
            }
        ],
        "event_groups": [
            {
                "type": "triggering",
                "title": "A title",
                "description": "A description",
                "event_name": "An event",
                "events": [
                    "00000000-0000-0000-0000-000000000000"
                ],
                "event_type": "CloudTrail",
                "start_time": "2023-03-09T12:41:33.000000",
                "end_time": "2023-03-09T12:41:33.000000",
                "time_indicator_text": None,
                "timeline_item_type": "event_group",
                "events_metadata": {
                    "00000000-0000-0000-0000-000000000000": {
                        "source_entity": {
                            "id": "Example IAM",
                            "metadata": {},
                            "type": "iam_user",
                            "name": None
                        },
                        "target_entities": [
                            {
                                "id": "Example RDS",
                                "type": "rds_cluster",
                                "metadata": {},
                                "name": None
                            }
                        ]
                    }
                },
                "metadata": {},
                "error_code": None
            }
        ],
        "state": "extended",
        "resolve_params": {
            "timeframe_lookup_window_hours": 24,
            "include_data_events": True
        }
    }
}


@patch('Gem.GemClient._generate_token', return_value=mock_auth_token)
@patch('Gem.BaseClient._http_request', return_value=test_get_alert_details_data)
def test_get_alert_details(_http_request, _generate_token):
    from Gem import get_alert_details, init_client
    client = init_client(params)
    args = {
        "alert_id": "00000000-0000-0000-0000-000000000000"
    }
    res = get_alert_details(client, args)
    assert res.outputs == test_get_alert_details_data


test_get_resource_details_data = {
    "resource_id": "11111111-1111-1111-1111-111111111111",
    "account": {
        "id": 123,
        "display_name": "display_name",
        "organization_name": "organization_name",
        "identifier": "11111111-1111-1111-1111-111111111111",
        "hierarchy_path": [],
        "account_status": "accessible",
        "tenant": "11111111-1111-1111-1111-111111111111",
        "cloud_provider": "azure_tenant"
    },
    "region": "region",
    "resource_type": "resource_type",
    "created_at": "2023-03-01T12:37:16Z",
    "identifiers": [],
    "external_url": "",
    "tags": {},
    "deleted": False,
    "categories": [
        "Identity"
    ]
}


@patch('Gem.GemClient._generate_token', return_value=mock_auth_token)
@patch('Gem.BaseClient._http_request', return_value=test_get_resource_details_data)
def test_get_resource_details(_http_request, _generate_token):
    from Gem import get_resource_details, init_client
    client = init_client(params)
    args = {
        "resource_id": "11111111-1111-1111-1111-111111111111"
    }
    res = get_resource_details(client, args)
    assert res.outputs == test_get_resource_details_data


test_list_inventory_resources_data = {'next': None, 'previous': None, 'results': [test_get_resource_details_data]}


@patch('Gem.GemClient._generate_token', return_value=mock_auth_token)
@patch('Gem.BaseClient._http_request', return_value=test_list_inventory_resources_data)
def test_list_inventory_resources(_http_request, _generate_token):
    from Gem import list_inventory_resources, init_client
    client = init_client(params)
    args = {
        "limit": "1"
    }
    res = list_inventory_resources(client, args)
    assert res.outputs == test_list_inventory_resources_data['results']


test_list_ips_by_entity_data = {
    "table": {
        "headers": [
            "SOURCEIPADDRESS",
            "COUNT_SOURCEIP",
            "CITY",
            "LONGITUDE",
            "LATITUDE",
            "IP_TYPE",
            "COUNTRY_CODE"
        ],
        "rows": [
            {
                "row": {
                    "SOURCEIPADDRESS": "1.1.1.1",
                    "COUNT_SOURCEIP": "4037",
                    "IP_TYPE": "external",
                    "COUNTRY_CODE": "IL",
                    "COUNTRY_NAME": "Israel",
                    "AS_NAME": "As Name",
                    "AS_NUMBER": "11111",
                    "CITY": "a city",
                    "LONGITUDE": "longitude",
                    "LATITUDE": "latitude",
                    "PROVIDER": "provider",
                    "IS_PRIVATE": "False"
                }
            },
            {
                "row": {
                    "SOURCEIPADDRESS": "2.2.2.2",
                    "COUNT_SOURCEIP": "499",
                    "IP_TYPE": "external",
                    "COUNTRY_CODE": "NL",
                    "COUNTRY_NAME": "Amsterdam",
                    "AS_NAME": "As Name",
                    "AS_NUMBER": "22222",
                    "CITY": "a city",
                    "LONGITUDE": "longitude",
                    "LATITUDE": "latitude",
                    "PROVIDER": "provider",
                    "IS_PRIVATE": "False"
                }
            }

        ]
    }
}


@patch('Gem.GemClient._generate_token', return_value=mock_auth_token)
@patch('Gem.BaseClient._http_request', return_value=test_list_ips_by_entity_data)
def test_list_ips_by_entity(_http_request, _generate_token):
    from Gem import list_ips_by_entity, init_client
    client = init_client(params)
    args = {
        "entity_id": "11111111-1111-1111-1111-111111111111",
        "entity_type": "rds_cluster",
        "start_time": "2024-03-01",
        "end_time": "2024-03-02"
    }
    res = list_ips_by_entity(client, args)
    assert res.outputs[0] == test_list_ips_by_entity_data['table']['rows'][0]['row']


test_list_services_by_entity_data = {
    "table": {
        "headers": [
            "SERVICE",
            "COUNT_SERVICE"
        ],
        "rows": [
            {
                "row": {
                    "SERVICE": "A service",
                    "COUNT_SERVICE": "567"
                }
            },
            {
                "row": {
                    "SERVICE": "Another service",
                    "COUNT_SERVICE": "524"
                }
            }
        ]
    }
}


@patch('Gem.GemClient._generate_token', return_value=mock_auth_token)
@patch('Gem.BaseClient._http_request', return_value=test_list_services_by_entity_data)
def test_list_services_by_entity(_http_request, _generate_token):
    from Gem import list_services_by_entity, init_client
    client = init_client(params)
    args = {
        "entity_id": "11111111-1111-1111-1111-111111111111",
        "entity_type": "rds_cluster",
        "start_time": "2024-03-01",
        "end_time": "2024-03-02"
    }
    res = list_services_by_entity(client, args)

    assert res.outputs[0] == test_list_services_by_entity_data['table']['rows'][0]['row']


test_list_events_by_entity_data = {
    "table": {
        "headers": [
            "EVENTNAME",
            "EVENTNAME_COUNT"
        ],
        "rows": [
            {
                "row": {
                    "EVENTNAME": "An event",
                    "EVENTNAME_COUNT": "6"
                }
            },
            {
                "row": {
                    "EVENTNAME": "Another event",
                    "EVENTNAME_COUNT": "1"
                }
            }
        ]
    }
}


@patch('Gem.GemClient._generate_token', return_value=mock_auth_token)
@patch('Gem.BaseClient._http_request', return_value=test_list_events_by_entity_data)
def test_list_events_by_entity(_http_request, _generate_token):
    from Gem import list_events_by_entity, init_client
    client = init_client(params)
    args = {
        "entity_id": "11111111-1111-1111-1111-111111111111",
        "entity_type": "rds_cluster",
        "start_time": "2024-03-01",
        "end_time": "2024-03-02"
    }
    res = list_events_by_entity(client, args)
    assert res.outputs[0] == test_list_events_by_entity_data['table']['rows'][0]['row']


test_list_accessing_entities_data = {
    "table": {
        "headers": [
            "USER_ID",
            "USER_COUNT"
        ],
        "rows": [
            {
                "row": {
                    "USER_ID": "user id",
                    "USER_COUNT": "4"
                }
            }
        ]
    }
}


@patch('Gem.GemClient._generate_token', return_value=mock_auth_token)
@patch('Gem.BaseClient._http_request', return_value=test_list_accessing_entities_data)
def test_list_accessing_entities(_http_request, _generate_token):
    from Gem import list_accessing_entities, init_client
    client = init_client(params)
    args = {
        "entity_id": "ec2/instance/id",
        "entity_type": "ec2_instance",
        "start_time": "2024-03-01",
        "end_time": "2024-03-02"
    }
    res = list_accessing_entities(client, args)
    assert res.outputs[0] == test_list_accessing_entities_data['table']['rows'][0]['row']


test_list_using_entities_data = {
    "table": {
        "headers": [
            "ENTITY_ID",
            "ENTITY_COUNT"
        ],
        "rows": [
            {
                "row": {
                    "ENTITY_ID": "entity id",
                    "ENTITY_COUNT": "4"
                }
            }
        ]
    }
}


@patch('Gem.GemClient._generate_token', return_value=mock_auth_token)
@patch('Gem.BaseClient._http_request', return_value=test_list_using_entities_data)
def test_list_using_entities(_http_request, _generate_token):
    from Gem import list_using_entities, init_client
    client = init_client(params)
    args = {
        "entity_id": "1.1.1.1",
        "entity_type": "external_ip",
        "start_time": "2024-03-01",
        "end_time": "2024-03-02"
    }
    res = list_using_entities(client, args)
    assert res.outputs[0] == test_list_using_entities_data['table']['rows'][0]['row']


test_list_events_on_entity_data = {
    "table": {
        "headers": [
            "EVENTNAME",
            "EVENTNAME_COUNT"
        ],
        "rows": [
            {
                "row": {
                    "EVENTNAME": "An event",
                    "EVENTNAME_COUNT": "6"
                }
            },
            {
                "row": {
                    "EVENTNAME": "Another event",
                    "EVENTNAME_COUNT": "1"
                }
            }
        ]
    }
}


@patch('Gem.GemClient._generate_token', return_value=mock_auth_token)
@patch('Gem.BaseClient._http_request', return_value=test_list_events_on_entity_data)
def test_list_events_on_entity(_http_request, _generate_token):
    from Gem import list_events_on_entity, init_client
    client = init_client(params)
    args = {
        "entity_id": "security group id",
        "entity_type": "security_group",
        "start_time": "2024-03-01",
        "end_time": "2024-03-02"
    }
    res = list_events_on_entity(client, args)
    assert res.outputs[0] == test_list_events_on_entity_data['table']['rows'][0]['row']


test_list_accessing_ips_data = {
    "table": {
        "headers": [
            "SOURCEIPADDRESS",
            "COUNT_SOURCEIP",
            "CITY",
            "LONGITUDE",
            "LATITUDE",
            "IP_TYPE",
            "COUNTRY_CODE"
        ],
        "rows": [
            {
                "row": {
                    "SOURCEIPADDRESS": "1.1.1.1",
                    "COUNT_SOURCEIP": "4037",
                    "IP_TYPE": "external",
                    "COUNTRY_CODE": "IL",
                    "COUNTRY_NAME": "Israel",
                    "AS_NAME": "As Name",
                    "AS_NUMBER": "11111",
                    "CITY": "a city",
                    "LONGITUDE": "longitude",
                    "LATITUDE": "latitude",
                    "PROVIDER": "provider",
                    "IS_PRIVATE": "False"
                }
            },
            {
                "row": {
                    "SOURCEIPADDRESS": "2.2.2.2",
                    "COUNT_SOURCEIP": "499",
                    "IP_TYPE": "external",
                    "COUNTRY_CODE": "NL",
                    "COUNTRY_NAME": "Amsterdam",
                    "AS_NAME": "As Name",
                    "AS_NUMBER": "22222",
                    "CITY": "a city",
                    "LONGITUDE": "longitude",
                    "LATITUDE": "latitude",
                    "PROVIDER": "provider",
                    "IS_PRIVATE": "False"
                }
            }

        ]
    }
}


@patch('Gem.GemClient._generate_token', return_value=mock_auth_token)
@patch('Gem.BaseClient._http_request', return_value=test_list_accessing_ips_data)
def test_list_accessing_ips(_http_request, _generate_token):
    from Gem import list_accessing_ips, init_client
    client = init_client(params)
    args = {
        "entity_id": "security group id",
        "entity_type": "security_group",
        "start_time": "2024-03-01",
        "end_time": "2024-03-02"
    }
    res = list_accessing_ips(client, args)
    assert res.outputs[0] == test_list_accessing_ips_data['table']['rows'][0]['row']


test_update_threat_status_data = None


@patch('Gem.GemClient._generate_token', return_value=mock_auth_token)
@patch('Gem.BaseClient._http_request', return_value=test_update_threat_status_data)
def test_update_threat_status(_http_request, _generate_token):
    from Gem import update_threat_status, init_client
    client = init_client(params)
    args = {
        "threat_id": "11111111-1111-1111-1111-111111111111",
        "status": "open"
    }
    res = update_threat_status(client, args)
    assert res is None


test_run_action_on_entity_data = {}


@patch('Gem.GemClient._generate_token', return_value=mock_auth_token)
@patch('Gem.BaseClient._http_request', return_value=test_run_action_on_entity_data)
def test_run_action_on_entity(_http_request, _generate_token):
    from Gem import run_action_on_entity, init_client
    client = init_client(params)
    args = {
        "action": "stop",
        "entity_id": "ec2 instance id",
        "entity_type": "ec2_instance",
        "alert_id": "00000000-0000-0000-0000-000000000000",
        "resource_id": "ec2 instance id",
    }
    res = run_action_on_entity(client, args)
    assert res.outputs == test_run_action_on_entity_data


test_add_timeline_event_data = {}


@patch('Gem.GemClient._generate_token', return_value=mock_auth_token)
@patch('Gem.BaseClient._http_request', return_value=test_add_timeline_event_data)
def test_add_timeline_event(_http_request, _generate_token):
    from Gem import add_timeline_event, init_client
    client = init_client(params)
    args = {
        "threat_id": "11111111-1111-1111-1111-111111111111",
        "comment": "A comment",
    }
    res = add_timeline_event(client, args)
    assert res.outputs == test_add_timeline_event_data
