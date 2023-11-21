"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

from freezegun import freeze_time
import AttackSurfaceManagement
from CommonServerPython import *
import pytest
import json
import io

import sys
import os

sys.path.append(os.getcwd())

SERVER_URL = "https://asm-api.advantage.mandiant.com/api/v1"

MOCK_GET_PROJECTS_RESPONSE = {
    "success": True,
    "message": "Projects",
    "result": [
        {
            "id": 6797,
            "created_at": "2022-08-18T16:10:20.842Z",
            "uuid": "be884e25-a0bb-4836-a836-df5eab176186",
            "icon": "🏡",
            "role": "owner",
            "name": "ASMQA_AttackSurfaceAPP",
            "owner_email": "name@attacksurface.app",
            "description": None,
            "expired_at": None,
            "organization_name": "ASMQA AttackSurfaceAPP",
            "organization_uuid": "075892c8-fe6f-454e-a071-34a7342c16a3",
            "plan_expires_at": "2025-09-17T00:00:00.000Z",
            "plan_status": "paid",
            "deleted_at": None,
            "deleted": False,
            "primary": False
        }
    ]
}

MOCK_GET_COLLECTIONS_RESPONSE = {
    "success": True,
    "message": "User collections",
    "result": [
        {
            "id": 132956,
            "uuid": "c1b502fe-1020-4a85-a620-e02614526ee9",
            "type": "user_collection",
            "name": "attacksurface_mw3tdwq",
            "following": None,
            "auto_refresh_schedule": "daily",
            "workflow_name": None,
            "printable_name": "Attacksurface_APP_QA",
            "tags": [],
            "last_updated": "2022-09-09T16:48:13.000Z",
            "created_at": "2022-08-18T16:10:20.930Z",
            "deleted": False,
            "deleted_at": None,
            "deleted_by": None,
            "local_icon_path": "/branding/icons/org.png",
            "entity_count": 1,
            "new_entity_count": 1,
            "total_entity_count": 16,
            "issues_by_severity": {
                "4": 1,
                "5": 3
            },
            "notify_emails_new_entities": None,
            "notify_webhooks_new_entities": None,
            "pointer_collection_id": None,
            "pointer_collection_uuid": None,
            "config": None,
            "refreshing": False,
            "project_id": 6797,
            "project_uuid": "be884e25-a0bb-4836-a836-df5eab176186",
            "project_name": "ASMQA_AttackSurfaceAPP",
            "owner_id": 6797,
            "owner_uuid": "be884e25-a0bb-4836-a836-df5eab176186",
            "owner_type": "project",
            "owner_name": "ASMQA_AttackSurfaceAPP",
            "role": "admin"
        }
    ]
}

MOCK_FETCH_ISSUES_RESPONSE = {
    "success": True,
    "message": "Search completed!",
    "result": {
        "search": {
            "search_body": {
                "query": {
                    "bool": {
                        "must": {
                            "range": {
                                "first_seen": {
                                    "gte": "2022-01-01T00:00:00Z"
                                }
                            }
                        },
                        "filter": {
                            "bool": {
                                "should": [
                                    {
                                        "bool": {
                                            "must": [
                                                {
                                                    "match": {
                                                        "collection": "collectionname_a6mz56o"
                                                    }
                                                },
                                                {
                                                    "range": {
                                                        "last_seen": {
                                                            "lte": "2023-01-31T18:59:39Z"
                                                        }
                                                    }
                                                }
                                            ]
                                        }
                                    }
                                ]
                            }
                        }
                    }
                },
                "aggs": {
                    "collection_bucket": {
                        "terms": {
                            "field": "collection",
                            "size": 10
                        }
                    },
                    "confidence": {
                        "terms": {
                            "field": "summary.confidence",
                            "size": 3
                        }
                    },
                    "issue_name_bucket": {
                        "terms": {
                            "field": "name.raw",
                            "size": 10
                        }
                    },
                    "severity_bucket": {
                        "terms": {
                            "field": "summary.severity",
                            "size": 5
                        }
                    },
                    "status_bucket": {
                        "terms": {
                            "field": "summary.status",
                            "size": 10
                        }
                    },
                    "status_new_bucket": {
                        "terms": {
                            "field": "summary.status_new.raw",
                            "size": 10
                        }
                    },
                    "status_detailed_bucket": {
                        "terms": {
                            "field": "summary.status_detailed.raw",
                            "size": 10
                        }
                    },
                    "ticket_list_bucket": {
                        "terms": {
                            "field": "summary.ticket_list.raw",
                            "size": 50
                        }
                    }
                },
                "sort": [
                    {
                        "last_seen": "asc"
                    },
                    "_doc"
                ]
            },
            "search_string": "collection:collectionname_a6mz56o first_seen_after:2022-01-01 last_seen_before:last_refresh",
            "search_type": "issues",
            "sort_direction": "asc",
            "sort_field": "last_seen",
            "group_by_field": None
        },
        "total_hits": 3945,
        "timed_out": False,
        "more": False,
        "page": 0,
        "page_size": 1,
        "total_pages": 3945,
        "hits": [
            {
                "id": "2e0134b5b346a5d0a9d5ee0efe7dfb69dfcc5c1cf65a6df63568f85dc587a120",
                "alias_group": "86373",
                "dynamic_id": 21852016,
                "name": "inferred_cve_2019_10081",
                "first_seen": "2022-10-07T17:36:37.000Z",
                "last_seen": "2022-10-07T17:36:37.000Z",
                "collection": "collectionname_a6mz56o",
                "collection_type": "user_collection",
                "collection_uuid": "f12c71db-d34d-4733-a19e-b8742ed7eb70",
                "organization_uuid": "075892c8-fe6f-454e-a071-34a7342c16a3",
                "entity_type": "Intrigue::Entity::Uri",
                "entity_name": "https://www.fakeurl.eu:443",
                "entity_uid": "2a7cdfb23b2253a9ea4cc88962e0b7cd9b1622f7d44e56f675a8700b934d1f51",
                "upstream": "intrigue",
                "summary": {
                    "pretty_name": "Apache HTTPD 2.4.39 mod_http2 Resource Exhaustion Vulnerability (Inferred CVE-2019-10081)",
                    "severity": 2,
                    "scoped": True,
                    "confidence": "potential",
                    "status": "open_new",
                    "category": "unknown",
                    "identifiers": [
                        {
                            "name": "CVE-2019-10081",
                            "type": "CVE"
                        }
                    ],
                    "status_new": "open",
                    "status_new_detailed": "new",
                    "ticket_list": []
                },
                "tags": []
            }
        ],
        "aggregations": {
            "severity_bucket": {
                "doc_count_error_upper_bound": 0,
                "sum_other_doc_count": 0,
                "buckets": [
                    {
                        "key": "1",
                        "doc_count": 1697
                    },
                    {
                        "key": "3",
                        "doc_count": 798
                    },
                    {
                        "key": "2",
                        "doc_count": 726
                    },
                    {
                        "key": "5",
                        "doc_count": 569
                    },
                    {
                        "key": "4",
                        "doc_count": 155
                    }
                ]
            },
            "ticket_list_bucket": {
                "doc_count_error_upper_bound": 0,
                "sum_other_doc_count": 0,
                "buckets": []
            },
            "issue_name_bucket": {
                "doc_count_error_upper_bound": 0,
                "sum_other_doc_count": 2220,
                "buckets": [
                    {
                        "key": "inferred_cve_2021_40438",
                        "doc_count": 265
                    },
                    {
                        "key": "inferred_cve_2020_11022",
                        "doc_count": 248
                    },
                    {
                        "key": "inferred_cve_2020_11023",
                        "doc_count": 248
                    },
                    {
                        "key": "inferred_cve_2019_11358",
                        "doc_count": 237
                    },
                    {
                        "key": "inferred_cve_2015_9251",
                        "doc_count": 206
                    },
                    {
                        "key": "deprecated_ssl_protocol_detected",
                        "doc_count": 178
                    },
                    {
                        "key": "weak_ssl_ciphers_enabled",
                        "doc_count": 99
                    },
                    {
                        "key": "wordpress_api_exposed",
                        "doc_count": 88
                    },
                    {
                        "key": "wordpress_admin_login_exposed",
                        "doc_count": 81
                    },
                    {
                        "key": "wordpress_user_info_leak",
                        "doc_count": 75
                    }
                ]
            },
            "status_bucket": {
                "doc_count_error_upper_bound": 0,
                "sum_other_doc_count": 0,
                "buckets": [
                    {
                        "key": "open_new",
                        "doc_count": 3940
                    },
                    {
                        "key": "open_triaged",
                        "doc_count": 3
                    },
                    {
                        "key": "closed_benign",
                        "doc_count": 1
                    },
                    {
                        "key": "closed_tracked_externally",
                        "doc_count": 1
                    }
                ]
            },
            "collection_bucket": {
                "doc_count_error_upper_bound": 0,
                "sum_other_doc_count": 0,
                "buckets": [
                    {
                        "key": "collectionname_a6mz56o",
                        "doc_count": 3945
                    }
                ]
            },
            "confidence": {
                "doc_count_error_upper_bound": 0,
                "sum_other_doc_count": 0,
                "buckets": [
                    {
                        "key": "potential",
                        "doc_count": 2834
                    },
                    {
                        "key": "confirmed",
                        "doc_count": 1111
                    }
                ]
            },
            "status_new_bucket": {
                "doc_count_error_upper_bound": 0,
                "sum_other_doc_count": 0,
                "buckets": [
                    {
                        "key": "open",
                        "doc_count": 3943
                    },
                    {
                        "key": "closed",
                        "doc_count": 2
                    }
                ]
            },
            "status_detailed_bucket": {
                "doc_count_error_upper_bound": 0,
                "sum_other_doc_count": 0,
                "buckets": []
            }
        },
        "next_page_token": "eyJhbGciOiJBMjU2R0NNS1ciLCJlbmMiOiJBMjU2R0NNIiwiaXYiOiJDMmhPQlRweE5jT2psUTNlIiwidGFnIjoiTGp"
                           "qaFhvQ1F0RWZjXzdJTkt4ZG5XZyJ9.MmWAi13CT942tNOv07i7l40wt9wm4XKt9PZ10x34cu0.0GDiGDyp6Snff9mk."
                           "MVB3X0pjYjkN8-9-glzlVQl5VjsAMkxtkFN_A8ZELCUGnpSg-pUEfMntNZ4iglMLk7amm4Bh7saZ2QGzNRLCmGcwIxl"
                           "mSqTWqB1UrSRRkdMpHec5O1EdAyh41SK4B2Vh8DnTnBwLQFYdExi82oNobIX5tWdJmVKdsAFFm7F_0gW1J2TR49HreX"
                           "yXxv5UtCRvFf3FlqvbPzWEO6cyQ8eMUuNEGvLi_F5YncAfxwsjuNY-FHk-TUl0aUOEj3mD4ZnaokFI4HK6SB95SqJ7W"
                           "CFSf3iSulVSMihnuJ7e0V_YCS9Lrk8n6DSOHdPelQ.-Z1v3MQn335tNg7FcflqPA"
    }
}

MOCK_GET_REMOTE_DATA_RESPONSE = {
    "success": True,
    "message": "successfully returned issue",
    "result": {
        "uuid": "9fc77fef-6362-4aef-a154-0ab4a058d5de",
        "dynamic_id": 6437944,
        "entity_uid": "a4cfa1f3c7864d343f8b9568248ad7550400598ddf10ea18959c860ca6253a01",
        "alias_group": "1156748",
        "category": "misconfiguration",
        "confidence": "confirmed",
        "description": "This server is configured to allow a deprecated ssl / tls protocol.",
        "details": {
            "name": "deprecated_ssl_protocol_detected",
            "added": "2020-01-01",
            "proof": {
                "details": {
                    "type": "tls",
                    "enabled": "1",
                    "version": "1.1"
                },
                "description": "Target supports deprecated protocol tls with version 1.1"
            },
            "source": "tls:1.1",
            "category": "misconfiguration",
            "severity": "5",
            "references": [
                {
                    "uri": "https://tools.ietf.org/id/draft-moriarty-tls-oldversions-diediedie-00.html",
                    "type": "description"
                }
            ],
            "description": "This server is configured to allow a deprecated ssl / tls protocol.",
            "pretty_name": "Deprecated SSL/TLS Protocol Detected",
            "remediation": "Disable the weak protocol according the the instructions for your web server."
        },
        "first_seen": "2022-08-18T17:12:20.000Z",
        "identifiers": None,
        "last_seen": "2022-08-23T20:05:56.000Z",
        "name": "deprecated_ssl_protocol_detected",
        "pretty_name": "Deprecated SSL/TLS Protocol Detected",
        "scoped": True,
        "severity": 5,
        "source": None,
        "status": "open_triaged",
        "ticket_list": None,
        "type": "standard",
        "uid": "8e02af6c136f297aa8fece36726a6d659bf59f512ca8a90350d93038215a19d7",
        "upstream": "tls:1.1",
        "created_at": "2022-09-25T05:21:20.000Z",
        "updated_at": "2023-02-11T17:39:17.810Z",
        "entity_id": 186794841,
        "collection_id": 132956,
        "elasticsearch_mappings_hash": None,
        "collection": "collectionname_mw3tdwq",
        "collection_type": "user_collection",
        "collection_uuid": "cb502f1e-10a8-4520-a620-e02614526ee9",
        "organization_uuid": "092c7588-fe6f-454e-a071-34a7342c16a3",
        "entity_name": "https://domain.app:443",
        "entity_type": "Intrigue::Entity::Uri",
        "summary": {
            "pretty_name": "Deprecated SSL/TLS Protocol Detected",
            "severity": 5,
            "scoped": True,
            "confidence": "confirmed",
            "status": "open_triaged",
            "category": "misconfiguration",
            "identifiers": None,
            "status_new": "open",
            "status_new_detailed": "triaged",
            "ticket_list": None
        },
        "tags": []
    }
}

MOCK_GET_REMOTE_DATA_NOTES_RESPONSE = {
    "success": True,
    "message": "Notes for issue 6b884a854d4998f787e1dde6b937f0ca63c844dcfe9558e1c2758cef0ca6d459",
    "result": [
        {
            "created_at": "2022-09-09 16:45:52 UTC",
            "collection": "attacksurface_mw3tdwq",
            "created_by": "c1ac6a07-fda8-4568-90c3-ea2ba6ec2535",
            "created_by_user": {
                "printable_name": "test_user"
            },
            "uid": "ee74ee7d3c06791bf984480810169ab123d97541b39afd623bd08b3981450d93",
            "item_type": "issue",
            "updated_at": "2022-09-09T16:45:52Z",
            "item_name": "weak_ssl_ciphers_enabled",
            "note": "- testing a note that supports markdown\n- and has some neat new features",
            "note_type": "issue",
            "organization_uuid": "",
            "item_uid": "6b884a854d4998f787e1dde6b937f0ca63c844dcfe9558e1c2758cef0ca6d459",
            "id": "issue#issue#weak_ssl_ciphers_enabled#c1ac6a07-fda8-4568-90c3-ea2ba6ec2535#2022-09-09T16:45:52Z",
            "entity_uid": "73084b532388540a4dc9fd951eb9369fd03ae312d20e45b553f670c84e8340c8"
        }
    ]
}


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.fixture()
def client() -> AttackSurfaceManagement.Client:
    return AttackSurfaceManagement.Client(
        access_key='FAKE_ACCESS_KEY',
        secret_key='fake_secret_key',
        project_id=1234,
        collection_ids=['12341234', '23452345'],
        base_url=SERVER_URL,
        verify=False,
        proxy=False,
        timeout=60,
        limit=100
    )


def test_get_projects(client: AttackSurfaceManagement.Client, requests_mock):
    requests_mock.get(f'{SERVER_URL}/projects', headers={'content-type': 'application/json'},
                      json=MOCK_GET_PROJECTS_RESPONSE)

    results = AttackSurfaceManagement.get_projects(client, None)

    results_dict = results.to_context()
    project_result = results_dict['Contents'][0]

    assert project_result['Name'] == 'ASMQA_AttackSurfaceAPP'
    assert project_result['ID'] == 6797
    assert project_result['Owner'] == 'name@attacksurface.app'


def test_get_collections_no_project(client: AttackSurfaceManagement.Client, requests_mock):
    requests_mock.get(f'{SERVER_URL}/user_collections', request_headers={'PROJECT_ID': '1234'},
                      headers={'content-type': 'application/json'}, json=MOCK_GET_COLLECTIONS_RESPONSE)

    results = AttackSurfaceManagement.get_collections(client, None)

    results_dict = results.to_context()
    collection_result = results_dict['Contents'][0]

    assert collection_result['Name'] == 'Attacksurface_APP_QA'
    assert collection_result['ID'] == 'attacksurface_mw3tdwq'
    assert collection_result['Owner'] == 'ASMQA_AttackSurfaceAPP'


def test_get_collections_with_project(client: AttackSurfaceManagement.Client, requests_mock):
    requests_mock.get(f'{SERVER_URL}/user_collections', request_headers={'PROJECT_ID': '5678'},
                      headers={'content-type': 'application/json'}, json=MOCK_GET_COLLECTIONS_RESPONSE)

    results = AttackSurfaceManagement.get_collections(client, {"project_id": "5678"})

    results_dict = results.to_context()
    collection_result = results_dict['Contents'][0]

    assert collection_result['Name'] == 'Attacksurface_APP_QA'
    assert collection_result['ID'] == 'attacksurface_mw3tdwq'
    assert collection_result['Owner'] == 'ASMQA_AttackSurfaceAPP'


@freeze_time(datetime.fromtimestamp(1681768194))
def test_fetch_incidents(client: AttackSurfaceManagement.Client, requests_mock, mocker):
    requests_mock.get(
        f'{SERVER_URL}/search/issues/collection%3A12341234%20collection%3A23452345%20last_seen_before'
        '%3A2023-04-17T21%3A49%3A54.000000Z%20last_seen_after%3A2023-03-18T21%3A49%3A54.000000Z%20severity_gte%3A1?page=0',
        headers={'content-type': 'application/json', 'project_id': '1234'}, json=MOCK_FETCH_ISSUES_RESPONSE)

    requests_mock.get(f'{SERVER_URL}/issues/2e0134b5b346a5d0a9d5ee0efe7dfb69dfcc5c1cf65a6df63568f85dc587a120',
                      headers={'content-type': 'application/json'}, json=MOCK_GET_REMOTE_DATA_RESPONSE)

    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch.object(demisto, "params", return_value={"first_fetch": "30 days", "minimum_severity": 1})

    issues_list = AttackSurfaceManagement.fetch_incidents(client)

    assert len(issues_list) == 1

    issue_result = issues_list[0]

    assert issue_result['name'] == 'Deprecated SSL/TLS Protocol Detected'
    assert issue_result['occurred'] == '2022-08-18T17:12:20+00:00'
    assert issue_result['severity'] == 0.5

    assert issue_result['dbotMirrorId'] == '8e02af6c136f297aa8fece36726a6d659bf59f512ca8a90350d93038215a19d7'


@freeze_time(datetime.fromtimestamp(1681768194))
def test_get_remote_data(client: AttackSurfaceManagement.Client, requests_mock, mocker):
    requests_mock.get(f'{SERVER_URL}/issues/2e0134b5b346a5d0a9d5ee0efe7dfb69dfcc5c1cf65a6df63568f85dc587a120',
                      headers={'content-type': 'application/json'}, json=MOCK_GET_REMOTE_DATA_RESPONSE)

    requests_mock.get(f'{SERVER_URL}/notes/issue/2e0134b5b346a5d0a9d5ee0efe7dfb69dfcc5c1cf65a6df63568f85dc587a120',
                      headers={'content-type': 'application/json'}, json=MOCK_GET_REMOTE_DATA_NOTES_RESPONSE)

    remote_data_params = {
        "id": "2e0134b5b346a5d0a9d5ee0efe7dfb69dfcc5c1cf65a6df63568f85dc587a120",
        "lastUpdate": "0"}

    results = AttackSurfaceManagement.get_remote_data_command(client, remote_data_params).extract_for_local()

    issue_data = json.loads(results[0]['details'])
    notes_data = results[1]

    assert issue_data['uuid'] == '9fc77fef-6362-4aef-a154-0ab4a058d5de'
    assert issue_data['entity_uid'] == 'a4cfa1f3c7864d343f8b9568248ad7550400598ddf10ea18959c860ca6253a01'
    assert issue_data['name'] == 'deprecated_ssl_protocol_detected'
    assert issue_data['severity'] == 5

    assert notes_data['Type'] == 1
    assert notes_data['Contents'] == '- testing a note that supports markdown\n' \
                                     '- and has some neat new features\n' \
                                     'test_user'
    assert notes_data["Note"] is True
    assert notes_data['Tags'] == ['note_from_ma_asm']


def test_update_remote_system(client: AttackSurfaceManagement.Client, requests_mock):
    args = {
        'data': {},
        'entries': [],
        'incidentChanged': True,
        'remoteId': 'FAKE_ID',
        'status': 2,
        'delta': {
            "runStatus": ""
        }
    }

    requests_mock.get(f'{SERVER_URL}/issues/FAKE_ID', json={'success': True})

    requests_mock.post(f'{SERVER_URL}/issues/FAKE_ID/status', json={
        "success": True,
        "message": "Successfully reported status as open_triaged",
        "result": True
    })

    result = AttackSurfaceManagement.update_remote_system_command(client, args)

    assert result == 'FAKE_ID'
