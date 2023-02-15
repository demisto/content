"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import json

import pytest

from Neosec import NeosecClient, fetch_incidents, NeosecNodeClient, set_alert_status

MOCK_URL = "http://123-fake-api.com"
MOCK_NODE_URL = "http://124-fake-api.com"
MOCK_TENANT_KEY = "fake_tenant"
MOCK_FIRST_TIME_TIMESTAMP = 1

MOCK_ALL_EVENTS = {
    "items": [
        {
            "id": "a29ceff4-52f3-efba-aabc-87909d0fbff2",
            "name": "Suspicious Privileged Operation Attempt",
            "timestamp": "2022-05-05T19:39:49.504000Z",
            "status": "Open",
            "severity": "Low",
            "description": "* Endpoint 'DELETE /v2/invoicing/invoices/{invoices_id}' in service 'Invoicing' \n"
                           "* MerchantID '1c4ce8d6-5847-4f38-a689-4d83991ac3297' tried to access what might be"
                           " high-privileged function \n* All 1 requested failed with '403 Forbbiden'  ",
            "category": "Data Access",
            "source": None,
            "author": "Analytics",
            "sequence_ids": None,
            "entities": [
                {
                    "value": "1c4ce8d6-5847-4f38-a689-4d83991ac329",
                    "name": "MerchantID",
                    "pretty_name": None,
                    "class": "user",
                    "family": "actor",
                    "value_type": "String"
                },
                {
                    "value": "E1SDajS6s1is7_13u+BW9uO_PHS80YQBj4nOpaXv9oOJ___KlA7pxr0WeAlQPiFeEi-"
                             "XQM1eLbHOlK_Uh0aZRcJvy6BFVmeCP",
                    "name": "AccessToken",
                    "pretty_name": None,
                    "class": "token",
                    "family": "actor",
                    "value_type": "String"
                },
                {
                    "value": "127.0.0.1",
                    "name": "IP",
                    "pretty_name": None,
                    "class": "ip",
                    "family": "actor",
                    "value_type": "IPv4"
                }
            ],
            "endpoints": [
                {
                    "id": "a94da4aa-52ce-b6d2-5c3a-55edcf1db288",
                    "method": "DELETE",
                    "endpoint_path": "/v2/invoicing/invoices/{invoices_id}",
                    "service_name": "Invoicing",
                    "labels": None,
                    "endpoint_labels": None,
                    "hidden_at": None,
                    "hidden_by": None,
                    "hidden": None,
                    "call_count": None,
                    "call_percentage": None,
                    "max_severity": None,
                    "first_seen": None,
                    "last_seen": None
                }
            ],
            "caller_ips": [
                "127.0.0.1"
            ],
            "labels": [
                "OWASP API1",
                "OWASP A5",
                "OWASP API5",
                "Data Leak",
                "PII"
            ],
            "alert_type": "UserBehaviorAlert",
            "recommendations": "* Is the resource being accessed private to the actor entity type accessing it?"
                               "\n* Is the actor entity accessing this resource an admin?\n* Investigate the"
                               " behavior of the API consumer around the time of the alert",
            "alert_info": "Some functions and resources in the API are accessible only by high-privilege or "
                          "admin users. When a low-privilege API consumer abnormally tries to use those functions,"
                          " they may be looking for an authorization bypass vulnerability, often called BFLA"
                          " (broken function level authorization).",
            "triggered_at": "2022-05-05T19:39:49.504000Z",
            "detection_model_id": "fa10ba69-89a0-4c15-876a-cdaf911fda25",
            "endpoint": "DELETE /v2/invoicing/invoices/{invoices_id}",
            "base_risk_score": 0,
            "call_ids": [
                "4fce6687-1c78-4083-a427-a82e1880d605"
            ]
        },
        {
            "id": "a29ceff4-fccf-efba-aabc-87909d0fbff2",
            "name": "Brute Force Authentication Attempt",
            "timestamp": "2022-05-05T19:24:09.129000Z",
            "status": "Open",
            "severity": "Low",
            "description": "* Endpoint 'POST /v1/oauth2/token' in service 'Authentication'\n* It received 30"
                           " or more bad requests in the last hour from IP 127.0.0.1\n* The average bad "
                           "request ratio per 10 minutes per IP for this endpoint was 20 in the last 5 days.",
            "category": "Account Takeover",
            "source": None,
            "author": "Analytics",
            "sequence_ids": None,
            "entities": [
                {
                    "value": "127.0.0.1",
                    "name": "IP",
                    "pretty_name": None,
                    "class": "ip",
                    "family": "actor",
                    "value_type": "IPv4"
                }
            ],
            "endpoints": [
                {
                    "id": "88061ea4-665a-60ff-4db5-00a44694c99e",
                    "method": "POST",
                    "endpoint_path": "/v1/oauth2/token",
                    "service_name": "Authentication",
                    "labels": None,
                    "endpoint_labels": None,
                    "hidden_at": None,
                    "hidden_by": None,
                    "hidden": None,
                    "call_count": None,
                    "call_percentage": None,
                    "max_severity": None,
                    "first_seen": None,
                    "last_seen": None
                }
            ],
            "caller_ips": [
                "127.0.0.1"
            ],
            "labels": [
                "OWASP API2",
                "OWASP A2",
                "OWASP API4",
                "Unauthenticated EP"
            ],
            "alert_type": "UserBehaviorAlert",
            "recommendations": "* Consider tightening rate limits for authentication endpoints\n* Look "
                               "at adding IP addresses performing brute force attempts to your firewall's"
                               " deny list\n* Any subsequent successful login from the alerted IP address "
                               "should be treated as suspicious.",
            "alert_info": "In brute force attacks, malicious actors try to login to accounts using different"
                          " passwords. These password could be part of a specified dictionary or simple "
                          "guessing without any logic. This attack method is considered to be quite old"
                          " but still effective and popular among hackers.",
            "triggered_at": "2022-05-05T19:24:09.129000Z",
            "detection_model_id": "a7d9f57d-b0d7-48ed-82a7-23db1b83271c",
            "endpoint": "POST /v1/oauth2/token",
            "base_risk_score": 0,
            "call_ids": [
                "0d9f54dd-5588-4462-8cc3-8fb4c0866eff",
                "35deff20-9646-4bf5-8a54-4947f913ac81",
                "717885d4-d5d6-455b-8a1f-5df60e8fff16",
                "2cdc6e23-6da6-4961-9ce8-88d0bc831ec1",
                "3b1969c0-1bfc-4817-8d70-b75bdc6494de",
                "0d8310ed-5318-45ab-912f-dff8f0c9f7d9",
                "715a5736-be61-4783-a5c2-1a2b709d7b8a",
                "d12fac0e-0693-4acb-bc08-c3607a1e648f",
                "9f2b35f3-173e-431a-b37a-0c9467c1a8c5",
                "0cefca46-6527-4c95-99c6-3c54d62e3b71",
                "68fe79ce-dc85-46a4-a210-76ccf3d73049",
                "d6f746f3-d72a-4a9f-a167-6c6724577554",
                "966b5ed6-38b0-43e7-beaa-9515a8d92f04",
                "6b79dea1-efa1-4961-84b1-a1db8f03e8f5",
                "18be3db1-0da4-475f-88b8-94729fe666eb",
                "84daa422-06ed-46ed-946a-29a1a11fbf84",
                "7c0ad902-eb04-42a8-8da3-eb932d963a41",
                "66f1b391-80db-424a-9fb6-af19aa6bc66c",
                "c66628fa-d65e-4a5c-beec-6aab578837ae",
                "01f66380-9c84-48dc-878a-b703ca3ceecb",
                "77dd2e77-6683-4a33-a48b-e3665b4e4b55",
                "b2e80ad7-edef-4201-819f-8ff0bc2a72be",
                "bc456b06-8efd-4e01-a087-593b9729cbf9",
                "b994df9f-8cff-4fed-a4ef-2e1e5595aaef",
                "8941f24f-0ff6-4ec8-995c-cd7a70486692",
                "0eea097f-5f58-4b8a-8d8a-9e72065d06c3",
                "08ba69e9-d90c-416e-8379-7c1a7b013dbc",
                "f97054f6-3894-4ce2-9834-4a41618b976a",
                "f432c9bd-e76d-4919-8ef4-970b9e9907cb",
                "b29e5267-354d-4d00-a164-2a6df8d2289d",
                "72d7daf8-9b00-46a0-b4c1-30a793515ab1",
                "700032ed-c209-434f-b006-f4a939d0fad5"
            ]
        },
        {
            "id": "a299aff4-52f3-efba-aabc-87909d0fbff2",
            "name": "Query Parameter Fuzzing",
            "timestamp": "2022-05-05T19:10:09.169000Z",
            "status": "Open",
            "severity": "Low",
            "description": "* Query parameter 'total_required' in endpoint 'GET /v2/invoicing/invoices' "
                           "in service 'Invoicing'\n* IP '127.0.0.1' used 52 unique 'total_required'"
                           " query parameter values in 10 minutes\n* 5 of IP requests returned 200 OK\n*"
                           " On average, a single IP uses 6 unique query parameter values in 10 minutes, "
                           "failing 2 of these requests.",
            "category": "Recon",
            "source": None,
            "author": "Analytics",
            "sequence_ids": None,
            "entities": [
                {
                    "value": "1c4ce8d6-5847-4f38-a689-4d83991ac329",
                    "name": "MerchantID",
                    "pretty_name": None,
                    "class": "user",
                    "family": "actor",
                    "value_type": "String"
                },
                {
                    "value": "E1SDajS6s1is7_13u+BW9uO_PHS80YQBj4nOpaXv9oOJ___"
                             "KlA7pxr0WeAlQPiFeEi-XQM1eLbHOlK_Uh0aZRcJvy6BFVmeCP",
                    "name": "AccessToken",
                    "pretty_name": None,
                    "class": "token",
                    "family": "actor",
                    "value_type": "String"
                },
                {
                    "value": "127.0.0.1",
                    "name": "IP",
                    "pretty_name": None,
                    "class": "ip",
                    "family": "actor",
                    "value_type": "IPv4"
                }
            ],
            "endpoints": [
                {
                    "id": "da1316f5-ab94-b2cb-67e6-ee30a832acd7",
                    "method": "GET",
                    "endpoint_path": "/v2/invoicing/invoices",
                    "service_name": "Invoicing",
                    "labels": None,
                    "endpoint_labels": None,
                    "hidden_at": None,
                    "hidden_by": None,
                    "hidden": None,
                    "call_count": None,
                    "call_percentage": None,
                    "max_severity": None,
                    "first_seen": None,
                    "last_seen": None
                }
            ],
            "caller_ips": [
                "127.0.0.1"
            ],
            "labels": [
                "OWASP API1",
                "OWASP API4",
                "OWASP A5",
                "PII"
            ],
            "alert_type": "UserBehaviorAlert",
            "recommendations": "* Check whether the fuzzing originated from a company-sanctioned "
                               "tool, or was part of an authorized penetration test\n* Has the same"
                               " actor performed any subsequent operations against your APIs? If so,"
                               " treat them as suspicious.",
            "alert_info": "Attackers fuzz query parameter values in order to find injection points "
                          "and whether the API is leaking any information. An extreme case of information"
                          " leaks is broken authorization, when attacker can access resources they should "
                          "not be able to access.\nThis detection model triggers on an API consumer fuzzing a "
                          "certain endpoint query parameter, and getting one or more successful responses."
                          " This may mean that the attacker managed to access unauthorized data. Note that"
                          " regardless of the success or failure of the calls themselves - the attacker may "
                          "also have learned important information from the response codes, sizes, and other"
                          " response attributes, such as the time it took to process each request.",
            "triggered_at": "2022-05-05T19:10:09.169000Z",
            "detection_model_id": "96c02fc1-430a-4dd5-8aef-72d42927620d",
            "endpoint": "GET /v2/invoicing/invoices",
            "base_risk_score": 0,
            "call_ids": [
                "f58c352f-f115-4aa9-a302-9d8e3596ec73",
                "f6ad2b35-8d55-461b-923d-301b6538637e",
                "3b2bcab2-84e1-481d-b524-1585afcd15d4",
                "217d4279-4c9d-4114-93cd-37d24ba8aa97",
                "6e9c3908-2fd9-4a04-a91c-0eedb1d3591f",
                "59b146f7-77eb-4e6c-a546-23f386fc1294",
                "a72c9d5d-fd08-447a-aa79-7799218ca99f",
                "ab9d501a-f277-4977-982b-ca97eae6addb",
                "f4b0ddc3-3c45-4ccb-b0ac-39b8b7c9ac69",
                "20a81ae7-96c4-43ae-9d59-e5850453e091",
                "fca1ad1d-bbc2-49bd-ac20-fccb3e323ad3",
                "e0fedd91-e28e-4167-a5f9-32390b287525",
                "3dcd7e30-03a0-40d2-a86f-a37fa863fbfd",
                "cc26945b-0e6e-4d04-a6d4-76712289c34e",
                "3af8da7d-e7c4-4ac6-bdd0-ecdd11d465d6",
                "8e3cfd4b-a416-4377-ba5c-34f3ae31ba28",
                "8de8bd9f-ffc1-4f6f-9945-3da5d89a7686",
                "9fb738f0-ef36-49a8-81c3-45fc2477dbd8",
                "ba099b16-ceea-4d5c-8c95-a156505e75eb",
                "6eee550d-b0b9-4f51-9aa4-0f4c1db564dd",
                "8355c0f4-55b2-4a32-8cbb-13494cc6d233",
                "3b3ca9dc-617f-430d-ba9c-410f5b412939",
                "6d06626a-50a5-4cd1-b7b7-71451851fe23",
                "0608201d-26d9-4cde-8c45-2be10e36ddcc",
                "2cbf0170-60a5-4c65-92d0-dd809ec47076",
                "4318f110-7ce1-43de-804b-8d8c9c969ff9",
                "0836e94c-3cec-4281-84ef-7d598777bf27",
                "fc2bcdfc-83c9-4c76-a75d-dec48c2880ba",
                "ad2caccc-3fbf-4686-bbc8-03023c2317d8",
                "b00341c5-343b-46f8-9777-165d42f8c9f2",
                "29312ed3-073c-4af1-8751-40add16836d6",
                "77f4c74b-3300-4c87-a045-e22eb9d8846c",
                "ea478030-eccc-43e0-9fdb-a4776fc1ae9f",
                "1cbc4e9f-0654-435d-a8d0-13d9e613ee32",
                "d8a08127-c72b-42f6-bf72-47d815f73fa5",
                "2eebe086-ef2e-4a34-a4c8-72f68746d9ac",
                "92c6b2d3-235d-445b-b140-cc2c58535496",
                "1069a3f7-035f-46c4-a51d-1e19e132fff0",
                "623e1428-5d88-4c67-8af9-65249b147300",
                "41d9b961-013e-43da-9920-e0759ecb8534",
                "e3efb87d-b69d-4bf6-ac63-2d6fa7d28f3f",
                "2220d185-41df-474f-ba1f-968c7fb44ea7",
                "6e9fcc02-d1c5-49fe-9481-cf76670a4b54",
                "f69c833e-3157-4142-a199-af1200b7d76d",
                "becc19f7-0349-4872-947b-f128ae58b579",
                "1d1cdc41-4eb0-40f9-9b2c-b2d25a5a00bb",
                "ae586ed6-45ba-41cd-8e17-017127c060e9",
                "f32b0726-4e68-4bd8-a3cf-f45d18901189",
                "a382109b-651e-4cc6-a7e7-be4cbbda18c1",
                "39ae1133-0ae2-4b15-9396-cb8b6bc771d2",
                "455f84d5-1052-4555-9c9c-71b0ea51f61e",
                "b10b7571-8de6-4fe7-a25b-03bd3ee5c98b"
            ]
        },
        {
            "id": "a299b804-52f3-48eb-abd1-87909d0f9ffd",
            "name": "Shadow Parameter",
            "timestamp": "2022-05-05T18:55:22.148000Z",
            "status": "Open",
            "severity": "Low",
            "description": "* Endpoint 'GET /v2/checkout/orders/{order_id}' in service 'Invoicing'\n* The "
                           "following query parameters are not documented: full_details\n* They had been"
                           " used successfully 5 times in the last 30 days",
            "category": "Shadow API",
            "source": None,
            "author": "Analytics",
            "sequence_ids": None,
            "entities": [],
            "endpoints": [
                {
                    "id": "997c741b-9cd9-df22-0a34-2e078fcead86",
                    "method": "GET",
                    "endpoint_path": "/v2/checkout/orders/{orders_id}",
                    "service_name": "Orders",
                    "labels": None,
                    "endpoint_labels": None,
                    "hidden_at": None,
                    "hidden_by": None,
                    "hidden": None,
                    "call_count": None,
                    "call_percentage": None,
                    "max_severity": None,
                    "first_seen": None,
                    "last_seen": None
                }
            ],
            "caller_ips": [
                "127.0.0.1"
            ],
            "labels": [
                "OWASP API9",
                "OWASP API7",
                "OWASP A6",
                "PII",
                "Money Out"
            ],
            "alert_type": "APIAlert",
            "recommendations": "* Review the endpoint and assess whether the parameter(s) should be exposed\n*"
                               " Update the documentation, preferably adding documentation generation into your"
                               " CI/CD pipeline",
            "alert_info": "Shadow parameters are undocumented parameters accepted by a documented API endpoint."
                          " These undocumented parameters may not have been tested as thoroughly as the documented"
                          " parameters, and therefore pose a greater security risk.",
            "triggered_at": "2022-05-05T18:55:22.148000Z",
            "detection_model_id": "5a78eeb0-8be0-434f-9ddb-96f3e9c97a3e",
            "endpoint": "GET /v2/checkout/orders/{orders_id}",
            "base_risk_score": 15,
            "call_ids": [
                "a58e2b82-843f-4115-99a3-61754b9b40ad",
                "73ab15a8-6292-4aff-85b8-5851f415c77d",
                "28bc4173-c3e2-45aa-b0cc-4ca40a85e9e8",
                "bc9a0fc4-e2ab-41c9-baf9-59d0a2e3dd56",
                "77e70698-805e-4fa1-a228-fc123f823940"
            ]
        }
    ],
    "count": 4,
    "total": 4
}

MOCK_NODE_ALL_EVENTS = {"Message": json.dumps(MOCK_ALL_EVENTS["items"])}
MOCK_ALERT_ID = "a299b804-52f3-48eb-abd1-87909d0f9ffd"
MOCK_NODE_HEALTH_CHECK = {"Status": "ok"}
MOCK_NODE_HEALTH_CHECK_FAILED = {"Status": "failed"}
MOCK_ALL_EVENTS_INVALID_TRIGGERED_AT = {
    "items": [
        {
            "id": "a29ceff4-52f3-efba-aabc-87909d0fbff2",
            "name": "Suspicious Privileged Operation Attempt",
            "timestamp": "2022-05-05T19:39:49.504000Z",
            "status": "Open",
            "severity": "Low",
            "description": "* Endpoint 'DELETE /v2/invoicing/invoices/{invoices_id}' in service 'Invoicing' \n"
                           "* MerchantID '1c4ce8d6-5847-4f38-a689-4d83991ac3297' tried to access what might be"
                           " high-privileged function \n* All 1 requested failed with '403 Forbbiden'  ",
            "category": "Data Access",
            "source": None,
            "author": "Analytics",
            "sequence_ids": None,
            "entities": [
                {
                    "value": "1c4ce8d6-5847-4f38-a689-4d83991ac329",
                    "name": "MerchantID",
                    "pretty_name": None,
                    "class": "user",
                    "family": "actor",
                    "value_type": "String"
                },
                {
                    "value": "E1SDajS6s1is7_13u+BW9uO_PHS80YQBj4nOpaXv9oOJ___KlA7pxr0WeAlQPiFeEi-"
                             "XQM1eLbHOlK_Uh0aZRcJvy6BFVmeCP",
                    "name": "AccessToken",
                    "pretty_name": None,
                    "class": "token",
                    "family": "actor",
                    "value_type": "String"
                },
                {
                    "value": "127.0.0.1",
                    "name": "IP",
                    "pretty_name": None,
                    "class": "ip",
                    "family": "actor",
                    "value_type": "IPv4"
                }
            ],
            "endpoints": [
                {
                    "id": "a94da4aa-52ce-b6d2-5c3a-55edcf1db288",
                    "method": "DELETE",
                    "endpoint_path": "/v2/invoicing/invoices/{invoices_id}",
                    "service_name": "Invoicing",
                    "labels": None,
                    "endpoint_labels": None,
                    "hidden_at": None,
                    "hidden_by": None,
                    "hidden": None,
                    "call_count": None,
                    "call_percentage": None,
                    "max_severity": None,
                    "first_seen": None,
                    "last_seen": None
                }
            ],
            "caller_ips": [
                "127.0.0.1"
            ],
            "labels": [
                "OWASP API1",
                "OWASP A5",
                "OWASP API5",
                "Data Leak",
                "PII"
            ],
            "alert_type": "UserBehaviorAlert",
            "recommendations": "* Is the resource being accessed private to the actor entity type accessing it?"
                               "\n* Is the actor entity accessing this resource an admin?\n* Investigate the"
                               " behavior of the API consumer around the time of the alert",
            "alert_info": "Some functions and resources in the API are accessible only by high-privilege or "
                          "admin users. When a low-privilege API consumer abnormally tries to use those functions,"
                          " they may be looking for an authorization bypass vulnerability, often called BFLA"
                          " (broken function level authorization).",
            "triggered_at": "201322-05-05T19:39:49.504000Z",
            "detection_model_id": "fa10ba69-89a0-4c15-876a-cdaf911fda25",
            "endpoint": "DELETE /v2/invoicing/invoices/{invoices_id}",
            "base_risk_score": 0,
            "call_ids": [
                "4fce6687-1c78-4083-a427-a82e1880d605"
            ]
        }
    ],
    "count": 4,
    "total": 4
}


def test_first_fetch_incidents(requests_mock):
    requests_mock.post(
        MOCK_URL + f'/organizations/{MOCK_TENANT_KEY}/alerts/query',
        json=MOCK_ALL_EVENTS)

    client = NeosecClient(
        base_url=MOCK_URL,
        verify=True,
        proxy=False,
        tenant_key=MOCK_TENANT_KEY,
        headers={}
    )

    next_run, incidents = fetch_incidents(
        client=client,
        node_client=None,
        max_results=50,
        last_run={},
        first_fetch_time=MOCK_FIRST_TIME_TIMESTAMP
    )

    assert len(incidents) == 4
    assert json.loads(incidents[3]['rawJSON'])["id"] == "a299b804-52f3-48eb-abd1-87909d0f9ffd"


def test_first_fetch_incidents_invalid_triggered_at(requests_mock):
    requests_mock.post(
        MOCK_URL + f'/organizations/{MOCK_TENANT_KEY}/alerts/query',
        json=MOCK_ALL_EVENTS_INVALID_TRIGGERED_AT)

    client = NeosecClient(
        base_url=MOCK_URL,
        verify=True,
        proxy=False,
        tenant_key=MOCK_TENANT_KEY,
        headers={}
    )

    with pytest.raises(ValueError):
        fetch_incidents(
            client=client,
            node_client=None,
            max_results=50,
            last_run={},
            first_fetch_time=MOCK_FIRST_TIME_TIMESTAMP
        )


def test_first_fetch_incidents_with_filters(requests_mock):
    requests_mock.post(
        MOCK_URL + f'/organizations/{MOCK_TENANT_KEY}/alerts/query',
        json=MOCK_ALL_EVENTS)

    client = NeosecClient(
        base_url=MOCK_URL,
        verify=True,
        proxy=False,
        tenant_key=MOCK_TENANT_KEY,
        headers={}
    )

    next_run, incidents = fetch_incidents(
        client=client,
        node_client=None,
        max_results=50,
        last_run={},
        first_fetch_time=MOCK_FIRST_TIME_TIMESTAMP,
        alert_status="Open",
        severities=["Info"],
        alert_type=["Posture"]
    )

    assert len(incidents) == 4
    assert json.loads(incidents[3]['rawJSON'])["id"] == "a299b804-52f3-48eb-abd1-87909d0f9ffd"


def test_next_fetch(requests_mock):
    requests_mock.post(
        MOCK_URL + f'/organizations/{MOCK_TENANT_KEY}/alerts/query',
        json=MOCK_ALL_EVENTS)

    client = NeosecClient(
        base_url=MOCK_URL,
        verify=True,
        proxy=False,
        tenant_key=MOCK_TENANT_KEY,
        headers={}
    )

    next_run, incidents = fetch_incidents(
        client=client,
        node_client=None,
        last_run={"last_fetch": MOCK_FIRST_TIME_TIMESTAMP},
        first_fetch_time=MOCK_FIRST_TIME_TIMESTAMP,
        max_results=50
    )

    assert len(incidents) == 4
    assert json.loads(incidents[3]['rawJSON'])["id"] == "a299b804-52f3-48eb-abd1-87909d0f9ffd"


def test_first_fetch_incidents_with_detok(requests_mock):
    requests_mock.post(
        MOCK_URL + f'/organizations/{MOCK_TENANT_KEY}/alerts/query',
        json=MOCK_ALL_EVENTS)

    requests_mock.post(MOCK_NODE_URL + '/detokenize', json=MOCK_NODE_ALL_EVENTS)

    client = NeosecClient(
        base_url=MOCK_URL,
        verify=True,
        proxy=False,
        tenant_key=MOCK_TENANT_KEY,
        headers={}
    )

    node_client = NeosecNodeClient(
        base_url=MOCK_NODE_URL,
        verify=True,
        proxy=False,
    )

    next_run, incidents = fetch_incidents(
        client=client,
        node_client=node_client,
        max_results=50,
        last_run={},
        first_fetch_time=MOCK_FIRST_TIME_TIMESTAMP
    )

    assert len(incidents) == 4
    assert json.loads(incidents[3]['rawJSON'])["id"] == "a299b804-52f3-48eb-abd1-87909d0f9ffd"


def test_test_module_sanity(requests_mock):
    from Neosec import test_module

    requests_mock.post(
        MOCK_URL + f'/organizations/{MOCK_TENANT_KEY}/alerts/query',
        json=MOCK_ALL_EVENTS)

    client = NeosecClient(
        base_url=MOCK_URL,
        verify=True,
        proxy=False,
        tenant_key=MOCK_TENANT_KEY,
        headers={}
    )

    result = test_module(client, None, None, None, None, 50)
    assert result == 'ok'


def test_test_module_with_detok_sanity(requests_mock):
    from Neosec import test_module

    requests_mock.post(
        MOCK_URL + f'/organizations/{MOCK_TENANT_KEY}/alerts/query',
        json=MOCK_ALL_EVENTS)
    requests_mock.get(MOCK_NODE_URL + '/healthcheck', json=MOCK_NODE_HEALTH_CHECK)

    client = NeosecClient(
        base_url=MOCK_URL,
        verify=True,
        proxy=False,
        tenant_key=MOCK_TENANT_KEY,
        headers={}
    )
    node_client = NeosecNodeClient(
        base_url=MOCK_NODE_URL,
        verify=True,
        proxy=False,
    )

    result = test_module(client, node_client, None, None, None, 50)
    assert result == 'ok'


def test_test_module_with_detok_failed(requests_mock):
    from Neosec import test_module

    requests_mock.post(
        MOCK_URL + f'/organizations/{MOCK_TENANT_KEY}/alerts/query',
        json=MOCK_ALL_EVENTS)
    requests_mock.get(MOCK_NODE_URL + '/healthcheck', json=MOCK_NODE_HEALTH_CHECK_FAILED)

    client = NeosecClient(
        base_url=MOCK_URL,
        verify=True,
        proxy=False,
        tenant_key=MOCK_TENANT_KEY,
        headers={}
    )
    node_client = NeosecNodeClient(
        base_url=MOCK_NODE_URL,
        verify=True,
        proxy=False,
    )

    result = test_module(client, node_client, None, None, None, 50)
    assert result != 'ok'


def test_set_alert_status_command(requests_mock):
    requests_mock.patch(MOCK_URL + f'/organizations/{MOCK_TENANT_KEY}/alerts/{MOCK_ALERT_ID}', json={})

    client = NeosecClient(
        base_url=MOCK_URL,
        verify=True,
        proxy=False,
        tenant_key=MOCK_TENANT_KEY,
        headers={}
    )
    set_alert_status(client, MOCK_ALERT_ID, "Closed")
