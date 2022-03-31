"""ListUsedDockersImages for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all functions names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

"""

INTEGRATION = '''
{
    "configurations":[
        {
            "brand": "",
            "id": "no-integration-script-conf",
            "display": "no-integration-script-conf",
            "integrationScript": null
        },
        {
            "brand": "",
            "id": "integration-script-java",
            "display": "integration-script-java",
            "integrationScript": {
                "subtype": "",
                "type": "java"
            }
        },
        {
            "brand": "",
            "id": "integration-script-python",
            "display": "integration-script-python",
            "integrationScript": {
                "subtype": "",
                "type": "python",
                "dockerImage": "demisto/python3:3.9.7.12345"
            }
        },
        {
            "brand": "",
            "id": "integration-script-powershell",
            "display": "integration-script-powershell",
            "integrationScript": {
                "subtype": "",
                "type": "python",
                "dockerImage": "demisto/powershell:3.9.7.12345"
            }
        },
        {
            "brand": "",
            "id": "no-integration-script",
            "display": "no-integration-script",
            "integrationScript": {
                "subtype": "",
                "type": "powershell"
            }
        }
    ],
    "instances":[
        {
            "brand": "not-enbaled-instance",
            "enabled": "false"
        },
        {
            "brand": "instance-integration-script-false",
            "enabled": "true",
            "isIntegrationScript": false
        },
        {
            "brand": "no-integration-script-conf",
            "enabled": "true",
            "isIntegrationScript": true
        },
        {
            "brand": "integration-script-java",
            "enabled": "true",
            "isIntegrationScript": true
        },
        {
            "brand": "integration-script-python",
            "enabled": "true",
            "isIntegrationScript": true
        },
        {
            "brand": "inst5",
            "enabled": "true",
            "isIntegrationScript": true
        }
    ]
}'''

AUTOMATIONS = '''{
    "scripts": [
        {
            "id": "AddDBotScoreToContext",
            "version": 1,
            "name": "AddDBotScoreToContext",
            "type": "python",
            "tags": [],
            "contextKeys": [],
            "enabled": true,
            "system": true,
            "detached": false,
            "locked": false,
            "user": "",
            "dockerImage": "demisto/python3:3.9.5.20070",
            "modified": "2021-10-07T12:29:40.415069382Z",
            "scriptTarget": 0,
            "runAs": "DBotWeakRole",
            "roles": [],
            "permitted": true,
            "propagationLabels": null
        },
        {
            "id": "AddEvidence",
            "version": 1,
            "name": "AddEvidence",
            "type": "javascript",
            "tags": [
                "Utility"
            ],
            "contextKeys": [],
            "enabled": true,
            "system": true,
            "detached": false,
            "locked": false,
            "user": "",
            "dockerImage": "",
            "modified": "2021-10-07T12:29:40.414798295Z",
            "scriptTarget": 0,
            "runAs": "DBotWeakRole",
            "roles": [],
            "permitted": true,
            "propagationLabels": null
        },
        {
            "id": "AddKeyToList",
            "version": 1,
            "name": "AddKeyToList",
            "type": "python",
            "tags": [],
            "contextKeys": [],
            "enabled": false,
            "system": true,
            "detached": false,
            "locked": false,
            "user": "",
            "dockerImage": "demisto/python3:3.8.6.13358",
            "modified": "2021-10-07T12:29:40.412254289Z",
            "scriptTarget": 0,
            "runAs": "DBotWeakRole",
            "roles": [],
            "permitted": true,
            "propagationLabels": null
        },
        {
            "id": "DBotMLFetchData",
            "version": 1,
            "name": "DBotMLFetchData",
            "type": "python",
            "tags": [
                "ml"
            ],
            "contextKeys": [],
            "enabled": false,
            "system": true,
            "detached": false,
            "locked": false,
            "user": "",
            "dockerImage": "demisto/fetch-data:1.0.0.22177",
            "modified": "2021-10-07T12:29:40.406291219Z",
            "scriptTarget": 0,
            "deprecated": true,
            "runAs": "DBotWeakRole",
            "roles": [],
            "permitted": true,
            "propagationLabels": null
        },
        {
            "id": "DemistoUploadFile",
            "version": 1,
            "name": "DemistoUploadFile",
            "type": "javascript",
            "tags": [
                "DemistoAPI"
            ],
            "contextKeys": [],
            "enabled": true,
            "system": true,
            "detached": false,
            "locked": false,
            "user": "",
            "dockerImage": "",
            "modified": "2021-10-07T12:29:40.416194161Z",
            "scriptTarget": 0,
            "dependsOn": {
                "must": [
                    "demisto-api-multipart"
                ]
            },
            "deprecated": true,
            "runAs": "DBotWeakRole",
            "roles": [],
            "permitted": true,
            "propagationLabels": null
        },
        {
            "id": "DBotPredictPhishingWords",
            "version": 1,
            "name": "DBotPredictPhishingWords",
            "type": "python",
            "tags": [
                "ml",
                "phishing"
            ],
            "contextKeys": [],
            "enabled": false,
            "system": true,
            "detached": false,
            "locked": false,
            "user": "",
            "dockerImage": "demisto/ml:1.0.0.23334",
            "modified": "2021-10-07T12:29:40.406051138Z",
            "scriptTarget": 0,
            "runAs": "DBotWeakRole",
            "roles": [],
            "permitted": true,
            "propagationLabels": null
        }
    ],
    "selectedScript": null,
    "suggestions": [
        "Condition",
        "DBot",
        "DemistoAPI",
        "Enrichment",
        "IAM",
        "JSON",
        "Threat Intel Management",
        "UrlScan",
        "Utilities",
        "Utility",
        "active directory",
        "autoextract",
        "basescript",
        "campaign",
        "carbon-black"
    ],
    "pythonEnabled": true
}'''


def test_api_response_parsing():
    """
        Tests REST API responses parsing content.
    """
    from ListUsedDockerImages import extract_dockers_from_automation_search_result, \
        extract_dockers_from_integration_search_result, merge_result, MAX_PER_DOCKER, format_result_for_markdown

    integration_response = extract_dockers_from_integration_search_result(
        INTEGRATION, False, True)
    automation_response = extract_dockers_from_automation_search_result(
        AUTOMATIONS)

    assert len(integration_response) == 1 or len(automation_response) == 1

    result_dict = {}
    result_dict = merge_result(integration_response, result_dict, MAX_PER_DOCKER)
    result_dict = merge_result(automation_response, result_dict, MAX_PER_DOCKER)

    assert len(result_dict) == 2

    result_str = format_result_for_markdown(result_dict)

    assert len(result_dict) == len(result_str)
