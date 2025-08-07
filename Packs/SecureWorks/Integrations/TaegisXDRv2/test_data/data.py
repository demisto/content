TAEGIS_URL = "https://ctpx.secureworks.com"

TAEGIS_ALERT = {
    "id": "alert://priv:crowdstrike:11772:1666247222095:4e41ec02-ca53-5ff7-95cc-eda434221ba6",
    "metadata": {
        "title": "Test Alert",
        "description": "This is a test alert",
        "severity": 0.5,
        "created_at": {"seconds": 1686083555},
    },
    "url": f"{TAEGIS_URL}/alerts/alert:%2F%2Fpriv:crowdstrike:11772:1666247222095:4e41ec02-ca53-5ff7-95cc-eda434221ba6",
}

TAEGIS_ASSET = {
    "architecture": "ARCH_AMD64",
    "biosSerial": "\\x12345",
    "createdAt": "2022-04-14T20:01:02.123456Z",
    "deletedAt": None,
    "endpointPlatform": "",
    "endpointType": "ENDPOINT_REDCLOAK",
    "firstDiskSerial": "\\x98765",
    "hostId": "110d1fd3a23c95c0120d0d10451cb001",
    "hostnames": [{"hostname": "WIN-DESKTOP", "id": "1236c34a-18ab-32c0-a584-8e5a32e617b8"}],
    "id": "123abc12-1111-22b2-3333-44446632c8fd",
    "ingestTime": "2023-01-15T08:01:35Z",
    "kernelRelease": "",
    "kernelVersion": "",
    "osCodename": "",
    "osDistributor": "Microsoft",
    "osFamily": "WINDOWS",
    "osRelease": "0.0",
    "osVersion": "VERSION_SERVER_2012_R2",
    "sensorId": "110d1fd3a23c95c0120d0d10451cb001",
    "sensorVersion": "2.8.5.0",
    "systemType": "NT_SERVER",
    "systemVolumeSerial": "\\x33363336323333333036",
    "tags": [{"__typename": "Tag", "key": "", "tag": "SERVER:TestMachine"}],
    "updatedAt": "2022-05-23T01:20:16.295598Z",
}

TAEGIS_COMMENT = {
    "author_user": {
        "email_normalized": "myuser@email.com",
        "given_name": "John",
        "family_name": "Smith",
        "id": "auth0|000000000000000000000001",
    },
    "athorId": "auth0|000000000000000000000001",
    "id": "ff9ca818-4749-4ccb-883a-2ccc6f6c9e0f",
    "comment": "This is a comment in an investigation",
    "createdAt": "2022-01-01T13:04:57.17234Z",
    "updatedAt": "2022-01-01T14:04:57.17234Z",
}

TAEGIS_ENDPOINT = {
    "hostId": "110d1fd3a23c95c0120d0d10451cb001",
    "hostname": "WIN-DESKTOP",
    "actualIsolationStatus": "",
    "desiredIsolationStatus": "",
    "firstConnectTime": "",
    "lastConnectTime": "",
    "sensorVersion": "2.8.5.0",
}

TAEGIS_ENVIRONMENT = "us1 (charlie)"

TAEGIS_INVESTIGATION = {
    "archived_at": None,
    "created_at": "2022-02-02T13:53:35Z",
    "description": "Test Investigation",
    "id": "c2e09554-833e-41a1-bc9d-8160aec0d70d",
    "key_findings": "",
    "priority": 2,
    "service_desk_id": "",
    "service_desk_type": "",
    "status": "Open",
    "alerts2": [],
    "url": f"{TAEGIS_URL}/investigations/c2e09554-833e-41a1-bc9d-8160aec0d70d",
}

TAEGIS_PLAYBOOK_EXECUTION_ID = "UGxheWJvb2tFeGVjdXRpb246ZjkxNWYzMjMtZDFlNS00MWQ2LTg4NzktYzE4ZTBhMmYzZmNh"
TAEGIS_PLAYBOOK_EXECUTION = {
    "createdAt": "2022-02-10T13:51:24Z",
    "executionTime": 1442,
    "id": TAEGIS_PLAYBOOK_EXECUTION_ID,
    "inputs": {
        "PagerDuty": {"dedup_key": "25f16f6c-dbc1-4efe-85a7-385e73f94efc"},
        "alert": {
            "description": "Please, verify the login was authorized.",
            "message": "Test Alert: Successful Login for User",
            "severity": 0.9,
            "uuid": "25f16f6c-dbc1-4efe-85a7-385e73f94efc",
        },
        "event": "create",
    },
    "instance": {"name": "My Playbook Instance", "playbook": {"name": "My Playbook Name"}},
    "outputs": "25f16f6c-dbc1-4efe-85a7-385e73f94efc",
    "state": "Completed",
    "updatedAt": "2022-02-10T13:51:31Z",
    "url": f"{TAEGIS_URL}/automations/playbook-executions/{TAEGIS_PLAYBOOK_EXECUTION_ID}",
}

TAEGIS_PLAYBOOK_EXECUTION_ID = "UGxheWJvb2tFeGVjdXRpb246M2NiM2FmYWItYTZiNy00ZWNmLTk1NDUtY2JlNjg1OTdhODY1"

TAEGIS_PLAYBOOK_INSTANCE_ID = "UGxheWJvb2tJbnN0YW5jZTphZDNmNzBlZi1mN2U0LTQ0OWYtODJiMi1hYWQwMjQzZTA2NTg="

TAEGIS_USER = {
    "email": "testuser@email.com",
    "given_name": "John",
    "family_name": "Smith",
    "user_id": "auth0|123456",
    "status": "Registered",
}

EXECUTE_PLAYBOOK_RESPONSE = {
    "data": {
        "executePlaybookInstance": {
            "id": TAEGIS_PLAYBOOK_EXECUTION_ID,
        }
    }
}

EXECUTE_PLAYBOOK_BAD_RESPONSE = {"data": {}, "errors": [{"message": "must be defined", "path": ["variables", "id"]}]}


FETCH_ALERTS_RESPONSE = {
    "data": {
        "alertsServiceSearch": {
            "alerts": {"list": [TAEGIS_ALERT]},
            "total_results": 1,
        }
    }
}

FETCH_ALERTS_BY_ID_RESPONSE = {
    "data": {
        "alertsServiceRetrieveAlertsById": {
            "alerts": {"list": [TAEGIS_ALERT]},
            "total_results": 1,
        }
    }
}

FETCH_ASSETS_RESPONSE = {"data": {"searchAssetsV2": {"assets": [TAEGIS_ASSET]}}}

FETCH_ASSETS_BAD_RESPONSE = {"data": {}, "errors": [{"message": "Cannot query requested field", "path": ["input", "unknown_id"]}]}

CREATE_COMMENT_RESPONSE = {
    "data": {
        "addCommentToInvestigation": {
            "id": TAEGIS_COMMENT["id"],
        }
    }
}

CREATE_UPDATE_COMMENT_BAD_RESPONSE = {
    "data": {},
    "errors": [
        {
            "message": "Comment cannot be empty",
            "path": [
                "comment",
            ],
        }
    ],
}

FETCH_COMMENT_RESPONSE = {"data": {"comment": TAEGIS_COMMENT}}

FETCH_COMMENTS_RESPONSE = {
    "data": {
        "commentsV2": {"comments": [TAEGIS_COMMENT]},
    }
}

FETCH_COMMENTS_BAD_RESPONSE = {
    "data": {},
    "errors": [
        {
            "message": "Comment not found",
            "path": [
                "comment",
            ],
        }
    ],
}

UPDATE_COMMENT_RESPONSE = {
    "data": {
        "updateInvestigationComment": {
            "id": TAEGIS_COMMENT["id"],
        }
    }
}

FETCH_ENDPOINT_RESPONSE = {"data": {"assetEndpointInfo": TAEGIS_ENDPOINT}}

FETCH_ENDPOINT_BAD_RESPONSE = {"data": {}, "errors": [{"message": "failed to fetch endpoint", "path": []}]}

FETCH_INCIDENTS_RESPONSE = {"data": {"investigationsSearch": {"investigations": [TAEGIS_INVESTIGATION]}}}

FETCH_INCIDENTS_BAD_RESPONSE = {"data": {}, "errors": [{"message": "failed to fetch investigations", "path": []}]}

FETCH_INVESTIGATION_RESPONSE = {"data": {"investigationV2": TAEGIS_INVESTIGATION}}

FETCH_INVESTIGATIONS_RESPONSE = {"data": {"investigationsSearch": {"investigations": [TAEGIS_INVESTIGATION]}}}

FETCH_INVESTIGATION_ALERTS_RESPONSE = {"data": {"investigationAlerts": {"alerts": [TAEGIS_ALERT]}}}

FETCH_PLAYBOOK_EXECUTION_RESPONSE = {"data": {"playbookExecution": TAEGIS_PLAYBOOK_EXECUTION}}

FETCH_PLAYBOOK_EXECUTION_BAD_RESPONSE = {"data": {}, "errors": [{"message": "failed to execute playbook", "path": []}]}

CREATE_INVESTIGATION_RESPONSE = {
    "data": {
        "createInvestigationV2": {
            "id": "593fa115-abad-4a52-9fc4-2ec403a8a1e4",
            "shortId": "INV00248",
        }
    }
}

UPDATE_INVESTIGATION_RESPONSE = {
    "data": {
        "updateInvestigationV2": {
            "id": "593fa115-abad-4a52-9fc4-2ec403a8a1e4",
            "shortId": "INV00248",
        }
    }
}

FETCH_USER_RESPONSE = {
    "data": {
        "tdrusersByIDs": [TAEGIS_USER],
    }
}

FETCH_USERS_BAD_RESPONSE = {"data": {}, "errors": [{"message": "invalid format", "path": ["variables", "id"]}]}

FETCH_USERS_RESPONSE = {
    "data": {
        "tdrUsersSearch": {
            "results": [TAEGIS_USER],
        }
    }
}

INVESTIGATION_ARCHIVE_RESPONSE = {
    "data": {
        "archiveInvestigation": {
            "id": TAEGIS_INVESTIGATION["id"],
        }
    }
}

INVESTIGATION_ARCHIVE_ALREADY_COMPLETE = {"data": {}, "errors": [{"message": "sql: no rows in result set"}]}

INVESTIGATION_NOT_ARCHIVED_RESPONSE = {"data": None, "errors": [{"Offset": 182}]}

INVESTIGATION_UNARCHIVE_RESPONSE = {
    "data": {
        "unArchiveInvestigation": {
            "id": TAEGIS_INVESTIGATION["id"],
        }
    }
}

ISOLATE_ASSET_RESPONSE = {
    "data": {
        "isolateAsset": {
            "id": TAEGIS_ASSET["id"],
        }
    }
}

ISOLATE_ASSET_BAD_RESPONSE = {"data": {}, "errors": [{"message": "invalid format", "path": ["variables", "id"]}]}

UPDATE_ALERT_STATUS_RESPONSE = {
    "data": {
        "alertsServiceUpdateResolutionInfo": {"reason": "feedback updates successfully applied", "resolution_status": "SUCCESS"}
    }
}

UPDATE_ALERT_STATUS_BAD_RESPONSE = {"data": {}, "errors": [{"message": "invalid format", "path": ["variables", "id"]}]}

TAEGIS_ADD_EVIDENCE_TO_INVESTIGATION_RESPONSE = {
    "data": {
        "addEvidenceToInvestigation": {"investigationId": UPDATE_INVESTIGATION_RESPONSE["data"]["updateInvestigationV2"]["id"]},
    }
}

CREATE_SHARELINK_RESPONSE = {
    "data": {
        "createShareLink": {
            "createdTime": "2023-06-12T15:59:45.526512Z",
            "id": "73a223f4-76d5-448a-8281-a361a2c2ce74",
            "linkRef": "7a021411-01b6-4101-843e-c14218063c02",
            "linkTarget": "",
        }
    }
}
