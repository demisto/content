TAEGIS_URL = "https://ctpx.secureworks.com"

TAEGIS_ALERT = {
    "id": "alert://priv:crowdstrike:11772:1666247222095:4e41ec02-ca53-5ff7-95cc-eda434221ba6",
    "metadata": {
        "title": "Test Alert",
        "description": "This is a test alert",
        "severity": 0.5,
    },
    "url": f"{TAEGIS_URL}/alerts/alert:%2F%2Fpriv:crowdstrike:11772:1666247222095:4e41ec02-ca53-5ff7-95cc-eda434221ba6",
}

TAEGIS_COMMENT = {
    "author_user": {
        "email_normalized": "myuser@email.com",
        "given_name": "John",
        "family_name": "Smith",
        "id": "auth0|000000000000000000000001",
    },
    "id": "ff9ca818-4749-4ccb-883a-2ccc6f6c9e0f",
    "comment": "This is a comment in an investigation",
    "created_at": "2022-01-01T13:04:57.17234Z",
    "deleted_at": None,
    "modified_at": None,
    "parent_id": "c2e09554-833e-41a1-bc9d-8160aec0d70d",
    "parent_type": "investigation",
}

TAEGIS_ENVIRONMENT = "us1"

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
        "PagerDuty": {
            "dedup_key": "25f16f6c-dbc1-4efe-85a7-385e73f94efc"
        },
        "alert": {
            "description": "Please, verify the login was authorized.",
            "message": "Test Alert: Successful Login for User",
            "severity": 0.9,
            "uuid": "25f16f6c-dbc1-4efe-85a7-385e73f94efc"
        },
        "event": "create"
    },
    "instance": {
        "name": "My Playbook Instance",
        "playbook": {
            "name": "My Playbook Name"
        }
    },
    "outputs": "25f16f6c-dbc1-4efe-85a7-385e73f94efc",
    "state": "Completed",
    "updatedAt": "2022-02-10T13:51:31Z",
    "url": f"{TAEGIS_URL}/automations/playbook-executions/{TAEGIS_PLAYBOOK_EXECUTION_ID}",
}

TAEGIS_PLAYBOOK_EXECUTION_ID = "UGxheWJvb2tFeGVjdXRpb246M2NiM2FmYWItYTZiNy00ZWNmLTk1NDUtY2JlNjg1OTdhODY1"

TAEGIS_PLAYBOOK_INSTANCE_ID = "UGxheWJvb2tJbnN0YW5jZTphZDNmNzBlZi1mN2U0LTQ0OWYtODJiMi1hYWQwMjQzZTA2NTg="

EXECUTE_PLAYBOOK_RESPONSE = {
    "data": {
        "executePlaybookInstance": {
            "id": TAEGIS_PLAYBOOK_EXECUTION_ID,
        }
    }
}

EXECUTE_PLAYBOOK_BAD_RESPONSE = {
    "data": {},
    "errors": [
        {
            "message": "must be defined",
            "path": [
                "variables",
                "id"
            ]
        }
    ]
}

FETCH_ALERTS_RESPONSE = {
    "data": {
        "alertsServiceSearch": {
            "alerts": {
                "list": [TAEGIS_ALERT]
            },
            "total_results": 1,
        }
    }
}

FETCH_ALERTS_BY_ID_RESPONSE = {
    "data": {
        "alertsServiceRetrieveAlertsById": {
            "alerts": {
                "list": [TAEGIS_ALERT]
            },
            "total_results": 1,
        }
    }
}

CREATE_COMMENT_RESPONSE = {
    "data": {
        "createComment": {
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
            ]
        }
    ]
}

FETCH_COMMENT_RESPONSE = {
    "data": {
        "comment": TAEGIS_COMMENT
    }
}

FETCH_COMMENTS_RESPONSE = {
    "data": {
        "commentsByParent": [TAEGIS_COMMENT]
    }
}

FETCH_COMMENTS_BAD_RESPONSE = {
    "data": {},
    "errors": [
        {
            "message": "Comment not found",
            "path": [
                "comment",
            ]
        }
    ]
}

UPDATE_COMMENT_RESPONSE = {
    "data": {
        "updateComment": {
            "id": TAEGIS_COMMENT["id"],
        }
    }
}

FETCH_INCIDENTS_RESPONSE = {
    "data": {
        "allInvestigations": [TAEGIS_INVESTIGATION]
    }
}

FETCH_INCIDENTS_BAD_RESPONSE = {
    "data": {},
    "errors": [
        {
            "message": "failed to fetch investigations",
            "path": []
        }
    ]
}

FETCH_INVESTIGATION_RESPONSE = {
    "data": {
        "investigation": TAEGIS_INVESTIGATION
    }
}

FETCH_INVESTIGATIONS = {
    "data": {
        "allInvestigations": [TAEGIS_INVESTIGATION]
    }
}

FETCH_INVESTIGATION_ALERTS_RESPONSE = {
    "data": {
        "investigationAlerts": {
            "alerts": [TAEGIS_ALERT]
        }
    }
}

FETCH_PLAYBOOK_EXECUTION_RESPONSE = {
    "data": {
        "playbookExecution": TAEGIS_PLAYBOOK_EXECUTION
    }
}

FETCH_PLAYBOOK_EXECUTION_BAD_RESPONSE = {
    "data": {},
    "errors": [
        {
            "message": "failed to execute playbook",
            "path": []
        }
    ]
}

CREATE_INVESTIGATION_RESPONSE = {
    "data": {
        "createInvestigation": {
            "id": "593fa115-abad-4a52-9fc4-2ec403a8a1e4",
        }
    }
}

UPDATE_INVESTIGATION_RESPONSE = {
    "data": {
        "updateInvestigation": {
            "id": "593fa115-abad-4a52-9fc4-2ec403a8a1e4",
        }
    }
}
