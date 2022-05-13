def alert_data():
    return [
        {
            "datetime_created": "2021-05-11T20:11:31Z",
            "datetime_closed": None,
            "datetime_firstevent": "2021-05-11T20:11:30Z",
            "datetime_events_added": "2021-05-11T20:11:31Z",
            "datetime_org_assigned": "2021-05-11T20:11:31Z",
            "id": 1,
            "status": "assigned",
            "description": "Test Alert 1",
            "url": "http://some_mock_url/#/incidents/1",
        },
        {
            "datetime_created": "2021-05-11T20:09:50Z",
            "datetime_closed": None,
            "datetime_firstevent": "2021-05-11T20:09:48Z",
            "datetime_events_added": "2021-05-11T20:09:50Z",
            "datetime_org_assigned": "2021-05-11T20:09:50Z",
            "id": 2,
            "status": "assigned",
            "description": "Test Alert 2",
            "url": "http://some_mock_url/#/incidents/2",
        },
    ]


def escalation_path_data():
    return [
        {
            "time": "2021-05-11T20:11:31Z",
            "group": "Default (dummy_org)",
            "group_id": "1",
            "type": "Group",
        },
    ]


def event_data():
    return [
        {
            "ata_event_count": 1,
            "datetime_created": "2021-05-11T20:11:30Z",
            "fields": [
                {"key": "auto_run", "label": "Auto Run", "value": "False", "order": 0},
                {
                    "key": "event_name",
                    "label": "Event Name",
                    "value": "threat_quarantined",
                    "order": 1,
                },
                {
                    "key": "event_timestamp",
                    "label": "Event Timestamp",
                    "value": "2021-05-11T20:11:30.728667",
                    "order": 2,
                },
            ],
            "trigger": True,
        },
    ]


def comment_data():
    return [
        {
            "comment": "Test comment",
            "datetime_created": "2021-05-10T19:36:48Z",
            "id": 1,
            "user": user_data(),
        },
        {
            "comment": "Closing alert due to duplicate.",
            "datetime_created": "2021-05-10T19:50:18Z",
            "id": 2,
            "user": user_data(),
        },
    ]


def organization_data():
    return [
        {
            "id": 2,
            "psa_id": "dummy_id",
            "name": "dummy_org",
            "monitoring_organization": {
                "id": 1,
                "psa_id": "csmssp",
                "name": "Critical Start MDR",
            },
        },
        {
            "id": 3,
            "psa_id": "child_org_id",
            "name": "child_org",
            "monitoring_organization": {
                "id": 1,
                "psa_id": "dummy_id",
                "name": "Critical Start MDR",
            },
        },
    ]


def group_data():
    return [
        {
            "id": 1,
            "name": "Different Group",
            "organization": {"id": 1, "name": "dummy_org"},
        },
        {
            "id": 2,
            "name": "Default",
            "organization": {"id": 1, "name": "dummy_org"},
        },
    ]


def user_data():
    return {
        "id": 1,
        "name": "Active User",
        "email": "test@test",
        "organization": {"id": 1, "name": "dummy_org", "psa_id": "dummy_id"},
    }
