def event_response():
    return [
        {
            "ata_event_count": 1,
            "datetime_created": "2021-05-11T20:11:30Z",
            "fields": [
                {
                    "key": "auto_run",
                    "label": "Auto Run",
                    "value": "False",
                    "order": 0,
                },
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

def alert_response():
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
            "xsoar_trigger_events": event_response(),
            "xsoar_trigger_kv": trigger_event_kv(),
            "xsoar_mirror_direction": "Both",
            "xsoar_mirror_instance": "dummy_instance",
            "xsoar_mirror_id": "1",
            "xsoar_mirror_tags": ["comment_tag", "escalate_tag"],
            "xsoar_input_tag": "input_tag",
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
            "xsoar_trigger_events": event_response(),
            "xsoar_trigger_kv": trigger_event_kv(),
            "xsoar_mirror_direction": "Both",
            "xsoar_mirror_instance": "dummy_instance",
            "xsoar_mirror_id": "2",
            "xsoar_mirror_tags": ["comment_tag", "escalate_tag"],
            "xsoar_input_tag": "input_tag",
        },
    ]


def alert_response_remote():
    return {
        "datetime_created": "2021-05-11T20:11:31Z",
        "datetime_closed": None,
        "datetime_firstevent": "2021-05-11T20:11:30Z",
        "datetime_events_added": "2021-05-11T20:11:31Z",
        "datetime_org_assigned": "2021-05-11T20:11:31Z",
        "id": 1,
        "status": "assigned",
        "description": "Test Alert 1",
        "url": "http://some_mock_url/#/incidents/1",
        "xsoar_trigger_events": event_response(),
        "in_mirror_error": "",
    }


def comment_response():
    return [
        {
            "comment": "Test comment",
            "datetime_created": "2021-05-10T19:36:48Z",
            "id": 1,
            "user": user_response(),
        },
        {
            "comment": "Closing alert due to duplicate.",
            "datetime_created": "2021-05-10T19:50:18Z",
            "id": 2,
            "user": user_response(),
        },
    ]

def user_response():
    return {
        "id": 1,
        "name": "Active User",
        "email": "test@test",
        "organization": {"id": 1, "name": "dummy_org", "psa_id": "dummy_id"},
    }

def trigger_event_kv():
    return {
        "auto_run": "False",
        "event_name": "threat_quarantined",
        "event_timestamp": "2021-05-11T20:11:30.728667",
    }

def comment_entries():
    return [
        {
            "Type": 1,
            "ContentsFormat": "json",
            "Contents": comment_response()[0],
            "HumanReadable": "Test comment\n\nSent by Active User (test@test) via ZTAP",
            "ReadableContentsFormat": "text",
            "Note": True,
            "Tags": ["input_tag"],
        },
        {
            "Type": 1,
            "ContentsFormat": "json",
            "Contents": comment_response()[1],
            "HumanReadable": "Closing alert due to duplicate.\n\nSent by Active User (test@test) via ZTAP",
            "ReadableContentsFormat": "text",
            "Note": True,
            "Tags": ["input_tag"],
        },
    ]
