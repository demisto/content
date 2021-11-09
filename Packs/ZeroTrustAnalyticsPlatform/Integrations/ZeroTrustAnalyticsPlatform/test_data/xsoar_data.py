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
            "xsoar_trigger_events": event_response(),
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
            "xsoar_trigger_events": event_response(),
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
        "xsoar_trigger_events": event_response(),
        "in_mirror_error": "",
    }


def comment_response():
    return [
        {
            "comment": "Test comment",
            "datetime_created": "2021-05-10T19:36:48Z",
            "id": 1,
        },
        {
            "comment": "Closing alert due to duplicate.",
            "datetime_created": "2021-05-10T19:50:18Z",
            "id": 2,
        },
    ]


def log_response():
    return [
        {
            "action": "Added a comment",
            "datetime": "2021-05-11T18:28:14Z",
            "id": 1,
        },
        {
            "action": "Incident locked due to closing.",
            "datetime": "2021-05-11T18:28:15Z",
            "id": 2,
        },
    ]


def log_entries():
    return [
        {
            "Type": 1,
            "ContentsFormat": "json",
            "Contents": log_response()[1],
            "HumanReadable": {
                "occurred": "2021-05-11T18:28:15Z",
                "contents": "Incident locked due to closing.",
                "type": "log",
            },
            "ReadableContentsFormat": "json",
            "Note": True,
            "Tags": ["input_tag"],
            "occurred": "2021-05-11T18:28:15Z_0_2",
        },
    ]


def comment_entries():
    return [
        {
            "Type": 1,
            "ContentsFormat": "json",
            "Contents": comment_response()[0],
            "HumanReadable": {
                "occurred": "2021-05-10T19:36:48Z",
                "contents": "Test comment",
                "type": "comment",
                "files": [],
            },
            "ReadableContentsFormat": "json",
            "Note": True,
            "Tags": ["input_tag"],
            "occurred": "2021-05-10T19:36:48Z_1_1",
        },
        {
            "Type": 1,
            "ContentsFormat": "json",
            "Contents": comment_response()[1],
            "HumanReadable": {
                "occurred": "2021-05-10T19:50:18Z",
                "contents": "Closing alert due to duplicate.",
                "type": "comment",
                "files": [],
            },
            "ReadableContentsFormat": "json",
            "Note": True,
            "Tags": ["input_tag"],
            "occurred": "2021-05-10T19:50:18Z_1_2",
        },
    ]
