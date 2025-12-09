SECURITY_EVENTS_LIST_RESULT = {
    "current_link": "",
    "last_log_item_generation_time": "2020-07-19T22:51:40.000Z",
    "next_link": "",
    "security_events": [
        {
            "event": "security_risk_scan",
            "log_item_id": "a9e2990a-8d7c-45e9-84a8-84b59087b2dd",
            "message": {
                "action": "Quarantine",
                "action_result": "success",
                "affected_user": "",
                "detected_by": "",
                "detection_time": "2020-07-19T22:51:30.000Z",
                "file_name": "20200325_100518.jpg",
                "file_upload_time": "2020-07-19T10:51:12.000Z",
                "location": "",
                "log_item_id": "a9e2990a-8d7c-45e9-84a8-84b59087b2dd",
                "risk_level": "",
                "scan_type": "Real-time scan",
                "security_risk_name": "20200325_100518.jpg",
                "triggered_policy_name": "Default OneDrive Policy ATP",
                "triggered_security_filter": "File Blocking",
            },
            "service": "OneDrive",
        }
    ],
    "traceId": "634810de-341e-4f33-b94e-09fc356ab408",
}

SECURITY_EVENTS_LIST_OUTPUT = {
    "security_risk": [
        {
            "event": "security_risk_scan",
            "log_item_id": "a9e2990a-8d7c-45e9-84a8-84b59087b2dd",
            "message": {
                "action": "Quarantine",
                "action_result": "success",
                "affected_user": "",
                "detected_by": "",
                "detection_time": "2020-07-19T22:51:30.000Z",
                "file_name": "20200325_100518.jpg",
                "file_upload_time": "2020-07-19T10:51:12.000Z",
                "location": "",
                "log_item_id": "a9e2990a-8d7c-45e9-84a8-84b59087b2dd",
                "risk_level": "",
                "scan_type": "Real-time scan",
                "security_risk_name": "20200325_100518.jpg",
                "triggered_policy_name": "Default OneDrive Policy ATP",
                "triggered_security_filter": "File Blocking",
            },
            "service": "OneDrive",
        }
    ]
}

EMAIL_SWEEP_RESULT = {
    "current_link": "",
    "next_link": "",
    "traceId": "80674f37-480d-4f37-862f-2f842ad8e732",
    "value": [
        {
            "mail_attachments": [],
            "mail_internet_headers": [{"HeaderName": "Return-Path", "Value": ""}],
            "mail_message_delivery_time": "2020-07-13T01:52:50.000Z",
            "mail_message_id": "",
            "mail_message_recipient": [""],
            "mail_message_sender": "",
            "mail_message_subject": "Test mail from Demisto",
            "mail_unique_id": "",
            "mail_urls": [],
            "mailbox": "",
            "source_domain": "",
            "source_ip": "0.0.0.0",
        }
    ],
}

USER_TAKE_ACTION_RESULT = {
    "batch_id": "02bc9a41-f5ac-47b8-8fd6-4fcc038d5578",
    "code": 0,
    "msg": "",
    "traceId": "9c06c712-3f0a-4d08-be5c-e504295dc570",
}

USER_TAKE_ACTION_OUTPUT = {
    "action_type": "action_type",
    "account_user_email": ["account_user_email1", "account_user_email2"],
    "batch_id": "02bc9a41-f5ac-47b8-8fd6-4fcc038d5578",
    "traceId": "9c06c712-3f0a-4d08-be5c-e504295dc570",
}

EMAIL_TAKE_ACTION_RESULT = {
    "batch_id": "02bc9a41-f5ac-47b8-8fd6-4fcc038d5578",
    "code": 0,
    "msg": "",
    "traceId": "9c06c712-3f0a-4d08-be5c-e504295dc570",
}

EMAIL_TAKE_ACTION_OUTPUT = {
    "action_type": "action_type",
    "mailbox": "mailbox",
    "batch_id": "02bc9a41-f5ac-47b8-8fd6-4fcc038d5578",
    "traceId": "9c06c712-3f0a-4d08-be5c-e504295dc570",
}

USER_ACTION_RESULT_RESULT = {
    "actions": [
        {
            "account_provider": "office365",
            "account_user_email": "avishai@demistodev.onmicrosoft.com",
            "action_executed_at": "2020-07-16T06:58:41.346Z",
            "action_id": "2cc933d7-2ca7-45b0-ac9a-c2e0cb0674b3",
            "action_requested_at": "2020-07-16T06:58:42.236Z",
            "action_type": "MAIL_DELETE",
            "batch_id": "e371b88f-1b23-4cf1-b372-1144a9af08fa",
            "error_code": -999,
            "error_message": "The action for these mails failed.",
            "mail_message_id": "\u003cDB7PR07MB5769F7ECC5AA5BAE27713D0399640@DB7PR07MB5769.eurprd07.prod.outlook.com\u003e",
            "mail_unique_id": "AAMkAGY3OTQyMzMzLWYxNjktNDE0My05NmZhLWQ5MGY1YjIyNzBkNABGAAAAAACYCKjWAnXBTrnhgWJCcLX7BwDrxRwRjq-zTrN6vWSzK4OWAAAAAAEJAADrxRwRjq-zTrN6vWSzK4OWAAOT6DZIAAA=",
            "mailbox": "avishai@demistodev.onmicrosoft.com",
            "service": "exchange",
            "status": "Failed",
        }
    ],
    "code": 0,
    "count": 1,
    "current_link": "https://api.tmcas.trendmicro.com/v1/mitigation/mails?batch_id=e371b88f-1b23-4cf1-b372-1144a9af08fa",
    "msg": "",
    "next_link": "null",
    "traceId": "d395a759-976c-45b7-a8d8-35708bbd0fb8",
}

USER_ACTION_RESULT_OUTPUT = [
    {
        "account_provider": "office365",
        "account_user_email": "avishai@demistodev.onmicrosoft.com",
        "action_executed_at": "2020-07-16T06:58:41.346Z",
        "action_id": "2cc933d7-2ca7-45b0-ac9a-c2e0cb0674b3",
        "action_requested_at": "2020-07-16T06:58:42.236Z",
        "action_type": "MAIL_DELETE",
        "batch_id": "e371b88f-1b23-4cf1-b372-1144a9af08fa",
        "error_code": -999,
        "error_message": "The action for these mails failed.",
        "mail_message_id": "\u003cDB7PR07MB5769F7ECC5AA5BAE27713D0399640@DB7PR07MB5769.eurprd07.prod.outlook.com\u003e",
        "mail_unique_id": "AAMkAGY3OTQyMzMzLWYxNjktNDE0My05NmZhLWQ5MGY1YjIyNzBkNABGAAAAAACYCKjWAnXBTrnhgWJCcLX7BwDrxRwRjq-zTrN6vWSzK4OWAAAAAAEJAADrxRwRjq-zTrN6vWSzK4OWAAOT6DZIAAA=",
        "mailbox": "avishai@demistodev.onmicrosoft.com",
        "service": "exchange",
        "status": "Failed",
    }
]

BLOCKED_LISTS_GET_RESULT = {
    "code": 0,
    "message": "Get rules successfully.",
    "rules": {
        "filehashes": ["f3cdddb37f6a933d6a256bd98b4bc703a448c621"],
        "senders": ["456@gmail.com", "123@gmail.com"],
        "urls": ["123.com", "456.com", "789.com"],
    },
}

BLOCKED_LISTS_OUTPUT = {
    "filehashes": ["f3cdddb37f6a933d6a256bd98b4bc703a448c621"],
    "senders": ["456@gmail.com", "123@gmail.com"],
    "urls": ["123.com", "456.com", "789.com"],
}

BLOCKED_LISTS_UPDATE_RESULT = {"code": 0, "message": "Add rules successfully."}
