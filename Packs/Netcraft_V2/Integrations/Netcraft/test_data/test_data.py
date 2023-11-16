from CommonServerPython import CommandResults
import requests

# flake8: noqa

takedown_list_readable = """### Netcraft Takedowns
|ID|Auth|Brand|Attack Type|Status|Attack URL|Date Reported|Last Updated|Date Authorized|Date Escalated|First Contact|First Resolved|
|---|---|---|---|---|---|---|---|---|---|---|---|
| 30480489 | true | Example Brand | phishing_url | Monitoring | https://l0gin.example.com/app/ | 2023-09-10 14:13:55.120309 | 2023-09-11 12:19:01 UTC | 2023-09-10 14:13:55.120309 | 2023-09-10 14:13:55.120309 | 2023-09-11 11:29:01 UTC | 2023-09-11 12:09:01 UTC |
"""


takedown_escalate_readable = """### Takedown successfully escalated.
|Takedown ID|
|---|
| takedown_id |
"""


takedown_note_create_readable = """### Note successfully added to takedown.
|Note ID|Takedown ID|
|---|---|
| 12345 | takedown_id |
"""


submission_file_list_readable = """### Submission Files
|Filename|Hash|Classification|
|---|---|---|
| malicious.exe | d41d8cd98f00b204e9800998ecf8427e | string |
| malicious2.exe | d41d8cd98f00b504e9800998ecf8427e | string2 |
"""


takedown_update_readable = """### Takedown successfully updated.
|Takedown ID|
|---|
| 30480489 |
"""


submission_list_readable = """### Netcraft Submissions
|Submission UUID|Submission Date|Submitter Email|State|Source|
|---|---|---|---|---|
| bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb | 2001-09-09 01:46:40+00:00 | example@example.com | string | scam@example.com |
| aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa | 2008-01-10 21:20:00+00:00 | example2@example.com | string2 | scam2@example.com |
"""


submission_list_with_uuid_readable = """### Netcraft Submission
|Submission UUID|Submission Date|Submitter Email|State|Source|
|---|---|---|---|---|
| submission_uuid | 2001-09-09 01:46:40+00:00 | test@example.com | processing | scam@example.com |
"""


submission_mail_get_readable = """### Submission Mails
|Subject|From|To|Classification|
|---|---|---|---|
| string | user@example.com | user@example.com | string |
"""


attack_report_readable = """### Netcraft attack reported
|Report status|Takedown ID|Response code|
|---|---|---|
| The attack was submitted to Netcraft successfully. | 30480489 | TD_OK |
"""


submission_url_list_readable = """### Submission URLs
|UUID|URL|Hostname|Classification|URL Classification Log|
|---|---|---|---|---|
| 46b1921f9b4e4b34b547bdf20c0c0263 | http://example.com/ | example.com | string | - date: 1000000000<br>  from_state: processing<br>  to_state: no threats<br> |
"""


takedown_note_list_readable = """### Takedown Notes
|Note ID|Takedown ID|Group ID|Time|Author|Note|
|---|---|---|---|---|---|
| 12345 | 30480489 | 30480489 | 2023-09-11 12:04:01 UTC | Netcraft | This is an important message! |
| 678910 | 123456 | 123456 | 2023-09-11 12:04:01 UTC | Netcraft | This is a very important message! |
"""


attack_type_list_readable = """### Netcraft Attack Types
|Name|Display Name|Base Type|Description|Automated|Auto Escalation|Auto Authorize|
|---|---|---|---|---|---|---|
| phishing_url | Phishing URL | url | description | true | true | true |
| phishing_url2 | Phishing URL2 | url2 | description2 | true | false | false |
"""


class fetch_incidents_first_run:
    last_run = None
    params = {
        "first_fetch": "2022-02-22 00:00:00",
        "max_fetch": "50000000",
        "region": "region",
    }
    api_response = [
        {"id": "1", "date_submitted": "2022-02-22 00:00:00"},
        {"id": "2", "date_submitted": "2022-02-22 00:00:00"},
    ]
    set_last_run = {"id": "2"}
    http_func_args = {
        "args": ["GET"],
        "kwargs": {
            "full_url": "https://takedown.netcraft.com/api/v1/attacks/",
            "data": None,
            "params": {
                "max_results": 100000,
                "sort": "id",
                "region": "region",
                "date_from": "2022-02-22 00:00:00",
            },
            "files": None,
            "resp_type": "json",
            "ok_codes": None,
        },
    }
    outputs = [
        {
            "name": "Takedown-1",
            "occurred": "2022-02-22T00:00:00",
            "rawJSON": '{"id": "1", "date_submitted": "2022-02-22 00:00:00"}',
        },
        {
            "name": "Takedown-2",
            "occurred": "2022-02-22T00:00:00",
            "rawJSON": '{"id": "2", "date_submitted": "2022-02-22 00:00:00"}',
        },
    ]


class fetch_incidents:
    last_run = {"id": "1111111111111"}
    params = {
        "first_fetch": "2022-02-22 00:00:00",
        "max_fetch": "50",
        "region": "region",
    }
    api_response = [
        {"id": "1111111111111", "date_submitted": "2022-02-22 00:00:00"},
        {"id": "1", "date_submitted": "2022-02-22 00:00:00"},
        {"id": "2", "date_submitted": "2022-02-22 00:00:00"},
    ]
    set_last_run = {"id": "2"}
    http_func_args = {
        "args": ["GET"],
        "kwargs": {
            "full_url": "https://takedown.netcraft.com/api/v1/attacks/",
            "data": None,
            "params": {
                "max_results": 50,
                "sort": "id",
                "region": "region",
                "id_after": "1111111111111",
            },
            "files": None,
            "resp_type": "json",
            "ok_codes": None,
        },
    }
    outputs = [
        {
            "name": "Takedown-1",
            "occurred": "2022-02-22T00:00:00",
            "rawJSON": '{"id": "1", "date_submitted": "2022-02-22 00:00:00"}',
        },
        {
            "name": "Takedown-2",
            "occurred": "2022-02-22T00:00:00",
            "rawJSON": '{"id": "2", "date_submitted": "2022-02-22 00:00:00"}',
        },
    ]


class takedown_list:
    args = {
        "all_results": "false",
        "attack_types": "attack_types,attack_types2",
        "auth_given": "Yes Customer",
        "date_from": "2023-09-10 14:13:55.120309",
        "date_to": "2023-09-10 14:13:55.120309",
        "escalated": "Yes Netcraft",
        "false_positive": "true",
        "id": "id",
        "id_after": "id_after",
        "id_before": "id_before",
        "ip": "ip",
        "limit": "50",
        "region": "region",
        "report_source": "Phishing Feed",
        "reporter_email": "reporter_email",
        "sort": "Auth Given",
        "sort_direction": "asc",
        "statuses": ["unverified", "contacted_hosting"],
        "url": "url",
    }
    http_func_args = {
        "args": ["GET"],
        "kwargs": {
            "full_url": "https://takedown.netcraft.com/api/v1/attacks/",
            "params": {
                "attack_types": "attack_types,attack_types2",
                "date_from": "2023-09-10 14:13:55.120309",
                "date_to": "2023-09-10 14:13:55.120309",
                "false_positive": "true",
                "id": "id",
                "id_after": "id_after",
                "id_before": "id_before",
                "ip": "ip",
                "region": "region",
                "report_source": "phish_feed",
                "reporter_email": "reporter_email",
                "sort": "authgiven",
                "statuses": "unverified,contacted_hosting",
                "url": "url",
                "authgiven": "yes:customer",
                "escalated": "yes:netcraft",
                "dir": "asc",
                "max_results": 50,
            },
            "data": None,
            "files": None,
            "resp_type": "json",
            "ok_codes": None,
        },
    }
    api_response = [
        {
            "attack_type": "phishing_url",
            "attack_url": "https://l0gin.example.com/app/",
            "authgiven": "1",
            "authorisation_source": "netcraft",
            "certificate": [],
            "certificate_revoked": "2023-09-11 12:04:01 UTC",
            "country_code": "us",
            "customer_label": "Internal Issue #12345",
            "customer_tag": "",
            "date_authed": "2023-09-10 14:13:55.120309",
            "date_escalated": "2023-09-10 14:13:55.120309",
            "date_first_actioned": "2023-09-10 14:13:55.120309",
            "date_submitted": "2023-09-10 14:13:55.120309",
            "deceptive_domain_score": 9.85,
            "domain": "examp1eb4nk.com",
            "domain_attack": "yes",
            "domain_risk_rating": 10,
            "escalated": "0",
            "escalation_source": "",
            "evidence_url": "https://incident.netcraft.com/1b24dexample/",
            "false_positive": "0",
            "final_outage": "00:45:00",
            "final_resolved": "2023-09-11 12:19:01 UTC",
            "first_contact": "2023-09-11 11:29:01 UTC",
            "first_inactive": "",
            "first_outage": "00:35:00",
            "first_resolved": "2023-09-11 12:09:01 UTC",
            "fwd_owner": "exampleregistrar.com",
            "group_id": "30480489",
            "gsb_block_status": [
                {
                    "is_blocked": True,
                    "platform": "android",
                    "test_date": "2023-09-11 12:04:01 UTC",
                },
                {
                    "is_blocked": False,
                    "platform": "ios",
                    "test_date": "2023-09-11 12:01:01 UTC",
                },
                {
                    "is_blocked": True,
                    "platform": "desktop",
                    "test_date": "2023-09-11 12:05:01 UTC",
                },
            ],
            "gsb_first_blocked": [
                {"first_blocked": "2023-09-11 12:04:01 UTC", "platform": "android"},
                {"first_blocked": "2023-09-11 12:01:01 UTC", "platform": "desktop"},
                {"first_blocked": "2023-09-11 12:05:01 UTC", "platform": "ios"},
            ],
            "has_phishing_kit": "1",
            "host": "Example Host",
            "hostname": "l0gin.examp1eb4nk.com",
            "hostname_attack": "yes_low_confidence",
            "hostname_ddss_score": 8.25,
            "id": "30480489",
            "ip": "192.0.2.1",
            "is_redirect": "final",
            "language": "english",
            "last_updated": "2023-09-11 12:19:01 UTC",
            "logged_credential_injections": [
                {"type": "username", "value": "user@example.com"},
                {"type": "password", "value": "3w45gw34"},
            ],
            "malware_category": "",
            "malware_family": "",
            "managed": "0",
            "phishing_kit_hash": "2818a25d2f839c3e0608f00af34bb98ca2571c74",
            "region": "example_region",
            "registrar": "Example Registrar",
            "report_source": "Takedown Interface",
            "reported_url": "https://l0gin.example.com/app/",
            "reporter": "user@examplebank.com",
            "restart_date": "",
            "rev_owner": "examplehost.com",
            "reverse_dns": "192-0-2-1.examplehost.com",
            "screenshot_url": "https://screenshot.netcraft.com/images/archive/<date>/s3e93b5d93ed97ebd2c3d0876dae9b57.png",
            "site_risk_rating": 9,
            "status": "Monitoring",
            "status_change_uptime": "00:40:00",
            "stop_monitoring_date": "",
            "tags": [],
            "target_brand": "Example Brand",
            "targeted_url": "https://examplebank.com/",
            "whois_data": "string",
            "whois_server": "whois.exampleregistrar.com",
        }
    ]
    outputs = CommandResults(
        outputs=[
            {
                "attack_type": "phishing_url",
                "attack_url": "https://l0gin.example.com/app/",
                "authgiven": True,
                "authorization_source": "netcraft",
                "certificate": [],
                "certificate_revoked": "2023-09-11 12:04:01 UTC",
                "country_code": "us",
                "customer_label": "Internal Issue #12345",
                "customer_tag": "",
                "date_authed": "2023-09-10 14:13:55.120309",
                "date_escalated": "2023-09-10 14:13:55.120309",
                "date_first_actioned": "2023-09-10 14:13:55.120309",
                "date_submitted": "2023-09-10 14:13:55.120309",
                "deceptive_domain_score": 9.85,
                "domain": "examp1eb4nk.com",
                "domain_attack": "yes",
                "domain_risk_rating": 10,
                "escalated": False,
                "escalation_source": "",
                "evidence_url": "https://incident.netcraft.com/1b24dexample/",
                "false_positive": False,
                "final_outage": "00:45:00",
                "final_resolved": "2023-09-11 12:19:01 UTC",
                "first_contact": "2023-09-11 11:29:01 UTC",
                "first_inactive": "",
                "first_outage": "00:35:00",
                "first_resolved": "2023-09-11 12:09:01 UTC",
                "fwd_owner": "exampleregistrar.com",
                "group_id": "30480489",
                "gsb_block_status": [
                    {
                        "is_blocked": True,
                        "platform": "android",
                        "test_date": "2023-09-11 12:04:01 UTC",
                    },
                    {
                        "is_blocked": False,
                        "platform": "ios",
                        "test_date": "2023-09-11 12:01:01 UTC",
                    },
                    {
                        "is_blocked": True,
                        "platform": "desktop",
                        "test_date": "2023-09-11 12:05:01 UTC",
                    },
                ],
                "gsb_first_blocked": [
                    {"first_blocked": "2023-09-11 12:04:01 UTC", "platform": "android"},
                    {"first_blocked": "2023-09-11 12:01:01 UTC", "platform": "desktop"},
                    {"first_blocked": "2023-09-11 12:05:01 UTC", "platform": "ios"},
                ],
                "has_phishing_kit": True,
                "host": "Example Host",
                "hostname": "l0gin.examp1eb4nk.com",
                "hostname_attack": "yes_low_confidence",
                "hostname_ddss_score": 8.25,
                "id": "30480489",
                "ip": "192.0.2.1",
                "is_redirect": "final",
                "language": "english",
                "last_updated": "2023-09-11 12:19:01 UTC",
                "logged_credential_injections": [
                    {"type": "username", "value": "user@example.com"},
                    {"type": "password", "value": "3w45gw34"},
                ],
                "malware_category": "",
                "malware_family": "",
                "managed": False,
                "phishing_kit_hash": "2818a25d2f839c3e0608f00af34bb98ca2571c74",
                "region": "example_region",
                "registrar": "Example Registrar",
                "report_source": "Takedown Interface",
                "reported_url": "https://l0gin.example.com/app/",
                "reporter": "user@examplebank.com",
                "restart_date": "",
                "rev_owner": "examplehost.com",
                "reverse_dns": "192-0-2-1.examplehost.com",
                "screenshot_url": "https://screenshot.netcraft.com/images/archive/<date>/s3e93b5d93ed97ebd2c3d0876dae9b57.png",
                "site_risk_rating": 9,
                "status": "Monitoring",
                "status_change_uptime": "00:40:00",
                "stop_monitoring_date": "",
                "tags": [],
                "target_brand": "Example Brand",
                "targeted_url": "https://examplebank.com/",
                "whois_data": "string",
                "whois_server": "whois.exampleregistrar.com",
            }
        ],
        outputs_key_field="id",
        outputs_prefix="Netcraft.Takedown",
        readable_output=takedown_list_readable,
    )


class takedown_escalate:
    args = {"takedown_id": "takedown_id"}
    api_response = {"status": "TD_OK"}
    http_func_args = {
        "args": ["POST"],
        "kwargs": {
            "full_url": "https://takedown.netcraft.com/api/v1/escalate/",
            "params": None,
            "data": {"takedown_id": "takedown_id"},
            "files": None,
            "resp_type": "json",
            "ok_codes": None,
        },
    }
    outputs = CommandResults(
        outputs=None,
        outputs_key_field=None,
        outputs_prefix=None,
        raw_response={"status": "TD_OK"},
        readable_output=takedown_escalate_readable,
    )


class takedown_note_create:
    args = {"note_text": "note_text", "notify": "true", "takedown_id": "takedown_id"}
    api_response = {"note_id": 12345}
    http_func_args = {
        "args": ["POST"],
        "kwargs": {
            "full_url": "https://takedown.netcraft.com/api/v1/notes/",
            "params": None,
            "data": {
                "notify": True,
                "takedown_id": "takedown_id",
                "text": "note_text",
            },
            "files": None,
            "resp_type": "json",
            "ok_codes": None,
        },
    }

    outputs = CommandResults(
        outputs={"note_id": 12345},
        outputs_key_field="note_id",
        outputs_prefix="Netcraft.TakedownNote",
        raw_response={"note_id": 12345},
        readable_output=takedown_note_create_readable,
    )


class submission_file_list:
    args = {
        "limit": "50",
        "page": "2",
        "page_size": "2",
        "submission_uuid": "submission_uuid",
    }
    api_response = {
        "files": [
            {
                "classification_log": [
                    {
                        "date": 1000000000,
                        "from_state": "processing",
                        "to_state": "no threats",
                    }
                ],
                "file_state": "string",
                "filename": "malicious.exe",
                "has_screenshot": "1",
                "hash": "d41d8cd98f00b204e9800998ecf8427e",
            },
            {
                "classification_log": [
                    {
                        "date": 1100000000,
                        "from_state": "no threats",
                        "to_state": "processing",
                    }
                ],
                "file_state": "string2",
                "filename": "malicious2.exe",
                "has_screenshot": "0",
                "hash": "d41d8cd98f00b504e9800998ecf8427e",
            },
        ],
        "filtered_count": 50,
        "total_count": 1,
    }
    http_func_args = {
        "args": ["GET"],
        "kwargs": {
            "full_url": "https://report.netcraft.com/api/v3/submission/submission_uuid/files",
            "params": {"page": 2, "count": 2},
            "json_data": None,
            "files": None,
            "resp_type": "json",
            "ok_codes": None,
        },
    }

    outputs = CommandResults(
        outputs=[
            {
                "classification_log": [
                    {
                        "date": 1000000000,
                        "from_state": "processing",
                        "to_state": "no threats",
                    }
                ],
                "file_state": "string",
                "filename": "malicious.exe",
                "has_screenshot": True,
                "hash": "d41d8cd98f00b204e9800998ecf8427e",
            },
            {
                "classification_log": [
                    {
                        "date": 1100000000,
                        "from_state": "no threats",
                        "to_state": "processing",
                    }
                ],
                "file_state": "string2",
                "filename": "malicious2.exe",
                "has_screenshot": False,
                "hash": "d41d8cd98f00b504e9800998ecf8427e",
            },
        ],
        outputs_key_field="hash",
        outputs_prefix="Netcraft.SubmissionFile",
        readable_output=submission_file_list_readable,
    )


class takedown_update:
    args = {
        "add_tags": "add_tags,add_tags2",
        "brand": "brand",
        "customer_label": "customer_label",
        "description": "description",
        "region": "region",
        "remove_tags": "remove_tags,remove_tags2",
        "suspected_fraud_domain": "true",
        "suspected_fraud_hostname": "true",
        "takedown_id": "takedown_id",
    }
    http_func_args = {
        "args": ["POST"],
        "kwargs": {
            "full_url": "https://takedown.netcraft.com/api/v1/update-attack/",
            "params": None,
            "data": {
                "set_customer_label": "customer_label",
                "set_description": "description",
                "set_region": "region",
                "set_brand": "brand",
                "set_suspected_fraudulent_domain": "true",
                "set_suspected_fraudulent_hostname": "true",
                "add_tags": "add_tags,add_tags2",
                "remove_tags": "remove_tags,remove_tags2",
                "takedown_id": "takedown_id",
            },
            "files": None,
            "resp_type": "json",
            "ok_codes": None,
        },
    }

    api_response = {
        "customer_label": "Internal Issue #12345",
        "description": "New description of takedown",
        "region": "example_region",
        "suspected_fraudulent_domain": "false",
        "suspected_fraudulent_hostname": "false",
        "tags": ["tag1", "tag2"],
        "takedown_id": "30480489",
        "target_brand": "Example Brand",
    }
    outputs = CommandResults(
        outputs=None,
        outputs_key_field=None,
        outputs_prefix=None,
        readable_output=takedown_update_readable,
        raw_response={
            "customer_label": "Internal Issue #12345",
            "description": "New description of takedown",
            "region": "example_region",
            "suspected_fraudulent_domain": "false",
            "suspected_fraudulent_hostname": "false",
            "tags": ["tag1", "tag2"],
            "takedown_id": "30480489",
            "target_brand": "Example Brand",
        },
    )


class submission_list:
    args = {
        "date_end": "2023-09-10 14:13:55.120309",
        "date_start": "2023-09-10 14:13:55.120309",
        "limit": "50",
        "next_token": "next_token",
        "page_size": "2",
        "source_name": "source_name",
        "state": "No Threats",
        "submission_reason": "submission_reason",
        "submitter_email": "submitter_email",
        "polling": "false",
        "ignore_404": False,
    }
    api_response = {
        "count": 25,
        "marker": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "submissions": [
            {
                "date": 1000000000,
                "source_name": "scam@example.com",
                "state": "string",
                "submitter_email": "example@example.com",
                "submitter_uuid": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "uuid": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            },
            {
                "date": 1200000000,
                "source_name": "scam2@example.com",
                "state": "string2",
                "submitter_email": "example2@example.com",
                "submitter_uuid": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "uuid": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            },
        ],
    }
    http_func_args = {
        "args": ["GET"],
        "kwargs": {
            "full_url": "https://report.netcraft.com/api/v3/submissions/",
            "params": {
                "state": "no threats",
                "source_name": "source_name",
                "submission_reason": "submission_reason",
                "submitter_email": "submitter_email",
                "date_end": "2023-09-10",
                "date_start": "2023-09-10",
                "marker": "next_token",
                "page_size": 2,
            },
            "json_data": None,
            "files": None,
            "resp_type": "json",
            "ok_codes": None,
        },
    }
    outputs = CommandResults(
        outputs={
            "Netcraft.Submission(val.uuid && val.uuid == obj.uuid)": [
                {
                    "date": 1000000000,
                    "source_name": "scam@example.com",
                    "state": "string",
                    "submitter_email": "example@example.com",
                    "submitter_uuid": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "uuid": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                },
                {
                    "date": 1200000000,
                    "source_name": "scam2@example.com",
                    "state": "string2",
                    "submitter_email": "example2@example.com",
                    "submitter_uuid": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "uuid": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                },
            ],
            "Netcraft(true)": {
                "SubmissionNextToken": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            },
        },
        outputs_key_field="uuid",
        outputs_prefix="Netcraft.Submission",
        readable_output=submission_list_readable,
    )


class submission_list_with_uuid:
    args = {
        "date_end": "2023-09-10 14:13:55.120309",
        "date_start": "2023-09-10 14:13:55.120309",
        "limit": "50",
        "next_token": "next_token",
        "page_size": "2",
        "source_name": "source_name",
        "state": "state",
        "submission_reason": "submission_reason",
        "submission_uuid": "submission_uuid",
        "submitter_email": "submitter_email",
        "polling": "false",
        "ignore_404": True,
    }
    api_response = {
        "classification_log": [
            {"date": 1000000000, "from_state": "no threats", "to_state": "malicious"}
        ],
        "date": 1000000000,
        "files": "https://report.netcraft.com/api/v3/submission/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/files",
        "has_cryptocurrency_addresses": "1",
        "has_files": "0",
        "has_issues": "0",
        "has_mail": "1",
        "has_phone_numbers": "1",
        "has_urls": "1",
        "is_archived": "1",
        "last_update": 1000000000,
        "mail": "https://report.netcraft.com/api/v3/submission/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/mail",
        "mail_state": "malicious",
        "original_source": {"name": "scam@example.com", "type": "email"},
        "pending": 0,
        "reason": "null",
        "source": {
            "name": "scam@example.com",
            "type": "email",
            "uuid": "9aebe138a5809803b768aa85a268a2e6",
        },
        "state": "processing",
        "state_counts": {
            "files": {"malicious": 1, "no threats": 2},
            "urls": {"malicious": 1, "no threats": 2},
        },
        "submitter": {"email": "test@example.com"},
        "tags": [{"description": "This is a phishing tag.", "name": "phishing"}],
        "urls": "https://report.netcraft.com/api/v3/submission/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/urls",
        "warnings": [
            {
                "link": "https://report.netcraft.com/release-notes",
                "warning": "This submission was made to v1 of the API which is now deprecated. Please upgrade to v3.",
            }
        ],
    }
    http_func_args = {
        "args": ["GET"],
        "kwargs": {
            "full_url": "https://report.netcraft.com/api/v3/submission/submission_uuid",
            "params": None,
            "json_data": None,
            "files": None,
            "resp_type": "json",
            "ok_codes": (200, 404),
        },
    }
    outputs = CommandResults(
        outputs={
            "classification_log": [
                {
                    "date": 1000000000,
                    "from_state": "no threats",
                    "to_state": "malicious",
                }
            ],
            "date": 1000000000,
            "files": "https://report.netcraft.com/api/v3/submission/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/files",
            "has_cryptocurrency_addresses": True,
            "has_files": False,
            "has_issues": False,
            "has_mail": True,
            "has_phone_numbers": True,
            "has_urls": True,
            "is_archived": True,
            "last_update": 1000000000,
            "mail": "https://report.netcraft.com/api/v3/submission/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/mail",
            "mail_state": "malicious",
            "original_source": {"name": "scam@example.com", "type": "email"},
            "pending": False,
            "reason": "null",
            "source": {
                "type": "email",
                "uuid": "9aebe138a5809803b768aa85a268a2e6",
            },
            "state": "processing",
            "state_counts": {
                "files": {"malicious": 1, "no threats": 2},
                "urls": {"malicious": 1, "no threats": 2},
            },
            "tags": [{"description": "This is a phishing tag.", "name": "phishing"}],
            "urls": "https://report.netcraft.com/api/v3/submission/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/urls",
            "warnings": [
                {
                    "link": "https://report.netcraft.com/release-notes",
                    "warning": "This submission was made to v1 of the API which is now deprecated. Please upgrade to v3.",
                }
            ],
            "source_name": "scam@example.com",
            "submitter_email": "test@example.com",
            "uuid": "submission_uuid",
        },
        outputs_key_field="uuid",
        outputs_prefix="Netcraft.Submission",
        readable_output=submission_list_with_uuid_readable,
    )


class email_report_submit:
    args = {
        "reporter_email": "reporter_email",
        "message": "message",
        "password": "password",
        "polling": "true",
        "timeout": "600",
        "interval_in_seconds": "30",
    }
    api_response = {
        "message": "Successfully reported",
        "uuid": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    }
    http_func_args = {
        "args": ["POST"],
        "kwargs": {
            "json_data": {
                "email": "reporter_email",
                "message": "message",
                "password": "password",
            },
            "files": None,
            "full_url": "https://report.netcraft.com/api/v3/report/mail",
            "ok_codes": None,
            "params": None,
            "resp_type": "json",
        },
    }
    get_submission_call_args = (
        {
            "polling": "true",
            "timeout": "600",
            "interval_in_seconds": "30",
            "ignore_404": True,
            "reporter_email": "reporter_email",
            "message": "message",
            "password": "password",
        },
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )


class mail_screenshot_get:
    args = {"submission_uuid": "submission_uuid"}
    api_response = requests.Response()
    api_response.status_code = 200
    http_func_args = {
        "args": ["GET"],
        "kwargs": {
            "full_url": "https://report.netcraft.com/api/v3/submission/submission_uuid/mail/screenshot",
            "params": None,
            "json_data": None,
            "files": None,
            "resp_type": "response",
            "ok_codes": (200, 404),
        },
    }
    outputs = "email_screenshot_submission_uuid.png"


class mail_screenshot_get_404(mail_screenshot_get):
    api_response = requests.Response()
    api_response.status_code = 404
    outputs = "No screenshot for mail."


class submission_mail_get:
    args = {"submission_uuid": "submission_uuid"}
    api_response = {
        "classification_log": [
            {"date": 1000000000, "from_state": "processing", "to_state": "no threats"}
        ],
        "from": ["user@example.com"],
        "hash": "string",
        "reply_to": ["user@example.com"],
        "state": "string",
        "subject": "string",
        "to": ["user@example.com"],
    }
    http_func_args = {
        "args": ["GET"],
        "kwargs": {
            "full_url": "https://report.netcraft.com/api/v3/submission/submission_uuid/mail",
            "params": None,
            "json_data": None,
            "files": None,
            "resp_type": "json",
            "ok_codes": None,
        },
    }
    outputs = CommandResults(
        outputs={
            "classification_log": [
                {
                    "date": 1000000000,
                    "from_state": "processing",
                    "to_state": "no threats",
                }
            ],
            "from": ["user@example.com"],
            "hash": "string",
            "reply_to": ["user@example.com"],
            "state": "string",
            "subject": "string",
            "to": ["user@example.com"],
        },
        outputs_key_field="hash",
        outputs_prefix="Netcraft.SubmissionMail",
        readable_output=submission_mail_get_readable,
    )


class file_report_submit_with_file_name_and_content:
    args = {
        "entry_id": "entry_id,entry_id2",
        "file_content": "file_content",
        "file_name": "file_name",
        "reason": "reason",
        "reporter_email": "reporter_email",
        "polling": "true",
        "timeout": "600",
        "interval_in_seconds": "30",
    }
    api_response = {
        "message": "Successfully reported",
        "uuid": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    }
    http_func_args = {
        "args": ["POST"],
        "kwargs": {
            "json_data": {
                "email": "reporter_email",
                "files": [{"content": "file_content", "filename": "file_name"}],
                "reason": "reason",
            },
            "files": None,
            "full_url": "https://report.netcraft.com/api/v3/report/files",
            "ok_codes": None,
            "params": None,
            "resp_type": "json",
        },
    }
    get_submission_call_args = (
        {
            "polling": "true",
            "timeout": "600",
            "interval_in_seconds": "30",
            "ignore_404": True,
        },
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    getFilePath_call_args = "[]"


class file_report_submit_with_entry_id(file_report_submit_with_file_name_and_content):
    args = {
        "entry_id": "entry_id,entry_id2",
        "reason": "reason",
        "reporter_email": "reporter_email",
        "polling": "true",
        "timeout": "600",
        "interval_in_seconds": "30",
    }
    http_func_args = {
        "args": ["POST"],
        "kwargs": {
            "json_data": {
                "email": "reporter_email",
                "files": [
                    {"content": "bW9jayBmaWxlIGNvbnRlbnRz", "filename": "file name"},
                    {"content": "bW9jayBmaWxlIGNvbnRlbnRz", "filename": "file name"},
                ],
                "reason": "reason",
            },
            "files": None,
            "full_url": "https://report.netcraft.com/api/v3/report/files",
            "ok_codes": None,
            "params": None,
            "resp_type": "json",
        },
    }
    getFilePath_call_args = "[call('entry_id'), call('entry_id2')]"


class attack_report:
    args = {
        "attack": "attack",
        "attack_type": "attack_type",
        "brand": "brand",
        "comment": "comment",
        "customer_label": "customer_label",
        "entry_id": "entry_id",
        "force_auth": "true",
        "inactive": "true",
        "malware": "true",
        "password": "password",
        "phishkit_fetch_url": "phishkit_fetch_url.com",
        "phishkit_phish_url": "phishkit_phish_url.com",
        "region": "region",
        "suspected_fraud_domain": "true",
        "tags": "tags,tags2",
    }
    api_response = "TD_OK\n30480489"
    http_func_args = {
        "args": ["POST"],
        "kwargs": {
            "full_url": "https://takedown.netcraft.com/api/v1/report/",
            "params": None,
            "data": {
                "attack": "attack",
                "brand": "brand",
                "comment": "comment",
                "customer_label": "customer_label",
                "entry_id": "entry_id",
                "force_auth": True,
                "inactive": True,
                "malware": True,
                "password": "password",
                "phishkit_fetch_url": "phishkit_fetch_url.com",
                "phishkit_phish_url": "phishkit_phish_url.com",
                "region": "region",
                "tags": "tags,tags2",
                "type": "attack_type",
                "suspected_fraudulent_domain": True,
            },
            "resp_type": "text",
            "ok_codes": None,
        },
    }
    outputs = CommandResults(
        outputs={"id": "30480489"},
        outputs_key_field="id",
        outputs_prefix="Netcraft.Takedown",
        raw_response="TD_OK\n30480489",
        readable_output=attack_report_readable,
    )


class submission_url_list:
    args = {
        "limit": "50",
        "page": "2",
        "page_size": "2",
        "submission_uuid": "submission_uuid",
    }
    api_response = {
        "filtered_count": 5,
        "total_count": 10,
        "urls": [
            {
                "classification_log": [
                    {
                        "date": 1000000000,
                        "from_state": "processing",
                        "to_state": "no threats",
                    }
                ],
                "country_code": "GB",
                "file_hash": "d41d8cd98f00b204e9800998ecf8427e",
                "hostname": "example.com",
                "incident_report_url": "https://incident.netcraft.com/aaaaaaaaaaaa/",
                "ip": "127.0.0.1",
                "reason": "This site impersonates an official brand website.",
                "screenshots": [
                    {"hash": "XswLgTyECQur1DxIisHiwmk6pScJ6rDl", "type": "gif"}
                ],
                "source": "mail",
                "sources": [
                    {
                        "file_hash": "3707006ea361435383622df81feffad6",
                        "file_name": "a.file",
                        "source": "mail",
                        "source_id": 1,
                    }
                ],
                "tags": [
                    {
                        "description": "This is a phishing tag.",
                        "name": "phishing",
                        "submitter_tag": 1,
                    }
                ],
                "takedown_link": "https://takedown.netcraft.com/1",
                "takedown_url_id": 1,
                "url": "http://example.com/",
                "url_classification_reason": "Already reported and rejected.",
                "url_state": "string",
                "url_takedown_state": "not injected",
                "uuid": "46b1921f9b4e4b34b547bdf20c0c0263",
            }
        ],
    }
    http_func_args = {
        "args": ["GET"],
        "kwargs": {
            "full_url": "https://report.netcraft.com/api/v3/submission/submission_uuid/urls",
            "params": {"page": 2, "count": 2},
            "json_data": None,
            "files": None,
            "resp_type": "json",
            "ok_codes": None,
        },
    }
    outputs = CommandResults(
        outputs=[
            {
                "classification_log": [
                    {
                        "date": 1000000000,
                        "from_state": "processing",
                        "to_state": "no threats",
                    }
                ],
                "country_code": "GB",
                "file_hash": "d41d8cd98f00b204e9800998ecf8427e",
                "hostname": "example.com",
                "incident_report_url": "https://incident.netcraft.com/aaaaaaaaaaaa/",
                "ip": "127.0.0.1",
                "reason": "This site impersonates an official brand website.",
                "screenshots": [
                    {"hash": "XswLgTyECQur1DxIisHiwmk6pScJ6rDl", "type": "gif"}
                ],
                "source": "mail",
                "sources": [
                    {
                        "file_hash": "3707006ea361435383622df81feffad6",
                        "file_name": "a.file",
                        "source": "mail",
                        "source_id": 1,
                    }
                ],
                "tags": [
                    {
                        "description": "This is a phishing tag.",
                        "name": "phishing",
                        "submitter_tag": 1,
                    }
                ],
                "takedown_link": "https://takedown.netcraft.com/1",
                "takedown_url_id": 1,
                "url": "http://example.com/",
                "url_classification_reason": "Already reported and rejected.",
                "url_state": "string",
                "url_takedown_state": "not injected",
                "uuid": "46b1921f9b4e4b34b547bdf20c0c0263",
            }
        ],
        outputs_key_field="uuid",
        outputs_prefix="Netcraft.SubmissionURL",
        readable_output=submission_url_list_readable,
    )


class url_screenshot_get:
    args = {
        "screenshot_hash": "screenshot_hash",
        "submission_uuid": "submission_uuid",
        "url_uuid": "url_uuid",
    }
    api_response = requests.Response()
    api_response.headers["Content-Type"] = "image/gif"
    http_func_args = {
        "args": ["GET"],
        "kwargs": {
            "full_url": "https://report.netcraft.com/api/v3/submission/submission_uuid/urls/url_uuid/screenshots/screenshot_hash",
            "params": None,
            "json_data": None,
            "files": None,
            "resp_type": "response",
            "ok_codes": None,
        },
    }
    outputs = "url_screenshot_screenshot_hash.gif"


class takedown_note_list:
    args = {
        "author_mail": "author_mail",
        "takedown_id": "takedown_id",
        "all_results": "false",
    }
    api_response = [
        {
            "author": "Netcraft",
            "group_id": "30480489",
            "note": "This is an important message!",
            "note_id": 12345,
            "takedown_id": "30480489",
            "time": "2023-09-11 12:04:01 UTC",
        },
        {
            "author": "Netcraft",
            "group_id": "123456",
            "note": "This is a very important message!",
            "note_id": 678910,
            "takedown_id": "123456",
            "time": "2023-09-11 12:04:01 UTC",
        },
    ]
    http_func_args = {
        "args": ["GET"],
        "kwargs": {
            "full_url": "https://takedown.netcraft.com/api/v1/notes/",
            "params": {"takedown_id": "takedown_id", "author": "author_mail"},
            "data": None,
            "files": None,
            "resp_type": "json",
            "ok_codes": None,
        },
    }

    outputs = CommandResults(
        outputs=[
            {
                "author": "Netcraft",
                "group_id": "30480489",
                "note": "This is an important message!",
                "note_id": 12345,
                "takedown_id": "30480489",
                "time": "2023-09-11 12:04:01 UTC",
            },
            {
                "author": "Netcraft",
                "group_id": "123456",
                "note": "This is a very important message!",
                "note_id": 678910,
                "takedown_id": "123456",
                "time": "2023-09-11 12:04:01 UTC",
            },
        ],
        outputs_key_field="note_id",
        outputs_prefix="Netcraft.TakedownNote",
        readable_output=takedown_note_list_readable,
    )


class file_screenshot_get:
    args = {"file_hash": "file_hash", "submission_uuid": "submission_uuid"}
    api_response = requests.Response()
    api_response.status_code = 200
    http_func_args = {
        "args": ["GET"],
        "kwargs": {
            "full_url": "https://report.netcraft.com/api/v3/submission/submission_uuid/files/file_hash/screenshot",
            "params": None,
            "json_data": None,
            "files": None,
            "resp_type": "response",
            "ok_codes": (200, 404),
        },
    }
    outputs = "file_screenshot_file_hash.png"


class file_screenshot_get_404(file_screenshot_get):
    api_response = requests.Response()
    api_response.status_code = 404
    outputs = "No screenshot for file."


class url_report_submit:
    args = {
        "interval_in_seconds": "30",
        "polling": "true",
        "reason": "reason",
        "reporter_email": "reporter_email",
        "timeout": "600",
        "urls": "urls,urls2",
    }
    api_response = {
        "message": "Successfully reported",
        "uuid": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    }
    http_func_args = {
        "args": ["POST"],
        "kwargs": {
            "json_data": {
                "email": "reporter_email",
                "reason": "reason",
                "urls": [{"url": "urls"}, {"url": "urls2"}],
            },
            "files": None,
            "full_url": "https://report.netcraft.com/api/v3/report/urls",
            "ok_codes": None,
            "params": None,
            "resp_type": "json",
        },
    }
    get_submission_call_args = (
        {
            "polling": "true",
            "timeout": "600",
            "interval_in_seconds": "30",
            "ignore_404": True,
        },
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )


class attack_type_list:
    args = {
        "all_results": "false",
        "auto_authorize": "true",
        "auto_escalation": "true",
        "automated": "true",
        "region": "region",
    }
    api_response = [
        {
            "auto_authorise": True,
            "auto_escalation": True,
            "automated": True,
            "base_type": "url",
            "description": "description",
            "display_name": "Phishing URL",
            "name": "phishing_url",
        },
        {
            "auto_authorise": False,
            "auto_escalation": False,
            "automated": True,
            "base_type": "url2",
            "description": "description2",
            "display_name": "Phishing URL2",
            "name": "phishing_url2",
        },
    ]
    http_func_args = {
        "args": ["GET"],
        "kwargs": {
            "full_url": "https://takedown.netcraft.com/api/v1/attack-types/",
            "params": {
                "auto_escalation": "true",
                "auto_authorise": "true",
                "automated": "true",
                "region": "region",
            },
            "data": None,
            "files": None,
            "resp_type": "json",
            "ok_codes": None,
        },
    }
    outputs = CommandResults(
        outputs=[
            {
                "auto_authorize": True,
                "auto_escalation": True,
                "automated": True,
                "base_type": "url",
                "description": "description",
                "display_name": "Phishing URL",
                "name": "phishing_url",
            },
            {
                "auto_authorize": False,
                "auto_escalation": False,
                "automated": True,
                "base_type": "url2",
                "description": "description2",
                "display_name": "Phishing URL2",
                "name": "phishing_url2",
            },
        ],
        outputs_key_field=None,
        outputs_prefix="Netcraft.AttackType",
        readable_output=attack_type_list_readable,
    )
