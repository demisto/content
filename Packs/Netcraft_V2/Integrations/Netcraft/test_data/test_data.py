from ..CommonServerPython import CommandResults

# flake8: noqa

takedown_list_readable = \
'''### Netcraft Takedowns
|ID|Brand|Attack Type|Status|Attack URL|Date Reported|Last Updated|Date Authorised|Date Escalated|First Contact|First Inactive (Monitoring)|First Resolved|
|---|---|---|---|---|---|---|---|---|---|---|---|
| 30480489 | Example Brand | phishing_url | Monitoring | https://l0gin.examp1eb4nk.com/app/ | 2023-09-10 14:13:55.120309 | 2023-09-11 12:19:01 UTC | 2023-09-10 14:13:55.120309 | 2023-09-10 14:13:55.120309 | 2023-09-11 11:29:01 UTC | N/A | 2023-09-11 12:09:01 UTC |
'''


takedown_escalate_readable = \
'''### Takedown successfully escalated.
|Takedown ID|
|---|
| takedown_id |
'''


takedown_note_create_readable = \
'''### Note successfully added to takedown.
|Note ID|Takedown ID|
|---|---|
| 12345 | takedown_id |
'''


submission_file_list_readable = \
'''### Submission Files
|Filename|Hash|Classification|
|---|---|---|
| malicious.exe | d41d8cd98f00b204e9800998ecf8427e | string |
| malicious2.exe | d41d8cd98f00b504e9800998ecf8427e | string2 |
'''


takedown_update_readable = \
'''### Takedown successfully updated.
|Takedown ID|
|---|
| 30480489 |
'''


submission_list_readable = \
'''### Submission submission_uuid
|Submission Date|Last Update|List URLs|List Files|
|---|---|---|---|
| None | None | *This submission has no URLs* | *This submission has no Files* |
'''


submission_mail_get_readable = \
'''### Submission Mails
|Subject|From|To|Classification|
|---|---|---|---|
| string | user@example.com | user@example.com | string |
'''


attack_report_readable = \
'''### Netcraft Takedown
|Report status|Takedown ID|Response code|
|---|---|---|
| The attack was submitted to Netcraft successfully. | 30480489 | TD_OK |
'''


submission_url_list_readable = \
'''### Submission URLs
|URL|Hostname|Classification|URL Classification Log|
|---|---|---|---|
| http://example.com/ | example.com | string | {'date': 1000000000, 'from_state': 'processing', 'to_state': 'no threats'} |
'''


takedown_note_list_readable = \
'''### Takedown Notes
|Note ID|Takedown ID|Group ID|Time|Author|Note|
|---|---|---|---|---|---|
| 12345 | 30480489 | 30480489 | 2023-09-11 12:04:01 UTC | Netcraft | This is an important message! |
| 678910 | 123456 | 123456 | 2023-09-11 12:04:01 UTC | Netcraft | This is a very important message! |
'''


attack_type_list_readable = \
'''### Takedown Notes
|Name|Display Name|Base Type|Description|Automated|Auto Escalation|Auto Authorise|
|---|---|---|---|---|---|---|
| phishing_url | Phishing URL | url | description | true | true | true |
| phishing_url2 | Phishing URL2 | url2 | description2 | true | false | false |
'''


class takedown_list:
    args = {
        "all_results": "false",
        "attack_types": "attack_types,attack_types2",
        "auth_given": "Yes",
        "date_from": "2023-09-10 14:13:55.120309",
        "date_to": "2023-09-10 14:13:55.120309",
        "escalated": "Yes",
        "false_positive": "true",
        "id": "id",
        "id_after": "id_after",
        "id_before": "id_before",
        "ip": "ip",
        "limit": "50",
        "region": "region",
        "report_source": "Interface",
        "reporter_email": "reporter_email",
        "sort": "Auth Given",
        "sort_direction": "asc",
        "statuses": "unverified",
        "url": "url",
    }
    api_response = [
        {
            "attack_type": "phishing_url",
            "attack_url": "https://l0gin.examp1eb4nk.com/app/",
            "authgiven": True,
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
            "escalated": "false",
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
            "reported_url": "https://l0gin.examp1eb4nk.com/app/",
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
    http_func_args = {
        "args": [
            "GET",
            "takedown",
            "attacks/",
            {
                "attack_types": "attack_types,attack_types2",
                "authgiven": "yes",
                "date_from": "2023-09-10 14:13:55.120309",
                "date_to": "2023-09-10 14:13:55.120309",
                "dir": "asc",
                "escalated": "Yes",
                "false_positive": "true",
                "id": "id",
                "id_after": "id_after",
                "id_before": "id_before",
                "ip": "ip",
                "max_results": 50,
                "region": "region",
                "report_source": "interface",
                "reporter_email": "reporter_email",
                "sort": "auth_given",
                "statuses": "unverified",
                "url": "url",
            },
        ],
        "kwargs": {},
    }
    outputs = CommandResults(
        outputs=[
            {
                "attack_type": "phishing_url",
                "attack_url": "https://l0gin.examp1eb4nk.com/app/",
                "authgiven": True,
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
                "escalated": "false",
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
                "reported_url": "https://l0gin.examp1eb4nk.com/app/",
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
        readable_output=takedown_list_readable
    )


class takedown_escalate:
    args = {"takedown_id": "takedown_id"}
    api_response = {"status": "TD_OK"}
    http_func_args = {
        "args": ["POST", "takedown", "escalate/"],
        "kwargs": {"json_data": {"takedown_id": "takedown_id"}},
    }
    outputs = CommandResults(
        outputs=None,
        outputs_key_field=None,
        outputs_prefix=None,
        raw_response={"status": "TD_OK"},
        readable_output=takedown_escalate_readable
    )


class takedown_note_create:
    args = {"note_text": "note_text", "notify": "true", "takedown_id": "takedown_id"}
    api_response = {"note_id": 12345}
    http_func_args = {
        "args": ["POST", "takedown", "notes/"],
        "kwargs": {
            "json_data": {
                "notify": "true",
                "takedown_id": "takedown_id",
                "text": "note_text",
            }
        },
    }
    outputs = CommandResults(
        outputs={"note_id": 12345},
        outputs_key_field="note_id",
        outputs_prefix="Netcraft.TakedownNote",
        raw_response={"note_id": 12345},
        readable_output=takedown_note_create_readable
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
        "args": ["GET", "submission", "submission/submission_uuid/files"],
        "kwargs": {"params": {"count": 2, "page": 2}},
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
        raw_response=[
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
        readable_output=submission_file_list_readable
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
    http_func_args = {
        "args": ["POST", "takedown", "update-attack/"],
        "kwargs": {
            "json_data": {
                "add_tags": "add_tags,add_tags2",
                "brand": "brand",
                "customer_label": "customer_label",
                "description": "description",
                "region": "region",
                "remove_tags": "remove_tags,remove_tags2",
                "set_brand": "brand",
                "set_customer_label": "customer_label",
                "set_description": "description",
                "set_region": "region",
                "set_suspected_fraudulent_domain": "true",
                "set_suspected_fraudulent_hostname": "true",
                "suspected_fraud_domain": "true",
                "suspected_fraud_hostname": "true",
                "takedown_id": "takedown_id",
            }
        },
    }
    outputs = CommandResults(
        outputs=None,
        outputs_key_field=None,
        outputs_prefix=None,
        raw_response=None,
        readable_output=takedown_update_readable
    )


class submission_list:
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
    }
    api_response = {
        "count": 25,
        "marker": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "submissions": [
            {
                "date": 1000000000,
                "source_name": "scam@netcraft.com",
                "state": "string",
                "submitter_email": "example@netcraft.com",
                "submitter_uuid": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "uuid": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            },
            {
                "date": 1200000000,
                "source_name": "scam2@netcraft.com",
                "state": "string2",
                "submitter_email": "example2@netcraft.com",
                "submitter_uuid": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "uuid": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            },
        ],
    }
    http_func_args = {
        "args": ["GET", "submission", "submission/submission_uuid"],
        "kwargs": {},
    }
    outputs = CommandResults(
        outputs={
            "count": 25,
            "has_cryptocurrency_addresses": None,
            "has_files": None,
            "has_issues": None,
            "has_mail": None,
            "has_phone_numbers": None,
            "has_urls": None,
            "is_archived": None,
            "marker": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "pending": None,
            "source_name": None,
            "submissions": [
                {
                    "date": 1000000000,
                    "source_name": "scam@netcraft.com",
                    "state": "string",
                    "submitter_email": "example@netcraft.com",
                    "submitter_uuid": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "uuid": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                },
                {
                    "date": 1200000000,
                    "source_name": "scam2@netcraft.com",
                    "state": "string2",
                    "submitter_email": "example2@netcraft.com",
                    "submitter_uuid": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "uuid": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                },
            ],
            "submitter_email": None,
            "uuid": "submission_uuid",
        },
        outputs_key_field="uuid",
        outputs_prefix="Netcraft.Submission",
        raw_response={
            "count": 25,
            "has_cryptocurrency_addresses": None,
            "has_files": None,
            "has_issues": None,
            "has_mail": None,
            "has_phone_numbers": None,
            "has_urls": None,
            "is_archived": None,
            "marker": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "pending": None,
            "source_name": None,
            "submissions": [
                {
                    "date": 1000000000,
                    "source_name": "scam@netcraft.com",
                    "state": "string",
                    "submitter_email": "example@netcraft.com",
                    "submitter_uuid": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "uuid": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                },
                {
                    "date": 1200000000,
                    "source_name": "scam2@netcraft.com",
                    "state": "string2",
                    "submitter_email": "example2@netcraft.com",
                    "submitter_uuid": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "uuid": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                },
            ],
            "submitter_email": None,
            "uuid": "submission_uuid",
        },
        readable_output=submission_list_readable
    )


class email_report_submit:
    args = {
        "interval_in_seconds": "30",
        "message": "message",
        "password": "password",
        "polling": "true",
        "reporter_email": "reporter_email",
        "timeout": "600",
    }
    api_response = {
        "message": "Successfully reported",
        "uuid": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    }
    http_func_args = {
        "args": ["POST", "submission", "report/mail"],
        "kwargs": {
            "json_data": {
                "email": "reporter_email",
                "message": "message",
                "password": "password",
            }
        },
    }
    outputs = submission_list.outputs


class mail_screenshot_get:
    args = {"submission_uuid": "submission_uuid"}
    api_response = None
    http_func_args = {
        "args": ["GET", "submission", "submission/submission_uuid/mail/screenshot"],
        "kwargs": {"resp_type": "content"},
    }
    outputs = "mail_screenshot_submission_uuid.png"


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
        "args": ["GET", "submission", "submission/submission_uuid/mail"],
        "kwargs": {},
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
        readable_output=submission_mail_get_readable
    )


class file_report_submit:
    args = {
        "entry_id": "entry_id,entry_id2",
        "file_content": "file_content",
        "file_name": "file_name",
        "interval_in_seconds": "30",
        "polling": "true",
        "reason": "reason",
        "reporter_email": "reporter_email",
        "timeout": "600",
    }
    api_response = {
        "message": "Successfully reported",
        "uuid": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    }
    http_func_args = {
        "args": ["POST", "submission", "report/files"],
        "kwargs": {
            "json_data": {
                "email": "reporter_email",
                "files": [{"content": "file_content", "filename": "file_name"}],
                "reason": "reason",
            }
        },
    }
    outputs = submission_list.outputs


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
        "args": ["POST", "takedown", "report/"],
        "kwargs": {
            "files": None,
            "json_data": {
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
                "suspected_fraudulent_domain": True,
                "tags": "tags,tags2",
                "type": "attack_type",
            },
            "resp_type": "text",
        },
    }
    outputs = CommandResults(
        outputs={"id": "30480489"},
        outputs_key_field="id",
        outputs_prefix="Netcraft.Takedown",
        raw_response="TD_OK\n30480489",
        readable_output=attack_report_readable
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
        "args": ["GET", "submission", "submission/submission_uuid/files"],
        "kwargs": {"params": {"count": 2, "page": 2}},
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
        readable_output=submission_url_list_readable
    )


class url_screenshot_get:
    args = {
        "screenshot_hash": "screenshot_hash",
        "submission_uuid": "submission_uuid",
        "url_uuid": "url_uuid",
    }
    api_response = None
    http_func_args = {
        "args": [
            "GET",
            "submission",
            "submission/submission_uuid/urls/url_uuid/screenshots/screenshot_hash",
        ],
        "kwargs": {"resp_type": "response"},
    }
    outputs = "url_screenshot_screenshot_hash.gif"


class takedown_note_list:
    args = {
        "all_results": "false",
        "author_mail": "author_mail",
        "takedown_id": "takedown_id",
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
        "args": ["GET", "takedown", "notes/"],
        "kwargs": {"params": {"author": "author_mail", "takedown_id": "takedown_id"}},
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
        readable_output=takedown_note_list_readable
    )


class file_screenshot_get:
    args = {"file_hash": "file_hash", "submission_uuid": "submission_uuid"}
    api_response = None
    http_func_args = {
        "args": [
            "GET",
            "submission",
            "submission/submission_uuid/files/file_hash/screenshot",
        ],
        "kwargs": {"resp_type": "content"},
    }
    outputs = "file_screenshot_file_hash.png"


class url_report_submit:
    args = {
        "interval_in_seconds": "30",
        "polling": "true",
        "reason": "reason",
        "reporter_email": "reporter_email",
        "timeout": "timeout",
        "urls": "urls,urls2",
    }
    api_response = {
        "message": "Successfully reported",
        "uuid": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    }
    http_func_args = {
        "args": ["POST", "submission", "report/urls"],
        "kwargs": {
            "json_data": {
                "email": "reporter_email",
                "reason": "reason",
                "urls": [{"url": "urls"}, {"url": "urls2"}],
            }
        },
    }
    outputs = submission_list.outputs


class attack_type_list:
    args = {
        "all_results": "false",
        "auto_authorise": "true",
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
        "args": ["GET", "takedown", "attack-types/"],
        "kwargs": {
            "params": {
                "auto_authorise": "true",
                "auto_escalation": "true",
                "automated": "true",
                "region": "region",
            }
        },
    }
    outputs = CommandResults(
        outputs=[
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
        ],
        outputs_key_field=None,
        outputs_prefix="Netcraft.AttackType",
        readable_output=attack_type_list_readable
    )
