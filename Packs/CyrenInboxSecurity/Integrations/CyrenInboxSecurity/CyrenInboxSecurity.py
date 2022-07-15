import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


# noqa: F401
# noqa: F401
# noqa: F401
# noqa: F401
# noqa: F401
# noqa: F401
"""
CyrenInboxSecurity Integration for Cortex XSOAR (formerly Demisto)

"""

import json
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''


MAX_INCIDENTS_TO_FETCH = 50

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    It handles requests and returns data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    """

    def get_token(self, client_id, client_secret):
        request_params = {
            'client_id': client_id,
            'client_secret': client_secret,
            'grant_type': 'client_credentials'
        }

        return self._http_request(
            method='POST',
            url_suffix='/v1/token',
            params=request_params
        )

    def get_incidents(self, token, date_from, max_fetch):
        request_params = {
            'date_from': date_from,
            'limit': max_fetch
        }

        headers = {
            'Authorization': f'Bearer {token}'
        }

        return self._http_request(
            method='GET',
            url_suffix='/v1/incidents',
            headers=headers,
            params=request_params
        )

    def resolve_and_remediate(self, token, case_id, **kwargs):

        headers = {
            'Authorization': f'Bearer {token}'
        }

        return self._http_request(
            method='PATCH',
            url_suffix=f'/v1/cases/{case_id}/resolution',
            headers=headers,
            json_data=kwargs
        )


''' HELPER FUNCTIONS '''


def convert_to_demisto_severity(severity):
    """Maps CyrenInboxSecurity severity to Cortex XSOAR severity

    Converts the CyrenInboxSecurity confidence levels (1, 2,
    3) to Cortex XSOAR incident severity (1 to 4)
    for mapping. Note, there are only 3 Cyren confidence levels

    :type severity: ``int``
    :param severity: severity as returned from the CyrenInboxSecurity API (int)

    :return: Cortex XSOAR Severity (2 to 4)
    :rtype: ``int``
    """

    return {
        0: IncidentSeverity.LOW,
        1: IncidentSeverity.MEDIUM,
        2: IncidentSeverity.HIGH,
        3: IncidentSeverity.CRITICAL
    }[severity]


''' COMMAND FUNCTIONS '''


def test_module(client, client_id, client_secret):
    """Tests API connectivity and authentication'

        Returning 'ok' indicates that the integration works
         like it is supposed to.
        Connection to the service is successful.
        Raises exceptions if something goes wrong.

        :type client: ``Client``
        :param Client: CyrenInboxSecurity client to use

        :type client_id: ``str``
        :param client_id: A unique string that identifies the client

        :type client_secret: ``str``
        :param client_secret: A unique string that represent the client secret

        :return: 'ok' if test passed, anything else will fail the test.
        :rtype: ``str``
        """

    try:
        client.get_token(client_id, client_secret)
    except DemistoException as e:
        raise e

    return 'ok'


def simulate_fetch():
    """
    Ingesting a sample incident to XSOAR
    """

    # Ensure only one sample is created
    last_run = demisto.getLastRun()
    if last_run.get("sample_fetched", False):
        return []
    else:
        demisto.setLastRun({'sample_fetched': True})

    now_time = datetime.now()
    now_time_timestamp_seconds = int(date_to_timestamp(now_time) / 1000)
    sample_incident = {
        "incident_id": "incidentID-" + str(now_time_timestamp_seconds),
        "case_id": "caseID-123",
        "tx_id": "txID-" + str(now_time_timestamp_seconds),
        "threat_type": "phishing",
        "application": "office365",
        "connection_id": "connectionID",
        "connection_name": "ConnectionName",
        "org_id": 1,
        "tenant_id": "tenantID",
        "remediation_data": {
            "remediation_type": "auto_remediation",
            "remediation": "not_remediated",
            "policy_action": [
                {
                    "performed_date": 1625484377,
                    "messages": None,
                    "action_type": "ADD_BANNER",
                    "action_status": "success"
                },
                {
                    "performed_date": 1625484378,
                    "messages": None,
                    "action_type": "MOVE_TO_SPAM",
                    "action_status": "success"
                },
                {
                    "performed_date": 1625484378,
                    "messages": None,
                    "action_type": "INCIDENT",
                    "action_status": "success"
                }
            ],
            "policy_condition": [
                {
                    "condition_type": "ORIGIN",
                    "condition_value": "ALL"
                },
                {
                    "condition_type": "EMAIL_STATE",
                    "condition_value": "ALL"
                },
                {
                    "condition_type": "REPORTED_BY",
                    "condition_value": "ALL"
                }
            ],
            "policy_name": "Default Rule",
            "resolution": "pending"
        },
        "message_details": {
            "internet_message_id": "internetMessageID-" + str(now_time_timestamp_seconds),
            "targeted_employee": {
                "name": "user1",
                "address": "user1@sample.com"
            },
            "other_recipients": [],
            "sender": {
                "name": "user2",
                "address": "user2@sample.com"
            },
            "from": {
                "name": "user2",
                "address": "user2@sample.com"
            },
            "to_recipients": [
                {
                    "name": "user1",
                    "address": "user1@sample.com"
                }
            ],
            "to_cc_recipients": [],
            "to_bcc_recipients": [],
            "reply_to": [],
            "email_subject": "subject - this is a sample",
            "email_body": "",
            "received_datetime": "2021-07-05T11:23:27Z",
            "sent_datetime": "2021-07-05T11:23:22Z",
            "created_datetime": "2021-07-05T11:23:26Z",
            "last_modified_datetime": "2021-07-05T11:23:28Z",
            "is_read": False,
            "is_external_from": False,
            "is_external_reply_to": False,
            "is_external_sender": False,
            "is_user_subscribed": True,
            "urls_classification": [
                {
                    "url": "http://phishing.com",
                    "classification_type": "malicious",
                    "is_phishing": True,
                    "classification": "malicious"
                }
            ],
            "user_id": "userID",
            "message_id": "messageID-" + str(now_time_timestamp_seconds),
            "attachments": [
                {
                    "file_size": 158,
                    "file_name": "attachment.html",
                    "file_hash": "hash",
                    "file_category": "PHISHING",
                    "aws_key": "key.zip",
                    "aws_bucket": "bucket"
                }
            ],
            "folder": "inbox"
        },
        "threat_indicators": [
            {
                "type": "url",
                "subType": "malicious_url",
                "value": "http://phishing.com",
                "details": {
                    "categories": [
                        ""
                    ],
                    "family_names": [
                        "Generic"
                    ],
                    "industries": [
                        ""
                    ],
                    "screenshot": "screenshot.png"
                }
            },

            {
                "type": "attachment",
                "subType": "attachment_hash",
                "value": "hash",
                "details": {
                    "categories": None,
                    "family_names": None,
                    "industries": None,
                    "screenshot": ""
                },
                "attachment": {
                    "file_size": 158,
                    "file_name": "attachment.html",
                    "file_hash": "hash",
                    "file_category": "PHISHING",
                    "aws_key": "key.zip",
                    "aws_bucket": "screenshot"
                }
            }
        ],
        "feedback": [
            {
                "details": "phishing url",
                "tx_id": "txID",
                "feedback_type": "phishing",
                "created_at": 1625653814,
                "threat_indicators_type": [
                    "url"
                ]
            },
        ],
        "reported_by": "admin@sample.com",
        "confidence": 3,
        "created_at": now_time_timestamp_seconds,
        "updated_at": now_time_timestamp_seconds
    }

    incidents = []
    incident_name = 'Cyren Inbox Security Sample - {} ({})'.format(
        sample_incident.get('threat_type', 'phishing'),
        sample_incident.get('reported_by', 'System')
    )
    incident_timestamp = now_time_timestamp_seconds
    incident_str_time = timestamp_to_datestring(incident_timestamp * 1000)
    incident = {
        'name': incident_name,
        'occurred': incident_str_time,
        'rawJSON': json.dumps(sample_incident),
        'severity': convert_to_demisto_severity(1),
    }

    incidents.append(incident)

    return incidents


def fetch_incidents(client, client_id, client_secret, last_run,
                    first_fetch_time, max_fetch
                    ):
    """
    This function will execute each interval (default is 1 minute).

    Args:
        client (Client): the client object
        client_id (String): client id
        client_secret (String): client secret
        last_run (dict): a dict with last_fetch as
         a key and a timestamp in seconds as a value
        first_fetch_time (datetime): datetime object
         on when to start fetching incidents
        max_fetch (int): Maximum numbers of incidents per fetch
    Returns:
        incidents: Incidents that will be created in Cortex XSOAR
    """
    # last run is a dict with last_fetch as a key and
    #  a timestamp in seconds as a value
    last_fetch = last_run.get('last_fetch')

    # Handle first fetch time
    if last_fetch is None:
        # if missing, use what provided via first_fetch_time
        date_from = int(date_to_timestamp(first_fetch_time) / 1000)
    else:
        # otherwise use the stored last fetch
        date_from = last_fetch

    last_fetched_time = date_from

    incidents = []
    token = client.get_token(client_id, client_secret).\
        get('data').get('access_token')
    cyren_incidents = client.get_incidents(token, date_from, max_fetch)
    for ci in cyren_incidents.get('data', []):
        incident_name = 'Cyren Inbox Security - {} ({})'.format(
            ci.get('threat_type', 'phishing'), ci.get('reported_by', 'System')
        )
        incident_timestamp = ci.get('created_at')
        incident_str_time = timestamp_to_datestring(incident_timestamp * 1000)
        incident = {
            'name': incident_name,
            'occurred': incident_str_time,
            'rawJSON': json.dumps(ci),
            'severity': convert_to_demisto_severity(ci.get('confidence', 1)),
        }

        incidents.append(incident)

        # Update last_fetch if the incident is newer than last_fetch
        if incident_timestamp > last_fetched_time:
            last_fetched_time = incident_timestamp + 1

    demisto.setLastRun({
        'last_fetch': last_fetched_time
    })

    return incidents


def resolve_and_remediate_command(client, args, client_id, client_secret):
    """
    Resolve a case and remediate it
    """
    case_id = args.get('case_id')
    resolution = args.get('resolution', 'phishing')
    resolution_reason = args.get('resolution_reason', '')
    resolution_reason_text = args.get('resolution_reason_text', '')
    actions = args.get('actions', [])
    if actions:
        actions = actions.split(',')

    if client_id == client_secret == "sample":
        resp = {"data": {"status": "ok"}}
    else:
        token = client.get_token(client_id, client_secret).\
            get('data').get('access_token')
        resp = client.resolve_and_remediate(
            token,
            case_id,
            resolution=resolution,
            resolution_reason=resolution_reason,
            resolution_reason_text=resolution_reason_text,
            actions=actions
        )

    readable_output = (
        tableToMarkdown("cyren-resolve-and-remediate results", resp["data"])
        + '\n*** end of results ***'
    )

    return CommandResults(
        outputs_prefix="Cyren",
        outputs=resp,
        readable_output=readable_output
    )


''' MAIN FUNCTION '''


def main() -> None:
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """

    url = demisto.params().get('url')
    client_id = demisto.params().get('client_id')
    client_secret = demisto.params().get('client_secret')
    first_fetch_time = arg_to_datetime(demisto.params().
                                       get('first_fetch', '3 days').strip())
    max_results = arg_to_number(arg=demisto.params().get('max_fetch', 50))

    if max_results is None:
        max_results = 1

    if max_results > MAX_INCIDENTS_TO_FETCH:
        max_results = MAX_INCIDENTS_TO_FETCH

    try:
        client = Client(
            base_url=url,
            verify=True,
            proxy=False
        )

        if demisto.command() == 'test-module':
            if url == client_id == client_secret == "sample":
                return_results('ok')
            else:
                result = test_module(client, client_id, client_secret)
                return_results(result)

        if demisto.command() == 'fetch-incidents':
            if url == client_id == client_secret == "sample":
                incidents = simulate_fetch()
                demisto.incidents(incidents)
            else:
                incidents = fetch_incidents(
                    client=client,
                    client_id=client_id,
                    client_secret=client_secret,
                    last_run=demisto.getLastRun(),
                    first_fetch_time=first_fetch_time,
                    max_fetch=max_results
                )
                demisto.incidents(incidents)

        if demisto.command() == 'cyren-resolve-and-remediate':
            return_results(resolve_and_remediate_command(
                client,
                demisto.args(),
                client_id=client_id,
                client_secret=client_secret)
            )

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute'
                     f' {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
