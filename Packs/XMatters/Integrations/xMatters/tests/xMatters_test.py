'''
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import requests
import json
import dateparser
import traceback

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


'''

from xMatters import Client
from typing import Any, Dict, Tuple, List, Optional, cast
import unittest


def test_xm_trigger_workflow_command(requests_mock):
    """Tests trigger workflow command

    :param requests_mock:
    :return:
    """
    from xMatters import Client, xm_trigger_workflow_command

    hostname = 'https://acme.xmatters.com/api/integration/1/functions/UUID/triggers'
    # '7a161a3f-8d53-42de-80cd-92fb017c5a12'
    mock_response = {
        'requestId': 'I GOT ONE!'
    }

    recipients = 'bonnieKat'
    subject = 'This glass is offending me.'
    body = 'I shall push it off the table'
    incident_id = '437'
    close_task_id = '3'

    base_url = 'https://acme.xmatters.com/?' + '&recipients=' + recipients + \
               '&subject=' + subject + \
               '&body=' + body + \
               '&incident_id=' + incident_id + \
               '&close_task_id=' + close_task_id

    requests_mock.register_uri('POST', base_url, json=mock_response)

    client = Client(
        base_url=base_url,
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    results = xm_trigger_workflow_command(client, recipients=recipients,
                                          subject=subject,
                                          body=body,
                                          incident_id=incident_id,
                                          close_task_id=close_task_id, )

    assert results.readable_output == "Successfully sent a message to xMatters."



def test_xm_get_events_command():
    assert True


def test_xm_get_event_command():
    assert True
