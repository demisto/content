import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa: F401

import json
import urllib3
import traceback
import requests
from typing import Any, Dict

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
MAX_INCIDENTS_TO_FETCH = 50
SEVERITES = ['Low', 'Medium', 'High', 'Critical']

''' CLIENT CLASS '''


class Client:
    """ Implements Arcanna API
    """

    def __init__(self, verify=True, proxy=False, api_key=None, base_url=None, default_job_id=-1):
        self.base_url = base_url
        self.verify = verify
        self.proxy = proxy
        self.api_key = api_key
        self.default_job_id = default_job_id

    def get_headers(self):
        """   Adds header

        """
        headers = {
            'accept': 'application/json',
            'x-arcanna-api-key': self.api_key
        }
        return headers

    def set_default_job_id(self, job_id):
        self.default_job_id = job_id

    def get_default_job_id(self):
        return self.default_job_id

    def test_arcanna(self):
        url_suffix = 'api/v1/health'
        raw_response = requests.get(url=self.base_url + url_suffix, headers=self.get_headers(), verify=self.verify)
        return json.loads(raw_response.text)

    def list_jobs(self):
        url_suffix = 'api/v1/jobs'
        raw_response = requests.get(url=self.base_url + url_suffix, headers=self.get_headers(), verify=self.verify)
        if raw_response.status_code != 200:
            raise Exception("Error HttpCode. Forbidden")
        return json.loads(raw_response.text)

    def send_raw_event(self, job_id=None, severity=None, title=None, raw_body=None):
        url_suffix = 'api/v1/events/'
        raw = json.loads(raw_body)
        body = {
            "job_id": job_id,
            "title": title,
            "raw_body": raw
        }
        if severity is not None:
            body["severity"] = severity

        raw_response = requests.post(url=self.base_url + url_suffix, headers=self.get_headers(), verify=self.verify,
                                     json=body)
        if raw_response.status_code != 201:
            raise Exception(f"Error HttpCode={raw_response.status_code} text={raw_response.text}")
        return json.loads(raw_response.text)

    def get_event_status(self, job_id=None, event_id=None):
        url_suffix = f"api/v1/events/{job_id}/{event_id}"
        raw_response = requests.get(url=self.base_url + url_suffix, headers=self.get_headers(), verify=self.verify)
        if raw_response.status_code != 200:
            raise Exception(f"Error HttpCode={raw_response.status_code}")
        return json.loads(raw_response.text)


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    try:
        response = client.test_arcanna()
        demisto.info(f'test_module response={response}')
        if not response["connected"]:
            return "Authentication Error, API Key invalid"
        else:
            return "ok"
    except DemistoException as e:
        raise e


def get_jobs(client: Client) -> CommandResults:
    demisto.info('Running get_jobs command')
    result = client.list_jobs()

    headers = ["job_id", "title", "data_type", "status"]

    readable_output = tableToMarkdown(name="arcanna_jobs", headers=headers, t=result)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='arcanna_jobs',
        outputs_key_field='',
        outputs=result
    )


def post_event(client: Client, args: Dict[str, Any]) -> CommandResults:
    demisto.info('Running send_event command')

    raw_payload = args.get("event_json")
    title = args.get("title")
    job_id = args.get("job_id")
    severity = args.get("severity")

    response = client.send_raw_event(job_id=job_id, severity=severity, title=title, raw_body=raw_payload)
    readable_output = f'## {response}'
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='arcanna',
        outputs_key_field='',
        outputs=response
    )


def get_event_status(client: Client, args: Dict[str, Any]) -> CommandResults:
    demisto.info('Running get_event_status command')
    job_id = args.get("job_id")
    event_id = args.get("event_id")
    response = client.get_event_status(job_id, event_id)
    readable_output = f'## {response}'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='arcanna',
        outputs_key_field='',
        outputs=response
    )


def get_default_job_id(client: Client) -> CommandResults:
    demisto.info('Running get_default_job_id command')
    response = client.get_default_job_id()
    readable_output = f'## {response}'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='arcanna_default_job_id',
        outputs_key_field='',
        outputs=response
    )


def set_default_job_id(client: Client, args: Dict[str, Any]) -> str:
    job_id = args.get("job_id")
    client.set_default_job_id(job_id)
    return "ok"


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    api_key = demisto.params().get('apikey')

    # get the service API url
    base_url = urljoin(demisto.params()['url'])

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not demisto.params().get('insecure', False)

    # How much time before the first fetch to retrieve incidents
    first_fetch_time = arg_to_datetime(
        arg=demisto.params().get('first_fetch', '3 days'),
        arg_name='First fetch time',
        required=True
    )
    first_fetch_timestamp = int(first_fetch_time.timestamp()) if first_fetch_time else None
    # Using assert as a type guard (since first_fetch_time is always an int when required=True)
    assert isinstance(first_fetch_timestamp, int)

    proxy = demisto.params().get('proxy', False)

    default_job_id = demisto.params().get('default_job_id', -1)
    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        client = Client(
            api_key=api_key,
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            default_job_id=default_job_id
        )

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result_test = test_module(client)
            return_results(result_test)
        elif demisto.command() == "get_jobs":
            result_get_jobs = get_jobs(client)
            return_results(result_get_jobs)
        elif demisto.command() == "send_event":
            result_send_event = post_event(client, demisto.args())
            return_results(result_send_event)
        elif demisto.command() == "get_event_status":
            result_get_event = get_event_status(client, demisto.args())
            return_results(result_get_event)
        elif demisto.command() == "get_default_job_id":
            result_get_default_id = get_default_job_id(client)
            return_results(result_get_default_id)
        elif demisto.command() == "set_default_job_id":
            result_set_default_id = set_default_job_id(client, demisto.args())
            return_results(result_set_default_id)

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
