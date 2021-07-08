import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import json
import urllib3
import traceback
import requests
from typing import Any, Dict

# Disable insecure warnings
urllib3.disable_warnings()

''' CLIENT CLASS '''


class Client:
    """ Implements Arcanna API
    """

    def __init__(self, api_key, base_url, verify=True, proxy=False, default_job_id=-1):
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
        return raw_response.json()

    def list_jobs(self):
        url_suffix = 'api/v1/jobs'
        raw_response = requests.get(url=self.base_url + url_suffix, headers=self.get_headers(), verify=self.verify)
        if raw_response.status_code != 200:
            raise Exception(f"Error in API call [{raw_response.status_code}]. Reason: {raw_response.reason}")
        return raw_response.json()

    def send_raw_event(self, job_id, severity, title, raw_body):
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
        return raw_response.json()

    def get_event_status(self, job_id, event_id):
        url_suffix = f"api/v1/events/{job_id}/{event_id}"
        raw_response = requests.get(url=self.base_url + url_suffix, headers=self.get_headers(), verify=self.verify)
        if raw_response.status_code != 200:
            raise Exception(f"Error HttpCode={raw_response.status_code}")
        return raw_response.json()


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    try:
        response = client.test_arcanna()
        demisto.info(f'test_module response={response}')
        if not response["connected"]:
            return "Authentication Error. Please check the API Key you provided."
        else:
            return "ok"
    except DemistoException as e:
        raise e


def get_jobs(client: Client) -> CommandResults:
    result = client.list_jobs()

    headers = ["job_id", "title", "data_type", "status"]

    readable_output = tableToMarkdown(name="Arcanna Jobs", headers=headers, t=result)

    outputs = {
        'Arcanna.Jobs(val.job_id && val.job_id === obj.job_id)': createContext(result)
    }
    return CommandResults(
        readable_output=readable_output,
        outputs=outputs,
        raw_response=result
    )


def post_event(client: Client, args: Dict[str, Any]) -> CommandResults:
    title = args.get("title")

    job_id = args.get("job_id", None)
    if not job_id:
        job_id = client.get_default_job_id()

    raw_payload = args.get("event_json")
    severity = args.get("severity")

    response = client.send_raw_event(job_id=job_id, severity=severity, title=title, raw_body=raw_payload)
    readable_output = f'## {response}'
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Arcanna.Event',
        outputs_key_field='event_id',
        outputs=response
    )


def get_event_status(client: Client, args: Dict[str, Any]) -> CommandResults:
    job_id = args.get("job_id", None)
    if not job_id:
        job_id = client.get_default_job_id()
    event_id = args.get("event_id")
    response = client.get_event_status(job_id, event_id)
    readable_output = f'## {response}'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Arcanna.Event',
        outputs_key_field='event_id',
        outputs=response
    )


def get_default_job_id(client: Client) -> CommandResults:
    response = client.get_default_job_id()
    readable_output = f'## {response}'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Arcanna.Default_Job_Id',
        outputs=response
    )


def set_default_job_id(client: Client, args: Dict[str, Any]) -> CommandResults:
    job_id = args.get("job_id")
    client.set_default_job_id(job_id)
    return get_default_job_id(client)


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    api_key = demisto.params().get('apikey')

    # get the service API url
    base_url = urljoin(demisto.params()['url'])
    verify_certificate = not demisto.params().get('insecure', False)
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
        elif demisto.command() == "arcanna-get-jobs":
            result_get_jobs = get_jobs(client)
            return_results(result_get_jobs)
        elif demisto.command() == "arcanna-send-event":
            result_send_event = post_event(client, demisto.args())
            return_results(result_send_event)
        elif demisto.command() == "arcanna-get-event-status":
            result_get_event = get_event_status(client, demisto.args())
            return_results(result_get_event)
        elif demisto.command() == "arcanna-get-default-job-id":
            result_get_default_id = get_default_job_id(client)
            return_results(result_get_default_id)
        elif demisto.command() == "arcanna-set-default-job-id":
            result_set_default_id = set_default_job_id(client, demisto.args())
            return_results(result_set_default_id)

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
