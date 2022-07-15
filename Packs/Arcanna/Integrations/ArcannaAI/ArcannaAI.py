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
        body = self.map_to_arcanna_raw_event(job_id, raw, severity, title)

        raw_response = requests.post(url=self.base_url + url_suffix, headers=self.get_headers(), verify=self.verify,
                                     json=body)
        if raw_response.status_code != 201:
            raise Exception(f"Error HttpCode={raw_response.status_code} text={raw_response.text}")
        return raw_response.json()

    def map_to_arcanna_raw_event(self, job_id, raw, severity, title):
        body = {
            "job_id": job_id,
            "title": title,
            "raw_body": raw
        }
        if severity is not None:
            body["severity"] = severity
        return body

    def get_event_status(self, job_id, event_id):
        url_suffix = f"api/v1/events/{job_id}/{event_id}"
        raw_response = requests.get(url=self.base_url + url_suffix, headers=self.get_headers(), verify=self.verify)
        if raw_response.status_code != 200:
            raise Exception(f"Error HttpCode={raw_response.status_code}")
        return raw_response.json()

    def send_feedback(self, job_id, event_id, username, arcanna_label, closing_notes, indicators):
        url_suffix = f"api/v1/events/{job_id}/{event_id}/feedback"
        body = self.map_to_arcanna_label(arcanna_label, closing_notes, username)
        if indicators:
            body["indicators"] = json.loads(indicators)
        raw_response = requests.put(url=self.base_url + url_suffix, headers=self.get_headers(), verify=self.verify,
                                    json=body)

        if raw_response.status_code != 200:
            raise Exception(f"Arcanna Error HttpCode={raw_response.status_code} body={raw_response.text}")
        return raw_response.json()

    @staticmethod
    def map_to_arcanna_label(arcanna_label, closing_notes, username):
        body = {
            "cortex_user": username,
            "feedback": arcanna_label,
            "closing_notes": closing_notes
        }
        return body

    def send_bulk(self, job_id, events):
        url_suffix = f"api/v1/bulk/{job_id}"
        body = {
            "count": len(events),
            "events": events
        }
        raw_response = requests.post(url=self.base_url + url_suffix, headers=self.get_headers(), verify=self.verify,
                                     json=body)

        if raw_response.status_code != 201:
            raise Exception(f"Arcanna Error HttpCode={raw_response.status_code} body={raw_response.text}")
        return raw_response.json()


''' COMMAND FUNCTIONS '''


def test_module(client: Client, feature_mapping_field: str) -> str:
    result = parse_mappings(feature_mapping_field)
    if len(result) < 2:
        return "Arcanna Mapping Error. Please check your feature_mapping field"

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


def get_feedback_field(params: Dict[str, Any]) -> CommandResults:
    response = params.get("closing_reason_field")
    readable_output = f' ## Get feedback returned results: {response}'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Arcanna.FeedbackField',
        outputs=response
    )


def set_default_job_id(client: Client, args: Dict[str, Any]) -> CommandResults:
    job_id = args.get("job_id")
    client.set_default_job_id(job_id)
    return get_default_job_id(client)


''' MAIN FUNCTION '''


def send_event_feedback(client: Client, feature_mapping_field: str, args: Dict[str, Any]) -> CommandResults:
    job_id = args.get("job_id", None)
    if not job_id:
        job_id = client.get_default_job_id()
    event_id = args.get("event_id")
    mappings = parse_mappings(feature_mapping_field)

    username = args.get("username")
    label = args.get("label")
    closing_notes = args.get("closing_notes", "")
    indicators = args.get("indicators", None)
    arcanna_label = mappings.get(label, None)
    if arcanna_label is None:
        raise Exception(f"Error in arcanna-send-feedback.Wrong label={label}")

    response = client.send_feedback(job_id, event_id, username, arcanna_label, closing_notes, indicators)
    readable_output = f' ## Arcanna send event feedback results: {response}'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Arcanna.Event',
        outputs_key_field='feedback_status',
        outputs=response
    )


def send_bulk_events(client: Client, feature_mapping_field: str, args: Dict[str, Any]) -> CommandResults:
    job_id = args.get("job_id")
    events = argToList(args.get("events"))
    mappings = parse_mappings(feature_mapping_field)
    mapped_events = []
    for event in events:
        closing_status = event.get("closingReason")
        closing_notes = event.get("closeNotes")
        closing_user = event.get("closeUser")
        arcanna_label = mappings.get(closing_status)
        title = event.get("name")
        severity = event.get("severity")

        body = client.map_to_arcanna_raw_event(job_id, event, severity, title)
        body["label"] = client.map_to_arcanna_label(arcanna_label, closing_notes, closing_user)

        mapped_events.append(body)

    response = client.send_bulk(job_id, mapped_events)
    readable_output = f' ## Arcanna send bulk results: {response}'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Arcanna.Bulk',
        outputs_key_field='status',
        outputs=response
    )


def parse_mappings(mapping: str) -> dict:
    result = {}
    pairs = mapping.split(",")
    for pair in pairs:
        parts = pair.split("=")
        if len(parts) != 2:
            raise BaseException("Arcanna: Error while parsing mapping fields")
        demisto_closing_reason = parts[0].strip().replace("\"", "")
        arcanna_label = parts[1].strip().replace("\"", "")
        result[demisto_closing_reason] = arcanna_label

    return result


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    api_key = demisto.params().get('apikey')

    # get the service API url
    base_url = urljoin(demisto.params()['url'])
    verify_certificate = not demisto.params().get('insecure', False)
    feature_mapping = demisto.params().get('feature_mapping')
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
            result_test = test_module(client, feature_mapping)
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
        elif demisto.command() == "arcanna-send-event-feedback":
            result_send_feedback = send_event_feedback(client, feature_mapping, demisto.args())
            return_results(result_send_feedback)
        elif demisto.command() == "arcanna-send-bulk-events":
            result_bulk = send_bulk_events(client, feature_mapping, demisto.args())
            return_results(result_bulk)
        elif demisto.command() == "arcanna-get-feedback-field":
            result_feedback_field = get_feedback_field(demisto.params())
            return_results(result_feedback_field)
    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
