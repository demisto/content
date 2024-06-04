import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa: F401


import json
import urllib3
import traceback
import requests
import time
from typing import Any, Dict

# Disable insecure warnings
urllib3.disable_warnings()

''' CLIENT CLASS '''

class Client(BaseClient):
    """
    Implements Arcanna API
    """

    def test_arcanna(self) -> Dict[str, Any]:
        return self._http_request(
            method="GET",
            url_suffix="/api/v1/health/"
        )

    def list_jobs(self):
        return self._http_request(
            method="GET",
            url_suffix="/api/v1/jobs/",
            ok_codes=(200,201,422)
        )

    def export_event(self, job_id: int, event_id: str) -> Dict[str, Any]:
        return self._http_request(
            method="GET",
            url_suffix=f"/api/v1/events/{job_id}/{event_id}/export",
            ok_codes=(200,201,422)
        )

    def trigger_training(self, job_id: int, username: str) -> Dict[str, Any]:
        return self._http_request(
            method="POST",
            url_suffix=f"/api/v1/jobs/{job_id}/train?username={username}",
            ok_codes=(200,201,422)
        )
    
    def get_decision_set(self, job_id: int) -> Dict[str, Any]:
        return self._http_request(
            method="GET",
            url_suffix=f"/api/v1/jobs/{job_id}/labels",
            ok_codes=(200,201,422)
        )

    def send_raw_event(self, job_id: int, payload: Dict[str, Any], id_value="") -> Dict[str, Any]:
        return self._http_request(
            method="POST",
            url_suffix=f"/api/v1/events/{id_value}",
            json_data = payload,
            ok_codes=(200,201,422)
        )

    def get_event_status(self, job_id: int, event_id: str, retries=10, seconds_per_retry=3) -> Dict[str, Any]:
        return self._http_request(
            method="GET",
            url_suffix=f"/api/v1/events/{job_id}/{event_id}",
            ok_codes=(200,201,422)
        )

    def send_feedback(self, job_id: int, event_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        return self._http_request(
            method="PUT",
            url_suffix=f"/api/v1/events/{job_id}/{event_id}/feedback",
            json_data=payload,
            ok_codes=(200,201,422)
        )


''' COMMAND FUNCTIONS '''

def test_module(client: Client) -> str:
    try:
        response = client.test_arcanna()
        demisto.info(f'test_module response={response}')
        if "connected" not in response:
            return "Authentication Error. Please check the API Key you provided."
        else:
            return "ok"
    except DemistoException as e:
        raise e

def get_jobs(client: Client) -> CommandResults:
    result = client.list_jobs()

    headers = ["job_id", "title", "status", "last_processed_timestamp"]

    readable_output = tableToMarkdown(name="Arcanna Jobs", headers=headers, t=result)

    outputs = {
        'Arcanna.Jobs(val.job_id && val.job_id === obj.job_id)': createContext(result)
    }
    return CommandResults(
        readable_output=readable_output,
        outputs=outputs,
        raw_response=result
    )

def export_event(client: Client, default_job_id: int, args: Dict[str, Any]) -> CommandResults:
    job_id = args.get("job_id", default_job_id)
    event_id = args.get("event_id")

    result = client.export_event(job_id=job_id, event_id=event_id)
    headers = ["arcanna_event", "status", "ingest_timestamp","event_id", "error_message"]
    readable_output = tableToMarkdown(name="Arcanna Event", headers=headers, t=result)

    outputs = {
        'Arcanna.Event(val.job_id && val.job_id === obj.job_id)': createContext(result)
    }

    return CommandResults(
        readable_output=readable_output,
        outputs=outputs,
        raw_response=result
    )


def trigger_training(client: Client, default_job_id: int, args: Dict[str, Any]) -> CommandResults:
    job_id = args.get("job_id", default_job_id)
    username = args.get("username", None)
    result = client.trigger_training(job_id=job_id, username=username)
    headers = ["result", "error_message"]
    readable_output = tableToMarkdown(name="Arcanna Training", headers=headers, t=result)

    outputs = {
        'Arcanna.Training(val.job_id && val.job_id === obj.job_id)': createContext(result)
    }

    return CommandResults(
        readable_output=readable_output,
        outputs=outputs,
        raw_response=result
    )

def get_decision_set(client: Client, default_job_id: int, args: Dict[str, Any]) -> CommandResults:
    job_id = args.get("job_id", default_job_id)
    result = client.get_decision_set(job_id=job_id)
    headers = ["decision_set", "error_message"]
    readable_output = tableToMarkdown(name="Arcanna Event", headers=headers, t=result)
    outcome = {
        "decision_set": result
    }
    outputs = {
        'Arcanna.Event(val.job_id && val.job_id === obj.job_id)': createContext(outcome)
    }

    return CommandResults(
        readable_output=readable_output,
        outputs=outputs,
        raw_response=result
    )

def map_to_arcanna_raw_event(job_id, raw, severity, title):
        body = {
            "job_id": int(job_id),
            "title": title,
            "raw_body": json.loads(raw)
        }
        if severity:
            severity = int(float(severity))
            body["severity"] = severity
        return body
        
def post_event(client: Client, default_job_id: int, args: Dict[str, Any]) -> CommandResults:
    job_id = args.get("job_id", default_job_id)
    title = args.get("title")
    raw_payload = args.get("event_json", {})
    severity = args.get("severity", 0)
    id_value = args.get("id_value", "")

    payload = map_to_arcanna_raw_event(job_id, raw_payload, severity, title)
    result = client.send_raw_event(job_id=job_id, payload=payload, id_value=id_value)

    
    headers = ["event_id", "ingest_timestamp", "status", "error_message","job_id"]
    readable_output = tableToMarkdown(name="Arcanna Event", headers=headers, t=result)

    outputs = {
        'Arcanna.Event(val.job_id && val.job_id === obj.job_id)': createContext(result)
    }

    return CommandResults(
        readable_output=readable_output,
        outputs=outputs,
        raw_response=result
    )

def get_event_status(client: Client, default_job_id: int, args: Dict[str, Any]) -> CommandResults:
    job_id = args.get("job_id", default_job_id)
    event_id = args.get("event_id")
    result = client.get_event_status(job_id, event_id)
    
    headers = ["event_id", "ingest_timestamp", "status", "error_message","bucket_state", "result", "confidence_score", "outlier", "arcanna_label"]
    
    readable_output = tableToMarkdown(name="Arcanna Event Status", headers=headers, t=result)

    outputs = {
        'Arcanna.Event(val.job_id && val.job_id === obj.job_id)': createContext(result)
    }

    return CommandResults(
        readable_output=readable_output,
        outputs=outputs,
        raw_response=result
    )

def map_to_arcanna_label(arcanna_label, username):
    body = {
        "cortex_user": username,
        "feedback": arcanna_label
    }
    return body

def send_event_feedback(client: Client, default_job_id: int, args: Dict[str, Any]) -> CommandResults:
    job_id = args.get("job_id", default_job_id)
    event_id = args.get("event_id")
    username = args.get("username")
    feedback = args.get("feedback", "<empty>")
    decision_set = args.get("valid_decisions", [])
    
    if feedback in decision_set is False:
        raise Exception(f"Error in arcanna-send-event-feedback.Unknown decision - {arcanna_label} ; Valid options: {decision_set} ")

    payload = map_to_arcanna_label(feedback, username)
    
    result = client.send_feedback(job_id, event_id, payload)
    
    headers = ["feedback_status", "status", "details"]
    readable_output = tableToMarkdown(name="Arcanna Event", headers=headers, t=result)

    outputs = {
        'Arcanna.Event(val.job_id && val.job_id === obj.job_id)': createContext(result)
    }

    return CommandResults(
        readable_output=readable_output,
        outputs=outputs,
        raw_response=result
    )


''' MAIN FUNCTION '''

def main() -> None:
	"""main function, parses params and runs command functions

	:return:
	:rtype:
	"""

	api_key = demisto.params().get('credentials', {}).get('password')

	# get the service API url
	base_url = urljoin(demisto.params()['url'])
	verify_certificate = demisto.params().get('ssl_verification', False)
	close_reasons = demisto.params().get('close_reasons')
	proxy = demisto.params().get('proxy', False)
	default_job_id = int(demisto.params().get('default_job_id', 1201))
	demisto.debug(f'Command being called is {demisto.command()}')
        headers = {
                        'accept': 'application/json',
                        'x-arcanna-api-key': self.api_key
                }

	try:

		client = Client(
			base_url=base_url,
                        headers=headers,
			verify=verify_certificate,
			proxy=proxy
		)

		if demisto.command() == 'test-module':
			# This is the call made when pressing the integration Test button.
			result_test = test_module(client, close_reasons)
			return_results(result_test)
		elif demisto.command() == "arcanna-get-jobs":
			result_get_jobs = get_jobs(client)
			return_results(result_get_jobs)
		elif demisto.command() == "arcanna-send-event":
			result_send_event = post_event(client, default_job_id, demisto.args())
			return_results(result_send_event)
		elif demisto.command() == "arcanna-export-event":
			result_export_event = export_event(client, default_job_id, demisto.args())
			return_results(result_export_event)
		elif demisto.command() == "arcanna-trigger-train":
			result_trigger_train = trigger_training(client, demisto.args())
			return_results(result_trigger_train)
		elif demisto.command() == "arcanna-get-decision-set":
			result_decision_set = get_decision_set(client, default_job_id, demisto.args())
			return_results(result_decision_set)
		elif demisto.command() == "arcanna-get-event-status":
			result_get_event = get_event_status(client, default_job_id, demisto.args())
			return_results(result_get_event)
		elif demisto.command() == "arcanna-send-event-feedback":
			result_send_feedback = send_event_feedback(client, default_job_id, close_reasons, demisto.args())
			return_results(result_send_feedback)
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
