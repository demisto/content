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



class Client:
	""" Implements Arcanna API
	"""

	def __init__(self, api_key, base_url, ssl_verification=False, proxy=False, default_job_id=-1):
		self.base_url = base_url
		self.verify = ssl_verification
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
		url_suffix = 'api/v1/health/'
		raw_response = requests.get(url=self.base_url + url_suffix, headers=self.get_headers(), verify=self.verify)
		return raw_response.json()

	def list_jobs(self):
		url_suffix = 'api/v1/jobs/'
		raw_response = requests.get(url=self.base_url + url_suffix, headers=self.get_headers(), verify=self.verify)
		if raw_response.status_code != 200:
			raise Exception(f"Error in API call [{raw_response.status_code}]. Reason: {raw_response.reason}")
		return raw_response.json()

	def export_event(self, job_id, event_id):
		url_suffix = f"/api/v1/events/{job_id}/{event_id}/export"
		raw_response = requests.get(url=self.base_url + url_suffix, headers=self.get_headers(), verify=self.verify)
		if raw_response.status_code not in [200, 422, 500]:
			 raise Exception(f"Error HttpCode={raw_response.status_code} text={raw_response.text} Job ID :#{self.base_url}# #{url_suffix}# #{self.get_headers()}# #{job_id}# #{body}#")
		return raw_response.json() 
		
	def trigger_training(self, job_id, username):
		url_suffix = f"/api/v1/jobs/{job_id}/train?username={username}"
		body = {
			 "username": username
		}
		raw_response = requests.post(url=self.base_url + url_suffix, headers=self.get_headers(), verify=self.verify, json=body)
		if raw_response.status_code not in [200, 422, 500]:
			 raise Exception(f"Error HttpCode={raw_response.status_code} text={raw_response.text} Job ID :#{self.base_url}# #{url_suffix}# #{self.get_headers()}# #{job_id}# #{body}#")
		return raw_response.json() 
	
	def get_decision_set(self, job_id):
		url_suffix = f"/api/v1/jobs/{job_id}/labels"
		raw_response = requests.get(url=self.base_url + url_suffix, headers=self.get_headers(), verify=self.verify)
		if raw_response.status_code not in [200, 422, 500]:
			 raise Exception(f"Error HttpCode={raw_response.status_code} text={raw_response.text} Job ID :#{self.base_url}# #{url_suffix}# #{self.get_headers()}# #{job_id}# #{body}#")
		return raw_response.json() 

	def send_raw_event(self, job_id, severity, title, raw_body,id_value=None):
		url_suffix = 'api/v1/events/'
		if id_value is not None and id_value != "":
			url_suffix = f"{url_suffix}{id_value}"
		raw = json.loads(raw_body)
		body = self.map_to_arcanna_raw_event(job_id, raw, severity, title)
		raw_response = None
		raw_response = requests.post(url=self.base_url + url_suffix, headers=self.get_headers(), verify=self.verify,
									 json=body)
		if raw_response.status_code not in [201,422,500]:
			raise Exception(f"Error HttpCode={raw_response.status_code} text={raw_response.text} Job ID :#{self.base_url}# #{url_suffix}# #{self.get_headers()}# #{job_id}# #{body}#")
		
		return raw_response.json()

	def map_to_arcanna_raw_event(self, job_id, raw, severity, title):
		body = {
			"job_id": int(job_id),
			"title": title,
			"raw_body": raw
		}
		if severity is not None:
			severity = int(float(severity))
			body["severity"] = severity
		return body

	def get_event_status(self, job_id, event_id, retries=10, seconds_per_retry=3):
		retry_count = 0
		while(retry_count < retries):
			url_suffix = f"api/v1/events/{job_id}/{event_id}"
			full_url = f"{self.base_url}{url_suffix}"
			raw_response = requests.get(url=full_url, headers=self.get_headers(), verify=self.verify)
			if raw_response.status_code not in [200,422]:
				raise Exception(f"Error HttpCode={raw_response.status_code} text={raw_response.text} Job ID :#{self.base_url}# #{url_suffix}#")
			if raw_response.json()['status'] == 'pending_inference':
				retry_count += 1
				time.sleep(seconds_per_retry)
			else:
				response = raw_response.json()
				response['retry_count'] = retry_count
				return raw_response.json()
		return raw_response.json()

	def send_feedback(self, job_id, event_id, username, arcanna_label, indicators):
		url_suffix = f"api/v1/events/{job_id}/{event_id}/feedback"
		body = self.map_to_arcanna_label(arcanna_label, username)
		if indicators:
			body["indicators"] = json.loads(indicators)
		raw_response = requests.put(url=self.base_url + url_suffix, headers=self.get_headers(), verify=self.verify,
									json=body)

		if raw_response.status_code not in [200, 422, 500]:
			raise Exception(f"Arcanna Error HttpCode={raw_response.status_code} body={raw_response.text}")
		return raw_response.json()

	@staticmethod
	def map_to_arcanna_label(arcanna_label, username):
		body = {
			"cortex_user": username,
			"feedback": arcanna_label
		}
		return body

	def send_bulk(self, job_id, events):
		url_suffix = f"api/v1/bulk/{job_id}"
		body = {
			"count": len(events),
			"events": events
		}
		demisto.log(f"bulk_body={body}")
		raw_response = requests.post(url=self.base_url + url_suffix, headers=self.get_headers(), verify=self.verify,
									 json=body)

		if raw_response.status_code != 201:
			raise Exception(f"Arcanna Error HttpCode={raw_response.status_code} body={raw_response.text}")
		return raw_response.json()


''' COMMAND FUNCTIONS '''


def test_module(client: Client, close_reasons_field: list) -> str:
	if len(close_reasons_field) < 1:
		return "Arcanna Mapping Error. Please check your close_reasons field has values set in the integration parameters"

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

def export_event(client: Client, args: Dict[str, Any]) -> CommandResults:
	job_id = args.get("job_id", None)
	if not job_id:
		job_id = client.get_default_job_id()
	event_id = args.get("event_id")
	
	response = client.export_event(job_id=job_id, event_id=event_id)
	readable_output = "## {response}"
	
	return CommandResults(
		readable_output=readable_output,
		outputs_prefix='Arcanna.Event',
		outputs_key_field='export',
		outputs=response
	)
	
def trigger_training(client: Client, args: Dict[str, Any]) -> CommandResults:
	job_id = args.get("job_id", None)
	if not job_id:
		job_id = client.get_default_job_id()
	username = args.get("username", None)
	response = client.trigger_training(job_id=job_id, username=username)
	readable_output = f"## {response}"

	return CommandResults(
		readable_output=readable_output,
		outputs_prefix='Arcanna.Training',
		outputs_key_field='result',
		outputs=response
	 )
	 
def get_decision_set(client: Client, args: Dict[str, Any]) -> CommandResults:
	job_id = args.get("job_id", None)
	if not job_id:
		job_id = client.get_default_job_id()

	response = client.get_decision_set(job_id=job_id)
	readable_output = f"## {response}"
	body = {
		"decision_set": str(response)
	}
	return CommandResults(
		readable_output=readable_output,
		outputs_prefix='Arcanna.Event',
		outputs_key_field='decision_set',
		outputs=body
	)
	
def post_event(client: Client, args: Dict[str, Any]) -> CommandResults:
	title = args.get("title")

	job_id = args.get("job_id", None)
	if not job_id:
		job_id = client.get_default_job_id()

	raw_payload = args.get("event_json")
	severity = args.get("severity")
	id_value = args.get("id_value", None)

	response = client.send_raw_event(job_id=job_id, severity=severity, title=title, raw_body=raw_payload, id_value=id_value)
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


def send_event_feedback(client: Client, close_reasons: list, args: Dict[str, Any]) -> CommandResults:
	job_id = args.get("job_id", None)
	if not job_id:
		job_id = client.get_default_job_id()
	event_id = args.get("event_id")
	username = args.get("username")
	labels = args.get("labels").replace("'","").strip("][").split(', ')
	arcanna_label = labels[-1]
	indicators = args.get("indicators", None)
	close_reason = args.get('close_reason', None)
	pos = 0
	for value in close_reasons:
		if close_reason == value:
			 if pos < len(labels):
				 arcanna_label = labels[pos] 
		pos += 1
	if arcanna_label is None:
		return_error(f"Error unknown label supplied.label={arcanna_label}")
		raise Exception(f"Error in arcanna-send-event-feedback.Wrong label")

	response = client.send_feedback(job_id, event_id, username, arcanna_label, indicators)
	readable_output = f' ## Arcanna send event feedback results: {response}'

	return CommandResults(
		readable_output=readable_output,
		outputs_prefix='Arcanna.Event',
		outputs_key_field='feedback_status',
		outputs=response
	)

def parse_mappings(mapping: str) -> dict:
	result = {}
	pairs = mapping.split(",")
	for pair in pairs:
		parts = pair.split("=")
		if len(parts) != 2:
			return_error("Arcanna: Error while parsing mapping fields")
			return result
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
	verify_certificate = demisto.params().get('ssl_verification', False)
	close_reasons = demisto.params().get('close_reasons')
	proxy = demisto.params().get('proxy', False)
	
	default_job_id = demisto.params().get('default_job_id', 1201)
	demisto.debug(f'Command being called is {demisto.command()}')
	try:

		client = Client(
			api_key=api_key,
			base_url=base_url,
			ssl_verification=verify_certificate,
			proxy=proxy,
			default_job_id=default_job_id
		)

		if demisto.command() == 'test-module':
			# This is the call made when pressing the integration Test button.
			result_test = test_module(client, close_reasons)
			return_results(result_test)
		elif demisto.command() == "arcanna-get-jobs":
			result_get_jobs = get_jobs(client)
			return_results(result_get_jobs)
		elif demisto.command() == "arcanna-send-event":
			result_send_event = post_event(client, demisto.args())
			return_results(result_send_event)
		elif demisto.command() == "arcanna-export-event":
			result_export_event = export_event(client, demisto.args())
			return_results(result_export_event)
		elif demisto.command() == "arcanna-trigger-train":
			result_trigger_train = trigger_training(client, demisto.args())
			return_results(result_trigger_train)
		elif demisto.command() == "arcanna-get-decision-set":
			result_decision_set = get_decision_set(client, demisto.args())
			return_results(result_decision_set)
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
			result_send_feedback = send_event_feedback(client, close_reasons, demisto.args())
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
