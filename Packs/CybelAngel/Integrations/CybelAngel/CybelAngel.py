import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from datetime import datetime, timedelta, UTC
import requests
import json


''' IMPORTS '''
# Disable insecure warnings
# urllib3.disable_warnings()


''' CONSTANTS '''
BASE_URL = "https://platform.cybelangel.com/"
AUTH_URL = "https://auth.cybelangel.com/oauth/token"

SEVERITIES = {"0": "informational",
              "1": "low",
              "2": "moderate",
              "3": "high",
              "4": "critical"}

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR


''' CLIENT CLASS '''


class Client(BaseClient):

    def __init__(self, client_id: str, client_secret: str, auth_token:str=None, token_time=None):
        self.base_url = "https://platform.cybelangel.com/"
        self.auth_url = "https://auth.cybelangel.com/oauth/token"
        self.client_id = client_id
        self.client_secret = client_secret
        self.token = auth_token
        self.token_time = token_time
        self.new_token_fetched = False
        self.first_request = False

    def fetch_token(self):
        headers = {'content-type': "application/json"}
        payload = {"client_id": self.client_id, "client_secret": self.client_secret,
                   "audience": self.base_url, "grant_type": "client_credentials"}

        try:
            token = requests.request('POST', self.auth_url, params=headers, data=payload)
            self.token = "Bearer " + json.loads(token.text)["access_token"]
            self.new_token_fetched = True
            demisto.info('New token acquired')

        except Exception as e:
            demisto.debug('Error fetching token')
            return {"msg": f"Error fetching token: {str(e)}"}

    def check_token(self):
        if self.token_time is None:
            self.fetch_token()
            self.token_time = datetime.now(UTC)
            return

        try:
            token_time = datetime.fromisoformat(self.token_time.replace('Z', '+00:00'))
            time_diff = (datetime.now(UTC) - token_time).total_seconds()
            if time_diff >= 3600:
                self.fetch_token()
                self.token_time = datetime.now(UTC).strftime(DATE_FORMAT)
        except (ValueError, TypeError):
            self.fetch_token()
            self.token_time = datetime.now(UTC).strftime(DATE_FORMAT)

    def get_reports(self, interval: int):
        self.check_token()
        headers = {'Content-Type': "application/json",
                   'Authorization': self.token}

        difference = datetime.now(UTC) - timedelta(minutes=interval)

        params = {
            'end-date': datetime.now(UTC).strftime(DATE_FORMAT),
            'start-date': difference.strftime(DATE_FORMAT)
        }
        try:
            demisto.info(f'Fetching incidents at interval :{interval}')

            response = json.loads(requests.get(f'{self.base_url}api/v2/reports',
                                               headers=headers, params=params).text)
            reports = []
            for report in response['reports']:
                reports.append(report)
            return reports

        except Exception as e:
            return [{"msg": f"Error getting reports : {e}"}]

    def get_all_reports(self):
        """ Get all reports from CybelAngel -- Only run once on Configuration """
        self.check_token()
        headers = {'Content-Type': "application/json",
                   'Authorization': self.token}
        params = {
            'end-date': datetime.now(UTC).strftime(DATE_FORMAT),
            'start-date': "2000-01-02T01:01:01"}
        try:
            response = json.loads(requests.get(f'{self.base_url}api/v2/reports',
                                               headers=headers, params=params).text)
            reports = []
            for report in response['reports']:
                reports.append(report)
            return reports

        except Exception as e:
            return [{"msg": f"Error getting reports : {e}"}]

    def get_report_by_id(self, report_id: str):
        self.check_token()
        headers = {'Content-Type': "application/json",
                   'Authorization': self.token}

        url = f'{self.base_url}api/v2/reports/{report_id}'
        try:
            response = requests.request(
                "GET", url, headers=headers).json()

            result = response
            # demisto.debug(f"RAW RESULT: {result}")
            return result
        except Exception as e:
            return [{"msg": f"Error getting report {report_id} : {e}"}]

    def get_report_attachment(self, report_id: str, attachment_id: str):
        self.check_token()
        url = f"{self.base_url}api/v1/reports/{report_id}/attachments/{attachment_id}"

        headers = {
            "Content-Type": "application/json",
            "Authorization": self.token
        }

        response = requests.request("GET", url, headers=headers)

        return response.content

    def remediate(self, report_id: str, email: str, requester_fullname:str):
        """ Create remediation request """
        self.check_token()
        url = f"{self.base_url}api/v1/reports/remediation-request"

        headers = {"Content-Type": "application/json",
                   "Accept": "application/json",
                   "Authorization": self.token}

        payload = {"report_id": report_id,
                   "requester_email": email,
                   "requester_fullname": requester_fullname}

        try:
            response = requests.request("POST", url, json=payload, headers=headers)

            return response.text, response.status_code

        except requests.exceptions.HTTPError as error:
            raise SystemExit(error)

    def get_comments(self, report_id: str):
        """ Get comments from the report """
        self.check_token()
        url = f"{self.base_url}api/v1/reports/{report_id}/comments"
        headers = {'Content-Type': "application/json",
                   'Authorization': self.token}

        try:
            response = json.loads(requests.request(
                "GET", url, headers=headers).text)

            comm = []
            for comment in response["comments"]:
                comm.append(comment)
            return comm
        except requests.exceptions.HTTPError as error:
            raise SystemExit(error)

    def post_comment(self, comment: str, report_id: str,
                     tenant_id: str, assigned: bool = True, parent_id=None):
        self.check_token()
        url = f"{self.base_url}api/v1/reports/{report_id}/comments"
        if parent_id:
            payload = {
                "content": comment,
                "discussion_id": f"{report_id}:{tenant_id}",
                "parent_id": parent_id,
                "assigned": assigned
            }
        else:
            payload = {
                "content": comment,
                "discussion_id": f"{report_id}:{tenant_id}",
                "assigned": assigned
            }

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": self.token
        }

        response = requests.request("POST", url, json=payload, headers=headers)

        return response.text, response.status_code

    def update_status(self, status: str, report_id: str):
        """ Retrieve CBA Reports using the polling interval
            Statuses: open, resolved """
        self.check_token()
        url = f"{self.base_url}api/v1/reports/{report_id}/status"
        headers = {'Content-Type': "application/json",
                   'Authorization': self.token}

        payload = {'status': status}

        try:
            response = requests.request(
                "PUT", url, json=payload, headers=headers)
            return response.text, response.status_code

        except requests.exceptions.HTTPError as error:
            raise SystemExit(error)

    def get_report_pdf(self, report_id: str):
        """ Retrieve pdf of a report from CybelAngel """
        self.check_token()
        url = url = f"{self.base_url}api/v1/reports/{report_id}/pdf"
        headers = {
            "Accept": "application/pdf, application/json",
            "Authorization": self.token
        }
        try:
            response = requests.get(url, headers=headers)
            return response.content
        except Exception as e:
            return f"Error occured : {e}"


''' HELPER FUNCTIONS '''


def _set_context(client: Client):
    if client.new_token_fetched:
        new_context = {
            'token': str(client.token),
            'expiry': datetime.now(UTC).strftime(DATE_FORMAT),
            'first_pull': str(False)
        }
        demisto.setIntegrationContext(new_context)
        demisto.info('New auth token stored')


def _datetime_helper(last_run_date):

    try:
        last_run = datetime.fromisoformat(last_run_date.replace('Z', '+00:00'))
    except (ValueError, TypeError):
        last_run = datetime.now(UTC) - timedelta(minutes=5)

    delta = datetime.now(UTC) - last_run
    total_minutes = int(delta.total_seconds() / 60)
    return total_minutes


''' COMMAND FUNCTIONS '''


def fetch_incidents(client: Client, first_fetch: bool,
                    last_run, first_fetch_interval: int):

    if first_fetch:
        fetch_interval = first_fetch_interval * 1140
    elif last_run:
        fetch_interval = _datetime_helper(last_run)
    else:
        fetch_interval = first_fetch_interval * 1140

    incident_reports = client.get_reports(fetch_interval)  # interval in minutes
    # Modify alerts into Demisto Alerts
    incidents = []
    for r in incident_reports:
        incident = {
            'name': f"CybelAngel Report - {r.get('incident_id')}",
            'occurred': f"{r.get('created_at')}Z",
            'severity': r.get('severity'),
            'category': r.get('category'),
            'details': r.get('abstract'),
            'rawJSON': json.dumps(r)
        }

        incidents.append(incident)

    # Create Incidents in XSOAR
    demisto.incidents(incidents=incidents)

    # Set the integration context
    _set_context(client)
    demisto.setLastRun({'start_time': datetime.now(UTC).strftime(DATE_FORMAT)})
    return incidents


def get_report_by_id_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    report_id = args.get('report_id')
    demisto.info(f"get_report_by_id_command called with report_id: {report_id}")

    try:
        result = client.get_report_by_id(str(report_id))

        # Log the raw result received from the client
        demisto.debug(f"Raw response from get_report_by_id: {json.dumps(result, indent=4)}")

        if not result:
            demisto.info(f"No report found for report_id: {report_id}")
            return_results('No report found with the given ID')
            return CommandResults(
                readable_output="No result found"
            )

        _set_context(client)

        # Log the output before returning
        demisto.info(f"Returning CommandResults for report_id: {report_id}")

        return CommandResults(
            outputs_prefix='CybelAngel.Report',
            outputs_key_field='id',
            outputs=result,
            readable_output=tableToMarkdown('CybelAngel Report', result),
            raw_response=result
        )

    except Exception as e:
        demisto.error(f"Error in get_report_by_id_command: {str(e)}")
        _set_context(client)
        return CommandResults(
            readable_output=f"Error: {str(e)}"
        )


def get_report_attachment_command(client: Client, args):
    report_id = args.get('report_id')
    attachment_id = args.get('attachment_id')
    filename = args.get('filename')
    try:
        attachment = client.get_report_attachment(report_id, attachment_id)

        return fileResult(filename=filename, data=attachment)

    except Exception as e:
        return CommandResults(
            readable_output=f'Error downloading attachment: {e}'
        )


def remediate_command(client: Client, args):
    report_id = args.get('report_id')
    email = args.get('email')
    requester_name = args.get('requester_fullname')
    try:
        response, status_code = client.remediate(report_id, email=email,
                                                 requester_fullname=requester_name)
        _set_context(client)
        return CommandResults(
            outputs_prefix='CybelAngel.Remediation',
            readable_output=f'Remediation Status {report_id} : {status_code}',
            raw_response=response
        )
    except Exception as e:
        _set_context(client)
        return CommandResults(
            readable_output=f'Error posting comment {e}'
        )


def get_comments_command(client: Client, args):
    report_id = args.get('report_id')
    try:
        comments = client.get_comments(report_id)
        _set_context(client)
        return CommandResults(
            outputs_prefix='CybelAngel.Comments',
            outputs_key_field='id',
            outputs=comments,
            readable_output=tableToMarkdown(f'Comments for Report {report_id}', comments)
        )
    except Exception as e:
        _set_context(client)
        return CommandResults(
            readable_output=f'Error posting comment {e}'
        )


def post_comment_command(client: Client, tenant_id: str, args):
    report_id = args.get('report_id')
    comment = args.get('comment')
    try:
        response, status_code = client.post_comment(comment=comment, report_id=report_id, tenant_id=tenant_id)
        _set_context(client)
        return CommandResults(
            readable_output=f'Comment added to report {report_id}: {comment} : STATUS: {status_code}'
        )
    except Exception as e:
        _set_context(client)
        return CommandResults(
            readable_output=f'Error posting comment {e}'
        )


def update_status_command(client: Client, args):
    report_id = args.get('report_id')
    status = args.get('status')
    try:
        response = client.update_status(status=status, report_id=report_id)
        _set_context(client)
        return CommandResults(
            outputs_prefix='CybelAngel.StatusUpdate',
            readable_output=f'Status Update for Report {report_id}, {response}',
            raw_response=response
        )
    except Exception as e:
        _set_context(client)
        return CommandResults(
            readable_output=f'Error Updating status {e}'
        )


def get_report_pdf_command(client: Client, args: Dict):
    report_id = args.get('report_id')
    if not report_id:
        return CommandResults(readable_output="Report ID not provided.")

    try:
        report_pdf = client.get_report_pdf(report_id=report_id)
        if not report_pdf:
            return CommandResults(
                readable_output=f"No report found with ID: {report_id}."
            )

        demisto.debug(f"PDF Length: {len(report_pdf)} bytes")
        filename = f"{report_id}.pdf"
        return fileResult(filename=filename, data=report_pdf)

    except Exception as e:
        demisto.error(f"An error occurred while fetching the PDF: {str(e)}")
        return CommandResults(
            readable_output=f'Error downloading the report: {str(e)}'
        )


def test_module(client: Client) -> str:
    message = ''
    try:
        result = client.get_reports(500)
        if result:
            return 'ok'
        return 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            message = str(e)
    demisto.debug(message)
    return ""


''' MAIN FUNCTION '''


def main() -> None:

   # Get Cybelangel credentials

    client_id = demisto.params().get("credentials", {}).get('identifier')
    client_secret = demisto.params().get("credentials", {}).get('password')
    tenant_id = demisto.params().get('tenant_id')

    # Get last run
    last_run = demisto.getLastRun().get('start_time')

    # Manage first fetch from client
    first_fetch_interval = arg_to_number(demisto.params().get('first_fetch')) or 0
    first_fetch = "first_pull" not in demisto.getIntegrationContext()

    # Get token and token time if it exists
    auth_token = demisto.getIntegrationContext().get('token')
    expiry = demisto.getIntegrationContext().get('expiry')

    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        args = demisto.args()
        # Create client connection to CybelAngel API
        client = Client(
            client_id=client_id,
            client_secret=client_secret,
            auth_token=auth_token,
            token_time=expiry
        )

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        if demisto.command() == "fetch-incidents":
            fetch_incidents(client, first_fetch=first_fetch, last_run=last_run,
                            first_fetch_interval=first_fetch_interval)
        elif demisto.command() == 'cybelangel-get-report-by-id':
            return_results(get_report_by_id_command(client, args))
        elif demisto.command() == 'cybelangel-get-report-attachment':
            return_results(get_report_attachment_command(client, args))
        elif demisto.command() == 'cybelangel-remediate':
            return_results(remediate_command(client, args))
        elif demisto.command() == 'cybelangel-get-comments':
            return_results(get_comments_command(client, args))
        elif demisto.command() == 'cybelangel-post-comment':
            return_results(post_comment_command(client, tenant_id, args))
        elif demisto.command() == 'cybelangel-update-status':
            return_results(update_status_command(client, args))
        elif demisto.command() == 'cybelangel-get-report-pdf':
            return_results(get_report_pdf_command(client, args))

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''
if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
