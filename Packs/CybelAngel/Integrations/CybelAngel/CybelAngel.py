import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import datetime as dt
import requests
import urllib3
import json
from enum import IntEnum, Enum
from uuid import UUID
from typing import Optional, List
from dataclasses import dataclass, field, asdict

"""CybelAngel Integration for Cortex XSOAR.

Provides interaction with the CybelAngel API, enabling incident management,
report retrieval, remediation, and comment management. Facilitates automated
incident handling and external risk monitoring by fetching, updating, and
processing CybelAngel data within Cortex XSOAR.

Resources:
    CybelAngel Developer Documentation: https://developer.cybelangel.com/
    XSOAR Developer Documentation: https://xsoar.pan.dev/docs/welcome

Commands:
    test-module:
        Tests API connectivity and authentication. This command runs when
        pressing the 'Test' button in XSOAR.
        Returns:
            str: 'ok' if authentication and connectivity are successful.

    fetch-incidents:
        Fetches incidents (reports) from CybelAngel within a specified time
        interval.
        Args:
            first_fetch_interval (int): The interval in minutes for initial fetch
            last_run: Timestamp of the last fetch to prevent duplicates
        Returns:
            list: XSOAR incidents populated with CybelAngel reports,
                 categorized by severity and including key details

    cybelangel-get-report-by-id:
        Retrieves a specific CybelAngel report by its unique ID.
        Args:
            report_id (str): The ID of the report to retrieve
        Returns:
            dict: Report data, formatted for display in XSOAR

    cybelangel-get-report-attachment:
        Retrieves an attachment from a specific report.
        Args:
            report_id (str): The report ID
            attachment_id (str): The attachment ID
            filename (str): The desired filename for the download
        Returns:
            File: The attachment file in XSOAR

    cybelangel-remediate:
        Submits a remediation request for a specific report.
        Args:
            report_id (str): The ID of the report for remediation
            email (str): Email address of the requester
            requester_fullname (str): Full name of the requester
        Returns:
            dict: Status and confirmation of the remediation request

    cybelangel-get-comments:
        Retrieves comments associated with a specific report.
        Args:
            report_id (str): The report ID
        Returns:
            list: Comments with metadata (content, author, timestamp)

    cybelangel-post-comment:
        Adds a comment to a specific report.
        Args:
            report_id (str): The report ID
            comment (str): The comment content
            tenant_id (str): The tenant ID associated with the report
            assigned (bool, optional): Specifies if comment is assigned
                                     Defaults to True
            parent_id (str, optional): Optional ID for nested comments
        Returns:
            dict: Confirmation of comment addition and status code

    cybelangel-update-status:
        Updates the status of a specific report.
        Args:
            report_id (str): The report ID
            status (str): New status value (e.g., "open", "resolved")
        Returns:
            dict: Confirmation with updated report details

    cybelangel-get-report-pdf:
        Downloads a PDF of the report.
        Args:
            report_id (str): The report ID
        Returns:
            File: PDF file of the report as download in XSOAR

    test_command:
        A testing command for development purposes.
        Not intended for production use.

Implementation Details:
    Authentication:
        Uses client ID and secret to fetch and renew tokens automatically.

    Token Management:
        Manages token expiration and renewal, with caching to reduce API calls.

    Error Handling:
        Catches exceptions and logs detailed errors for debugging within XSOAR.

    Data Parsing:
        Parses and structures data from CybelAngel API responses for clear
        presentation in XSOAR.

    Incident Creation:
        Maps CybelAngel reports to XSOAR incidents with relevant metadata,
        including severity and timestamps.
"""


''' IMPORTS '''
# Disable insecure warnings
# urllib3.disable_warnings()


''' CONSTANTS '''
BASE_URL = "https://platform.cybelangel.com/"
AUTH_URL = "https://auth.cybelangel.com/oauth/token"

SEVERITIES = {"0": "informational", "1": "low", "2": "moderate", "3": "high", "4": "critical"}

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR


''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def __init__(self, client_id: str, client_secret: str, auth_token=None, token_time=None):
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
        """ Check to see if token exists or if there is still time left with to use the token """
        if self.token_time is None:
            self.fetch_token()
            self.token_time = dt.datetime.utcnow()

        else:
            token_time = dt.datetime.strptime(self.token_time, "%Y-%m-%d %H:%M:%S.%f")

            timeDiff = (dt.datetime.utcnow() - token_time).total_seconds()
            if timeDiff >= 3600:
                self.fetch_token()
                self.token_time = dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f")

    def get_reports(self, interval: int):
        """ Get all reports from CybelAngel based on specified time interval
            args:
            """
        self.check_token()
        headers = {'Content-Type': "application/json",
                   'Authorization': self.token}
        params = {
            'end-date': dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M"),
            'start-date': (dt.datetime.utcnow() - dt.timedelta(minutes=interval)).strftime("%Y-%m-%dT%H:%M")}
        try:
            demisto.info(f'Fetching incidents at interval :{interval}')

            response = json.loads(requests.get(f'{self.base_url}api/v2/reports', headers=headers, params=params).text)
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
            'end-date': dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M"),
            'start-date': "2000-01-02T01:01:01"}
        try:
            response = json.loads(requests.get(f'{self.base_url}api/v2/reports', headers=headers, params=params).text)
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
            demisto.info(type(result))
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

    def remediate(self, report_id: str, email: str, requester_fullname):
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

    def post_comment(self, comment: str, report_id: str, tenant_id: str, assigned: bool = True, parent_id=None):
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
    """ Stores new token in integration cache if new token is fetched by base client"""
    if client.new_token_fetched:
        new_context = {
            'token': str(client.token),
            'expiry': str(client.token_time),
            'first_pull': str(False)
        }
        demisto.setIntegrationContext(new_context)
        demisto.info('New auth token stored')


def _datetime_helper(last_run_date):
    """_summary_

    Args:
        last_run_date (_type_): Used to

    Returns:
        _type_: _description_
    """

    delta = dt.datetime.utcnow() - dt.datetime.strptime(last_run_date, '%Y-%m-%dT%H:%M:%SZ')
    total_minutes = int(delta.total_seconds() / 60)
    return total_minutes


''' COMMAND FUNCTIONS '''


def fetch_incidents(client: Client, first_fetch: bool, last_run, first_fetch_interval: int):
    """ Fetches reports from specific time range """

    # Change fetch interval from days to minutes if this is first fetch
    if first_fetch:
        fetch_interval = first_fetch_interval * 1140
    else:
        fetch_interval = _datetime_helper(last_run)

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
    demisto.setLastRun({'start_time': dt.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S') + "Z"})
    return incidents


def get_report_by_id_command(client: Client, args):
    report_id = args.get('report_id')
    demisto.debug(f"Fetching report with ID: {report_id}")

    try:
        result = client.get_report_by_id(report_id)

        if not result:
            return_results('No report found with the given ID')
            return

        command_results = CommandResults(
            outputs_prefix='CybelAngel.Report',
            outputs_key_field='id',
            outputs=result,
            readable_output=tableToMarkdown('CybelAngel Report', result),
            raw_response=result
        )
        _set_context(client)
        return command_results
    except Exception as e:
        error_message = f"Unexpected error: {str(e)}"
        demisto.error(error_message)
        _set_context(client)
        return CommandResults(
            readable_output=error_message
        )



def get_report_attachment_command(client: Client, args):
    report_id = args.get('report_id')
    attachment_id = args.get('attachment_id')
    filename = args.get('filename')
    try:
        # Retrieve the attachment from the client; assuming it returns the file's binary data
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
        response, status_code = client.remediate(report_id, email=email, requester_fullname=requester_name)
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
        # Retrieve the report PDF using the report ID; assuming it returns the file's binary data
        report_pdf = client.get_report_pdf(report_id=report_id)
        if not report_pdf:
            return CommandResults(
                readable_output=f"No report found with ID: {report_id}."
            )

        demisto.debug(f"PDF Length: {len(report_pdf)} bytes")  # This ensures we have data before proceeding
        filename = f"{report_id}.pdf"
        return fileResult(filename=filename, data=report_pdf)

    except Exception as e:
        demisto.error(f"An error occurred while fetching the PDF: {str(e)}")  
        return CommandResults(
            readable_output=f'Error downloading the report: {str(e)}'
        )


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message = ''
    try:
        result = client.get_reports(500)
        if result:
            return 'ok'
    except DemistoException as e:
        if 'Forbidden' in e or 'Authorization' in e: 
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            message = e
    demisto.debug(message)

''' MAIN FUNCTION '''
def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    
   # Get Cybelangel credentials
    client_id = demisto.params().get('client_id')
    client_secret = demisto.params().get('client_secret')
    tenant_id = demisto.params().get('tenant_id')

    # Get last run
    last_run = demisto.getLastRun().get('start_time')

    # Manage first fetch from client
    first_fetch_interval = arg_to_number(demisto.params().get('first_fetch'))
    first_fetch = "first_pull" not in demisto.getIntegrationContext().keys()

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
            fetch_incidents(client, first_fetch=first_fetch, last_run=last_run, first_fetch_interval=first_fetch_interval)
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
        if demisto.command() == "test_command":
            test_command(client)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''
if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
