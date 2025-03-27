"""
Anomali Security Analytics Alerts Integration
"""

from datetime import datetime, timezone
import urllib3
import demistomock as demisto
from CommonServerPython import * 
from CommonServerUserPython import * 

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR
VENDOR_NAME = 'Anomali Security Analytics Alerts'
UTC = timezone.utc

""" CLIENT CLASS """


class Client(BaseClient):
    """
    Client to use in the Anomali Security Analytics Alerts integration.
    """

    def __init__(self, server_url: str, username: str, api_key: str, verify: bool, proxy: bool):
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'apikey {username}:{api_key}'
        }
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers)
        self._username = username
        self._api_key = api_key

    def create_search_job(self, query: str, source: str, time_range: dict) -> dict:
        """
        Create a search job.

        Args:
            query: The query string
            source: The source identifier (e.g. third_party_mynewapp)
            time_range: A dict with keys "from", "to" and "timezone"
                        (e.g. {"from": 1738681620000,
                        "to": 1738706820000,
                        "timezone": "America/New_York"})

        Returns:
            Response from API.
        """
        data = {
            'query': query,
            'source': source,
            'time_range': time_range
        }
        return self._http_request(method='POST',
                                  url_suffix='/api/v1/xdr/search/jobs/',
                                  json_data=data)

    def get_search_job_status(self, job_id: str) -> dict:
        """
        Get the status of a search job.

        Args:
            job_id: the search job uuid

        Returns:
            Response from API.
        """
        return self._http_request(method='GET',
                                  url_suffix=f'/api/v1/xdr/search/jobs/{job_id}/')

    def get_search_job_results(self, job_id: str) -> dict:
        """
        Get the results of a search job.

        Args:
            job_id: the search job uuid

        Returns:
            Response from API.
        """
        return self._http_request(method='GET',
                                  url_suffix=f'/api/v1/xdr/search/jobs/{job_id}/results/')

    def update_alert(self, data: dict) -> dict:
        """
        Update alert data (status or comment).
        """
        return self._http_request(method='PATCH',
                                  url_suffix='/api/v1/xdr/event/lookup/iceberg/update/',
                                  json_data=data)


""" COMMAND FUNCTIONS """


def command_create_search_job(client: Client, args: dict) -> CommandResults:
    """Start a search job for IOCs.

    Args:
        client (Client): Client object with request
        args (dict): Usually demisto.args()

    Returns:
        CommandResults.
    """
    query = str(args.get('query', ''))
    source = str(args.get('source', ''))
    tz_str = str(args.get('timezone', 'UTC'))
    from_datetime = arg_to_datetime(args.get('from', '1 day'), 
                                    arg_name='from', 
                                    is_utc=True, 
                                    required=False)

    if args.get('to'):
        to_datetime = arg_to_datetime(args.get('to'), 
                                    arg_name='to', 
                                    is_utc=True, 
                                    required=False)
    else:
        to_datetime = datetime.now(tz=UTC)

    time_from_ms = int(from_datetime.timestamp() * 1000)
    time_to_ms = int(to_datetime.timestamp() * 1000)

    time_range = {
        "from": time_from_ms,
        "to": time_to_ms,
        "timezone": tz_str
    }

    response = client.create_search_job(query, source, time_range)
    outputs = {
        'job_id': response.get('job_id', ''),
        'status': 'in progress'
    }

    return CommandResults(
        outputs_prefix='ThreatstreamAlerts.SearchJob',
        outputs_key_field='job_id',
        outputs=outputs,
        readable_output=tableToMarkdown(name="Search Job Created", t=outputs, removeNull=True),
        raw_response=response
    )


def command_get_search_job_status(client: Client, args: dict) -> list[CommandResults]:
    """Get the search job status.

    Args:
        client (Client): Client object with request
        args (dict): Usually demisto.args()

    Returns:
        list[CommandResults]: A list of command results containing the job status.
    """
    job_ids = ArgToList(str(args.get('job_id')))
    command_results: list[CommandResults] = []
    for job_id in job_ids:
        response = client.get_search_job_status(job_id)
        if 'error' in response:
            human_readable = (
                f"No results found for Job ID: {job_id}. "
                f"Error message: {response.get('error')}. "
                f"Please verify the Job ID and try again."
            )
            command_result = CommandResults(
                outputs_prefix='ThreatstreamAlerts.SearchJobStatus',
                outputs={},
                readable_output=human_readable,
                raw_response=response
            )
            command_results.append(command_result)
            continue

        status_value = response.get('status')
        outputs = {"job_id": job_id, "status": status_value}
        human_readable = tableToMarkdown(name="Search Job Status", t=outputs, removeNull=True)

        command_result = CommandResults(
            outputs_prefix='ThreatstreamAlerts.SearchJobStatus',
            outputs_key_field='job_id',
            outputs=outputs,
            readable_output=human_readable,
            raw_response=response
        )
        command_results.append(command_result)
    return command_results


def command_get_search_job_results(client: Client, args: dict) -> list[CommandResults]:
    """Get the search job results.

    Args:
        client (Client): Client object with request
        args (dict): Usually demisto.args()

    Returns:
        list[CommandResults]: A list of command results for each job id.
    """
    job_ids = ArgToList(str(args.get('job_id')))
    command_results: list[CommandResults] = []
    for job_id in job_ids:
        response = client.get_search_job_results(job_id)

        if 'fields' in response and 'records' in response:
            headers = response['fields']
            records = response['records']
            table_data = [dict(zip(headers, record)) for record in records]
            human_readable = tableToMarkdown(name="Search Job Results",
                                             t=table_data,
                                             headers=headers,
                                             removeNull=True)
        else:
            human_readable = tableToMarkdown(name="Search Job Results",
                                             t=response,
                                             removeNull=True)

        command_result = CommandResults(
            outputs_prefix='ThreatstreamAlerts.SearchJobResults',
            outputs_key_field='job_id',
            outputs=response,
            readable_output=human_readable,
            raw_response=response
        )
        command_results.append(command_result)
    return command_results


def command_update_alert_status(client: Client, args: dict) -> CommandResults:
    """Update the status of an alert.

    Args:
        client (Client): Client object with request
        args (dict): Usually demisto.args()

    Returns:
        CommandResults.
    """
    status = str(args.get('status'))
    uuid_val = str(args.get('uuid'))
    if not status or not uuid_val:
        raise Exception("Please provide both 'status' and 'uuid' parameters.")
    data = {
        "table_name": "alert",
        "columns": {
            "status": status
        },
        "primary_key_columns": ["uuid_"],
        "primary_key_values": [[uuid_val]]
    }
    response = client.update_alert(data)
    return CommandResults(
        outputs_prefix='ThreatstreamAlerts.UpdateAlertStatus',
        outputs=response,
        readable_output=tableToMarkdown(name="Update Alert Status", t=response, removeNull=True),
        raw_response=response
    )


def command_update_alert_comment(client: Client, args: dict) -> CommandResults:
    """Update the comment of an alert.

    Args:
        client (Client): Client object with request
        args (dict): Usually demisto.args()

    Returns:
        CommandResults.
    """
    comment = str(args.get('comment'))
    uuid_val = str(args.get('uuid'))
    if not comment or not uuid_val:
        raise Exception("Please provide both 'comment' and 'uuid' parameters.")
    data = {
        "table_name": "alert",
        "columns": {
            "comment": comment
        },
        "primary_key_columns": ["uuid_"],
        "primary_key_values": [[uuid_val]]
    }
    response = client.update_alert(data)
    return CommandResults(
        outputs_prefix='ThreatstreamAlerts.UpdateAlertComment',
        outputs=response,
        readable_output=tableToMarkdown(name="Update Alert Comment", t=response, removeNull=True),
        raw_response=response
    )


def module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises:
     exceptions if something goes wrong.

    Args:
        Client: client to use

    Returns:
        'ok' if test passed, anything else will fail the test.
    """

    try:
        now_dt = datetime.now(tz=UTC)
        now_ts = int(now_dt.timestamp() * 1000)
        one_day_ago_ts = now_ts - 24 * 3600 * 1000

        client.create_search_job(
            query="alert",
            source="third_party_mynewapp",
            time_range={
                "from": one_day_ago_ts,
                "to": now_ts
            }
        )
        return "ok"
    except Exception as e:
        raise Exception(f"Test failed: {str(e)}")


''' MAIN FUNCTION '''


def main():
    """main function, parses params and runs command functions"""

    params = demisto.params()
    base_url = params.get("url")
    verify_certificate = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))

    command = demisto.command()

    try:
        username = params.get("credentials", {}).get("identifier")
        api_key = params.get("credentials", {}).get("password")
        client = Client(
            server_url=base_url,
            username=username,
            api_key=api_key,
            verify=verify_certificate,
            proxy=proxy
        )
        args = demisto.args()
        commands = {
            'anomali-security-analytics-search-job-create': command_create_search_job,
            'anomali-security-analytics-search-job-status': command_get_search_job_status,
            'anomali-security-analytics-search-job-results': command_get_search_job_results,
            'anomali-security-analytics-update-alert-status': command_update_alert_status,
            'anomali-security-analytics-update-alert-comment': command_update_alert_comment,
        }
        if command == 'test-module':
            return_results(module(client))
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')

    except Exception as err:
        return_error(f'Failed to execute {command} command. Error: {str(err)} \n '
                     f'tracback: {traceback.format_exc()}')


''' ENTRY POINT '''

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
