from typing import Tuple, Dict, Union, Optional

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
import urllib3
import json

# Disable insecure warnings
urllib3.disable_warnings()
"""GLOBALS/PARAMS
Attributes:
    INTEGRATION_NAME:
        Name of the integration as shown in the integration UI, for example: Microsoft Graph User.

    INTEGRATION_COMMAND_NAME:
        Command names should be written ina all lower-case letters,
        and each word separated with a hyphen, for example: msgraph-user.

    INTEGRATION_CONTEXT_NAME:
        Context output names should be written in camel case, for example: MSGraphUser.
"""
INTEGRATION_NAME = 'Database Integration'
# lowercase with `-` dividers
INTEGRATION_COMMAND_NAME = 'database'
# No dividers
INTEGRATION_CONTEXT_NAME = 'Database'

ROWS_LIMIT = 50


class Client(BaseClient):
    def query(self, query_string: str) -> Union[Dict, list]:
        """Send query as is to server. note it's unsecured (can drop tables etc.).

        Args:
            query_string: query to send
            limit: limit number of rows

        Returns:
             List of lines from DB
        """

        params = {'query': query_string}
        return self._http_request('POST', url_suffix='', params=params)


def fetch_incidents_command(client: Client, last_run_dict: Optional[dict], first_fetch_time: str,
                            table_name: str, columns: str, date_name: str
                            ) -> Tuple[dict, list]:
    date_format = "%Y-%m-%dT%H:%M:%SZ"
    if not last_run_dict:
        last_fetch, _ = parse_date_range(first_fetch_time, date_format=date_format, utc=True)
    else:
        last_fetch = last_run_dict.get('last_run')
    query = "SELECT "
    for column in argToList(columns):
        query += f"{column}, "
    query = query.rstrip(',')
    query += f"FROM {table_name} WHERE {date_name} > {last_fetch}"
    raw_response = client.query(query)
    incidents = [
        {
            'name': f'Database incident: {row[0]}',
            'occurred': row[1],
            'rawJSON': json.dumps(raw_response)
        } for row in raw_response
    ]
    # Get last fetch from incidents
    if incidents:
        incidents.sort(key=lambda row: row.get('occurred'))
        last_fetch = incidents[-1]['occurred']
    return {'last_run': last_fetch}, incidents


def query_command(client: Client, args: dict) -> Tuple[str, dict, list]:
    query = args.get('query', '')
    columns = argToList(args.get('columns', ''))
    limit = args.get('limit') if args.get('limit') else ROWS_LIMIT  # type: ignore # [assignment]
    if 'limit' not in query.lower():
        query = query.rstrip(' ') + ' '
        query += f'LIMIT {limit}'
    raw_response = client.query(query)
    if raw_response:
        if columns:
            context = list()
            for row in raw_response:
                context_entry = dict()
                for i in range(len(columns)):
                    context_entry[columns[i]] = row[i]
                context.append(context_entry)
        else:
            context = raw_response  # type: ignore # [assignment]
        readable_output = tableToMarkdown(
            f"Results from {INTEGRATION_NAME}",
            context,
        )
        context = {"Database": {"Result": context}}  # type: ignore # [assignment]
        return readable_output, context, raw_response  # type: ignore # [assignment]
    return f"{INTEGRATION_NAME} - Found no results for given query.", {}, raw_response  # type: ignore # [assignment]


def main():
    params = demisto.params()
    username = params.get('credentials').get('identifier')
    password = params.get('credentials').get('password')
    server = urljoin(params.get('url'), '/api/v2.0/')
    # Should we use SSL
    use_ssl = not params.get('insecure')
    use_proxy = params.get('proxy')
    # Headers to be sent in requests
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
    }
    client = Client(server, use_ssl, use_proxy, headers=headers, auth=(username, password))
    # Commands switch case
    command = demisto.command()
    commands = {
        f'{INTEGRATION_COMMAND_NAME}-query': query_command
    }
    if command == 'fetch-incidents':
        # How many time before the first fetch to retrieve incidents
        fetch_time = params.get('fetch_time', '3 days')
        columns = params.get('columns')
        table_name = params.get('table_name')
        date_name = params.get('date_name')
        last_run, incidents = fetch_incidents_command(
            client, demisto.getLastRun(), fetch_time, table_name, columns, date_name
        )
        demisto.setLastRun(last_run)
        demisto.incidents(incidents)
    elif command in commands:
        return_outputs(*commands[command](client, demisto.args()))


if __name__ == 'builtins':
    main()
