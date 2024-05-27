import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, Tuple
import dateparser
import urllib3

"""Dragos Worldview Integration for XSOAR."""

# flake8: noqa: F402,F405 lgtm


STATUS_TO_RETRY = [500, 501, 502, 503, 504]

# disable insecure warnings
urllib3.disable_warnings()  # pylint:disable=no-member


class Client(BaseClient):
    def whoami(self) -> Dict[str, Any]:
        """Test that API works."""
        return self._http_request(
            method="get",
            url_suffix="indicators?page=1&page_size=1&serial%5B%5D=AA-2022-24",
            timeout=60,
        )

    def api_request(self, suffix: str, response_type: str = 'json'):
        return self._http_request(
            method="get",
            url_suffix=suffix,
            timeout=30,
            retries=3,
            status_list_to_retry=STATUS_TO_RETRY,
            resp_type=response_type
        )


def get_report(client: Client, args: Dict[str, Any]) -> Dict[str, Any]:
    serial = args.get('serial')
    if serial is None:
        api_query = ''
    else:
        api_query = 'products/' + serial + '/report'

    file = client.api_request(api_query, 'content')
    file_entry = fileResult(filename='report.pdf', data=file)
    return file_entry


def get_csv(client: Client, args: Dict[str, Any]) -> Dict[str, Any]:
    serial = args.get('serial')
    if serial is None:
        api_query = ''
    else:
        api_query = 'products/' + serial + '/csv'

    file = client.api_request(api_query, 'content')
    file_entry = fileResult(filename='indicators.csv', data=file)

    return file_entry


def get_stix(client: Client, args: Dict[str, Any]) -> Dict[str, Any]:
    serial = args.get('serial')
    if serial is None:
        api_query = ''
    else:
        api_query = 'products/' + serial + '/stix2'

    file = client.api_request(api_query, 'content')
    file_entry = fileResult(filename='indicators.stix2.json', data=file)

    return file_entry


def get_indicators(client: Client, args: Dict[str, Any]) -> CommandResults:
    exclude_suspect_domain = argToBoolean(args.get('exclude_suspect_domain', False))
    page = args.get('page')
    page_size = args.get('page_size')
    updated_after = args.get('updated_after')
    value = args.get('value')
    indicator_type = args.get('type')
    serials = argToList(args.get('serial'))
    tags = argToList(args.get('tags'))

    # The arguments page, page_size and exclude_suspect_domain have an API default of 1, 500 and false respectively,
    # and do not need to be included in the query unless changed
    query_list = []
    if page:
        query_list.append('page=' + page)
    if exclude_suspect_domain:
        query_list.append('exclude_suspect_domain=' + str(exclude_suspect_domain).lower())
    if page_size:
        query_list.append('page_size=' + page_size)
    if updated_after:
        query_list.append('updated_after=' + updated_after.replace(":", "%3A"))
    if value:
        query_list.append('value=' + value)
    if indicator_type:
        query_list.append('type=' + indicator_type)
    for serial in serials:
        query_list.append('serial%5B%5D=' + serial)
    for tag in tags:
        query_list.append('tags%5B%5D=' + tag)

    # If any arguments were submitted then run the relevent query,
    # else return all indicators from the last 48 hours
    if query_list:
        query_string = '&'.join(query_list)
        api_query = f'indicators?{query_string}'
    else:
        time = str(datetime.now() - timedelta(hours=48))
        time = time.replace(":", "%3A")
        api_query = f'indicators?updated_after={time}'
    raw_response = client.api_request(api_query)
    data = raw_response['indicators']
    page_number = 2 if not page else int(page) + 1
    if page:
        query_list.pop(0)
        query_string = '&'.join(query_list)
    full_response = raw_response

    # If there are still more dragos pages (ie more indicators) than was returned by
    # the intial query, iterate through the remaining pages and add all unique indicators
    # to the return data
    while int(raw_response['total_pages']) > int(raw_response['page']):
        if query_list:
            api_query = f'indicators?page={page_number}&{query_string}'
        else:
            api_query = f'indicators?page={page_number}&updated_after={time}'
        page_number += 1
        raw_response = client.api_request(api_query)
        new_data = raw_response['indicators']

        data.extend(new_data)
        for item in new_data:
            if item not in full_response['indicators']:
                full_response['indicators'].append(item)

    results = CommandResults(
        outputs_prefix='Dragos.Indicators',
        outputs_key_field='indicator_id',
        outputs=data,
        readable_output=tableToMarkdown('Dragos Indicators', data),
        raw_response=full_response
    )

    return results


def fetch_incidents(client: Client, last_run: dict, first_fetch: str) -> Tuple[list, dict]:
    if last_run == {}:
        last_fetch = dateparser.parse(first_fetch)
    else:
        last_fetch = last_run.get('time')
        last_fetch = dateparser.parse(str(last_fetch))

    max_time = last_fetch

    api_query = "products?released_after="
    api_query = api_query + str(max_time)
    api_query = api_query.replace(":", "%3A")
    api_query = api_query.replace(" ", "%20")

    incident_data = client.api_request(api_query)
    incidents = []
    items = incident_data['products']

    for item in items:
        item['updated_at'] = item['updated_at'][:-5]
        incident_time = dateparser.parse(item['updated_at'])
        incident = {
            'name': item['title'],
            'occurred': incident_time.strftime('%Y-%m-%dT%H:%M:%SZ'),  # type: ignore
            'rawJSON': json.dumps(item)
        }

        incidents.append(incident)

        if incident_time > max_time:  # type: ignore
            max_time = incident_time

    next_run = {'time': max_time.strftime('%Y-%m-%dT%H:%M:%S')}  # type: ignore
    incidents.reverse()

    return incidents, next_run


def main() -> None:
    """Main method used to run actions."""
    try:
        demisto_params = demisto.params()
        base_url = demisto_params.get("url", "").rstrip("/")
        base_url = base_url + "/api/v1"
        verify_ssl = not demisto_params.get("insecure", False)
        proxy = demisto_params.get("proxy", False)
        api_token = demisto_params.get("credential_token", {}).get("password") or demisto_params.get("apitoken")
        if not api_token:
            return_error('Please provide a valid API token')
        api_key = demisto_params.get("credential_key", {}).get("password") or demisto_params.get("apikey")
        if not api_key:
            return_error('Please provide a valid API key')
        headers = {
            "accept": "*/*",
            "API-TOKEN": api_token,
            "API-SECRET": api_key,
        }
        client = Client(
            base_url=base_url, verify=verify_ssl, headers=headers, proxy=proxy
        )
        commands: Dict[str, Callable] = {
            'dragos-get-indicators': get_indicators,
            'dragos-get-full-report': get_report,
            'dragos-get-ioc-csv': get_csv,
            'dragos-get-stix2': get_stix
        }
        command = demisto.command()
        if command == "test-module":
            try:
                client.whoami()
                return_results("ok")
            except Exception as err:
                message = str(err)
                try:
                    error = json.loads(str(err).split("\n")[1])
                    if "fail" in error.get("result", {}).get("status", ""):
                        message = error.get("result", {})["message"]
                except Exception:
                    message = (
                        "Unknown error. Please verify that the API"
                        f" URL, Token and Key are correctly configured. RAW Error: {err}"
                    )
                raise DemistoException(f"Failed due to - {message}")
        elif command == 'fetch-incidents':
            first_fetch = demisto_params.get('first_fetch', '24 hours').strip()
            incidents, next_run = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch=first_fetch
            )
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
        elif command in commands:
            return_results(commands[command](client, demisto.args()))

    except Exception as e:
        return_error(
            f"Failed to execute {demisto.command()} command. "
            f"Error: {str(e)}"
        )


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
