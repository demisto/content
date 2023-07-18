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
    serial = args.get('serial')
    if serial:
        api_query = "indicators?serial%5B%5D=" + serial
    else:
        time = datetime.now() - timedelta(hours=48)
        api_query = "indicators?updated_after="
        api_query = api_query + str(time)
        api_query = api_query.replace(":", "%3A")

    raw_response = client.api_request(api_query)
    data = raw_response['indicators']
    page_number = 2
    full_response = raw_response

    while raw_response['total_pages'] >= raw_response['page']:
        if serial:
            api_query = "indicators?page=" + str(page_number) + "&serial%5B%5D=" + serial
        else:
            api_query = "indicators?page=" + str(page_number) + "&updated_after=" + str(time)
            api_query = api_query.replace(":", "%3A")
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
        headers = {
            "accept": "*/*",
            "API-TOKEN": demisto_params["apitoken"],
            "API-SECRET": demisto_params["apikey"],
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
