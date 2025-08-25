import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# Cortex XSOAR Integration for SpiderSilk API
# This script is intended for use with the "Bring Your Own Integration" (BYOI) feature.
# Version: 1.2 - Replaced demisto.warning with demisto.info for compatibility.

import requests
import json
from datetime import datetime, timezone

# Disable insecure warnings if 'insecure' parameter is true
if demisto.params().get('insecure', False):
    try:
        requests.packages.urllib3.disable_warnings()
    except Exception:
        pass

# === CLIENT CLASS ===
# A single client class to handle all API requests.


class SpiderSilkClient:
    """Client to handle API requests to SpiderSilk."""

    def __init__(self, base_url, api_key_token, verify_ssl, proxy):
        self.base_url = base_url.rstrip('/')
        self.verify_ssl = verify_ssl
        self.headers = {
            'Authorization': "Bearer {}".format(api_key_token),
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        # handle_proxy() is part of CommonServerPython and will use the 'proxy' parameter
        handle_proxy(proxy_param_name='proxy')

    def http_request(self, method, url_suffix, params=None, json_data=None):
        """Generic HTTP request handler."""
        full_url = self.base_url + url_suffix
        demisto.debug("Sending {} request to {}".format(method, full_url))
        try:
            response = requests.request(
                method,
                full_url,
                headers=self.headers,
                params=params,
                json=json_data,
                verify=self.verify_ssl
            )
            response.raise_for_status()
            try:
                return response.json()
            except ValueError:
                # Handle cases where the response is not valid JSON
                return response.text
        except requests.exceptions.RequestException as e:
            err_msg = "API Request Error: {}".format(str(e))
            if e.response is not None:
                err_msg += " - Status: {}, Body: {}".format(e.response.status_code, e.response.text[:500])
            raise DemistoException(err_msg)

# === COMMAND FUNCTIONS ===


def test_module(client: SpiderSilkClient) -> str:
    """
    Tests API connectivity and authentication using the /stats endpoint.
    Returns 'ok' on success, raises DemistoException on failure.
    """
    try:
        response = client.http_request('GET', '/stats')
        # Based on response examples, a successful response contains a 'data' key.
        if isinstance(response, dict) and 'data' in response:
            return 'ok'
        else:
            raise DemistoException("Test failed. Unexpected response: {}".format(
                json.dumps(response) if isinstance(response, dict) else response
            ))
    except DemistoException as e:
        # Re-raise DemistoExceptions with a more specific test-module message
        raise DemistoException("Test failed. {}".format(str(e)))
    except Exception as e:
        raise DemistoException("Test failed. An unexpected error occurred: {}".format(str(e)))


def fetch_incidents(client: SpiderSilkClient, params: dict) -> tuple[list[dict], dict]:
    """
    Fetches dark web credential exposures as incidents.
    """
    last_run = demisto.getLastRun() or {}
    last_fetch_timestamp_str = last_run.get('last_fetch_created_at')

    first_fetch_time_hours = float(params.get('first_fetch_hours') or params.get('reported_since_hours', "24"))
    max_fetch = int(params.get('max_fetch', 100))
    hours_to_fetch_since = first_fetch_time_hours

    if last_fetch_timestamp_str:
        try:
            last_fetch_dt = arg_to_datetime(last_fetch_timestamp_str)
            now_utc = datetime.now(timezone.utc)
            delta_seconds = (now_utc - last_fetch_dt).total_seconds()
            hours_to_fetch_since = max(0.5, delta_seconds / 3600)
        except (ValueError, TypeError):
            # FIX: Replaced demisto.warning with demisto.info for compatibility
            demisto.info("Could not parse last fetch timestamp '{}'. Using first fetch settings.".format(last_fetch_timestamp_str))

    demisto.info("Fetching incidents reported since approx {} hours ago.".format(round(hours_to_fetch_since, 2)))

    incidents = []
    new_latest_credential_created_at = last_fetch_timestamp_str
    current_page = 1
    # Safety break to avoid potential infinite loops
    max_pages_to_check = 100 if max_fetch > 1000 else (max_fetch // 100) + 10

    while len(incidents) < max_fetch and current_page <= max_pages_to_check:
        api_page_limit = 100  # API max items per page
        items_to_request = min(api_page_limit, max_fetch - len(incidents))
        if items_to_request <= 0:
            break

        try:
            response = client.http_request(
                'GET',
                '/darkweb_credentials',
                params={'reported_since': round(hours_to_fetch_since, 2), 'limit': items_to_request, 'page': current_page}
            )
            credentials_list = demisto.get(response, 'data.credentials_list', [])

            if not credentials_list:
                break

            for item in credentials_list:
                created_at_str = item.get('created_at')
                # Check if timestamp exists and is newer than the last fetched one
                if created_at_str and (last_fetch_timestamp_str is None or created_at_str > last_fetch_timestamp_str):

                    # *** FIX: Convert timestamp to ISO 8601 format for XSOAR ***
                    try:
                        # Parse the API's timestamp format (e.g., "2025-06-30 15:56:26")
                        dt_obj = datetime.strptime(created_at_str, '%Y-%m-%d %H:%M:%S')
                        # Convert to ISO 8601 format with Z for UTC (e.g., "2025-06-30T15:56:26Z")
                        occurred_iso = dt_obj.isoformat() + "Z"
                    except ValueError:
                        # If parsing fails, fall back to the original string and let XSOAR handle it.
                        # FIX: Replaced demisto.warning with demisto.info for compatibility
                        demisto.info("Could not parse timestamp '{}'. Using original value.".format(created_at_str))
                        occurred_iso = created_at_str

                    incident_name = "SpiderSilk Leaked Credential: {} from {}".format(
                        demisto.get(item, 'credenatials.username', 'N/A'), item.get('title', 'Unknown Source')
                    )
                    incident = {'name': incident_name, 'occurred': occurred_iso, 'rawJSON': json.dumps(item)}
                    incidents.append(incident)

                    # Track the latest timestamp string from the API to prevent re-fetching
                    if new_latest_credential_created_at is None or created_at_str > new_latest_credential_created_at:
                        new_latest_credential_created_at = created_at_str

            if len(credentials_list) < items_to_request:
                break
            current_page += 1
        except Exception as e:
            demisto.error("Failed during fetch-incidents loop: {}".format(str(e)))
            break

    next_run = {'last_fetch_created_at': new_latest_credential_created_at} if new_latest_credential_created_at else last_run
    return incidents, next_run


def get_darkweb_credentials_command(client: SpiderSilkClient, args: dict) -> CommandResults:
    """Gets dark web credentials based on arguments."""
    reported_since = args.get('reported_since_hours')
    limit = args.get('limit', 50)
    page = args.get('page', 1)

    response = client.http_request('GET', '/darkweb_credentials',
                                   params={'reported_since': reported_since, 'limit': limit, 'page': page})
    credentials_list = demisto.get(response, 'data.credentials_list', [])

    if credentials_list:
        readable_output = tableToMarkdown("SpiderSilk Dark Web Credentials", credentials_list, headers=[
                                          'uuid', 'key', 'title', 'category', 'status', 'created_at'])
        return CommandResults(outputs_prefix='SpiderSilk.DarkwebCredential', outputs_key_field='uuid', outputs=credentials_list, readable_output=readable_output)
    return CommandResults(readable_output="No Dark Web credentials found for the specified criteria.")


def get_darkweb_reports_command(client: SpiderSilkClient, args: dict) -> CommandResults:
    """Gets dark web reports."""
    limit = args.get('limit', 50)
    page = args.get('page', 1)

    response = client.http_request('GET', '/darkweb', params={'limit': limit, 'page': page})
    reports_list = demisto.get(response, 'data.darkweb_list', [])

    if reports_list:
        readable_output = tableToMarkdown("SpiderSilk Dark Web Reports", reports_list, headers=[
                                          'uuid', 'key', 'title', 'category', 'status', 'created', 'credentials'])
        return CommandResults(outputs_prefix='SpiderSilk.DarkwebReport', outputs_key_field='uuid', outputs=reports_list, readable_output=readable_output)
    return CommandResults(readable_output="No Dark Web reports found.")


def get_darkweb_report_details_command(client: SpiderSilkClient, args: dict) -> CommandResults:
    """Gets details for a specific dark web report."""
    uuid = args.get('uuid')
    response = client.http_request('GET', '/darkweb/{}'.format(uuid))
    report_data = demisto.get(response, 'data', {})

    if report_data:
        readable_output = tableToMarkdown("SpiderSilk Dark Web Report Details for {}".format(report_data.get('key')), report_data)
        return CommandResults(outputs_prefix='SpiderSilk.DarkwebReport', outputs_key_field='uuid', outputs=report_data, readable_output=readable_output)
    raise DemistoException("Could not retrieve details for UUID '{}'.".format(uuid))


def update_darkweb_report_status_command(client: SpiderSilkClient, args: dict) -> str:
    """Updates the status of a dark web report."""
    uuid = args.get('uuid')
    status_id = arg_to_number(args.get('status_id'))
    comment = args.get('comment')

    payload = {'status_id': status_id, 'comment': comment}
    response = client.http_request('PUT', '/darkweb/{}'.format(uuid), json_data=payload)

    if demisto.get(response, 'code') == 'success' or demisto.get(response, 'message'):
        return "Successfully updated status for Dark Web report '{}'. Message: {}".format(uuid, response.get('message', 'N/A'))
    raise DemistoException("Failed to update status for Dark Web report '{}'. Response: {}".format(uuid, response))


def get_threats_command(client: SpiderSilkClient, args: dict) -> CommandResults:
    """Gets threats."""
    limit = args.get('limit', 50)
    page = args.get('page', 1)
    updated_since = args.get('updated_since')

    params = {'limit': limit, 'page': page, 'updated_since': updated_since}
    response = client.http_request('GET', '/threats', params=params)
    threats_list = demisto.get(response, 'data.threats_list', [])

    if threats_list:
        readable_output = tableToMarkdown("SpiderSilk Threats", threats_list, headers=[
                                          'uuid', 'threat_key', 'title', 'category', 'severity', 'status', 'created'])
        return CommandResults(outputs_prefix='SpiderSilk.Threat', outputs_key_field='uuid', outputs=threats_list, readable_output=readable_output)
    return CommandResults(readable_output="No threats found for the specified criteria.")


def get_threat_details_command(client: SpiderSilkClient, args: dict) -> CommandResults:
    """Gets details for a specific threat."""
    uuid = args.get('uuid')
    response = client.http_request('GET', '/threats/{}'.format(uuid))
    threat_data = demisto.get(response, 'data', {})

    if threat_data:
        readable_output = tableToMarkdown("SpiderSilk Threat Details for {}".format(threat_data.get('threat_key')), threat_data)
        return CommandResults(outputs_prefix='SpiderSilk.Threat', outputs_key_field='uuid', outputs=threat_data, readable_output=readable_output)
    raise DemistoException("Could not retrieve details for UUID '{}'.".format(uuid))


def update_threat_status_command(client: SpiderSilkClient, args: dict) -> str:
    """Updates the status of a threat."""
    uuid = args.get('uuid')
    status_id = arg_to_number(args.get('status_id'))
    comment = args.get('comment')

    payload = {'status_id': status_id, 'comment': comment}
    response = client.http_request('PUT', '/threats/{}'.format(uuid), json_data=payload)

    if demisto.get(response, 'code') == 'success' or demisto.get(response, 'message'):
        return "Successfully updated status for threat '{}'. Message: {}".format(uuid, response.get('message', 'N/A'))
    raise DemistoException("Failed to update status for threat '{}'. Response: {}".format(uuid, response))


def get_assets_command(client: SpiderSilkClient, args: dict) -> CommandResults:
    """Gets assets."""
    limit = args.get('limit', 50)
    page = args.get('page', 1)

    response = client.http_request('GET', '/assets', params={'limit': limit, 'page': page})
    assets_list = demisto.get(response, 'data.assets_list', [])

    if assets_list:
        readable_output = tableToMarkdown("SpiderSilk Assets", assets_list, headers=[
                                          'asset_id', 'hostname', 'asset_type', 'service_provider', 'country_iso', 'created'])
        return CommandResults(outputs_prefix='SpiderSilk.Asset', outputs_key_field='asset_id', outputs=assets_list, readable_output=readable_output)
    return CommandResults(readable_output="No assets found.")


def get_asset_details_command(client: SpiderSilkClient, args: dict) -> CommandResults:
    """Gets details for a specific asset."""
    asset_id = args.get('asset_id')
    response = client.http_request('GET', '/assets/{}'.format(asset_id))
    asset_data = demisto.get(response, 'data', {})

    if asset_data:
        readable_output = tableToMarkdown("SpiderSilk Asset Details for {}".format(asset_data.get('hostname')), asset_data)
        return CommandResults(outputs_prefix='SpiderSilk.Asset', outputs_key_field='asset_id', outputs=asset_data, readable_output=readable_output)
    raise DemistoException("Could not retrieve details for Asset ID '{}'.".format(asset_id))


# === MAIN FUNCTION ===
def main() -> None:
    """Main function, parses command and executes the corresponding function."""

    params = demisto.params()
    base_url = params.get('base_url')
    api_key_details = params.get('api_key')
    api_key = api_key_details.get('password') if isinstance(api_key_details, dict) else api_key_details
    verify_ssl = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    command = demisto.command()
    args = demisto.args()

    # Log the command being executed, but not the API key
    demisto.info("Command being called is: {}".format(command))

    try:
        # Create a client instance
        client = SpiderSilkClient(base_url, api_key, verify_ssl, proxy)

        # Command routing
        if command == 'test-module':
            result = test_module(client)
            return_results(result)
        elif command == 'fetch-incidents':
            incidents, next_run = fetch_incidents(client, params)
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
        elif command == 'spidersilk-get-darkweb-credentials':
            return_results(get_darkweb_credentials_command(client, args))
        elif command == 'spidersilk-get-darkweb-reports':
            return_results(get_darkweb_reports_command(client, args))
        elif command == 'spidersilk-get-darkweb-report-details':
            return_results(get_darkweb_report_details_command(client, args))
        elif command == 'spidersilk-update-darkweb-report-status':
            return_results(update_darkweb_report_status_command(client, args))
        elif command == 'spidersilk-get-threats':
            return_results(get_threats_command(client, args))
        elif command == 'spidersilk-get-threat-details':
            return_results(get_threat_details_command(client, args))
        elif command == 'spidersilk-update-threat-status':
            return_results(update_threat_status_command(client, args))
        elif command == 'spidersilk-get-assets':
            return_results(get_assets_command(client, args))
        elif command == 'spidersilk-get-asset-details':
            return_results(get_asset_details_command(client, args))
        else:
            raise NotImplementedError("Command '{}' is not implemented.".format(command))

    except Exception as e:
        # For any other unhandled exception, return an error
        return_error("Failed to execute command '{}'. Error: {}".format(command, str(e)))


# === Standard Entry Point ===
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
