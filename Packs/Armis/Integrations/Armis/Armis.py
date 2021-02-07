''' IMPORTS '''

from typing import List

import pytz
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import json
import dateparser
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


class AccessToken:
    def __init__(self, token: str, expiration: datetime):
        self._expiration = expiration
        self._token = token

    def __str__(self):
        return self._token

    @property
    def expired(self) -> bool:
        return self._expiration < datetime.now()


class Client(BaseClient):
    def __init__(self, secret: str, base_url, verify=True, proxy=False, ok_codes=tuple(), headers=None, auth=None):
        super().__init__(base_url, verify, proxy, ok_codes, headers, auth)
        self._secret = secret
        self._token: AccessToken = AccessToken('', datetime.now())

    def _get_token(self, force_new=False):
        """ Returns an existing access token if a valid one is available and creates one if not

        :param force_new: create a new access token even if an existing one is available
        :return: The access token
        :rtype: AccessToken
        """
        if self._token is None or force_new or self._token.expired:
            response = self._http_request('POST', '/access_token/', params={'secret_key': self._secret})
            self._token = AccessToken(response.get('data').get('access_token'),
                                      dateparser.parse(response.get('data').get('expiration_utc')))
        return self._token

    def search_by_aql_string(self, aql_string, order_by=None, max_results=None, page_from=None):
        """ Search with an AQL string and return the results.
        This function exists to allow a more advanced search than is provided for
        by the basic search alerts and search devices functions
        """
        token = self._get_token()
        params = {'aql': aql_string}
        if order_by is not None:
            params['orderBy'] = order_by
        if max_results is not None:
            params['length'] = max_results
        if page_from is not None:
            params['from'] = page_from

        response = self._http_request('GET', '/search/', params=params,
                                      headers={'accept': 'application/json', 'Authorization': str(token)})
        if max_results is None:
            # if max results was not specified get all results.
            results: list = response.get('data').get('results')
            while response.get('data').get('next') is not None:
                # while the response says there are more results use the 'page from' parameter to get the next results
                params['from'] = len(results)
                response = self._http_request('GET', '/search/', params=params,
                                              headers={'accept': 'application/json', 'Authorization': str(token)})
                results.extend(response.get('data').get('results'))

            response['data']['results'] = results

        return response['data']

    def search_alerts(self,
                      severity: List[str] = None,
                      status: List[str] = None,
                      alert_type: List[str] = None,
                      alert_id: str = None,
                      time_frame: str = None,
                      order_by: str = None,
                      max_results: int = None,
                      page_from: int = None):
        """ Search Alerts based on commonly used parameters rather than a free string """
        time_frame = '30 Days' if time_frame is None else time_frame
        aql_string = ['in:alerts', f'timeFrame:"{time_frame}"']
        if severity is not None:
            severity_string = ','.join([severity_option for severity_option in severity])
            aql_string.append(f'riskLevel:{severity_string}')
        if status is not None:
            status_string = ','.join([status_option for status_option in status])
            aql_string.append(f'status:{status_string}')
        if alert_type is not None:
            alert_string = ','.join([f'"{alert_option}"' for alert_option in alert_type])
            aql_string.append(f'type:{alert_string}')
        if alert_id is not None:
            aql_string.append(f'alertId:({alert_id})')

        aql_string = ' '.join(aql_string)
        return self.search_by_aql_string(aql_string, order_by=order_by, max_results=max_results, page_from=page_from)

    def free_string_search_alerts(self, aql_string, order_by=None, max_results=None, page_from=None):
        return self.search_by_aql_string(
            f'in:alerts {aql_string}',
            order_by=order_by,
            max_results=max_results,
            page_from=page_from)

    def update_alert_status(self, alert_id, status: str):
        """ Update the status of an alert """
        token = self._get_token()
        return self._http_request('PATCH', f'/alerts/{alert_id}/',
                                  headers={
                                      'accept': 'application/json',
                                      'Authorization': str(token),
                                      'content-type': 'application/x-www-form-urlencoded'
                                  },
                                  data={'status': status})

    def tag_device(self, device_id, tags: List[str]):
        """ Add tags to a device """
        token = self._get_token()
        return self._http_request('POST', f'/devices/{device_id}/tags/', json_data={'tags': tags},
                                  headers={'accept': 'application/json', 'Authorization': str(token)})

    def untag_device(self, device_id, tags):
        """ Remove a tag from a device"""
        token = self._get_token()
        return self._http_request('DELETE', f'/devices/{device_id}/tags/', json_data={'tags': tags},
                                  headers={'accept': 'application/json', 'Authorization': str(token)})

    def search_devices(self,
                       name=None,
                       device_id=None,
                       mac_address=None,
                       risk_level=None,
                       ip_address=None,
                       device_type=None,
                       time_frame: str = None,
                       order_by: str = None,
                       max_results: int = None):
        """ Search Devices using commonly used search parameters"""
        time_frame = '30 Days' if time_frame is None else time_frame
        aql_string = ['in:devices', f'timeFrame:"{time_frame}"']
        if name is not None:
            aql_string.append(f'name:({name})')
        if device_type is not None:
            type_string = ','.join([f'"{type_option}"' for type_option in device_type])
            aql_string.append(f'type:{type_string}')
        if mac_address is not None:
            aql_string.append(f'macAddress:({mac_address})')
        if ip_address is not None:
            aql_string.append(f'ipAddress:({ip_address})')
        if device_id is not None:
            aql_string.append(f'deviceId:({device_id})')
        if risk_level is not None:
            risk_level_string = ','.join([risk_level_option for risk_level_option in risk_level])
            aql_string.append(f'riskLevel:{risk_level_string}')

        aql_string = ' '.join(aql_string)
        return self.search_by_aql_string(aql_string, order_by=order_by, max_results=max_results)

    def free_string_search_devices(self, aql_string, order_by: str = None, max_results: int = None):
        return self.search_by_aql_string(f'in:devices {aql_string}', order_by=order_by, max_results=max_results)


def test_module(client):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.
    This test works by using a Client instance to create a temporary access token using the provided secret key,
    thereby testing both the connection to the server and the validity of the secret key

    Args:
        client: Armis client

    Returns:
        'ok' if test passed, anything else will fail the test.
    """

    try:
        client._get_token(force_new=True)
        return 'ok'
    except Exception as e:
        return f'Test failed with the following error: {repr(e)}'


def _ensure_timezone(date: datetime):
    """
    Some datetime objects are timezone naive and these cannot be compared to timezone aware datetime objects.
    This function sets a default timezone of UTC for any object without a timezone
    """
    if date.tzinfo is None:
        return date.replace(tzinfo=pytz.UTC)
    return date


def fetch_incidents(client,
                    last_run,
                    first_fetch_time,
                    minimum_severity,
                    alert_type,
                    alert_status,
                    free_search_string,
                    max_results):
    """
    This function will execute each interval (default is 1 minute).

    Args:
        client (Client): Armis client
        last_run (dateparser.time): The greatest incident created_time we fetched from last fetch
        first_fetch_time (dateparser.time): If last_run is None then fetch all incidents since first_fetch_time
        minimum_severity (str): the minimum severity of alerts to fetch
        alert_type ((List[str])): the type of alerts to fetch
        alert_status ((List[str])): the status of alerts to fetch
        free_search_string (str): A custom search string for fetching alerts
        max_results: (int): The maximum number of alerts to fetch at once

    Returns:
        next_run: This will be last_run in the next fetch-incidents
        incidents: Incidents that will be created in Demisto
    """
    # Get the last fetch time, if exists
    last_fetch = last_run.get('last_fetch')
    incomplete_fetches = last_run.get('incomplete_fetches', 0)

    # Handle first time fetch
    if last_fetch:
        last_fetch = _ensure_timezone(dateparser.parse(last_fetch))
    else:
        last_fetch = _ensure_timezone(dateparser.parse(first_fetch_time))
    # use the last fetch time to build a time frame in which to search for alerts
    time_frame = f'{round((_ensure_timezone(datetime.now()) - last_fetch).total_seconds())} seconds'

    latest_created_time = _ensure_timezone(last_fetch)

    # get a list of severities from the minimum specified and upward
    severities_in_order = ['Low', 'Medium', 'High']
    requested_severities = severities_in_order[severities_in_order.index(minimum_severity):]
    incidents = []

    page_from = max_results * incomplete_fetches or None
    if free_search_string:
        data = client.free_string_search_alerts(
            f'{free_search_string} timeFrame:{time_frame}',
            order_by='time',
            max_results=max_results,
            page_from=page_from)
    else:
        data = client.search_alerts(
            status=alert_status,
            severity=requested_severities,
            alert_type=alert_type,
            time_frame=time_frame,
            order_by='time',
            max_results=max_results,
            page_from=page_from
        )

    for alert in data.get('results'):
        incident_created_time = dateparser.parse(alert['time'])
        incident = {
            'name': alert['description'],
            'occurred': incident_created_time.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'rawJSON': json.dumps(alert)
        }

        incidents.append(incident)

        # Update last run and add incident if the incident is newer than last fetch
        incident_created_time = _ensure_timezone(incident_created_time)

        if incident_created_time > latest_created_time:
            latest_created_time = incident_created_time

    if data.get('next'):
        next_run = {'last_fetch': last_fetch.strftime(DATE_FORMAT), 'incomplete_fetches': incomplete_fetches + 1}
    else:
        next_run = {'last_fetch': latest_created_time.strftime(DATE_FORMAT), 'incomplete_fetches': 0}
    return next_run, incidents


def untag_device_command(client, device_id, tag):
    """armis-untag-device command: Remove the given tag from a device

        :param tag: the tag to remove from the device
        :type tag: str
        :param device_id: the ID of the device
        :type device_id: str
        :type client: ``Client``
        :param client: Armis Client object
    """
    client.untag_device(device_id, tag)
    return 'Untagging successful'


def tag_device_command(client, device_id, tags):
    """armis-tag-device command: Add the given tags to a device

        :param tags: the new tags to add to the device
        :type tags: List[str]
        :param device_id: the ID of the device
        :type device_id: str
        :type client: ``Client``
        :param client: Armis Client object
    """
    client.tag_device(device_id, tags)
    return 'Tagging successful'


def update_alert_status_command(client, alert_id, status):
    """armis-update-alert-status command: Update the status of an Alert to the given status

        :param alert_id: the id of the alert to update
        :type alert_id: str
        :param status: the new status for the alert
        :type status: str
        :type client: ``Client``
        :param client: Armis Client object
    """
    client.update_alert_status(alert_id, status)
    return 'Alert status updated successfully'


def search_alerts_command(client: Client, alert_type, severity, status, alert_id, time_frame):
    """armis-search-alerts command: Returns results for searching Alerts by common parameters

        :param alert_type: the types of alerts
        :type alert_type: List[str]
        :param severity: the severities of alerts
        :type severity: List[str]
        :param status: the statuses of the alert
        :type status: List[str]
        :param alert_id: the ID of the alert
        :type alert_id: str
        :param time_frame: the time frame in which to search
        :type time_frame: str
        :type client: ``Client``
        :param client: Armis Client object

        :return:
            A ``CommandResults`` compatible to return ``return_results()``,
            that contains a a json of the devices matching the given parameters

        :rtype: CommandResults
    """
    results = client.search_alerts(severity, status, alert_type, alert_id, time_frame).get('results')
    if results:
        return CommandResults(
            outputs_prefix='Armis.SearchAlerts',
            outputs_key_field='alertId',
            outputs=results,
            readable_output=tableToMarkdown('Alerts', results, headers=[
                'severity',
                'type',
                'time',
                'status',
                'title',
                'description',
                'activityIds',
                'activityUUIDs',
                'alertId',
                'connectionIds',
                'deviceIds'
            ])
        )
    return 'No results found'


def search_devices_command(client: Client, name, device_id, mac_address, risk_level, ip_address, device_type,
                           time_frame):
    """armis-search-devices command: Returns results for searching Devices by common parameters

        :param device_type: the type of device
        :type device_type: str
        :param ip_address: the ip address of the device
        :type ip_address: str
        :param risk_level: the risk level of the device
        :type risk_level: str
        :param mac_address: the MAC Address of the device
        :type mac_address: str
        :param device_id: the device ID
        :type device_id: str
        :param name: the name of the device
        :type name: str
        :param time_frame: the time frame in which to search
        :type time_frame: str
        :type client: ``Client``
        :param client: Armis Client object

        :return:
            A ``CommandResults`` compatible to return ``return_results()``,
            that contains a a json of the devices matching the given parameters

        :rtype: CommandResults
    """
    results = client.search_devices(name,
                                    device_id,
                                    mac_address,
                                    risk_level,
                                    ip_address,
                                    device_type,
                                    time_frame).get('results')
    if results:
        return CommandResults(
            outputs_prefix='Armis.SearchDevices',
            outputs_key_field='deviceId',
            outputs=results
        )
    return 'No devices found'


def search_devices_by_aql_command(client: Client, aql_string):
    """armis-search-devices-by-aql command: Returns results for searching Devices using a free AQL string

        :param aql_string: the free AQL string to search by
        :type aql_string: str
        :type client: ``Client``
        :param client: Armis Client object

        :return:
            A ``CommandResults`` compatible to return ``return_results()``,
            that contains a json of the devices matching the AQL string

        :rtype: CommandResults
    """
    results = client.free_string_search_devices(aql_string).get('results')
    if results:
        return CommandResults(
            outputs_prefix='Armis.SearchDevicesByAql',
            outputs_key_field='deviceId',
            outputs=results
        )
    return 'No devices found'


def search_alerts_by_aql_command(client: Client, aql_string):
    """armis-search-alerts-by-aql command: Returns results for searching Alerts using a free AQL string

        :param aql_string: the free AQL string to search by
        :type aql_string: str
        :type client: ``Client``
        :param client: Armis Client object

        :return:
            A ``CommandResults`` compatible to return ``return_results()``,
            that contains a json of the alerts matching the AQL string

        :rtype: CommandResults
    """
    results = client.free_string_search_alerts(aql_string).get('results')
    if results:
        return CommandResults(
            outputs_prefix='Armis.SearchAlertsByAql',
            outputs_key_field='alertId',
            outputs=results,
            readable_output=tableToMarkdown('Alerts', results, headers=[
                'severity',
                'type',
                'time',
                'status',
                'title',
                'description',
                'activityIds',
                'activityUUIDs',
                'alertId',
                'connectionIds',
                'deviceIds',
            ])
        )
    return 'No alerts found'


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    secret = demisto.params()['secret']

    # get the service API url
    base_url = demisto.params()['url']

    # How much time before the first fetch to retrieve incidents
    first_fetch_time = demisto.params().get('fetch_time', '3 days').strip()

    LOG(f'Command being called is {demisto.command()}')
    try:
        client = Client(secret, base_url=base_url)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)

        elif demisto.command() == 'fetch-incidents':
            minimum_severity = demisto.params()['min_severity']
            alert_status = demisto.params()['alert_status']
            alert_type = demisto.params()['alert_type']
            free_search_string = demisto.params()['free_fetch_string']

            # Set and define the fetch incidents command to run after activated via integration settings.
            next_run, incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_time,
                alert_type=alert_type,
                alert_status=alert_status,
                minimum_severity=minimum_severity,
                free_search_string=free_search_string,
                max_results=int(demisto.params()['max_fetch'])
            )

            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif demisto.command() == 'armis-search-alerts':
            severity = demisto.args().get('severity')
            if severity is not None:
                severity = severity.split(',')

            status = demisto.args().get('status')
            if status is not None:
                status = status.split(',')

            alert_type = demisto.args().get('alert_type')
            if alert_type is not None:
                alert_type = alert_type.split(',')

            alert_id = demisto.args().get('alert_id')
            time_frame = demisto.args().get('time_frame')

            return_results(search_alerts_command(client, alert_type, severity, status, alert_id, time_frame))

        elif demisto.command() == 'armis-update-alert-status':
            return_results(update_alert_status_command(client, demisto.args()['alert_id'], demisto.args()['status']))

        elif demisto.command() == 'armis-tag-device':
            return_results(tag_device_command(client, demisto.args()['device_id'], demisto.args()['tags'].split(',')))

        elif demisto.command() == 'armis-untag-device':
            return_results(untag_device_command(client, demisto.args()['device_id'], demisto.args()['tags'].split(',')))

        elif demisto.command() == 'armis-search-devices':
            risk_level = demisto.args().get('risk_level')
            if risk_level is not None:
                risk_level = risk_level.split(',')

            device_type = demisto.args().get('device_type')
            if device_type is not None:
                device_type = device_type.split(',')

            return_results(search_devices_command(client,
                                                  demisto.args().get('name'),
                                                  demisto.args().get('device_id'),
                                                  demisto.args().get('macAddres'),
                                                  risk_level,
                                                  demisto.args().get('ip_address'),
                                                  device_type,
                                                  demisto.args().get('time_frame')))

        elif demisto.command() == 'armis-search-devices-by-aql':
            return_results(search_devices_by_aql_command(client, demisto.args()['aql_string']))

        elif demisto.command() == 'armis-search-alerts-by-aql-string':
            return_results(search_alerts_by_aql_command(client, demisto.args()['aql_string']))

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
