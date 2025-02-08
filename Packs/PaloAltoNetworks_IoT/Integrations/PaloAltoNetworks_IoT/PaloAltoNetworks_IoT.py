import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import dateparser
from datetime import datetime, UTC
import json
import time
from typing import Any

import urllib3
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]

# IMPORTS


# Disable insecure warnings
urllib3.disable_warnings()

# CONSTANTS
# api list size limit
PAGELENGTH = 100


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(self, base_url, tenant_id, first_fetch='-1', max_fetch=10, api_timeout=60, verify=True, proxy=False,
                 ok_codes=(), headers=None):
        super().__init__(base_url, verify=verify, proxy=proxy, ok_codes=ok_codes, headers=headers)
        self.tenant_id = tenant_id
        self.api_timeout = api_timeout
        self.first_fetch = first_fetch
        self.max_fetch = min(max_fetch, PAGELENGTH)

    def _http_request(self, **kwargs):  # type: ignore[override]
        try:
            return super()._http_request(**kwargs)
        except DemistoException as error:
            error_message = error.args[0]
            if '[404]' in error_message:
                ind = error_message.find('Not Found')
                new_message = error_message[:ind] + '\nValidate your server url address'
                raise DemistoException(new_message)
            elif '[403]' in error_message:
                ind = error_message.find('Forbidden')
                new_message = error_message[:ind] + '\nValidate your Tenant ID, Access Key ID or Secret Access Key '
                raise DemistoException(new_message)
            else:
                raise error

    def get_device(self, id):
        """
        Get a device from IoT security portal by device ID
        """
        return self._http_request(
            method='GET',
            url_suffix='/device',
            params={
                'customerid': self.tenant_id,
                'deviceid': id
            },
            timeout=self.api_timeout
        )

    def get_device_by_ip(self, ip):
        """
        Get a device from IoT security portal by ip
        """
        return self._http_request(
            method='GET',
            url_suffix='/device/ip',
            params={
                'customerid': self.tenant_id,
                'ip': ip
            },
            timeout=self.api_timeout
        )

    def list_alerts(self, stime='-1', offset=0, pagelength=100, sortdirection='asc'):
        """
        returns alerts inventory list
        """
        data = self._http_request(
            method='GET',
            url_suffix='/alert/list',
            params={
                'customerid': self.tenant_id,
                'offset': offset,
                'pagelength': pagelength,
                'stime': stime,
                'type': 'policy_alert',
                'resolved': 'no',
                'sortfield': 'date',
                'sortdirection': sortdirection
            },
            timeout=self.api_timeout
        )
        return data['items']

    def list_vulns(self, stime='-1', offset=0, pagelength=100):
        """
        returns vulnerability instances
        """
        data = self._http_request(
            method='GET',
            url_suffix='/vulnerability/list',
            params={
                'customerid': self.tenant_id,
                'offset': offset,
                'pagelength': pagelength,
                'stime': stime,
                'type': 'vulnerability',
                'status': 'Confirmed',
                'groupby': 'device'
            },
            timeout=self.api_timeout
        )
        return data['items']

    def list_devices(self, offset, pagelength):
        """
        returns a list of devices
        """
        data = self._http_request(
            method='GET',
            url_suffix='/device/list',
            params={
                'customerid': self.tenant_id,
                'filter_monitored': 'no',
                'offset': offset,
                'pagelength': pagelength,
                'stime': '%sZ' % datetime.utcfromtimestamp(int(time.time()) - 2592000).isoformat(),
                'detail': 'true',
                'sortfield': 'MAC',
                'sortdirection': 'asc'
            },
            timeout=self.api_timeout
        )
        return data['devices']

    def resolve_alert(self, alert_id, reason, reason_type="No Action Needed"):
        """
        resolve an IoT alert
        """
        return self._http_request(
            method='PUT',
            url_suffix='/alert/update',
            params={
                'customerid': self.tenant_id,
                'id': alert_id
            },
            json_data={
                'resolved': 'yes',
                'reason': reason,
                'reason_type': [reason_type]
            },
            timeout=self.api_timeout
        )

    def resolve_vuln(self, vuln_id, full_name, reason):
        """
        resolve an IoT vulnerability
        """
        return self._http_request(
            method='PUT',
            url_suffix='/vulnerability/update',
            params={
                'customerid': self.tenant_id
            },
            json_data={
                'action': 'mitigate',
                'full_name': full_name,
                'reason': reason,
                'ticketIdList': [vuln_id]
            },
            timeout=self.api_timeout
        )


def arg_to_timestamp(arg: Any, arg_name: str, required: bool = False) -> int | None:
    """Converts an XSOAR argument to a timestamp (seconds from epoch)

    This function is used to quickly validate an argument provided to XSOAR
    via ``demisto.args()`` into an ``int`` containing a timestamp (seconds
    since epoch). It will throw a ValueError if the input is invalid.
    If the input is None, it will throw a ValueError if required is ``True``,
    or ``None`` if required is ``False.

    :type arg: ``Any``
    :param arg: argument to convert

    :type arg_name: ``str``
    :param arg_name: argument name

    :type required: ``bool``
    :param required:
        throws exception if ``True`` and argument provided is None

    :return:
        returns an ``int`` containing a timestamp (seconds from epoch) if conversion works
        returns ``None`` if arg is ``None`` and required is set to ``False``
        otherwise throws an Exception
    :rtype: ``Optional[int]``
    """
    if arg is None:
        if required is True:
            raise ValueError(f'Missing "{arg_name}"')
        return None

    if isinstance(arg, str) and arg.isdigit():
        # timestamp is a str containing digits - we just convert it to int
        return int(arg)
    if isinstance(arg, str):
        # we use dateparser to handle strings either in ISO8601 format, or
        # relative time stamps.
        # For example: format 2019-10-23T00:00:00 or "3 days", etc
        date = dateparser.parse(arg, settings={'TIMEZONE': 'UTC'})
        if date is None:
            # if d is None it means dateparser failed to parse it
            raise ValueError(f'Invalid date: {arg}')

        return int(date.replace(tzinfo=UTC).timestamp())
    if isinstance(arg, int | float):
        # Convert to int if the input is a float
        return int(arg)
    raise ValueError(f'Invalid date: "{arg}"')


def test_module(client):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client: IoT client

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    if demisto.params().get('isFetch'):
        fetch_incidents(client, last_run=demisto.getLastRun(), is_test=True)
    else:
        client.list_devices(0, 1)
    return 'ok'


def iot_get_device(client, args):
    """
    Returns an IoT device

    Args:
        client (Client): IoT client.
        args (dict): all command arguments.

    Returns:
        device

        CommandResults
    """
    device_id = args.get('id')

    result = client.get_device(device_id)

    return CommandResults(
        outputs_prefix='PaloAltoNetworksIoT.Device',
        outputs_key_field='deviceid',
        outputs=result
    )


def iot_get_device_by_ip(client, args):
    """
    Returns an IoT device

    Args:
        client (Client): IoT client.
        args (dict): all command arguments.

    Returns:
        device

        CommandResults
    """
    device_ip = args.get('ip')

    result = client.get_device_by_ip(device_ip)

    return CommandResults(
        outputs_prefix='PaloAltoNetworksIoT.Device',
        outputs_key_field='devices',
        outputs=result['devices']
    )


def iot_list_devices(client, args):
    """
    Returns a list of IoT devices

    Args:
        client (Client): IoT client.
        args (dict): all command arguments.

    Returns:
        List of devices

        CommandResults
    """
    offset = args.get('offset', '0')
    pagelength = args.get('limit', client.max_fetch)
    result = client.list_devices(offset, pagelength)

    if not result:
        return CommandResults(
            readable_output='### No devices found'
        )

    return CommandResults(
        outputs_prefix="PaloAltoNetworksIoT.DeviceList",
        outputs_key_field='deviceid',
        outputs=result
    )


def iot_list_alerts(client, args):
    """
    Returns a list of IoT alerts (max: 1000)

    Args:
        client (Client): IoT client.
        args (dict): all command arguments.

    Returns:
        List of alerts

        CommandResults
    """
    stime = args.get('start_time', '-1')
    offset = args.get('offset', 0)
    pagelength = min(int(args.get('limit', client.max_fetch)), PAGELENGTH)
    result = client.list_alerts(stime, offset, pagelength, 'desc')

    if not result:
        return CommandResults(
            readable_output='### No alerts found'
        )

    return CommandResults(
        outputs_prefix="PaloAltoNetworksIoT.Alerts",
        outputs_key_field="id",
        outputs=result
    )


def iot_list_vulns(client, args):
    """
    Returns a list of IoT vulnerabilties (max: 1000)

    Args:
        client (Client): IoT client.
        args (dict): all command arguments.

    Returns:
        List of vulnerabilties

        CommandResults
    """
    stime = args.get('start_time', '-1')
    offset = args.get('offset', 0)
    pagelength = min(int(args.get('limit', client.max_fetch)), PAGELENGTH)
    result = client.list_vulns(stime, offset, pagelength)

    if not result:
        return CommandResults(
            readable_output='### No vulnerabilities found'
        )

    return CommandResults(
        outputs_prefix="PaloAltoNetworksIoT.Vulns",
        outputs_key_field="zb_ticketid",
        outputs=result
    )


def iot_resolve_alert(client, args):
    """
    Resolve an IoT alert

    Args:
        client (Client): IoT client.
        args (dict): all command arguments.

    Returns:
        None in CommandResults
    """
    alert_id = args.get('id')
    reason = args.get('reason', 'resolved by XSOAR')
    reason_type = args.get('reason_type', 'No Action Needed')

    client.resolve_alert(alert_id, reason, reason_type)

    return CommandResults(
        readable_output=f'Alert {alert_id} was resolved successfully'
    )


def iot_resolve_vuln(client, args):
    """
    Resolve an IoT vulnerability

    Args:
        client (Client): IoT client.
        args (dict): all command arguments.

    Returns:
        None in CommandResults
    """
    vuln_id = args.get('id')
    full_name = args.get('full_name')
    reason = args.get('reason', 'resolved by XSOAR')

    client.resolve_vuln(vuln_id, full_name, reason)

    return CommandResults(
        readable_output=f'Vulnerability {vuln_id} was resolved successfully'
    )


def fetch_incidents(client, last_run, is_test=False):
    """
    This function will execute each interval (default is 1 minute).

    Args:
        client (Client): IoT client
        last_run: last_run dict containing the timestamps of the latest incident we fetched from previous fetch

    Returns:
        next_run: This will be last_run in the next fetch-incidents
        incidents: Incidents that will be created in Demisto
    """
    demisto.debug("PaloAltoNetworks_IoT - Start fetching")
    demisto.debug(f"PaloAltoNetworks_IoT - Last run: {json.dumps(last_run)}")
    # Get the last fetch time, if exists
    last_alerts_fetch = last_run.get('last_alerts_fetch')
    last_vulns_fetch = last_run.get('last_vulns_fetch')
    max_fetch = client.max_fetch

    incidents = []

    if demisto.params().get('fetch_alerts', True):
        stime = client.first_fetch
        if last_alerts_fetch is not None:
            # need to add 1ms for the stime
            stime = datetime.utcfromtimestamp(last_alerts_fetch + 0.001).isoformat() + "Z"

        alerts = client.list_alerts(stime, pagelength=max_fetch)
        demisto.debug(f"PaloAltoNetworks_IoT - Number of incidents- alerts before filtering: {len(alerts)}")

        # special handling for the case of having more than the pagelength
        if len(alerts) == max_fetch:
            # get the last date
            last_date = alerts[-1]['date']
            offset = 0
            done = False
            while not done:
                offset += max_fetch
                others = client.list_alerts(stime, offset, pagelength=max_fetch)
                for alert in others:
                    if alert['date'] == last_date:
                        alerts.append(alert)
                    else:
                        done = True
                        break
                if len(others) != max_fetch:
                    break

        for alert in alerts:
            alert_date_epoch = datetime.strptime(
                alert['date'], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC).timestamp()
            alert_id = alert["zb_ticketid"].replace("alert-", "")
            incident = {
                'name': alert['name'],
                "type": "IoT Alert",
                'occurred': alert['date'],
                'rawJSON': json.dumps(alert),
                'details': alert['description'] if 'description' in alert else '',
                'CustomFields': {
                    'iotincidenturl': f'{demisto.params()["url"]}/guardian/policies/alert?id={alert_id}'
                }
            }
            incidents.append(incident)

            # Update last run and add incident if the incident is newer than last fetch
            if last_alerts_fetch is None or alert_date_epoch > last_alerts_fetch:
                last_alerts_fetch = alert_date_epoch

    if demisto.params().get('fetch_vulns', True):
        stime = client.first_fetch
        if last_vulns_fetch is not None:
            # need to add 1ms for the stime
            stime = datetime.utcfromtimestamp(last_vulns_fetch + 0.001).isoformat() + "Z"

        vulns = client.list_vulns(stime, pagelength=max_fetch)

        # special handling for the case of having more than the pagelength
        if len(vulns) == max_fetch:
            # get the last date
            last_date = vulns[-1]['detected_date']
            if last_date and isinstance(last_date, list):
                last_date = last_date[0]

            offset = 0
            done = False
            while not done:
                offset += max_fetch
                others = client.list_vulns(stime, offset, pagelength=max_fetch)
                for vuln in others:
                    detected_date = vuln['detected_date']
                    if detected_date and isinstance(detected_date, list):
                        detected_date = detected_date[0]

                    if detected_date == last_date:
                        vulns.append(vuln)
                    else:
                        done = True
                        break
                if len(others) != max_fetch:
                    break
        demisto.debug(f"PaloAltoNetworks_IoT - Number of incidents- vulnerability before filtering: {len(vulns)}")
        for vuln in vulns:
            detected_date = vuln['detected_date']
            if detected_date and isinstance(detected_date, list):
                detected_date = detected_date[0]

            vuln_date_epoch = datetime.strptime(
                detected_date, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC).timestamp()
            vuln_name_encoded = vuln['vulnerability_name'].replace(' ', '+')
            incident = {
                'name': vuln['name'],
                "type": "IoT Vulnerability",
                'occurred': detected_date,
                'rawJSON': json.dumps(vuln),
                'details': f'Device {vuln["name"]} at IP {vuln["ip"]}: {vuln["vulnerability_name"]}',
                'CustomFields': {
                    'iotincidenturl': f'{demisto.params()["url"]}/guardian/monitor/inventory/device/'
                                      f'{vuln["deviceid"]}?index=0&vuln=true&vulname={vuln_name_encoded}'
                }
            }
            incidents.append(incident)

            if last_vulns_fetch is None or vuln_date_epoch > last_vulns_fetch:
                last_vulns_fetch = vuln_date_epoch

    next_run = {
        'last_alerts_fetch': last_alerts_fetch,
        'last_vulns_fetch': last_vulns_fetch
    }
    demisto.debug(f"PaloAltoNetworks_IoT - Number of incidents (alerts and vulnerability) after filtering : {len(incidents)}")
    demisto.debug(f'PaloAltoNetworks_IoT - Next run after incidents fetching: {json.dumps(next_run)}')

    if is_test:
        return None, None

    return next_run, incidents


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    tenant_id = demisto.params()['tenant_id']
    access_key_id = demisto.params().get('credentials', {}).get('identifier') or demisto.params().get('access_key_id')
    secret_access_key = demisto.params().get('credentials', {}).get('password') or demisto.params().get('secret_access_key')

    api_timeout = 60
    try:
        api_timeout = int(demisto.params().get('api_timeout', '60'))
    except ValueError:
        return_error('API timeout needs to be an integer')

    first_fetch = '-1'
    try:
        ff = arg_to_timestamp(
            arg=demisto.params().get('first_fetch'),
            arg_name='First fetch time',
            required=False
        )
        if ff:
            first_fetch = datetime.fromtimestamp(ff).astimezone(UTC).strftime('%Y-%m-%dT%H:%M:%SZ')
    except ValueError as e:
        return_error(f'First fetch time is in a wrong format. Error: {str(e)}')

    max_fetch = 10
    try:
        max_fetch = int(demisto.params().get('max_fetch', '10'))
    except ValueError:
        return_error('Maximum number of incidents per fetch needs to be an integer')

    # get the service API url
    base_url = urljoin(demisto.params()['url'], '/pub/v4.0')

    verify_certificate = not demisto.params().get('insecure', False)

    proxy = demisto.params().get('proxy', False)

    demisto.info(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=base_url,
            tenant_id=tenant_id,
            api_timeout=api_timeout,
            first_fetch=first_fetch,
            max_fetch=max_fetch,
            verify=verify_certificate,
            proxy=proxy,
            ok_codes=(200,),
            headers={
                'X-Key-Id': access_key_id,
                'X-Access-Key': secret_access_key
            })

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)

        elif demisto.command() == 'fetch-incidents':
            # Set and define the fetch incidents command to run after activated via integration settings.
            next_run, incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun())

            if next_run is not None:
                demisto.setLastRun(next_run)

            if incidents is not None:
                demisto.incidents(incidents)

        elif demisto.command() == 'iot-security-get-device':
            return_results(iot_get_device(client, demisto.args()))

        elif demisto.command() == 'iot-security-get-device-by-ip':
            return_results(iot_get_device_by_ip(client, demisto.args()))

        elif demisto.command() == 'iot-security-list-devices':
            return_results(iot_list_devices(client, demisto.args()))

        elif demisto.command() == 'iot-security-list-alerts':
            return_results(iot_list_alerts(client, demisto.args()))

        elif demisto.command() == 'iot-security-list-vulns':
            return_results(iot_list_vulns(client, demisto.args()))

        elif demisto.command() == 'iot-security-resolve-alert':
            return_results(iot_resolve_alert(client, demisto.args()))

        elif demisto.command() == 'iot-security-resolve-vuln':
            return_results(iot_resolve_vuln(client, demisto.args()))

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
