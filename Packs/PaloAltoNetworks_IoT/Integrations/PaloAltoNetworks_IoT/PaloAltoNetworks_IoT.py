from datetime import datetime
import json
import time

import demistomock as demisto
import requests
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]

# IMPORTS


# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

# CONSTANTS
# api list size limit
PAGELENGTH = 1000


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """
    def __init__(self, base_url, tenant_id, api_timeout=60, verify=True, proxy=False, ok_codes=tuple(), headers=None):
        super().__init__(base_url, verify=verify, proxy=proxy, ok_codes=ok_codes, headers=headers)
        self.tenant_id = tenant_id
        self.api_timeout = api_timeout

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

    def list_alerts(self, stime='-1', offset=0, sortdirection='asc'):
        """
        returns alerts inventory list
        """
        data = self._http_request(
            method='GET',
            url_suffix='/alert/list',
            params={
                'customerid': self.tenant_id,
                'offset': offset,
                'pagelength': PAGELENGTH,
                'stime': stime,
                'type': 'policy_alert',
                'resolved': 'no',
                'sortfield': 'date',
                'sortdirection': sortdirection
            },
            timeout=self.api_timeout
        )
        return data['items']

    def list_vulns(self, stime='-1', offset=0):
        """
        returns vulnerability instances
        """
        data = self._http_request(
            method='GET',
            url_suffix='/vulnerability/list',
            params={
                'customerid': self.tenant_id,
                'offset': offset,
                'pagelength': PAGELENGTH,
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


def test_module(client):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    Args:
        client: IoT client

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    client.get_device("")
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
        outputs_prefix='device',
        outputs_key_field='deviceid',
        outputs=result
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
    pagelength = args.get('pagelength', '1000')
    result = client.list_devices(offset, pagelength)

    outputs = {
        'devices': result
    }

    return CommandResults(
        outputs_prefix="",
        outputs_key_field="",
        outputs=outputs
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
    stime = args.get('stime', '-1')
    offset = args.get('offset', 0)
    result = client.list_alerts(stime, offset, 'desc')

    outputs = {
        'alerts': result
    }

    return CommandResults(
        outputs_prefix="",
        outputs_key_field="",
        outputs=outputs
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
    stime = args.get('stime', '-1')
    offset = args.get('offset', 0)
    result = client.list_vulns(stime, offset)

    outputs = {
        'vulns': result
    }

    return CommandResults(
        outputs_prefix="",
        outputs_key_field="",
        outputs=outputs
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

    result = client.resolve_alert(alert_id, reason, reason_type)

    return CommandResults(
        outputs_prefix="",
        outputs_key_field="",
        outputs=result
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

    result = client.resolve_vuln(vuln_id, full_name, reason)

    return CommandResults(
        outputs_prefix="",
        outputs_key_field="",
        outputs=result
    )


def fetch_incidents(client, last_run):
    """
    This function will execute each interval (default is 1 minute).

    Args:
        client (Client): HelloWorld client
        last_run: The greatest incident date we fetched from last fetch

    Returns:
        next_run: This will be last_run in the next fetch-incidents
        incidents: Incidents that will be created in Demisto
    """
    # Get the last fetch time, if exists
    last_alerts_fetch = last_run.get('last_alerts_fetch')
    last_vulns_fetch = last_run.get('last_vulns_fetch')

    incidents = []

    if demisto.params().get('fetch_alerts', True):
        stime = '-1'
        if last_alerts_fetch is not None:
            # need to add 1ms for the stime
            stime = datetime.utcfromtimestamp(last_alerts_fetch + 0.001).isoformat() + "Z"

        alerts = client.list_alerts(stime)

        # special handling for the case of having more than the pagelength
        if len(alerts) == PAGELENGTH:
            # get the last date
            last_date = alerts[-1]['date']
            offset = 0
            done = False
            while not done:
                offset += PAGELENGTH
                others = client.list_alerts(stime, offset)
                for alert in others:
                    if alert['date'] == last_date:
                        alerts.append(alert)
                    else:
                        done = True
                        break
                if len(others) != PAGELENGTH:
                    break

        for alert in alerts:
            alert_date_epoch = (
                datetime.strptime(alert['date'], "%Y-%m-%dT%H:%M:%S.%fZ") - datetime(1970, 1, 1)).total_seconds()
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
        stime = '-1'
        if last_vulns_fetch is not None:
            # need to add 1ms for the stime
            stime = datetime.utcfromtimestamp(last_vulns_fetch + 0.001).isoformat() + "Z"

        vulns = client.list_vulns(stime)

        # special handling for the case of having more than the pagelength
        if len(vulns) == PAGELENGTH:
            # get the last date
            last_date = vulns[-1]['detected_date']
            offset = 0
            done = False
            while not done:
                offset += PAGELENGTH
                others = client.list_vulns(stime, offset)
                for vuln in others:
                    if vuln['detected_date'] == last_date:
                        vulns.append(vuln)
                    else:
                        done = True
                        break
                if len(others) != PAGELENGTH:
                    break

        for vuln in vulns:
            vuln_date_epoch = (
                datetime.strptime(vuln['detected_date'], "%Y-%m-%dT%H:%M:%S.%fZ") - datetime(1970, 1, 1)).total_seconds()
            vuln_name_encoded = vuln['vulnerability_name'].replace(' ', '+')
            incident = {
                'name': vuln['name'],
                "type": "IoT Vulnerability",
                'occurred': vuln['detected_date'],
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
    return next_run, incidents


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    tenant_id = demisto.params()['tenant_id']
    access_key_id = demisto.params()['access_key_id']
    secret_access_key = demisto.params()['secret_access_key']
    api_timeout = int(demisto.params().get('api_timeout', '60'))

    # get the service API url
    base_url = urljoin(demisto.params()['url'], '/pub/v4.0')

    verify_certificate = not demisto.params().get('insecure', False)

    proxy = demisto.params().get('proxy', False)

    LOG(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            base_url=base_url,
            tenant_id=tenant_id,
            api_timeout=api_timeout,
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

            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif demisto.command() == 'iot-get-device':
            return_results(iot_get_device(client, demisto.args()))

        elif demisto.command() == 'iot-list-devices':
            return_results(iot_list_devices(client, demisto.args()))

        elif demisto.command() == 'iot-list-alerts':
            return_results(iot_list_alerts(client, demisto.args()))

        elif demisto.command() == 'iot-list-vulns':
            return_results(iot_list_vulns(client, demisto.args()))

        elif demisto.command() == 'iot-resolve-alert':
            return_results(iot_resolve_alert(client, demisto.args()))

        elif demisto.command() == 'iot-resolve-vuln':
            return_results(iot_resolve_vuln(client, demisto.args()))

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
