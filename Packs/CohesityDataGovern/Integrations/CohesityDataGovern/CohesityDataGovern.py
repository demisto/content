"""Cohesity Data governance Integration for Cortex XSOAR (aka Demisto)

This is an empty Integration with some basic structure according
to the code conventions.

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

This is an empty structure file. Check an example at;
https://github.com/demisto/content/blob/master/Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.py

"""

from datetime import datetime, timedelta
import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
from typing import Dict, Any

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


''' CONSTANTS '''

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

    # Helper functions to interact with helios services.
    def get_was_alerts(self, startTimeMillis, endTimeMillis) -> Dict[str, Any]:
        """Gets the Wide Access Shield Alerts.

        :return: dict containing the Wide Access Shields alerts
        returned from the API
        :rtype: ``Dict[str, Any]``
        """
        return self._http_request(
            method='GET',
            url_suffix='/mcm/argus/api/v1/public/shields/WIDE_ACCESS/incidences',
            params={
                "startTimeMsecs": startTimeMillis,
                "endTimeMsecs": endTimeMillis
            }
        )

    def get_ransomware_alerts(self, nHours: int) -> Dict[str, Any]:
        """Gets the Cohesity ransomware alerts.
        """
        return self._http_request(
            method='GET',
            url_suffix='/mcm/alerts',
            params={
                "maxAlerts": 1000,
                "alertCategoryList": "kSecurity",
                "alertStateList": "kOpen",
                "_includeTenantInfo": True,
                "startDateUsecs": get_nHour_prev_date_time(nHours)
            }
        )


''' HELPER FUNCTIONS '''


def get_date_time_from_millis(time_in_millis):
    dt = datetime.fromtimestamp(time_in_millis / 1000.0)
    return dt.strftime("%m/%d/%Y, %H:%M:%S")


def get_current_date_time():
    dt = datetime.now()
    return int(dt.timestamp() * 1000)


def get_nHour_prev_date_time(nHours: int):
    dt = datetime.now() - timedelta(hours=nHours)
    return int(dt.timestamp() * 1000)


''' COMMAND FUNCTIONS '''


def get_was_alerts_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """get_was_alerts command: Returns Wide Access Sheild Alerts.

    :type client: ``Client``
    :param Client: CohesityDataGovern client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains Wide Access Shield Alerts.

    :rtype: ``CommandResults``
    """
    nHours = int(args.get('num_hours', "168"))

    # Fetch was alerts since last nHours.
    startTimeMillis = get_nHour_prev_date_time(nHours)
    endTimeMillis = get_current_date_time()
    resp = client.get_was_alerts(startTimeMillis, endTimeMillis)

    # Parse alerts for readable_output.
    raw_incidences = resp.get('incidences', {})
    incidences_list = []

    for raw_incidence in raw_incidences:
        incidence = {
            "id": raw_incidence.get("id"),
            "incidenceTime": get_date_time_from_millis(
                raw_incidence.get("incidenceTimeMsecs")),
            "ruleID": raw_incidence.get("ruleId")
        }
        incidences_list.append(incidence)

    md = tableToMarkdown('Alerts', incidences_list, ["id", "incidence time", "ruleID"])

    # return results.
    return CommandResults(
        readable_output=md,
        outputs_prefix='CohesityDataGovern.WASAlert',
        outputs_key_field='id',
        outputs=incidences_list,
    )


def get_ransomware_alerts_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Get_ransomware_alerts_command: Returns ransomware alerts detected
        in last n hours.
    """
    nHours = int(args.get('num_hours', "168"))
    resp = client.get_ransomware_alerts(nHours)

    # CohesityTBD: Parse alert response.
    return CommandResults(
        outputs_prefix='CohesityDataGovern.RansomwareAlert',
        outputs_key_field='alert_id',
        outputs=resp,
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

    message: str = ''
    try:
        client.get_was_alerts(1631471400000, 1632076199999)
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message

# TODO: ADD additional command functions that translate XSOAR inputs/outputs to Client


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    # Get API key for authentication.
    api_key = demisto.params().get('apikey')

    # Get helios service API url.
    base_url = demisto.params()['url']

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not demisto.params().get('insecure', False)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = demisto.params().get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        # Prepare client and set authentication headers.
        headers: Dict = {
            'apikey': api_key
        }
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif demisto.command() == 'cohesity-get-was-alerts':
            return_results(get_was_alerts_command(client, demisto.args()))

        elif demisto.command() == 'cohesity-get-ransomware-alerts':
            return_results(get_ransomware_alerts_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
