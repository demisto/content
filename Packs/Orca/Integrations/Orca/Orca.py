import dateutil.parser

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from typing import Any, Dict, Union, Optional, Tuple

DEMISTO_OCCURRED_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
DEMISTO_INFORMATIONAL = 0.5
ORCA_API_TIMEOUT = 30  # Increase timeout for ORCA API
ORCA_API_LIMIT = 500  # limit number of returned records from ORCA API


class OrcaClient:
    def __init__(self, client: BaseClient):
        self.client = client

    def validate_api_key(self) -> str:
        demisto.info("validate_api_key, enter")
        invalid_token_string = "Test failed becasue the Orca API key that was entered is invalid, please provide a valid API key"
        try:
            response = self.client._http_request(method="GET", url_suffix="/user/action?", timeout=ORCA_API_TIMEOUT)
        except Exception:
            return invalid_token_string

        if response.get("status") != "success":
            return invalid_token_string

        return "ok"

    def get_alerts_by_filter(
            self,
            alert_type: Optional[str] = None,
            asset_unique_id: Optional[str] = None,
            limit: int = 1000
    ) -> Union[  # pylint: disable=E1136 # noqa: E501
        List[Dict[str, Any]], str]:  # pylint: disable=E1136 # noqa: E125
        demisto.info("get_alerts_by_filter, enter")

        url_suffix = "/alerts"

        if alert_type and asset_unique_id or (not alert_type and not asset_unique_id):
            demisto.info("must supply exactly one filter")
            return "must supply exactly one filter"

        params = {}
        if alert_type:
            params = {"type": alert_type}
        elif asset_unique_id:
            params = {"asset_unique_id": asset_unique_id}

        params["limit"] = str(limit)

        try:
            response = self.client._http_request(method="GET", url_suffix=url_suffix, params=params,
                                                 timeout=ORCA_API_TIMEOUT)
            if response['status'] != 'success':
                demisto.info("bad response from Orca API")
                return response['error']

            alerts = response.get("data")
            return alerts
        except requests.exceptions.ReadTimeout as e:
            demisto.info(f"Alerts Request ReadTimeout error: {str(e)}")
            return []

    def get_alerts(
            self,
            first_fetch: Optional[str],
            fetch_informational: bool = False,
            next_page_token: Optional[str] = None,
            limit: int = 1000
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        demisto.info("Get alerts, enter")
        alerts: List[Dict[str, Any]] = []
        params: Dict[str, Any] = {"show_informational_alerts": True} if fetch_informational else {}
        params["limit"] = limit

        if first_fetch:
            params["dsl_filter"] = json.dumps({
                "filter": [
                    {
                        "field": "state.created_at",
                        "range": {"gte": first_fetch}
                    }
                ]
            })

        if next_page_token:
            params['next_page_token'] = next_page_token

        try:
            response = self.client._http_request(method="GET", url_suffix="/query/alerts", params=params,
                                                 timeout=ORCA_API_TIMEOUT)
            if response['status'] != 'success':
                demisto.info(f"got bad response, {response['error']}")
            else:
                alerts = response.get("data")
                next_page_token = response.get("next_page_token")

        except requests.exceptions.ReadTimeout as e:
            demisto.info(f"Alerts Request ReadTimeout error: {str(e)}")

        demisto.info(f"done fetching orca alerts, fetched {len(alerts)} alerts.")
        if next_page_token:
            demisto.info("not the last page")
        else:
            demisto.info("the last page fetched")
        return alerts, next_page_token

    def get_asset(self, asset_unique_id: str) -> Union[Dict[str, Any], str]:  # pylint: disable=E1136
        demisto.debug("get_asset, enter")
        try:
            response = self.client._http_request(method="GET", url_suffix=f"/assets/{asset_unique_id}",
                                                 timeout=ORCA_API_TIMEOUT)
        except DemistoException:
            demisto.debug(f"could not find {asset_unique_id}")
            return {}
        except requests.exceptions.ReadTimeout as e:
            demisto.info(f"Assets Request ReadTimeout error: {str(e)}")
            return {}

        if 'error' in response or not response:
            return "Asset Not Found"

        return response

    def get_updated_alerts(self) -> List[Dict[str, Any]]:
        """ Updated can't contains more than 200 alerts. Incidents can be imported in one step """
        demisto.info("get_kafka_alerts, enter")

        try:
            response = self.client._http_request(method="GET", url_suffix="/query/alerts/updates",
                                                 timeout=ORCA_API_TIMEOUT)
            if response['status'] != 'success':
                demisto.info(f"got bad response, {response['error']}")
                return []

            return response['data']

        except Exception as e:
            demisto.info(f"got Exception while getting updated alerts, {(str(e))}")
            return []


def map_orca_score_to_demisto_score(orca_score: int) -> Union[int, float]:  # pylint: disable=E1136
    # demisto_unknown = 0  (commented because of linter issues)
    demisto_informational = 0.5
    # demisto_low = 1  (commented because of linter issues)
    demisto_medium = 2
    demisto_high = 3
    demisto_critical = 4

    # LHS is Orca score
    MAPPING = {1: demisto_critical, 2: demisto_high, 3: demisto_medium, 4: demisto_informational}

    return MAPPING[orca_score]


def get_incident_from_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    if alert is None:
        return {}

    last_seen_time = dateutil.parser.parse(alert.get('state', {}).get('last_seen')).isoformat()
    return {
        'name': alert.get('state', {}).get('alert_id'),
        'occurred': last_seen_time,
        'rawJSON': json.dumps(alert),
        'severity': map_orca_score_to_demisto_score(orca_score=alert.get('state', {}).get('score'))
    }


def get_incidents_from_alerts(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    demisto.info("get_incidents_from_alerts enter")
    incidents = []
    for alert in alerts:
        alert['demisto_score'] = map_orca_score_to_demisto_score(orca_score=alert.get("state", {}).get("score", 1))
        incident = get_incident_from_alert(alert=alert)
        incidents.append(incident)

    demisto.info(f"get_incidents_from_alerts: Got {len(incidents)} incidents")
    return incidents


def fetch_incidents(
        orca_client: OrcaClient,
        last_run: Dict[str, Any],
        max_fetch: int,
        first_fetch_time: Optional[str],  # pylint: disable=E1136
        fetch_informational: bool = False,
        pull_existing_alerts: bool = False,
        fetch_type: str = "XSOAR-Pull"
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    demisto.info(f"fetch-incidents called {max_fetch=}")

    last_run_time = last_run.get("lastRun")
    next_page_token = last_run.get("next_page_token")

    if last_run_time and not next_page_token:
        # Not need to store incidents in to queue
        demisto.info("not first run, exporting reminder of alerts")
        incidents = []
        if fetch_type == "XSOAR-Pull":
            updated_alerts = orca_client.get_updated_alerts()
            incidents = get_incidents_from_alerts(updated_alerts)
            incidents = [incident for incident in incidents
                         if incident.get("severity") > DEMISTO_INFORMATIONAL]  # type: ignore

        next_run = {'lastRun': datetime.now().strftime(DEMISTO_OCCURRED_FORMAT)}
        return next_run, incidents
    else:
        if not pull_existing_alerts:
            demisto.info("pull_existing_alerts flag is not set, not pulling alerts")
            return {'lastRun': datetime.now().strftime(DEMISTO_OCCURRED_FORMAT)}, []

        # Initial export flow
        # Fetch and import alerts per page.
        # Loading all alerts consumes a lot of RAM.
        demisto.info("first run. export of existing alerts")
        alerts, next_page_token = orca_client.get_alerts(
            fetch_informational=fetch_informational,
            first_fetch=first_fetch_time,
            next_page_token=next_page_token,
            limit=max_fetch
        )
        if not alerts:
            # Nothing to export
            demisto.incidents([])
            return {}, []

        incidents = get_incidents_from_alerts(alerts)
        next_run = {
            "lastRun": datetime.now().strftime(DEMISTO_OCCURRED_FORMAT),
        }
        if next_page_token:
            next_run['next_page_token'] = next_page_token
        return next_run, incidents


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    try:
        command = demisto.command()
        demisto.debug(f'Orca Command being called is {command}')
        api_key = demisto.params().get('apikey')
        api_host = demisto.params().get('api_host')
        fetch_informational = demisto.params().get('fetch_informational')
        max_fetch = int(demisto.params().get('max_fetch', '200'))
        pull_existing_alerts = demisto.params().get('pull_existing_alerts')
        fetch_type = demisto.params().get('fetch_type')

        if max_fetch > 500:
            max_fetch = 500

        api_url = f"https://{api_host}/api"

        # How much time before the first fetch to retrieve incidents
        first_fetch_time = None
        if arg := demisto.params().get('first_fetch'):
            first_fetch_time_stamp = dateparser.parse(arg)
            if first_fetch_time_stamp:
                first_fetch_time = first_fetch_time_stamp.isoformat()

        client = BaseClient(
            base_url=api_url,
            verify=True,
            headers={
                'Authorization': f'Bearer {api_key}'
            },
            proxy=True)

        orca_client = OrcaClient(client=client)
        if command == "orca-get-alerts":
            demisto_args = demisto.args()
            alert_type = demisto_args.get('alert_type')
            asset_unique_id = demisto_args.get('asset_unique_id')
            alerts = orca_client.get_alerts_by_filter(
                alert_type=alert_type,
                asset_unique_id=asset_unique_id,
                limit=ORCA_API_LIMIT,
            )
            if isinstance(alerts, str):
                #  this means alert is an error
                command_result = CommandResults(readable_output=alerts, raw_response=alerts)
            else:
                command_result = CommandResults(outputs_prefix="Orca.Manager.Alerts", outputs=alerts,
                                                raw_response=alerts)

            return_results(command_result)

        elif command == "orca-get-asset":
            asset = orca_client.get_asset(asset_unique_id=demisto.args()['asset_unique_id'])
            command_result = CommandResults(outputs_prefix="Orca.Manager.Asset", outputs=[asset], raw_response=asset)
            return_results(command_result)

        elif command == "fetch-incidents":
            next_run, incidents = fetch_incidents(
                orca_client,
                last_run=demisto.getLastRun(),
                max_fetch=max_fetch,
                fetch_informational=fetch_informational,
                pull_existing_alerts=pull_existing_alerts,
                fetch_type=fetch_type,
                first_fetch_time=first_fetch_time
            )
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif command == "test-module":
            test_res = orca_client.validate_api_key()
            return_results(test_res)

        else:
            raise NotImplementedError(f'{command} is not an existing orca command')
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
