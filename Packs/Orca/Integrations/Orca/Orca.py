import dateutil.parser

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from typing import Any, Dict, Union, Optional

ORCA_API_DNS_NAME = "https://api.orcasecurity.io/api"

DEMISTO_OCCURRED_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
DEMISTO_INFORMATIONAL = 0.5


class OrcaClient:
    def __init__(self, client: BaseClient):
        self.client = client

    def validate_api_key(self) -> str:
        demisto.info("validate_api_key, enter")
        invalid_token_string = "Test failed becasue the Orca API key that was entered is invalid, please provide a valid API key"
        try:
            response = self.client._http_request(method="GET", url_suffix="/user/action?")
        except Exception:
            return invalid_token_string

        if response.get("status") != "success":
            return invalid_token_string

        return "ok"

    def get_alerts_by_filter(self, alert_type: Optional[str] = None, asset_unique_id: Optional[str] = None) -> Union[  # pylint: disable=E1136 # noqa: E501
        List[Dict[str, Any]], str]:  # pylint: disable=E1136 # noqa: E125
        demisto.info("get_alerts_by_filter, enter")

        url_suffix = "/alerts"

        if alert_type and asset_unique_id or (not alert_type and not asset_unique_id):
            demisto.info("must supply exactly one filter")
            return "must supply exactly one filter"

        if alert_type:
            params = {"type": alert_type}

        elif asset_unique_id:
            params = {"asset_unique_id": asset_unique_id}

        response = self.client._http_request(method="GET", url_suffix=url_suffix, params=params)

        if response['status'] != 'success':
            demisto.info("bad response from Orca API")
            return response['error']

        alerts = response.get("data")

        return alerts

    def get_all_alerts(self, first_fetch: Optional[str], fetch_informational: bool = False) -> List[Dict[str, Any]]:  # pylint: disable=E1136 # noqa: E501
        demisto.info("get_all_alerts, enter")

        alerts: List[Dict[str, Any]] = []
        params: Dict[str, Any] = {"show_informational_alerts": True} if fetch_informational else {}
        if first_fetch:
            params["dsl_filter"] = json.dumps({
                "filter": [
                    {
                        "field": "state.created_at",
                        "range": {"gte": first_fetch}
                    }
                ]
            })
        next_page_token = None

        while True:
            if next_page_token:
                params["next_page_token"] = next_page_token

            response = self.client._http_request(method="GET", url_suffix="/query/alerts", params=params)
            if response['status'] != 'success':
                demisto.info(f"got bad response, {response['error']}")
                return response['error']

            alerts = alerts + response["data"]

            if "next_page_token" not in response:
                # that was the last chunk
                break
            else:
                next_page_token = response.get("next_page_token")

        demisto.info(f"done fetching orca alerts, fetched {len(alerts)} alerts")

        return alerts

    def get_asset(self, asset_unique_id: str) -> Union[Dict[str, Any], str]:  # pylint: disable=E1136
        demisto.debug("get_asset, enter")
        try:
            response = self.client._http_request(method="GET", url_suffix=f"/assets/{asset_unique_id}")
        except DemistoException:
            demisto.debug(f"could not find {asset_unique_id}")
            return {}

        if 'error' in response or not response:
            return "Asset Not Found"

        return response

    def get_updated_alerts(self) -> List[Dict[str, Any]]:
        demisto.info("get_kafka_alerts, enter")

        try:
            response = self.client._http_request(method="GET", url_suffix="/query/alerts/updates")
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

    demisto.info("get_incidents_from_alerts done")
    return incidents


def fetch_incidents(orca_client: OrcaClient, max_fetch: int, first_fetch_time: Optional[str],   # pylint: disable=E1136
                    fetch_informational: bool = False,
                    pull_existing_alerts: bool = False, fetch_type="XSOAR-Pull") -> List[Dict[str, Any]]:
    demisto.info(f"fetch-incidents called {max_fetch=}")

    if not pull_existing_alerts:
        demisto.info("pull_existing_alerts flag is not set, not pulling alerts")
        demisto.incidents([])
        return []

    if demisto.getLastRun().get('lastRun'):
        demisto.info("not first run, exporting reminder of alerts")
        incidents_queue = demisto.getLastRun().get('incidents_for_next_run')
        incidents_to_export = incidents_queue[:max_fetch]
        if not fetch_informational:
            incidents_to_export = [incident for incident in incidents_to_export if
                                   incident.get("severity") > DEMISTO_INFORMATIONAL]  # type: ignore

        incidents_for_next_run = incidents_queue[max_fetch:]

        if not incidents_to_export:
            # finished exporting from the queue of alerts
            incidents = []
            if fetch_type == "XSOAR-Pull":
                updated_alerts = orca_client.get_updated_alerts()
                incidents = get_incidents_from_alerts(updated_alerts)
                incidents = [incident for incident in incidents
                             if incident.get("severity") > DEMISTO_INFORMATIONAL]  # type: ignore

            demisto.incidents(incidents)
            demisto.setLastRun(
                {'lastRun': datetime.now().strftime(DEMISTO_OCCURRED_FORMAT), "incidents_for_next_run": []})

            return incidents

        else:
            # still exporting from alerts queue
            demisto.info("still exporting from alerts queue")
            demisto.incidents(incidents_to_export)
            demisto.setLastRun({'lastRun': datetime.now().strftime(DEMISTO_OCCURRED_FORMAT),
                                "incidents_for_next_run": incidents_for_next_run})
            return []

    else:
        # this is the first run
        alerts = orca_client.get_all_alerts(fetch_informational=fetch_informational, first_fetch=first_fetch_time)
        if not alerts:
            demisto.incidents([])
            return []

        incidents = get_incidents_from_alerts(alerts)
        demisto.incidents(incidents[:max_fetch])
        demisto.setLastRun(
            {'lastRun': datetime.now().strftime(DEMISTO_OCCURRED_FORMAT),
             "incidents_for_next_run": incidents[max_fetch:]})
        return incidents


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    try:
        command = demisto.command()
        demisto.debug(f'Orca Command being called is {command}')
        api_key = demisto.params().get('apikey')
        fetch_informational = demisto.params().get('fetch_informational')
        max_fetch = int(demisto.params().get('max_fetch'))
        pull_existing_alerts = demisto.params().get('pull_existing_alerts')
        fetch_type = demisto.params().get('fetch_type')

        # How much time before the first fetch to retrieve incidents
        first_fetch_time = None
        if arg := demisto.params().get('first_fetch'):
            first_fetch_time_stamp = dateparser.parse(arg)
            if first_fetch_time_stamp:
                first_fetch_time = first_fetch_time_stamp.isoformat()

        client = BaseClient(
            base_url=ORCA_API_DNS_NAME,
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
            alerts = orca_client.get_alerts_by_filter(alert_type=alert_type, asset_unique_id=asset_unique_id)
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
            fetch_incidents(orca_client, max_fetch=max_fetch, fetch_informational=fetch_informational,
                            pull_existing_alerts=pull_existing_alerts, fetch_type=fetch_type,
                            first_fetch_time=first_fetch_time)

        elif command == "test-module":
            test_res = orca_client.validate_api_key()
            return_results(test_res)

        else:
            raise NotImplementedError(f'{command} is not an existing orca command')
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
