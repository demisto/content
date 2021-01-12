import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from typing import Any, Dict, Union, Optional

ORCA_API_DNS_NAME = "https://orcadeveden-internal-dev.orcasecurity.net/api"
DEMISTO_OCCURRED_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


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

    def get_alerts_by_filter(self, alert_type: Optional[str] = None, asset_unique_id: Optional[str] = None) -> Union[
        List[Dict[str, Any]], str]:  # pylint: disable=E1136 # noqa: E125
        demisto.info("get_alerts_by_filter, enter")

        url_suffix = "/alerts"

        if alert_type and asset_unique_id or (not alert_type and not asset_unique_id):
            demisto.info("must supply exactly one filter")
            return "must supply exactly one filter"

        if alert_type:
            # url_suffix = f"{url_suffix}?type={alert_type}"
            params = {"type": alert_type}

        elif asset_unique_id:
            params = {"asset_unique_id": asset_unique_id}

        response = self.client._http_request(method="GET", url_suffix=url_suffix, params=params)

        if response['status'] != 'success':
            demisto.info("bad response from Orca API")
            return response['error']

        alerts = response.get("data")

        return alerts

    def get_all_alerts(self) -> List[Dict[str, Any]]:
        demisto.info("get_all_alerts, enter")

        alerts: List[Dict[str, Any]] = []
        params: Dict[str, str] = {}
        next_page_token = None

        while True:
            if next_page_token:
                params = {"next_page_token": next_page_token}

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

    def get_asset(self, asset_unique_id: str) -> Union[List[Dict[str, Any]], str]:  # pylint: disable=E1136
        demisto.debug("get_asset, enter")
        try:
            response = self.client._http_request(method="GET", url_suffix=f"/assets/{asset_unique_id}")
        except DemistoException:
            return f"could not find {asset_unique_id}"

        if 'error' in response or not response:
            return "Asset Not Found"

        return response


def map_orca_score_to_demisto_score(orca_score: int) -> int:
    MAPPING = {1: 1, 2: 1, 3: 2, 4: 3}
    return MAPPING[orca_score]


def fetch_incidents(orca_client: OrcaClient) -> List[Dict[str, Any]]:
    demisto.debug("fetch-incidents called")
    if demisto.getLastRun().get('lastRun'):
        demisto.info("not first run, returning")
        # only first run is relevant, other incidents are dynamically pushed from Kafka
        demisto.incidents([])
        return []

    alerts = orca_client.get_all_alerts()
    if not alerts:
        demisto.incidents([])
        return []

    incidents = []
    for alert in alerts:
        alert['demisto_score'] = map_orca_score_to_demisto_score(orca_score=alert.get("state", {}).get("score", 1))
        incident = {
            'name': f"Orca Cloud Incident: {alert.get('state', {}).get('alert_id')}.",
            'occurred': datetime_to_string(
                datetime.strptime(alert.get('state', {}).get('last_seen'), "%Y-%m-%dT%H:%M:%S%z").isoformat()),
            'rawJSON': json.dumps(alert),
            'severity': map_orca_score_to_demisto_score(orca_score=alert.get('state', {}).get('score'))
        }
        incidents.append(incident)

    demisto.setLastRun({'lastRun': datetime.now().strftime(DEMISTO_OCCURRED_FORMAT)})
    demisto.incidents(incidents)
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
            alerts = orca_client.get_alerts_by_filter(alert_type=demisto_args.get('alert_type'),
                                                      asset_unique_id=demisto_args.get('asset_unique_id'))
            if isinstance(alerts, str):
                return_error(alerts)
            if not alerts:
                return_error("Alerts not exists")
            command_result = CommandResults(outputs_prefix="Orca.Manager.Alerts", outputs=alerts, raw_response=alerts)
            return_results(command_result)

        elif command == "orca-get-asset":
            asset = orca_client.get_asset(asset_unique_id=demisto.args()['asset_unique_id'])
            if not isinstance(asset, Dict):
                # this means asset not found
                return_error(asset)

            command_result = CommandResults(outputs_prefix="Orca.Manager.Asset", outputs=[asset], raw_response=asset)
            return_results(command_result)

        elif command == "fetch-incidents":
            fetch_incidents(orca_client)

        elif command == "test-module":
            test_res = orca_client.validate_api_key()
            return_results(test_res)

        else:
            raise NotImplementedError(f'{command} is not an existing orca command')
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
