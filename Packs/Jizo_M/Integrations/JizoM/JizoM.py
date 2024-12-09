import demistomock as demisto
from CommonServerPython import *
import json
from typing import Any
from datetime import datetime
# Disable Secure Warnings
import urllib3
urllib3.disable_warnings()

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
JIZO_DATE_FORMAT = "%Y-%m-%d %H:%M:%S.%f"
MAX_ALERTS_TO_FETCH = 10
ITEM_TEMP = '"id":{id},"name":"Jizo Alert #{id}",'\
    '"alert_type":"{alert_type}","severity":"{severity}",'\
    '"category":"{category}","signature":"{signature}",'\
    '"IP_source":"{IP_source}","IP_destination":"{IP_destination}","date":"{date}"'


""" CLIENT CLASS """


class Client(BaseClient):
    """
    Client class to interact with the service API

    """

    def __init__(
        self,
        base_url: str,
        auth: tuple,
        headers: dict = {},
        verify: bool = False,
        proxy: bool = False,
    ) -> None:

        self.base_url = base_url
        self.auth = auth
        self.headers = headers
        self.verify = verify
        self.proxy = proxy

    def test_module(self) -> bool:
        """Check if the API is active

        Returns:
            dict: response body of the ping endpoint
        """

        url = f"{self.base_url}/ping"
        # Define headers
        headers = {"Content-Type": "application/json"}

        # Sending POST request to the API endpoint with the specified headers and request body
        response = requests.get(
            url, headers=headers, verify=self.verify
        )  # Setting verify=False ignores SSL certificate verification. Be cautious about using it in a production environment.
        # Checking if the request was successful (status code 200)
        return response.status_code == 200

    def get_protocols(self, args: dict[str, Any]):
        """
        Get jizo protocols. You can filter by ip_src, ip_dest.
        You can filter also by timestamp or probe name
        """

        url = f"{self.base_url}/jizo_get_protocols"

        response = requests.get(
            url, params=args, headers=self.headers, verify=self.verify
        )
        if response.status_code == 200:
            return response.json()
        else:
            raise DemistoException(response.text, response.status_code, response.reason)

    def get_peers(self, args: dict[str, Any]):
        """
        Get jizo peers. You can filter by ip_src, ip_dest.
        You can filter also by timestamp or probe name or probe Ip

        """

        url = f"{self.base_url}/jizo_get_peers"

        response = requests.get(
            url, params=args, headers=self.headers, verify=self.verify
        )
        if response.status_code == 200:
            return response.json()
        else:
            raise DemistoException(response.text, response.status_code, response.reason)

    def get_query_records(self, args: dict[str, Any]):
        """
        Get jizo query records. You can filter by ip_src, proto, port_src, FlowId, Sid.
        You can filter also by timestamp or probe name

        """
        url = f"{self.base_url}/jizo_query_records"

        response = requests.get(
            url, params=args, headers=self.headers, verify=self.verify
        )
        if response.status_code == 200:
            return response.json()
        else:
            raise DemistoException(response.text, response.status_code, response.reason)

    def get_alert_list(
        self, limit: int, start_time: str, last_id: int = 0, first_fetched_ids: list = []
    ):
        """Call jizo_query_records endpoint and select specific fields
        of response to return in alerts summary

        Args:
            limit (int): The number of items to generate.
            start_time (str): first fetch time of incidents.
            last_id(int): last incidents id
            first_fetched_ids (list): The ids of the first fetched alerts

        Returns:
            list[dict]: data of formatted items
        """

        context_data = self.get_query_records(
            args={"datetime_from": start_time}
        )
        alerts: list[dict] = []
        # Get alerts details
        alert_data = context_data["alerts_flows"]["data"]

        if last_id == 0 and not bool(first_fetched_ids):  # means no previous alerts were fetched
            # Save first fetched alert id to check later
            # for other coming alerts
            first_fetched_ids.append(alert_data[0]["idx"])

        if bool(first_fetched_ids) and first_fetched_ids[-1] == -1 and alert_data[0]["idx"] not in first_fetched_ids:
            # Means the last element in alert_data list was reached in previous fetch
            # and, new alerts were coming
            last_id = 0
            first_fetched_ids.append(alert_data[0]["idx"])

        elif bool(first_fetched_ids) and first_fetched_ids[-1] == -1:
            # In case no new alerts have come, exit with empty list
            # of alerts to fetch
            return alerts, first_fetched_ids

        # Get index of next alert to fetch
        if last_id == 0:
            next_index_to_fetch = 0
        else:
            # search for last fetched alert index
            next_index_to_fetch = next((index for (index, d) in enumerate(alert_data) if d["idx"] == last_id), 0)
            next_index_to_fetch += 1

        if bool(alert_data):
            for i in range(limit):

                if next_index_to_fetch + i == len(alert_data) or \
                        (alert_data[next_index_to_fetch + i]["idx"] in first_fetched_ids
                            and alert_data[next_index_to_fetch + i]["idx"] != first_fetched_ids[-1]):
                    # Means the final element in alert_data list was fetched
                    # Or, In this fetch ,new coming alerts were fetched, but we are reaching
                    # indexes of alerts that were already fetched in previous ones
                    first_fetched_ids.append(-1)
                    break

                severity = alert_data[next_index_to_fetch + i].get("severity", "4")
                category = alert_data[next_index_to_fetch + i].get("alert_category", "")
                # Fill in the alert item
                item = ITEM_TEMP.format(
                    id=alert_data[next_index_to_fetch + i]["idx"],
                    alert_type="alert flow",
                    severity=severity,
                    category=category,
                    signature=alert_data[next_index_to_fetch + i].get("signature", ""),
                    IP_source=alert_data[next_index_to_fetch + i].get("ip_src", ""),
                    IP_destination=alert_data[next_index_to_fetch + i].get("ip_dest", ""),
                    date=formatting_date(alert_data[next_index_to_fetch]["date"]["date"]),
                )
                dict_item = json.loads("{" + item + "}")
                alerts.append(dict_item)

        return alerts, first_fetched_ids


""" HELPER FUNCTIONS """


def formatting_date(date: str) -> str:
    """
    Converts date retrieved from Jizo to Cortex XSOAR date format
    """

    formatted = datetime.strptime(date, JIZO_DATE_FORMAT)

    return datetime.strftime(formatted, DATE_FORMAT)


def convert_date(date: str) -> str:
    """
    Converts date of format n days ago to datetime
    """

    formatted = datetime.now() - timedelta(days=int(date.split(' ')[0]))

    return formatted.strftime(JIZO_DATE_FORMAT)


def convert_to_demisto_severity(severity: str) -> int:
    """
    Maps Jizo severity to Cortex XSOAR severity.
    In Jizo severities are from 4 to 1 (Alert of severity 1 is critical)
    In Cortex XSOAR it is the opposite logic

    Args:
        severity (str): severity as returned from the JizoM API.

    Returns:
        int: Cortex XSOAR Severity (1 to 4)
    """

    return {
        "4": IncidentSeverity.LOW,
        "3": IncidentSeverity.MEDIUM,
        "2": IncidentSeverity.HIGH,
        "1": IncidentSeverity.CRITICAL,
    }[severity]


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    if client.test_module():
        return "ok"
    else:
        return "Request error, please check your API"


def get_token(client: Client):

    try:
        url = f"{client.base_url}/login"

        # Include username and password as JSON in the request body
        data = {
            "username": client.auth[0],
            "password": client.auth[1],
        }

        # Define headers
        headers = {"Content-Type": "application/json"}

        # Sending POST request to the API endpoint with the specified headers and request body
        response = requests.post(
            url, headers=headers, json=data, verify=False
        )  # Setting verify=False ignores SSL certificate verification. Be cautious about using it in a production environment.
        # Checking if the request was successful (status code 200)
        if response.status_code == 200:
            return response.json()
        else:
            return_error(
                f"Error: {response.status_code} - Authentication failed, please try again with appropriate credentials "
            )

    except Exception as e:
        return_error(f"An error occurred: {e}")


def get_protocols_command(client: Client, args: dict[str, Any]) -> List[CommandResults]:
    """
    Returns response of jizo_get_protocols endpoint

    Args:
        client (Client): JizoM client to use.

    Returns:
        CommandResults: A  list of ``CommandResults`` object that will be then passed to ``return_results``
    """

    # Call the Client function and get the raw response
    result = client.get_protocols(args)

    command_results = []

    headers = {'alerts_flows': ['Protocol', 'Probe name', 'Flow id', 'IP source', 'IP destination'],
               'alerts_files': ['Protocol', 'Probe name', 'Flow id', 'IP source', 'IP destination'],
               'alerts_usecase': ['Protocol', 'Probe name', 'Flow id', 'IP source', 'IP destination']}

    for alert_type in result:
        alert_data = result[alert_type]["data"]
        human_readable = []
        for protocol in alert_data:
            for data in alert_data[protocol]:
                d = {'Protocol': protocol,
                     'Probe name': data.get('probe_name', 'None'),
                     'Flow id': data.get('flow_id', 'None'),
                     'IP source': data.get('src_ip', 'None'),
                     'IP destination': data.get('dest_ip', 'None')}

                human_readable.append(d)

        readable_output = tableToMarkdown(
            name=alert_type.replace("_", " "),
            t=human_readable,
            removeNull=True,
            headers=headers[alert_type]
        )
        command_results.append(
            CommandResults(
                readable_output=readable_output,
                outputs_prefix=f"JizoM.Protocols.{alert_type}",
                outputs_key_field='flow_id',
                outputs=result[alert_type],
            ))

    return command_results


def get_peers_command(client: Client, args: dict[str, Any]) -> List[CommandResults]:

    # Call the Client function and get the raw response
    result = client.get_peers(args)

    command_results = []

    headers = {'alerts_flows': ['Probe name', 'IP source', 'IP destination', 'Protocol', 'Flow id'],
               'alerts_files': ['Probe name', 'IP source', 'IP destination', 'Protocol', 'Flow id'],
               'alerts_usecase': ['Probe name', 'IP source', 'IP destination', 'Protocol', 'Flow id']}

    for alert_type in result:
        alert_data = result[alert_type]["data"]
        human_readable = []
        for probe in alert_data:
            for ip in alert_data[probe]:
                for data in alert_data[probe][ip]:
                    d = {
                        'Probe name': probe,
                        'IP source': ip,
                        'IP destination': data.get('dest_ip', 'None'),
                        'Protocol': data.get('protocol', 'None'),
                        'Flow id': data.get('flow_id', 'None'),
                    }

                    human_readable.append(d)

        readable_output = tableToMarkdown(
            name=alert_type.replace("_", " "),
            t=human_readable,
            removeNull=True,
            headers=headers[alert_type],
        )
        command_results.append(
            CommandResults(
                readable_output=readable_output,
                outputs_prefix=f"JizoM.Peers.{alert_type}",
                outputs_key_field='flow_id',
                outputs=result[alert_type],
            ))

    return command_results


def get_query_records_command(client: Client, args: dict[str, Any]) -> List[CommandResults]:

    # Call the Client function and get the raw response
    result = client.get_query_records(args)

    command_results = []

    headers = {'alerts_flows': ['Probe name', 'IP source', 'IP destination', 'Alert category', 'Severity'],
               'alerts_files': ['Probe name', 'Rule name', 'Rule type', 'File name', 'Message'],
               'alerts_usecase': ['Probe name', 'IP source', 'IP destination']}
    for alert_type in result:
        alert_data = result[alert_type]["data"]
        human_readable = []
        for value in alert_data:
            if 'flows' in alert_type:
                d = {'Probe name': value.get('ip_probe', 'None'),
                     'IP source': value.get('ip_src', 'None'),
                     'IP destination': value.get('ip_dest', 'None'),
                     'Alert category': value.get('alert_category', 'None'),
                     'Severity': convert_to_demisto_severity(str(value.get('severity', '4')))}
            elif 'files' in alert_type:
                d = {'Probe name': value.get('probe_name', 'None'),
                     'Rule name': value.get('rule_name', 'None'),
                     'Rule type': value.get('type_rule', 'None'),
                     'File name': value.get('filename', 'None'),
                     'Message': value.get('message', 'None')}
            else:
                d = {'Probe name': value.get('probe_name', 'None'),
                     'IP source': value.get('ip_src', 'None'),
                     'IP destination': value.get('ip_dest', 'None')}
            human_readable.append(d)

        readable_output = tableToMarkdown(
            name=alert_type.replace("_", " "),
            t=human_readable,
            removeNull=True,
            headers=headers[alert_type]
        )
        command_results.append(
            CommandResults(
                readable_output=readable_output,
                outputs_prefix=f"JizoM.QueryRecords.{alert_type}",
                outputs_key_field='idx',
                outputs=result[alert_type],
            ))

    return command_results


def fetch_incidents(
    client: Client, max_results: int, last_run: dict[str, Any], first_fetch_time: str
) -> tuple[dict[str, Any], List[dict]]:
    """
    Fetch incidents (alerts) from Jizo Manager API.

    Parameters:
    - client (Client): Client object to interact with the API.
    - max_results (int, optional): Maximum number of incidents to fetch.
    - last_run (Dict[str, Any]): Dictionary containing details about the last time incidents were fetched.
    - first_fetch_time (str): ISO formatted string indicating the first time from which to start fetching incidents.


    Returns:
    - Tuple[Dict[str, str], List[Dict]]: Tuple containing a dictionary with the `last_fetch` time and a list of fetched incidents.
    """

    # Get the last fetch time, if exists
    last_fetch = last_run.get("last_fetch", None)
    last_ids: list[int] = last_run.get("last_ids", []) or []
    first_fetched_ids: list[int] = last_run.get("first_fetched_ids", []) or []

    if last_fetch is None:
        last_fetch = first_fetch_time

    assert last_fetch

    incidents: list[dict[str, Any]] = []
    last_id = min(last_ids) if last_ids else 0
    demisto.debug(f"Running API query with {last_fetch=}")

    alerts, first_fetched_ids = client.get_alert_list(
        limit=max_results, start_time=first_fetch_time, last_id=last_id, first_fetched_ids=first_fetched_ids
    )

    last_fetched_time = alerts[-1]["date"] if alerts else last_fetch
    last_ids = []
    for alert in alerts:
        if alert["date"] == last_fetched_time:
            last_ids.append(alert["id"])

        incident = {
            "name": alert["name"],
            "occurred": alert["date"],
            "type": "Jizo Alert",  # Map to Jizo ALert which is specific XSOAR alert Type
            "severity": convert_to_demisto_severity(alert.get("severity", "low")),
            "Category": alert["category"],
            "Signature": alert["signature"],
            "rawJSON": json.dumps(alert),
        }

        incidents.append(incident)

    next_run = {"last_fetch": last_fetched_time, "last_ids": last_ids, "first_fetched_ids": first_fetched_ids}
    return next_run, incidents


""" MAIN FUNCTION """


def main() -> None:  # pragma: no cover
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    # get the service API url
    base_url = params.get("url")

    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    first_fetch_time = arg_to_datetime(
        arg=params.get("first_fetch", "7 days"),
        arg_name="First fetch time",
        required=True,
    )
    demisto.debug(f" first fetch time {first_fetch_time}")
    headers = {
        "Content-Type": "application/json",
    }
    # get credentials
    username = demisto.params().get("credentials", {}).get("identifier")
    password = demisto.params().get("credentials", {}).get("password")
    demisto.debug(f"Command being called is {command}")
    # convert date to jizo date format
    if "datetime_from" in args and "days" in args["datetime_from"]:
        args["datetime_from"] = convert_date(args["datetime_from"])
    if "datetime_to" in args and "days" in args["datetime_to"]:
        args["datetime_to"] = convert_date(args["datetime_to"])

    try:

        client = Client(
            base_url=base_url,
            auth=(username, password),
            headers=headers,
            verify=verify_certificate,
            proxy=proxy,
        )

        # get token
        connect = get_token(client)
        token = connect["token"]
        # add token to headers
        client.headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        }
        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client))
        elif command == "fetch-incidents":
            # Convert the argument to an int using helper function or set to MAX_ALERTS_TO_FETCH
            max_results = arg_to_number(
                arg=params.get("max_fetch"), arg_name="max_fetch", required=False
            )
            if not max_results or max_results > MAX_ALERTS_TO_FETCH:
                max_results = MAX_ALERTS_TO_FETCH

            next_run, incidents = fetch_incidents(
                client=client,
                max_results=max_results,
                last_run=demisto.getLastRun(),  # getLastRun() gets the last run dict
                first_fetch_time=datetime.strftime(first_fetch_time, DATE_FORMAT),  # type: ignore
            )

            # saves next_run for the time fetch-incidents is invoked
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
        elif command == "jizo-m-protocols-get":
            return_results(get_protocols_command(client, args))

        elif command == "jizo-m-peers-get":
            return_results(get_peers_command(client, args))

        elif command == "jizo-m-query-records-get":
            return_results(get_query_records_command(client, args))

        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
