import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

""" IMPORTS """

import json
import urllib3
from typing import Any, Dict
from enum import Enum

# Disable insecure warnings
urllib3.disable_warnings()

"""CONSTANTS"""

MAX_INCIDENTS_TO_FETCH = 100

""" CLIENT CLASS """


class Client(BaseClient):
    """Implements Gamma API"""

    def __init__(self, demisto):
        api_key = demisto.params().get("credentials_api_key", {}).get("password") or demisto.params()["api_key"]
        if not api_key:
            raise DemistoException("Gamma API Key must be provided.")
        headers = {"X-API-Key": api_key}
        base_url = urljoin(demisto.params()["url"], "/api/discovery/v1/")
        verify_certificate = not (demisto.params().get("insecure", False))
        proxy = demisto.params().get("proxy", False)

        super().__init__(base_url=base_url, verify=verify_certificate, headers=headers, proxy=proxy)

    def get_violation_list(self, minimum_violation: int, limit: int) -> Dict[str, Any]:
        """Gets dict of all violations starting from the minimum ID

        :type minimum_violation: int
        :param minimum_violation: unique violation ID to begin search

        :type limit: int
        :param limit: <=100, enforced by API
        """

        return self._http_request(
            method="GET", url_suffix="/violation/list", params={"minimum_violation_id": minimum_violation, "limit": limit}
        )

    def get_violation(self, violation: int) -> Dict[str, Any]:
        """Get dict of violation by unique ID

        :type violation: int
        :param violation: unique violation ID
        """

        return self._http_request(
            method="GET", url_suffix="/violation/list", params={"minimum_violation_id": violation, "limit": 1}
        )

    def update_violation(self, violation: int, status: str, notes: str) -> Dict[str, Any]:
        """Update a violation's status and notes

        :type violation: int
        :param violation: unique violation ID

        :type status: string
        :param status: status to mark the violation. options are 'OPEN', 'RESOLVED', 'IGNORED'

        :type notes: string
        :param notes: notes to update current notes for the violation
        """

        return self._http_request(
            method="PUT", url_suffix=f"/violation/{violation}", json_data={"violation_status": status, "notes": notes}
        )


class ViolationStatus(Enum):
    OPEN = "OPEN"
    RESOLVED = "RESOLVED"
    IGNORED = "IGNORED"


""" COMMANDS """


class Command:
    @staticmethod
    def get_violation_list(client: Client, args: Dict[str, Any]) -> CommandResults:
        """
        :type client: Client
        :param client: Gamma client

        :param args: all command arguments, usually passed from demisto.args()
            args['name'] is used as input name

        :return:
            A CommandResults object that is then passed to return_results

        :rtype: ``CommandResults``
        """

        minimum_violation = args.get("minimum_violation", 1)
        limit = args.get("limit", 10)

        if int(minimum_violation) < 1:
            raise ValueError("minimum_violation must be greater than 0")
        if int(limit) < 1 or int(limit) > 100:
            raise ValueError("limit must be between 1 and 100")

        response = client.get_violation_list(minimum_violation, limit)
        violations = response["response"]

        note = ""
        if violations[0]["violation_id"] != int(minimum_violation):
            note += (
                "Violation with the minimum_violation ID does not exist. "
                "Showing violations pulled from the next available ID: "
                f'{violations[0]["violation_id"]} \r'
            )

        human_readable = get_human_readable(violations)

        return CommandResults(
            readable_output=human_readable,
            outputs_prefix="GammaViolation",
            outputs_key_field="violation_id",
            outputs=violations,
            raw_response=violations,
        )

    @staticmethod
    def get_violation(client: Client, args: Dict[str, Any]) -> CommandResults:
        """
        :type client: Client
        :param client: Gamma client

        :param args: all command arguments, usually passed from demisto.args()
            args['name'] is used as input name

        :return:
            A CommandResults object that is then passed to return_results

        :rtype: ``CommandResults``
        """

        violation_id = args["violation"]

        if int(violation_id) < 1:
            raise ValueError("Violation must be greater than 0")

        response = client.get_violation(violation_id)
        violations = response["response"]

        if violations[0]["violation_id"] != int(violation_id):
            raise ValueError("Violation with this ID does not exist.")

        human_readable = get_human_readable(violations)

        return CommandResults(
            readable_output=human_readable,
            outputs_prefix="GammaViolation",
            outputs_key_field="violation_id",
            outputs=violations,
            raw_response=violations,
        )

    @staticmethod
    def update_violation(client: Client, args: Dict[str, Any]) -> CommandResults:
        """
        :type client: Client
        :param client: Gamma client

        :param args: all command arguments, usually passed from demisto.args()
            args['name'] is used as input name

        :return:
            A CommandResults object that is then passed to return_results

        :rtype: ``CommandResults``
        """

        violation = args["violation"]
        status = args["status"].upper()
        notes = args["notes"]

        if int(violation) < 1:
            raise ValueError("Violation must be greater than 0")
        try:
            ViolationStatus(status)
        except ValueError:
            raise ValueError("Status must be one of the following: OPEN, RESOLVED, IGNORED")

        client.update_violation(violation, status, notes)

        response = client.get_violation(violation)
        updated_violation = response["response"]
        human_readable = get_human_readable(updated_violation)

        return CommandResults(
            readable_output=human_readable,
            outputs_prefix="GammaViolation",
            outputs_key_field="violation_id",
            outputs=updated_violation,
            raw_response=updated_violation,
        )

    @staticmethod
    def run(command, client, args):
        if command == "gamma-get-violation-list":
            return Command.get_violation_list(client, args)
        elif command == "gamma-get-violation":
            return Command.get_violation(client, args)
        elif command == "gamma-update-violation":
            return Command.update_violation(client, args)
        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication

    Returning 'ok' indicates that the integration works like it is supposed to and connection to
    the service is successful.

    Raises exceptions if something goes wrong.

    :type client: Client
    :param client: Gamma client

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    try:
        client.get_violation_list(minimum_violation=1, limit=10)
    except DemistoException as e:
        if "UNAUTHORIZED" in str(e):
            return "Authorization Error: Make sure Gamma Discovery API Key is correctly set"
        else:
            raise e
    return "ok"


def fetch_incidents(client: Client, last_run_violation: dict, str_first_fetch_violation: str, str_max_results: str):
    """This function will run each interval (default 1 minute)

    :type client: client
    :param client: Gamma client

    :type last_run_violation: dict
    :param last_run_violation: last violation ID that was queried from Gamma

    :type str_first_fetch_violation: str
    :param str_first_fetch_violation: if last_violation is None, then begin from this violation ID

    :type str_max_results: str
    :param str_first_fetch_violation: the max number of violations to pull, bound by
    MAX_INCIDENTS_TO_FETCH
    """

    try:
        first_fetch_violation = int(str_first_fetch_violation)
        max_results = int(str_max_results)
    except ValueError:
        raise ValueError("first_fetch_violation and max_limit must be integers")

    if first_fetch_violation < 1:
        raise ValueError("first_fetch_violation must be equal to 1 or higher")
    if max_results < 1:
        max_results = 10
    elif max_results > MAX_INCIDENTS_TO_FETCH:
        max_results = MAX_INCIDENTS_TO_FETCH

    # get the last violation id fetched, if exists
    starting_violation = last_run_violation.get("starting_violation", first_fetch_violation)

    most_recent_violation = starting_violation
    incidents = []
    violations = client.get_violation_list(starting_violation, max_results)

    for item in violations["response"]:
        incident_violation = item["violation_id"]
        incident_time_ms = item["violation_event_timestamp"] * 1000

        if incident_violation <= most_recent_violation:
            continue

        incident = {
            "name": f"Gamma Violation {incident_violation}",
            "occurred": timestamp_to_datestring(incident_time_ms),
            "rawJSON": json.dumps(item),
        }

        incidents.append(incident)

        # update last run if violation id is greater than last fetch
        if incident_violation > most_recent_violation:
            most_recent_violation = incident_violation

    next_run_violation = {"starting_violation": most_recent_violation}

    return next_run_violation, incidents


def get_human_readable(violation: List[Dict[str, Any]]) -> str:
    """Parse results into human readable format

    :type violation: List
    :param violation: List object obtaining violation data

    :return: String with Markdown formatting
    :rtype: str
    """

    def violation_to_str(v):
        return (
            f'### Violation {v["violation_id"]} \r'
            f'|Violation ID|Status|Timestamp|Dashboard URL|User|App Name| \r'
            f'|---|---|---|---|---|---| \r'
            f'| {v["violation_id"]} | {v["violation_status"]} | '
            f'{timestamp_to_datestring(v["violation_event_timestamp"] * 1000)} | '
            f'{v["dashboard_url"]} | {v["user"]} | {v["app_name"]} | \r'
        )

    return "\r".join(violation_to_str(key) for key in violation)


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    demisto.debug(f"Command being called is {demisto.command()}")
    try:
        client = Client(demisto)

        if demisto.command() == "fetch-incidents":
            str_first_fetch_violation = demisto.params().get("first_fetch", 1)
            str_max_results = demisto.params().get("max_fetch", 10)

            next_run_violation, incidents = fetch_incidents(
                client=client,
                last_run_violation=demisto.getLastRun(),
                str_first_fetch_violation=str_first_fetch_violation,
                str_max_results=str_max_results,
            )

            demisto.setLastRun(next_run_violation)
            demisto.incidents(incidents)
        elif demisto.command() == "test-module":
            result = test_module(client)
            return_results(result)
        else:
            return_results(Command.run(demisto.command(), client, demisto.args()))

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
