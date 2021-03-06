''' IMPORTS '''

import json
from typing import Any, Dict

'''CONSTANTS'''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
MAX_INCIDENTS_TO_FETCH = 100
VALID_VIOLATION_STATUSES = ['OPEN', 'RESOLVED', 'IGNORED']


''' CLIENT CLASS '''


class Client(BaseClient):
    """ Implements Gamma API """

    def get_violation_list(self, minimum_violation: int, limit: int) -> Dict[str, Any]:
        """ Gets dict of all violations starting from the minimum ID

        :type minimum_violation: int
        :param minimum_violation: unique violation ID to begin search

        :type limit: int
        :param limit: <=100, enforced by API
        """

        return self._http_request(
            method="GET",
            url_suffix=f"/violation/list",
            params={
                "minimum_violation_id": minimum_violation,
                "limit": limit
            }
        )

    def get_violation(self, violation: int) -> Dict[str, Any]:
        """ Get dict of violation by unique ID

        :type violation: int
        :param violation: unique violation ID
        """

        return self._http_request(
            method="GET",
            url_suffix=f"/violation/list",
            params={
                "minimum_violation_id": violation,
                "limit": 1
            }
        )

    def update_violation(self, violation: int, status: str, notes: str) -> Dict[str, Any]:
        """ Update a violation's status and notes

        :type violation: int
        :param violation: unique violation ID

        :type status: string
        :param status: status to mark the violation. options are 'OPEN', 'RESOLVED', 'IGNORED'

        :type notes: string
        :param notes: notes to update current notes for the violation
        """

        return self._http_request(
            method="PUT",
            url_suffix=f"/violation/{violation}",
            json_data={
                "violation_status": status,
                "notes": notes
            }
        )


''' COMMANDS '''


def fetch_incidents(client: Client, last_run_violation: dict, first_fetch_violation: str, max_results: str):
    """ This function will run each interval (default 1 minute)

    :type client: client
    :param client: Gamma client

    :type last_run_violation: dict
    :param last_run_violation: last violation ID that was queried from Gamma

    :type first_fetch_violation: int
    :param first_fetch_violation: if last_violation is None, then begin from this violation ID

    :type max_results: int
    :param max_results: the max number of violations to pull, bound by MAX_INCIDENTS_TO_FETCH
    """

    try:
        first_fetch_violation = int(first_fetch_violation)
        max_results = int(max_results)
    except:
        raise ValueError("first_fetch_violation and max_limit must be integers")

    if not first_fetch_violation > 0:
        raise ValueError("first_fetch_violation must be equal to 1 or higher")
    if not max_results > 0:
        max_results = 10
    elif max_results > MAX_INCIDENTS_TO_FETCH:
        max_results = MAX_INCIDENTS_TO_FETCH

    # get the last violation id fetched, if exists
    starting_violation = last_run_violation.get('starting_violation', first_fetch_violation)

    most_recent_violation = starting_violation
    incidents = []
    violations = client.get_violation_list(starting_violation, max_results)

    for item in violations['response']:
        incident_violation = item['violation_id']
        incident_time_ms = item['violation_event_timestamp'] * 1000

        if incident_violation <= most_recent_violation:
            continue

        incident = {
            "name": f'Gamma Violation {incident_violation}',
            "occurred": timestamp_to_datestring(incident_time_ms),
            "rawJSON": json.dumps(item)
        }

        incidents.append(incident)

        # update last run if violation id is greater than last fetch
        if incident_violation > most_recent_violation:
            most_recent_violation = incident_violation

    next_run_violation = {'starting_violation': most_recent_violation}

    return next_run_violation, incidents


def get_violation_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
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

    if not int(minimum_violation) >= 1:
        raise ValueError("minimum_violation must be greater than 0")
    if not int(limit) >= 1 or not int(limit) <= 100:
        raise ValueError("limit must be between 1 and 100")

    v_list = client.get_violation_list(minimum_violation, limit)

    note = ''
    if v_list['response'][0]['violation_id'] != int(minimum_violation):
        note += f'Violation with the minimum_violation ID does not exist. Showing violations pulled from the next available ID: {v_list["response"][0]["violation_id"]} \r'

    human_readable = note
    for i in v_list['response']:
        violation_id = i['violation_id']
        human_readable += f'### Violation {i["violation_id"]} \r' \
                          f'|Violation ID|Status|Timestamp|Dashboard URL|User|App Name| \r' \
                          f'|---|---|---|---|---|---| \r' \
                          f'| {violation_id} | {i["violation_status"]} | {timestamp_to_datestring(i["violation_event_timestamp"]*1000)} | {i["dashboard_url"]} | {i["user"]} | {i["app_name"]} | \r'

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix="GammaViolation",
        outputs_key_field="violation_id",
        outputs=v_list,
        raw_response=v_list
    )


def get_violation_command(client: Client, args: Dict[str, Any]) -> CommandResults:
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

    if not int(violation_id) >= 1:
        raise ValueError("violation must be greater than 0")

    violation = client.get_violation(violation_id)

    if violation['response'][0]['violation_id'] != int(violation_id):
        return "Violation with this ID does not exist."

    human_readable = ''
    for i in violation['response']:
        human_readable += f'### Violation {i["violation_id"]} \r' \
                          f'|Violation ID|Status|Timestamp|Dashboard URL|User|App Name| \r' \
                          f'|---|---|---|---|---|---| \r' \
                          f'| {i["violation_id"]} | {i["violation_status"]} | {timestamp_to_datestring(i["violation_event_timestamp"] * 1000)} | {i["dashboard_url"]} | {i["user"]} | {i["app_name"]} | \r'

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix="GammaViolation",
        outputs_key_field="violation_id",
        outputs=violation,
        raw_response=violation
    )


def update_violation_command(client: Client, args: Dict[str, Any]) -> CommandResults:
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

    if not int(violation) >= 1:
        raise ValueError("violation must be greater than 0")
    if status not in VALID_VIOLATION_STATUSES:
        raise ValueError("status must be one of the following: OPEN, RESOLVED, IGNORED")

    client.update_violation(violation, status, notes)

    updated_violation = client.get_violation(violation)
    human_readable = ''
    for i in updated_violation['response']:
        violation_id = i['violation_id']
        human_readable += f'### Updated Violation {i["violation_id"]} \r' \
                          f'|Violation ID|Status|Timestamp|Dashboard URL|User|App Name| \r' \
                          f'|---|---|---|---|---|---| \r' \
                          f'| {violation_id} | {i["violation_status"]} | {timestamp_to_datestring(i["violation_event_timestamp"] * 1000)} | {i["dashboard_url"]} | {i["user"]} | {i["app_name"]} | \r'

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix="GammaViolation",
        outputs_key_field="violation_id",
        outputs=updated_violation,
        raw_response=updated_violation
    )


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    api_key = demisto.params()['api_key']

    # get the service API url
    base_url = urljoin(demisto.params()['url'], '/api/discovery/v1/')

    verify_certificate = not(demisto.params().get('insecure', False))
    proxy = demisto.params().get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        headers = {
            'X-API-Key': api_key,
        }
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'fetch-incidents':
            first_fetch_violation = demisto.params().get('first_fetch_violation', 1)
            max_results = demisto.params().get('max_results', 10)

            next_run_violation, incidents = fetch_incidents(
                client=client,
                last_run_violation=demisto.getLastRun(),
                first_fetch_violation=first_fetch_violation,
                max_results=max_results
            )

            demisto.setLastRun(next_run_violation)
            demisto.incidents(incidents)

        elif demisto.command() == 'gamma-get-violation-list':
            return_results(get_violation_list_command(client, demisto.args()))
        elif demisto.command() == 'gamma-get-violation':
            return_results(get_violation_command(client, demisto.args()))
        elif demisto.command() == 'gamma-update-violation':
            return_results(update_violation_command(client, demisto.args()))

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
