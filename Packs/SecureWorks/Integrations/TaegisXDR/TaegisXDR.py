from typing import Any, Dict

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

""" CONSTANTS """


AUTH_ENDPOINT = "/auth/api/v2/auth/token"
GRAPHQL_ENDPOINT = "/graphql"
XDR_URL = "https://ctpx.secureworks.com"

INVESTIGATION_STATUSES = set((
    "Open",
    "Active",
    "Suspended",
    "Closed: Authorized Activity",
    "Closed: False Positive Alert",
    "Closed: Informational",
    "Closed: Not Vulnerable",
))
INVESTIGATION_UPDATE_FIELDS = set(("key_findings", "priority", "status", "service_desk_id", "service_desk_type"))


""" CLIENT """


class Client(BaseClient):
    """
    Secureworks Taegis XDR Client class for implementing API logic with Taegis
    """
    _auth_header = {"access_token": "None"}

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        base_url: str,
        proxy: bool = False,
        verify: bool = False,
    ) -> None:
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.base_url = base_url
        self._client_id = client_id
        self._client_secret = client_secret
        self.verify = verify
        return

    def auth(self) -> None:
        """Authenticate to the Taegis API using client_id and client_secret

        See the documentation for obtaining the client ID and secret: https://docs.ctpx.secureworks.com/apis/api_authenticate/
        """
        response = self._http_request(
            "POST",
            AUTH_ENDPOINT,
            headers={"Content-Type": "application/json"},
            json_data={"grant_type": "client_credentials"},
            auth=(self._client_id, self._client_secret),
        )

        token = response.get("access_token", None)
        self._auth_header = {"Authorization": f"Bearer {token}"}

        return

    def graphql_run(self, query: str, variables: Dict[str, Any] = None):
        """Perform a GraphQL query

        :type query: ``str``
        :param query: The GraphQL query

        :type variables: ``Dict[str, Any]``
        :param variables: The variables to utilize with the query
        """
        json_data: Dict[str, Any] = {"query": query}

        if variables:
            json_data["variables"] = variables

        response = self._http_request(
            method="POST",
            url_suffix=GRAPHQL_ENDPOINT,
            json_data=json_data,
            headers=self._auth_header,
        )
        return response

    def test(self) -> Dict[str, Any]:
        """
        Get the current API/asset version for testing auth and connectivity
        """
        response = self._http_request(
            method="GET",
            url_suffix="/assets/version",
            headers=self._auth_header,
        )
        return response


""" COMMANDS """


def create_investigation_command(client: Client, args=None):
    query = """
    mutation ($investigation: InvestigationInput!) {
    createInvestigation(investigation: $investigation) {
            id
        }
    }
    """

    variables = {
        "investigation": {
            "description": args.get("description", "Demisto Created Investigation"),
            "priority": args.get("priority", 2),
            "status": "Open",
        }
    }

    result = client.graphql_run(query=query, variables=variables)

    investigation_url = f"{XDR_URL}/investigations/{result['data']['createInvestigation']['id']}"
    readable_output = f"## Results\n* Created Investigation: [{result['data']['createInvestigation']['id']}]({investigation_url})"
    outputs = result["data"]["createInvestigation"]

    results = CommandResults(
        outputs_prefix="TaegisXDR.Result",
        outputs_key_field="id",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=result,
    )

    return results


def fetch_alerts_command(client: Client, args=None):
    """
    The results from listing alerts is not always the most recent. It's recommended
        that specific alert IDs are utilized rather than fetching all alerts.

    Max number of results: 10
    """
    if not args.get("ids"):
        args["ids"] = []

    query = """
    query alerts {
        alerts(alertIDs: %s) {
            id
            alert_type
            data {
                username
                message
                source_ip
                destination_ip
                raw_event
            }
            group_key
            confidence
            severity
            creator
            creator_version
            tenant_id
            message
            description
            timestamp {
                seconds
            }
            investigations
            source {
                uuid
                origin
                source_event
                event_snippet
            }
            related_entities
            references {
                description
                url
            }
        }
    }
    """ % (str(args["ids"]))

    result = client.graphql_run(query)
    readable_output = f'## Results\nFound {len(result["data"]["alerts"])} alerts'

    if result["data"]["alerts"]:
        readable_output += "\n\n### Alerts\n"
        for alert in result["data"]["alerts"]:
            readable_output += f"* [{alert['message']}]({XDR_URL}/alerts/{alert['id']})\n"

    outputs = result["data"]["alerts"]

    results = CommandResults(
        outputs_prefix="TaegisXDR.Result",
        outputs_key_field="id",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=result,
    )

    return results


def fetch_investigation_alerts_command(client: Client, args=None):
    investigation_id = args.get("id")
    if not investigation_id:
        raise ValueError("Cannot fetch investigation, missing investigation_id")

    query = """
    query investigationAlerts($investigation_id: ID!) {
        investigationAlerts(investigation_id: $investigation_id) {
            alerts {
                id
            }
            totalCount
        }
    }
    """

    variables = {"investigation_id": investigation_id}

    result = client.graphql_run(query=query, variables=variables)

    if not result.get("data"):
        return_error(f"Failed to locate investigation: {investigation_id}")

    alerts = result["data"]["investigationAlerts"].get("alerts", [])

    readable_output = f"## Results\nFound {len(alerts)} alerts related to investigation {investigation_id}"

    if alerts:
        readable_output = "## Investigation Alerts"
        for alert in alerts:
            readable_output += f"* [{alert['id']}]({XDR_URL}/alerts/{alert['id']})\n"
    outputs = alerts

    results = CommandResults(
        outputs_prefix="TaegisXDR.Result",
        outputs_key_field="id",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=result,
    )

    return results


def fetch_investigation_command(client: Client, args=None):
    investigation_id = args.get("id", None)
    page = args.get("page", 0)
    page_size = args.get("page_size", 10)

    fields = """
        id
        tenant_id
        description
        key_findings
        alerts {
            id
            alert_type
            severity
            message
        }
        service_desk_id
        service_desk_type
        latest_activity
        priority
        status
        assets {
            id
            hostnames {
                id
                hostname
            }
            tags {
                tag
            }
        }
        """

    if investigation_id:
        query = """
        query investigation($investigation_id: ID!) {
            investigation(investigation_id: $investigation_id) {
                %s
            }
        }
        """ % (fields)

        variables = {"investigation_id": investigation_id}
        result = client.graphql_run(query=query, variables=variables)
    else:
        query = """
        query investigations {
            allInvestigations(page: %s, perPage: %s) {
                %s
            }
        }
        """ % (
            page,
            page_size,
            fields,
        )

        result = client.graphql_run(query=query)

    try:
        outputs = [result["data"]["investigation"]] if investigation_id else result["data"]["allInvestigations"]
    except KeyError:
        outputs = []

    readable_output = f"## Results\nFound {len(outputs)} investigation(s)"

    for investigation in outputs:
        readable_output += f"""\n\n### [{investigation['description']}]({XDR_URL}/investigations/{investigation["id"]})
* ID: {investigation['id']}
* Priority: {investigation['priority']}
* Status: {investigation['status']}
"""

    results = CommandResults(
        outputs_prefix="TaegisXDR.Result",
        outputs_key_field="id",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=result,
    )

    return results


def update_investigation_command(client: Client, args=None):
    investigation_id = args.get("id")
    if not investigation_id:
        raise ValueError("Cannot fetch investigation without investigation_id defined")

    query = """
    mutation ($investigation_id: ID!, $investigation: UpdateInvestigationInput!) {
        updateInvestigation(investigation_id: $investigation_id, investigation: $investigation) {
            id
        }
    }
    """
    variables = {"investigation_id": investigation_id, "investigation": dict()}

    for field in INVESTIGATION_UPDATE_FIELDS:
        if not args.get(field):
            continue

        if field == "status" and args.get("status") not in INVESTIGATION_STATUSES:
            raise ValueError((
                "The provided status, {args['status']}, is not valid for updating an investigation. "
                f"Supported Status Values: {INVESTIGATION_STATUSES}"))

        variables["investigation"][field] = args.get(field)

    if not variables["investigation"]:
        raise ValueError(f"No valid investigation fields provided. Supported Update Fields: {INVESTIGATION_UPDATE_FIELDS}")

    result = client.graphql_run(query=query, variables=variables)

    investigation_url = f"{XDR_URL}/investigations/{result['data']['updateInvestigation']['id']}"
    readable_output = f"## Results\n* Updated Investigation: [{result['data']['updateInvestigation']['id']}]({investigation_url})"
    outputs = result["data"]["updateInvestigation"]

    results = CommandResults(
        outputs_prefix="TaegisXDR.Result",
        outputs_key_field="id",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=result,
    )

    return results


def test_module(client: Client) -> str:
    """
    Returns success if authentication was successful
    """
    try:
        client.test()
        return "ok"
    except DemistoException as exception:
        raise DemistoException(exception)


""" MAIN """


def main():
    command = demisto.command()
    demisto.info(f'Command being called is {command}')

    commands: Dict[str, Any] = {
        "taegis-create-investigation": create_investigation_command,
        "taegis-fetch-alerts": fetch_alerts_command,
        "taegis-fetch-investigation": fetch_investigation_command,
        "taegis-fetch-investigation-alerts": fetch_investigation_alerts_command,
        "taegis-update-investigation": update_investigation_command,
        "test-module": test_module,
    }

    PARAMS = demisto.params()
    try:
        client = Client(
            client_id=PARAMS.get("client_id"),
            client_secret=PARAMS.get("client_secret"),
            base_url=PARAMS.get("endpoint"),
            proxy=PARAMS.get("proxy", False),
            verify=PARAMS.get("verify", True),
        )
        client.auth()

        if command not in commands:
            raise NotImplementedError(
                f'The "{command}" command has not been implemented.'
            )

        if command == "test-module":
            result = test_module(client)
            return return_results(result)
        else:
            return_results(commands[command](client=client, args=demisto.args()))
    except Exception as e:
        error_string = str(e)
        demisto.error(f"Error running command: {e}")

        if "Unauthorized" in error_string:
            error_string = "Invalid credentials (Client ID or Client Secret)"
        return_error(f"Failed to execute {command} command. Error: {error_string}")


""" ENTRY POINT """
if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
