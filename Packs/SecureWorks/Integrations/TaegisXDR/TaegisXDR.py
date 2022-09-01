from typing import Any, Dict

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

""" CONSTANTS """


AUTH_ENDPOINT = "/auth/api/v2/auth/token"
GRAPHQL_ENDPOINT = "/graphql"

ENV_URLS = {
    "us1": {"api": "https://api.ctpx.secureworks.com", "xdr": "https://ctpx.secureworks.com"},
    "us2": {"api": "https://api.delta.taegis.secureworks.com", "xdr": "https://delta.taegis.secureworks.com"},
    "eu": {"api": "https://api.echo.taegis.secureworks.com", "xdr": "https://echo.taegis.secureworks.com"},
}

INVESTIGATION_STATUSES = set((
    "Open",
    "Suspended",
    "Active",
    "Awaiting Action",
    "Closed: Authorized Activity",
    "Closed: False Positive Alert",
    "Closed: Inconclusive",
    "Closed: Informational",
    "Closed: Not Vulnerable",
    "Closed: Threat Mitigated",
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
        verify: bool = True,
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


def create_investigation_command(client: Client, env: str, args=None):
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

    investigation_url = f"{ENV_URLS[env]['xdr']}/investigations/{result['data']['createInvestigation']['id']}"
    readable_output = f"""
## Results
* Created Investigation: [{result['data']['createInvestigation']['id']}]({investigation_url})
"""
    outputs = result["data"]["createInvestigation"]

    results = CommandResults(
        outputs_prefix="TaegisXDR.Investigation",
        outputs_key_field="id",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=result,
    )

    return results


def execute_playbook_command(client: Client, env: str, args=None):
    playbook_id = args.get("id")
    if not playbook_id:
        raise ValueError("Cannot execute playbook, missing playbook_id")

    query = """
    mutation executePlaybookInstance(
        $playbookInstanceId: ID!
        $parameters: JSONObject
    ) {
        executePlaybookInstance(
            playbookInstanceId: $playbookInstanceId
            parameters: $parameters
        ) {
            id
        }
    }
    """

    playbook_inputs = args.get("inputs", {})

    variables = {
        "playbookInstanceId": playbook_id,
        "parameters": playbook_inputs,
    }

    result = client.graphql_run(query=query, variables=variables)

    if not result.get("data"):
        raise ValueError(f"Failed to execute playbook: {result['errors'][0]['message']}")

    execution_url = f"{ENV_URLS[env]['xdr']}/automations/playbook-executions/{result['data']['executePlaybookInstance']['id']}"
    readable_output = f"""
## Results
* Executed Playbook Instance: [{result['data']['executePlaybookInstance']['id']}]({execution_url})
"""
    outputs = result["data"]["executePlaybookInstance"]

    results = CommandResults(
        outputs_prefix="TaegisXDR.Execution",
        outputs_key_field="id",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=result,
    )

    return results


def fetch_alerts_command(client: Client, env: str, args=None):
    """
    Fetch a specific alert or a list of alerts based on a CQL Taegis query
    """
    variables: dict = {
        "cql_query": args.get("cql_query", "from alert severity >= 0.6 and status='OPEN'"),
        "limit": args.get("limit", 10),
        "offset": args.get("offset", 0),
    }
    fields: str = """
            status
            reason
            alerts {
                total_results
                list {
                    id
                    tenant_id
                    status
                    suppressed
                    suppression_rules {
                      id
                      version
                    }
                    resolution_reason
                    attack_technique_ids
                    entities{
                      entities
                      relationships{
                        from_entity
                        relationship
                        to_entity
                      }
                    }
                    metadata {
                      engine {
                        name
                      }
                      creator {
                        detector {
                          version
                          detector_id
                        }
                        rule {
                          rule_id
                          version
                        }
                      }
                      title
                      description
                      confidence
                      severity
                      created_at {
                        seconds
                      }
                    }
                    investigation_ids {
                      id
                    }
                    sensor_types
                }
            }
        """

    if args.get("ids"):
        field = "alertsServiceRetrieveAlertsById"
        query = """
        query alertsServiceRetrieveAlertsById {
            alertsServiceRetrieveAlertsById(
                in: {
                    iDs: %s
                }
            ) {
                %s
            }
        }
        """ % (str(args["ids"]), fields)
    else:
        field = "alertsServiceSearch"
        query = """
        query alertsServiceSearch($cql_query: String, $limit: Int, $offset: Int) {
            alertsServiceSearch(
                in: {
                    cql_query:$cql_query,
                    offset:$offset,
                    limit:$limit
                }
            ) {
                %s
            }
        }
        """ % (fields)

    result = client.graphql_run(query=query, variables=variables)
    alerts = result["data"][field]["alerts"]["list"]

    readable_output = f'## Results\nFound {len(alerts)} alerts'

    if alerts:
        readable_output += "\n\n### Alerts\n"
        for alert in alerts:
            alert_id: str = alert['id'].replace('/', '%2F')
            readable_output += f"* [{alert['metadata']['title']}]({ENV_URLS[env]['xdr']}/alerts/{alert_id})\n"

    results = CommandResults(
        outputs_prefix="TaegisXDR.Alerts",
        outputs_key_field="id",
        outputs=alerts,
        readable_output=readable_output,
        raw_response=result,
    )

    return results


def fetch_incidents(client: Client, max_fetch: int = 15):
    """
    Fetch Taegis Investigations for the use with "Fetch Incidents"
    """
    if not 0 < int(max_fetch) < 201:
        raise ValueError("Max Fetch must be between 1 and 200")

    query = """
    query investigations(
          $page: Int,
          $perPage: Int,
          $status: [String],
          $createdAfter: String,
          $orderByField: OrderFieldInput,
          $orderDirection: OrderDirectionInput
      ) {
          allInvestigations(
              page: $page,
              perPage: $perPage,
              status: $status,
              createdAfter: $createdAfter,
              orderByField: $orderByField,
              orderDirection: $orderDirection
          ) {
            id
            tenant_id
            description
            key_findings
            assignee {
                name
                id
                email
            }
            alerts2 {
                id
                suppressed
                status
                priority {
                    value
                }
                metadata {
                    title
                    description
                    created_at {
                        seconds
                    }
                    severity
                    confidence
                }
            }
            archived_at
            created_at
            updated_at
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
        }
    }
    """

    variables = {
        "orderByField": "created_at",
        "orderDirection": "asc",
        "page": 0,
        "perPage": max_fetch,
        "status": ["Open", "Active", "Awaiting Action"]
    }

    last_run = demisto.getLastRun()
    demisto.debug(f"Last Fetch Incident Run: {last_run}")

    now = datetime.now()
    start_time = str(now - timedelta(days=1))  # Default start if first ever run
    if last_run and "start_time" in last_run:
        start_time = last_run.get("start_time")
    variables["createdAfter"] = start_time

    result = client.graphql_run(query=query, variables=variables)

    if result.get("errors") and result["errors"]:
        raise DemistoException(f"Error when fetching investigations: {result['errors'][0]['message']}")

    incidents = []
    for investigation in result["data"]["allInvestigations"]:
        # createdAfter really means createdAtOrAfter so skip the duplicate
        if start_time == investigation["created_at"]:
            continue

        # Skip archived, if necessary
        if investigation["archived_at"]:
            demisto.debug(f"Skipping Archived Investigation: {investigation['description']} ({investigation['id']})")
            continue

        demisto.debug(f"Found New Investigation: {investigation['description']} ({investigation['id']})")
        incidents.append({
            "name": investigation["description"],
            "occured": investigation["created_at"],
            "rawJSON": json.dumps(investigation)
        })

    demisto.debug(f"Located {len(incidents)} Incidents")

    last_run = str(now) if not incidents else incidents[-1]["occured"]
    demisto.debug(f"Last Run/Incident Time: {last_run}")
    demisto.setLastRun({"start_time": last_run})

    demisto.incidents(incidents)

    return incidents


def fetch_investigation_alerts_command(client: Client, env: str, args=None):
    investigation_id = args.get("id")
    page = args.get("page", 0)
    page_size = args.get("page_size", 10)
    if not investigation_id:
        raise ValueError("Cannot fetch investigation, missing investigation_id")

    query = """
    query investigationAlerts($investigation_id: ID!, $page: Int, $perPage: Int) {
        investigationAlerts(investigation_id: $investigation_id, page: $page, perPage: $perPage) {
            alerts {
                id
            }
            totalCount
        }
    }
    """

    variables = {"page": page, "perPage": page_size, "investigation_id": investigation_id}

    result = client.graphql_run(query=query, variables=variables)

    if not result.get("data"):
        readable_output = f"## Results\nCould not locate investigation '{investigation_id}'"
        alerts = []
    else:
        alerts = result["data"]["investigationAlerts"].get("alerts", [])
        readable_output = f"## Results\nFound {len(alerts)} alerts related to investigation {investigation_id}"
        if alerts:
            readable_output += "## Investigation Alerts"
        for alert in alerts:
            readable_output += f"* [{alert['id']}]({ENV_URLS[env]['xdr']}/alerts/{alert['id']})\n"

    results = CommandResults(
        outputs_prefix="TaegisXDR.InvestigationAlerts",
        outputs_key_field="id",
        outputs=alerts,
        readable_output=readable_output,
        raw_response=result,
    )

    return results


def fetch_investigation_command(client: Client, env: str, args=None):
    investigation_id = args.get("id", None)
    page = args.get("page", 0)
    page_size = args.get("page_size", 10)
    status = args.get("status", [])

    fields = """
        id
        tenant_id
        description
        key_findings
        alerts2 {
            id
            suppressed
            status
            priority {
                value
            }
            metadata {
                title
                description
                created_at {
                    seconds
                }
                severity
                confidence
            }
        }
        assignee {
            name
            id
            email
        }
        archived_at
        created_at
        updated_at
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
        query investigations($page: Int, $perPage: Int, $status: [String]) {
            allInvestigations(page: $page, perPage: $perPage, status: $status) {
                %s
            }
        }
        """ % (fields)
        variables = {"page": page, "perPage": page_size, "status": status}
        result = client.graphql_run(query=query, variables=variables)

    try:
        outputs = [result["data"]["investigation"]] if investigation_id else result["data"]["allInvestigations"]
    except KeyError:
        outputs = []

    readable_output = f"## Results\nFound {len(outputs)} investigation(s)"

    for investigation in outputs:
        readable_output += f"""\n\n### [{investigation['description']}]({ENV_URLS[env]['xdr']}/investigations/{investigation["id"]})
* ID: {investigation['id']}
* Priority: {investigation['priority']}
* Status: {investigation['status']}
"""

    results = CommandResults(
        outputs_prefix="TaegisXDR.Investigations",
        outputs_key_field="id",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=result,
    )

    return results


def fetch_playbook_execution_command(client: Client, env: str, args=None):
    execution_id = args.get("id")
    if not execution_id:
        raise ValueError("Cannot fetch playbook execution, missing execution id")

    query = """
    query playbookExecution($playbookExecutionId: ID!) {
      playbookExecution(playbookExecutionId: $playbookExecutionId) {
        id
        state
        instance {
          name
          playbook {
              name
          }
        }
        inputs
        createdAt
        updatedAt
        executionTime
        outputs
      }
    }
    """

    variables = {
        "playbookExecutionId": execution_id
    }

    result = client.graphql_run(query=query, variables=variables)

    if not result.get("data"):
        readable_output = f"## Results\n* Could not locate execution '{execution_id}': {result['errors'][0]['message']}"
        outputs = {}
    else:
        execution = result['data']["playbookExecution"]
        execution_url = f"{ENV_URLS[env]['xdr']}/automations/playbook-executions/{execution['id']}"
        readable_output = f"""
## Results
* Playbook Name: {execution['instance']['playbook']['name']}
* Playbook Instance Name: {execution['instance']['name']}
* Executed Playbook Instance: [{execution['id']}]({execution_url})
* Executed Time: {execution['createdAt']}
* Run Time: {execution['executionTime']}
* Execution State: {execution['state']}
* Execution Outputs:

```
{execution['outputs']}
```
"""
        outputs = result["data"]["playbookExecution"]

    results = CommandResults(
        outputs_prefix="TaegisXDR.PlaybookExecution",
        outputs_key_field="id",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=result,
    )

    return results


def update_investigation_command(client: Client, env: str, args=None):
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
                f"The provided status, {args['status']}, is not valid for updating an investigation. "
                f"Supported Status Values: {INVESTIGATION_STATUSES}"))

        variables["investigation"][field] = args.get(field)

    if not variables["investigation"]:
        raise ValueError(f"No valid investigation fields provided. Supported Update Fields: {INVESTIGATION_UPDATE_FIELDS}")

    result = client.graphql_run(query=query, variables=variables)

    investigation_url = f"{ENV_URLS[env]['xdr']}/investigations/{result['data']['updateInvestigation']['id']}"
    readable_output = f"## Results\n* Updated Investigation: [{result['data']['updateInvestigation']['id']}]({investigation_url})"
    outputs = result["data"]["updateInvestigation"]

    results = CommandResults(
        outputs_prefix="TaegisXDR.InvestigationUpdate",
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
        "fetch-incidents": fetch_incidents,
        "taegis-create-investigation": create_investigation_command,
        "taegis-execute-playbook": execute_playbook_command,
        "taegis-fetch-alerts": fetch_alerts_command,
        "taegis-fetch-investigation": fetch_investigation_command,
        "taegis-fetch-investigation-alerts": fetch_investigation_alerts_command,
        "taegis-fetch-playbook-execution": fetch_playbook_execution_command,
        "taegis-update-investigation": update_investigation_command,
        "test-module": test_module,
    }

    PARAMS = demisto.params()
    try:
        if command not in commands:
            raise NotImplementedError(f'The "{command}" command has not been implemented.')

        environment = PARAMS.get("environment", "us1").lower()
        if not ENV_URLS.get(environment):
            raise ValueError(f"Unknown Environment Provided: {environment}")

        verify_cert = not PARAMS.get("insecure", False)

        client = Client(
            client_id=PARAMS.get("client_id"),
            client_secret=PARAMS.get("client_secret"),
            base_url=ENV_URLS[environment]["api"],
            proxy=PARAMS.get("proxy", False),
            verify=verify_cert,
        )
        client.auth()

        if command == "test-module":
            result = commands[command](client=client)
            return_results(result)

        elif command == "fetch-incidents":
            commands[command](client=client, max_fetch=PARAMS.get("max_fetch"))
        else:
            return_results(commands[command](client=client, env=environment, args=demisto.args()))
    except Exception as e:
        error_string = str(e)
        demisto.error(f"Error running command: {e}")

        if "Unauthorized" in error_string:
            error_string = "Invalid credentials (Client ID or Client Secret)"
        return_error(f"Failed to execute {command} command. Error: {error_string}")


""" ENTRY POINT """
if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
