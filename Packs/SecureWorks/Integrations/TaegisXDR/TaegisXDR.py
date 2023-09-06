import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Any, Dict


""" CONSTANTS """


AUTH_ENDPOINT = "/auth/api/v2/auth/token"
GRAPHQL_ENDPOINT = "/graphql"

ENV_URLS = {
    "us1": {"api": "https://api.ctpx.secureworks.com", "xdr": "https://ctpx.secureworks.com"},
    "us2": {"api": "https://api.delta.taegis.secureworks.com", "xdr": "https://delta.taegis.secureworks.com"},
    "eu": {"api": "https://api.echo.taegis.secureworks.com", "xdr": "https://echo.taegis.secureworks.com"},
}

ALERT_STATUSES = set((
    "FALSE_POSITIVE",
    "NOT_ACTIONABLE",
    "OPEN",
    "TRUE_POSITIVE_BENIGN",
    "TRUE_POSITIVE_MALICIOUS",
))
ASSET_SEARCH_FIELDS = ((
    "endpoint_type",
    "host_id",
    "hostname",
    "investigation_id",
    "ip_address",
    "mac_address",
    "os_family",
    "os_version",
    "sensor_version",
    "username",
))
COMMENT_TYPES = set((
    "investigation",
))
INVESTIGATION_STATUSES = set((
    "Open",
    "Active",
    "Awaiting Action",
    "Suspended",
    "Closed: Authorized Activity",
    "Closed: Confirmed Security Incident",
    "Closed: False Positive Alert",
    "Closed: Inconclusive",
    "Closed: Informational",
    "Closed: Not Vulnerable",
    "Closed: Threat Mitigated",
))
INVESTIGATION_UPDATE_FIELDS = set(("key_findings", "priority", "status", "service_desk_id", "service_desk_type", "assignee_id"))


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


def create_comment_command(client: Client, env: str, args=None):
    if not args.get("comment"):
        raise ValueError("Cannot create comment, comment cannot be empty")

    if not args.get("parent_id"):
        raise ValueError("Cannot create comment, parent_id cannot be empty")

    parent_type = args.get("parent_type", "investigation").lower()
    if parent_type not in COMMENT_TYPES:
        raise ValueError(
            f"The provided comment parent type, {parent_type}, is not valid. "
            f"Supported Parent Types Values: {COMMENT_TYPES}"
        )

    query = """
    mutation createComment ($comment: CommentInput!) {
        createComment(comment: $comment) {
            id
        }
    }
    """

    variables = {
        "comment": {
            "comment": args.get("comment"),
            "parent_id": args.get("parent_id"),
            "parent_type": parent_type,
            "section_id": args.get("section_id", ""),
            "section_type": args.get("section_type", ""),
        }
    }

    result = client.graphql_run(query=query, variables=variables)

    try:
        comment = result["data"]["createComment"]
    except (KeyError, TypeError):
        raise ValueError(f"Failed to create comment: {result['errors'][0]['message']}")

    results = CommandResults(
        outputs_prefix="TaegisXDR.CommentCreate",
        outputs_key_field="id",
        outputs=comment,
        readable_output=tableToMarkdown(
            "Taegis Comment",
            comment,
            removeNull=True,
        ),
        raw_response=result,
    )

    return results


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

    try:
        investigation = result["data"]["createInvestigation"]
        investigation["url"] = generate_id_url(env, "investigations", investigation["id"])
    except (KeyError, TypeError):
        raise ValueError(f"Failed to create investigation: {result['errors'][0]['message']}")

    results = CommandResults(
        outputs_prefix="TaegisXDR.Investigation",
        outputs_key_field="id",
        outputs=investigation,
        readable_output=tableToMarkdown(
            "Taegis Investigation",
            investigation,
            removeNull=True,
            url_keys=("url"),
        ),
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

    execution = result["data"]["executePlaybookInstance"]
    execution["url"] = generate_id_url(env, "automations/playbook-executions", execution["id"])

    results = CommandResults(
        outputs_prefix="TaegisXDR.Execution",
        outputs_key_field="id",
        outputs=execution,
        readable_output=tableToMarkdown(
            "Taegis Playbook Execution",
            execution,
            removeNull=True,
            url_keys=("url"),
        ),
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
        "ids": args.get("ids", []),  # ["alerts://id1", "alerts://id2"]
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
        query alertsServiceRetrieveAlertsById($ids: [String!]) {
            alertsServiceRetrieveAlertsById(
                in: {
                    iDs: $ids
                }
            ) {
                %s
            }
        }
        """ % (fields)

        if type(variables["ids"]) == str:
            variables["ids"] = variables["ids"].split(",")  # alerts://id1,alerts://id2
        variables["ids"] = [x.strip() for x in variables["ids"]]  # Ensure no whitespace
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

    for alert in alerts:
        alert.update({"url": generate_id_url(env, "alerts", alert["id"])})

    results = CommandResults(
        outputs_prefix="TaegisXDR.Alerts",
        outputs_key_field="id",
        outputs=alerts,
        readable_output=tableToMarkdown(
            "Taegis Alerts",
            alerts,
            removeNull=True,
            url_keys=("url"),
        ),
        raw_response=result,
    )

    return results


def fetch_assets_command(client: Client, env: str, args=None):
    page = arg_to_number(args.get("page")) or 0
    page_size = arg_to_number(args.get("page_size")) or 10

    variables: Dict[str, Any] = {
        "input": {},
        "pagination_input": {
            "limit": page_size,
            "offset": page_size * page,
        }
    }

    # Loop over allowed search fields and add valid search options to the query variables
    for field in ASSET_SEARCH_FIELDS:
        if args.get(field):
            variables["input"][field] = args.get(field).strip()

    query = """
    query searchAssetsV2($input: SearchAssetsInput!, $pagination_input: SearchAssetsPaginationInput!) {
         searchAssetsV2(input: $input, paginationInput:$pagination_input) {
           assets {
              id
              ingestTime
              createdAt
              updatedAt
              deletedAt
              biosSerial
              firstDiskSerial
              systemVolumeSerial
              sensorVersion
              endpointPlatform
              architecture
              osFamily
              osVersion
              osDistributor
              osRelease
              systemType
              osCodename
              kernelRelease
              kernelVersion
              hostnames {
                id
                hostname
              },
              tags {
                key
                tag
              }
              endpointType
              hostId
              sensorId
            }
          }
        }
    """

    result = client.graphql_run(query=query, variables=variables)
    try:
        assets = result["data"]["searchAssetsV2"]["assets"]
    except (KeyError, TypeError):
        raise ValueError(f"Failed to fetch assets: {result['errors'][0]['message']}")

    results = CommandResults(
        outputs_prefix="TaegisXDR.Assets",
        outputs_key_field="id",
        outputs=assets,
        readable_output=tableToMarkdown(
            "Taegis Assets",
            assets,
            removeNull=True,
        ),
        raw_response=result,
    )

    return results


def fetch_comment_command(client: Client, env: str, args=None):
    comment_id = args.get("id")
    if not comment_id:
        raise ValueError("Cannot fetch comment, missing comment_id")

    query = """
    query comment ($comment_id: ID!) {
        comment(comment_id: $comment_id) {
            author_user {
                id
                family_name
                given_name
                email_normalized
            }
            id
            comment
            modified_at
            deleted_at
            created_at
            parent_id
            parent_type
        }
    }
    """

    variables = {"comment_id": comment_id}

    result = client.graphql_run(query=query, variables=variables)

    try:
        comment = result["data"]["comment"]
    except (KeyError, TypeError):
        raise ValueError("Could not locate comment by provided ID")

    results = CommandResults(
        outputs_prefix="TaegisXDR.Comment",
        outputs_key_field="id",
        outputs=comment,
        readable_output=tableToMarkdown(
            "Taegis Comment",
            comment,
            removeNull=True,
        ),
        raw_response=result,
    )

    return results


def fetch_comments_command(client: Client, env: str, args=None):
    if not args.get("parent_id"):
        raise ValueError("Cannot fetch comments, missing parent_id")

    parent_type = args.get("parent_type", "investigation")
    if parent_type not in COMMENT_TYPES:
        raise ValueError((
            f"The provided comment parent type, {parent_type}, is not valid. "
            f"Supported Parent Types Values: {parent_type}"
        ))

    query = """
    query commentsByParent ($parent_type: String!, $parent_id: String!) {
        commentsByParent(parent_type: $parent_type,parent_id:$parent_id) {
            author_user {
                id
                family_name
                given_name
                email_normalized
            }
            id
            comment
            modified_at
            deleted_at
            created_at
            parent_id
            parent_type
        }
    }
    """

    variables = {
        "parent_id": args.get("parent_id"),
        "parent_type": parent_type
    }

    result = client.graphql_run(query=query, variables=variables)

    try:
        comments = result["data"]["commentsByParent"]
    except (KeyError, TypeError):
        raise ValueError(f"Failed to fetch comments: {result['errors'][0]['message']}")

    results = CommandResults(
        outputs_prefix="TaegisXDR.Comments",
        outputs_key_field="id",
        outputs=comments,
        readable_output=tableToMarkdown(
            "Taegis Comments",
            comments,
            removeNull=True,
        ),
        raw_response=result,
    )

    return results


def fetch_endpoint_command(client: Client, env: str, args=None):
    if not args.get("id"):
        raise ValueError("Cannot fetch endpoint information, missing id")

    variables: Dict[str, Any] = {
        "id": args.get("id")
    }

    query = """
    query assetEndpointInfo($id: ID!) {
      assetEndpointInfo(id: $id) {
        hostId
        hostName
        actualIsolationStatus
        allowedDomain
        desiredIsolationStatus
        firstConnectTime
        moduleHealth {
            enabled
            lastRunningTime
            moduleDisplayName
        }
        lastConnectAddress
        lastConnectTime
        sensorVersion
      }
    }
    """

    result = client.graphql_run(query=query, variables=variables)
    try:
        endpoint = result["data"]["assetEndpointInfo"]
    except (KeyError, TypeError):
        raise ValueError(f"Failed to fetch endpoint information: {result['errors'][0]['message']}")

    results = CommandResults(
        outputs_prefix="TaegisXDR.Endpoint",
        outputs_key_field="hostId",
        outputs=endpoint,
        readable_output=tableToMarkdown(
            "Taegis Endpoint",
            endpoint,
            removeNull=True,
        ),
        raw_response=result,
    )

    return results


def fetch_incidents(client: Client, max_fetch: int = 15, include_assets: bool = True):
    """
    Fetch Taegis Investigations for the use with "Fetch Incidents"
    """
    if not 0 < int(max_fetch) < 201:
        raise ValueError("Max Fetch must be between 1 and 200")

    asset_query = ""
    if include_assets:
        demisto.debug("include_assets=True, fetching assets with investigation")
        asset_query = "assets {id hostnames {id hostname} tags {tag}}"

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
            %s
        }
    }
    """ % (asset_query)

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
            alerts2 {
                id
            }
            totalCount
        }
    }
    """

    variables = {"page": page, "perPage": page_size, "investigation_id": investigation_id}
    result = client.graphql_run(query=query, variables=variables)

    try:
        alerts = result["data"]["investigationAlerts"]["alerts"]
    except (KeyError, TypeError):
        alerts = []

    for alert in alerts:
        alert.update({"url": generate_id_url(env, "alerts", alert["id"])})

    results = CommandResults(
        outputs_prefix="TaegisXDR.InvestigationAlerts",
        outputs_key_field="id",
        outputs=alerts,
        readable_output=tableToMarkdown(
            "Taegis Investigation Alerts",
            alerts,
            removeNull=True,
            url_keys=("url"),
        ),
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
        genesis_alerts2 {
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
        investigations = [result["data"]["investigation"]] if investigation_id else result["data"]["allInvestigations"]
    except (KeyError, TypeError):
        investigations = []

    for investigation in investigations:
        investigation.update({"url": generate_id_url(env, "investigations", investigation["id"])})

    results = CommandResults(
        outputs_prefix="TaegisXDR.Investigations",
        outputs_key_field="id",
        outputs=investigations,
        readable_output=tableToMarkdown(
            "Taegis Investigations",
            investigations,
            removeNull=True,
            url_keys=("url"),
        ),
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

    try:
        execution = result['data']["playbookExecution"]
        execution["url"] = generate_id_url(env, "automations/playbook-executions", execution["id"])
    except (KeyError, TypeError):
        raise ValueError(f"Failed to fetch playbook execution: {result['errors'][0]['message']}")

    results = CommandResults(
        outputs_prefix="TaegisXDR.PlaybookExecution",
        outputs_key_field="id",
        outputs=execution,
        readable_output=tableToMarkdown(
            "Taegis Playbook Execution",
            execution,
            removeNull=True,
            url_keys=("url"),
        ),
        raw_response=result,
    )

    return results


def fetch_users_command(client: Client, env: str, args=None):
    page = int(args.get("page", 0))
    page_size = int(args.get("page_size", 10))

    variables: Dict[str, Any] = {
        "filters": {
            "status": args.get("status", ""),
            "perPage": page_size,
            "pageOffset": page_size * page,
        }
    }
    fields = "user_id email family_name given_name status"
    if args.get("id"):
        if not args["id"].startswith("auth0"):
            raise ValueError("id MUST be in 'auth0|12345' format")

        query = """
        query ($ids: [String!]) {
            tdrusersByIDs (userIDs: $ids) {
                %s
            }
        }
        """ % (fields)
        variables = {"ids": [args["id"]]}
    else:
        query = """
        query ($filters: TDRUsersSearchInput) {
            tdrUsersSearch (filters: $filters) {
                results {
                    %s
                }
            }
        }
        """ % (fields)

    if args.get("email"):
        variables["filters"]["emails"] = args["email"]

    result = client.graphql_run(query=query, variables=variables)

    try:
        if args.get("id"):
            user = result["data"]["tdrusersByIDs"]
        else:
            user = result["data"]["tdrUsersSearch"]["results"]
    except (KeyError, TypeError):
        raise ValueError(f"Failed to fetch user information: {result['errors'][0]['message']}")

    results = CommandResults(
        outputs_prefix="TaegisXDR.Users",
        outputs_key_field="user_id",
        outputs=user,
        readable_output=tableToMarkdown(
            "Taegis Users",
            user,
            removeNull=True,
        ),
        raw_response=result,
    )

    return results


def isolate_asset_command(client: Client, env: str, args=None):
    if not args.get("id"):
        raise ValueError("Cannot isolate asset, missing id")
    if not args.get("reason"):
        raise ValueError("Cannot isolate asset, missing reason")

    variables: Dict[str, Any] = {
        "id": args.get("id"),
        "reason": args.get("reason")
    }

    query = """
    mutation isolateAsset ($id: ID!, $reason: String!) {
      isolateAsset (id: $id, reason: $reason) {
        id
      }
    }
    """

    result = client.graphql_run(query=query, variables=variables)

    try:
        isolation = result["data"]["isolateAsset"]
    except (KeyError, TypeError):
        raise ValueError(f"Failed to isolate asset: {result['errors'][0]['message']}")

    results = CommandResults(
        outputs_prefix="TaegisXDR.AssetIsolation",
        outputs_key_field="id",
        outputs=isolation,
        readable_output=tableToMarkdown(
            "Taegis Asset Isolation",
            isolation,
            removeNull=True,
        ),
        raw_response=result,
    )

    return results


def update_alert_status_command(client: Client, env: str, args=None):
    if not args.get("ids"):
        raise ValueError("Alert IDs must be defined")
    if not args.get("status"):
        raise ValueError("Alert status must be defined")

    if args.get("status").upper() not in ALERT_STATUSES:
        raise ValueError((
            f"The provided status, {args['status']}, is not valid for updating an alert. "
            f"Supported Status Values: {ALERT_STATUSES}"))

    variables = {
        "alert_ids": argToList(args.get("ids")),
        "reason": args.get("reason", ""),
        "resolution_status": args.get("status"),
    }

    query = """
    mutation alertsServiceUpdateResolutionInfo($alert_ids: [String!], $reason: String, $resolution_status: ResolutionStatus) {
      alertsServiceUpdateResolutionInfo(
        in: {
          alert_ids: $alert_ids,
            reason: $reason,
            resolution_status: $resolution_status
        }
      ) {
        resolution_status
        reason
      }
    }
    """
    result = client.graphql_run(query=query, variables=variables)

    try:
        update_result = result["data"]["alertsServiceUpdateResolutionInfo"]
    except (KeyError, TypeError):
        raise ValueError(f"Failed to locate/update alert: {result['errors'][0]['message']}")

    results = CommandResults(
        outputs_prefix="TaegisXDR.AlertStatusUpdate",
        outputs_key_field="status",
        outputs=update_result,
        readable_output=tableToMarkdown(
            "Taegis Alert Update",
            update_result,
            removeNull=True,
        ),
        raw_response=result,
    )

    return results


def update_comment_command(client: Client, env: str, args=None):
    if not args.get("id"):
        raise ValueError("Cannot update comment, comment id cannot be empty")

    if not args.get("comment"):
        raise ValueError("Cannot update comment, comment cannot be empty")

    query = """
    mutation updateComment ($comment_id: ID!, $comment: CommentUpdate!) {
        updateComment(comment_id: $comment_id, comment: $comment) {
            id
        }
    }
    """
    variables = {
        "comment_id": args.get("id"),
        "comment": {
            "comment": args.get("comment")
        },
    }

    result = client.graphql_run(query=query, variables=variables)

    try:
        comment = result["data"]["updateComment"]
    except (KeyError, TypeError):
        raise ValueError(f"Failed to locate/update comment: {result['errors'][0]['message']}")

    results = CommandResults(
        outputs_prefix="TaegisXDR.CommentUpdate",
        outputs_key_field="id",
        outputs=comment,
        readable_output=tableToMarkdown(
            "Taegis Comment",
            comment,
            removeNull=True,
        ),
        raw_response=result,
    )

    return results


def update_investigation_command(client: Client, env: str, args=None):
    investigation_id = args.get("id")
    if not investigation_id:
        raise ValueError("Cannot fetch investigation without investigation_id defined")

    if args.get("assignee_id"):
        if not args["assignee_id"].startswith("auth0") and args["assignee_id"] != "@secureworks":
            raise ValueError("assignee_id MUST be in 'auth0|12345' format or '@secureworks'")

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

    try:
        investigation = result["data"]["updateInvestigation"]
        investigation["url"] = generate_id_url(env, "investigations", investigation["id"])
    except (KeyError, TypeError):
        raise ValueError(f"Failed to locate/update investigation: {result['errors'][0]['message']}")

    results = CommandResults(
        outputs_prefix="TaegisXDR.InvestigationUpdate",
        outputs_key_field="id",
        outputs=investigation,
        readable_output=tableToMarkdown(
            "Taegis Investigation",
            investigation,
            removeNull=True,
            url_keys=("url"),
        ),
        raw_response=result,
    )

    return results


def archive_investigation_command(client: Client, env: str, args=None):
    investigation_id = args.get("id")
    if not investigation_id:
        raise ValueError("Cannot archive investigation, missing investigation id")

    query = """
    mutation ($investigation_id: ID!) {
      archiveInvestigation(investigation_id: $investigation_id) {
        id
      }
    }
    """

    variables = {"investigation_id": investigation_id}
    result = client.graphql_run(query=query, variables=variables)
    try:
        investigation = result["data"]["archiveInvestigation"]
        status = "Successfully Archived Investigation"
    except (KeyError, TypeError):
        raise ValueError(f"Could not locate investigation with id: {investigation_id}")

    archive_results = {
        "id": investigation_id,
        "result": investigation,
        "status": status,
        "url": generate_id_url(env, "investigations", investigation_id),
    }

    results = CommandResults(
        outputs_prefix="TaegisXDR.ArchivedInvestigation",
        outputs_key_field="id",
        outputs=archive_results,
        readable_output=tableToMarkdown(
            "Taegis Investigation Archiving",
            archive_results,
            removeNull=True,
            url_keys=("url"),
        ),
        raw_response=result,
    )

    return results


def unarchive_investigation_command(client: Client, env: str, args=None):
    investigation_id = args.get("id")
    if not investigation_id:
        raise ValueError("Cannot unarchive investigation, missing investigation id")

    query = """
    mutation ($investigation_id: ID!) {
      unArchiveInvestigation(investigation_id: $investigation_id) {
        id
      }
    }
    """

    variables = {"investigation_id": investigation_id}
    result = client.graphql_run(query=query, variables=variables)
    try:
        investigation = result["data"]["unArchiveInvestigation"]
        status = "Successfully Unarchived Investigation"
    except (KeyError, TypeError):
        if result["errors"][0].get("message"):
            investigation = {}
            status = "Investigation is not currently archived"
        else:
            raise ValueError(f"Could not locate investigation with id: {investigation_id}")

    archive_results = {
        "id": investigation_id,
        "result": investigation,
        "status": status,
        "url": generate_id_url(env, "investigations", investigation_id),
    }

    results = CommandResults(
        outputs_prefix="TaegisXDR.UnarchivedInvestigation",
        outputs_key_field="id",
        outputs=archive_results,
        readable_output=tableToMarkdown(
            "Taegis Investigation Unarchiving",
            archive_results,
            removeNull=True,
            url_keys=("url"),
        ),
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


""" UTILITIES """


def generate_id_url(env: str, endpoint: str, element_id: str):
    element_id: str = element_id.replace('/', '%2F')
    return f"{ENV_URLS[env]['xdr']}/{endpoint}/{element_id}"


""" MAIN """


def main():
    command = demisto.command()
    demisto.info(f'Command being called is {command}')

    commands: Dict[str, Any] = {
        "fetch-incidents": fetch_incidents,
        "taegis-create-comment": create_comment_command,
        "taegis-create-investigation": create_investigation_command,
        "taegis-execute-playbook": execute_playbook_command,
        "taegis-fetch-alerts": fetch_alerts_command,
        "taegis-fetch-assets": fetch_assets_command,
        "taegis-fetch-comment": fetch_comment_command,
        "taegis-fetch-comments": fetch_comments_command,
        "taegis-fetch-endpoint": fetch_endpoint_command,
        "taegis-fetch-investigation": fetch_investigation_command,
        "taegis-fetch-investigation-alerts": fetch_investigation_alerts_command,
        "taegis-fetch-playbook-execution": fetch_playbook_execution_command,
        "taegis-fetch-users": fetch_users_command,
        "taegis-isolate-asset": isolate_asset_command,
        "taegis-update-alert-status": update_alert_status_command,
        "taegis-update-comment": update_comment_command,
        "taegis-update-investigation": update_investigation_command,
        "taegis-archive-investigation": archive_investigation_command,
        "taegis-unarchive-investigation": unarchive_investigation_command,
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
            commands[command](client=client, max_fetch=PARAMS.get("max_fetch"), include_assets=PARAMS.get("include_assets"))
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
