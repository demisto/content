from typing import Any

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

""" CONSTANTS """


AUTH_ENDPOINT = "/auth/api/v2/auth/token"
GRAPHQL_ENDPOINT = "/graphql"

ENV_URLS = {
    "us1 (charlie)": {"api": "https://api.ctpx.secureworks.com", "xdr": "https://ctpx.secureworks.com"},
    "us2 (delta)": {"api": "https://api.delta.taegis.secureworks.com", "xdr": "https://delta.taegis.secureworks.com"},
    "us3 (foxtrot)": {"api": "https://api.foxtrot.taegis.secureworks.com", "xdr": "https://foxtrot.taegis.secureworks.com"},
    "eu (echo)": {"api": "https://api.echo.taegis.secureworks.com", "xdr": "https://echo.taegis.secureworks.com"},
}

ALERT_STATUSES = {
    "FALSE_POSITIVE",
    "NOT_ACTIONABLE",
    "OPEN",
    "TRUE_POSITIVE_BENIGN",
    "TRUE_POSITIVE_MALICIOUS",
    "OTHER",
    "SUPPRESSED",
}
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
COMMENT_TYPES = {
    "investigation",
}
INVESTIGATION_STATUSES = {
    "OPEN",
    "ACTIVE",
    "AWAITING_ACTION",
    "SUSPENDED",
    "CLOSED_AUTHORIZED_ACTIVITY",
    "CLOSED_CONFIRMED_SECURITY_INCIDENT",
    "CLOSED_FALSE_POSITIVE_ALERT",
    "CLOSED_INCONCLUSIVE",
    "CLOSED_INFORMATIONAL",
    "CLOSED_NOT_VULNERABLE",
    "CLOSED_THREAT_MITIGATED",
}
INVESTIGATION_TYPES = {
    "SECURITY_INVESTIGATION",
    "INCIDENT_RESPONSE",
    "THREAT_HUNT",
    "MANAGED_XDR_THREAT_HUNT",
    "CTU_THREAT_HUNT",
    "MANAGED_XDR_ELITE_THREAT_HUNT",
    "SECUREWORKS_INCIDENT_RESPONSE",
}
INVESTIGATION_UPDATE_FIELDS = {
    "keyFindings",
    "priority",
    "status",
    "assigneeId",
    "title",
    "type",
    "serviceDeskId",
    "serviceDeskType",
    "tags",
}
SHARELINK_TYPES = {
    "alertId",
    "connectorId",
    "connectionId",
    "endpointDetails",
    "eventId",
    "investigationId",
    "queryId",
    "playbookTemplateId",
    "playbookInstanceId",
    "playbookExecutionId",
}

DEFAULT_FIRST_FETCH_INTERVAL = "1 day"


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
        tenant_id: str = "",
    ) -> None:
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.base_url = base_url
        self._client_id = client_id
        self._client_secret = client_secret
        self.verify = verify
        self.tenant_id = tenant_id

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
        self._auth_header = {
            "Authorization": f"Bearer {token}",
            "x-tenant-context": self.tenant_id,
        }

    def graphql_run(self, query: str, variables: dict[str, Any] = None):
        """Perform a GraphQL query

        :type query: ``str``
        :param query: The GraphQL query

        :type variables: ``Dict[str, Any]``
        :param variables: The variables to utilize with the query
        """
        json_data: dict[str, Any] = {"query": query}

        if variables:
            json_data["variables"] = variables

        response = self._http_request(
            method="POST",
            url_suffix=GRAPHQL_ENDPOINT,
            json_data=json_data,
            headers=self._auth_header,
        )
        return response

    def test(self) -> dict[str, Any]:
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


def add_evidence_to_investigation_command(client: Client, env: str, args=None):
    """
    Add events or alert evidence to an investigation
    """

    if not args.get("id"):
        raise ValueError("Cannot add evidence to investigation, id cannot be empty")
    if not args.get("alerts") and not args.get("events") and not args.get("alert_query"):
        raise ValueError("Cannot add evidence to investigation. alerts, events, or alert_query must be defined")

    variables: dict = {
        "input": {
            "investigationId": args.get("id"),
            "alerts": argToList(args.get("alerts")),
            "events": argToList(args.get("events")),
            "alertsSearchQuery": args.get("alert_query", ""),
        }
    }

    fields: str = args.get("fields") or "investigationId"

    query = """
    mutation addEvidenceToInvestigation($input: AddEvidenceToInvestigationInput!) {
      addEvidenceToInvestigation(input: $input) {
        %s
      }
    }
    """ % (fields)

    result = client.graphql_run(query=query, variables=variables)
    try:
        investigation = result["data"]["addEvidenceToInvestigation"]
        investigation["url"] = generate_id_url(env, "investigations", investigation["investigationId"])
    except (KeyError, TypeError):
        raise ValueError(f"Failed to create investigation: {result['errors'][0]['message']}")

    results = CommandResults(
        outputs_prefix="TaegisXDR.InvestigationEvidenceUpdate",
        outputs_key_field="investigationId",
        outputs=investigation,
        readable_output=tableToMarkdown(
            "Taegis Investigation Evidence",
            investigation,
            removeNull=True,
            url_keys=("url"),
        ),
        raw_response=result,
    )

    return results


def create_comment_command(client: Client, env: str, args=None):
    if not args.get("comment"):
        raise ValueError("Cannot create comment, comment cannot be empty")

    if not args.get("id"):
        raise ValueError("Cannot create comment, id cannot be empty")

    fields: str = args.get("fields") or "id"

    query = """
    mutation addCommentToInvestigation($input: AddCommentToInvestigationInput!) {
        addCommentToInvestigation(input: $input) {
            %s
        }
    }
    """ % (fields)

    variables = {
        "input": {
            "comment": args.get("comment"),
            "investigationId": args.get("id"),
        }
    }

    result = client.graphql_run(query=query, variables=variables)

    try:
        comment = result["data"]["addCommentToInvestigation"]
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
    fields: str = args.get("fields") or "id shortId"
    query = """
    mutation ($input: CreateInvestigationInput!) {
    createInvestigationV2(input: $input) {
            %s
        }
    }
    """ % (fields)

    variables = {
        "input": {
            "title": args.get("title"),
            "priority": arg_to_number(args.get("priority", 3)),
            "status": args.get("status", "OPEN"),
            "alerts": argToList(args.get("alerts")),
            "keyFindings": args.get("key_findings", ""),
            "type": args.get("type", "SECURITY_INVESTIGATION"),
            "assigneeId": args.get("assignee_id", "@secureworks"),
            "tags": argToList(args.get("tags")),
        }
    }

    if not variables["input"]["assigneeId"].startswith("auth0") and variables["input"]["assigneeId"] != "@secureworks":
        raise ValueError("assigneeId MUST be in 'auth0|12345' format or '@secureworks'")
    if variables["input"]["priority"] and not 0 < variables["input"]["priority"] < 5:
        raise ValueError("Priority must be between 1-4")
    if variables["input"]["status"] not in INVESTIGATION_STATUSES:
        raise ValueError(
            f"The provided status, {variables['input']['status']}, is not valid for updating an investigation. "
            f"Supported Status Values: {INVESTIGATION_STATUSES}")
    if variables["input"]["type"] not in INVESTIGATION_TYPES:
        raise ValueError(
            f"The provided type, {variables['input']['type']}, is not valid for updating an investigation. "
            f"Supported Type Values: {INVESTIGATION_TYPES}")
    if not variables["input"]["title"]:
        raise ValueError("Title must be defined")

    result = client.graphql_run(query=query, variables=variables)

    try:
        investigation = result["data"]["createInvestigationV2"]
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


def create_sharelink_command(client: Client, env: str, args=None):
    """
    Create a ShareLink to an investigation or alert
    """

    if not args.get("id"):
        raise ValueError("Cannot create ShareLink, id cannot be empty")
    if not args.get("type"):
        raise ValueError("Cannot create ShareLink, type cannot be empty")
    if args["type"] not in SHARELINK_TYPES:
        raise ValueError(
            f"The provided ShareLink type, {args['type']}, is not valid for creating a ShareLink. "
            f"Supported Type Values: {SHARELINK_TYPES}")

    variables: dict = {
        "sharelink": {
            "linkRef": args["id"],
            "linkType": args["type"],
        }
    }

    if args.get("tenant_id"):
        variables["tenant_id"] = args["tenant_id"]

    fields: str = args.get("fields") or "id createdTime"

    query = """
    mutation ($sharelink: ShareLinkCreateInput!) {
        createShareLink (input: $sharelink) {
            %s
        }
    }
    """ % (fields)

    result = client.graphql_run(query=query, variables=variables)
    try:
        link_result = result["data"]["createShareLink"]
    except (KeyError, TypeError):
        raise ValueError(f"Failed to create ShareLink: {result['errors'][0]['message']}")

    link_result.update({"url": generate_id_url(env, "share", link_result["id"])})

    results = CommandResults(
        outputs_prefix="TaegisXDR.ShareLink",
        outputs_key_field="id",
        outputs=link_result,
        readable_output=tableToMarkdown(
            "Taegis ShareLink",
            link_result,
            url_keys=("url"),
        ),
        raw_response=result,
    )

    return results


def execute_playbook_command(client: Client, env: str, args=None):
    playbook_id = args.get("id")
    if not playbook_id:
        raise ValueError("Cannot execute playbook, missing playbook_id")

    fields: str = args.get("fields") or "id"
    query = """
    mutation executePlaybookInstance(
        $playbookInstanceId: ID!
        $parameters: JSONObject
    ) {
        executePlaybookInstance(
            playbookInstanceId: $playbookInstanceId
            parameters: $parameters
        ) {
            %s
        }
    }
    """ % (fields)

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
        "cql_query": args.get("cql_query", "from alert severity >= 0.4 and status='OPEN'"),
        "limit": arg_to_number(args.get("limit", 10)),
        "offset": arg_to_number(args.get("offset", 0)),
        "ids": args.get("ids", []),  # ["alert://id1", "alert://id2"]
    }
    fields: str = args.get("fields") or """
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
                event_ids {
                  id
                  event_data
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

        variables["ids"] = argToList(variables["ids"])
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

    variables: dict[str, Any] = {
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

    fields: str = args.get("fields") or """
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
        """
    query = """
    query searchAssetsV2($input: SearchAssetsInput!, $pagination_input: SearchAssetsPaginationInput!) {
         searchAssetsV2(input: $input, paginationInput:$pagination_input) {
           assets {
              %s
            }
          }
        }
    """ % (fields)

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

    fields: str = args.get("fields") or """
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
        """

    query = """
    query comment ($comment_id: ID!) {
        comment(comment_id: $comment_id) {
            %s
        }
    }
    """ % (fields)

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
    if not args.get("id"):
        raise ValueError("Cannot fetch comments, missing id")

    fields: str = args.get("fields") or """
        author {
            id
            family_name
            given_name
            email_normalized
        }
        authorId
        id
        comment
        createdAt
        updatedAt
        """

    query = """
    query commentsV2 ($arguments: CommentsV2Arguments!) {
        commentsV2(arguments: $arguments) {
            comments {
                %s
            }
        }
    }
    """ % (fields)

    variables = {
        "arguments": {
            "investigationId": args.get("id"),
            "page": arg_to_number(args.get("page", 0)),
            "perPage": arg_to_number(args.get("page_size", 10)),
            "orderBy": args.get("order_direction", "DESCENDING")
        }
    }

    result = client.graphql_run(query=query, variables=variables)

    try:
        comments = result["data"]["commentsV2"]["comments"]
    except (KeyError, TypeError):
        comments = []

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

    variables: dict[str, Any] = {
        "id": args.get("id")
    }

    fields: str = args.get("fields") or """
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
        """

    query = """
    query assetEndpointInfo($id: ID!) {
      assetEndpointInfo(id: $id) {
        %s
      }
    }
    """ % (fields)

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


def fetch_incidents(
    client: Client,
    env: str,
    fetch_type: str = "investigations",
    max_fetch: int = 15,
    include_assets: bool = True,
    first_fetch_interval: str = DEFAULT_FIRST_FETCH_INTERVAL,
):
    """
    Fetch Taegis Investigations or Alerts for the use with "Fetch Incidents"
    """
    if not 0 < int(max_fetch) < 201:
        raise ValueError("Max Fetch must be between 1 and 200")

    if fetch_type not in ["alerts", "investigations"]:
        raise ValueError("Incident Type is invalid. Supported types: ['alerts', 'investigations']")

    last_run = demisto.getLastRun()
    demisto.debug(f"Last Fetch Incident Run: {last_run}")
    now = datetime.now()
    start_time = str(dateparser.parse(first_fetch_interval))  # Default start if first ever run
    if last_run and "start_time" in last_run:
        start_time = last_run.get("start_time")

    if fetch_type == "alerts":
        query = """
          query alertsServiceSearch($cql_query: String, $limit: Int) {
            alertsServiceSearch(
              in: {
                cql_query:$cql_query,
                limit:$limit
              }
            ) {
                  status
              reason
              alerts {
                list {
                  id
                  status
                  tenant_id
                  suppressed
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
                        detector_name
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
                    began_at {
                      seconds
                    }
                    ended_at {
                      seconds
                    }
                  }
                  event_ids {
                      id
                      event_data
                  }
                  investigation_ids {
                    id
                  }
                  sensor_types
                }
                total_results
              }
            }
          }
        """

        variables = {
            "limit": arg_to_number(max_fetch),
            # We only support Medium, High, Critical
            "cql_query": f"from alert where severity >=0.4 AND earliest = '{start_time}'",
        }
    elif fetch_type == "investigations":
        asset_query = ""
        if include_assets:
            demisto.debug("include_assets=True, fetching assets with investigation")
            # Assets to be deprecated in the future
            asset_query = "assets {id hostnames {id hostname} tags {tag}} assetsEvidence {id assetId}"

        query = """
        query investigationsSearch(
            $page: Int,
            $perPage: Int,
            $orderByField: OrderFieldInput,
            $orderDirection: OrderDirectionInput,
            $query: String
        ) {
          investigationsSearch(
            page: $page,
            perPage: $perPage,
            orderByField: $orderByField,
            orderDirection: $orderDirection,
            query: $query
          ) {
            totalCount
            investigations {
                id
                tenant_id
                description
                key_findings
                assignee {
                    name
                    id
                    email
                }
                assignee_user {
                    family_name
                    given_name
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
                    entities {
                        entities
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
                created_by
                created_by_scwx
                service_desk_id
                service_desk_type
                latest_activity
                priority
                status
                created_at
                archived_at
                alertsEvidence {id alertId}
                tags
                %s
            }
          }
        }
        """ % (asset_query)

        variables = {
            "orderByField": "created_at",
            "orderDirection": "asc",
            "page": 0,
            "perPage": arg_to_number(max_fetch),
            "query": f"status in ('Open', 'Active', 'Awaiting Action') AND earliest = '{start_time}'"
        }
    else:
        query = ""
        variables = {}
        demisto.debug(f"No condition was met -> {query=} {variables=}")

    result = client.graphql_run(query=query, variables=variables)
    if result.get("errors") and result["errors"]:
        raise DemistoException(f"Error when fetching incidents: {result['errors'][0]['message']}")

    try:
        results = result["data"]["investigationsSearch"]["investigations"] \
            if fetch_type == "investigations" \
            else result["data"]["alertsServiceSearch"]["alerts"]["list"]
    except (TypeError, KeyError):
        results = []

    incidents = []
    for incident in results:
        # createdAfter really means createdAtOrAfter so skip the duplicate
        created_date = incident["created_at"] if fetch_type == "investigations" else \
            datetime.fromtimestamp(int(incident["metadata"]["created_at"]["seconds"])).strftime("%Y-%m-%d %H:%M:%S.%f")
        if start_time == created_date:
            continue

        # Skip archived, if necessary
        if fetch_type == "investigations" and incident["archived_at"]:
            demisto.debug(f"Skipping Archived Investigation: {incident['description']} ({incident['id']})")
            continue

        incident_name: str = incident['description'] if fetch_type == "investigations" else incident['metadata']['title']
        demisto.debug(f"Found New Incident: [{incident['id']}] {incident_name}")

        incident.update({"url": generate_id_url(env, fetch_type, incident["id"])})
        incidents.append({
            "name": incident_name,
            "occured": created_date,
            "dbotMirrorId": incident["id"],
            "rawJSON": json.dumps(incident),
        })

    demisto.debug(f"Located {len(incidents)} Incidents")

    last_run = str(now) if not incidents else incidents[-1]["occured"]
    demisto.debug(f"Setting New Last Run Time: {last_run}")
    demisto.setLastRun({"start_time": last_run})

    demisto.incidents(incidents)

    return incidents


def fetch_investigation_alerts_command(client: Client, env: str, args=None):
    investigation_id = args.get("id")
    page = arg_to_number(args.get("page", 0))
    page_size = arg_to_number(args.get("page_size", 10))
    if not investigation_id:
        raise ValueError("Cannot fetch investigation, missing investigation_id")

    fields: str = args.get("fields") or """
        alerts {
            id
        }
        alerts2 {
            id
        }
        totalCount
        """

    query = """
    query investigationAlerts($investigation_id: ID!, $page: Int, $perPage: Int) {
        investigationAlerts(investigation_id: $investigation_id, page: $page, perPage: $perPage) {
            %s
        }
    }
    """ % (fields)

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
    fields: str = ""
    variables: Dict[str, Any] = {}
    if args.get("id"):
        # alerts, assets, and assignee to be deprecated in the future
        fields = args.get("fields") or """
            id
            shortId
            title
            keyFindings
            alerts
            assets
            alertsEvidence {id alertId}
            assetsEvidence {id assetId}
            status
            assignee {
                id
                family_name
                given_name
            }
            priority
            type
            processingStatus {
                assets
                events
                alerts
            }
            archivedAt
            tags
            """

        query = """
        query investigationV2($arguments: InvestigationV2Arguments!) {
            investigationV2(arguments: $arguments) {
                %s
            }
        }
        """ % (fields)

        variables = {
            "arguments": {
                "id": args.get("id")
            }
        }
        result = client.graphql_run(query=query, variables=variables)
    else:
        # assignee {} to be deprecated in the future
        fields = args.get("fields") or """
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
            assignee_user {
                family_name
                given_name
                email
                id
            }
            archived_at
            created_at
            updated_at
            service_desk_id
            service_desk_type
            latest_activity
            priority
            status
            type
            processing_status {
                assets
                events
                alerts
            }
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
            alertsEvidence {id alertId}
            assetsEvidence {id assetId}
            tags
            """

        query = """
        query investigationsSearch(
            $page: Int,
            $perPage: Int,
            $orderByField: OrderFieldInput,
            $orderDirection: OrderDirectionInput,
            $query: String
        ) {
            investigationsSearch(
                page: $page
                perPage: $perPage
                orderByField: $orderByField
                orderDirection: $orderDirection
                query: $query
            ) {
                totalCount
                investigations {
                    %s
                }
            }
        }
        """ % (fields)
        variables = {
            "page": arg_to_number(args.get("page", 0)),
            "perPage": arg_to_number(args.get("page_size", 10)),
            "query": args.get("query", "deleted_at is null"),
            "orderByField": args.get("order_by", "created_at"),
            "orderDirection": args.get("order_direction", "desc")
        }
        result = client.graphql_run(query=query, variables=variables)

    try:
        investigations = [result["data"]["investigationV2"]] if args.get("id") \
            else result["data"]["investigationsSearch"]["investigations"]
    except (KeyError, TypeError):
        investigations = []

    # If no investigation found, no error status is returned but investigation will be null
    if len(investigations) == 1 and investigations[0] is None:
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

    fields: str = args.get("fields") or """
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
        """

    query = """
    query playbookExecution($playbookExecutionId: ID!) {
      playbookExecution(playbookExecutionId: $playbookExecutionId) {
        %s
      }
    }
    """ % (fields)

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
    page = arg_to_number(args.get("page")) or 0
    page_size = arg_to_number(args.get("page_size")) or 10

    variables: dict[str, Any] = {
        "filters": {
            "status": args.get("status", ""),
            "perPage": page_size,
            "pageOffset": page_size * page,
        }
    }
    fields: str = args.get("fields") or "user_id email family_name given_name status"
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

    variables: dict[str, Any] = {
        "id": args.get("id"),
        "reason": args.get("reason")
    }

    fields: str = args.get("fields") or "id"

    query = """
    mutation isolateAsset ($id: ID!, $reason: String!) {
      isolateAsset (id: $id, reason: $reason) {
        %s
      }
    }
    """ % (fields)

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
        raise ValueError(
            f"The provided status, {args['status']}, is not valid for updating an alert. "
            f"Supported Status Values: {ALERT_STATUSES}")

    variables = {
        "alert_ids": argToList(args.get("ids")),
        "reason": args.get("reason", ""),
        "resolution_status": args.get("status"),
    }

    fields: str = args.get("fields") or "resolution_status reason"

    query = """
    mutation alertsServiceUpdateResolutionInfo($alert_ids: [String!], $reason: String, $resolution_status: ResolutionStatus) {
      alertsServiceUpdateResolutionInfo(
        in: {
          alert_ids: $alert_ids,
            reason: $reason,
            resolution_status: $resolution_status
        }
      ) {
        %s
      }
    }
    """ % (fields)
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

    fields: str = args.get("fields") or "id"

    query = """
    mutation updateInvestigationComment($input: UpdateInvestigationCommentInput!) {
        updateInvestigationComment(input: $input) {
            %s
        }
    }
    """ % (fields)
    variables = {
        "input": {
            "commentId": args.get("id"),
            "comment": args.get("comment"),
        }
    }

    result = client.graphql_run(query=query, variables=variables)

    try:
        comment = result["data"]["updateInvestigationComment"]
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
    if not args.get("id"):
        raise ValueError("Cannot fetch investigation without id defined")

    fields: str = args.get("fields") or "id shortId"

    query = """
    mutation updateInvestigationV2($input: UpdateInvestigationV2Input!) {
        updateInvestigationV2(input: $input) {
            %s
        }
    }
    """ % (fields)

    variables = {"input": {"id": args.get("id")}}

    for field in INVESTIGATION_UPDATE_FIELDS:
        if not args.get(field):
            continue

        if field == "assigneeId" and not args["assigneeId"].startswith("auth0") and args["assigneeId"] != "@secureworks":
            raise ValueError("assigneeId MUST be in 'auth0|12345' format or '@secureworks'")
        if field == "priority" and not 0 < int(args.get("priority", 0)) < 5:
            raise ValueError("Priority must be between 1-4")
        if field == "status" and args.get("status") not in INVESTIGATION_STATUSES:
            raise ValueError(
                f"The provided status, {args['status']}, is not valid for updating an investigation. "
                f"Supported Status Values: {INVESTIGATION_STATUSES}")
        if field == "type" and args.get("type") not in INVESTIGATION_TYPES:
            raise ValueError(
                f"The provided type, {args['type']}, is not valid for updating an investigation. "
                f"Supported Type Values: {INVESTIGATION_TYPES}")

        if field == "tags":
            variables["input"]["tags"] = argToList(args["tags"])
        else:
            variables["input"][field] = args.get(field)

    if len(variables["input"]) < 2:
        raise ValueError(f"No valid investigation fields provided. Supported Update Fields: {INVESTIGATION_UPDATE_FIELDS}")

    result = client.graphql_run(query=query, variables=variables)

    try:
        investigation = result["data"]["updateInvestigationV2"]
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

    fields: str = args.get("fields") or "id"

    query = """
    mutation ($investigation_id: ID!) {
      archiveInvestigation(investigation_id: $investigation_id) {
        %s
      }
    }
    """ % (fields)

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

    fields: str = args.get("fields") or "id"

    query = """
    mutation ($investigation_id: ID!) {
      unArchiveInvestigation(investigation_id: $investigation_id) {
        %s
      }
    }
    """ % (fields)

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
    demisto.debug(f'Running Taegis Command: {command}')

    commands: dict[str, Any] = {
        "fetch-incidents": fetch_incidents,
        "taegis-add-evidence-to-investigation": add_evidence_to_investigation_command,
        "taegis-create-comment": create_comment_command,
        "taegis-create-investigation": create_investigation_command,
        "taegis-create-sharelink": create_sharelink_command,
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

    ARGS = demisto.args()
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
            tenant_id=ARGS.get("tenant_id"),
        )
        client.auth()

        if command == "test-module":
            result = commands[command](client=client)
            return_results(result)

        elif command == "fetch-incidents":
            commands[command](
                client=client,
                env=environment,
                fetch_type=PARAMS.get("fetch_type"),
                max_fetch=PARAMS.get("max_fetch"),
                include_assets=PARAMS.get("include_assets"),
                first_fetch_interval=PARAMS.get('first_fetch', DEFAULT_FIRST_FETCH_INTERVAL),
            )
        else:
            return_results(commands[command](client=client, env=environment, args=ARGS))
    except Exception as e:
        error_string = str(e)
        demisto.error(f"Error running command: {e}")

        if "Unauthorized" in error_string:
            error_string = "Invalid credentials (Client ID or Client Secret)"
        return_error(f"Failed to execute {command} command. Error: {error_string}")


""" ENTRY POINT """
if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
