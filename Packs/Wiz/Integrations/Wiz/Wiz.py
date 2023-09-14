from CommonServerPython import *
import demistomock as demisto
from urllib import parse

DEMISTO_OCCURRED_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
WIZ_API_TIMEOUT = 300  # Increase timeout for Wiz API
WIZ_HTTP_QUERIES_LIMIT = 500  # Request limit during run
WIZ_API_LIMIT = 500  # limit number of returned records from the Wiz API
WIZ = 'wiz'

# Standard headers
HEADERS_AUTH = {}
HEADERS_AUTH["Content-Type"] = "application/x-www-form-urlencoded"
HEADERS = {}
HEADERS["Content-Type"] = "application/json"

TOKEN = None
URL = ''
AUTH_E = ''
AUTH_DEFAULT = "auth"  # NEED TO BE REMOVED AFTER THAT AUTH0 IS DEPRECATED
COGNITO_PREFIX = [
    "auth.app",
    "auth.gov",
    "auth.test"
]
AUTH0_PREFIX = [
    "auth",
    "auth0.gov",
    "auth0.test"
]
URL_SUFFIX = 'wiz.io/oauth/token'

# Pull Issues
PULL_ISSUES_QUERY = ("""
query IssuesTable(
  $filterBy: IssueFilters
  $first: Int
  $after: String
  $orderBy: IssueOrder
) {
  issues:issuesV2(filterBy: $filterBy
    first: $first
    after: $after
    orderBy: $orderBy) {
    nodes {
      id
      sourceRule{
        __typename
        ... on Control {
          id
          name
          controlDescription: description
          resolutionRecommendation
          securitySubCategories {
            title
            category {
              name
              framework {
                name
              }
            }
          }
        }
        ... on CloudEventRule{
          id
          name
          cloudEventRuleDescription: description
          sourceType
          type
        }
        ... on CloudConfigurationRule{
          id
          name
          cloudConfigurationRuleDescription: description
          remediationInstructions
          serviceType
        }
      }
      createdAt
      updatedAt
      dueAt
      projects {
        id
        name
        slug
        businessUnit
        riskProfile {
          businessImpact
        }
      }
      status
      severity
      entitySnapshot {
        id
        type
        nativeType
        name
        status
        cloudPlatform
        cloudProviderURL
        providerId
        region
        resourceGroupExternalId
        subscriptionExternalId
        subscriptionName
        subscriptionTags
        tags
        externalId
      }
      serviceTickets {
        externalId
        name
        url
      }
      notes {
        id
        createdAt
        updatedAt
        text
        user {
          name
          email
        }
        serviceAccount {
          name
        }
      }
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}
""")
PULL_ISSUE_WITH_EVIDENCE_PARAM_QUERY = ("""
query IssuesTable(
  $filterBy: IssueFilters
  $first: Int
  $after: String
  $orderBy: IssueOrder
) {
  issues:issuesV2(filterBy: $filterBy
    first: $first
    after: $after
    orderBy: $orderBy) {
    nodes {
      evidenceQuery
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}
""")
PULL_ISSUES_TEST_VARIABLES = test_variables = {
    'first': 1,
    'filterBy': {
        'status': [
            'OPEN',
            'IN_PROGRESS'
        ]
    },
    'orderBy': {
        'field': 'SEVERITY',
        'direction': 'DESC'
    }
}

# Pull Issue Evidence
PULL_ISSUE_EVIDENCE_QUERY = ("""
  query GraphSearch(
    $query: GraphEntityQueryInput
    $controlId: ID
    $projectId: String!
    $first: Int
    $after: String
    $fetchTotalCount: Boolean!
    $quick: Boolean = true
    $fetchPublicExposurePaths: Boolean = false
    $fetchInternalExposurePaths: Boolean = false
    $fetchIssueAnalytics: Boolean = false
    $fetchLateralMovement: Boolean = false
    $fetchKubernetes: Boolean = false
  ) {
    graphSearch(
      query: $query
      controlId: $controlId
      projectId: $projectId
      first: $first
      after: $after
      quick: $quick
    ) {
      totalCount @include(if: $fetchTotalCount)
      maxCountReached @include(if: $fetchTotalCount)
      pageInfo {
        endCursor
        hasNextPage
      }
      nodes {
        entities {
          ...PathGraphEntityFragment
          userMetadata {
            isInWatchlist
            isIgnored
            note
          }
          technologies {
            id
            icon
          }
          publicExposures(first: 10) @include(if: $fetchPublicExposurePaths) {
            nodes {
              ...NetworkExposureFragment
            }
          }
          otherSubscriptionExposures(first: 10)
            @include(if: $fetchInternalExposurePaths) {
            nodes {
              ...NetworkExposureFragment
            }
          }
          otherVnetExposures(first: 10)
            @include(if: $fetchInternalExposurePaths) {
            nodes {
              ...NetworkExposureFragment
            }
          }
          lateralMovementPaths(first: 10) @include(if: $fetchLateralMovement) {
            nodes {
              id
              pathEntities {
                entity {
                  ...PathGraphEntityFragment
                }
              }
            }
          }
          kubernetesPaths(first: 10) @include(if: $fetchKubernetes) {
            nodes {
              id
              path {
                ...PathGraphEntityFragment
              }
            }
          }
        }
        aggregateCount
      }
    }
  }

  fragment PathGraphEntityFragment on GraphEntity {
    id
    name
    type
    properties
    issueAnalytics: issues(filterBy: { status: [IN_PROGRESS, OPEN] })
      @include(if: $fetchIssueAnalytics) {
      highSeverityCount
      criticalSeverityCount
    }
  }


  fragment NetworkExposureFragment on NetworkExposure {
    id
    portRange
    sourceIpRange
    destinationIpRange
    path {
      ...PathGraphEntityFragment
    }
    applicationEndpoints {
      ...PathGraphEntityFragment
    }
  }
    """)
PULL_ISSUE_EVIDENCE_PARAMS = {
    'quick': True,
    'fetchPublicExposurePaths': False,
    'fetchInternalExposurePaths': False,
    'fetchIssueAnalytics': False,
    'fetchLateralMovement': False,
    'fetchKubernetes': False,
    'first': 5,
    'projectId': '*',
    'query': None,
    'fetchTotalCount': False
}
UPDATE_ISSUE_QUERY = ("""
mutation UpdateIssue(
    $issueId: ID!
    $patch: UpdateIssuePatch
    $override: UpdateIssuePatch
  ) {
    updateIssue(input: { id: $issueId, patch: $patch, override: $override }) {
      issue {
        id
        notes {
          ...IssueNoteDetails
        }
        status
        dueAt
        resolutionReason
      }
    }
  }

  fragment IssueNoteDetails on IssueNote {
    id
    text
    updatedAt
    createdAt
    user {
      id
      email
    }
    serviceAccount {
      id
      name
    }
  }
""")
CREATE_COMMENT_QUERY = ("""
mutation CreateIssueComment($input: CreateIssueNoteInput!) {
    createIssueNote(input: $input) {
      issueNote {
        createdAt
        id
        text
        user {
          id
          email
        }
      }
    }
  }
    """)
DELETE_NOTE_QUERY = ("""
    mutation DeleteIssueNote($input: DeleteIssueNoteInput!) {
    deleteIssueNote(input: $input) {
      _stub
    }
  }
    """)

# Pull Resources
PULL_RESOURCES_QUERY = ("""
        query GraphSearch(
            $query: GraphEntityQueryInput
            $controlId: ID
            $projectId: String!
            $first: Int
            $after: String
            $fetchTotalCount: Boolean!
            $quick: Boolean
            $fetchPublicExposurePaths: Boolean = false
            $fetchInternalExposurePaths: Boolean = false
            $fetchIssueAnalytics: Boolean = false
          ) {
            graphSearch(
                query: $query
                controlId: $controlId
                projectId: $projectId
                first: $first
                after: $after
                quick: $quick
            ) {
                totalCount @include(if: $fetchTotalCount)
                maxCountReached @include(if: $fetchTotalCount)
                pageInfo {
                    endCursor
                    hasNextPage
                }
                nodes {
                    entities {
                        id
                        name
                        type
                        properties
                        userMetadata {
                            isInWatchlist
                            isIgnored
                            note
                        }
                        issueAnalytics: issues(filterBy: { status: [IN_PROGRESS, OPEN] })
                            @include(if: $fetchIssueAnalytics) {
                            lowSeverityCount
                            mediumSeverityCount
                            highSeverityCount
                            criticalSeverityCount
                        }
                        publicExposures(first: 10) @include(if: $fetchPublicExposurePaths) {
                            nodes {
                                ...NetworkExposureFragment
                            }
                        }
                        otherSubscriptionExposures(first: 10)
                            @include(if: $fetchInternalExposurePaths) {
                            nodes {
                                ...NetworkExposureFragment
                            }
                        }
                        otherVnetExposures(first: 10)
                            @include(if: $fetchInternalExposurePaths) {
                                nodes {
                                    ...NetworkExposureFragment
                                }
                            }
                        }
                        aggregateCount
                    }
                }
            }

            fragment NetworkExposureFragment on NetworkExposure {
                id
                portRange
                sourceIpRange
                destinationIpRange
                path {
                    id
                    name
                    type
                    properties
                    issueAnalytics: issues(filterBy: { status: [IN_PROGRESS, OPEN] })
                        @include(if: $fetchIssueAnalytics) {
                            lowSeverityCount
                            mediumSeverityCount
                            highSeverityCount
                            criticalSeverityCount
                        }
                }
            }
    """)
PULL_RESOURCES_VARIABLES = {
    "fetchPublicExposurePaths": True,
    "fetchInternalExposurePaths": False,
    "fetchIssueAnalytics": False,
    "first": 50,
    "query": {
        "type": [
            "CLOUD_RESOURCE"
        ],
        "select": True,
        "where": {
            "providerUniqueId": {
                "EQUALS": []
            }
        }
    },
    "projectId": "*",
    "fetchTotalCount": True,
    "quick": True
}


class WizInputParam:
    ISSUE_ID = 'issue_id'
    ISSUE_TYPE = 'issue_type'
    RESOURCE_ID = 'resource_id'
    SEVERITY = 'severity'
    REJECT_REASON = 'reject_reason'
    REJECT_NOTE = 'reject_note'
    REOPEN_NOTE = 'reopen_note'
    NOTE = 'note'
    DUE_AT = 'due_at'
    VM_ID = 'vm_id'
    PROJECT_NAME = 'project_name'


class WizStatus:
    OPEN = 'OPEN'
    IN_PROGRESS = 'IN PROGRESS'
    REJECTED = 'REJECTED'


def set_authentication_endpoint(auth_endpoint):
    global AUTH_E
    AUTH_E = generate_auth_urls(AUTH_DEFAULT)[1] if auth_endpoint == '' else auth_endpoint


def set_api_endpoint(api_endpoint):
    global URL
    URL = api_endpoint


def generate_auth_urls(prefix):
    auth_url = f"{prefix}.{URL_SUFFIX}"
    http_auth_url = f"https://{auth_url}"
    return auth_url, http_auth_url


def get_token():
    """
    Retrieve the token using the credentials
    """
    audience = ''
    cognito_list = []
    for cognito_prefix in COGNITO_PREFIX:
        cognito_list.extend(generate_auth_urls(cognito_prefix))

    auth0_list = []
    for auth0_prefix in AUTH0_PREFIX:
        auth0_list.extend(generate_auth_urls(auth0_prefix))

    # check Wiz portal auth endpoint - Cognito or Auth0
    if AUTH_E in cognito_list:
        audience = 'wiz-api'
    elif AUTH_E in auth0_list:
        audience = 'beyond-api'
    else:
        raise Exception('Not a valid authentication endpoint')

    demisto_params = demisto.params()
    said = demisto_params.get('credentials').get('identifier')
    sasecret = demisto_params.get('credentials').get('password')
    auth_payload = parse.urlencode({
        'grant_type': 'client_credentials',
        'audience': audience,
        'client_id': said,
        'client_secret': sasecret
    })
    response = requests.post(AUTH_E, headers=HEADERS_AUTH, data=auth_payload)

    if response.status_code != requests.codes.ok:
        raise Exception('Error authenticating to Wiz [%d] - %s' % (response.status_code, response.text))
    try:
        response_json = response.json()
        TOKEN = response_json.get('access_token')
        if not TOKEN:
            demisto.debug(json.dumps(response_json))
            message = 'Could not retrieve token from Wiz: {}'.format(response_json.get("message"))
            raise Exception(message)
    except ValueError as exception:
        demisto.debug(exception)
        raise Exception('Could not parse API response')
    HEADERS["Authorization"] = "Bearer " + TOKEN

    return TOKEN


def checkAPIerrors(query, variables):
    if not TOKEN:
        get_token()

    data = {"variables": variables, "query": query}

    demisto.info(f"Invoking the API with is {json.dumps(data)}")

    result = requests.post(url=URL, json=data, headers=HEADERS)

    demisto.info(f"Result is {result}")
    demisto.info(f"Result Json is {result.json()}")

    error_message = ""
    if "errors" in result.json():
        error_message = f"Error details: {get_error_output(result.json())}"

    elif 'data' in result.json() and 'issues' in result.json()['data'] and len(result.json()['data']['issues'].get('nodes')) == 0:
        error_message = "Error details: The Issue ID is not correct"

    if error_message:
        demisto.error("An error has occurred using:\n"
                      f"\tQuery: {query}\n"
                      f"\tVariables: {variables}\n"
                      f"\t{error_message}")
        demisto.error(error_message)
        raise Exception(f"{error_message}\nCheck 'server.log' file to get additional information")
    return result.json()


def translate_severity(issue):
    """
    Translate issue severity to demisto
    Might take risk grade into account in the future
    """
    severity = demisto.get(issue, WizInputParam.SEVERITY)
    if severity == 'CRITICAL':
        return 4
    if severity == 'HIGH':
        return 3
    if severity == 'MEDIUM':
        return 2
    if severity == 'LOW':
        return 1
    if severity == 'INFORMATIONAL':
        return 0.5
    return None


def build_incidents(issue):
    if issue is None:
        return {}

    return {
        'name': issue.get('sourceRule', {}).get('name', 'No sourceRule') + ' - ' + issue.get('id'),
        'occurred': issue['createdAt'],
        'rawJSON': json.dumps(issue),
        'severity': translate_severity(issue)
    }


def fetch_issues(max_fetch):
    """
    Fetch all Issues (OOB XSOAR Fetch)
    """

    if max_fetch > 500:
        max_fetch = 500

    last_run = demisto.getLastRun().get('time')
    if not last_run:  # first time fetch
        last_run = dateparser.parse(demisto.params().get('first_fetch', '7 days').strip())
        last_run = (last_run.isoformat()[:-3] + 'Z')

    query = PULL_ISSUES_QUERY
    variables = {
        "first": max_fetch,
        "filterBy": {
            "status": [
                "OPEN",
                "IN_PROGRESS"
            ],

            "createdAt": {
                "after":
                    last_run
            },
            "relatedEntity":
                {}
        },
        "orderBy": {
            "field":
                "SEVERITY",
            "direction":
                "DESC"
        }
    }

    response_json = checkAPIerrors(query, variables)

    issues = response_json['data']['issues']['nodes']
    while response_json['data']['issues']['pageInfo']['hasNextPage']:
        variables['after'] = response_json['data']['issues']['pageInfo']['endCursor']
        response_json = checkAPIerrors(query, variables)
        if response_json['data']['issues']['nodes'] != []:
            issues += (response_json['data']['issues']['nodes'])

    incidents = []
    for issue in issues:
        incident = build_incidents(issue=issue)
        incidents.append(incident)

    demisto.incidents(incidents)
    demisto.setLastRun(
        {'time': datetime.now().strftime(DEMISTO_OCCURRED_FORMAT)})


def get_filtered_issues(issue_type, resource_id, severity, limit, issue_id=''):
    """
    Retrieves Filtered Issues
    """
    demisto.info(f"Issue type is {issue_type}\n"
                 f"Resource ID is {resource_id}\n"
                 f"Severity is {severity}")
    error_msg = ''

    if not severity and not issue_type and not resource_id and not issue_id:
        error_msg = "You should pass (at least) one of the following parameters:\n\tissue_type\n\tresource_id" \
                    "\n\tseverity\n"

    if issue_type and resource_id:
        error_msg = f"{error_msg}You cannot pass issue_type and resource_id together\n"

    if error_msg:
        demisto.error(error_msg)
        return error_msg

    issue_variables = {}
    query = PULL_ISSUES_QUERY

    if issue_type:
        issue_variables = {
            "first": limit,
            "filterBy": {
                "status": [
                    "OPEN",
                    "IN_PROGRESS"
                ],
                "relatedEntity": {
                    "type": [
                        issue_type
                    ]
                }
            },
            "orderBy": {
                "field":
                    "SEVERITY",
                "direction":
                    "DESC"
            }
        }
    elif resource_id:
        get_resource_graph_id_helper_variables = {
            "projectId": "*",
            "query": {
                "type": [
                    "CLOUD_RESOURCE"
                ],
                "where": {
                    "providerUniqueId": {
                        "EQUALS":
                            resource_id
                    }
                }
            }
        }
        get_resource_graph_id_helper_query = ("""
            query GraphEntityResourceFilterAutosuggest(
                $query: GraphEntityQueryInput
                $projectId: String!
              ) {
                graphSearch(
                    first: 100, query: $query, quick: true, projectId: $projectId
                ) {
                    nodes {
                        entities {
                            id
                            name
                            type
                        }
                    }
                }
            }
        """)
        graph_resource_response_json = checkAPIerrors(get_resource_graph_id_helper_query,
                                                      get_resource_graph_id_helper_variables)
        if graph_resource_response_json['data']['graphSearch']['nodes'] != []:
            graph_resource_id = graph_resource_response_json['data']['graphSearch']['nodes'][0]['entities'][0]['id']
            issue_variables = \
                {"first": limit,
                 "filterBy": {"status": ["OPEN", "IN_PROGRESS"],
                              "relatedEntity":
                                  {"id": graph_resource_id}},
                 "orderBy": {"field": "SEVERITY", "direction": "DESC"}}
        else:
            demisto.info("Resource not found.")
            return "Resource not found."

    if severity:
        if 'filterBy' not in issue_variables.keys():
            issue_variables['filterBy'] = {"severity": []}
            issue_variables['first'] = limit
        if severity.upper() == 'CRITICAL':
            issue_variables['filterBy']['severity'] = ['CRITICAL']
        elif severity.upper() == 'HIGH':
            issue_variables['filterBy']['severity'] = ['CRITICAL', 'HIGH']
        elif severity.upper() == 'MEDIUM':
            issue_variables['filterBy']['severity'] = ['CRITICAL', 'HIGH', 'MEDIUM']
        elif severity.upper() == 'LOW':
            issue_variables['filterBy']['severity'] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        elif severity.upper() == 'INFORMATIONAL':
            issue_variables['filterBy']['severity'] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL']
        else:
            demisto.info("You should only use these severity types: CRITICAL, HIGH, MEDIUM, LOW or INFORMATIONAL "
                         "in upper or lower case.")
            return ("You should only use these severity types: CRITICAL, HIGH, MEDIUM, LOW or INFORMATIONAL in "
                    "upper or lower case.")

    if issue_id:
        issue_variables = {
            "first": 5,
            "filterBy": {
                "id": issue_id
            }
        }

    demisto.info(f"Query is {query}")
    demisto.info(f"Issue variables is {issue_variables}")

    response_json = checkAPIerrors(query, issue_variables)

    demisto.info(f"The API response is {response_json}")

    issues = {}
    if response_json['data']['issues']['nodes'] != []:
        issues = response_json['data']['issues']['nodes']
    while response_json['data']['issues']['pageInfo']['hasNextPage']:

        issue_variables['after'] = response_json['data']['issues']['pageInfo']['endCursor']
        response_json = checkAPIerrors(query, issue_variables)
        if response_json['data']['issues']['nodes'] != []:
            issues += (response_json['data']['issues']['nodes'])

    return issues


def get_resource(resource_id):
    """
    Retrieves Resource Details
    """

    demisto.debug("get_resource, enter")

    variables = {
        "fetchPublicExposurePaths": True,
        "fetchInternalExposurePaths": False,
        "fetchIssueAnalytics": False,
        "first": 50,
        "query": {
            "type": [
                "CLOUD_RESOURCE"
            ],
            "select": True,
            "where": {
                "providerUniqueId": {
                    "EQUALS": [resource_id]
                }
            }
        },
        "projectId": "*",
        "fetchTotalCount": True,
        "quick": True
    }

    try:
        response_json = checkAPIerrors(PULL_RESOURCES_QUERY, variables)
    except DemistoException:
        demisto.debug(f"could not find resource with ID {resource_id}")
        return {}

    if response_json['data']['graphSearch']['nodes'] is None or not response_json['data']['graphSearch']['nodes']:
        demisto.info("Resource Not Found")
        return {}
    else:
        return response_json['data']['graphSearch']['nodes'][0]['entities'][0]


def reject_issue(issue_id, reject_reason, reject_comment):
    """
    Reject a Wiz Issue
    """
    demisto.debug("reject_issue, enter")

    if not issue_id or not reject_reason or not reject_comment:
        demisto.error("You should pass all of: Issue ID, rejection reason and comment.")
        return "You should pass all of: Issue ID, rejection reason and note."

    variables = {
        'issueId': issue_id,
        'patch': {
            'status': 'REJECTED',
            'note': reject_comment,
            'resolutionReason': reject_reason
        }
    }
    query = UPDATE_ISSUE_QUERY

    try:
        response = checkAPIerrors(query, variables)
    except DemistoException:
        demisto.debug(f"could not find Issue with ID {issue_id}")
        return {}

    return response


def reopen_issue(issue_id, reopen_note):
    """
    Re-open a Wiz Issue
    """

    demisto.debug("reopen_issue, enter")

    if not issue_id:
        demisto.error("You should pass an Issue ID.")
        return "You should pass an Issue ID."

    variables = {
        'issueId': issue_id,
        'patch': {
            'status': 'OPEN'
        }
    }
    query = UPDATE_ISSUE_QUERY

    response = checkAPIerrors(query, variables)

    if reopen_note:
        set_issue_comment(issue_id, reopen_note)

    return response


def issue_in_progress(issue_id):
    """
    Set a Wiz Issue to In Progress
    """

    demisto.debug("issue_in_progress, enter")

    if not issue_id:
        demisto.error("You should pass an Issue ID.")
        return "You should pass an Issue ID."

    variables = {
        'issueId': issue_id,
        'patch': {
            'status': 'IN_PROGRESS'
        }
    }
    query = UPDATE_ISSUE_QUERY

    response = checkAPIerrors(query, variables)

    return response


def _get_issue(issue_id, is_evidence=False):
    issue_variables = {
        'first': 1,
        'filterBy': {
            'id': issue_id
        },
    }

    issue_query = PULL_ISSUE_WITH_EVIDENCE_PARAM_QUERY if is_evidence else PULL_ISSUES_QUERY

    issue_response = checkAPIerrors(issue_query, issue_variables)

    return issue_response


def set_issue_comment(issue_id, comment):
    """
    Set a note on Wiz Issue
    """

    demisto.debug("set_issue_comment, enter")

    if not issue_id or not comment:
        demisto.error("You should pass an Issue ID and note.")
        return "You should pass an Issue ID and note."

    issue_variables = {
        "input": {
            "issueId": issue_id,
            "text": comment
        }
    }
    issue_query = CREATE_COMMENT_QUERY

    response = checkAPIerrors(issue_query, issue_variables)

    return response


def get_error_output(wiz_api_response):
    error_output_message = ''
    if 'errors' in wiz_api_response:
        for error_message in wiz_api_response['errors']:
            if 'message' in error_message:
                error_output_message = error_output_message + error_message['message']

    return error_output_message if error_output_message else wiz_api_response


def clear_issue_note(issue_id):
    """
    Clear the note from a Wiz Issue
    """

    demisto.debug("clear_issue_note, enter")

    if not issue_id:
        demisto.error("You should pass an Issue ID.")
        return "You should pass an Issue ID."

    issue_object = _get_issue(issue_id)

    issue_notes = issue_object['data']['issues']['nodes'][0]['notes']
    demisto.info(f"The issue notes are: {issue_notes}")

    query = DELETE_NOTE_QUERY
    for note in issue_notes:

        variables = {
            "input": {
                "id": note['id']
            }
        }

        response = checkAPIerrors(query, variables)

    return response


def set_issue_due_date(issue_id, due_at):
    """
    Set a due date for a Wiz Issue
    """

    demisto.debug("set_issue_due_date, enter")

    if not issue_id or not due_at:
        demisto.error("issue_id and due_at parameters must be provided.")
        return "issue_id and due_at parameters must be provided."

    format = "%Y-%m-%d"
    try:
        datetime.strptime(due_at, format)
        demisto.info("This is the correct date string format.")
    except ValueError:
        demisto.error("This is the incorrect. It should be YYYY-MM-DD")
        return "The date format is the incorrect. It should be YYYY-MM-DD"
    due_at = due_at + 'T00:00:00.000Z'

    variables = {
        'issueId': issue_id,
        'patch': {
            'dueAt': due_at
        }
    }
    query = UPDATE_ISSUE_QUERY

    try:
        response = checkAPIerrors(query, variables)
    except DemistoException:
        demisto.debug(f"could not find Issue with ID {issue_id}")
        return {}

    return response


def clear_issue_due_date(issue_id):
    """
    Clear a due date for a Wiz Issue
    """

    demisto.debug("clear_issue_due_date, enter")

    if not issue_id:
        demisto.error("You should pass an Issue ID.")
        return "You should pass an Issue ID."

    issue_query = UPDATE_ISSUE_QUERY
    issue_variables = {
        'issueId': issue_id,
        'override': {
            'dueAt': None
        }
    }

    issue_response = checkAPIerrors(issue_query, issue_variables)

    return issue_response


def get_issue_evidence(issue_id):
    """
    Get evidence on a Wiz Issue
    """

    demisto.debug("get_issue_evidence, enter")

    if not issue_id:
        demisto.error("You should pass an Issue ID.")
        return "You should pass an Issue ID."

    # Getting the Issue Evidence Query
    issue_object = _get_issue(issue_id, is_evidence=True)

    query_for_evidence = issue_object['data']['issues']['nodes'][0]['evidenceQuery']

    # Creating the query/variables to get the Issue Evidence
    query = PULL_ISSUE_EVIDENCE_QUERY
    variables = PULL_ISSUE_EVIDENCE_PARAMS
    variables['query'] = query_for_evidence

    try:
        response = checkAPIerrors(query, variables)
    except Exception as e:
        error_message = f"Failed getting Issue evidence on ID {issue_id}.\nError details: {str(e)}"
        demisto.error(error_message)
        raise Exception(error_message)

    if response.get('data', {}).get('graphSearch', {}).get('nodes') is None:
        return "Resource Not Found"
    else:
        return response['data']['graphSearch']['nodes'][0].get('entities', {})


def rescan_machine_disk(vm_id):
    """
    Rescan a VM disk in Wiz
    """

    demisto.debug("rescan_machine_disk, enter")

    if not vm_id:
        demisto.error("You should pass a VM ID.")
        return "You should pass a VM ID."

    # find VM on the graph
    vm_variables = {
        "projectId": "*",
        "query": {
            "type": [
                "VIRTUAL_MACHINE"
            ],
            "where": {
                "providerUniqueId": {
                    "EQUALS": [
                        vm_id
                    ]
                }
            }
        }
    }
    vm_query = (  # pragma: no cover
        """
        query GraphEntityResourceFilterAutosuggest(
            $query: GraphEntityQueryInput
            $projectId: String!
            ) {
            graphSearch(
                first: 100, query: $query, quick: true, projectId: $projectId
            ) {
                nodes {
                    entities {
                        id
                        name
                        type
                    }
                }
            }
        }
    """)

    try:
        vm_response = checkAPIerrors(vm_query, vm_variables)
    except DemistoException:
        demisto.debug(f"could not find VM with ID {vm_id}")
        return {}

    # Run the rescan query
    if not vm_response.get('data', {}).get('graphSearch', {}).get('nodes', []):
        demisto.error(f"could not find VM with ID {vm_id}")
        return f"could not find VM with ID {vm_id}"

    else:
        vm_id_wiz = vm_response['data']['graphSearch']['nodes'][0]['entities'][0]['id']
        demisto.info(f"Found VM with ID {vm_id}")

    variables = {
        'input': {
            'id': vm_id_wiz,
            'type': 'VIRTUAL_MACHINE'
        }
    }
    query = (  # pragma: no cover
        """
        mutation RequestResourceScan($input: RequestConnectorEntityScanInput!) {
          requestConnectorEntityScan(input: $input) {
            success
            reason
          }
        }
    """)

    demisto.info(f"Running scan on VM ID {vm_id}")
    try:
        response = checkAPIerrors(query, variables)
    except DemistoException:
        demisto.debug(f"could not find run scan on VM ID {vm_id}")
        return {}

    demisto.info(f"Scan on VM ID {vm_id} submitted successfully.")
    return response


def get_project_team(project_name):
    """
    Get the Project Owners and Security Champions details
    """

    demisto.debug("wiz-get-project-team, enter")

    if not project_name:
        demisto.error("You should pass a Project name")
        return "You should pass an Project name."

    # find VM on the graph
    project_variables = {
        "first": 20,
        "filterBy": {
            "search": project_name
        },
        "orderBy": {
            "field": "SECURITY_SCORE",
            "direction": "ASC"
        },
        "analyticsSelection": {}
    }
    project_query = (  # pragma: no cover
        """
    query ProjectsTable(
        $filterBy: ProjectFilters
        $first: Int
        $after: String
        $orderBy: ProjectOrder
        $analyticsSelection: ProjectIssueAnalyticsSelection
    ) {
        projects(
        filterBy: $filterBy
        first: $first
        after: $after
        orderBy: $orderBy
        ) {
        nodes {
            id
            name
            description
            businessUnit
            archived
            slug
            projectOwners {
            id
            name
            email
            }
            securityChampions {
            id
            name
            email
            }
            cloudAccountCount
            repositoryCount
            securityScore
            riskProfile {
            businessImpact
            }
            teamMemberCount
            issueAnalytics(selection: $analyticsSelection) {
            issueCount
            scopeSize
            informationalSeverityCount
            lowSeverityCount
            mediumSeverityCount
            highSeverityCount
            criticalSeverityCount
            }
        }
        pageInfo {
            hasNextPage
            endCursor
        }
        }
    }
    """)

    try:
        response_json = checkAPIerrors(project_query, project_variables)
    except DemistoException:
        demisto.debug(f"Error with finding Project with name {project_name}")
        return {}

    project_response = response_json.get('data', {}).get('projects', {}).get('nodes')

    demisto.info(f"Validating if Project with name \"{project_name}\" exists.")
    if not project_response:
        demisto.debug(f"Project with name {project_name} does not exist")
        return {}

    else:
        project_team = {
            "projectOwners": project_response[0]['projectOwners'],
            "securityChampions": project_response[0]['securityChampions']
        }
        return project_team


def main():
    params = demisto.params()
    set_authentication_endpoint(params.get('auth_endpoint'))
    set_api_endpoint(params.get('api_endpoint', ''))
    try:
        command = demisto.command()
        if command == 'test-module':
            auth_token = get_token()
            if 'error' not in auth_token:
                test_response = checkAPIerrors(PULL_ISSUES_QUERY, PULL_ISSUES_TEST_VARIABLES)

                if 'errors' not in test_response:
                    demisto.results('ok')
                else:
                    demisto.results(test_response)
            else:
                demisto.results("Invalid token")

        elif command == 'fetch-incidents':
            max_fetch = int(demisto.params().get('max_fetch'))
            fetch_issues(
                max_fetch=max_fetch
            )

        elif command == 'wiz-get-issues':
            demisto_args = demisto.args()
            issue_type = demisto_args.get(WizInputParam.ISSUE_TYPE)
            resource_id = demisto_args.get(WizInputParam.RESOURCE_ID)
            severity = demisto_args.get(WizInputParam.SEVERITY)
            issues = get_filtered_issues(
                issue_type=issue_type,
                resource_id=resource_id,
                severity=severity,
                limit=WIZ_API_LIMIT,
            )
            if isinstance(issues, str):
                #  this means the Issue is an error
                command_result = CommandResults(readable_output=issues, raw_response=issues)
            else:
                command_result = CommandResults(outputs_prefix="Wiz.Manager.Issues", outputs=issues,
                                                raw_response=issues)
            return_results(command_result)

        elif command == "wiz-get-resource":
            resource = get_resource(resource_id=demisto.args()[WizInputParam.RESOURCE_ID])
            command_result = CommandResults(outputs_prefix="Wiz.Manager.Resource", outputs=resource,
                                            raw_response=resource)
            return_results(command_result)

        elif command == 'wiz-reject-issue':
            demisto_args = demisto.args()
            issue_id = demisto_args.get(WizInputParam.ISSUE_ID)
            reject_reason = demisto_args.get(WizInputParam.REJECT_REASON)
            reject_note = demisto_args.get(WizInputParam.REJECT_NOTE)
            issue_response = reject_issue(
                issue_id=issue_id,
                reject_reason=reject_reason,
                reject_comment=reject_note
            )
            command_result = CommandResults(readable_output=issue_response, raw_response=issue_response)
            return_results(command_result)

        elif command == 'wiz-reopen-issue':
            demisto_args = demisto.args()
            issue_id = demisto_args.get(WizInputParam.ISSUE_ID)
            reopen_note = demisto_args.get(WizInputParam.REOPEN_NOTE)
            issue_response = reopen_issue(
                issue_id=issue_id,
                reopen_note=reopen_note
            )
            command_result = CommandResults(readable_output=issue_response, raw_response=issue_response)
            return_results(command_result)

        elif command == 'wiz-issue-in-progress':
            demisto_args = demisto.args()
            issue_id = demisto_args.get(WizInputParam.ISSUE_ID)
            issue_response = issue_in_progress(
                issue_id=issue_id
            )
            command_result = CommandResults(readable_output=issue_response, raw_response=issue_response)
            return_results(command_result)

        elif command == 'wiz-set-issue-note':
            demisto_args = demisto.args()
            issue_id = demisto_args.get(WizInputParam.ISSUE_ID)
            note = demisto_args.get(WizInputParam.NOTE)
            issue_response = set_issue_comment(
                issue_id=issue_id,
                comment=note
            )
            command_result = CommandResults(readable_output=issue_response, raw_response=issue_response)
            return_results(command_result)

        elif command == 'wiz-clear-issue-note':
            demisto_args = demisto.args()
            issue_id = demisto_args.get(WizInputParam.ISSUE_ID)
            issue_response = clear_issue_note(
                issue_id=issue_id
            )
            command_result = CommandResults(readable_output=issue_response, raw_response=issue_response)
            return_results(command_result)

        elif command == 'wiz-get-issue-evidence':
            demisto_args = demisto.args()
            issue_id = demisto_args.get(WizInputParam.ISSUE_ID)
            issue_response = get_issue_evidence(
                issue_id=issue_id
            )
            command_result = CommandResults(readable_output=issue_response, raw_response=issue_response)
            return_results(command_result)

        elif command == 'wiz-set-issue-due-date':
            demisto_args = demisto.args()
            issue_id = demisto_args.get(WizInputParam.ISSUE_ID)
            due_at = demisto_args.get('due_at')
            issue_response = set_issue_due_date(
                issue_id=issue_id,
                due_at=due_at
            )
            command_result = CommandResults(readable_output=issue_response, raw_response=issue_response)
            return_results(command_result)

        elif command == 'wiz-clear-issue-due-date':
            demisto_args = demisto.args()
            issue_id = demisto_args.get(WizInputParam.ISSUE_ID)
            issue_response = clear_issue_due_date(
                issue_id=issue_id
            )
            command_result = CommandResults(readable_output=issue_response, raw_response=issue_response)
            return_results(command_result)

        elif command == 'wiz-rescan-machine-disk':
            demisto_args = demisto.args()
            vm_id = demisto_args.get(WizInputParam.VM_ID)
            issue_response = rescan_machine_disk(
                vm_id=vm_id
            )
            command_result = CommandResults(readable_output=issue_response, raw_response=issue_response)
            return_results(command_result)

        elif command == 'wiz-get-project-team':
            demisto_args = demisto.args()
            project_name = demisto_args.get(WizInputParam.PROJECT_NAME)
            projects_response = get_project_team(
                project_name=project_name
            )
            command_result = CommandResults(readable_output=projects_response, raw_response=projects_response)
            return_results(command_result)

        else:
            raise Exception('Unrecognized command: ' + command)
    except Exception as err:
        demisto.error(traceback.format_exc())
        return_error(str(err))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
