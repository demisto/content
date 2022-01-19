import json
import demistomock as demisto
from CommonServerPython import *
from urllib import parse

DEMISTO_OCCURRED_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
Wiz_API_TIMEOUT = 300  # Increase timeout for Wiz API
Wiz_HTTP_QUERIES_LIMIT = 500  # Request limit during run
Wiz_API_LIMIT = 500  # limit number of returned records from the Wiz API

# Standard headers
HEADERS_AUTH = dict()
HEADERS_AUTH["Content-Type"] = "application/x-www-form-urlencoded"
HEADERS = dict()
HEADERS["Content-Type"] = "application/json"
TOKEN = None
URL = ''


def get_token():
    """
    Retrieve the token using the credentials
    """
    demisto_params = demisto.params()
    said = demisto_params.get('credentials').get('identifier')
    sasecret = demisto_params.get('credentials').get('password')
    auth_payload = parse.urlencode({
        'grant_type': 'client_credentials',
        'audience': 'beyond-api',
        'client_id': said,
        'client_secret': sasecret
    })
    response = requests.post("https://auth.wiz.io/oauth/token", headers=HEADERS_AUTH, data=auth_payload)

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
        demisto.log(exception)
        raise Exception('Could not parse API response')
    HEADERS["Authorization"] = "Bearer " + TOKEN

    return TOKEN


def checkAPIerrors(query, variables):
    if not TOKEN:
        get_token()

    data = {"variables": variables, "query": query}

    try:
        result = requests.post(url=URL, json=data, headers=HEADERS)

    except Exception as e:
        if '502: Bad Gateway' not in str(e) and '503: Service Unavailable' not in str(e):
            demisto.error("<p>Wiz-API-Error: %s</p>" % str(e))
            return(e)
        else:
            demisto.log("Retry")

    return result.json()


def translate_severity(issue):
    """
    Translate issue severity to demisto
    Might take risk grade into account in the future
    """
    severity = demisto.get(issue, 'severity')
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


def build_incidents(issue):
    if issue is None:
        return {}

    return {
        'name': issue.get('control', {}).get('name', 'No Control') + ' - ' + issue.get('id'),
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

    query = ("""
        query IssuesTable(
            $filterBy: IssueFilters
            $first: Int
            $after: String
            $orderBy: IssueOrder
          ) {
            issues(
                filterBy: $filterBy
                first: $first
                after: $after
                orderBy: $orderBy
            ) {
                nodes {
                    ...IssueDetails
                }
                pageInfo {
                    hasNextPage
                    endCursor
                }
                totalCount
                informationalSeverityCount
                lowSeverityCount
                mediumSeverityCount
                highSeverityCount
                criticalSeverityCount
                uniqueEntityCount
            }
        }

        fragment IssueDetails on Issue {
            id
            control {
                id
                name
                query
                description
            }
            createdAt
            updatedAt
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
            entity {
                id
                name
                type
            }
            entitySnapshot {
                id
                type
                nativeType
                name
                subscriptionId
                subscriptionExternalId
                subscriptionName
                resourceGroupId
                resourceGroupExternalId
                region
                cloudPlatform
                cloudProviderURL
                status
                tags
                providerId
                subscriptionTags
            }
            note
            dueAt
            serviceTicket {
                externalId
                name
                url
            }
            serviceTickets {
                externalId
                name
                url
                action {
                    id
                    type
                }
            }
        }
    """)
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
    while (response_json['data']['issues']['pageInfo']['hasNextPage']):

        variables['after'] = response_json['data']['issues']['pageInfo']['endCursor']
        response_json = checkAPIerrors(query, variables)
        if response_json['data']['issues']['nodes'] != []:
            issues += (response_json['data']['issues']['nodes'])

    incidents = list()
    for issue in issues:
        incident = build_incidents(issue=issue)
        incidents.append(incident)

    demisto.incidents(incidents)
    demisto.setLastRun(
        {'time': datetime.now().strftime(DEMISTO_OCCURRED_FORMAT)})


def get_filtered_issues(issue_type, resource_id, severity, limit):
    """
    Retrieves Filtered Issues
    """

    if issue_type and resource_id or (not issue_type and not resource_id):
        demisto.error("You should (only) pass one filter")
        return "You should (only) pass one filter"

    query = ("""
        query IssuesTable(
            $filterBy: IssueFilters
            $first: Int
            $after: String
            $orderBy: IssueOrder
          ) {
            issues(
                filterBy: $filterBy
                first: $first
                after: $after
                orderBy: $orderBy
            ) {
                nodes {
                    ...IssueDetails
                }
                pageInfo {
                    hasNextPage
                    endCursor
                }
                totalCount
                informationalSeverityCount
                lowSeverityCount
                mediumSeverityCount
                highSeverityCount
                criticalSeverityCount
                uniqueEntityCount
            }
        }
        fragment IssueDetails on Issue {
            id
            control {
                id
                name
                query
            }
            createdAt
            updatedAt
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
            entity {
                id
                name
                type
            }
            entitySnapshot {
                id
                type
                nativeType
                name
                subscriptionId
                subscriptionExternalId
                subscriptionName
                resourceGroupId
                resourceGroupExternalId
                region
                cloudPlatform
                cloudProviderURL
                status
                tags
                providerId
                subscriptionTags
            }
            note
            dueAt
            serviceTicket {
                externalId
                name
                url
            }
            serviceTickets {
                externalId
                name
                url
                action {
                    id
                    type
                }
            }
        }
    """)

    if issue_type:
        variables = {
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
        graph_resource_response_json = checkAPIerrors(get_resource_graph_id_helper_query, get_resource_graph_id_helper_variables)
        if graph_resource_response_json['data']['graphSearch']['nodes'] != []:
            graph_resource_id = graph_resource_response_json['data']['graphSearch']['nodes'][0]['entities'][0]['id']
            variables = {"first": limit, "filterBy": {"status": ["OPEN", "IN_PROGRESS"], "relatedEntity": {"id":
                         graph_resource_id}}, "orderBy": {"field": "SEVERITY", "direction": "DESC"}}
        else:
            demisto.info("Resource not found.")
            return "Resource not found."

    if severity:
        if severity.upper() == 'CRITICAL':
            variables['filterBy']['severity'] = ['CRITICAL']
        elif severity.upper() == 'HIGH':
            variables['filterBy']['severity'] = ['CRITICAL', 'HIGH']
        elif severity.upper() == 'MEDIUM':
            variables['filterBy']['severity'] = ['CRITICAL', 'HIGH', 'MEDIUM']
        elif severity.upper() == 'LOW':
            variables['filterBy']['severity'] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        elif severity.upper() == 'INFORMATIONAL':
            variables['filterBy']['severity'] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL']
        else:
            demisto.info("You should only use these severity types: CRITICAL, HIGH, MEDIUM, LOW or INFORMATIONAL "
                         "in upper or lower case.")
            return ("You should only use these severity types: CRITICAL, HIGH, MEDIUM, LOW or INFORMATIONAL in "
                    "upper or lower case.")

    response_json = checkAPIerrors(query, variables)

    issues = dict()
    if response_json['data']['issues']['nodes'] != []:
        issues = response_json['data']['issues']['nodes']
    while (response_json['data']['issues']['pageInfo']['hasNextPage']):

        variables['after'] = response_json['data']['issues']['pageInfo']['endCursor']
        response_json = checkAPIerrors(query, variables)
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
                    "EQUALS": [
                        resource_id
                    ]
                }
            }
        },
        "projectId": "*",
        "fetchTotalCount": True,
        "quick": True
    }
    query = ("""
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

    try:
        response_json = checkAPIerrors(query, variables)
    except DemistoException:
        demisto.debug(f"could not find resource with ID {resource_id}")
        return {}

    if response_json['data']['graphSearch']['nodes'] is None:
        return "Resource Not Found"
    else:
        return response_json['data']['graphSearch']['nodes'][0]['entities'][0]


def reject_issue(issue_id, reject_reason, reject_note):
    """
    Reject a Wiz Issue
    """

    demisto.debug("reject_issue, enter")

    if not issue_id or not reject_reason or not reject_note or (not issue_id and not reject_reason and not reject_note):
        demisto.error("You should pass all of: Issue ID, rejection reason and note.")
        return "You should pass all of: Issue ID, rejection reason and note."

    variables = {
        'issueId': issue_id,
        'patch': {
            'status': 'REJECTED',
            'resolutionReason': reject_reason,
            'note': reject_note
        }
    }
    query = ("""
        mutation UpdateIssue(
            $issueId: ID!
            $patch: UpdateIssuePatch
            $override: UpdateIssuePatch
            ) {
            updateIssue(input: { id: $issueId, patch: $patch, override: $override }) {
                issue {
                    id
                    note
                    status
                    dueAt
                    resolutionReason
                }
            }
        }
    """)

    try:
        response = checkAPIerrors(query, variables)
    except DemistoException:
        demisto.debug(f"could not find Issue with ID {issue_id}")
        return {}

    if 'errors' in response:
        demisto.error(f"Could not find Issue with ID {issue_id}")
        demisto.error(f"Error: {response}")
        return (f"Could not find Issue with ID {issue_id}")

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
            'status': 'OPEN',
            'note': reopen_note
        }
    }
    query = ("""
        mutation UpdateIssue(
            $issueId: ID!
            $patch: UpdateIssuePatch
            $override: UpdateIssuePatch
            ) {
            updateIssue(input: { id: $issueId, patch: $patch, override: $override }) {
                issue {
                    id
                    note
                    status
                    dueAt
                    resolutionReason
                }
            }
        }
    """)

    try:
        response = checkAPIerrors(query, variables)
    except DemistoException:
        demisto.debug(f"could not find Issue with ID {issue_id}")
        return {}

    if 'errors' in response:
        demisto.error(f"Could not find Issue with ID {issue_id}")
        demisto.error(f"Error: {response}")
        return (f"Could not find Issue with ID {issue_id}")

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
    query = ("""
        mutation UpdateIssue(
            $issueId: ID!
            $patch: UpdateIssuePatch
            $override: UpdateIssuePatch
            ) {
            updateIssue(input: { id: $issueId, patch: $patch, override: $override }) {
                issue {
                    id
                    note
                    status
                    dueAt
                    resolutionReason
                }
            }
        }
    """)

    try:
        response = checkAPIerrors(query, variables)
    except DemistoException:
        demisto.debug(f"could not find Issue with ID {issue_id}")
        return {}

    if 'errors' in response:
        demisto.error(f"Could not find Issue with ID {issue_id}")
        demisto.error(f"Error: {response}")
        return (f"Could not find Issue with ID {issue_id}")

    return response


def set_issue_note(issue_id, note):
    """
    Set a note on Wiz Issue
    """

    demisto.debug("set_issue_note, enter")

    if not issue_id and not note:
        demisto.error("You should pass an Issue ID and note.")
        return "You should pass an Issue ID and note."

    # get existing note to append to it.
    issue_variables = {
        'issueId': issue_id
    }
    issue_query = ("""
        query IssueDrawer($issueId: ID!) {
          issue(id: $issueId) {
            id
            note
          }
        }
    """)

    try:
        issue_response = checkAPIerrors(issue_query, issue_variables)
    except DemistoException:
        demisto.debug(f"could not find Issue with ID {issue_id}")
        return {}

    if 'errors' in issue_response:
        demisto.error(f"Could not find Issue with ID {issue_id}")
        demisto.error(f"Error: {issue_response}")
        return (f"Could not find Issue with ID {issue_id}")

    # Check if note is empty for appending
    issue_response_json = issue_response['data']
    if not issue_response_json['issue']['note']:
        new_note = datetime.today().strftime('%Y-%m-%d') + " " + note
    else:
        new_note = issue_response_json['issue']['note'] + "\n" + datetime.today().strftime('%Y-%m-%d') + " " + note

    variables = {
        'issueId': issue_id,
        'patch': {
            'note': new_note
        }
    }
    query = ("""
        mutation UpdateIssue(
            $issueId: ID!
            $patch: UpdateIssuePatch
            $override: UpdateIssuePatch
            ) {
            updateIssue(input: { id: $issueId, patch: $patch, override: $override }) {
                issue {
                    id
                    note
                    status
                    dueAt
                    resolutionReason
                }
            }
        }
    """)

    try:
        response = checkAPIerrors(query, variables)
    except DemistoException:
        demisto.debug(f"Could not update Issue with ID {issue_id}")
        return {}

    return response


def clear_issue_note(issue_id):
    """
    Clear a note from a Wiz Issue
    """

    demisto.debug("clear_issue_note, enter")

    if not issue_id:
        demisto.error("You should pass an Issue ID.")
        return "You should pass an Issue ID."

    variables = {
        'issueId': issue_id,
        'patch': {
            'note': ''
        }
    }
    query = ("""
        mutation UpdateIssue(
            $issueId: ID!
            $patch: UpdateIssuePatch
            $override: UpdateIssuePatch
            ) {
            updateIssue(input: { id: $issueId, patch: $patch, override: $override }) {
                issue {
                    id
                    note
                    status
                    dueAt
                    resolutionReason
                }
            }
        }
    """)

    try:
        response = checkAPIerrors(query, variables)
    except DemistoException:
        demisto.debug(f"could not find Issue with ID {issue_id}")
        return {}

    if 'errors' in response:
        demisto.error(f"Could not find Issue with ID {issue_id}")
        demisto.error(f"Error: {response}")
        return (f"Could not find Issue with ID {issue_id}")

    return response


def set_issue_due_date(issue_id, due_at):
    """
    Set a due date for a Wiz Issue
    """

    demisto.debug("set_issue_due_date, enter")

    if not issue_id:
        demisto.error("You should pass an Issue ID.")
        return "You should pass an Issue ID."

    if (due_at is not None) and (due_at != ""):
        # time has to be like 2022-01-19T00:00:00.000Z
        format = "%Y-%m-%d"
        try:
            datetime.strptime(due_at, format)
            demisto.info("This is the correct date string format.")
        except ValueError:
            demisto.error("This is the incorrect. It should be YYYY-MM-DD")
            return "The date format is the incorrect. It should be YYYY-MM-DD"
        due_at = due_at + 'T00:00:00.000Z'
    else:
        demisto.error("This is the incorrect. It should be YYYY-MM-DD")
        return "The date format is the incorrect. It should be YYYY-MM-DD"

    variables = {
        'issueId': issue_id,
        'patch': {
            'dueAt': due_at
        }
    }
    query = ("""
        mutation UpdateIssue(
            $issueId: ID!
            $patch: UpdateIssuePatch
            $override: UpdateIssuePatch
            ) {
            updateIssue(input: { id: $issueId, patch: $patch, override: $override }) {
                issue {
                    id
                    note
                    status
                    dueAt
                    resolutionReason
                }
            }
        }
    """)

    try:
        response = checkAPIerrors(query, variables)
    except DemistoException:
        demisto.debug(f"could not find Issue with ID {issue_id}")
        return {}

    if 'errors' in response:
        demisto.error(f"Could not find Issue with ID {issue_id}")
        demisto.error(f"Error: {response}")
        return (f"Could not find Issue with ID {issue_id}")

    return response


def clear_issue_due_date(issue_id):
    """
    Clear a due date for a Wiz Issue
    """

    demisto.debug("clear_issue_due_date, enter")

    if not issue_id:
        demisto.error("You should pass an Issue ID.")
        return "You should pass an Issue ID."

    issue_variables = {
        'issueId': issue_id
    }
    issue_query = ("""
        query IssueDrawer($issueId: ID!) {
            issue(id: $issueId) {
                id
                note
                status
                dueAt
                resolutionReason
            }
        }
    """)

    try:
        issue_response = checkAPIerrors(issue_query, issue_variables)
    except DemistoException:
        demisto.debug(f"could not find Issue with ID {issue_id}")
        return {}

    variables = {
        'issueId': issue_id,
        'override': {
            'note': issue_response['data']['issue']['note'],
            'status': issue_response['data']['issue']['status'],
            'resolutionReason': issue_response['data']['issue']['resolutionReason']
        }
    }

    query = ("""
        mutation UpdateIssue(
            $issueId: ID!
            $patch: UpdateIssuePatch
            $override: UpdateIssuePatch
            ) {
            updateIssue(input: { id: $issueId, patch: $patch, override: $override }) {
                issue {
                    id
                    note
                    status
                    dueAt
                    resolutionReason
                }
            }
        }
    """)

    try:
        response = checkAPIerrors(query, variables)
    except DemistoException:
        demisto.debug(f"could not find Issue with ID {issue_id}")
        return {}

    if 'errors' in response:
        demisto.error(f"Could not find Issue with ID {issue_id}")
        demisto.error(f"Error: {response}")
        return (f"Could not find Issue with ID {issue_id}")

    return response


def get_issue_evidence(issue_id):
    """
    Get evidence on a Wiz Issue
    """

    demisto.debug("get_issue_evidence, enter")

    if not issue_id:
        demisto.error("You should pass an Issue ID.")
        return "You should pass an Issue ID."

    # get Control Query to search it.
    issue_variables = {
        'issueId': issue_id
    }
    issue_query = ("""
        query IssueDrawer($issueId: ID!) {
          issue(id: $issueId) {
            id
            control {
                id
                name
                query
            }
          }
        }
    """)

    try:
        issue_response = checkAPIerrors(issue_query, issue_variables)
    except DemistoException:
        demisto.debug(f"Could not find Issue with ID {issue_id}")
        return {}

    if 'errors' in issue_response:
        demisto.error(f"Could not find Issue with ID {issue_id}")
        demisto.error(f"Error: {issue_response}")
        return (f"Could not find Issue with ID {issue_id}")

    # Run the Graph Query
    issue_response_json = issue_response['data']
    query_for_evidence = issue_response_json['issue']['control']['query']

    variables = {
        'fetchPublicExposurePaths': True,
        'fetchInternalExposurePaths': False,
        'fetchIssueAnalytics': True,
        'first': 5,
        'projectId': '*',
        'query': query_for_evidence,
        'fetchTotalCount': True
    }

    query = ("""
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

    try:
        response = checkAPIerrors(query, variables)
    except DemistoException:
        demisto.debug(f"Failed getting Issue evidence on ID {issue_id}")
        return {}

    if response['data']['graphSearch']['nodes'] is None:
        return "Resource Not Found"
    else:
        return response['data']['graphSearch']['nodes'][0]['entities']


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
    vm_query = ("""
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
    if vm_response['data']['graphSearch']['nodes'] == []:
        demisto.log(f"could not find VM with ID {vm_id}")
        return(f"could not find VM with ID {vm_id}")

    else:
        vm_id_wiz = vm_response['data']['graphSearch']['nodes'][0]['entities'][0]['id']
        demisto.log(f"Found VM with ID {vm_id}")

    variables = {
        'input': {
            'id': vm_id_wiz,
            'type': 'VIRTUAL_MACHINE'
        }
    }
    query = ("""
        mutation RequestResourceScan($input: RequestConnectorEntityScanInput!) {
          requestConnectorEntityScan(input: $input) {
            success
            reason
          }
        }
    """)

    demisto.log(f"Running scan on VM ID {vm_id}")
    try:
        response = checkAPIerrors(query, variables)
    except DemistoException:
        demisto.debug(f"could not find run scan on VM ID {vm_id}")
        return {}

    demisto.log(f"Scan on VM ID {vm_id} submitted successfully.")
    return response


def main():
    global URL
    params = demisto.params()
    URL = params.get('api_endpoint')
    try:
        command = demisto.command()
        if command == 'test-module':
            get_token()
            demisto.results('ok')

        elif command == 'fetch-incidents':
            max_fetch = int(demisto.params().get('max_fetch'))
            fetch_issues(
                max_fetch=max_fetch
            )

        elif command == 'wiz-get-issues':
            demisto_args = demisto.args()
            issue_type = demisto_args.get('issue_type')
            resource_id = demisto_args.get('resource_id')
            severity = demisto_args.get('severity')
            issues = get_filtered_issues(
                issue_type=issue_type,
                resource_id=resource_id,
                severity=severity,
                limit=Wiz_API_LIMIT,
            )
            if isinstance(issues, str):
                #  this means the Issue is an error
                command_result = CommandResults(readable_output=issues, raw_response=issues)
            else:
                command_result = CommandResults(outputs_prefix="Wiz.Manager.Issues", outputs=issues,
                                                raw_response=issues)
            return_results(command_result)

        elif command == "wiz-get-resource":
            resource = get_resource(resource_id=demisto.args()['resource_id'])
            command_result = CommandResults(outputs_prefix="Wiz.Manager.Resource", outputs=resource, raw_response=resource)
            return_results(command_result)

        elif command == 'wiz-reject-issue':
            demisto_args = demisto.args()
            issue_id = demisto_args.get('issue_id')
            reject_reason = demisto_args.get('reject_reason')
            reject_note = demisto_args.get('reject_note')
            issue_response = reject_issue(
                issue_id=issue_id,
                reject_reason=reject_reason,
                reject_note=reject_note
            )
            command_result = CommandResults(readable_output=issue_response, raw_response=issue_response)
            return_results(command_result)

        elif command == 'wiz-reopen-issue':
            demisto_args = demisto.args()
            issue_id = demisto_args.get('issue_id')
            reopen_note = demisto_args.get('reopen_note')
            issue_response = reopen_issue(
                issue_id=issue_id,
                reopen_note=reopen_note
            )
            command_result = CommandResults(readable_output=issue_response, raw_response=issue_response)
            return_results(command_result)

        elif command == 'wiz-issue-in-progress':
            demisto_args = demisto.args()
            issue_id = demisto_args.get('issue_id')
            issue_response = issue_in_progress(
                issue_id=issue_id
            )
            command_result = CommandResults(readable_output=issue_response, raw_response=issue_response)
            return_results(command_result)

        elif command == 'wiz-set-issue-note':
            demisto_args = demisto.args()
            issue_id = demisto_args.get('issue_id')
            note = demisto_args.get('note')
            issue_response = set_issue_note(
                issue_id=issue_id,
                note=note
            )
            command_result = CommandResults(readable_output=issue_response, raw_response=issue_response)
            return_results(command_result)

        elif command == 'wiz-clear-issue-note':
            demisto_args = demisto.args()
            issue_id = demisto_args.get('issue_id')
            issue_response = clear_issue_note(
                issue_id=issue_id
            )
            command_result = CommandResults(readable_output=issue_response, raw_response=issue_response)
            return_results(command_result)

        elif command == 'wiz-get-issue-evidence':
            demisto_args = demisto.args()
            issue_id = demisto_args.get('issue_id')
            issue_response = get_issue_evidence(
                issue_id=issue_id
            )
            command_result = CommandResults(readable_output=issue_response, raw_response=issue_response)
            return_results(command_result)

        elif command == 'wiz-set-issue-due-date':
            demisto_args = demisto.args()
            issue_id = demisto_args.get('issue_id')
            due_at = demisto_args.get('due_at')
            issue_response = set_issue_due_date(
                issue_id=issue_id,
                due_at=due_at
            )
            command_result = CommandResults(readable_output=issue_response, raw_response=issue_response)
            return_results(command_result)

        elif command == 'wiz-clear-issue-due-date':
            demisto_args = demisto.args()
            issue_id = demisto_args.get('issue_id')
            issue_response = clear_issue_due_date(
                issue_id=issue_id
            )
            command_result = CommandResults(readable_output=issue_response, raw_response=issue_response)
            return_results(command_result)

        elif command == 'wiz-rescan-machine-disk':
            demisto_args = demisto.args()
            vm_id = demisto_args.get('vm_id')
            issue_response = rescan_machine_disk(
                vm_id=vm_id
            )
            command_result = CommandResults(readable_output=issue_response, raw_response=issue_response)
            return_results(command_result)

        else:
            raise Exception('Unrecognized command: ' + command)
    except Exception as err:
        demisto.error(traceback.format_exc())
        return_error(str(err))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
