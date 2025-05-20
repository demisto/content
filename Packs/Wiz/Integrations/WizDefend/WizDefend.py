import copy
import uuid
import traceback

from CommonServerPython import *
import demistomock as demisto
from urllib import parse

WIZ_VERSION = '1.0.0'
WIZ_DEFEND = 'wiz_defend'
WIZ_DEFEND_INCIDENT_TYPE = 'WizDefend Detection'
USER_AGENT_NAME = 'xsoar_defend'
INTEGRATION_GUID = '8864e131-72db-4928-1293-e292f0ed699f'
WIZ_DOMAIN_URL = ''

DEMISTO_OCCURRED_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
WIZ_API_LIMIT = 250
API_MAX_FETCH = 1000
MAX_DAYS_FIRST_FETCH_DETECTIONS = 5
FETCH_INTERVAL_MINIMUM_MIN = 10
FETCH_INTERVAL_MAXIMUM_MIN = 600
DEFAULT_FETCH_BACK = '12 hours'

# Threats
THREATS_DAYS_MIN = 1
THREATS_DAYS_MAX = 30
THREATS_DAYS_DEFAULT = 5


class WizInputParam:
    DETECTION_ID = 'detection_id'
    ISSUE_ID = 'issue_id'
    TYPE = 'type'
    PLATFORM = 'platform'
    ORIGIN = 'origin'
    CLOUD_ACCOUNT_OR_CLOUD_ORG = 'cloud_account_or_cloud_organization'
    RESOURCE_ID = 'resource_id'
    SEVERITY = 'severity'
    STATUS = 'status'
    CREATION_MINUTES_BACK = 'creation_minutes_back'
    CREATION_DAYS_BACK = 'creation_days_back'
    RULE_MATCH_ID = 'rule_match_id'
    RULE_MATCH_NAME = 'rule_match_name'
    PROJECT_ID = 'project'


class WizApiResponse:
    DATA = 'data'
    DETECTIONS = 'detections'
    ISSUES = 'issues'
    NODES = 'nodes'
    PAGE_INFO = 'pageInfo'
    HAS_NEXT_PAGE = 'hasNextPage'
    END_CURSOR = 'endCursor'
    ACCESS_TOKEN = 'access_token'
    FILTER_BY = 'filterBy'
    TYPE = 'type'
    ERRORS = 'errors'
    MESSAGE = 'message'


class WizApiInputFields:
    API_ENDPOINT = 'api_endpoint'
    AUTH_ENDPOINT = 'auth_endpoint'
    CLIENT_ID = 'client_id'
    CLIENT_SECRET = 'client_secret'


class DemistoParams:
    CREDENTIALS = 'credentials'
    IDENTIFIER = 'identifier'
    PASSWORD = 'password'
    AUTH_ENDPOINT = 'auth_endpoint'
    API_ENDPOINT = 'api_endpoint'
    MAX_FETCH = 'max_fetch'
    FIRST_FETCH = 'first_fetch'
    TIME = 'time'
    NAME = 'name'
    OCCURRED = 'occurred'
    RAW_JSON = 'rawJSON'
    SEVERITY = 'severity'
    MIRROR_ID = 'dbotMirrorId'
    AFTER_TIME = 'after_time'
    URL = 'url'
    IS_FETCH = 'isFetch'
    INCIDENT_FETCH_INTERVAL = 'incidentFetchInterval'
    INCIDENT_TYPE = 'incidentType'


class WizApiVariables:
    FIRST = 'first'
    AFTER = 'after'
    FILTER_BY = 'filterBy'
    FILTER_SCOPE = 'filterScope'
    ORDER_BY = 'orderBy'
    STATUS = 'status'
    CREATED_AT = 'createdAt'
    AFTER_TIME = 'after'
    FIELD = 'field'
    DIRECTION = 'direction'
    TYPE = 'type'
    PROVIDER_UNIQUE_ID = 'providerUniqueId'
    RELATED_ENTITY = 'relatedEntity'
    CLOUD_PLATFORM = 'cloudPlatform'
    ID = 'id'
    ISSUE_ID = 'issueId'
    EQUALS = 'equals'
    SEVERITY = 'severity'
    IN_LAST = 'inLast'
    AMOUNT = 'amount'
    UNIT = 'unit'
    RESOURCE = 'resource'
    MATCHED_RULE = 'matchedRule'
    MATCHED_RULE_NAME = 'matchedRuleName'
    PROJECT_ID = 'projectId'
    PROJECT = 'project'
    NAME = 'name'
    RULE = 'rule'
    RULE_MATCH = 'ruleMatch'
    ORIGIN = 'origin'
    EVENT_ORIGIN = 'eventOrigin'
    CLOUD_ACCOUNT_OR_CLOUD_ORGANIZATION_ID = 'cloudAccountOrCloudOrganizationId'
    URL = 'url'
    THREAT_RESOURCE = 'threatResource'
    IDS = 'ids'


class WizThreatVariables:
    ALL_ISSUE_DETECTIONS = 'ALL_ISSUE_DETECTIONS'
    THREAT_DETECTION = 'THREAT_DETECTION'


class WizStatus:
    OPEN = 'OPEN'
    IN_PROGRESS = 'IN_PROGRESS'
    REJECTED = 'REJECTED'
    RESOLVED = 'RESOLVED'


class WizOrderByFields:
    SEVERITY = 'SEVERITY'
    CREATED_AT = 'CREATED_AT'


class WizOrderDirection:
    DESC = 'DESC'
    ASC = 'ASC'


class WizDetectionStatus:
    OPEN = 'OPEN'
    IN_PROGRESS = 'IN_PROGRESS'
    CLOSED = 'CLOSED'
    REJECTED = 'REJECTED'


class WizSeverity:
    CRITICAL = 'CRITICAL'
    HIGH = 'HIGH'
    MEDIUM = 'MEDIUM'
    LOW = 'LOW'
    INFORMATIONAL = 'INFORMATIONAL'


class DemistoCommands:
    TEST_MODULE = 'test-module'
    FETCH_INCIDENTS = 'fetch-incidents'
    WIZ_GET_DETECTIONS = 'wiz-get-detections'
    WIZ_GET_DETECTION = 'wiz-get-detection'
    WIZ_GET_THREAT = 'wiz-get-threat'
    WIZ_GET_THREATS = 'wiz-get-threats'


class AuthParams:
    GRANT_TYPE = 'grant_type'
    AUDIENCE = 'audience'
    CLIENT_ID = 'client_id'
    CLIENT_SECRET = 'client_secret'


class HeaderFields:
    CONTENT_TYPE = 'Content-Type'
    USER_AGENT = 'User-Agent'
    AUTHORIZATION = 'Authorization'


class ContentTypes:
    JSON = 'application/json'
    FORM_URLENCODED = 'application/x-www-form-urlencoded'


class OutputPrefix:
    DETECTIONS = 'Wiz.Manager.Detections'
    DETECTION = 'Wiz.Manager.Detection'
    THREAT = 'Wiz.Manager.Threat'
    THREATS = 'Wiz.Manager.Threats'


class ValidationType:
    """Class representing field names for validation results"""
    IS_VALID = "is_valid"
    ERROR_MESSAGE = "error_message"
    VALUE = "value"
    SEVERITY_LIST = "severity_list"
    MINUTES_VALUE = "minutes_value"
    DAYS_VALUE = "days_value"
    STATUS_LIST = "status_list"


class ValidationResponse:
    """Class for standardized validation responses"""

    def __init__(self, is_valid=True, error_message=None, value=None):
        self.is_valid = is_valid
        self.error_message = error_message
        self.value = value
        self.days_value = None
        self.minutes_value = None
        self.severity_list = None
        self.status_list = None

    def to_dict(self):
        """Convert the response to a dictionary"""
        return {
            ValidationType.IS_VALID: self.is_valid,
            ValidationType.ERROR_MESSAGE: self.error_message,
            ValidationType.VALUE: self.value,
            ValidationType.DAYS_VALUE: self.days_value,
            ValidationType.MINUTES_VALUE: self.minutes_value,
            ValidationType.SEVERITY_LIST: self.severity_list,
            ValidationType.STATUS_LIST: self.status_list
        }

    @classmethod
    def create_success(cls, value=None):
        """Create a successful validation response"""
        return cls(is_valid=True, error_message=None, value=value)

    @classmethod
    def create_error(cls, error_message):
        """Create a failed validation response"""
        return cls(is_valid=False, error_message=error_message, value=None)


class DetectionType:
    """Detection types supported by the API"""
    GENERATED_THREAT = "GENERATED THREAT"
    DID_NOT_GENERATE_THREAT = "DID NOT GENERATE THREAT"
    api_dict = {
        GENERATED_THREAT: "GENERATED_THREAT",
        DID_NOT_GENERATE_THREAT: "MATCH_ONLY"
    }

    @classmethod
    def values(cls):
        """Get all available detection types with capital letters"""
        return [key for key in cls.api_dict.keys() if any(c.isupper() for c in key)]

    @classmethod
    def api_values(cls):
        """Get all available API values (values in api_dict)"""
        return list(cls.api_dict.values())

    @classmethod
    def get_api_value(cls, user_input):
        """Convert user-friendly input to API value using api_dict"""
        if not user_input:
            return None

        user_input_lower = user_input.lower()
        for friendly_value, api_value in cls.api_dict.items():
            if friendly_value.lower() in user_input_lower:
                return api_value
        return None


class CloudPlatform:
    """Cloud platforms supported by the API"""
    AWS = "AWS"
    GCP = "GCP"
    AZURE = "Azure"
    OCI = "OCI"
    ALIBABA = "Alibaba"
    VSPHERE = "vSphere"
    OPENSTACK = "OpenStack"
    AKS = "AKS"
    EKS = "EKS"
    GKE = "GKE"
    KUBERNETES = "Kubernetes"
    OPENSHIFT = "OpenShift"
    OKE = "OKE"
    LINODE = "Linode"
    AZURE_DEVOPS = "AzureDevOps"
    GITHUB = "GitHub"
    GITLAB = "GitLab"
    BITBUCKET = "Bitbucket"
    TERRAFORM = "Terraform"
    OPENAI = "OpenAI"
    SNOWFLAKE = "Snowflake"
    MONGODB_ATLAS = "MongoDBAtlas"
    DATABRICKS = "Databricks"
    OKTA = "Okta"
    CLOUDFLARE = "Cloudflare"
    MICROSOFT365 = "Microsoft365"
    WIZ = "Wiz"
    ACK = "ACK"
    SELF_HOSTED = "SelfHosted"
    LKE = "LKE"

    @classmethod
    def values(cls):
        """Get all available cloud platforms"""
        return [getattr(cls, attr) for attr in dir(cls)
                if not attr.startswith('_') and not callable(getattr(cls, attr))]


class DurationUnit:
    """Duration units for API filters"""
    DAYS = "DurationFilterValueUnitDays"
    HOURS = "DurationFilterValueUnitHours"
    MINUTES = "DurationFilterValueUnitMinutes"


class DetectionOrigin:
    """Detection origins supported by the API"""
    WIZ_SENSOR = "WIZ_SENSOR"
    WIZ_ADMISSION_CONTROLLER = "WIZ_ADMISSION_CONTROLLER"
    WIZ_FILE_INTEGRITY_MONITORING = "WIZ_FILE_INTEGRITY_MONITORING"
    AWS_GUARD_DUTY = "AWS_GUARD_DUTY"
    AWS_CLOUDTRAIL = "AWS_CLOUDTRAIL"
    AZURE_DEFENDER_FOR_CLOUD = "AZURE_DEFENDER_FOR_CLOUD"
    AZURE_ACTIVITY_LOGS = "AZURE_ACTIVITY_LOGS"
    GCP_SECURITY_COMMAND_CENTER = "GCP_SECURITY_COMMAND_CENTER"
    GCP_AUDIT_LOGS = "GCP_AUDIT_LOGS"
    WIZ_AGENTLESS_FILE_INTEGRITY_MONITORING = "WIZ_AGENTLESS_FILE_INTEGRITY_MONITORING"
    AZURE_ACTIVE_DIRECTORY = "AZURE_ACTIVE_DIRECTORY"
    GOOGLE_WORKSPACE_AUDIT_LOGS = "GOOGLE_WORKSPACE_AUDIT_LOGS"
    WIN_SENTINEL_ONE = "WIN_SENTINEL_ONE"
    WIZ_CODE_ANALYZER = "WIZ_CODE_ANALYZER"
    WIN_SALT = "WIN_SALT"
    WIN_NONAME = "WIN_NONAME"
    WIN_CROWD_STRIKE = "WIN_CROWD_STRIKE"
    WIN_TRACEABLE = "WIN_TRACEABLE"
    WIZ_CLI = "WIZ_CLI"
    WIZ_IDE_EXTENSION = "WIZ_IDE_EXTENSION"
    WIZ_THREAT_DETECTION = "WIZ_THREAT_DETECTION"
    WIZ_KUBERNETES_AUDIT_LOGS_COLLECTOR = "WIZ_KUBERNETES_AUDIT_LOGS_COLLECTOR"
    WIZ_CUSTOM_INTEGRATION = "WIZ_CUSTOM_INTEGRATION"
    WIN_AKAMAI_GUARDICORE = "WIN_AKAMAI_GUARDICORE"
    OKTA_SYSTEM_LOGS = "OKTA_SYSTEM_LOGS"
    WIN_SNOWFLAKE = "WIN_SNOWFLAKE"
    WIN_FALCO = "WIN_FALCO"
    OCI_AUDIT_LOGS = "OCI_AUDIT_LOGS"
    WIZ_VCS_FETCHER = "WIZ_VCS_FETCHER"
    AWS_VPC_FLOW_LOGS = "AWS_VPC_FLOW_LOGS"
    GITHUB_AUDIT_LOGS = "GITHUB_AUDIT_LOGS"
    WIN_FIRE_TAIL = "WIN_FIRE_TAIL"
    AZURE_STORAGE_ACCOUNT = "AZURE_STORAGE_ACCOUNT"
    AZURE_KEY_VAULT = "AZURE_KEY_VAULT"
    AWS_RESOLVER_QUERY_LOGS = "AWS_RESOLVER_QUERY_LOGS"
    AWS_S3_DATA_EVENTS = "AWS_S3_DATA_EVENTS"
    GCP_STORAGE_DATA_ACCESS_LOGS = "GCP_STORAGE_DATA_ACCESS_LOGS"
    AWS_CLOUDTRAIL_NETWORK_ACTIVITY = "AWS_CLOUDTRAIL_NETWORK_ACTIVITY"
    WIZ_BROWSER_EXTENSION = "WIZ_BROWSER_EXTENSION"
    WIN_SALT_SECURITY = "WIN_SALT_SECURITY"

    @classmethod
    def values(cls):
        """Get all available detection origins"""
        return [getattr(cls, attr) for attr in dir(cls)
                if not attr.startswith('_') and not callable(getattr(cls, attr))]


def get_integration_user_agent():
    integration_user_agent = f'{INTEGRATION_GUID}/{USER_AGENT_NAME}/{WIZ_VERSION}'
    return integration_user_agent


# Standard headers
HEADERS_AUTH = {
    HeaderFields.CONTENT_TYPE: ContentTypes.FORM_URLENCODED,
    HeaderFields.USER_AGENT: get_integration_user_agent()
}

HEADERS = {
    HeaderFields.CONTENT_TYPE: ContentTypes.JSON,
    HeaderFields.USER_AGENT: get_integration_user_agent()
}

TOKEN = None
URL = ''
AUTH_E = ''

# Pull Detections
PULL_DETECTIONS_QUERY = """
query Detections($filterBy: DetectionFilters, $first: Int, $after: String, $orderBy: DetectionOrder, $includeTriggeringEvents: Boolean = true) {
  detections(
    filterBy: $filterBy
    first: $first
    after: $after
    orderBy: $orderBy
    enforceTimestampContinuity: true
  ) {
    nodes {
      id
      issue {
        id
        url
        dueAt
        projects {
          id
          name
        }
        resolutionReason
        notes {
          text
        }
      }
      ruleMatch {
        rule {
          id
          name
          sourceType
        }
      }
      description
      severity
      createdAt
      cloudAccounts {
        cloudProvider
        externalId
        name
        linkedProjects {
          id
          name
        }
      }
      cloudOrganizations {
        cloudProvider
        externalId
        name
      }
      startedAt
      endedAt
      actors {
        id
        externalId
        name
        type
        nativeType
        actingAs {
          id
          externalId
          name
          type
          nativeType
        }
      }
      primaryActor {
        id
      }
      resources {
        id
        externalId
        name
        type
        nativeType
        region
        cloudAccount {
          cloudProvider
          externalId
          name
        }
        kubernetesNamespace {
          id
          providerUniqueId
          name
        }
        kubernetesCluster {
          id
          providerUniqueId
          name
        }
      }
      primaryResource {
        id
      }
      triggeringEvents(first: 10) @include(if: $includeTriggeringEvents) {
        nodes {
          ... on CloudEvent {
            id
            origin
            name
            description
            cloudProviderUrl
            cloudPlatform
            timestamp
            source
            category
            status
            actor {
              id
              actingAs {
                id
              }
            }
            actorIP
            actorIPMeta {
              country
              autonomousSystemNumber
              autonomousSystemOrganization
              reputation
              reputationDescription
              reputationSource
              relatedAttackGroupNames
              customIPRanges {
                id
                name
                isInternal
                ipRanges
              }
            }
            resources {
              id
            }
            extraDetails {
              ... on CloudEventRuntimeDetails {
                processTree {
                  command
                  container {
                    id
                    externalId
                    name
                    image {
                      id
                      externalId
                    }
                  }
                  path
                  hash
                  size
                  executionTime
                  runtimeProgramId
                  userId
                  userName
                }
              }
            }
          }
        }
      }
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}
"""

PULL_DETECTIONS_VARIABLES = {
    WizApiVariables.ORDER_BY: {WizApiVariables.FIELD: WizOrderByFields.CREATED_AT,
                               WizApiVariables.DIRECTION: WizOrderDirection.ASC}
}

PULL_ISSUE_QUERY = """
query IssuesTable($filterBy: IssueFilters, $filterScope: IssueFiltersScope, $first: Int, $after: String, $orderBy: IssueOrder) {
  issues: issuesV2(
    filterBy: $filterBy
    first: $first
    after: $after
    orderBy: $orderBy
    filterScope: $filterScope
  ) {
    nodes {
      id
      sourceRule {
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
        ... on CloudEventRule {
          id
          name
          cloudEventRuleDescription: description
          sourceType
          type
        }
        ... on CloudConfigurationRule {
          id
          name
          cloudConfigurationRuleDescription: description
          remediationInstructions
          serviceType
        }
      }
      type
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
"""

PULL_THREAT_ISSUE_VARIABLES = {
    WizApiVariables.FILTER_BY: {
        WizApiVariables.TYPE: [WizThreatVariables.THREAT_DETECTION]
    },
    WizApiVariables.FILTER_SCOPE: WizThreatVariables.ALL_ISSUE_DETECTIONS,
    WizApiVariables.ORDER_BY: {WizApiVariables.FIELD: WizOrderByFields.CREATED_AT,
                               WizApiVariables.DIRECTION: WizOrderDirection.DESC}

}


def set_authentication_endpoint(auth_endpoint):
    global AUTH_E
    AUTH_E = auth_endpoint


def set_api_endpoint(api_endpoint):
    global URL
    URL = api_endpoint


def get_token():
    """
    Retrieve the token using the credentials
    """
    global TOKEN
    audience = 'wiz-api'

    demisto_params = demisto.params()
    said = demisto_params.get(DemistoParams.CREDENTIALS).get(DemistoParams.IDENTIFIER)
    sasecret = demisto_params.get(DemistoParams.CREDENTIALS).get(DemistoParams.PASSWORD)
    auth_payload = parse.urlencode({
        AuthParams.GRANT_TYPE: 'client_credentials',
        AuthParams.AUDIENCE: audience,
        AuthParams.CLIENT_ID: said,
        AuthParams.CLIENT_SECRET: sasecret
    })
    response = requests.post(AUTH_E, headers=HEADERS_AUTH, data=auth_payload)

    if response.status_code != requests.codes.ok:
        raise Exception('Error authenticating to Wiz [%d] - %s' % (response.status_code, response.text))
    try:
        response_json = response.json()
        TOKEN = response_json.get(WizApiResponse.ACCESS_TOKEN)
        if not TOKEN:
            demisto.debug(json.dumps(response_json))
            message = 'Could not retrieve token from Wiz: {}'.format(response_json.get(WizApiResponse.MESSAGE))
            raise Exception(message)
    except ValueError as exception:
        demisto.debug(exception)
        raise Exception('Could not parse API response')
    HEADERS[HeaderFields.AUTHORIZATION] = "Bearer " + TOKEN

    return TOKEN


def get_entries(query, variables, wiz_type):
    if not TOKEN:
        get_token()

    data = {"variables": variables, "query": query}
    demisto.info(f"Invoking the API with {json.dumps(data)}")

    try:
        response = requests.post(url=URL, json=data, headers=HEADERS)
        response_json = response.json()

        demisto.info(f"Response status code is {response.status_code}")
        demisto.info(f"The response is {response_json}")

        if response.status_code != requests.codes.ok:
            raise Exception('Got an error querying Wiz API [{}] - {}'.format(response.status_code, response.text))

        if WizApiResponse.ERRORS in response_json:
            demisto.error(f"Wiz error content: {response_json[WizApiResponse.ERRORS]}")
            error_message = f"Wiz API error details: {get_error_output(response_json)}"
            demisto.error("An error has occurred using:"
                          f"\tQuery: {query} - "
                          f"\tVariables: {variables} -"
                          f"\t{error_message}")
            demisto.error(error_message)
            raise Exception(f"{error_message}\n"
                            f"Check 'server.log' instance file to get additional information")

        return response_json[WizApiResponse.DATA][wiz_type][WizApiResponse.NODES], \
               response_json[WizApiResponse.DATA][wiz_type][WizApiResponse.PAGE_INFO]

    except Exception as e:
        error_message = f"Received an error while performing an API call.\nError info: {str(e)}"
        demisto.error(error_message)
        raise Exception(f"An unexpected error occurred.\nError info: {error_message}")


def query_detections(query, variables, paginate=True):
    return query_api(query, variables, WizApiResponse.DETECTIONS, paginate=paginate)


def query_threats(query, variables, paginate=True):
    return query_api(query, variables, WizApiResponse.ISSUES, paginate=paginate)


def query_api(query, variables, wiz_type, paginate=True):
    entries, page_info = get_entries(query, variables, wiz_type)
    if not entries:
        demisto.info("No detection(/s) available to fetch.")
        entries = {}

    while page_info[WizApiResponse.HAS_NEXT_PAGE] and paginate:
        demisto.debug(f"Successfully pulled {len(entries)} detections")

        variables[WizApiVariables.AFTER] = page_info[WizApiResponse.END_CURSOR]
        new_entries, page_info = get_entries(query, variables, wiz_type)
        if new_entries is not None:
            entries += new_entries
        if len(entries) >= API_MAX_FETCH:
            demisto.info(f"Reached the maximum fetch limit of {API_MAX_FETCH} detections.\n"
                         f"Some detections will not be processed in this fetch cycle.\n"
                         f"Consider adjusting the filters to get relevant logs")
            break

    return entries


def translate_severity(detection):
    """
    Translate detection severity to demisto
    Might take risk grade into account in the future
    """
    severity = demisto.get(detection, WizInputParam.SEVERITY)
    if severity == WizSeverity.CRITICAL:
        return 4
    if severity == WizSeverity.HIGH:
        return 3
    if severity == WizSeverity.MEDIUM:
        return 2
    if severity == WizSeverity.LOW:
        return 1
    if severity == WizSeverity.INFORMATIONAL:
        return 0.5
    return None


def build_incidents(detection):
    if detection is None:
        return {}

    return {
        DemistoParams.NAME: detection.get(WizApiVariables.RULE_MATCH, {}).get(WizApiVariables.RULE, {}).get(
            WizApiVariables.NAME, f'No {WizApiVariables.NAME}') + ' - ' + detection.get(WizApiVariables.ID),
        DemistoParams.OCCURRED: detection[WizApiVariables.CREATED_AT],
        DemistoParams.RAW_JSON: json.dumps(detection),
        DemistoParams.SEVERITY: translate_severity(detection),
        DemistoParams.MIRROR_ID: str(detection[WizApiVariables.ID]),
    }


def get_last_run_time():
    """
    Gets the last run time for fetch incidents.
    If the last run time is more than MAX_DAYS_FIRST_FETCH_DETECTIONS days ago,
    it returns MAX_DAYS_FIRST_FETCH_DETECTIONS days ago instead.

    Returns:
        str: ISO formatted timestamp string for the last run time
    """
    demisto_params = demisto.params()

    last_run = demisto.getLastRun().get(DemistoParams.TIME)

    if not last_run:
        demisto.info(f"First Time Fetch")
        first_fetch_param = demisto_params.get(DemistoParams.FIRST_FETCH,
                                               DEFAULT_FETCH_BACK).strip()
        last_run = get_fetch_timestamp(first_fetch_param)
        return last_run

    # Check if last_run is older than MAX_DAYS_FIRST_FETCH_DETECTIONS
    try:
        last_run_datetime = datetime.strptime(last_run, DEMISTO_OCCURRED_FORMAT)
        max_days_ago = datetime.now() - timedelta(days=MAX_DAYS_FIRST_FETCH_DETECTIONS)

        if last_run_datetime < max_days_ago:
            demisto.info(f"Last run time ({last_run}) is more than {MAX_DAYS_FIRST_FETCH_DETECTIONS} days ago. "
                         f"Using {MAX_DAYS_FIRST_FETCH_DETECTIONS} days ago as the fetch time.")

            # Format max_days_ago to match DEMISTO_OCCURRED_FORMAT
            last_run = max_days_ago.strftime(DEMISTO_OCCURRED_FORMAT)
    except Exception as e:
        demisto.error(f"Error parsing last run time: {str(e)}. Using {MAX_DAYS_FIRST_FETCH_DETECTIONS} days ago as fetch time.")
        max_days_ago = datetime.now() - timedelta(days=MAX_DAYS_FIRST_FETCH_DETECTIONS)
        last_run = max_days_ago.strftime(DEMISTO_OCCURRED_FORMAT)

    return last_run


def extract_params_from_integration_settings(advanced_params=False):
    demisto_params = demisto.params()

    integration_setting_params = {
        WizInputParam.SEVERITY: demisto_params.get(WizInputParam.SEVERITY),
        WizInputParam.TYPE: demisto_params.get(WizInputParam.TYPE),
        WizInputParam.PLATFORM: demisto_params.get(WizInputParam.PLATFORM),
        WizInputParam.ORIGIN: demisto_params.get(WizInputParam.ORIGIN),
        WizInputParam.CLOUD_ACCOUNT_OR_CLOUD_ORG: demisto_params.get(WizInputParam.CLOUD_ACCOUNT_OR_CLOUD_ORG)
    }

    if advanced_params:
        for demisto_param in [DemistoParams.FIRST_FETCH, DemistoParams.INCIDENT_FETCH_INTERVAL,
                              DemistoParams.INCIDENT_TYPE, DemistoParams.IS_FETCH]:
            integration_setting_params[demisto_param] = demisto_params.get(demisto_param)

    return integration_setting_params


def check_advanced_params(integration_settings_params):
    error_message = ""
    are_params_valid = True

    is_fetch = integration_settings_params.get(DemistoParams.IS_FETCH)
    first_fetch = integration_settings_params.get(DemistoParams.FIRST_FETCH)
    incident_fetch_interval = integration_settings_params.get(DemistoParams.INCIDENT_FETCH_INTERVAL)
    incident_type = integration_settings_params.get(DemistoParams.INCIDENT_TYPE)

    if is_fetch:
        first_fetch_validation = validate_first_fetch(first_fetch)
        if not first_fetch_validation.is_valid:
            are_params_valid = False
            error_message += f"{first_fetch_validation.error_message}\n"

        fetch_interval_validation = validate_fetch_interval(incident_fetch_interval)
        if not fetch_interval_validation.is_valid:
            are_params_valid = False
            error_message += f"{fetch_interval_validation.error_message}\n"

        incident_type_validation = validate_incident_type(incident_type)
        if not incident_type_validation.is_valid:
            are_params_valid = False
            error_message += f"{incident_type_validation.error_message}\n"

    return are_params_valid, error_message


def test_module():
    """
    Test the connection to the Wiz API and validate the params
    """
    integration_settings_params = extract_params_from_integration_settings(advanced_params=True)

    are_params_valid, error_message = check_advanced_params(integration_settings_params)
    if not are_params_valid:
        demisto.results(error_message)
        return
    else:
        demisto.info("Advanced parameters are valid")

    wiz_detection = get_filtered_detections(
        detection_type=integration_settings_params[WizInputParam.TYPE],
        detection_platform=integration_settings_params[WizInputParam.PLATFORM],
        severity=integration_settings_params[WizInputParam.SEVERITY],
        detection_origin=integration_settings_params[WizInputParam.ORIGIN],
        detection_cloud_account_or_cloud_organization=integration_settings_params[WizInputParam.CLOUD_ACCOUNT_OR_CLOUD_ORG],
        api_limit=1,
        paginate=False
    )

    if WizApiResponse.ERRORS in wiz_detection or type(wiz_detection) is not list:
        demisto.results(wiz_detection)
    else:
        demisto.results('ok')


def fetch_incidents():
    """
    Fetch all Detections (OOB XSOAR Fetch)
    """
    integration_settings_params = extract_params_from_integration_settings()
    last_run = get_last_run_time()

    api_start_run_time = datetime.now().strftime(DEMISTO_OCCURRED_FORMAT)

    wiz_detections = get_filtered_detections(
        detection_type=integration_settings_params[WizInputParam.TYPE],
        detection_platform=integration_settings_params[WizInputParam.PLATFORM],
        severity=integration_settings_params[WizInputParam.SEVERITY],
        detection_origin=integration_settings_params[WizInputParam.ORIGIN],
        detection_cloud_account_or_cloud_organization=integration_settings_params[WizInputParam.CLOUD_ACCOUNT_OR_CLOUD_ORG],
        after_time=last_run
    )

    if isinstance(wiz_detections, str):
        demisto.error(f"Error fetching detections: {wiz_detections}")
        return

    # Build incidents from detections
    incidents = []
    for detection in wiz_detections:
        incident = build_incidents(detection=detection)
        incidents.append(incident)

    demisto.incidents(incidents)
    demisto.setLastRun({DemistoParams.TIME: api_start_run_time})

    if incidents:
        demisto.info(f"Successfully fetched and created {len(incidents)} incidents - "
                     f"Set last run time to {api_start_run_time}.")
    else:
        demisto.info(f"No new incidents to fetch - Set last run time to {api_start_run_time}.")


def get_fetch_timestamp(first_fetch_param):
    """
    Gets the fetch timestamp based on the first fetch parameter
    Handles validation, error logging, and info messages

    Args:
        first_fetch_param (str): The first fetch parameter (e.g., "2 days", "30 days")

    Returns:
        str: ISO formatted timestamp for fetching

    Raises:
        ValueError: If the first fetch parameter is invalid
    """
    # Validate first fetch timestamp
    is_valid, error_message, valid_date = validate_first_fetch_timestamp(first_fetch_param)

    if not is_valid:
        demisto.error(error_message)
        raise ValueError(error_message)

    # Check if we had to adjust the date to MAX_DAYS_FIRST_FETCH_DETECTIONS days max
    original_date = dateparser.parse(first_fetch_param or DEFAULT_FETCH_BACK)
    if original_date and valid_date.date() != original_date.date():
        demisto.info(f"First fetch timestamp was more than {MAX_DAYS_FIRST_FETCH_DETECTIONS} days "
                     f"({first_fetch_param}), automatically setting to "
                     f"{MAX_DAYS_FIRST_FETCH_DETECTIONS} days back")

    # Return the ISO formatted timestamp
    return valid_date.isoformat()[:-3] + 'Z'


def update_wiz_domain_url():
    """
    Get the Wiz domain URL based on the integration settings
    """
    global WIZ_DOMAIN_URL
    demisto_params = demisto.params()
    auth_endpoint = demisto_params.get(DemistoParams.AUTH_ENDPOINT)
    match = re.search(r"https://auth\.([\w\-]+\.\wiz\.\w+)/oauth/token", auth_endpoint)
    if match:
        WIZ_DOMAIN_URL = match.group(1)
    else:
        demisto.debug("Could not find the domain in the auth endpoint. "
                      "Using default domain: app.wiz.io")
        WIZ_DOMAIN_URL = 'app.wiz.io'


def get_detection_url(detection):
    if not WIZ_DOMAIN_URL:
        update_wiz_domain_url()

    detection_url = f"https://{WIZ_DOMAIN_URL}/findings/detections#~(filters~(updateTime~(dateRange~(past~(amount~5~unit~'day))))~detectionId~'{detection.get('id')}~streamCols~(~'event~'principal~'principalIp~'resource))"
    return detection_url


def get_threat_url(threat):
    if not WIZ_DOMAIN_URL:
        update_wiz_domain_url()

    detection_url = f"https://{WIZ_DOMAIN_URL}/threats#~(filters~(createdAt~(inTheLast~(amount~90~unit~'days)))~issue~'{threat.get('id')})"
    return detection_url


def validate_first_fetch_timestamp(first_fetch_param):
    """
    Validates if the first fetch timestamp is within the limit

    Args:
        first_fetch_param (str): The first fetch parameter (e.g., "2 days", "30 days")

    Returns:
        tuple: (is_valid (bool), error_message (str), valid_date (datetime))
    """
    try:
        if not first_fetch_param:
            first_fetch_param = DEFAULT_FETCH_BACK

        # Parse the first fetch parameter
        first_fetch_date = dateparser.parse(first_fetch_param)

        if not first_fetch_date:
            return False, f"Invalid date format for first fetch: {first_fetch_param}", None

        # Calculate the maximum allowed date
        now = datetime.now()
        max_days_back = now - timedelta(days=MAX_DAYS_FIRST_FETCH_DETECTIONS)

        # Validate that first fetch is not more than MAX_DAYS_FIRST_FETCH_DETECTIONS
        if first_fetch_date < max_days_back:
            # Instead of erroring out, set it to the maximum allowed
            return True, None, max_days_back

        return True, None, first_fetch_date

    except Exception as e:
        error_msg = f"Error validating first fetch timestamp: {str(e)}"
        return False, error_msg, None


def validate_detection_type(detection_type):
    """
    Validates if the detection type is supported and converts user input to API value

    Args:
        detection_type (str): The detection type to validate

    Returns:
        ValidationResponse: Response with validation results
    """
    if not detection_type:
        return ValidationResponse.create_success()

    # Convert user-friendly input to API value
    api_value = DetectionType.get_api_value(detection_type)

    if api_value and api_value in DetectionType.api_values():
        return ValidationResponse.create_success(api_value)
    else:
        error_msg = f"Invalid detection type: {detection_type}. Valid types are: {', '.join(DetectionType.values())}"
        demisto.error(error_msg)
        return ValidationResponse.create_error(error_msg)


def validate_matched_rule_id(matched_rule_id):
    """
    Validates if the matched rule ID is a valid UUID

    Args:
        matched_rule_id (str): The matched rule ID to validate

    Returns:
        ValidationResponse: Response with validation results
    """
    if not matched_rule_id:
        return ValidationResponse.create_success()

    if is_valid_uuid(matched_rule_id):
        return ValidationResponse.create_success(matched_rule_id)
    else:
        error_msg = f"Invalid matched rule ID: {matched_rule_id}. Must be a valid UUID."
        demisto.error(error_msg)
        return ValidationResponse.create_error(error_msg)


def validate_detection_platform(platform):
    """
    Validates if the detection platform is supported

    Args:
        platform (str or list): The platform(s) to validate

    Returns:
        ValidationResponse: Response with validation results
    """
    if not platform:
        return ValidationResponse.create_success()

    # Handle case where platform is a comma-separated string
    if isinstance(platform, str) and ',' in platform:
        platforms = [p.strip() for p in platform.split(',')]
    elif isinstance(platform, str):
        platforms = [platform]
    elif isinstance(platform, list):
        platforms = platform
    else:
        platforms = [platform]

    valid_platforms = CloudPlatform.values()
    invalid_platforms = [p for p in platforms if p not in valid_platforms]

    if invalid_platforms:
        error_msg = f"Invalid platform(s): {', '.join(invalid_platforms)}. Valid platforms are: {', '.join(valid_platforms)}"
        demisto.error(error_msg)
        return ValidationResponse.create_error(error_msg)

    return ValidationResponse.create_success(platforms)


def validate_detection_cloud_account_or_cloud_organization(cloud_account_or_cloud_organization):
    """
    Validates the detection cloud_account_or_cloud_organization parameter(s) are valid UUIDs

    Args:
        cloud_account_or_cloud_organization (str or list): The cloud_account_or_cloud_organization ID(s) to validate

    Returns:
        ValidationResponse: Response with validation results
    """
    if not cloud_account_or_cloud_organization:
        return ValidationResponse.create_success()

    # Handle case where cloud_account_or_cloud_organization is a comma-separated string
    if isinstance(cloud_account_or_cloud_organization, str) and ',' in cloud_account_or_cloud_organization:
        cloud_account_or_cloud_organizations = [s.strip() for s in cloud_account_or_cloud_organization.split(',')]
    elif isinstance(cloud_account_or_cloud_organization, str):
        cloud_account_or_cloud_organizations = [cloud_account_or_cloud_organization]
    elif isinstance(cloud_account_or_cloud_organization, list):
        cloud_account_or_cloud_organizations = cloud_account_or_cloud_organization
    else:
        error_msg = f"{WizInputParam.CLOUD_ACCOUNT_OR_CLOUD_ORG} must be a text value or list of text values"
        demisto.error(error_msg)
        return ValidationResponse.create_error(error_msg)

    # Validate each cloud_account_or_cloud_organization is a UUID
    invalid_cloud_account_or_cloud_organizations = [s for s in cloud_account_or_cloud_organizations if not is_valid_uuid(s)]
    if invalid_cloud_account_or_cloud_organizations:
        error_msg = f"Invalid {WizInputParam.CLOUD_ACCOUNT_OR_CLOUD_ORG} ID(s): " \
                    f"{', '.join(invalid_cloud_account_or_cloud_organizations)}. " \
                    f"All {WizInputParam.CLOUD_ACCOUNT_OR_CLOUD_ORG} must be in valid UUID format."
        demisto.error(error_msg)
        return ValidationResponse.create_error(error_msg)

    return ValidationResponse.create_success(cloud_account_or_cloud_organizations)


def validate_detection_origin(origin):
    """
    Validates if the detection origin is supported

    Args:
        origin (str or list): The origin(s) to validate

    Returns:
        ValidationResponse: Response with validation results
    """
    if not origin:
        return ValidationResponse.create_success()

    # Handle case where origin is a comma-separated string
    if isinstance(origin, str) and ',' in origin:
        origins = [o.strip() for o in origin.split(',')]
    elif isinstance(origin, str):
        origins = [origin]
    elif isinstance(origin, list):
        origins = origin
    else:
        origins = [origin]

    valid_origins = DetectionOrigin.values()
    invalid_origins = [o for o in origins if o not in valid_origins]

    if invalid_origins:
        error_msg = f"Invalid origin(s): {', '.join(invalid_origins)}. Valid origins are: {', '.join(valid_origins)}"
        demisto.error(error_msg)
        return ValidationResponse.create_error(error_msg)

    return ValidationResponse.create_success(origins)


def validate_creation_time_back(time_value, time_unit='minutes'):
    """
    Validates if the creation time parameter is valid

    Args:
        time_value (str): Number of time units back to retrieve data
        time_unit (str): The time unit to validate ('minutes' or 'days')

    Returns:
        ValidationResponse: Response with validation results and time value
    """
    response = ValidationResponse.create_success()

    # Set default values and limits based on the time unit
    if time_unit == 'minutes':
        param_name = WizInputParam.CREATION_MINUTES_BACK
        min_value = FETCH_INTERVAL_MINIMUM_MIN
        max_value = FETCH_INTERVAL_MAXIMUM_MIN
        default_value = FETCH_INTERVAL_MINIMUM_MIN
        response.minutes_value = default_value
    elif time_unit == 'days':
        param_name = WizInputParam.CREATION_DAYS_BACK
        min_value = THREATS_DAYS_MIN
        max_value = THREATS_DAYS_MAX
        default_value = THREATS_DAYS_DEFAULT
        response.days_value = default_value
    else:
        error_msg = f"Invalid time unit: {time_unit}. Supported units are 'minutes' and 'days'."
        return ValidationResponse.create_error(error_msg)

    if not time_value:
        return response

    error_msg = f"{param_name} must be a valid integer between {min_value} and {max_value}."

    try:
        time_int_value = int(time_value)
        if min_value <= time_int_value <= max_value:
            if time_unit == 'minutes':
                response.minutes_value = time_int_value
            else:  # days
                response.days_value = time_int_value
            return response
        else:
            return ValidationResponse.create_error(error_msg)
    except ValueError:
        demisto.error(error_msg)
        return ValidationResponse.create_error(error_msg)


def validate_fetch_interval(fetch_interval):
    """
    Validates if the creation_minutes_back parameter is valid

    Args:
        fetch_interval (int): Number of minutes back to retrieve detections

    Returns:
        ValidationResponse: Response with validation results and minutes value
    """
    response = ValidationResponse.create_success()
    response.minutes_value = FETCH_INTERVAL_MINIMUM_MIN

    if fetch_interval and fetch_interval >= FETCH_INTERVAL_MINIMUM_MIN:
        response.minutes_value = fetch_interval
        return response

    error_msg = f"Invalid Incidents Fetch Interval - It must be a valid integer " \
                f"higher or equal than {FETCH_INTERVAL_MINIMUM_MIN}. Received {fetch_interval}."
    return ValidationResponse.create_error(error_msg)


def validate_incident_type(incident_type):
    """
    Validates if the incident type is set to WizDefend Detection

    Args:
        incident_type (str): The incident type to validate

    Returns:
        ValidationResponse: Response with validation results
    """
    if incident_type == WIZ_DEFEND_INCIDENT_TYPE:
        return ValidationResponse.create_success(incident_type)
    else:
        error_msg = f"Invalid incident type: {incident_type}. Expected '{WIZ_DEFEND_INCIDENT_TYPE}'."
        demisto.error(error_msg)
        return ValidationResponse.create_error(error_msg)


def validate_first_fetch(first_fetch):
    """
    Validates if the first fetch timestamp is in the correct format and within the maximum days limit

    Args:
        first_fetch (str): The first fetch parameter (e.g., "2 days", "12 hours")

    Returns:
        ValidationResponse: Response with validation results and time value
    """
    response = ValidationResponse.create_success()
    error_msg = f"Invalid first fetch format: {first_fetch}. " \
                f"Expected format is '<number> <time unit>' (e.g., '12 hours', '1 day')."

    if not first_fetch:
        demisto.error(error_msg)
        return ValidationResponse.create_error(error_msg)

    # Check for valid format and duration
    pattern = r"^(\d+)\s(hours?|days?|minutes?)$"
    match = re.match(pattern, first_fetch, re.IGNORECASE)

    if not match:
        demisto.error(error_msg)
        return ValidationResponse.create_error(error_msg)

    number = int(match.group(1))
    unit = match.group(2).lower()

    max_hours = MAX_DAYS_FIRST_FETCH_DETECTIONS * 24

    # Check if the duration is within limits
    if unit.startswith("minute"):
        if number > (max_hours * 60):  # Maximum minutes
            error_msg = f"First fetch duration too long: {first_fetch}. Maximum allowed is {MAX_DAYS_FIRST_FETCH_DETECTIONS} days " \
                        f"({max_hours * 60} minutes)."
            demisto.error(error_msg)
            return ValidationResponse.create_error(error_msg)
    elif unit.startswith("hour"):
        if number > max_hours:  # Maximum hours
            error_msg = f"First fetch duration too long: {first_fetch}. Maximum allowed is {MAX_DAYS_FIRST_FETCH_DETECTIONS} days " \
                        f"({max_hours} hours)."
            demisto.error(error_msg)
            return ValidationResponse.create_error(error_msg)
    elif unit.startswith("day"):
        if number > MAX_DAYS_FIRST_FETCH_DETECTIONS:
            error_msg = f"First fetch duration too long: {first_fetch}. Maximum allowed is {MAX_DAYS_FIRST_FETCH_DETECTIONS} days."
            demisto.error(error_msg)
            return ValidationResponse.create_error(error_msg)

    response.value = first_fetch
    return response


def validate_severity(severity):
    """
    Validates if the severity parameter is valid

    Args:
        severity (str): The severity level to validate

    Returns:
        ValidationResponse: Response with validation results and severity list
    """
    response = ValidationResponse.create_success()

    if not severity:
        return response

    severity = severity.upper()
    valid_severities = [WizSeverity.CRITICAL, WizSeverity.HIGH, WizSeverity.MEDIUM, WizSeverity.LOW, WizSeverity.INFORMATIONAL]

    if severity not in valid_severities:
        error_msg = f"Invalid severity: {severity}. Valid severities are: {', '.join(valid_severities)}."
        demisto.error(error_msg)
        return ValidationResponse.create_error(error_msg)

    # Return severity list based on selected level (inclusive of higher levels)
    severity_map = {
        WizSeverity.CRITICAL: [WizSeverity.CRITICAL],
        WizSeverity.HIGH: [WizSeverity.CRITICAL, WizSeverity.HIGH],
        WizSeverity.MEDIUM: [WizSeverity.CRITICAL, WizSeverity.HIGH, WizSeverity.MEDIUM],
        WizSeverity.LOW: [WizSeverity.CRITICAL, WizSeverity.HIGH, WizSeverity.MEDIUM, WizSeverity.LOW],
        WizSeverity.INFORMATIONAL: [WizSeverity.CRITICAL, WizSeverity.HIGH, WizSeverity.MEDIUM, WizSeverity.LOW,
                                    WizSeverity.INFORMATIONAL]
    }

    response.severity_list = severity_map[severity]
    return response


def validate_status(status):
    """
    Validates if the status parameter is valid

    Args:
        status (str or list): The status(es) to validate

    Returns:
        ValidationResponse: Response with validation results and status list
    """
    response = ValidationResponse.create_success()

    if not status:
        return response

    # Handle case where status is a comma-separated string
    if isinstance(status, str) and ',' in status:
        statuses = [s.strip() for s in status.split(',')]
    elif isinstance(status, str):
        statuses = [status.upper()]  # Convert to uppercase for comparison
    elif isinstance(status, list):
        statuses = [s.upper() for s in status]  # Convert all to uppercase
    else:
        statuses = [str(status).upper()]  # Convert non-string to string and uppercase

    valid_statuses = [WizStatus.OPEN, WizStatus.IN_PROGRESS, WizStatus.REJECTED, WizStatus.RESOLVED]

    invalid_statuses = [s for s in statuses if s not in valid_statuses]

    if invalid_statuses:
        error_msg = f"Invalid status(es): {', '.join(invalid_statuses)}. Valid statuses are: " \
                    f"{', '.join(valid_statuses)}."
        demisto.error(error_msg)
        return ValidationResponse.create_error(error_msg)

    response.status_list = statuses
    return response


def validate_resource_id(resource_id):
    """
    Validates resource_id parameter

    Args:
        resource_id (str): The resource ID to validate

    Returns:
        ValidationResponse: Response with validation results
    """
    if not resource_id and not isinstance(resource_id, str):
        return ValidationResponse.create_success()

    return ValidationResponse.create_success(resource_id)


def validate_rule_match_id(rule_match_id):
    """
    Validates the rule match ID (must be a valid UUID if provided)

    Args:
        rule_match_id (str): The rule match ID to validate

    Returns:
        ValidationResponse: Response with validation results
    """
    if not rule_match_id:
        return ValidationResponse.create_success()

    if is_valid_uuid(rule_match_id):
        return ValidationResponse.create_success(rule_match_id)
    else:
        error_msg = f"Invalid rule match ID: {rule_match_id}. Must be a valid UUID."
        demisto.error(error_msg)
        return ValidationResponse.create_error(error_msg)


def validate_rule_match_name(rule_match_name):
    """
    Validates the rule match name

    Args:
        rule_match_name (str): The rule match name to validate

    Returns:
        ValidationResponse: Response with validation results
    """
    if not rule_match_name and not isinstance(rule_match_name, str):
        return ValidationResponse.create_success()

    return ValidationResponse.create_success(rule_match_name)


def validate_project(project):
    """
    Validates the project parameter

    Args:
        project (str): The project to validate

    Returns:
        ValidationResponse: Response with validation results
    """
    if not project and not isinstance(project, str):
        return ValidationResponse.create_success()

    return ValidationResponse.create_success(project)


def validate_all_detection_parameters(parameters_dict):
    """
    Validates all parameters in a centralized function

    Args:
        parameters_dict (dict): Dictionary containing all parameters to validate

    Returns:
        tuple: (success, error_message, validated_values)
            - success (bool): True if all validations pass
            - error_message (str): Error message if validation fails
            - validated_values (dict): Dictionary of validated values
    """
    validated_values = {}

    # Extract parameters from dictionary
    detection_id = parameters_dict.get(WizInputParam.DETECTION_ID)
    issue_id = parameters_dict.get(WizInputParam.ISSUE_ID)
    detection_type = parameters_dict.get(WizInputParam.TYPE)
    detection_platform = parameters_dict.get(WizInputParam.PLATFORM)
    detection_origin = parameters_dict.get(WizInputParam.ORIGIN)
    detection_cloud_account_or_cloud_organization = parameters_dict.get(WizInputParam.CLOUD_ACCOUNT_OR_CLOUD_ORG)
    resource_id = parameters_dict.get(WizInputParam.RESOURCE_ID)
    severity = parameters_dict.get(WizInputParam.SEVERITY)
    creation_minutes_back = parameters_dict.get(WizInputParam.CREATION_MINUTES_BACK)
    matched_rule = parameters_dict.get(WizInputParam.RULE_MATCH_ID)
    rule_match_name = parameters_dict.get(WizInputParam.RULE_MATCH_NAME)
    project_id = parameters_dict.get(WizInputParam.PROJECT_ID)
    after_time = parameters_dict.get(DemistoParams.AFTER_TIME)

    # Check for conflicting time parameters
    if creation_minutes_back and after_time:
        error_msg = f"Cannot provide both {WizInputParam.CREATION_MINUTES_BACK} and {DemistoParams.AFTER_TIME} parameters"
        demisto.error(error_msg)
        return False, error_msg, None

    # For manual commands, check if at least one parameter is provided
    if not after_time:  # If not fetch incident flow
        if not any([detection_id, issue_id, severity, detection_type, detection_platform, detection_origin,
                    detection_cloud_account_or_cloud_organization, resource_id, matched_rule, rule_match_name, project_id]):
            param_list = [
                f"\t{WizInputParam.DETECTION_ID}",
                f"\t{WizInputParam.ISSUE_ID}",
                f"\t{WizInputParam.TYPE}",
                f"\t{WizInputParam.PLATFORM}",
                f"\t{WizInputParam.ORIGIN}",
                f"\t{WizInputParam.CLOUD_ACCOUNT_OR_CLOUD_ORG}",
                f"\t{WizInputParam.RESOURCE_ID}",
                f"\t{WizInputParam.SEVERITY}",
                f"\t{WizInputParam.RULE_MATCH_ID}",
                f"\t{WizInputParam.RULE_MATCH_NAME}",
                f"\t{WizInputParam.PROJECT_ID}"
            ]
            error_msg = f"You should pass at least one of the following parameters:\n" + "\n".join(param_list)
            demisto.error(error_msg)
            return False, error_msg, None

    # Validate detection_id if provided
    if detection_id:
        if isinstance(detection_id, list):
            for d_id in detection_id:
                is_valid_id, message = is_valid_param_id(d_id, WizInputParam.DETECTION_ID)
                if not is_valid_id:
                    return False, message, None
            validated_values[WizInputParam.DETECTION_ID] = detection_id
        else:
            is_valid_id, message = is_valid_param_id(detection_id, WizInputParam.DETECTION_ID)
            if not is_valid_id:
                return False, message, None
            validated_values[WizInputParam.DETECTION_ID] = [detection_id]

    # Validate issue_id if provided
    if issue_id:
        is_valid_id, message = is_valid_param_id(issue_id, WizInputParam.ISSUE_ID)
        if not is_valid_id:
            return False, message, None
        validated_values[WizInputParam.ISSUE_ID] = issue_id

    # Validate detection type
    type_validation = validate_detection_type(detection_type)
    if not type_validation.is_valid:
        return False, type_validation.error_message, None
    validated_values[WizInputParam.TYPE] = type_validation.value

    # Validate platform
    platform_validation = validate_detection_platform(detection_platform)
    if not platform_validation.is_valid:
        return False, platform_validation.error_message, None
    validated_values[WizInputParam.PLATFORM] = platform_validation.value

    # Validate origin
    origin_validation = validate_detection_origin(detection_origin)
    if not origin_validation.is_valid:
        return False, origin_validation.error_message, None
    validated_values[WizInputParam.ORIGIN] = origin_validation.value

    # Validate cloud_account_or_cloud_organization
    cloud_account_or_cloud_organization_validation = \
        validate_detection_cloud_account_or_cloud_organization(detection_cloud_account_or_cloud_organization)
    if not cloud_account_or_cloud_organization_validation.is_valid:
        return False, cloud_account_or_cloud_organization_validation.error_message, None
    validated_values[WizInputParam.CLOUD_ACCOUNT_OR_CLOUD_ORG] = cloud_account_or_cloud_organization_validation.value

    # Validate creation_minutes_back (only if provided)
    if creation_minutes_back:
        minutes_validation = validate_creation_time_back(creation_minutes_back)
        if not minutes_validation.is_valid:
            return False, minutes_validation.error_message, None
        validated_values[WizInputParam.CREATION_MINUTES_BACK] = minutes_validation.minutes_value

    # Validate severity
    severity_validation = validate_severity(severity)
    if not severity_validation.is_valid:
        return False, severity_validation.error_message, None
    validated_values[WizInputParam.SEVERITY] = severity_validation.severity_list

    # Validate resource_id
    resource_validation = validate_resource_id(resource_id)
    if not resource_validation.is_valid:
        return False, resource_validation.error_message, None
    validated_values[WizInputParam.RESOURCE_ID] = resource_validation.value

    # Validate matched_rule
    matched_rule_validation = validate_matched_rule_id(matched_rule)
    if not matched_rule_validation.is_valid:
        return False, matched_rule_validation.error_message, None
    validated_values[WizInputParam.RULE_MATCH_ID] = matched_rule_validation.value

    validated_values[WizInputParam.RULE_MATCH_NAME] = rule_match_name
    validated_values[WizInputParam.PROJECT_ID] = project_id
    validated_values[DemistoParams.AFTER_TIME] = after_time

    return True, None, validated_values


def validate_all_threat_parameters(parameters_dict):
    """
    Validates all threat parameters in a centralized function

    Args:
        parameters_dict (dict): Dictionary containing all parameters to validate

    Returns:
        tuple: (success, error_message, validated_values)
            - success (bool): True if all validations pass
            - error_message (str): Error message if validation fails
            - validated_values (dict): Dictionary of validated values
    """
    validated_values = {}

    # Extract parameters from dictionary
    issue_id = parameters_dict.get(WizInputParam.ISSUE_ID)
    platform = parameters_dict.get(WizInputParam.PLATFORM)
    origin = parameters_dict.get(WizInputParam.ORIGIN)
    cloud_account_or_cloud_organization = parameters_dict.get(WizInputParam.CLOUD_ACCOUNT_OR_CLOUD_ORG)
    resource_id = parameters_dict.get(WizInputParam.RESOURCE_ID)
    severity = parameters_dict.get(WizInputParam.SEVERITY)
    status = parameters_dict.get(WizInputParam.STATUS)
    creation_days_back = parameters_dict.get(WizInputParam.CREATION_DAYS_BACK)
    project_id = parameters_dict.get(WizInputParam.PROJECT_ID)

    # Check if at least one parameter is provided
    if not any([issue_id, platform, cloud_account_or_cloud_organization, resource_id, severity, status, project_id, creation_days_back]):
        param_list = [
            f"\t{WizInputParam.ISSUE_ID}",
            f"\t{WizInputParam.PLATFORM}",
            f"\t{WizInputParam.ORIGIN}",
            f"\t{WizInputParam.CLOUD_ACCOUNT_OR_CLOUD_ORG}",
            f"\t{WizInputParam.RESOURCE_ID}",
            f"\t{WizInputParam.SEVERITY}",
            f"\t{WizInputParam.STATUS}",
            f"\t{WizInputParam.PROJECT_ID}",
            f"\t{WizInputParam.CREATION_DAYS_BACK}"
        ]
        error_msg = f"You should pass at least one of the following parameters:\n" + "\n".join(param_list)
        demisto.error(error_msg)
        return False, error_msg, None

    # Validate issue_id if provided
    if issue_id:
        is_valid_id, message = is_valid_param_id(issue_id, WizInputParam.ISSUE_ID)
        if not is_valid_id:
            return False, message, None
        validated_values[WizInputParam.ISSUE_ID] = issue_id

    # Validate platform
    if platform:
        platform_validation = validate_detection_platform(platform)
        if not platform_validation.is_valid:
            return False, platform_validation.error_message, None
        validated_values[WizInputParam.PLATFORM] = platform_validation.value

    # Validate origin
    origin_validation = validate_detection_origin(origin)
    if not origin_validation.is_valid:
        return False, origin_validation.error_message, None
    validated_values[WizInputParam.ORIGIN] = origin_validation.value

    # Validate cloud_account_or_cloud_organization
    if cloud_account_or_cloud_organization:
        cloud_account_or_cloud_organization_validation = \
            validate_detection_cloud_account_or_cloud_organization(cloud_account_or_cloud_organization)
        if not cloud_account_or_cloud_organization_validation.is_valid:
            return False, cloud_account_or_cloud_organization_validation.error_message, None
        validated_values[WizInputParam.CLOUD_ACCOUNT_OR_CLOUD_ORG] = cloud_account_or_cloud_organization_validation.value

    # Validate creation_days_back
    if creation_days_back:
        days_validation = validate_creation_time_back(creation_days_back, time_unit='days')
        if not days_validation.is_valid:
            return False, days_validation.error_message, None
        validated_values[WizInputParam.CREATION_DAYS_BACK] = days_validation.days_value

    # Validate severity
    if severity:
        severity_validation = validate_severity(severity)
        if not severity_validation.is_valid:
            return False, severity_validation.error_message, None
        validated_values[WizInputParam.SEVERITY] = severity_validation.severity_list

    # Validate status
    if status:
        status_validation = validate_status(status)
        if not status_validation.is_valid:
            return False, status_validation.error_message, None
        validated_values[WizInputParam.STATUS] = status_validation.status_list

    # Validate resource_id
    if resource_id:
        resource_validation = validate_resource_id(resource_id)
        if not resource_validation.is_valid:
            return False, resource_validation.error_message, None
        validated_values[WizInputParam.RESOURCE_ID] = resource_validation.value

    # Validate project_id
    if project_id:
        project_validation = validate_project(project_id)
        if not project_validation.is_valid:
            return False, project_validation.error_message, None
        validated_values[WizInputParam.PROJECT_ID] = project_validation.value

    return True, None, validated_values


def apply_rule_match_id_filter(variables, matched_rule_id):
    """
    Adds the matched rule ID filter to the query variables

    Args:
        variables (dict): The query variables
        matched_rule_id (str): The matched rule ID

    Returns:
        dict: Updated variables with the filter
    """
    if not matched_rule_id:
        return variables

    if WizApiVariables.FILTER_BY not in variables:
        variables[WizApiVariables.FILTER_BY] = {}

    variables[WizApiVariables.FILTER_BY][WizApiVariables.MATCHED_RULE] = {
        WizApiVariables.ID: matched_rule_id
    }

    return variables


def apply_rule_match_name_filter(variables, matched_rule_name):
    """
    Adds the matched rule name filter to the query variables

    Args:
        variables (dict): The query variables
        matched_rule_name (str): The matched rule name

    Returns:
        dict: Updated variables with the filter
    """
    if not matched_rule_name:
        return variables

    if WizApiVariables.FILTER_BY not in variables:
        variables[WizApiVariables.FILTER_BY] = {}

    variables[WizApiVariables.FILTER_BY][WizApiVariables.MATCHED_RULE_NAME] = {
        WizApiVariables.EQUALS: [matched_rule_name]
    }

    return variables


def apply_creation_in_last_filter(variables, time_value, time_unit='minutes'):
    """
    Adds a creation time filter (minutes or days) to the query variables

    Args:
        variables (dict): The query variables
        time_value (int): Number of time units back
        time_unit (str): The time unit to use ('minutes' or 'days')

    Returns:
        dict: Updated variables with the filter
    """
    if not time_value:
        return variables

    if WizApiVariables.FILTER_BY not in variables:
        variables[WizApiVariables.FILTER_BY] = {}

    # Select the appropriate duration unit based on the time_unit parameter
    duration_unit = DurationUnit.MINUTES if time_unit == 'minutes' else DurationUnit.DAYS

    variables[WizApiVariables.FILTER_BY][WizApiVariables.CREATED_AT] = {
        WizApiVariables.IN_LAST: {
            WizApiVariables.AMOUNT: time_value,
            WizApiVariables.UNIT: duration_unit
        }
    }

    return variables


def apply_creation_after_time_filter(variables, after_time):
    """
    Args:
        variables (dict): The query variables
        after_time (str): The time to filter after

    Returns:
        dict: Updated variables with the filter
    """
    if not after_time:
        return variables

    if WizApiVariables.FILTER_BY not in variables:
        variables[WizApiVariables.FILTER_BY] = {}

    variables[WizApiVariables.FILTER_BY][WizApiVariables.CREATED_AT] = {
        WizApiVariables.AFTER: after_time
    }

    return variables


def apply_detection_id_filter(variables, detection_ids):
    """
    Adds the detection ID filter to the query variables

    Args:
        variables (dict): The query variables
        detection_ids (list): List of detection IDs to filter by

    Returns:
        dict: Updated variables with the filter
    """
    if not detection_ids:
        return variables

    if WizApiVariables.FILTER_BY not in variables:
        variables[WizApiVariables.FILTER_BY] = {}

    variables[WizApiVariables.FILTER_BY][WizApiVariables.ID] = {
        WizApiVariables.EQUALS: detection_ids
    }

    return variables


def apply_issue_id_filter(variables, issue_id, is_detection=True):
    """
    Adds the issue ID filter to the query variables

    Args:
        variables (dict): The query variables
        issue_id (str): The issue ID to filter by

    Returns:
        dict: Updated variables with the filter
    """
    if not issue_id:
        return variables

    if WizApiVariables.FILTER_BY not in variables:
        variables[WizApiVariables.FILTER_BY] = {}

    if is_detection:
        variables[WizApiVariables.FILTER_BY][WizApiVariables.ISSUE_ID] = issue_id
    else:
        variables[WizApiVariables.FILTER_BY][WizApiVariables.ID] = issue_id

    return variables


def apply_detection_type_filter(variables, detection_type):
    """
    Adds the detection type filter to the query variables

    Args:
        variables (dict): The query variables
        detection_type (str): The detection type

    Returns:
        dict: Updated variables with the filter
    """
    if not detection_type:
        return variables

    if WizApiVariables.FILTER_BY not in variables:
        variables[WizApiVariables.FILTER_BY] = {}

    variables[WizApiVariables.FILTER_BY][WizApiVariables.TYPE] = {
        WizApiVariables.EQUALS: [detection_type]
    }

    return variables


def apply_platform_filter(variables, platforms, is_detection=True):
    """
    Adds the platform filter to the query variables

    Args:
        variables (dict): The query variables
        platforms (list or str): The cloud platform(s)
        is_detection (bool): If True, apply filter for detections. If False, apply filter for threats.

    Returns:
        dict: Updated variables with the filter
    """
    if not platforms:
        return variables

    if WizApiVariables.FILTER_BY not in variables:
        variables[WizApiVariables.FILTER_BY] = {}

    # Handle both single platform (str) and multiple platforms (list)
    if isinstance(platforms, str):
        platform_list = [platforms]
    else:
        platform_list = platforms

    # Apply filter based on whether it's for detections or threats
    if is_detection:
        variables[WizApiVariables.FILTER_BY][WizApiVariables.CLOUD_PLATFORM] = {
            WizApiVariables.EQUALS: platform_list
        }
    else:
        if WizApiVariables.RELATED_ENTITY not in variables[WizApiVariables.FILTER_BY]:
            variables[WizApiVariables.FILTER_BY][WizApiVariables.RELATED_ENTITY] = {}

        variables[WizApiVariables.FILTER_BY][WizApiVariables.RELATED_ENTITY][WizApiVariables.CLOUD_PLATFORM] = platform_list

    return variables


def apply_origin_filter(variables, platforms, is_detection=True):
    """
    Adds the platform origin to the query variables

    Args:
        variables (dict): The query variables
        platforms (list or str): The cloud event origin(s)

    Returns:
        dict: Updated variables with the filter
    """
    if not platforms:
        return variables

    if WizApiVariables.FILTER_BY not in variables:
        variables[WizApiVariables.FILTER_BY] = {}

    # Handle both single origin (str) and multiple origins (list)
    if isinstance(platforms, str):
        platform_list = [platforms]
    else:
        platform_list = platforms

    origin_var = WizApiVariables.ORIGIN if is_detection else WizApiVariables.EVENT_ORIGIN
    variables[WizApiVariables.FILTER_BY][origin_var] = {
        WizApiVariables.EQUALS: platform_list
    }

    return variables


def apply_resource_id_filter(variables, resource_id, is_detection=True):
    """
    Adds the resource ID filter to the query variables

    Args:
        variables (dict): The query variables
        resource_id (str): The resource ID

    Returns:
        dict: Updated variables with the filter
    """
    if not resource_id:
        return variables

    if WizApiVariables.FILTER_BY not in variables:
        variables[WizApiVariables.FILTER_BY] = {}

    if is_detection:
        variables[WizApiVariables.FILTER_BY][WizApiVariables.RESOURCE] = {
            WizApiVariables.ID: {
                WizApiVariables.EQUALS: [resource_id]
            }
        }
    else:
        if not variables[WizApiVariables.FILTER_BY].get(WizApiVariables.THREAT_RESOURCE):
            variables[WizApiVariables.FILTER_BY][WizApiVariables.THREAT_RESOURCE] = {}
        variables[WizApiVariables.FILTER_BY][WizApiVariables.THREAT_RESOURCE][WizApiVariables.IDS] = [resource_id]

    return variables


def apply_cloud_account_or_cloud_organization_filter(variables, cloud_account_or_cloud_organization_id_list, is_detection=True):
    """
    Adds the cloud_account_or_cloud_organization filter to the query variables

    Args:
        variables (dict): The query variables
        cloud_account_or_cloud_organization_id_list (str or list): The cloud_account_or_cloud_organization ID(s)
        is_detection (bool): Whether this is for a detection query (True) or other query (False)

    Returns:
        dict: Updated variables with the filter
    """
    if not cloud_account_or_cloud_organization_id_list:
        return variables

    if WizApiVariables.FILTER_BY not in variables:
        variables[WizApiVariables.FILTER_BY] = {}

    # Handle both single cloud_account_or_cloud_organization (str) and multiple cloud_account_or_cloud_organization (list)
    if isinstance(cloud_account_or_cloud_organization_id_list, str):
        cloud_account_or_cloud_organization_list = [cloud_account_or_cloud_organization_id_list]
    else:
        cloud_account_or_cloud_organization_list = cloud_account_or_cloud_organization_id_list

    if is_detection:
        variables[WizApiVariables.FILTER_BY][WizApiVariables.CLOUD_ACCOUNT_OR_CLOUD_ORGANIZATION_ID] = {
            WizApiVariables.EQUALS: cloud_account_or_cloud_organization_list
        }
    else:
        variables[WizApiVariables.FILTER_BY][WizApiVariables.CLOUD_ACCOUNT_OR_CLOUD_ORGANIZATION_ID] = \
            cloud_account_or_cloud_organization_list

    return variables

def apply_severity_filter(variables, severity_list, is_detection=True):
    """
    Adds the severity filter to the query variables

    Args:
        variables (dict): The query variables
        severity_list (list): List of severities to filter by

    Returns:
        dict: Updated variables with the filter
    """
    if not severity_list:
        return variables

    if WizApiVariables.FILTER_BY not in variables:
        variables[WizApiVariables.FILTER_BY] = {}

    if is_detection:
        variables[WizApiVariables.FILTER_BY][WizApiVariables.SEVERITY] = {
            WizApiVariables.EQUALS: severity_list
        }
    else:
        variables[WizApiVariables.FILTER_BY][WizApiVariables.SEVERITY] = severity_list

    return variables


def apply_status_filter(variables, status_list):
    """
    Adds the status filter to the query variables

    Args:
        variables (dict): The query variables
        status_list (list): List of statuses to filter by

    Returns:
        dict: Updated variables with the filter
    """
    if not status_list:
        return variables

    if WizApiVariables.FILTER_BY not in variables:
        variables[WizApiVariables.FILTER_BY] = {}

    variables[WizApiVariables.FILTER_BY][WizApiVariables.STATUS] = status_list

    return variables


def apply_project_id_filter(variables, project_id, is_detection=True):
    """
    Adds the project ID filter to the query variables

    Args:
        variables (dict): The query variables
        project_id (str): The project ID

    Returns:
        dict: Updated variables with the filter
    """
    if not project_id:
        return variables

    if WizApiVariables.FILTER_BY not in variables:
        variables[WizApiVariables.FILTER_BY] = {}

    project_var = WizApiVariables.PROJECT_ID if is_detection else WizApiVariables.PROJECT
    variables[WizApiVariables.FILTER_BY][project_var] = project_id

    return variables


def apply_all_detection_filters(variables, validated_values):
    """
    Applies all filters to the query variables in a centralized function

    Args:
        variables (dict): Base query variables
        validated_values (dict): Dictionary of validated values

    Returns:
        dict: Updated query variables with all filters applied
    """
    # Apply time filter based on which parameter is present
    if validated_values.get(DemistoParams.AFTER_TIME):
        variables = apply_creation_after_time_filter(variables, validated_values.get(DemistoParams.AFTER_TIME))
    elif validated_values.get(WizInputParam.CREATION_MINUTES_BACK):
        variables = apply_creation_in_last_filter(variables, validated_values.get(WizInputParam.CREATION_MINUTES_BACK))

    # Apply other filters
    variables = apply_detection_id_filter(variables, validated_values.get(WizInputParam.DETECTION_ID))
    variables = apply_issue_id_filter(variables, validated_values.get(WizInputParam.ISSUE_ID))
    variables = apply_detection_type_filter(variables, validated_values.get(WizInputParam.TYPE))
    variables = apply_platform_filter(variables, validated_values.get(WizInputParam.PLATFORM))
    variables = apply_origin_filter(variables, validated_values.get(WizInputParam.ORIGIN))
    variables = apply_cloud_account_or_cloud_organization_filter(variables, validated_values.get(WizInputParam.CLOUD_ACCOUNT_OR_CLOUD_ORG))
    variables = apply_resource_id_filter(variables, validated_values.get(WizInputParam.RESOURCE_ID))
    variables = apply_severity_filter(variables, validated_values.get(WizInputParam.SEVERITY))
    variables = apply_rule_match_id_filter(variables, validated_values.get(WizInputParam.RULE_MATCH_ID))
    variables = apply_rule_match_name_filter(variables, validated_values.get(WizInputParam.RULE_MATCH_NAME))
    variables = apply_project_id_filter(variables, validated_values.get(WizInputParam.PROJECT_ID))

    return variables


def get_filtered_detections(detection_id=None, issue_id=None, detection_type=None, detection_platform=None,
                            detection_origin=None, detection_cloud_account_or_cloud_organization=None, resource_id=None, severity=None,
                            creation_minutes_back=None, rule_match_id=None, rule_match_name=None, project_id=None,
                            after_time=None, add_detection_url=True, api_limit=WIZ_API_LIMIT, paginate=True):
    """
    Retrieves Filtered Detections

    Args:
        detection_id (str or list): Detection ID or list of detection IDs
        issue_id (str): Issue ID
        detection_type (str): Type of detections
        detection_platform (list): Cloud platforms
        detection_origin (list): Detection origins
        detection_cloud_account_or_cloud_organization (str): Detection cloud_account_or_cloud_organization
        resource_id (str): Resource ID
        severity (str): Severity level
        creation_minutes_back (str): Number of minutes back for creation filter
        rule_match_id (str): Matched rule ID
        rule_match_name (str): Matched rule name
        project_id (str): Project ID
        after_time (str): Timestamp for filtering detections created after this time (used for fetch incidents)

    Returns:
        list/str: List of detections or error message
    """
    demisto.info(f"Detection ID is {detection_id}\n"
                 f"Issue ID is {issue_id}\n"
                 f"Detection type is {detection_type}\n"
                 f"Detection platform is {detection_platform}\n"
                 f"Detection origin is {detection_origin}\n"
                 f"Detection cloud_account_or_cloud_organization is {detection_cloud_account_or_cloud_organization}\n"
                 f"Resource ID is {resource_id}\n"
                 f"Severity is {severity}\n"
                 f"Creation minutes back is {creation_minutes_back}\n"
                 f"After time is {after_time}\n"
                 f"Matched rule is {rule_match_id}\n"
                 f"Matched rule name is {rule_match_name}\n"
                 f"Project ID is {project_id}\n"
                 f"First is {api_limit}\n")

    # Create parameters dictionary for validation
    parameters_dict = {
        WizInputParam.DETECTION_ID: detection_id,
        WizInputParam.ISSUE_ID: issue_id,
        WizInputParam.TYPE: detection_type,
        WizInputParam.PLATFORM: detection_platform,
        WizInputParam.ORIGIN: detection_origin,
        WizInputParam.CLOUD_ACCOUNT_OR_CLOUD_ORG: detection_cloud_account_or_cloud_organization,
        WizInputParam.RESOURCE_ID: resource_id,
        WizInputParam.SEVERITY: severity,
        WizInputParam.CREATION_MINUTES_BACK: creation_minutes_back,
        WizInputParam.RULE_MATCH_ID: rule_match_id,
        WizInputParam.RULE_MATCH_NAME: rule_match_name,
        WizInputParam.PROJECT_ID: project_id,
        DemistoParams.AFTER_TIME: after_time
    }

    validation_success, error_message, validated_values = validate_all_detection_parameters(parameters_dict)

    if not validation_success or error_message:
        return error_message

    detection_variables = PULL_DETECTIONS_VARIABLES.copy()
    detection_variables[WizApiVariables.FIRST] = api_limit
    detection_variables = apply_all_detection_filters(detection_variables, validated_values)

    wiz_detections = query_detections(query=PULL_DETECTIONS_QUERY, variables=detection_variables,
                                      paginate=paginate)

    if add_detection_url:
        for detection in wiz_detections:
            detection[WizApiVariables.URL] = get_detection_url(detection)

    return wiz_detections


def apply_all_threat_filters(variables, validated_values):
    """
    Applies all threat filters to the query variables in a centralized function

    Args:
        variables (dict): Base query variables
        validated_values (dict): Dictionary of validated values

    Returns:
        dict: Updated query variables with all filters applied
    """
    variables = apply_issue_id_filter(variables, validated_values.get(WizInputParam.ISSUE_ID), is_detection=False)
    variables = apply_creation_in_last_filter(variables, validated_values.get(WizInputParam.CREATION_DAYS_BACK), 'days')
    variables = apply_platform_filter(variables, validated_values.get(WizInputParam.PLATFORM), is_detection=False)
    variables = apply_cloud_account_or_cloud_organization_filter(variables, validated_values.get(WizInputParam.CLOUD_ACCOUNT_OR_CLOUD_ORG), is_detection=False)
    variables = apply_resource_id_filter(variables, validated_values.get(WizInputParam.RESOURCE_ID), is_detection=False)
    variables = apply_severity_filter(variables, validated_values.get(WizInputParam.SEVERITY), is_detection=False)
    variables = apply_status_filter(variables, validated_values.get(WizInputParam.STATUS))
    variables = apply_origin_filter(variables, validated_values.get(WizInputParam.ORIGIN), is_detection=False)
    variables = apply_project_id_filter(variables, validated_values.get(WizInputParam.PROJECT_ID), is_detection=False)

    return variables


def get_filtered_threats(issue_id=None, platform=None, cloud_account_or_cloud_organization=None, resource_id=None, origin=None,
                         severity=None, status=None, creation_days_back=None, project_id=None,
                         add_threat_url=True, api_limit=WIZ_API_LIMIT, paginate=True):
    """
    Retrieves Filtered Threats

    Args:
        issue_id (str): Issue ID
        platform (list): Cloud platforms
        origin (list): Cloud origin
        cloud_account_or_cloud_organization (str): Cloud account or cloud organization
        resource_id (str): Resource ID
        severity (str): Severity level
        status (list): Threat status
        creation_days_back (str): Number of days back for creation filter
        project_id (str): Project ID
        add_threat_url (bool): Whether to add threat URL to the results
        api_limit (int): Limit for API pagination
        paginate (bool): Whether to paginate results

    Returns:
        list/str: List of threats or error message
    """
    demisto.info(f"Issue ID is {issue_id}\n"
                 f"Platform is {platform}\n"
                 f"Origin is {origin}\n"
                 f"Cloud account or cloud organization is {cloud_account_or_cloud_organization}\n"
                 f"Resource ID is {resource_id}\n"
                 f"Severity is {severity}\n"
                 f"Status is {status}\n"
                 f"Creation days back is {creation_days_back}\n"
                 f"Project ID is {project_id}\n"
                 f"First is {api_limit}\n")

    parameters_dict = {
        WizInputParam.ISSUE_ID: issue_id,
        WizInputParam.PLATFORM: platform,
        WizInputParam.ORIGIN: origin,
        WizInputParam.CLOUD_ACCOUNT_OR_CLOUD_ORG: cloud_account_or_cloud_organization,
        WizInputParam.RESOURCE_ID: resource_id,
        WizInputParam.SEVERITY: severity,
        WizInputParam.STATUS: status,
        WizInputParam.CREATION_DAYS_BACK: creation_days_back,
        WizInputParam.PROJECT_ID: project_id
    }

    validation_success, error_message, validated_values = validate_all_threat_parameters(parameters_dict)

    if not validation_success or error_message:
        return error_message

    threat_variables = PULL_THREAT_ISSUE_VARIABLES.copy()
    threat_variables[WizApiVariables.FIRST] = api_limit
    threat_variables = apply_all_threat_filters(threat_variables, validated_values)

    wiz_threats = query_threats(query=PULL_ISSUE_QUERY, variables=threat_variables,
                                paginate=paginate)

    if add_threat_url:
        for threat in wiz_threats:
            threat[WizApiVariables.URL] = get_threat_url(threat)

    return wiz_threats


def get_error_output(wiz_api_response):
    error_output_message = ''
    first_error_message = ''
    if WizApiResponse.ERRORS in wiz_api_response:
        for error_dict in wiz_api_response[WizApiResponse.ERRORS]:
            if WizApiResponse.MESSAGE in error_dict:
                error_message = error_dict[WizApiResponse.MESSAGE]

                # Do not print duplicate errors
                if first_error_message and first_error_message == error_message:
                    continue
                if not first_error_message:
                    first_error_message = error_message

                error_output_message = error_output_message + error_message + '\n'

    return error_output_message if error_output_message else wiz_api_response


def is_valid_uuid(uuid_string):
    if not isinstance(uuid_string, str):
        uuid_string = str(uuid_string)
    try:
        uuid_obj = uuid.UUID(uuid_string)
        return str(uuid_obj) == uuid_string
    except ValueError:
        return False
    except Exception:
        return False


def is_valid_param_id(detection_id, param_name=WizInputParam.DETECTION_ID):
    if not detection_id:
        error_msg = f"You should pass a {param_name}."
        demisto.error(error_msg)
        return False, error_msg

    if not is_valid_uuid(detection_id):
        error_msg = f"Wrong format: {param_name} should be in UUID format."

        demisto.error(error_msg)
        return False, error_msg

    return True, f"{param_name}: {detection_id} is in a valid format"


def get_detections():
    """
    Retrieves detections based on command arguments.

    Returns:
        CommandResults: Command results object containing the detections
    """
    demisto_args = demisto.args()
    detection_type = demisto_args.get(WizInputParam.TYPE)
    detection_platform = demisto_args.get(WizInputParam.PLATFORM)
    detection_origin = demisto_args.get(WizInputParam.ORIGIN)
    detection_cloud_account_or_cloud_organization = demisto_args.get(WizInputParam.CLOUD_ACCOUNT_OR_CLOUD_ORG)
    resource_id = demisto_args.get(WizInputParam.RESOURCE_ID)
    severity = demisto_args.get(WizInputParam.SEVERITY)
    creation_minutes_back = demisto_args.get(WizInputParam.CREATION_MINUTES_BACK, '10')
    matched_rule = demisto_args.get(WizInputParam.RULE_MATCH_ID)
    matched_rule_name = demisto_args.get(WizInputParam.RULE_MATCH_NAME)
    project_id = demisto_args.get(WizInputParam.PROJECT_ID)

    detections = get_filtered_detections(
        detection_type=detection_type,
        detection_platform=detection_platform,
        detection_origin=detection_origin,
        detection_cloud_account_or_cloud_organization=detection_cloud_account_or_cloud_organization,
        resource_id=resource_id,
        severity=severity,
        creation_minutes_back=creation_minutes_back,
        rule_match_id=matched_rule,
        rule_match_name=matched_rule_name,
        project_id=project_id
    )

    if isinstance(detections, str):
        # this means the Detection is an error
        return_error(detections)
    else:
        return CommandResults(outputs_prefix=OutputPrefix.DETECTIONS, outputs=detections,
                              raw_response=detections)


def get_single_detection():
    """
    Retrieves a single detection by ID.

    Returns:
        CommandResults: Command results object containing the detection
    """
    demisto_args = demisto.args()
    detection_id = demisto_args.get(WizInputParam.DETECTION_ID)
    if not detection_id:
        return_error(f"Missing required argument: {WizInputParam.DETECTION_ID}")

    detection = get_filtered_detections(
        detection_id=detection_id
    )
    if isinstance(detection, str):
        # this means the Detection is an error
        return_error(detection)
    else:
        return CommandResults(outputs_prefix=OutputPrefix.DETECTION, outputs=detection,
                              readable_output=detection, raw_response=detection)


def get_single_threat():
    """
    Retrieves a single threat by Issue ID.

    Returns:
        CommandResults: Command results object containing the threat
    """
    demisto_args = demisto.args()
    issue_id = demisto_args.get(WizInputParam.ISSUE_ID)
    if not issue_id:
        return_error(f"Missing required argument: {WizInputParam.ISSUE_ID}")

    threat = get_filtered_threats(
        issue_id=issue_id
    )
    if isinstance(threat, str):
        # this means the Threat is an error
        return_error(threat)
    else:
        return CommandResults(outputs_prefix=OutputPrefix.THREAT, outputs=threat,
                              readable_output=threat, raw_response=threat)


def get_threats():
    """
    Retrieves threats based on command arguments.

    Returns:
        CommandResults: Command results object containing the threats
    """
    demisto_args = demisto.args()
    creation_days_back = demisto_args.get(WizInputParam.CREATION_DAYS_BACK, '5')
    platform = demisto_args.get(WizInputParam.PLATFORM)
    project_id = demisto_args.get(WizInputParam.PROJECT_ID)
    resource_id = demisto_args.get(WizInputParam.RESOURCE_ID)
    severity = demisto_args.get(WizInputParam.SEVERITY)
    status = demisto_args.get(WizInputParam.STATUS)
    cloud_account_or_cloud_organization = demisto_args.get(WizInputParam.CLOUD_ACCOUNT_OR_CLOUD_ORG)

    threats = get_filtered_threats(
        platform=platform,
        cloud_account_or_cloud_organization=cloud_account_or_cloud_organization,
        resource_id=resource_id,
        severity=severity,
        status=status,
        creation_days_back=creation_days_back,
        project_id=project_id
    )

    if isinstance(threats, str):
        # this means the threats retrieval resulted in an error
        return_error(threats)
    else:
        return CommandResults(outputs_prefix=OutputPrefix.THREATS, outputs=threats,
                              raw_response=threats)


def main():
    params = demisto.params()
    set_authentication_endpoint(params.get(DemistoParams.AUTH_ENDPOINT))
    set_api_endpoint(params.get(DemistoParams.API_ENDPOINT, ''))
    try:
        command = demisto.command()

        if command == DemistoCommands.TEST_MODULE:
            test_module()

        elif command == DemistoCommands.FETCH_INCIDENTS:
            fetch_incidents()

        elif command == DemistoCommands.WIZ_GET_DETECTION:
            command_result = get_single_detection()
            return_results(command_result)

        elif command == DemistoCommands.WIZ_GET_DETECTIONS:
            command_result = get_detections()
            return_results(command_result)

        elif command == DemistoCommands.WIZ_GET_THREAT:
            command_result = get_single_threat()
            return_results(command_result)

        elif command == DemistoCommands.WIZ_GET_THREATS:
            command_result = get_threats()
            return_results(command_result)

        else:
            raise Exception('Unrecognized command: ' + command)
    except Exception as err:
        demisto.error(str(traceback.format_exc()))
        return_error(f"An error occurred: {str(err)}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
