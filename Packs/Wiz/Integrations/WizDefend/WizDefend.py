import uuid
import traceback

from CommonServerPython import *
import demistomock as demisto
from urllib import parse

WIZ_VERSION = "1.0.0"
WIZ_DEFEND = "wiz_defend"
WIZ_DEFEND_INCIDENT_TYPE = "WizDefend Detection"
USER_AGENT_NAME = "xsoar_defend"
INTEGRATION_GUID = "8864e131-72db-4928-1293-e292f0ed699f"
WIZ_DOMAIN_URL = ""

DEMISTO_OCCURRED_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
WIZ_API_LIMIT = 250
API_MIN_FETCH = 10
API_MAX_FETCH = 1000
API_END_CURSOR: Optional[str] = ""
MAX_DAYS_FIRST_FETCH_DETECTIONS = 2
FETCH_INTERVAL_MINIMUM_MIN = 10
FETCH_INTERVAL_MAXIMUM_MIN = 600
DEFAULT_FETCH_BACK = "12 hours"
MAX_FETCH_BUFFER = 15  # Percentage buffer for fetch interval calculations


# Threats
THREATS_DAYS_MIN = 1
THREATS_DAYS_MAX = 30
THREATS_DAYS_DEFAULT = 5


class WizInputParam:
    DETECTION_ID = "detection_id"
    ISSUE_ID = "issue_id"
    TYPE = "type"
    PLATFORM = "platform"
    ORIGIN = "origin"
    CLOUD_ACCOUNT_OR_CLOUD_ORG = "cloud_account_or_cloud_organization"
    RESOURCE_ID = "resource_id"
    SEVERITY = "severity"
    STATUS = "status"
    CREATION_MINUTES_BACK = "creation_minutes_back"
    CREATION_DAYS_BACK = "creation_days_back"
    RULE_MATCH_ID = "rule_match_id"
    RULE_MATCH_NAME = "rule_match_name"
    PROJECT_ID = "project"
    RESOLUTION_REASON = "resolution_reason"
    RESOLUTION_NOTE = "resolution_note"
    REOPEN_NOTE = "reopen_note"
    NOTE = "note"


class WizApiResponse:
    DATA = "data"
    DETECTIONS = "detections"
    ISSUES = "issues"
    UPDATE_ISSUE = "updateIssue"
    CREATE_ISSUE_NOTE = "createIssueNote"
    CLOUD_RESOURCES = "cloudResources"
    PROJECTS = "projects"
    GRAPH_SEARCH = "graphSearch"
    NODES = "nodes"
    PAGE_INFO = "pageInfo"
    HAS_NEXT_PAGE = "hasNextPage"
    END_CURSOR = "endCursor"
    ACCESS_TOKEN = "access_token"
    FILTER_BY = "filterBy"
    TYPE = "type"
    ERRORS = "errors"
    MESSAGE = "message"
    NOTES = "notes"


class WizApiInputFields:
    API_ENDPOINT = "api_endpoint"
    AUTH_ENDPOINT = "auth_endpoint"
    CLIENT_ID = "client_id"
    CLIENT_SECRET = "client_secret"


class DemistoParams:
    CREDENTIALS = "credentials"
    IDENTIFIER = "identifier"
    PASSWORD = "password"
    AUTH_ENDPOINT = "auth_endpoint"
    API_ENDPOINT = "api_endpoint"
    MAX_FETCH = "max_fetch"
    FIRST_FETCH = "first_fetch"
    TIME = "time"
    NAME = "name"
    OCCURRED = "occurred"
    RAW_JSON = "rawJSON"
    SEVERITY = "severity"
    MIRROR_ID = "dbotMirrorId"
    AFTER_TIME = "after_time"
    URL = "url"
    IS_FETCH = "isFetch"
    INCIDENT_FETCH_INTERVAL = "incidentFetchInterval"
    INCIDENT_TYPE = "incidentType"


class WizApiVariables:
    FIRST = "first"
    AFTER = "after"
    BEFORE = "before"
    FILTER_BY = "filterBy"
    FILTER_SCOPE = "filterScope"
    ORDER_BY = "orderBy"
    STATUS = "status"
    CREATED_AT = "createdAt"
    FIELD = "field"
    DIRECTION = "direction"
    TYPE = "type"
    PROVIDER_UNIQUE_ID = "providerUniqueId"
    RELATED_ENTITY = "relatedEntity"
    CLOUD_PLATFORM = "cloudPlatform"
    ID = "id"
    ISSUE_ID = "issueId"
    EQUALS = "equals"
    SEVERITY = "severity"
    IN_LAST = "inLast"
    AMOUNT = "amount"
    UNIT = "unit"
    RESOURCE = "resource"
    MATCHED_RULE = "matchedRule"
    MATCHED_RULE_NAME = "matchedRuleName"
    PROJECT_ID = "projectId"
    PROJECT = "project"
    NAME = "name"
    RULE = "rule"
    RULE_MATCH = "ruleMatch"
    ORIGIN = "origin"
    EVENT_ORIGIN = "eventOrigin"
    CLOUD_ACCOUNT_OR_CLOUD_ORGANIZATION_ID = "cloudAccountOrCloudOrganizationId"
    URL = "url"
    THREAT_RESOURCE = "threatResource"
    IDS = "ids"
    FETCH_CLOUD_ACCOUNTS_AND_CLOUD_ORG = "fetchCloudAccountsAndCloudOrganizations"
    PATCH = "patch"
    NOTE = "note"
    RESOLUTION_REASON = "resolutionReason"


class WizThreatVariables:
    ALL_ISSUE_DETECTIONS = "ALL_ISSUE_DETECTIONS"
    THREAT_DETECTION = "THREAT_DETECTION"


class WizStatus:
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    REJECTED = "REJECTED"
    RESOLVED = "RESOLVED"


class WizOrderByFields:
    SEVERITY = "SEVERITY"
    CREATED_AT = "CREATED_AT"


class WizOrderDirection:
    DESC = "DESC"
    ASC = "ASC"


class WizDetectionStatus:
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    CLOSED = "CLOSED"
    REJECTED = "REJECTED"


class WizIssueType:
    TOXIC_COMBINATION = "TOXIC_COMBINATION"
    THREAT_DETECTION = "THREAT_DETECTION"
    CLOUD_CONFIGURATION = "CLOUD_CONFIGURATION"


class WizOperation:
    REJECT = "reject"
    RESOLUTION = "resolution"


class WizSeverity:
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class DemistoCommands:
    TEST_MODULE = "test-module"
    FETCH_INCIDENTS = "fetch-incidents"
    WIZ_DEFEND_GET_DETECTIONS = "wiz-defend-get-detections"
    WIZ_DEFEND_GET_DETECTION = "wiz-defend-get-detection"
    WIZ_DEFEND_GET_THREAT = "wiz-defend-get-threat"
    WIZ_DEFEND_GET_THREATS = "wiz-defend-get-threats"
    WIZ_DEFEND_REOPEN_THREAT = "wiz-defend-reopen-threat"
    WIZ_DEFEND_RESOLVE_THREAT = "wiz-defend-resolve-threat"
    WIZ_DEFEND_SET_THREAT_IN_PROGRESS = "wiz-defend-set-threat-in-progress"
    WIZ_DEFEND_SET_THREAT_COMMENT = "wiz-defend-set-threat-comment"
    WIZ_DEFEND_CLEAR_THREAT_COMMENTS = "wiz-defend-clear-threat-comments"


class AuthParams:
    GRANT_TYPE = "grant_type"
    AUDIENCE = "audience"
    CLIENT_ID = "client_id"
    CLIENT_SECRET = "client_secret"


class HeaderFields:
    CONTENT_TYPE = "Content-Type"
    USER_AGENT = "User-Agent"
    AUTHORIZATION = "Authorization"


class ContentTypes:
    JSON = "application/json"
    FORM_URLENCODED = "application/x-www-form-urlencoded"


class OutputPrefix:
    DETECTIONS = "Wiz.Manager.Detections"
    DETECTION = "Wiz.Manager.Detection"
    THREAT = "Wiz.Manager.Threat"
    THREATS = "Wiz.Manager.Threats"


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
            ValidationType.STATUS_LIST: self.status_list,
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
    api_dict = {GENERATED_THREAT: "GENERATED_THREAT", DID_NOT_GENERATE_THREAT: "MATCH_ONLY"}

    @classmethod
    def values(cls):
        """Get all available detection types with capital letters"""
        return [key for key in cls.api_dict if any(c.isupper() for c in key)]

    @classmethod
    def api_values(cls):
        """Get all available API values (values in api_dict)"""
        return list(cls.api_dict.values())

    @classmethod
    def get_api_value(cls, user_input):
        """Convert user-friendly input to API value using api_dict

        Args:
            user_input: String or list of strings to convert

        Returns:
            Single API value (if string input) or list of API values (if list input)
        """
        if not user_input:
            return None

        # Handle list input
        if isinstance(user_input, list):
            api_values = []
            for item in user_input:
                if item:  # Skip empty/None items
                    item_lower = item.lower()
                    for friendly_value, api_value in cls.api_dict.items():
                        if friendly_value.lower() in item_lower:
                            api_values.append(api_value)
                            break
            return api_values if api_values else None

        # Handle string input (original logic)
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
        return [getattr(cls, attr) for attr in dir(cls) if not attr.startswith("_") and not callable(getattr(cls, attr))]


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
        return [getattr(cls, attr) for attr in dir(cls) if not attr.startswith("_") and not callable(getattr(cls, attr))]


def get_integration_user_agent():
    integration_user_agent = f"{INTEGRATION_GUID}/{USER_AGENT_NAME}/{WIZ_VERSION}"
    return integration_user_agent


# Standard headers
HEADERS_AUTH = {HeaderFields.CONTENT_TYPE: ContentTypes.FORM_URLENCODED, HeaderFields.USER_AGENT: get_integration_user_agent()}

HEADERS = {HeaderFields.CONTENT_TYPE: ContentTypes.JSON, HeaderFields.USER_AGENT: get_integration_user_agent()}

TOKEN = None
URL = ""
AUTH_E = ""

# Pull Detections
PULL_DETECTIONS_QUERY = """
query Detections($filterBy: DetectionFilters, $first: Int, $after: String, $orderBy: DetectionOrder,
$includeTriggeringEvents: Boolean = true) {
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
    WizApiVariables.ORDER_BY: {
        WizApiVariables.FIELD: WizOrderByFields.CREATED_AT,
        WizApiVariables.DIRECTION: WizOrderDirection.DESC,
    }
}

PULL_ISSUE_QUERY = """
query IssuesTable($filterBy: IssueFilters, $filterScope: IssueFiltersScope, $first: Int, $after: String, $orderBy: IssueOrder,
$fetchSecurityScoreImpact: Boolean = false, $fetchThreatDetectionDetails: Boolean = false,
$securityScoreImpactSelection: SecurityScoreImpactSelection, $fetchTotalCount: Boolean = true,
$fetchActorsAndResourcesGraphEntities: Boolean = false, $fetchCloudAccountsAndCloudOrganizations: Boolean = false,
$fetchMultipleSourceRules: Boolean = false, $fetchCommentThread: Boolean = false, $fetchThreatCenterActors: Boolean = false,
$fetchTdrLogic: Boolean = false, $fetchSecuritySubCategories: Boolean = false) {
  issues: issuesV2(
    filterBy: $filterBy
    first: $first
    after: $after
    orderBy: $orderBy
    filterScope: $filterScope
  ) {
    nodes {
      id
      type
      resolutionNote
      resolvedAt
      resolutionReason
      ...ResolvedByUser
      control {
        id
        name
        description
        severity
        type
        query
        enabled
        enabledForLBI
        enabledForMBI
        enabledForHBI
        enabledForUnattributed
        tagsV2 {
          key
          value
        }
        risks
        threats
        sourceCloudConfigurationRule {
          id
          name
        }
        serviceTickets {
          ...ControlServiceTicket
        }
      }
      sourceRules {
        ...SourceRuleFields
        securitySubCategories @include(if: $fetchSecuritySubCategories) {
          id
          title
          category {
            id
            name
            framework {
              id
              name
              enabled
            }
          }
        }
      }
      sourceRules @include(if: $fetchMultipleSourceRules) {
        ...SourceRuleFields
        securitySubCategories @include(if: $fetchSecuritySubCategories) {
          id
          title
          category {
            id
            name
            framework {
              id
              name
              enabled
            }
          }
        }
      }
      createdAt
      updatedAt
      resolvedAt
      dueAt
      rejectionExpiredAt
      projects {
        id
        name
        slug
        isFolder
        businessUnit
        riskProfile {
          businessImpact
        }
      }
      status
      severity
      resolutionReason
      entitySnapshot {
        id
        type
        status
        name
        cloudPlatform
        region
        subscriptionName
        subscriptionId
        subscriptionExternalId
        nativeType
        kubernetesClusterId
        kubernetesClusterName
        kubernetesNamespaceName
        tags
        externalId
      }
      notes {
        id
        text
      }
      environments
      cloudAccounts @include(if: $fetchCloudAccountsAndCloudOrganizations) {
        id
        name
        externalId
        cloudProvider
      }
      cloudOrganizations @include(if: $fetchCloudAccountsAndCloudOrganizations) {
        id
        name
        externalId
        cloudProvider
      }
      threatDetectionDetails @include(if: $fetchThreatDetectionDetails) {
        ...ThreatDetectionDetailsActorsResources
        ...ThreatDetectionDetailsMainDetection
        detections(first: 0) {
          totalCount
        }
        eventOrigin
      }
      threatCenterActors @include(if: $fetchThreatCenterActors) {
        id
        name
        type
      }
      serviceTickets {
        id
        externalId
        name
        url
      }
      applicationServices {
        id
        displayName
      }
      commentThread @include(if: $fetchCommentThread) {
        id
        hasComments
      }
    }
    pageInfo {
      hasNextPage
      endCursor
    }
    totalCount @include(if: $fetchTotalCount)
  }
}

fragment ResolvedByUser on Issue {
  resolvedBy {
    user {
      id
      email
      name
    }
  }
}

fragment ControlServiceTicket on ServiceTicket {
  id
  externalId
  name
  url
  project {
    id
    name
  }
  integration {
    id
    type
    name
    typeConfiguration {
      type
      iconUrl
    }
  }
}

fragment SourceRuleFields on IssueSourceRule {
  ... on CloudConfigurationRule {
    id
    tags {
      key
      value
    }
    builtin
    createdBy {
      name
    }
    name
    description
    subjectEntityType
    hasAutoRemediation
    cloudProvider
    securityScoreImpact(selection: $securityScoreImpactSelection) @include(if: $fetchSecurityScoreImpact)
    risks
    threats
    control {
      id
      resolutionRecommendation
    }
  }
  ... on CloudEventRule {
    id
    name
    cloudEventRuleType: type
    description
    ruleSeverity: severity
    builtin
    createdBy {
      name
    }
    generateIssues
    generateFindings
    enabled
    sourceType
    ...CloudEventRuleLogicFields @include(if: $fetchTdrLogic)
    securityScoreImpact(selection: $securityScoreImpactSelection) @include(if: $fetchSecurityScoreImpact)
    risks
    threats
  }
  ... on Control {
    id
    tagsV2 {
      key
      value
    }
    name
    query
    type
    enabled
    enabledForHBI
    enabledForLBI
    enabledForMBI
    enabledForUnattributed
    builtin
    createdBy {
      name
    }
    resolutionRecommendation
    controlDescription: description
    securityScoreImpact(selection: $securityScoreImpactSelection) @include(if: $fetchSecurityScoreImpact)
    risks
    threats
  }
}

fragment CloudEventRuleLogicFields on CloudEventRule {
  params {
    ...CloudEventRuleParamsLogicFields
  }
}

fragment CloudEventRuleParamsLogicFields on CorrelationCloudEventRuleParams {
  securityGraphContext {
    description
    inUse
  }
  detectionThresholds {
    inUse
  }
  behavioralBaselines {
    id
    builtInId
    title
    description
  }
}

fragment ThreatDetectionDetailsActorsResources on ThreatDetectionIssueDetails {
  actorsMaxCountReached
  actorsTotalCount
  actors {
    id
    name
    externalId
    providerUniqueId
    type
    nativeType
    graphEntity @include(if: $fetchActorsAndResourcesGraphEntities) {
      id
      deletedAt
      type
      name
      properties
    }
  }
  resourcesTotalCount
  resourcesMaxCountReached
  resources {
    id
    name
    externalId
    providerUniqueId
    type
    nativeType
    graphEntity @include(if: $fetchActorsAndResourcesGraphEntities) {
      id
      type
      deletedAt
      name
      properties
    }
  }
}

fragment ThreatDetectionDetailsMainDetection on ThreatDetectionIssueDetails {
  mainDetection {
    id
    startedAt
    severity
    description(format: MARKDOWN)
    ruleMatch {
      rule {
        id
        name
        origins
      }
    }
  }
}
"""

UPDATE_ISSUE_QUERY = """
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
"""
CREATE_COMMENT_QUERY = """
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
    """
DELETE_NOTE_QUERY = """
    mutation DeleteIssueNote($input: DeleteIssueNoteInput!) {
    deleteIssueNote(input: $input) {
      _stub
    }
  }
    """

PULL_THREAT_ISSUE_VARIABLES = {
    WizApiVariables.FILTER_BY: {WizApiVariables.TYPE: [WizThreatVariables.THREAT_DETECTION]},
    WizApiVariables.FILTER_SCOPE: WizThreatVariables.ALL_ISSUE_DETECTIONS,
    WizApiVariables.FETCH_CLOUD_ACCOUNTS_AND_CLOUD_ORG: True,
    WizApiVariables.ORDER_BY: {
        WizApiVariables.FIELD: WizOrderByFields.CREATED_AT,
        WizApiVariables.DIRECTION: WizOrderDirection.DESC,
    },
}


class FetchIncident:
    """
    Class to manage fetch incidents functionality with pagination support using last run only
    """

    def __init__(self):
        """Initialize FetchIncident with last run data"""
        self.last_run_data = demisto.getLastRun()
        self.api_start_run_time = datetime.now().strftime(DEMISTO_OCCURRED_FORMAT)

        # Extract pagination values from last run using enums
        self.end_cursor = self.last_run_data.get(WizApiResponse.END_CURSOR)
        self.stored_after = self.last_run_data.get(WizApiVariables.AFTER)
        self.stored_before = self.last_run_data.get(WizApiVariables.BEFORE)
        self.last_run_time = self.get_last_run_time()

        self._validate_and_reset_params()

    def get_last_run_time(self):
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
            demisto.info("First Time Fetch")
            first_fetch_param = demisto_params.get(DemistoParams.FIRST_FETCH, DEFAULT_FETCH_BACK).strip()
            last_run = get_fetch_timestamp(first_fetch_param)
            return last_run

        # Check if last_run is older than MAX_DAYS_FIRST_FETCH_DETECTIONS
        try:
            last_run_datetime = datetime.strptime(last_run, DEMISTO_OCCURRED_FORMAT)
            max_days_ago = datetime.now() - timedelta(days=MAX_DAYS_FIRST_FETCH_DETECTIONS)

            if last_run_datetime < max_days_ago:
                demisto.info(
                    f"Last run time ({last_run}) is more than {MAX_DAYS_FIRST_FETCH_DETECTIONS} days ago. "
                    f"Using {MAX_DAYS_FIRST_FETCH_DETECTIONS} days ago as the fetch time."
                )

                last_run = max_days_ago.strftime(DEMISTO_OCCURRED_FORMAT)
        except Exception as e:
            demisto.error(
                f"Error parsing last run time: {str(e)}. Using {MAX_DAYS_FIRST_FETCH_DETECTIONS} days ago as fetch time."
            )
            max_days_ago = datetime.now() - timedelta(days=MAX_DAYS_FIRST_FETCH_DETECTIONS)
            last_run = max_days_ago.strftime(DEMISTO_OCCURRED_FORMAT)

        return last_run

    def reset_params(self, reason="Invalid parameters detected"):
        """
        Reset pagination parameters to safe defaults

        Args:
            reason (str): Reason for reset (for logging)
        """
        demisto.info(f"Resetting fetch parameters: {reason}")

        if self.last_run_time:
            safe_after_str = self.last_run_time
        else:
            # Calculate safe_after_str as api_start_run_time - incidentFetchInterval
            try:
                demisto_params = demisto.params()
                fetch_interval_str = demisto_params.get(DemistoParams.INCIDENT_FETCH_INTERVAL, str(FETCH_INTERVAL_MINIMUM_MIN))

                # Validate the fetch interval using existing validation
                validation_response = validate_fetch_interval(fetch_interval_str)
                if not validation_response.is_valid:
                    demisto.error(f"Invalid fetch interval, using default: {validation_response.error_message}")
                    fetch_interval_minutes = FETCH_INTERVAL_MINIMUM_MIN
                else:
                    fetch_interval_minutes = validation_response.minutes_value

                # Calculate safe_after_str as current time minus fetch interval
                api_start_datetime = datetime.strptime(self.api_start_run_time, DEMISTO_OCCURRED_FORMAT)
                safe_after_datetime = api_start_datetime - timedelta(minutes=fetch_interval_minutes)
                safe_after_str = safe_after_datetime.strftime(DEMISTO_OCCURRED_FORMAT)

                demisto.debug(
                    f"Calculated safe_after_str using fetch interval of {fetch_interval_minutes} minutes: {safe_after_str}"
                )

            except Exception as e:
                demisto.error(f"Error calculating safe_after_str with fetch interval: {str(e)}. Using api_start_run_time")
                safe_after_str = self.api_start_run_time

        # Reset to safe values
        self.end_cursor = None
        self.stored_after = safe_after_str
        self.stored_before = self.api_start_run_time  # Current time as before

        demisto.info(
            f"Reset fetch incidents parameter complete - "
            f"after: {self.stored_after}, before: {self.stored_before}, endCursor: None"
        )

    def _validate_and_reset_params(self):
        """
        Validate stored parameters and reset if invalid
        """
        needs_reset = False
        reset_reason = []

        if self._is_legacy_format():
            needs_reset = True
            reset_reason.append("migrating from legacy format (only 'time' field)")

        # Check for None values that should have timestamps when pagination is active
        if self.end_cursor is not None:
            # If end_cursor exists, both stored_after and stored_before must exist
            if self.stored_after is None:
                needs_reset = True
                reset_reason.append("stored_after is None but endCursor exists")

            if self.stored_before is None:
                needs_reset = True
                reset_reason.append("stored_before is None but endCursor exists")

        # Validate timestamp formats
        timestamp_fields = [
            ("stored_after", self.stored_after),
            ("stored_before", self.stored_before),
            ("last_run_time", self.last_run_time),
        ]

        for field_name, timestamp in timestamp_fields:
            if timestamp and not self._is_valid_timestamp(timestamp):
                needs_reset = True
                reset_reason.append(f"invalid {field_name} format: {timestamp}")

        # Validate time ordering (before >= after)
        if self.stored_after and self.stored_before and not self._is_valid_time_ordering(self.stored_after, self.stored_before):
            needs_reset = True
            reset_reason.append(f"invalid time ordering: before ({self.stored_before}) < after ({self.stored_after})")

        # Validate after time is not too old
        if self.stored_after and self._is_after_time_too_old(self.stored_after):
            needs_reset = True
            reset_reason.append(f"after time too old: {self.stored_after}")

        if needs_reset:
            reason = "; ".join(reset_reason)
            self.reset_params(reason)
        else:
            demisto.info(
                f"Using fetch incidents parameters: - "
                f"after: {self.stored_after}, before: {self.stored_before}, endCursor: None"
            )

    def _is_legacy_format(self):
        """
        Check if this is legacy format (existing customer with only 'time' field)

        Returns:
            bool: True if legacy format detected
        """
        # Legacy format: has 'time' but missing the new pagination fields
        has_time = self.last_run_time is not None
        missing_new_fields = self.stored_after is None and self.stored_before is None and self.end_cursor is None

        is_legacy = has_time and missing_new_fields

        if is_legacy:
            demisto.info(
                f"Legacy format detected - last_run_time: {self.last_run_time}, " f"missing after/before/endCursor fields"
            )

        return is_legacy

    def _is_valid_timestamp(self, timestamp):
        """
        Check if timestamp is in valid format

        Args:
            timestamp (str): Timestamp to validate

        Returns:
            bool: True if valid, False otherwise
        """
        try:
            datetime.strptime(timestamp, DEMISTO_OCCURRED_FORMAT)
            return True
        except Exception:
            return False

    def _is_valid_time_ordering(self, after_time, before_time):
        """
        Check if before_time >= after_time

        Args:
            after_time (str): After timestamp
            before_time (str): Before timestamp

        Returns:
            bool: True if ordering is valid, False otherwise
        """
        try:
            after_datetime = datetime.strptime(after_time, DEMISTO_OCCURRED_FORMAT)
            before_datetime = datetime.strptime(before_time, DEMISTO_OCCURRED_FORMAT)
            return before_datetime >= after_datetime
        except Exception:
            return False

    def _get_max_fetch_interval_minutes(self):
        """
        Calculate the maximum fetch interval based on first_fetch setting + buffer

        Returns:
            int: Maximum allowed fetch interval in minutes
        """
        try:
            demisto_params = demisto.params()
            first_fetch_param = demisto_params.get(DemistoParams.FIRST_FETCH, DEFAULT_FETCH_BACK).strip()

            # Parse first_fetch parameter to get minutes
            import dateparser

            first_fetch_time = dateparser.parse(f"{first_fetch_param} ago")

            if first_fetch_time:
                current_time = datetime.now()
                time_delta = current_time - first_fetch_time
                first_fetch_minutes = int(time_delta.total_seconds() / 60)

                # Use the global buffer parameter
                buffer_multiplier = 1 + (MAX_FETCH_BUFFER / 100)  # Convert 15 to 1.15
                max_minutes = int(first_fetch_minutes * buffer_multiplier)

                max_minutes = max(max_minutes, FETCH_INTERVAL_MINIMUM_MIN)

                demisto.debug(
                    f"Calculated max fetch interval: {first_fetch_minutes} minutes "
                    f"+ {MAX_FETCH_BUFFER}% buffer = {max_minutes} minutes (from first_fetch: '{first_fetch_param}')"
                )

                return max_minutes

        except Exception as e:
            demisto.debug(f"Error calculating first_fetch interval: {str(e)}. Using default maximum.")

        # Fallback to original maximum
        return FETCH_INTERVAL_MAXIMUM_MIN

    def _is_after_time_too_old(self, after_time):
        """
        Check if after_time exceeds maximum fetch interval

        Args:
            after_time (str): After timestamp to check

        Returns:
            bool: True if too old, False otherwise
        """
        try:
            after_datetime = datetime.strptime(after_time, DEMISTO_OCCURRED_FORMAT)
            current_datetime = datetime.strptime(self.api_start_run_time, DEMISTO_OCCURRED_FORMAT)

            # Use dynamic maximum based on first_fetch + 15%
            max_interval_minutes = self._get_max_fetch_interval_minutes()
            max_interval = timedelta(minutes=max_interval_minutes)
            time_difference = current_datetime - after_datetime

            is_too_old = time_difference > max_interval

            if is_too_old:
                demisto.info(
                    f"After time {after_time} exceeds maximum interval of {max_interval_minutes} minutes "
                    f"(difference: {int(time_difference.total_seconds() / 60)} minutes)"
                )

            return is_too_old

        except Exception:
            return True  # If we can't parse, consider it invalid

    def get_api_after_parameter(self):
        """
        Get the 'after' parameter value for the GraphQL API call.
        """
        if self.should_continue_previous_run():
            # Continuing pagination - use stored after time
            after_time = self.stored_after
        else:
            # Fresh fetch - use stored_after (which is set correctly by reset or previous run)
            after_time = self.stored_after if self.stored_after else self.last_run_time

        return after_time

    def get_api_before_parameter(self):
        """
        Get the 'before' parameter value for the GraphQL API call.
        """
        if self.should_continue_previous_run():
            before_time = self.stored_before
        else:
            before_time = self.api_start_run_time

        return before_time

    def should_continue_previous_run(self):
        """
        Determines if this is a continuation of a previous paginated fetch.

        Returns:
            bool: True if we should continue previous run, False for fresh run
        """
        return bool(self.end_cursor)

    def _validate_and_adjust_after_time(self, after_time):
        """
        Validate that after_time is not older than FETCH_INTERVAL_MAXIMUM_MIN minutes
        and adjust if necessary

        Args:
            after_time (str): The after time to validate

        Returns:
            str: The validated/adjusted after time
        """
        if not after_time:
            return self.api_start_run_time

        try:
            # Parse the after_time
            after_datetime = datetime.strptime(after_time, DEMISTO_OCCURRED_FORMAT)
            current_datetime = datetime.strptime(self.api_start_run_time, DEMISTO_OCCURRED_FORMAT)

            # Calculate maximum allowed time difference
            max_interval = timedelta(minutes=FETCH_INTERVAL_MAXIMUM_MIN)
            time_difference = current_datetime - after_datetime

            if time_difference > max_interval:
                # After time is too old, adjust to maximum allowed
                adjusted_after = current_datetime - max_interval
                adjusted_after_str = adjusted_after.strftime(DEMISTO_OCCURRED_FORMAT)

                demisto.info(
                    f"After time {after_time} exceeds maximum fetch interval of {FETCH_INTERVAL_MAXIMUM_MIN} minutes. "
                    f"Adjusting to {adjusted_after_str}"
                )
                return adjusted_after_str

            return after_time

        except Exception as e:
            log_and_return_error(f"Error validating after_time {after_time}: {str(e)}")
            return None

    def get_api_cursor_parameter(self):
        """
        Get the cursor parameter value for the GraphQL API call.

        Returns:
            str or None: The cursor to use for pagination, None if fresh fetch
        """
        return self.end_cursor

    def _save_pagination_context(self):
        last_run_data = {
            DemistoParams.TIME: self.api_start_run_time,
            WizApiResponse.END_CURSOR: API_END_CURSOR,
            WizApiVariables.AFTER: self.stored_after,
            WizApiVariables.BEFORE: self.stored_after,
        }

        # Save using setLastRun
        demisto.setLastRun(last_run_data)

        demisto.debug(f"Fetch incidents didn't complete - set last run data to {json.dumps(last_run_data)}")

    def _clear_pagination_context(self):
        """
        Clear pagination context when no more pages to fetch
        """
        demisto.info("No end cursor found, clearing pagination context")

        # Create last run data without pagination context using enums
        last_run_data = {
            DemistoParams.TIME: self.api_start_run_time,
            WizApiResponse.END_CURSOR: None,
            WizApiVariables.AFTER: self.stored_before,
            WizApiVariables.BEFORE: self.api_start_run_time,
        }

        # Save using setLastRun
        demisto.setLastRun(last_run_data)

        demisto.info(f"Fetch incidents completed - set last run data to {json.dumps(last_run_data)}")

    def handle_post_incident_creation(self):
        """
        Handle post-incident creation logic based on global API_END_CURSOR.
        Decides about pagination context and last run time based on API_END_CURSOR.

        Returns:
            None
        """
        if bool(API_END_CURSOR):
            self._save_pagination_context()
        else:
            self._clear_pagination_context()

    def log_current_state(self):
        """
        Log current state for debugging
        """
        if self.end_cursor:
            status = (
                f"Pagination in progress - {WizApiResponse.END_CURSOR}: {self.end_cursor}, "
                f"{WizApiVariables.AFTER}: {self.stored_after}, {WizApiVariables.BEFORE}: {self.stored_before}"
            )
        else:
            status = "No active pagination"

        demisto.info(f"State: {status} - Last run time: {self.last_run_time}, API start time: {self.api_start_run_time}")


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
    audience = "wiz-api"

    demisto_params = demisto.params()
    said = demisto_params.get(DemistoParams.CREDENTIALS).get(DemistoParams.IDENTIFIER)
    sasecret = demisto_params.get(DemistoParams.CREDENTIALS).get(DemistoParams.PASSWORD)
    auth_payload = parse.urlencode(
        {
            AuthParams.GRANT_TYPE: "client_credentials",
            AuthParams.AUDIENCE: audience,
            AuthParams.CLIENT_ID: said,
            AuthParams.CLIENT_SECRET: sasecret,
        }
    )
    response = requests.post(AUTH_E, headers=HEADERS_AUTH, data=auth_payload)

    if response.status_code != requests.codes.ok:
        raise Exception(f"Error authenticating to Wiz [{response.status_code}] - {response.text}")
    try:
        response_json = response.json()
        TOKEN = response_json.get(WizApiResponse.ACCESS_TOKEN)
        if not TOKEN:
            demisto.debug(json.dumps(response_json))
            message = f"Could not retrieve token from Wiz: {response_json.get(WizApiResponse.MESSAGE)}"
            raise Exception(message)
    except ValueError as exception:
        demisto.debug(exception)
        raise Exception("Could not parse API response")
    HEADERS[HeaderFields.AUTHORIZATION] = "Bearer " + TOKEN

    return TOKEN


def set_api_end_cursor(page_info):
    global API_END_CURSOR

    if page_info and page_info.get(WizApiResponse.HAS_NEXT_PAGE):
        API_END_CURSOR = page_info.get(WizApiResponse.END_CURSOR, "")
    else:
        API_END_CURSOR = None


def get_entries(query, variables, wiz_type):
    if not TOKEN:
        get_token()

    data = {"variables": variables, "query": query}
    demisto.info(f"Invoking Wiz API with variables {json.dumps(variables)}")

    try:
        response = requests.post(url=URL, json=data, headers=HEADERS)
        response_json = response.json()

        demisto.info(f"Wiz API response status code is {response.status_code}")
        demisto.debug(f"The response is {response_json}")

        if response.status_code != requests.codes.ok:
            raise Exception(f"Got an error querying Wiz API [{response.status_code}] - {response.text}")

        if WizApiResponse.ERRORS in response_json:
            demisto.error(f"Wiz error content: {response_json[WizApiResponse.ERRORS]}")
            error_message = f"Wiz API error details: {get_error_output(response_json)}"
            demisto.error(f"An error has occurred using:\tVariables: {variables} -\t{error_message}")
            demisto.error(error_message)
            raise Exception(f"{error_message}\nCheck 'server.log' instance file to get additional information")

        if WizApiResponse.NODES in response_json[WizApiResponse.DATA][wiz_type]:
            new_entries = response_json[WizApiResponse.DATA][wiz_type][WizApiResponse.NODES]
            page_info = response_json[WizApiResponse.DATA][wiz_type][WizApiResponse.PAGE_INFO]
        else:
            new_entries = response_json[WizApiResponse.DATA][wiz_type]
            page_info = None

        set_api_end_cursor(page_info)

        return new_entries, page_info

    except Exception as e:
        error_message = f"Received an error while performing an API call.\nError info: {str(e)}"
        demisto.error(error_message)
        return_error(error_message)


def query_detections(variables, paginate=True, max_fetch=API_MAX_FETCH):
    return query_api(PULL_DETECTIONS_QUERY, variables, WizApiResponse.DETECTIONS, paginate=paginate, max_fetch=max_fetch)


def query_issues(variables, paginate=True):
    return query_api(PULL_ISSUE_QUERY, variables, WizApiResponse.ISSUES, paginate=paginate)


def query_single_issue(issue_id):
    issue_variables = {
        WizApiVariables.FIRST: 1,
        WizApiVariables.FILTER_BY: {WizApiVariables.ID: issue_id},
    }
    return query_issues(issue_variables, paginate=False)


def query_api(query, variables, wiz_type, paginate=True, max_fetch=API_MAX_FETCH):
    entries, page_info = get_entries(query, variables, wiz_type)
    if not entries:
        demisto.info(f"No {wiz_type}(/s) available to fetch.")
        entries = {}

    while page_info[WizApiResponse.HAS_NEXT_PAGE] and paginate:
        demisto.debug(f"Successfully pulled {len(entries)} {wiz_type}")

        variables[WizApiVariables.AFTER] = page_info[WizApiResponse.END_CURSOR]

        new_entries, page_info = get_entries(query, variables, wiz_type)
        if new_entries is not None:
            entries += new_entries
        if len(entries) >= max_fetch:
            demisto.info(
                f"Reached the maximum fetch limit of {max_fetch} detections.\n"
                f"Some detections will not be processed in this fetch cycle.\n"
                f"Consider adjusting the filters to get relevant logs"
            )
            break
    if entries:
        demisto.info(f"Successfully pulled {len(entries)} {wiz_type}")
    else:
        demisto.info(f"No {wiz_type}(/s) available to fetch according to this filter.")
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

    rule_name = detection.get(WizApiVariables.RULE_MATCH, {}).get(WizApiVariables.RULE, {}).get(WizApiVariables.NAME)

    incident_name = f"{rule_name or 'Unknown Rule'} - {detection.get(WizApiVariables.ID, '')}"

    return {
        DemistoParams.NAME: incident_name,
        DemistoParams.OCCURRED: detection[WizApiVariables.CREATED_AT],
        DemistoParams.RAW_JSON: json.dumps(detection),
        DemistoParams.SEVERITY: translate_severity(detection),
        DemistoParams.MIRROR_ID: str(detection[WizApiVariables.ID]),
    }


def extract_params_from_integration_settings(advanced_params=False):
    demisto_params = demisto.params()

    integration_setting_params = {
        WizInputParam.SEVERITY: demisto_params.get(WizInputParam.SEVERITY),
        WizInputParam.TYPE: demisto_params.get(WizInputParam.TYPE),
        WizInputParam.PLATFORM: demisto_params.get(WizInputParam.PLATFORM),
        WizInputParam.ORIGIN: demisto_params.get(WizInputParam.ORIGIN),
        WizInputParam.CLOUD_ACCOUNT_OR_CLOUD_ORG: demisto_params.get(WizInputParam.CLOUD_ACCOUNT_OR_CLOUD_ORG),
    }

    if advanced_params:
        for demisto_param in [
            DemistoParams.FIRST_FETCH,
            DemistoParams.INCIDENT_FETCH_INTERVAL,
            DemistoParams.INCIDENT_TYPE,
            DemistoParams.IS_FETCH,
            DemistoParams.MAX_FETCH,
        ]:
            integration_setting_params[demisto_param] = demisto_params.get(demisto_param)

    return integration_setting_params


def check_advanced_params(integration_settings_params):
    error_message = ""
    are_params_valid = True

    is_fetch = integration_settings_params.get(DemistoParams.IS_FETCH)
    first_fetch = integration_settings_params.get(DemistoParams.FIRST_FETCH)
    incident_fetch_interval = integration_settings_params.get(DemistoParams.INCIDENT_FETCH_INTERVAL)
    incident_type = integration_settings_params.get(DemistoParams.INCIDENT_TYPE)
    max_fetch = integration_settings_params.get(DemistoParams.MAX_FETCH)

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

        max_fetch_validation = validate_max_fetch(max_fetch)
        if not max_fetch_validation.is_valid:
            are_params_valid = False
            error_message += f"{max_fetch_validation.error_message}\n"

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
        paginate=False,
    )

    if WizApiResponse.ERRORS in wiz_detection or type(wiz_detection) is not list:
        demisto.results(wiz_detection)
    else:
        demisto.results("ok")


def get_fetch_incidents_api_max_fetch(max_fetch):
    """
    Get the API limit for fetching incidents
    """
    max_fetch_validation = validate_max_fetch(max_fetch)
    api_limit = max_fetch_validation.value if max_fetch_validation.is_valid else API_MAX_FETCH
    return api_limit


def fetch_incidents():
    """
    Fetch all Detections (OOB XSOAR Fetch)
    """
    global API_MAX_FETCH

    fetch_manager = FetchIncident()
    fetch_manager.log_current_state()

    try:
        # Get integration settings
        integration_settings_params = extract_params_from_integration_settings(advanced_params=True)
        API_MAX_FETCH = get_fetch_incidents_api_max_fetch(integration_settings_params.get(DemistoParams.MAX_FETCH))

        wiz_detections = get_filtered_detections(
            detection_type=integration_settings_params[WizInputParam.TYPE],
            detection_platform=integration_settings_params[WizInputParam.PLATFORM],
            severity=integration_settings_params[WizInputParam.SEVERITY],
            detection_origin=integration_settings_params[WizInputParam.ORIGIN],
            detection_cloud_account_or_cloud_organization=integration_settings_params[WizInputParam.CLOUD_ACCOUNT_OR_CLOUD_ORG],
            after_time=fetch_manager.get_api_after_parameter(),
            before_time=fetch_manager.get_api_before_parameter(),
            end_cursor=fetch_manager.get_api_cursor_parameter(),
            max_fetch=API_MAX_FETCH,
        )

        if isinstance(wiz_detections, str):
            demisto.error(f"Error fetching detections: {wiz_detections}")
            return None

        # Build incidents from detections
        incidents = []
        for detection in wiz_detections:
            incident = build_incidents(detection=detection)
            incidents.append(incident)

        demisto.incidents(incidents)

        fetch_manager.handle_post_incident_creation()

        if incidents:
            demisto.info(f"Successfully fetched and created {len(incidents)} incidents")
        else:
            demisto.info("No new incidents to fetch")
    except Exception as e:
        return log_and_return_error(f"Error fetching incidents: {e}")


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
        demisto.info(
            f"First fetch timestamp was more than {MAX_DAYS_FIRST_FETCH_DETECTIONS} days "
            f"({first_fetch_param}), automatically setting to "
            f"{MAX_DAYS_FIRST_FETCH_DETECTIONS} days back"
        )

    # Return the ISO formatted timestamp
    return valid_date.isoformat()[:-3] + "Z"


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
        demisto.debug("Could not find the domain in the auth endpoint. Using default domain: app.wiz.io")
        WIZ_DOMAIN_URL = "app.wiz.io"


def get_detection_url(detection):
    if not WIZ_DOMAIN_URL:
        update_wiz_domain_url()

    detection_url = (
        f"https://{WIZ_DOMAIN_URL}/findings/detections#~(filters"
        f"~(updateTime~(dateRange~(past~(amount~5~unit~'day))))~detectionId~'{detection.get('id')}"
        f"~streamCols~(~'event~'principal~'principalIp~'resource))"
    )
    return detection_url


def get_threat_url(threat):
    if not WIZ_DOMAIN_URL:
        update_wiz_domain_url()

    detection_url = (
        f"https://{WIZ_DOMAIN_URL}/threats#~(filters~(createdAt~(inTheLast~(amount~90~unit~'days)))~issue~'{threat.get('id')})"
    )
    return detection_url


def validate_wiz_enum_parameter(parameter_value, enum_class, parameter_name):
    """
    Generic validation function for Wiz enum parameters

    Args:
        parameter_value (str or list): The parameter value(s) to validate
        enum_class: The enum class that contains valid values (e.g., WizIssueType)
        parameter_name (str): The human-readable parameter name for error messages (e.g., "issue type")

    Returns:
        ValidationResponse: Response with validation results
    """
    if not parameter_value:
        return ValidationResponse.create_success()

    values = argToList(parameter_value)

    valid_values = enum_class.values()
    invalid_values = [v for v in values if v not in valid_values]

    if invalid_values:
        error_msg = (
            f"Invalid {parameter_name}(s): {', '.join(invalid_values)}. Valid {parameter_name}s are: "
            f"{', '.join(valid_values)}"
        )
        demisto.error(error_msg)
        return ValidationResponse.create_error(error_msg)

    return ValidationResponse.create_success(values)


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
    api_value = DetectionType.get_api_value(user_input=detection_type)

    if api_value:
        # Handle both single values and lists
        if isinstance(api_value, list):
            valid_api_values = set(DetectionType.api_values())
            if set(api_value).issubset(valid_api_values):
                return ValidationResponse.create_success(api_value)
        else:
            if api_value in DetectionType.api_values():
                return ValidationResponse.create_success(api_value)

    # If we get here, validation failed
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
    return validate_wiz_enum_parameter(platform, CloudPlatform, "platform")


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
    if isinstance(cloud_account_or_cloud_organization, str) and "," in cloud_account_or_cloud_organization:
        cloud_account_or_cloud_organizations = [s.strip() for s in cloud_account_or_cloud_organization.split(",")]
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
        error_msg = (
            f"Invalid {WizInputParam.CLOUD_ACCOUNT_OR_CLOUD_ORG} ID(s): "
            f"{', '.join(invalid_cloud_account_or_cloud_organizations)}. "
            f"All {WizInputParam.CLOUD_ACCOUNT_OR_CLOUD_ORG} must be in valid UUID format."
        )
        demisto.error(error_msg)
        return ValidationResponse.create_error(error_msg)

    return ValidationResponse.create_success(cloud_account_or_cloud_organizations)


def validate_detection_origin(origin):
    return validate_wiz_enum_parameter(origin, DetectionOrigin, "origin")


def validate_creation_time_back(time_value, time_unit="minutes"):
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
    if time_unit == "minutes":
        param_name = WizInputParam.CREATION_MINUTES_BACK
        min_value = FETCH_INTERVAL_MINIMUM_MIN
        max_value = FETCH_INTERVAL_MAXIMUM_MIN
        default_value = FETCH_INTERVAL_MINIMUM_MIN
        response.minutes_value = default_value
    elif time_unit == "days":
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
            if time_unit == "minutes":
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

    if not fetch_interval:
        error_msg = "Incidents Fetch Interval is required and cannot be empty."
        return ValidationResponse.create_error(error_msg)

    error_msg = (
        f"Invalid Incidents Fetch Interval - It must be a valid integer "
        f"higher or equal than {FETCH_INTERVAL_MINIMUM_MIN}. Received {fetch_interval}."
    )

    try:
        fetch_interval_int = int(fetch_interval)

        if fetch_interval_int >= FETCH_INTERVAL_MINIMUM_MIN:
            response.minutes_value = fetch_interval_int
            return response
        else:
            return ValidationResponse.create_error(error_msg)

    except (ValueError, TypeError):
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


def validate_max_fetch(max_fetch):
    """
    Validates if the max fetch parameter is valid

    Args:
        max_fetch (str or int): The max fetch value to validate

    Returns:
        ValidationResponse: Response with validation results and max fetch value
    """
    response = ValidationResponse.create_success()
    response.value = API_MAX_FETCH

    if not max_fetch:
        return response

    error_msg = f"{DemistoParams.MAX_FETCH} must be a valid integer between 10 and 1000."

    try:
        max_fetch_int = int(max_fetch)
        if API_MIN_FETCH <= max_fetch_int <= API_MAX_FETCH:
            response.value = max_fetch_int
            return response
        else:
            return ValidationResponse.create_error(f"{error_msg} - Received {max_fetch}")
    except ValueError:
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
    error_msg = (
        f"Invalid first fetch format: {first_fetch}. Expected format is '<number> <time unit>' (e.g., '12 hours', '1 day')."
    )

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
    # Create a dictionary to map time units to their maximum values and format strings
    time_unit_limits = {
        "minute": (max_hours * 60, f"({max_hours * 60} minutes)"),
        "hour": (max_hours, f"({max_hours} hours)"),
        "day": (MAX_DAYS_FIRST_FETCH_DETECTIONS, ""),
    }

    # Find which time unit is being used
    for unit_prefix, (max_value, format_suffix) in time_unit_limits.items():
        if unit.startswith(unit_prefix) and number > max_value:
            suffix = format_suffix if format_suffix else ""
            error_msg = (
                f"First fetch duration too long: {first_fetch}. "
                f"Maximum allowed is {MAX_DAYS_FIRST_FETCH_DETECTIONS} days {suffix}"
            )
            demisto.error(error_msg)
            return ValidationResponse.create_error(error_msg)

    response.value = first_fetch
    return response


def validate_severity(severity):
    """
    Validates if the severity parameter is valid

    Args:
        severity (str or list): The severity level(s) to validate. Can be:
                               - Single severity string (returns that severity + all higher levels)
                               - List of severity strings (returns only specified severities)

    Returns:
        ValidationResponse: Response with validation results and severity list
    """
    response = ValidationResponse.create_success()

    if not severity:
        return response

    # Define severity hierarchy (highest to lowest)
    severity_hierarchy = [
        WizSeverity.CRITICAL,
        WizSeverity.HIGH,
        WizSeverity.MEDIUM,
        WizSeverity.LOW,
        WizSeverity.INFORMATIONAL,
    ]

    valid_severities_set = set(severity_hierarchy)

    # Handle list of severities (multi-selection)
    if isinstance(severity, list):
        severity_list = [s.upper() for s in severity if s]  # Filter out empty strings

        # Validate each severity in the list
        invalid_severities = [s for s in severity_list if s not in valid_severities_set]
        if invalid_severities:
            error_msg = (
                f"Invalid severities: {', '.join(invalid_severities)}. Valid severities are: {', '.join(severity_hierarchy)}."
            )
            demisto.error(error_msg)
            return ValidationResponse.create_error(error_msg)

        response.severity_list = severity_list
        return response

    # Handle single severity string (backward compatibility - includes higher levels)
    severity = severity.upper()

    if severity not in valid_severities_set:
        error_msg = f"Invalid severity: {severity}. Valid severities are: {', '.join(severity_hierarchy)}."
        demisto.error(error_msg)
        return ValidationResponse.create_error(error_msg)

    # Return severity and all higher levels for single selection
    severity_index = severity_hierarchy.index(severity)
    response.severity_list = severity_hierarchy[: severity_index + 1]
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

    statuses = argToList(status, transform=lambda s: str(s).upper())

    valid_statuses = [WizStatus.OPEN, WizStatus.IN_PROGRESS, WizStatus.REJECTED, WizStatus.RESOLVED]

    invalid_statuses = [s for s in statuses if s not in valid_statuses]

    if invalid_statuses:
        error_msg = f"Invalid status(es): {', '.join(invalid_statuses)}. Valid statuses are: {', '.join(valid_statuses)}."
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


def validate_end_cursor(end_cursor):
    """
    Validates if the end_cursor is a valid base64 string

    Args:
        end_cursor (str): The end cursor to validate

    Returns:
        tuple: (is_valid (bool), error_message (str or None))
    """
    if not end_cursor:
        return True, None

    try:
        import base64

        base64.b64decode(end_cursor, validate=True)
        return True, None
    except Exception as e:
        error_msg = f"Invalid end_cursor format: {end_cursor}. Must be a valid base64 string. Error: {str(e)}"
        demisto.error(error_msg)
        return False, error_msg


def validate_after_and_before_timestamps(after_time, before_time):
    """
    Validates after_time and before_time parameters

    Args:
        after_time (str): The after timestamp
        before_time (str): The before timestamp

    Returns:
        tuple: (is_valid (bool), error_message (str or None))
    """
    if not after_time and not before_time:
        return True, None

    def parse_timestamp(timestamp_str):
        """Helper function to parse timestamp in multiple formats"""
        if not timestamp_str:
            return None

        # Try parsing with milliseconds first (e.g., "2025-06-18T20:59:59.999Z")
        try:
            return datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%fZ")
        except ValueError:
            pass

        # Try parsing without milliseconds (DEMISTO format: "2025-06-18T20:59:59Z")
        try:
            return datetime.strptime(timestamp_str, DEMISTO_OCCURRED_FORMAT)
        except ValueError:
            pass

        # Try parsing ISO format without Z
        try:
            return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        except ValueError:
            pass

        return None

    # Check if both are provided and not null
    error_time_format_msg = "Expected ISO format like '2025-06-18T20:59:59.999Z' or '2025-06-18T20:59:59Z'"

    if after_time and before_time:
        after_dt = parse_timestamp(after_time)
        before_dt = parse_timestamp(before_time)

        if after_dt is None:
            error_msg = f"Invalid after_time format: {after_time}. {error_time_format_msg}"
            demisto.error(error_msg)
            return False, error_msg

        if before_dt is None:
            error_msg = f"Invalid before_time format: {before_time}. {error_time_format_msg}"
            demisto.error(error_msg)
            return False, error_msg

        # Ensure before_time is greater than or equal to after_time
        if before_dt < after_dt:
            error_msg = f"before_time ({before_time}) must be greater than or equal to after_time ({after_time})"
            demisto.error(error_msg)
            return False, error_msg

    # Individual validation for after_time
    if after_time:
        after_dt = parse_timestamp(after_time)
        if after_dt is None:
            error_msg = f"Invalid after_time format: {after_time}. {error_time_format_msg}"
            demisto.error(error_msg)
            return False, error_msg

    # Individual validation for before_time
    if before_time:
        before_dt = parse_timestamp(before_time)
        if before_dt is None:
            error_msg = f"Invalid before_time format: {before_time}. {error_time_format_msg}"
            demisto.error(error_msg)
            return False, error_msg

    return True, None


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
    after_time = parameters_dict.get(WizApiVariables.AFTER)
    before_time = parameters_dict.get(WizApiVariables.BEFORE)
    end_cursor = parameters_dict.get(WizApiResponse.END_CURSOR)

    # Validate end_cursor if provided
    if end_cursor:
        is_valid, error_message = validate_end_cursor(end_cursor)
        if not is_valid:
            return False, error_message, None
        validated_values[WizApiResponse.END_CURSOR] = end_cursor

    # Check for conflicting time parameters
    if creation_minutes_back and after_time:
        error_msg = f"Cannot provide both {WizInputParam.CREATION_MINUTES_BACK} and {DemistoParams.AFTER_TIME} parameters"
        demisto.error(error_msg)
        return False, error_msg, None

    # For manual commands, check if at least one parameter is provided
    if not after_time:
        param_map = {
            WizInputParam.DETECTION_ID: detection_id,
            WizInputParam.ISSUE_ID: issue_id,
            WizInputParam.TYPE: detection_type,
            WizInputParam.PLATFORM: detection_platform,
            WizInputParam.ORIGIN: detection_origin,
            WizInputParam.CLOUD_ACCOUNT_OR_CLOUD_ORG: detection_cloud_account_or_cloud_organization,
            WizInputParam.RESOURCE_ID: resource_id,
            WizInputParam.SEVERITY: severity,
            WizInputParam.RULE_MATCH_ID: matched_rule,
            WizInputParam.RULE_MATCH_NAME: rule_match_name,
            WizInputParam.PROJECT_ID: project_id,
        }

        # Check if any parameter has a value
        if not any(param_map.values()):
            # Generate the error message using the parameter names
            param_list = [f"\t{param}" for param in param_map]
            error_msg = "You should pass at least one of the following parameters:\n" + "\n".join(param_list)
            demisto.error(error_msg)
            return False, error_msg, None

    if after_time or before_time:
        is_valid, error_message = validate_after_and_before_timestamps(after_time, before_time)
        if not is_valid:
            return False, error_message, None
        validated_values[WizApiVariables.AFTER] = after_time
        validated_values[WizApiVariables.BEFORE] = before_time

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
    cloud_account_or_cloud_organization_validation = validate_detection_cloud_account_or_cloud_organization(
        detection_cloud_account_or_cloud_organization
    )
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

    # Create a dictionary mapping parameter names to their values
    param_map = {
        WizInputParam.ISSUE_ID: parameters_dict.get(WizInputParam.ISSUE_ID),
        WizInputParam.PLATFORM: parameters_dict.get(WizInputParam.PLATFORM),
        WizInputParam.ORIGIN: parameters_dict.get(WizInputParam.ORIGIN),
        WizInputParam.CLOUD_ACCOUNT_OR_CLOUD_ORG: parameters_dict.get(WizInputParam.CLOUD_ACCOUNT_OR_CLOUD_ORG),
        WizInputParam.RESOURCE_ID: parameters_dict.get(WizInputParam.RESOURCE_ID),
        WizInputParam.SEVERITY: parameters_dict.get(WizInputParam.SEVERITY),
        WizInputParam.STATUS: parameters_dict.get(WizInputParam.STATUS),
        WizInputParam.CREATION_DAYS_BACK: parameters_dict.get(WizInputParam.CREATION_DAYS_BACK),
        WizInputParam.PROJECT_ID: parameters_dict.get(WizInputParam.PROJECT_ID),
    }

    # Check if at least one parameter has a value
    if not any(param_map.values()):
        param_list = [f"\t{param}" for param in param_map]
        error_msg = "You should pass at least one of the following parameters:\n" + "\n".join(param_list)
        demisto.error(error_msg)
        return False, error_msg, None

    # Validate issue_id if provided
    issue_id = param_map[WizInputParam.ISSUE_ID]
    if issue_id:
        is_valid_id, message = is_valid_param_id(issue_id, WizInputParam.ISSUE_ID)
        if not is_valid_id:
            return False, message, None
        validated_values[WizInputParam.ISSUE_ID] = issue_id

    # Validate platform
    platform = param_map[WizInputParam.PLATFORM]
    if platform:
        platform_validation = validate_detection_platform(platform)
        if not platform_validation.is_valid:
            return False, platform_validation.error_message, None
        validated_values[WizInputParam.PLATFORM] = platform_validation.value

    # Validate origin
    origin = param_map[WizInputParam.ORIGIN]
    origin_validation = validate_detection_origin(origin)
    if not origin_validation.is_valid:
        return False, origin_validation.error_message, None
    validated_values[WizInputParam.ORIGIN] = origin_validation.value

    # Validate cloud_account_or_cloud_organization
    cloud_account_or_cloud_organization = param_map[WizInputParam.CLOUD_ACCOUNT_OR_CLOUD_ORG]
    if cloud_account_or_cloud_organization:
        cloud_validation = validate_detection_cloud_account_or_cloud_organization(cloud_account_or_cloud_organization)
        if not cloud_validation.is_valid:
            return False, cloud_validation.error_message, None
        validated_values[WizInputParam.CLOUD_ACCOUNT_OR_CLOUD_ORG] = cloud_validation.value

    # Validate creation_days_back
    creation_days_back = param_map[WizInputParam.CREATION_DAYS_BACK]
    if creation_days_back:
        days_validation = validate_creation_time_back(creation_days_back, time_unit="days")
        if not days_validation.is_valid:
            return False, days_validation.error_message, None
        validated_values[WizInputParam.CREATION_DAYS_BACK] = days_validation.days_value

    # Validate severity
    severity = param_map[WizInputParam.SEVERITY]
    if severity:
        severity_validation = validate_severity(severity)
        if not severity_validation.is_valid:
            return False, severity_validation.error_message, None
        validated_values[WizInputParam.SEVERITY] = severity_validation.severity_list

    # Validate status
    status = param_map[WizInputParam.STATUS]
    if status:
        status_validation = validate_status(status)
        if not status_validation.is_valid:
            return False, status_validation.error_message, None
        validated_values[WizInputParam.STATUS] = status_validation.status_list

    # Validate resource_id
    resource_id = param_map[WizInputParam.RESOURCE_ID]
    if resource_id:
        resource_validation = validate_resource_id(resource_id)
        if not resource_validation.is_valid:
            return False, resource_validation.error_message, None
        validated_values[WizInputParam.RESOURCE_ID] = resource_validation.value

    # Validate project_id
    project_id = param_map[WizInputParam.PROJECT_ID]
    if project_id:
        project_validation = validate_project(project_id)
        if not project_validation.is_valid:
            return False, project_validation.error_message, None
        validated_values[WizInputParam.PROJECT_ID] = project_validation.value

    return True, None, validated_values


def apply_wiz_filter(variables, filter_value, api_field, equals_wrapper=True, is_detection=True, nested_path=None):
    """
    Generic function to apply filters to Wiz API query variables

    Args:
        variables (dict): The query variables to modify
        filter_value (str or list): The filter value(s) to apply
        api_field (str): The API field name (e.g., WizApiVariables.ORIGIN)
        equals_wrapper (bool): Whether to wrap the value in {"equals": [values]} structure
        is_detection (bool): Whether this is for detections (True) or threats (False)
        nested_path (str): Additional nested path for complex filters (e.g., "relatedEntity")

    Returns:
        dict: Updated variables with the filter applied
    """
    if not filter_value:
        return variables

    # Initialize filterBy if it doesn't exist
    if WizApiVariables.FILTER_BY not in variables:
        variables[WizApiVariables.FILTER_BY] = {}

    # Convert single values to list for consistency
    if isinstance(filter_value, str):
        value_list = [filter_value]
    elif isinstance(filter_value, list):
        value_list = filter_value
    else:
        value_list = [filter_value]

    filter_target = variables[WizApiVariables.FILTER_BY]
    if nested_path and not is_detection:
        if nested_path not in filter_target:
            filter_target[nested_path] = {}
        filter_target = filter_target[nested_path]

    if equals_wrapper:
        filter_target[api_field] = {WizApiVariables.EQUALS: value_list}
    else:
        filter_target[api_field] = value_list

    return variables


def apply_creation_before_time_filter(variables, before_time):
    """
    Adds a creation before time filter to the query variables

    Args:
        variables (dict): The query variables
        before_time (str): The time to filter before

    Returns:
        dict: Updated variables with the filter
    """
    if not before_time:
        return variables

    if WizApiVariables.FILTER_BY not in variables:
        variables[WizApiVariables.FILTER_BY] = {}

    if WizApiVariables.CREATED_AT not in variables[WizApiVariables.FILTER_BY]:
        variables[WizApiVariables.FILTER_BY][WizApiVariables.CREATED_AT] = {}

    variables[WizApiVariables.FILTER_BY][WizApiVariables.CREATED_AT][WizApiVariables.BEFORE] = before_time

    return variables


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

    variables[WizApiVariables.FILTER_BY][WizApiVariables.MATCHED_RULE] = {WizApiVariables.ID: matched_rule_id}

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

    variables[WizApiVariables.FILTER_BY][WizApiVariables.MATCHED_RULE_NAME] = {WizApiVariables.EQUALS: [matched_rule_name]}

    return variables


def apply_creation_in_last_filter(variables, time_value, time_unit="minutes"):
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
    duration_unit = DurationUnit.MINUTES if time_unit == "minutes" else DurationUnit.DAYS

    variables[WizApiVariables.FILTER_BY][WizApiVariables.CREATED_AT] = {
        WizApiVariables.IN_LAST: {WizApiVariables.AMOUNT: time_value, WizApiVariables.UNIT: duration_unit}
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

    if WizApiVariables.CREATED_AT not in variables[WizApiVariables.FILTER_BY]:
        variables[WizApiVariables.FILTER_BY][WizApiVariables.CREATED_AT] = {}

    variables[WizApiVariables.FILTER_BY][WizApiVariables.CREATED_AT][WizApiVariables.AFTER] = after_time

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

    variables[WizApiVariables.FILTER_BY][WizApiVariables.ID] = {WizApiVariables.EQUALS: detection_ids}

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
    """Adds the detection type filter to the query variables"""
    return apply_wiz_filter(variables, detection_type, WizApiVariables.TYPE, equals_wrapper=True, is_detection=True)


def apply_platform_filter(variables, platforms, is_detection=True):
    """Adds the platform filter to the query variables"""
    if is_detection:
        return apply_wiz_filter(variables, platforms, WizApiVariables.CLOUD_PLATFORM, equals_wrapper=True, is_detection=True)
    else:
        # For threats, platform goes under relatedEntity
        return apply_wiz_filter(
            variables,
            platforms,
            WizApiVariables.CLOUD_PLATFORM,
            equals_wrapper=False,
            is_detection=False,
            nested_path=WizApiVariables.RELATED_ENTITY,
        )


def apply_origin_filter(variables, origins, is_detection=True):
    """Adds the origin filter to the query variables"""
    api_field = WizApiVariables.ORIGIN if is_detection else WizApiVariables.EVENT_ORIGIN
    return apply_wiz_filter(variables, origins, api_field, equals_wrapper=True, is_detection=is_detection)


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
            WizApiVariables.ID: {WizApiVariables.EQUALS: [resource_id]}
        }
    else:
        if not variables[WizApiVariables.FILTER_BY].get(WizApiVariables.THREAT_RESOURCE):
            variables[WizApiVariables.FILTER_BY][WizApiVariables.THREAT_RESOURCE] = {}
        variables[WizApiVariables.FILTER_BY][WizApiVariables.THREAT_RESOURCE][WizApiVariables.IDS] = [resource_id]

    return variables


def apply_cloud_account_or_cloud_organization_filter(variables, cloud_account_ids, is_detection=True):
    """Adds the cloud account/organization filter to the query variables"""
    return apply_wiz_filter(
        variables,
        cloud_account_ids,
        WizApiVariables.CLOUD_ACCOUNT_OR_CLOUD_ORGANIZATION_ID,
        equals_wrapper=is_detection,
        is_detection=is_detection,
    )


def apply_severity_filter(variables, severity_list, is_detection=True):
    """Adds the severity filter to the query variables"""
    return apply_wiz_filter(
        variables, severity_list, WizApiVariables.SEVERITY, equals_wrapper=is_detection, is_detection=is_detection
    )


def apply_status_filter(variables, status_list):
    """Adds the status filter to the query variables"""
    return apply_wiz_filter(variables, status_list, WizApiVariables.STATUS, equals_wrapper=False, is_detection=True)


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


def apply_end_cursor(variables, end_cursor):
    """
    Adds the end cursor for pagination to the query variables

    Args:
        variables (dict): The query variables
        end_cursor (str): The pagination cursor (base64 encoded)

    Returns:
        dict: Updated variables with the pagination cursor
    """
    if not end_cursor:
        return variables

    # Set the pagination cursor using the 'after' parameter
    variables[WizApiVariables.AFTER] = end_cursor

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
    if validated_values.get(WizApiVariables.AFTER) and validated_values.get(WizApiVariables.BEFORE):
        variables = apply_creation_after_time_filter(variables, validated_values.get(WizApiVariables.AFTER))
        variables = apply_creation_before_time_filter(variables, validated_values.get(WizApiVariables.BEFORE))

        # Apply end_cursor for pagination if provided
        if validated_values.get(WizApiResponse.END_CURSOR):
            variables = apply_end_cursor(variables, validated_values.get(WizApiResponse.END_CURSOR))

    elif validated_values.get(WizInputParam.CREATION_MINUTES_BACK):
        variables = apply_creation_in_last_filter(variables, validated_values.get(WizInputParam.CREATION_MINUTES_BACK))

    # Apply other filters
    variables = apply_detection_id_filter(variables, validated_values.get(WizInputParam.DETECTION_ID))
    variables = apply_issue_id_filter(variables, validated_values.get(WizInputParam.ISSUE_ID))
    variables = apply_detection_type_filter(variables, validated_values.get(WizInputParam.TYPE))
    variables = apply_platform_filter(variables, validated_values.get(WizInputParam.PLATFORM))
    variables = apply_origin_filter(variables, validated_values.get(WizInputParam.ORIGIN))
    variables = apply_cloud_account_or_cloud_organization_filter(
        variables, validated_values.get(WizInputParam.CLOUD_ACCOUNT_OR_CLOUD_ORG)
    )
    variables = apply_resource_id_filter(variables, validated_values.get(WizInputParam.RESOURCE_ID))
    variables = apply_severity_filter(variables, validated_values.get(WizInputParam.SEVERITY))
    variables = apply_rule_match_id_filter(variables, validated_values.get(WizInputParam.RULE_MATCH_ID))
    variables = apply_rule_match_name_filter(variables, validated_values.get(WizInputParam.RULE_MATCH_NAME))
    variables = apply_project_id_filter(variables, validated_values.get(WizInputParam.PROJECT_ID))

    return variables


def log_input_parameters(parameters_dict):
    """
    Log parameters for debugging/informational purposes.
    Only logs parameters that have values (not None or empty).
    Can be used for both detections and threats.

    Args:
        parameters_dict (dict): Dictionary containing parameters
    """
    log_lines = []

    for param_key, param_value in parameters_dict.items():
        # Only include non-empty values
        if param_value is not None and param_value != "":
            log_lines.append(f"{param_key}: {param_value}")

    # Only log if there are actually parameters to log
    demisto_command = demisto.command()
    if log_lines:
        str_param = f"'{demisto_command}' input parameters are: "
        str_param += " - ".join(log_lines)
        demisto.info(str_param)
    else:
        demisto.info(f"{demisto_command} input parameters are empty.")


def get_filtered_detections(
    detection_id=None,
    issue_id=None,
    detection_type=None,
    detection_platform=None,
    detection_origin=None,
    detection_cloud_account_or_cloud_organization=None,
    resource_id=None,
    severity=None,
    creation_minutes_back=None,
    rule_match_id=None,
    rule_match_name=None,
    project_id=None,
    after_time=None,
    before_time=None,
    end_cursor=None,
    max_fetch=None,
    add_detection_url=True,
    api_limit=WIZ_API_LIMIT,
    paginate=True,
):
    """
    Retrieves Filtered Detections with enhanced pagination support

    Args:
        detection_id (str or list): Detection ID or list of detection IDs
        issue_id (str): Issue ID
        detection_type (str or list): Type of detections
        detection_platform (list): Cloud platforms
        detection_origin (list): Detection origins
        detection_cloud_account_or_cloud_organization (str): Detection cloud_account_or_cloud_organization
        resource_id (str): Resource ID
        severity (str): Severity level
        creation_minutes_back (str): Number of minutes back for creation filter
        rule_match_id (str): Matched rule ID
        rule_match_name (str): Matched rule name
        project_id (str): Project ID
        after_time (str): Start time for filtering (ISO format) - used for fetch incidents
        before_time (str): End time for filtering (ISO format) - optional, used for pagination
        end_cursor (str): Pagination cursor from previous request
        max_fetch (int): Maximum number of detections to fetch (overrides api_limit when provided)
        add_detection_url (bool): Whether to add detection URL to each detection
        api_limit (int): API limit for backward compatibility (default: WIZ_API_LIMIT)
        paginate (bool): Whether to enable pagination
        return_page_info (bool): Whether to return page info along with detections

    Returns:
        list/tuple/str:
            - If return_page_info=False: List of detections or error message (backward compatible)
            - If return_page_info=True: Tuple of (detections_list, page_info_dict) or (error_message, {})
    """
    # Create parameters dictionary
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
        WizApiVariables.AFTER: after_time,
        WizApiVariables.BEFORE: before_time,
        WizApiResponse.END_CURSOR: end_cursor,
    }

    log_input_parameters(parameters_dict)

    validation_success, error_message, validated_values = validate_all_detection_parameters(parameters_dict)

    if not validation_success or error_message:
        return error_message

    detection_variables = PULL_DETECTIONS_VARIABLES.copy()
    detection_variables[WizApiVariables.FIRST] = api_limit
    detection_variables = apply_all_detection_filters(detection_variables, validated_values)

    wiz_detections = query_detections(variables=detection_variables, paginate=paginate, max_fetch=max_fetch)

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
    variables = apply_creation_in_last_filter(variables, validated_values.get(WizInputParam.CREATION_DAYS_BACK), "days")
    variables = apply_platform_filter(variables, validated_values.get(WizInputParam.PLATFORM), is_detection=False)
    variables = apply_cloud_account_or_cloud_organization_filter(
        variables, validated_values.get(WizInputParam.CLOUD_ACCOUNT_OR_CLOUD_ORG), is_detection=False
    )
    variables = apply_resource_id_filter(variables, validated_values.get(WizInputParam.RESOURCE_ID), is_detection=False)
    variables = apply_severity_filter(variables, validated_values.get(WizInputParam.SEVERITY), is_detection=False)
    variables = apply_status_filter(variables, validated_values.get(WizInputParam.STATUS))
    variables = apply_origin_filter(variables, validated_values.get(WizInputParam.ORIGIN), is_detection=False)
    variables = apply_project_id_filter(variables, validated_values.get(WizInputParam.PROJECT_ID), is_detection=False)

    return variables


def get_filtered_threats(
    issue_id=None,
    platform=None,
    cloud_account_or_cloud_organization=None,
    resource_id=None,
    origin=None,
    severity=None,
    status=None,
    creation_days_back=None,
    project_id=None,
    add_threat_url=True,
    api_limit=WIZ_API_LIMIT,
    paginate=True,
):
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
    parameters_dict = {
        WizInputParam.ISSUE_ID: issue_id,
        WizInputParam.PLATFORM: platform,
        WizInputParam.ORIGIN: origin,
        WizInputParam.CLOUD_ACCOUNT_OR_CLOUD_ORG: cloud_account_or_cloud_organization,
        WizInputParam.RESOURCE_ID: resource_id,
        WizInputParam.SEVERITY: severity,
        WizInputParam.STATUS: status,
        WizInputParam.CREATION_DAYS_BACK: creation_days_back,
        WizInputParam.PROJECT_ID: project_id,
    }

    log_input_parameters(parameters_dict)

    validation_success, error_message, validated_values = validate_all_threat_parameters(parameters_dict)

    if not validation_success or error_message:
        return error_message

    threat_variables = PULL_THREAT_ISSUE_VARIABLES.copy()
    threat_variables[WizApiVariables.FIRST] = api_limit
    threat_variables = apply_all_threat_filters(threat_variables, validated_values)

    wiz_threats = query_issues(variables=threat_variables, paginate=paginate)

    if add_threat_url:
        for threat in wiz_threats:
            threat[WizApiVariables.URL] = get_threat_url(threat)

    return wiz_threats


def get_error_output(wiz_api_response):
    error_output_message = ""
    first_error_message = ""
    if WizApiResponse.ERRORS in wiz_api_response:
        for error_dict in wiz_api_response[WizApiResponse.ERRORS]:
            if WizApiResponse.MESSAGE in error_dict:
                error_message = error_dict[WizApiResponse.MESSAGE]

                # Do not print duplicate errors
                if first_error_message and first_error_message == error_message:
                    continue
                if not first_error_message:
                    first_error_message = error_message

                error_output_message = error_output_message + error_message + "\n"

    return error_output_message if error_output_message else wiz_api_response


def log_and_return_error(message):
    """
    Logs an error message and returns error to Demisto.

    Args:
        message (str): The error message to log and return
    """
    demisto.error(message)
    return_error(message)


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
    """
    try:
        demisto_args = demisto.args()
        detection_type = demisto_args.get(WizInputParam.TYPE)
        detection_platform = demisto_args.get(WizInputParam.PLATFORM)
        detection_origin = demisto_args.get(WizInputParam.ORIGIN)
        detection_cloud_account_or_cloud_organization = demisto_args.get(WizInputParam.CLOUD_ACCOUNT_OR_CLOUD_ORG)
        resource_id = demisto_args.get(WizInputParam.RESOURCE_ID)
        severity = demisto_args.get(WizInputParam.SEVERITY)
        creation_minutes_back = demisto_args.get(WizInputParam.CREATION_MINUTES_BACK, "10")
        matched_rule = demisto_args.get(WizInputParam.RULE_MATCH_ID)
        matched_rule_name = demisto_args.get(WizInputParam.RULE_MATCH_NAME)
        project_id = demisto_args.get(WizInputParam.PROJECT_ID)
        issue_id = demisto_args.get(WizInputParam.ISSUE_ID)

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
            project_id=project_id,
            issue_id=issue_id,
        )

        if isinstance(detections, str):
            return log_and_return_error(f"Error retrieving detections: {detections}")
        else:
            return_results(CommandResults(outputs_prefix=OutputPrefix.DETECTIONS, outputs=detections, raw_response=detections))
    except Exception as err:
        demisto.error(str(traceback.format_exc()))
        return log_and_return_error(f"An error occurred while retrieving detections: {str(err)}")


def get_single_detection():
    """Retrieves a single detection by ID."""
    try:
        demisto_args = demisto.args()
        detection_id = demisto_args.get(WizInputParam.DETECTION_ID)
        if not detection_id:
            return log_and_return_error(f"Missing required argument: {WizInputParam.DETECTION_ID}")

        detection = get_filtered_detections(
            detection_id=detection_id, detection_type=[DetectionType.GENERATED_THREAT, DetectionType.DID_NOT_GENERATE_THREAT]
        )

        if isinstance(detection, str):
            return log_and_return_error(f"Error retrieving detection: {detection}")
        else:
            return_results(
                CommandResults(
                    outputs_prefix=OutputPrefix.DETECTION, outputs=detection, readable_output=detection, raw_response=detection
                )
            )
    except Exception as err:
        demisto.error(str(traceback.format_exc()))
        return log_and_return_error(f"An error occurred while retrieving detection: {str(err)}")


def is_valid_issue_id(issue_id):
    if not issue_id:
        error_message = "You should pass an Issue ID."
        demisto.error(error_message)
        return False, error_message

    if not is_valid_uuid(issue_id):
        error_message = f"Wrong format: The Issue ID should be in UUID format. Received: {issue_id}"
        demisto.error(error_message)
        return False, error_message

    return True, f"The Issue ID {issue_id} is in a valid format"


def get_single_threat():
    """Retrieves a single threat by Issue ID."""
    try:
        demisto_args = demisto.args()
        issue_id = demisto_args.get(WizInputParam.ISSUE_ID)
        is_valid_id, message = is_valid_issue_id(issue_id)
        if not is_valid_id:
            return log_and_return_error(message)

        threat = get_filtered_threats(issue_id=issue_id)

        if isinstance(threat, str):
            return log_and_return_error(f"Error retrieving threat: {threat}")
        else:
            return_results(
                CommandResults(outputs_prefix=OutputPrefix.THREAT, outputs=threat, readable_output=threat, raw_response=threat)
            )
    except Exception as err:
        demisto.error(str(traceback.format_exc()))
        return log_and_return_error(f"An error occurred while retrieving threat: {str(err)}")


def get_threats():
    """Retrieves threats based on command arguments."""
    try:
        demisto_args = demisto.args()
        severity = demisto_args.get(WizInputParam.SEVERITY)
        platform = demisto_args.get(WizInputParam.PLATFORM)
        status = demisto_args.get(WizInputParam.STATUS)
        origin = demisto_args.get(WizInputParam.ORIGIN)
        cloud_account_or_cloud_organization = demisto_args.get(WizInputParam.CLOUD_ACCOUNT_OR_CLOUD_ORG)
        resource_id = demisto_args.get(WizInputParam.RESOURCE_ID)
        creation_days_back = demisto_args.get(WizInputParam.CREATION_DAYS_BACK)
        project_id = demisto_args.get(WizInputParam.PROJECT_ID)

        threats = get_filtered_threats(
            severity=severity,
            platform=platform,
            status=status,
            origin=origin,
            cloud_account_or_cloud_organization=cloud_account_or_cloud_organization,
            resource_id=resource_id,
            creation_days_back=creation_days_back,
            project_id=project_id,
        )

        if isinstance(threats, str):
            return log_and_return_error(f"Error retrieving threats: {threats}")
        else:
            return_results(CommandResults(outputs_prefix=OutputPrefix.THREATS, outputs=threats, raw_response=threats))
    except Exception as err:
        demisto.error(str(traceback.format_exc()))
        return log_and_return_error(f"An error occurred while retrieving threats: {str(err)}")


def set_status(issue_id, status):
    """
    Set a Wiz Issue status with validation

    Args:
        issue_id (str): The issue ID
        status (str): The status to set (must be a valid WizStatus value)

    Returns:
        dict/str: API response or error message
    """
    demisto.debug(f"Starting set status function for: {status}")

    # Validate issue ID
    is_valid_id, message = is_valid_issue_id(issue_id)
    if not is_valid_id:
        return message

    # Validate status is in WizStatus
    valid_statuses = [WizStatus.OPEN, WizStatus.IN_PROGRESS, WizStatus.REJECTED, WizStatus.RESOLVED]
    if status not in valid_statuses:
        error_msg = f"Invalid status: {status}. Valid statuses are: {', '.join(valid_statuses)}."
        demisto.error(error_msg)
        return error_msg

    variables = {WizApiVariables.ISSUE_ID: issue_id, WizApiVariables.PATCH: {WizApiVariables.STATUS: status}}
    query = UPDATE_ISSUE_QUERY

    response = get_entries(query, variables, WizApiResponse.UPDATE_ISSUE)

    return response


def reject_or_resolve_issue(issue_id, reject_or_resolve_reason, reject_or_resolve_comment, status):
    """
    Reject a Wiz Issue
    """
    demisto.debug(f"Starting reject or resolve issue : {status}, enter")
    operation = WizOperation.REJECT if status == WizStatus.REJECTED else WizOperation.RESOLUTION

    is_valid_id, message = is_valid_issue_id(issue_id)
    if not is_valid_id:
        return return_error(f"Error: {message}")

    if not reject_or_resolve_reason or not reject_or_resolve_comment:
        error_message = f"You should pass all of: Issue ID, {operation} reason and {operation} note."
        demisto.error(error_message)
        return return_error(f"Error: {error_message}")

    variables = {
        WizApiVariables.ISSUE_ID: issue_id,
        WizApiVariables.PATCH: {
            WizApiVariables.STATUS: status,
            WizApiVariables.NOTE: reject_or_resolve_comment,
            WizApiVariables.RESOLUTION_REASON: reject_or_resolve_reason,
        },
    }
    query = UPDATE_ISSUE_QUERY

    response = get_entries(query, variables, WizApiResponse.UPDATE_ISSUE)
    if response:
        return_results(
            CommandResults(outputs_prefix=OutputPrefix.THREAT, outputs=f"Successfully modified the threat status to {status}.")
        )
        return None
    else:
        return log_and_return_error(f"Failed to {operation} issue with ID {issue_id}. Please check the input parameters.")


def validate_threat_detections_issue(issue_id):
    is_valid_id, message = is_valid_issue_id(issue_id)
    if not is_valid_id:
        return False, message

    issue_object = query_single_issue(issue_id=issue_id)
    issue_type = issue_object[0][WizApiResponse.TYPE]

    if issue_type != WizIssueType.THREAT_DETECTION:
        error_message = f"Only a Threat Detection Issue can be resolved.\nReceived an Issue of type {issue_type}."
        demisto.error(error_message)
        return False, error_message

    return True, None


def resolve_threat():
    demisto_args = demisto.args()
    issue_id = demisto_args.get(WizInputParam.ISSUE_ID)
    resolution_reason = demisto_args.get(WizInputParam.RESOLUTION_REASON)
    resolution_note = demisto_args.get(WizInputParam.RESOLUTION_NOTE)
    demisto.debug(
        f"resolve_threat called with issue_id: {issue_id}, "
        f"resolution_reason: {resolution_reason}, resolution_note: {resolution_note}"
    )

    is_threat_issue, message = validate_threat_detections_issue(issue_id)
    if not is_threat_issue:
        return return_error(f"Error: {message}")

    return reject_or_resolve_issue(issue_id, resolution_reason, resolution_note, WizStatus.RESOLVED)


def set_issue_note(issue_id, comment):
    """
    Set a note on Wiz Issue
    """

    is_valid_id, message = is_valid_issue_id(issue_id)
    if not is_valid_id:
        return message

    variables = {"input": {"issueId": issue_id, "text": comment}}
    query = CREATE_COMMENT_QUERY

    response = get_entries(query, variables, WizApiResponse.CREATE_ISSUE_NOTE)
    if not response:
        return_error(f"Error: Failed to set note on issue with ID {issue_id}.\n" f"Please check the input parameters.")
    return response


def _reopen_issue(issue_id, reopen_note):
    """
    Re-open a Wiz Issue
    """

    demisto.debug("reopen_issue, enter")

    is_valid_id, message = is_valid_issue_id(issue_id)
    if not is_valid_id:
        return return_error(message)

    query = UPDATE_ISSUE_QUERY
    variables = {"issueId": issue_id, "patch": {"status": "OPEN"}}

    response = get_entries(query, variables, WizApiResponse.UPDATE_ISSUE)
    demisto.info(f"Ariel the response is {response}")
    if not response:
        error_message = f"Failed to reopen issue with ID {issue_id}. Please check the input parameters."
        demisto.error(error_message)
        return_error(f"Error: {error_message}")

    if reopen_note:
        return set_issue_note(issue_id, reopen_note)

    return response


def reopen_threat():
    demisto_args = demisto.args()
    issue_id = demisto_args.get(WizInputParam.ISSUE_ID)
    reopen_note = demisto_args.get(WizInputParam.REOPEN_NOTE)
    demisto.debug(f"reopen_threat called with issue_id: {issue_id}, reopen_note: {reopen_note}")

    if _reopen_issue(issue_id, reopen_note):
        return_results(
            CommandResults(outputs_prefix=OutputPrefix.THREAT, outputs=f"Successfully reopened the threat with ID {issue_id}.")
        )
    else:
        return_error(
            f"Error: Failed to reopen the threat with ID {issue_id}. " f"Please check the input parameters and try again."
        )


def set_threat_in_progress():
    demisto_args = demisto.args()
    issue_id = demisto_args.get(WizInputParam.ISSUE_ID)
    demisto.debug(f"set_threat_in_progress called with issue_id: {issue_id}")

    if set_status(issue_id, WizStatus.IN_PROGRESS):
        return_results(
            CommandResults(
                outputs_prefix=OutputPrefix.THREAT, outputs=f"Successfully set the threat with ID {issue_id} to In Progress."
            )
        )
    else:
        return_error(
            f"Error: Failed to set the threat with ID {issue_id} to In Progress. "
            f"Please check the input parameters and try again."
        )


def set_threat_comment():
    demisto_args = demisto.args()
    issue_id = demisto_args.get(WizInputParam.ISSUE_ID)
    note = demisto_args.get(WizInputParam.NOTE)
    demisto.debug(f"set_threat_note called with issue_id: {issue_id} and note {note}")

    if set_issue_note(issue_id, note):
        return_results(
            CommandResults(
                outputs_prefix=OutputPrefix.THREAT, outputs=f"Successfully set {note} as comment to the threat with ID {issue_id}"
            )
        )
    else:
        return_error(
            f"Error: Failed to set the comment {note} to the threat with ID {issue_id}. "
            f"Please check the input parameters and try again."
        )


def clear_threat_comments():
    demisto_args = demisto.args()
    issue_id = demisto_args.get(WizInputParam.ISSUE_ID)
    demisto.debug(f"clear_threat_note called with issue_id: {issue_id}")

    threat = get_filtered_threats(issue_id=issue_id)
    threat_notes = threat[0].get(WizApiResponse.NOTES, [])

    for note in threat_notes:
        variables = {"input": {"id": note["id"]}}
        if not get_entries(DELETE_NOTE_QUERY, variables, "deleteIssueNote"):
            return log_and_return_error(
                f"Error: Failed to delete the comment {note['text']} from the threat with ID {issue_id}. "
                f"Please check the input parameters and try again."
            )

    return_results(
        CommandResults(
            outputs_prefix=OutputPrefix.THREAT,
            outputs=f"Successfully cleared all the comments from the threat with ID {issue_id}.",
        )
    )
    return None


def get_safe_params_for_logging() -> Dict[str, Any]:
    """
    Returns integration parameters with sensitive credential information filtered out.
    This function is safe to use in logging and debugging as it excludes service account
    credentials and other sensitive information.

    Returns:
        dict: Filtered parameters dictionary without sensitive data
    """
    params = demisto.params()

    # Define sensitive parameter keys that should be excluded from logging
    sensitive_param_keys = {
        DemistoParams.CREDENTIALS,  # The entire credentials object
        DemistoParams.IDENTIFIER,  # Service account ID/Client ID
        DemistoParams.PASSWORD,  # Service account secret/Client Secret
        WizApiInputFields.CLIENT_ID,  # Alternative client ID field
        WizApiInputFields.CLIENT_SECRET,  # Alternative client secret field
        "service_account_id",  # Legacy field name
        "service_account_secret",  # Legacy field name
        "client_id",  # Direct client ID field
        "client_secret",  # Direct client secret field
        "access_token",  # Any access tokens
        "token",  # Generic token field
        "api_key",  # API keys
        "secret",  # Generic secret field
        "password",  # Generic password field
    }

    safe_params: Dict[str, Any] = {}

    for key, value in params.items():
        if isinstance(value, dict):
            safe_nested: Dict[str, Any] = {}
            for nested_key, nested_value in value.items():
                if nested_key in sensitive_param_keys:
                    safe_nested[nested_key] = "***REDACTED***"
                else:
                    safe_nested[nested_key] = nested_value
            safe_params[key] = safe_nested
        elif key in sensitive_param_keys:
            # Replace sensitive values with placeholder
            safe_params[key] = "***REDACTED***"
        else:
            # Keep non-sensitive values as-is
            safe_params[key] = value

    return safe_params


def main():
    params = demisto.params()
    set_authentication_endpoint(params.get(DemistoParams.AUTH_ENDPOINT))
    set_api_endpoint(params.get(DemistoParams.API_ENDPOINT, ""))
    try:
        command = demisto.command()
        demisto.info(f"=== Starting {WIZ_DEFEND} integration version {WIZ_VERSION}. Command being called is '{command}' ===")
        demisto.debug(
            f"Extracting parameters from integration settings: {get_safe_params_for_logging()}\n"
            f"Command arguments: {demisto.args()}\n"
        )

        if command == "test-module":
            test_module()

        elif command == "fetch-incidents":
            fetch_incidents()

        elif command == "wiz-defend-get-detection":
            get_single_detection()

        elif command == "wiz-defend-get-detections":
            get_detections()

        elif command == "wiz-defend-get-threat":
            get_single_threat()

        elif command == "wiz-defend-get-threats":
            get_threats()

        elif command == "wiz-defend-resolve-threat":
            resolve_threat()

        elif command == "wiz-defend-reopen-threat":
            reopen_threat()

        elif command == "wiz-defend-set-threat-in-progress":
            set_threat_in_progress()

        elif command == "wiz-defend-set-threat-comment":
            set_threat_comment()

        elif command == "wiz-defend-clear-threat-comments":
            clear_threat_comments()

        # elif command == "wiz-copy-threat-to-forensics-account":
        #     return_results(copy_to_forensics())

        else:
            raise Exception("Unrecognized command: " + command)
    except Exception as err:
        demisto.error(str(traceback.format_exc()))
        return_error(f"An error occurred: {str(err)}")
        return


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
