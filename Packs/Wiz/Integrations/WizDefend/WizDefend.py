import uuid
import traceback

from CommonServerPython import *
import demistomock as demisto
from urllib import parse

DEMISTO_OCCURRED_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
WIZ_API_LIMIT = 1  # limit number of returned records from the Wiz API
WIZ = 'wiz'

WIZ_VERSION = '1.0.0'
INTEGRATION_GUID = '8864e131-72db-4928-1293-e292f0ed699f'


class WizInputParam:
    DETECTION_ID = 'detection_id'
    ISSUE_ID = 'issue_id'
    DETECTION_TYPE = 'detection_type'
    DETECTION_PLATFORM = 'detection_platform'
    RESOURCE_ID = 'resource_id'
    SEVERITY = 'severity'
    CREATION_DAYS_BACK = 'creation_days_back'
    MATCHED_RULE = 'matched_rule'
    MATCHED_RULE_NAME = 'matched_rule_name'
    PROJECT_ID = 'project_id'


class WizApiResponse:
    DATA = 'data'
    DETECTIONS = 'detections'
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


class WizApiVariables:
    FIRST = 'first'
    AFTER = 'after'
    FILTER_BY = 'filterBy'
    ORDER_BY = 'orderBy'
    STATUS = 'status'
    CREATED_AT = 'createdAt'
    AFTER_TIME = 'after'
    FIELD = 'field'
    DIRECTION = 'direction'
    TYPE = 'type'
    PROVIDER_UNIQUE_ID = 'providerUniqueId'
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
    NAME = 'name'
    RULE = 'rule'
    RULE_MATCH = 'ruleMatch'


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


class ValidationType:
    """Class representing field names for validation results"""
    IS_VALID = "is_valid"
    ERROR_MESSAGE = "error_message"
    VALUE = "value"
    SEVERITY_LIST = "severity_list"
    DAYS_VALUE = "days_value"


class ValidationResponse:
    """Class for standardized validation responses"""

    def __init__(self, is_valid=True, error_message=None, value=None):
        self.is_valid = is_valid
        self.error_message = error_message
        self.value = value
        self.days_value = None
        self.severity_list = None

    def to_dict(self):
        """Convert the response to a dictionary"""
        return {
            ValidationType.IS_VALID: self.is_valid,
            ValidationType.ERROR_MESSAGE: self.error_message,
            ValidationType.VALUE: self.value,
            ValidationType.DAYS_VALUE: self.days_value,
            ValidationType.SEVERITY_LIST: self.severity_list
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
    GENERATED_THREAT = "GENERATED_THREAT"
    MATCH_ONLY = "MATCH_ONLY"

    @classmethod
    def values(cls):
        """Get all available detection types"""
        return [getattr(cls, attr) for attr in dir(cls)
                if not attr.startswith('_') and not callable(getattr(cls, attr))]


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


def get_integration_user_agent():
    integration_user_agent = f'{INTEGRATION_GUID}/xsoar_defend/{WIZ_VERSION}'
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
      }
      ruleMatch {
        rule {
          id
          name
          sourceType
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
    WizApiVariables.FIRST: WIZ_API_LIMIT,
    WizApiVariables.ORDER_BY: {WizApiVariables.FIELD: WizOrderByFields.CREATED_AT,
                               WizApiVariables.DIRECTION: WizOrderDirection.ASC}
}


# Functions to handle Wiz API
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


def get_entries(query, variables):
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
            raise Exception('Error authenticating to Wiz [{}] - {}'.format(response.status_code, response.text))

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

        return response_json[WizApiResponse.DATA][WizApiResponse.DETECTIONS][WizApiResponse.NODES], \
               response_json[WizApiResponse.DATA][WizApiResponse.DETECTIONS][WizApiResponse.PAGE_INFO]

    except Exception as e:
        error_message = f"Received an error while performing an API call.\nError info: {str(e)}"
        demisto.error(error_message)
        raise Exception(f"An unexpected error occurred.\nError info: {error_message}")


def query_api(query, variables):
    entries, page_info = get_entries(query, variables)
    if not entries:
        demisto.info("No detection(/s) available to fetch.")

    while page_info[WizApiResponse.HAS_NEXT_PAGE]:
        variables[WizApiVariables.AFTER] = page_info[WizApiResponse.END_CURSOR]
        new_entries, page_info = get_entries(query, variables)
        if new_entries is not None:
            entries += new_entries
    return entries


def checkAPIerrors(query, variables):
    if not TOKEN:
        get_token()

    data = {"variables": variables, "query": query}

    demisto.info(f"Invoking the API with {json.dumps(data)}")

    result = requests.post(url=URL, json=data, headers=HEADERS)

    demisto.info(f"Response status code is {result.status_code}")
    demisto.info(f"The response is {result.json()}")

    error_message = ""
    result_json = result.json()
    if WizApiResponse.ERRORS in result_json:
        demisto.info(f"Wiz error content: {result_json[WizApiResponse.ERRORS]}")
        error_message = f"Wiz API error details: {get_error_output(result_json)}"

    elif WizApiResponse.DATA in result_json and \
        WizApiResponse.DETECTIONS in result_json[WizApiResponse.DATA] and \
        not result_json[WizApiResponse.DATA][WizApiResponse.DETECTIONS].get(WizApiResponse.NODES):
        demisto.info("No detection(/s) available to fetch.")

    if error_message:
        demisto.error("An error has occurred using:"
                      f"\tQuery: {query} - "
                      f"\tVariables: {variables} -"
                      f"\t{error_message}")
        demisto.error(error_message)
        raise Exception(f"{error_message}\nCheck 'server.log' instance file to get additional information")
    return result_json


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


def fetch_incidents():
    """
    Fetch all Detections (OOB XSOAR Fetch)
    """

    last_run = demisto.getLastRun().get(DemistoParams.TIME)

    if not last_run:  # first time fetch
        last_run = dateparser.parse(demisto.params().get(DemistoParams.FIRST_FETCH, '3 days').strip())
        last_run = (last_run.isoformat()[:-3] + 'Z')

    detection_variables = PULL_DETECTIONS_VARIABLES.copy()
    if WizApiVariables.FILTER_BY not in detection_variables:
        detection_variables[WizApiVariables.FILTER_BY] = {}

    detection_variables = apply_creation_after_days_filter(detection_variables, last_run)
    api_start_run_time = datetime.now().strftime(DEMISTO_OCCURRED_FORMAT)

    response_json = checkAPIerrors(PULL_DETECTIONS_QUERY, detection_variables)

    detections = response_json[WizApiResponse.DATA][WizApiResponse.DETECTIONS][WizApiResponse.NODES]
    while response_json[WizApiResponse.DATA][WizApiResponse.DETECTIONS][WizApiResponse.PAGE_INFO][WizApiResponse.HAS_NEXT_PAGE]:
        detection_variables[WizApiVariables.AFTER] = \
            response_json[WizApiResponse.DATA][WizApiResponse.DETECTIONS][WizApiResponse.PAGE_INFO][WizApiResponse.END_CURSOR]
        response_json = checkAPIerrors(PULL_DETECTIONS_QUERY, detection_variables)
        if response_json[WizApiResponse.DATA][WizApiResponse.DETECTIONS][WizApiResponse.NODES] != []:
            detections.extend(response_json[WizApiResponse.DATA][WizApiResponse.DETECTIONS][WizApiResponse.NODES])

    incidents = []
    for detection in detections:
        incident = build_incidents(detection=detection)
        incidents.append(incident)

    demisto.incidents(incidents)
    demisto.setLastRun({DemistoParams.TIME: api_start_run_time})


def get_detection(detection_id=None, issue_id=None):
    """
    Get detection details by detection_id or issue_id
    """
    demisto.info(f"Detection ID is {detection_id}, Issue ID is {issue_id}\n")

    # Validate at least one parameter is provided
    if not detection_id and not issue_id:
        error_msg = f"You must provide either {WizInputParam.DETECTION_ID} or {WizInputParam.ISSUE_ID}."
        demisto.error(error_msg)
        return error_msg

    detection_variables = PULL_DETECTIONS_VARIABLES.copy()
    if WizApiVariables.FILTER_BY not in detection_variables:
        detection_variables[WizApiVariables.FILTER_BY] = {}

    # Handle detection_id
    if detection_id:
        if isinstance(detection_id, list):
            for d_id in detection_id:
                is_valid_id, message = is_valid_param_id(d_id, WizInputParam.DETECTION_ID)
                if not is_valid_id:
                    demisto.debug(message)
                    return message
            detection_ids = detection_id
        else:
            is_valid_id, message = is_valid_param_id(detection_id, WizInputParam.DETECTION_ID)
            if not is_valid_id:
                demisto.debug(message)
                return message
            detection_ids = [detection_id]

        detection_variables[WizApiVariables.FILTER_BY][WizApiVariables.ID] = {
            WizApiVariables.EQUALS: detection_ids
        }

    # Handle issue_id
    if issue_id:
        is_valid_id, message = is_valid_param_id(issue_id, WizInputParam.ISSUE_ID)
        if not is_valid_id:
            demisto.debug(message)
            return message
        detection_variables[WizApiVariables.FILTER_BY][WizApiVariables.ISSUE_ID] = issue_id

    wiz_detection = query_api(PULL_DETECTIONS_QUERY, detection_variables)
    demisto.info(f"wiz detection is {wiz_detection} and the type is {type(wiz_detection)}")

    if not wiz_detection:
        wiz_detection = {}
        if detection_id:
            demisto.info(f"There was no result for Detection ID: {detection_id}")
        else:
            demisto.info(f"There was no result for Issue ID: {issue_id}")

    return wiz_detection


def validate_detection_type(detection_type):
    """
    Validates if the detection type is supported

    Args:
        detection_type (str): The detection type to validate

    Returns:
        ValidationResponse: Response with validation results
    """
    if not detection_type:
        return ValidationResponse.create_success()

    if detection_type in DetectionType.values():
        return ValidationResponse.create_success(detection_type)
    else:
        valid_types = DetectionType.values()
        error_msg = f"Invalid detection type: {detection_type}. Valid types are: {', '.join(valid_types)}"
        demisto.error(error_msg)
        return ValidationResponse.create_error(error_msg)


def validate_detection_platform(platform):
    """
    Validates if the detection platform is supported

    Args:
        platform (str): The platform to validate

    Returns:
        ValidationResponse: Response with validation results
    """
    if not platform:
        return ValidationResponse.create_success()

    if platform in CloudPlatform.values():
        return ValidationResponse.create_success(platform)
    else:
        valid_platforms = CloudPlatform.values()
        error_msg = f"Invalid platform: {platform}. Valid platforms are: {', '.join(valid_platforms)}"
        demisto.error(error_msg)
        return ValidationResponse.create_error(error_msg)


def validate_creation_days_back(days_back):
    """
    Validates if the creation_days_back parameter is valid

    Args:
        days_back (str): Number of days back to retrieve detections

    Returns:
        ValidationResponse: Response with validation results and days value
    """
    response = ValidationResponse.create_success()
    response.days_value = 2  # Default to 2 days

    if not days_back:
        return response

    try:
        days_value = int(days_back)
        if 1 <= days_value <= 60:
            response.days_value = days_value
            return response
        else:
            error_msg = "creation_days_back must be between 1 and 60."
            demisto.error(error_msg)
            return ValidationResponse.create_error(error_msg)
    except ValueError:
        error_msg = "creation_days_back must be a valid integer between 1 and 60."
        demisto.error(error_msg)
        return ValidationResponse.create_error(error_msg)


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
        error_msg = "You should only use these severity types: CRITICAL, HIGH, MEDIUM, LOW or INFORMATIONAL in upper or lower case."
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


def validate_resource_id(resource_id):
    """
    Validates resource_id parameter

    Args:
        resource_id (str): The resource ID to validate

    Returns:
        ValidationResponse: Response with validation results
    """
    if not resource_id:
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
    if not rule_match_name:
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
    if not project:
        return ValidationResponse.create_success()

    return ValidationResponse.create_success(project)


def validate_all_parameters(parameters_dict):
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
    detection_type = parameters_dict.get(WizInputParam.DETECTION_TYPE)
    detection_platform = parameters_dict.get(WizInputParam.DETECTION_PLATFORM)
    resource_id = parameters_dict.get(WizInputParam.RESOURCE_ID)
    severity = parameters_dict.get(WizInputParam.SEVERITY)
    creation_days_back = parameters_dict.get(WizInputParam.CREATION_DAYS_BACK)
    matched_rule = parameters_dict.get(WizInputParam.MATCHED_RULE)
    matched_rule_name = parameters_dict.get(WizInputParam.MATCHED_RULE_NAME)
    project_id = parameters_dict.get(WizInputParam.PROJECT_ID)

    # Check if at least one parameter is provided
    if not any([severity, detection_type, detection_platform, resource_id,
                matched_rule, matched_rule_name, project_id]):
        param_list = [
            f"\t{WizInputParam.DETECTION_TYPE}",
            f"\t{WizInputParam.DETECTION_PLATFORM}",
            f"\t{WizInputParam.RESOURCE_ID}",
            f"\t{WizInputParam.SEVERITY}",
            f"\t{WizInputParam.MATCHED_RULE}",
            f"\t{WizInputParam.MATCHED_RULE_NAME}",
            f"\t{WizInputParam.PROJECT_ID}"
        ]
        error_msg = f"You should pass at least one of the following parameters:\n" + "\n".join(param_list)
        demisto.error(error_msg)
        return False, error_msg, None

    # Validate detection type
    type_validation = validate_detection_type(detection_type)
    if not type_validation.is_valid:
        return False, type_validation.error_message, None
    validated_values[WizInputParam.DETECTION_TYPE] = type_validation.value

    # Validate platform
    platform_validation = validate_detection_platform(detection_platform)
    if not platform_validation.is_valid:
        return False, platform_validation.error_message, None
    validated_values[WizInputParam.DETECTION_PLATFORM] = platform_validation.value

    # Validate creation_days_back
    days_validation = validate_creation_days_back(creation_days_back)
    if not days_validation.is_valid:
        return False, days_validation.error_message, None
    validated_values[WizInputParam.CREATION_DAYS_BACK] = days_validation.days_value

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

    validated_values[WizInputParam.MATCHED_RULE] = matched_rule
    validated_values[WizInputParam.MATCHED_RULE_NAME] = matched_rule_name
    validated_values[WizInputParam.PROJECT_ID] = project_id

    return True, None, validated_values


def apply_creation_in_last_days_filter(variables, days_back):
    """
    Adds the creation_days_back filter to the query variables

    Args:
        variables (dict): The query variables
        days_back (int): Number of days back

    Returns:
        dict: Updated variables with the filter
    """
    if not days_back:
        return variables

    if WizApiVariables.FILTER_BY not in variables:
        variables[WizApiVariables.FILTER_BY] = {}

    variables[WizApiVariables.FILTER_BY][WizApiVariables.CREATED_AT] = {
        WizApiVariables.IN_LAST: {WizApiVariables.AMOUNT: days_back,
                                  WizApiVariables.UNIT: DurationUnit.DAYS}
    }

    return variables


def apply_creation_after_days_filter(variables, after_time):
    """
    Adds the creation_days_back filter to the query variables

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


def apply_platform_filter(variables, platform):
    """
    Adds the platform filter to the query variables

    Args:
        variables (dict): The query variables
        platform (str): The cloud platform

    Returns:
        dict: Updated variables with the filter
    """
    if not platform:
        return variables

    if WizApiVariables.FILTER_BY not in variables:
        variables[WizApiVariables.FILTER_BY] = {}

    variables[WizApiVariables.FILTER_BY][WizApiVariables.CLOUD_PLATFORM] = {
        WizApiVariables.EQUALS: [platform]
    }

    return variables


def apply_resource_id_filter(variables, resource_id):
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

    variables[WizApiVariables.FILTER_BY][WizApiVariables.RESOURCE] = {
        WizApiVariables.ID: {
            WizApiVariables.EQUALS: [resource_id]
        }
    }

    return variables


def apply_severity_filter(variables, severity_list):
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

    variables[WizApiVariables.FILTER_BY][WizApiVariables.SEVERITY] = {
        WizApiVariables.EQUALS: severity_list
    }

    return variables


def apply_matched_rule_filter(variables, matched_rule):
    """
    Adds the matched rule filter to the query variables

    Args:
        variables (dict): The query variables
        matched_rule (str): The matched rule ID

    Returns:
        dict: Updated variables with the filter
    """
    if not matched_rule:
        return variables

    if WizApiVariables.FILTER_BY not in variables:
        variables[WizApiVariables.FILTER_BY] = {}

    variables[WizApiVariables.FILTER_BY][WizApiVariables.MATCHED_RULE] = {
        WizApiVariables.ID: matched_rule
    }

    return variables


def apply_matched_rule_name_filter(variables, matched_rule_name):
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


def apply_project_id_filter(variables, project_id):
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

    variables[WizApiVariables.FILTER_BY][WizApiVariables.PROJECT_ID] = project_id

    return variables


def apply_all_filters(variables, validated_values):
    """
    Applies all filters to the query variables in a centralized function

    Args:
        variables (dict): Base query variables
        validated_values (dict): Dictionary of validated values

    Returns:
        dict: Updated query variables with all filters applied
    """
    variables = apply_creation_in_last_days_filter(variables, validated_values.get(WizInputParam.CREATION_DAYS_BACK))
    variables = apply_detection_type_filter(variables, validated_values.get(WizInputParam.DETECTION_TYPE))
    variables = apply_platform_filter(variables, validated_values.get(WizInputParam.DETECTION_PLATFORM))
    variables = apply_resource_id_filter(variables, validated_values.get(WizInputParam.RESOURCE_ID))
    variables = apply_severity_filter(variables, validated_values.get(WizInputParam.SEVERITY))
    variables = apply_matched_rule_filter(variables, validated_values.get(WizInputParam.MATCHED_RULE))
    variables = apply_matched_rule_name_filter(variables, validated_values.get(WizInputParam.MATCHED_RULE_NAME))
    variables = apply_project_id_filter(variables, validated_values.get(WizInputParam.PROJECT_ID))

    return variables


def get_filtered_detections(detection_type, detection_platform, resource_id, severity, limit,
                           creation_days_back=None, matched_rule=None, matched_rule_name=None, project_id=None):
    """
    Retrieves Filtered Detections

    Args:
        detection_type (str): Type of detections
        detection_platform (str): Cloud platform
        resource_id (str): Resource ID
        severity (str): Severity level
        limit (int): Limit of results
        creation_days_back (str): Number of days back for creation filter
        matched_rule (str): Matched rule ID
        matched_rule_name (str): Matched rule name
        project_id (str): Project ID

    Returns:
        list/str: List of detections or error message
    """
    demisto.debug(f"Detection type is {detection_type}\n"
                  f"Detection platform is {detection_platform}\n"
                  f"Resource ID is {resource_id}\n"
                  f"Severity is {severity}\n"
                  f"Creation days back is {creation_days_back}\n"
                  f"Matched rule is {matched_rule}\n"
                  f"Matched rule name is {matched_rule_name}\n"
                  f"Project ID is {project_id}")

    # Create parameters dictionary for validation
    parameters_dict = {
        WizInputParam.DETECTION_TYPE: detection_type,
        WizInputParam.DETECTION_PLATFORM: detection_platform,
        WizInputParam.RESOURCE_ID: resource_id,
        WizInputParam.SEVERITY: severity,
        WizInputParam.CREATION_DAYS_BACK: creation_days_back,
        WizInputParam.MATCHED_RULE: matched_rule,
        WizInputParam.MATCHED_RULE_NAME: matched_rule_name,
        WizInputParam.PROJECT_ID: project_id
    }

    # Validate all parameters in a single function call
    validation_success, error_message, validated_values = validate_all_parameters(parameters_dict)

    if not validation_success or error_message:
        return error_message

    detection_variables = PULL_DETECTIONS_VARIABLES.copy()

    # Apply all filters in a single function call
    detection_variables = apply_all_filters(detection_variables, validated_values)

    response_json = checkAPIerrors(PULL_DETECTIONS_QUERY, detection_variables)

    demisto.info(f"The API response is {response_json}")

    detections = {}
    if response_json[WizApiResponse.DATA][WizApiResponse.DETECTIONS][WizApiResponse.NODES] != []:
        detections = response_json[WizApiResponse.DATA][WizApiResponse.DETECTIONS][WizApiResponse.NODES]

    # Handle pagination
    while response_json[WizApiResponse.DATA][WizApiResponse.DETECTIONS][WizApiResponse.PAGE_INFO][WizApiResponse.HAS_NEXT_PAGE]:
        detection_variables[WizApiVariables.AFTER] = \
            response_json[WizApiResponse.DATA][WizApiResponse.DETECTIONS][WizApiResponse.PAGE_INFO][WizApiResponse.END_CURSOR]
        response_json = checkAPIerrors(PULL_DETECTIONS_QUERY, detection_variables)
        if response_json[WizApiResponse.DATA][WizApiResponse.DETECTIONS][WizApiResponse.NODES] != []:
            detections.extend(response_json[WizApiResponse.DATA][WizApiResponse.DETECTIONS][WizApiResponse.NODES])

    return detections


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


def main():
    params = demisto.params()
    set_authentication_endpoint(params.get(DemistoParams.AUTH_ENDPOINT))
    set_api_endpoint(params.get(DemistoParams.API_ENDPOINT, ''))
    try:
        command = demisto.command()
        if command == DemistoCommands.TEST_MODULE:
            auth_token = get_token()
            if 'error' not in auth_token:
                test_response = checkAPIerrors(PULL_DETECTIONS_QUERY, PULL_DETECTIONS_VARIABLES)

                if WizApiResponse.ERRORS not in test_response:
                    demisto.results('ok')
                else:
                    demisto.results(test_response)
            else:
                demisto.results("Invalid token")

        elif command == DemistoCommands.FETCH_INCIDENTS:
            fetch_incidents()

        elif command == DemistoCommands.WIZ_GET_DETECTIONS:
            demisto_args = demisto.args()
            detection_type = demisto_args.get(WizInputParam.DETECTION_TYPE)
            detection_platform = demisto_args.get(WizInputParam.DETECTION_PLATFORM)
            resource_id = demisto_args.get(WizInputParam.RESOURCE_ID)
            severity = demisto_args.get(WizInputParam.SEVERITY)
            creation_days_back = demisto_args.get(WizInputParam.CREATION_DAYS_BACK, '2')
            matched_rule = demisto_args.get(WizInputParam.MATCHED_RULE)
            matched_rule_name = demisto_args.get(WizInputParam.MATCHED_RULE_NAME)
            project_id = demisto_args.get(WizInputParam.PROJECT_ID)

            detections = get_filtered_detections(
                detection_type=detection_type,
                detection_platform=detection_platform,
                resource_id=resource_id,
                severity=severity,
                limit=WIZ_API_LIMIT,
                creation_days_back=creation_days_back,
                matched_rule=matched_rule,
                matched_rule_name=matched_rule_name,
                project_id=project_id
            )

            if isinstance(detections, str):
                #  this means the Detection is an error
                command_result = CommandResults(readable_output=detections, raw_response=detections)
            else:
                command_result = CommandResults(outputs_prefix=OutputPrefix.DETECTIONS, outputs=detections,
                                                raw_response=detections)
            return_results(command_result)

        elif command == DemistoCommands.WIZ_GET_DETECTION:
            demisto_args = demisto.args()
            detection_id = demisto_args.get(WizInputParam.DETECTION_ID)
            issue_id = demisto_args.get(WizInputParam.ISSUE_ID)
            detection_result = get_detection(
                detection_id=detection_id,
                issue_id=issue_id
            )
            command_result = CommandResults(outputs_prefix=OutputPrefix.DETECTION, outputs=detection_result,
                                            readable_output=detection_result, raw_response=detection_result)
            return_results(command_result)

        else:
            raise Exception('Unrecognized command: ' + command)
    except Exception as err:
        demisto.error(str(traceback.format_exc()))
        return_error(f"An error occurred: {str(err)}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()