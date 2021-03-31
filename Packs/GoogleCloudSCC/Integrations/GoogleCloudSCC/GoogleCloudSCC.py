from CommonServerPython import *

""" IMPORTS """
import json
from typing import Any, Dict, List, Optional, Tuple, Callable, Union

import urllib.parse
import dateparser
import httplib2
import traceback
from copy import deepcopy
from google.auth import exceptions
from google.oauth2 import service_account
from googleapiclient import discovery
from googleapiclient.errors import HttpError
from google_auth_httplib2 import AuthorizedHttp

""" CONSTANTS """
SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]
SERVICE_NAME = "securitycenter"
PUBSUB_SERVICE_NAME = "pubsub"
SERVICE_VERSION = "v1"
PUBSUB_SERVICE_VERSION = "v1"
DEFAULT_MAX_FETCH_VALUE = "50"
MAX_FETCH_VALUE = "200"
DEFAULT_PAGE_SIZE = 10
INCIDENT_NAME_PREFIX = "GoogleCloudSCC"
STATE_LIST = ["ACTIVE", "INACTIVE"]  # List of state mentioned in API doc
SEVERITY_LIST = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]  # List of severity mentioned in API doc
ALLOWED_DATE_UNIT = ["minute", "minutes", "hour", "hours", "day", "days", "month", "months", "year", "years"]
DATE_FORMAT = "%B %d, %Y at %I:%M:%S %p"
ISO_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
MARKDOWN_LINK = "[{}]({})"
TIMEOUT_TIME = 60  # in second

# The maximum number of results to return in a single response.
# (ref: https://cloud.google.com/security-command-center/docs/reference/rest/v1/organizations.sources.findings/list)
MAX_PAGE_SIZE = 1000

ERROR_MESSAGES: Dict[str, str] = {
    "JSON_PARSE_ERROR": "Unable to parse json. Please check the {} parameter.",
    "INVALID_ORGANIZATION_ID": "Invalid Organization ID.",
    "INVALID_ORGANIZATION_OR_PERMISSION_DENIED_ERROR": "Organization Id is not valid or permission denied.",
    "INVALID_SERVICE_ACCOUNT": "Invalid service account credentials.",
    "BAD_REQUEST_ERROR": "An error occurred while fetching/submitting the data. Reason: {}",
    "AUTHENTICATION_ERROR": "Unauthenticated. Check the configured Service Account JSON. Reason: {}",
    "AUTHORIZATION_ERROR": "Request has insufficient privileges. Reason: {}",
    "NOT_FOUND_ERROR": "Not found. Reason: {}",
    "TOO_MANY_REQUESTS_ERROR": "Too many requests please try after sometime. Reason: {}",
    "INTERNAL_SERVER_ERROR": "The server encountered an internal error. Reason: {}",
    "CONFLICT_ERROR": "Conflict. Reason: {}",
    "TIMEOUT_ERROR": "Connection Timeout Error - potential reasons might be that the Server is not accessible "
                     "from your host. Reason: {}",
    "PROXY_ERROR": "Proxy Error - if the 'Use system proxy' checkbox in the integration configuration is"
                   " selected, try clearing the checkbox.",
    "UNKNOWN_ERROR": "An error occurred. Status: {}. Reason: {}",
    "NO_RECORDS_FOUND": "No {} record(s) found for the given argument(s).",
    "MAX_INCIDENT_ERROR": "The parameter Max Incidents must be a positive integer."
                          " Accepted values can be in the range of 1-{}.".format(MAX_FETCH_VALUE),
    "INVALID_STATE_ERROR": "The state value must be ACTIVE or INACTIVE.",
    "INVALID_SEVERITY_ERROR": "The severity value must be LOW, MEDIUM, HIGH or CRITICAL.",
    "INVALID_PAGE_SIZE_ERROR": "Page size should be an integer between 1 to 1000.",
    "INVALID_SOURCE_PROPERTIES": "Invalid format provided in sourceProperties. Supported format: key1=value1,key2="
                                 "value2. if the value contains ',' or '=' character then escape with extra '\\'.",
    "REQUIRED_PROJECT_ID": "Project ID is required for fetch incidents.",
    "REQUIRED_SUBSCRIPTION_ID": "Subscription ID is required for fetch incidents.",
    "INVALID_INCIDENT": "Error while parsing pub/sub message. Reason: {}"
}

OUTPUT_PREFIX: Dict[str, Any] = {
    "LIST_ASSET": "GoogleCloudSCC.Asset(val.name == obj.name)",
    "LIST_FINDING": "GoogleCloudSCC.Finding(val.name == obj.name)",
    "TOKEN": "GoogleCloudSCC.Token(val.name == obj.name)",
    "FINDING": "GoogleCloudSCC.Finding"
}

GET_OUTPUT_MESSAGE: Dict[str, Any] = {
    "HEADER_MESSAGE": "Total retrieved {0}: {1}"
}

COMMON_STRING: Dict[str, str] = {
    "RESOURCE_NAME": "Resource Name",
    "SECURITY_MARKS": "Security Marks",
    "SET_STATE_HR_STR": "The state of the finding has been updated successfully.",
    "EVENT_TIME": "Event Time (In UTC)",
    "CREATE_TIME": "Create Time (In UTC)"
}

""" HELPER CLASSES """


class GoogleNameParser:
    """
    Used to easily transform Google Cloud SCC names
    """
    # Google SCC helpers
    ORGANIZATION_PATH = "organizations/{}"
    SOURCE_PATH = "/sources/{}"
    FINDING_PATH = "/findings/{}"
    SCC_URL = "https://console.cloud.google.com/security/command-center/{}?organizationId={}&resourceId={}"

    # Google Pub/Sub helpers
    PROJECT_PATH = "projects/{}"
    SUBSCRIPTION_PATH = "/subscriptions/{}"

    @staticmethod
    def get_organization_id():
        """
        Return a fully-qualified organizations string.

        :return: fully-qualified organizations string.
        """
        return demisto.params().get("organization_id", "")

    @staticmethod
    def get_organization_path():
        """
        Return a fully-qualified organizations string.

        :return: fully-qualified organizations string.
        """
        return GoogleNameParser.ORGANIZATION_PATH.format(GoogleNameParser.get_organization_id())

    @staticmethod
    def get_source_path(source: str) -> str:
        """
        Return a fully-qualified source string.

        :param source: source id param.
        :return: fully-qualified source string.
        """
        return GoogleNameParser.get_organization_path() + GoogleNameParser.SOURCE_PATH.format(source)

    @staticmethod
    def get_finding_path(source, finding):
        """
        fully-qualified finding string.

        :param source: source name or source id
        :param finding: finding id
        :return: fully-qualified finding string.
        """
        return GoogleNameParser.get_source_path(source) + GoogleNameParser.FINDING_PATH.format(finding)

    @staticmethod
    def get_finding_url(name: str):
        """
        Get a finding url which redirect UI

        :param name: resource name
        :return: finding url
        """
        return GoogleNameParser.SCC_URL.format("findings", GoogleNameParser.get_organization_id(), name)

    @staticmethod
    def get_asset_url(name: str):
        """
        Get a asset url which redirect UI

        :param name: resource name
        :return: asset url
        """
        return GoogleNameParser.SCC_URL.format("assets", GoogleNameParser.get_organization_id(), name)

    @staticmethod
    def get_project_path(project_id):
        """
        Get a fully-qualified project path.

        :param project_id: project id of project
        :return: fully-qualified project path
        """
        return GoogleNameParser.PROJECT_PATH.format(project_id)

    @staticmethod
    def get_subscription_path(project_id, subscription_id):
        """
        Get a fully-qualified subscription path.

        :param project_id: project id of project
        :param subscription_id: subscription id of the topic
        :return:
        """
        return GoogleNameParser.get_project_path(project_id) + GoogleNameParser.SUBSCRIPTION_PATH.format(
            subscription_id)


class BaseGoogleClient:
    """
    A Client class to wrap the google cloud api library as a service.
    """

    def __init__(self, service_name: str, service_version: str, service_account_json: str, scopes: list, proxy: bool,
                 **kwargs):
        """
        :param service_name: The name of the service. You can find this and the service  here
         https://github.com/googleapis/google-api-python-client/blob/master/docs/dyn/index.md
        :param service_version: The version of the API.
        :param service_account_json: A string of the generated credentials.json
        :param scopes: The scope needed for the project. (i.e. ['https://www.googleapis.com/auth/cloud-platform'])
        :param proxy: Proxy flag
        :param kwargs: Potential arguments dict
        """
        service_account_json = safe_load_non_strict_json(service_account_json)
        try:
            credentials = service_account.Credentials.from_service_account_info(info=service_account_json,
                                                                                scopes=scopes)
            http_client = AuthorizedHttp(credentials=credentials, http=self.get_http_client_with_proxy(proxy))
            self.service = discovery.build(service_name, service_version, http=http_client,
                                           cache_discovery=False)
        except httplib2.ServerNotFoundError as e:
            raise ValueError(ERROR_MESSAGES["TIMEOUT_ERROR"].format(str(e)))
        except (httplib2.socks.HTTPError, IndexError) as e:
            # library not able to handle Proxy error and throws Index Error
            demisto.debug(f"Failed to execute {demisto.command()} command. Error: {str(e)} , "
                          f"traceback: {traceback.format_exc()}")
            raise ValueError(ERROR_MESSAGES["PROXY_ERROR"])
        except exceptions.RefreshError as error:
            error_message = ERROR_MESSAGES["INVALID_SERVICE_ACCOUNT"]
            if error.args:
                error_message += " Reason: {}".format(error.args[0])
            raise ValueError(error_message)

    @staticmethod
    def get_http_client_with_proxy(proxy: bool) -> httplib2.Http:
        """
        Create an http client with proxy with whom to use when using a proxy.
        :param proxy: Whether to use a proxy.

        :return: ProxyInfo object.
        """
        proxy_info = {}
        if proxy:
            proxies = handle_proxy()
            https_proxy = proxies.get("https")
            http_proxy = proxies.get("http")
            proxy_conf = https_proxy if https_proxy else http_proxy

            if proxy_conf:
                if not proxy_conf.startswith("https") and not proxy_conf.startswith("http"):
                    proxy_conf = "https://" + proxy_conf
                parsed_proxy = urllib.parse.urlparse(proxy_conf)
                proxy_info = httplib2.ProxyInfo(
                    proxy_type=httplib2.socks.PROXY_TYPE_HTTP,
                    proxy_host=parsed_proxy.hostname,
                    proxy_port=parsed_proxy.port,
                    proxy_user=parsed_proxy.username,
                    proxy_pass=parsed_proxy.password,
                )
        return httplib2.Http(proxy_info=proxy_info, timeout=TIMEOUT_TIME)

    @staticmethod
    def execute_request(request) -> Dict[str, Any]:
        """
        Execute the request and handle error scenario.

        :param request: request object
        :return: dictionary of json response
        """
        try:
            return request.execute()
        except HttpError as e:
            status = e.resp.status
            reason = e._get_reason()

            status_code_message_map = {
                400: ERROR_MESSAGES["BAD_REQUEST_ERROR"],
                401: ERROR_MESSAGES["AUTHENTICATION_ERROR"],
                403: ERROR_MESSAGES["AUTHORIZATION_ERROR"],
                404: ERROR_MESSAGES["NOT_FOUND_ERROR"],
                409: ERROR_MESSAGES["CONFLICT_ERROR"],
                429: ERROR_MESSAGES["TOO_MANY_REQUESTS_ERROR"],
                500: ERROR_MESSAGES["INTERNAL_SERVER_ERROR"],
            }

            if status in status_code_message_map:
                raise ValueError(status_code_message_map[status].format(reason))
            else:
                raise ValueError(ERROR_MESSAGES["UNKNOWN_ERROR"].format(status, reason))
        except httplib2.socks.HTTPError as e:
            demisto.debug(f"Failed to execute {demisto.command()} command. Error: {str(e)} , "
                          f"traceback: {traceback.format_exc()}")
            raise ValueError(ERROR_MESSAGES["PROXY_ERROR"])
        except httplib2.ServerNotFoundError as e:
            raise ValueError(ERROR_MESSAGES["TIMEOUT_ERROR"].format(str(e)))


class GoogleSccClient(BaseGoogleClient):
    """
    A Client class to wrap the google cloud security center api library as a service.
    """

    def __init__(self, organization_id: str, **kwargs):
        """Constructor for GoogleSccClient class."""
        super().__init__(**kwargs)
        self.organization_id = organization_id

    def get_findings(self, parent: str, compare_duration: Optional[str] = None, field_mask: Optional[str] = None,
                     filter_string: Optional[str] = None, order_by: Optional[str] = None,
                     page_size: Optional[Union[str, int]] = DEFAULT_PAGE_SIZE, page_token: Optional[str] = None,
                     read_time: Optional[str] = None) -> Dict[str, Any]:
        """
        Get an organization or source's findings.

        :param parent: Name of the source the findings belong to.
        :param compare_duration: A duration in seconds that is used to derived stateChange of finding.
        :param field_mask: A field mask to specify the Finding fields to be listed in the response.
        :param filter_string: Expression that defines the filter to apply across findings.
        :param order_by: Expression that defines what fields and order to use for sorting.
        :param page_size: The maximum number of results to return in a single response.
        :param page_token: The value returned by the last call; indicates that this is a continuation of a prior call.
        :param read_time: The Time used as a reference point when filtering findings.

        :return: list of findings
        """
        request = self.service.organizations().sources().findings().list(  # pylint: disable=E1101
            parent=parent, compareDuration=compare_duration, fieldMask=field_mask, filter=filter_string,
            orderBy=order_by, pageSize=page_size, pageToken=page_token, readTime=read_time)
        result = self.execute_request(request)
        return result

    def get_assets(self, parent: str, compare_duration: str, field_mask: str, filter_string: str, order_by: str,
                   page_size: Union[str, int], page_token: str, read_time: str) -> Dict[str, Any]:
        """
        Get an organization's assets.

        :param parent: Name of the organization assets should belong to.
        :param compare_duration: A duration in seconds that is used to derived stateChange of finding.
        :param field_mask: A field mask to specify the Finding fields to be listed in the response.
        :param filter_string: Expression that defines the filter to apply across findings.
        :param order_by: Expression that defines what fields and order to use for sorting.
        :param page_size: The maximum number of results to return in a single response.
        :param page_token: The value returned by the last call; indicates that this is a continuation of a prior call.
        :param read_time: The Time used as a reference point when filtering findings.
        :return: list of assets
        """
        request = self.service.organizations().assets().list(  # pylint: disable=E1101
            parent=parent, compareDuration=compare_duration, fieldMask=field_mask, filter=filter_string,
            orderBy=order_by, pageSize=page_size, pageToken=page_token, readTime=read_time)

        result = self.execute_request(request)
        return result

    def get_source(self, name: str) -> Dict[str, Any]:
        """
        Gets a source.

        :param name: A Relative resource name of the source.
        :return:
        """
        request = self.service.organizations().sources().get(name=name)  # pylint: disable=E1101
        result = self.execute_request(request)
        return result

    def update_finding(self, name: str, event_time: Optional[str], severity: Optional[str],
                       external_uri: Optional[str], source_properties: Optional[str],
                       update_mask: List) -> Dict[str, Any]:
        """
        Updates a finding. The corresponding source must exist for a finding update to succeed.

        :param name: The resource name of this finding.
        :param event_time: event time of finding
        :param severity: severity of finding
        :param external_uri: external_uri of finding
        :param source_properties: source_properties of finding
        :param update_mask: which field you want to update

        :return: updated finding response
        """
        body = assign_params(eventTime=event_time, severity=severity, externalUri=external_uri,
                             sourceProperties=source_properties)
        update_mask = get_update_mask_for_update_finding(body, update_mask)
        request = self.service.organizations().sources().findings().patch(  # pylint: disable=E1101
            name=name, updateMask=update_mask, body=body)
        result = self.execute_request(request)
        return result


class GooglePubSubClient(BaseGoogleClient):
    """
        A Client class to wrap the google cloud pub/sub api library as a service.
    """

    def __init__(self, project_id, subscription_id, service_account_json, **kwargs):
        """Constructor for GooglePubSubClient class."""
        super().__init__(service_account_json=service_account_json, **kwargs)
        self.project_id = project_id or extract_project_id_from_service_account(service_account_json)
        self.subscription_id = subscription_id

    def pull_messages(self, max_messages, ret_immediately=True) -> Dict[str, Any]:
        """
        Pull messages for the subscription

        :param max_messages: The maximum number of messages to return for this request. Must be a positive integer
        :param ret_immediately: when set to true will return immediately, otherwise will be async
        :return: Messages
        """
        subscription = GoogleNameParser.get_subscription_path(self.project_id, self.subscription_id)
        body = assign_params(returnImmediately=ret_immediately, maxMessages=max_messages)
        request = self.service.projects().subscriptions().pull(  # pylint: disable=E1101
            subscription=subscription, body=body)
        result = self.execute_request(request)
        return result

    def acknowledge_messages(self, acks_list: List) -> Dict[str, Any]:
        """
        Pull messages for the subscription

        :param acks_list: The maximum number of messages to return for this request. Must be a positive integer
        :return:
        """
        subscription = GoogleNameParser.get_subscription_path(self.project_id, self.subscription_id)
        body = assign_params(ackIds=acks_list)
        request = self.service.projects().subscriptions().acknowledge(  # pylint: disable=E1101
            subscription=subscription, body=body)
        result = self.execute_request(request)
        return result


""" HELPER FUNCTIONS """


def init_google_scc_client(**kwargs) -> GoogleSccClient:
    """
    Initializes google scc client
    :param kwargs: keyword arguments
    :return: SCC Client object
    """
    client = GoogleSccClient(service_name=SERVICE_NAME, service_version=SERVICE_VERSION, scopes=SCOPES, **kwargs)
    return client


def init_google_pubsub_client(**kwargs) -> GooglePubSubClient:
    """
    Initializes google scc client
    :param kwargs: keyword arguments
    :return: SCC Client object
    """
    client = GooglePubSubClient(service_name=PUBSUB_SERVICE_NAME, service_version=PUBSUB_SERVICE_VERSION,
                                scopes=SCOPES, **kwargs)
    return client


def safe_load_non_strict_json(json_string: str) -> Dict[str, Any]:
    """
    Loads the JSON with non-strict mode.

    :param json_string: json string to parse.

    :return: Parsed dictionary.
    :raises ValueError: If there is any other issues while parsing json.
    """
    try:
        if json_string:
            return json.loads(json_string, strict=False)
        return {}
    except ValueError:
        raise ValueError(ERROR_MESSAGES["JSON_PARSE_ERROR"].format("Service Account JSON"))


def validate_get_int(max_results: Optional[str], message: str, limit: Union[int, str] = 0) -> Optional[int]:
    """
    Validate and convert string max_results to integer.

    :param max_results: max results in string.
    :param message: Message to display when exception raised.
    :param limit: If max_results > limit raise the exception.

    :return: int max_results
    :raises ValueError: if max_results is not a integer and < 0.
    """
    if max_results:
        try:
            max_results_int = int(max_results)
            if max_results_int <= 0:
                raise ValueError(message)
            if limit and max_results_int > int(limit):
                raise ValueError(message)
            return max_results_int
        except ValueError:
            raise ValueError(message)
    return None


def validate_project_and_subscription_id(params: Dict[str, Any]) -> None:
    """
    Validates parameters for fetch-incidents command.

    :param params: parameters dictionary.

    :return: None
    """
    pubsub_client = init_google_pubsub_client(**params)
    pubsub_client.pull_messages(1)


def validate_service_account_and_organization_name(params: Dict[str, str]) -> None:
    """
    Validate Service Account JSON and Organization ID

    :param params: configuration parameter
    :return:
    """
    service_account_json = safe_load_non_strict_json(params.get("service_account_json", ""))

    if not isinstance(service_account_json, dict) or not service_account_json:
        raise ValueError(ERROR_MESSAGES["INVALID_SERVICE_ACCOUNT"])

    client = init_google_scc_client(**params)
    parent = GoogleNameParser.get_source_path("-")
    client.get_findings(parent, page_size=1)


def validate_state_and_severity_list(state_list: List, severity_list: List) -> None:
    """
    Validate severity and state list values

    :param state_list: state list
    :param severity_list: severity list

    :return:
    """
    for state in state_list:
        if state and state.strip().upper() not in STATE_LIST:
            raise ValueError(ERROR_MESSAGES["INVALID_STATE_ERROR"])

    # Validate Severity param
    for severity in severity_list:
        if severity and severity.strip().upper() not in SEVERITY_LIST:
            raise ValueError(ERROR_MESSAGES["INVALID_SEVERITY_ERROR"])


def validate_configuration_param(params: Dict[str, Any]) -> None:
    """
    validate configuration parameter through API call.

    :param params: parameter dictionary
    :return: None
    """
    # Validate parameter by hitting finding endpoint
    organization_id: str = params.get("organization_id", "")
    if not organization_id:
        raise ValueError(ERROR_MESSAGES["INVALID_ORGANIZATION_ID"])

    max_fetch = params.get("max_fetch") or DEFAULT_MAX_FETCH_VALUE
    validate_get_int(max_fetch, ERROR_MESSAGES["MAX_INCIDENT_ERROR"], MAX_FETCH_VALUE)
    service_account_json = params.get("service_account_json", "")
    project_id = params.get("project_id", "") or extract_project_id_from_service_account(service_account_json)
    subscription_id = params.get("subscription_id", "")
    is_fetch = params.get("isFetch", False)
    if is_fetch and not project_id:
        raise ValueError(ERROR_MESSAGES["REQUIRED_PROJECT_ID"])

    if is_fetch and not subscription_id:
        raise ValueError(ERROR_MESSAGES["REQUIRED_SUBSCRIPTION_ID"])


def create_filter_list_findings(category: str, filter_string: str, severity: list, state: list) -> str:
    """
    creating common filter query string for "list findings" API based on various filter parameter.

    :param category: category filter
    :param filter_string: filter string
    :param severity: severity filter
    :param state: state filter
    :return: filter query string
    """
    if severity:
        filter_string = add_filter("Severity", filter_string, severity)
    if state:
        filter_string = add_filter("State", filter_string, state)
    if category:
        category_list: list = category.split(",")
        filter_string = add_filter("Category", filter_string, category_list)

    return filter_string


def add_filter(label, filter_string, values) -> str:
    """
    adding filter in filter parameter string.

    :param label: label of the filter. i.e Severity, Category etc
    :param filter_string: filter param string
    :param values: list of values
    :return: filter params string
    """
    if filter_string:
        filter_string = filter_string + " AND "

    filter_string += "({})".format(" OR ".join(['{}="{}"'.format(label, value.strip()) for value in values]))
    return filter_string


def prepare_markdown_fields_for_fetch_incidents(fields: Dict[str, Any]) -> Dict[str, str]:
    """
    Prepares markdown fields for incident.

    :param fields: fields received in response of incident.
    :returns: None
    """
    security_marks = dict_safe_get(fields, ["finding", "securityMarks", "marks"], {})
    mfa_details = dict_safe_get(fields, ["finding", "sourceProperties", "MfaDetails"], {})
    security_marks_hr = tableToMarkdown("", security_marks)
    mfa_details_hr = tableToMarkdown("", mfa_details)
    return {"securityMarks": security_marks_hr, "MfaDetails": mfa_details_hr}


def strip_dict(args: Dict[str, str]) -> Dict[str, str]:
    """
    Remove leading and trailing white spaces from dictionary values and remove empty entries.
    :param args: Arguments dict.
    :return: Dictionary with whitespaces and empty entries removed.
    """
    return {key: value.strip() for (key, value) in args.items() if value and value.strip()}


def create_filter_list_assets(asset_type: str, project: str, filter_string: str, active_assets_only: str) -> str:
    """
    creating common filter query string for "list findings" API based on various filter parameter.
    :param asset_type: type filter
    :param filter_string: filter dict
    :param project: project filter
    :param  active_assets_only: lifeCycleState filter
    :return: filter query string
    """
    if filter_string is None:
        filter_string = ""
    if project:
        project_list: list = project.split(",")
        filter_string = add_filter("resourceProperties.name", filter_string, project_list)
    if asset_type:
        type_list: list = asset_type.split(",")
        filter_string = add_filter("securityCenterProperties.resourceType", filter_string, type_list)
    if active_assets_only.lower() == "true":
        filter_string = add_filter('resourceProperties.lifecycleState', filter_string, ['ACTIVE'])
    return filter_string


def prepare_human_readable_dict_for_list_asset(asset: Dict[str, Any]) -> Dict[str, Any]:
    """
    Prepare human-readable dictionary for list asset command.
    :param asset: asset information
    :return: human-readable dict
    """
    asset_url = GoogleNameParser.get_asset_url(asset.get("name", ""))

    return {
        COMMON_STRING["RESOURCE_NAME"]: asset.get("securityCenterProperties", {}).get("resourceName", ""),
        "Resource Type": asset.get("securityCenterProperties", {}).get("resourceType", ""),
        "Resource Owners": asset.get("securityCenterProperties", {}).get("resourceOwners", {}),
        "Project": asset.get("resourceProperties", {}).get("name", ""),
        "Name": get_markdown_link(asset.get("name", ""), asset_url),
        COMMON_STRING["SECURITY_MARKS"]: asset.get("securityMarks", {}).get("marks", {})
    }


def prepare_outputs_for_list_assets(result) -> Tuple[Dict[str, Any], str]:
    """
    Preparing context output and human-readable for list-assets command.

    :param result: result dictionary
    :return:
    """
    hr_asset_list = []
    ec_asset_list = []

    list_assets = result.get("listAssetsResults", [])
    if len(list_assets) <= 0:
        return {}, ERROR_MESSAGES["NO_RECORDS_FOUND"].format("asset")

    read_time = result.get("readTime", "")
    total_size = result.get("totalSize")

    for asset in list_assets:
        flatten_keys_to_root(asset, ["asset"], {"readTime": read_time, "stateChange": asset.get("stateChange", None)})
        ec_asset_list.append(asset)
        hr_asset_dict = prepare_human_readable_dict_for_list_asset(asset)
        hr_asset_list.append(hr_asset_dict)

    # Preparing headers
    headers = ["Name", "Project", COMMON_STRING["RESOURCE_NAME"], "Resource Type", "Resource Owners",
               COMMON_STRING["SECURITY_MARKS"]]
    readable_output = tableToMarkdown(GET_OUTPUT_MESSAGE["HEADER_MESSAGE"].format("asset(s)", total_size),
                                      t=hr_asset_list, headers=headers, removeNull=True)

    # preparing context
    ec_asset_dict: Dict[str, Any] = {
        OUTPUT_PREFIX["LIST_ASSET"]: ec_asset_list
    }

    next_page_token = result.get("nextPageToken", "")
    if next_page_token:
        token_ec = {"name": "google-cloud-scc-asset-list", "nextPageToken": next_page_token}
        ec_asset_dict.update({OUTPUT_PREFIX["TOKEN"]: token_ec})

    return remove_empty_elements(ec_asset_dict), readable_output


def flatten_keys_to_root(data_dict: Dict[str, Any], keys: List, update_dict: Dict[str, Any]):
    """
    Add list of keys to root level in dict

    :param data_dict: dictionary
    :param keys: list of keys
    :param update_dict: dictionary that will be add in data dict
    :return: flatten dict for provided keys
    """
    for key in keys:
        value = data_dict.pop(key, None)
        if value and isinstance(value, dict):
            data_dict.update(value)
        else:
            data_dict[key] = value
    data_dict.update(update_dict)


def convert_string_to_date_format(date: str, date_format: str = DATE_FORMAT) -> Optional[str]:
    """
    Convert date into given format

    :param date: date string
    :param date_format: output date format
    :return: human readable date
    """
    date_obj = dateparser.parse(date)

    if date_obj:
        return date_obj.strftime(date_format)
    return None


def prepare_hr_and_ec_for_list_findings(result: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    """
    Prepare human readable output

    :param result: List findings API response
    :return: markdown string and context data  of list findings
    """
    # Preparing list of entry context and human readable
    hr_finding_list = []
    ec_finding_list = []

    findings = result.get("listFindingsResults", [])
    if not len(findings):
        return ERROR_MESSAGES["NO_RECORDS_FOUND"].format("finding"), {}

    read_time = result.get("readTime", "")
    total_size = result.get("totalSize")

    for finding in findings:
        flatten_keys_to_root(finding, ["finding"],
                             {"readTime": read_time, "stateChange": finding.get("stateChange", None)})
        ec_finding_list.append(finding)
        finding_url = GoogleNameParser.get_finding_url(finding.get("name", ""))
        hr_finding_list.append({
            "Name": get_markdown_link(finding.get("name", ""), finding_url),
            "Category": finding.get("category", ""),
            COMMON_STRING["RESOURCE_NAME"]: finding.get("resourceName", ""),
            COMMON_STRING["EVENT_TIME"]: convert_string_to_date_format(finding.get("eventTime", "")),
            COMMON_STRING["CREATE_TIME"]: convert_string_to_date_format(finding.get("createTime", "")),
            COMMON_STRING["SECURITY_MARKS"]: finding.get("securityMarks", {}).get("marks", {})
        })

    headers = ["Name", "Category", COMMON_STRING["RESOURCE_NAME"], COMMON_STRING["EVENT_TIME"],
               COMMON_STRING["CREATE_TIME"], COMMON_STRING["SECURITY_MARKS"]]
    readable_output = tableToMarkdown(GET_OUTPUT_MESSAGE["HEADER_MESSAGE"].format("finding(s)", total_size),
                                      t=hr_finding_list, headers=headers, removeNull=True)

    # preparing context
    ec_dict: Dict[str, Any] = {
        OUTPUT_PREFIX["LIST_FINDING"]: ec_finding_list
    }
    next_page_token = result.get("nextPageToken", "")
    if next_page_token:
        token_ec = {"name": "google-cloud-scc-finding-list", "nextPageToken": next_page_token}
        ec_dict[OUTPUT_PREFIX["TOKEN"]] = token_ec

    return readable_output, remove_empty_elements(ec_dict)


def get_and_validate_args_finding_update(args: Dict[str, Any]) -> Tuple:
    """
    Get and validate arguments of finding update command.

    :param args: arguments of finding update command.
    :return: name, event_time, severity, external_uri, source_properties, update_mask
    """
    # Get command args
    name = args.get("name", None)
    event_time = args.get("eventTime") or datetime.now().strftime(ISO_DATE_FORMAT)
    severity = args.get("severity", "").upper()
    external_uri = args.get("externalUri", None)
    source_properties = args.get("sourceProperties", None)
    update_mask = [value for value in args.get("updateMask", "").split(",") if value.strip()]

    if severity and severity.strip().upper() not in SEVERITY_LIST:
        raise ValueError(ERROR_MESSAGES["INVALID_SEVERITY_ERROR"])

    try:
        if source_properties:
            source_properties = dict(split_and_escape(line, "=")  # type: ignore
                                     for line in split_and_escape(source_properties, ","))
    except ValueError:
        raise ValueError(ERROR_MESSAGES["INVALID_SOURCE_PROPERTIES"])

    return name, event_time, severity, external_uri, source_properties, update_mask


def prepare_hr_and_ec_for_update_finding(result: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    """
    Prepare human readable output

    :param result: List findings API response
    :return: markdown string and context data  of list findings
    """
    # Preparing list of entry context and human readable
    finding_url = GoogleNameParser.get_finding_url(result.get("name", ""))

    hr_data = {
        "Name": get_markdown_link(result.get("name", ""), finding_url),
        "State": result.get("state", ""),
        "Severity": result.get("severity", ""),
        "Category": result.get("category", ""),
        COMMON_STRING["EVENT_TIME"]: convert_string_to_date_format(result.get("eventTime", "")),
        COMMON_STRING["CREATE_TIME"]: convert_string_to_date_format(result.get("createTime", "")),
        "External Uri": get_markdown_link(result.get("externalUri", ""), result.get("externalUri", "")),
        COMMON_STRING["RESOURCE_NAME"]: result.get("resourceName", "")
    }

    headers = ["Name", "State", "Severity", "Category", COMMON_STRING["EVENT_TIME"], COMMON_STRING["CREATE_TIME"],
               "External Uri", COMMON_STRING["RESOURCE_NAME"]]
    readable_output = tableToMarkdown("The finding has been updated successfully.", t=hr_data, headers=headers,
                                      removeNull=True)

    return readable_output, remove_empty_elements(result)


def get_update_mask_for_update_finding(body: Dict[str, Any], update_mask: List) -> str:
    """
    Get updateMask for finding update API call.

    :param body: json body
    :param update_mask: list which contains which field should update
    :return: updateMask
    """
    for key, value in body.items():
        if key == "sourceProperties" and key not in update_mask:
            update_mask.extend(["sourceProperties." + inner_key for inner_key in value.keys()])
            continue
        if key not in update_mask:
            update_mask.append(key)
    return ",".join(update_mask)


def split_and_escape(key: str, delimiter) -> List[str]:
    """
    Split key by delimiter with escape support.

    :param key: string which will be split
    :param delimiter: delimiter
    :return: a list of the extract keys
    """
    regex = r"(?<!\\)" + re.escape(delimiter)
    split_keys = map(lambda x: x.replace(r"\{}".format(delimiter), delimiter), re.split(regex, key))
    keys = [split_key.strip() for split_key in list(split_keys)]
    return keys


def get_markdown_link(name: str, link: str) -> Optional[str]:
    """
    Prepare markdown supported link.

    :param name: display name of link
    :param link: link address
    :return: link in markdown format
    """
    if name and link:
        return MARKDOWN_LINK.format(name, link)
    return None


def extract_project_id_from_service_account(service_account_json: str) -> str:
    """
    Extracts project name from a client secret json

    :param service_account_json: service account json string
    :return:
    """
    service_account_json = safe_load_non_strict_json(service_account_json)
    project_id = ""
    if isinstance(service_account_json, dict):
        project_id = service_account_json.get("project_id")  # type: ignore
    if isinstance(project_id, list):
        project_id = project_id[0]
    return project_id


def get_finding_id_from_path(finding_path: str) -> str:
    """
    Get finding ID from finding path

    :param finding_path: fully qualified path of finding
    :return: finding id
    """
    id_list = finding_path.split("findings/", 1)[-1:]
    if id_list:
        return id_list[0]
    return ""


def convert_messages_to_incidents(messages: Dict[str, Any]) -> Tuple[List, List]:
    """
    convert pub/sub messages to incidents

    :param messages: pub/sdub message
    :return: list of incidents and list of ack ids
    """
    incidents = []
    acknowledges = []

    data_list = messages.get("receivedMessages", [])

    for data in data_list:
        acknowledges.append(data.get("ackId"))
        encoded_data = data.get("message", {}).get("data", "")
        try:
            data = base64.b64decode(encoded_data).decode()
            json_data = json.loads(data)

            finding = json_data.get("finding", {})
            finding_name = finding.get("name", "")
            # Support for only finding ingestion for Google Cloud SCC
            if not finding_name:
                continue
            incident_name = get_finding_id_from_path(finding_name)
            create_time = finding.get("createTime")

            json_data["custom"] = prepare_markdown_fields_for_fetch_incidents(json_data)
            json_data["finding_url"] = GoogleNameParser.get_finding_url(finding_name)

            incidents.append({
                "name": "{} - {}".format(INCIDENT_NAME_PREFIX, incident_name),
                "occurred": create_time,
                "rawJSON": json.dumps(json_data),
                "details": json.dumps(json_data)
            })
        except Exception as e:
            demisto.error(ERROR_MESSAGES["INVALID_INCIDENT"].format(str(e)))

    acknowledges = [ack_id for ack_id in acknowledges if ack_id]
    return incidents, acknowledges


""" COMMANDS """


def test_module(params: Dict[str, Any]) -> None:
    """
    Test authentication using service json
    """
    # Basic validation on configuration parameter
    validate_configuration_param(params)

    # Validate Service Account JSON and Organization ID
    validate_service_account_and_organization_name(params)
    if params.get('isFetch', False):
        # Validate Project ID and Subscription ID.
        validate_project_and_subscription_id(params)
    demisto.results("ok")


def fetch_incidents(client: GooglePubSubClient, params: Dict[str, Any]) -> Optional[list]:
    """
    Prepares incidents from past activity in Google Drive.

    :param client: GooglePubSubClient object
    :param params: arguments for fetch-incident.

    :return: incidents (``List[dict]``): List of incidents that will be created in XSOAR.
    """
    validate_configuration_param(params)
    max_messages = params.get("max_fetch") or DEFAULT_MAX_FETCH_VALUE

    messages = client.pull_messages(max_messages=max_messages)
    incidents, acks_id = convert_messages_to_incidents(messages)
    if acks_id:
        client.acknowledge_messages(acks_id)
    return incidents


@logger
def asset_list_command(client: GoogleSccClient, args: Dict) -> CommandResults:
    """
    Lists an organization's assets.
    :param client: SccClient Object.
    :param args: Command argument(s).
    :return: CommandResults object with context and human-readable.
    """
    # To validate arguments.
    page_size = validate_get_int(args.get("pageSize"), ERROR_MESSAGES["INVALID_PAGE_SIZE_ERROR"],
                                 MAX_PAGE_SIZE) or DEFAULT_PAGE_SIZE

    resource_type = args.get("resourceType", "")
    project = args.get("project", "")
    field_mask = args.get("fieldMask", None)
    order_by = args.get("orderBy", None)
    active_assets_only = args.get("activeAssetsOnly", "false")
    filter_string = args.get("filter", "")
    read_time = args.get("readTime", None)
    compare_duration = args.get("compareDuration", None)
    page_token = args.get("pageToken", None)

    # Creating filter
    filter_string = create_filter_list_assets(resource_type, project, filter_string, active_assets_only)
    demisto.debug(f"running command using the following filter: {filter_string}")

    # Build a request
    parent = GoogleNameParser.get_organization_path()
    raw_response = client.get_assets(parent, compare_duration, field_mask, filter_string, order_by, page_size,
                                     page_token, read_time)
    result = deepcopy(raw_response)  # To preserve original API response

    # Preparing list of entry context and human readable
    ec_asset_dict, readable_output = prepare_outputs_for_list_assets(result)

    return CommandResults(readable_output=readable_output, outputs=ec_asset_dict, raw_response=raw_response)


@logger
def finding_list_command(client: GoogleSccClient, args: Dict) -> CommandResults:
    """
    Lists an organization or source's findings.

    :param client: SccClient Object.
    :param args: Command argument(s).
    :return: CommandResults object with context and human-readable.
    """

    # Get command args
    severity = [value for value in args.get("severity", "").split(",") if value.strip()]
    category = args.get("category", "")
    source_type = args.get("sourceTypeId", "-")
    page_size = args.get("pageSize")
    state = [value for value in args.get("state", "").split(",") if value.strip()]
    filter_string = args.get("filter", "")
    order_by = args.get("orderBy", None)
    compare_duration = args.get("compareDuration", None)
    field_mask = args.get("fieldMask", None)
    read_time = args.get("readTime", None)
    page_token = args.get("pageToken", None)

    # Validates command args
    validate_state_and_severity_list(state, severity)
    page_size = validate_get_int(page_size, ERROR_MESSAGES["INVALID_PAGE_SIZE_ERROR"],
                                 MAX_PAGE_SIZE) or DEFAULT_PAGE_SIZE

    # Creating filter
    filter_string = create_filter_list_findings(category, filter_string, severity, state)
    demisto.debug(f"running command using the following filter: {filter_string}")

    parent = GoogleNameParser.get_source_path(source_type)
    raw_response = client.get_findings(parent, compare_duration, field_mask, filter_string, order_by, page_size,
                                       page_token, read_time)
    result = deepcopy(raw_response)  # To preserve original API response
    readable_output, context = prepare_hr_and_ec_for_list_findings(result)

    return CommandResults(readable_output=readable_output, outputs=context, raw_response=raw_response)


@logger
def finding_update_command(client: GoogleSccClient, args: Dict) -> CommandResults:
    """
    Lists an organization or source's findings.

    :param client: SccClient Object.
    :param args: Command argument(s).
    :return: CommandResults object with context and human-readable.
    """

    # Get validated command args
    arguments = get_and_validate_args_finding_update(args)

    # Get response
    result = client.update_finding(*arguments)

    readable_output, context = prepare_hr_and_ec_for_update_finding(result)

    return CommandResults(readable_output=readable_output, outputs_key_field="name",
                          outputs_prefix=OUTPUT_PREFIX['FINDING'], outputs=context, raw_response=result)


def main() -> None:
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    # Commands dictionary
    commands: Dict[str, Callable] = {
        "google-cloud-scc-asset-list": asset_list_command,
        "google-cloud-scc-finding-list": finding_list_command,
        "google-cloud-scc-finding-update": finding_update_command
    }
    params = demisto.params()
    command = demisto.command()
    demisto.info(f"Command being called is {command}")
    try:
        # Trim the arguments
        args = strip_dict(demisto.args())
        client: Optional[Union[GoogleSccClient, GooglePubSubClient]] = None

        if command == "test-module":
            # This is the call made when pressing the integration test button.
            test_module(params)
        elif command == "fetch-incidents":
            client = init_google_pubsub_client(**params)
            incidents = fetch_incidents(client, params)
            demisto.incidents(incidents)
        elif command in commands:
            client = init_google_scc_client(**params)
            return_results(commands[command](client, args))
    # Log exceptions
    except Exception as e:
        return_error("Failed to execute {} command. Error: {}".format(demisto.command(), str(e)))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
