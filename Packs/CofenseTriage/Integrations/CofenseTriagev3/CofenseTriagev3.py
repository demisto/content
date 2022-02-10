import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
import time
import requests
import traceback
from typing import Any, Callable, Dict, Tuple

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'  # ISO8601 format with UTC, default in XSOAR
DEFAULT_MAX_FETCH = "15"
DEFAULT_FIRST_FETCH = "3 days"

URL_SUFFIX = {
    "SYSTEM_STATUS": "/api/public/v2/system/status",
    "AUTH": "oauth/token",
    "REPORTS": "api/public/v2/reports",
    "REPORTS_BY_CATEGORY": "api/public/v2/categories/{}/reports",
    "REPORTS_BY_CLUSTER": "api/public/v2/clusters/{}/reports",
    "THREAT_INDICATORS": "/api/public/v2/threat_indicators",
    "REPORT_DOWNLOAD": "api/public/v2/reports/{}/download",
    "REPORT_IMAGE_DOWNLOAD": "api/public/v2/reports/{}/download.{}",
    "REPORT_CATEGORIZE": "/api/public/v2/reports/{}/categorize",
    "CATEGORY": "api/public/v2/categories/",
    "URLS": "api/public/v2/urls",
    "RULE": "api/public/v2/rules",
    "REPORTERS": "api/public/v2/reporters",
    "INTEGRATION_SUBMISSION": "/api/public/v2/{}/{}/integration_submissions",
    "ATTACHMENT_PAYLOAD": "api/public/v2/attachment_payloads",
    "COMMENTS": "api/public/v2/comments/",
    "REPORT_ID": "api/public/v2/reports/{}",
    "CLUSTER": "api/public/v2/clusters"
}

OUTPUT_PREFIX = {
    "REPORT": "Cofense.Report",
    "THREAT_INDICATOR": "Cofense.ThreatIndicator",
    "CATEGORY": "Cofense.Category",
    "URL": "Cofense.Url",
    "RULE": "Cofense.Rule",
    "REPORTER": "Cofense.Reporter",
    "ATTACHMENT_PAYLOAD": "Cofense.AttachmentPayload",
    "INTEGRATION_SUBMISSION": "Cofense.IntegrationSubmission",
    "COMMENT": "Cofense.Comment",
    "CLUSTER": "Cofense.Cluster"
}

MESSAGES = {
    'NO_RECORDS_FOUND': "No {} were found for the given argument(s).",
    "API_TOKEN": "No API token found. Please try again.",
    "PAGE_SIZE": "{} is an invalid value for page size. Page size must be between 1 and 200.",
    "PAGE_NUMBER": "{} is an invalid value for page number. Page number must be greater than 0",
    "FILTER": 'Please provide the filter in the valid JSON format. Format accepted- \' '
              '{"attribute1_operator" : "value1, value2" , "attribute2_operator" : "value3, value4"} \'',
    "REQUIRED_ARGUMENT": "Invalid argument value. {} is a required argument.",
    "INVALID_MAX_FETCH": "{} is an invalid value for maximum fetch. Maximum fetch must be between 1 and 200.",
    "INVALID_FIRST_FETCH": "Argument 'First fetch time interval' should be a valid date or relative timestamp such as "
                           "'2 days', '2 months', 'yyyy-mm-dd', 'yyyy-mm-ddTHH:MM:SSZ'",
    "INVALID_LOCATION_FOR_CATEGORY_ID": "If Category ID is provided in fetch incident parameters, the Report Location "
                                        "cannot be 'Inbox' or 'Reconnaissance'.",
    "INVALID_LOCATION_FOR_CATEGORIZATION_TAGS": "If Categorization Tags are provided in fetch incident parameters, "
                                                "the Report Location cannot be 'Inbox' or 'Reconnaissance'.",
    "INVALID_LOCATION_FOR_TAGS": "If Tags are provided in fetch incident parameters, the Report Location "
                                 "must be 'Reconnaissance'.",
    "BODY_FORMAT": "Invalid value for body format. Body format must be text or json.",
    "INTEGRATION_SUBMISSION_TYPE": "Invalid value for integration submission type. Type must be urls or "
                                   "attachment_payloads.",
    "INVALID_IMAGE_TYPE": "Invalid value for type. Type must be png or jpg."
}

TYPE_HEADER = 'application/vnd.api+json'
CREATED_AT = "Created At"
UPDATED_AT = "Updated At"
TOKEN_EXPIRY_TIMEOUT = 60 * 60 * 2
BODY_FORMAT = ["text", "json"]
INTEGRATION_SUBMISSION_TYPE = ["urls", "attachment_payloads"]
DEFAULT_THREAT_SOURCE = "XSOAR-UI"
DEFAULT_REPORT_IMAGE_TYPE = "png"
VALID_IMAGE_TYPE = ["png", "jpg"]
MIRROR_DIRECTION = {
    'None': None,
    'Incoming': 'In'
}

HTTP_ERRORS = {
    400: "Bad request: an error occurred while fetching the data.",
    401: "Authentication error: please provide valid Client ID and Client Secret.",
    403: "Forbidden: please provide valid Client ID and Client Secret.",
    404: "Resource not found: invalid endpoint was called.",
    500: "The server encountered an internal error for Cofense Triage v3 and was unable to complete your request."
}

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API
    """

    def __init__(self, base_url: str, verify: bool, proxy: bool, client_id, client_secret):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        self.client_id = client_id,
        self.client_secret = client_secret

    def http_request(self, url_suffix, method="GET", resp_type="json", headers=None, json_data=None,
                     params=None) -> Any:
        """
        Function to make http requests using inbuilt _http_request() method.
        Handles token expiration case and makes request using refreshed token.
        :param json_data: The data to send in a 'POST' request.
        :param resp_type:Determines which data format to return from the HTTP request. The default
                is 'json'
        :param headers: headers to send with request
        :param method: http method to use
        :param url_suffix: the API endpoint
        :param params: parameters to send with request
        :return: response from the request
        """
        token = self.get_api_token()
        if not token:
            response = self._http_request(
                method='POST',
                url_suffix=URL_SUFFIX["AUTH"],
                params={
                    'client_id': self.client_id,
                    'client_secret': self.client_secret,
                    'grant_type': 'client_credentials'
                },
                headers={'Content-Type': 'application/json'},
                error_handler=self.exception_handler
            )
            token = self.set_integration_context(response)

        if not headers:
            headers = {
                'Accept': TYPE_HEADER
            }
        headers['Authorization'] = token
        response = self._http_request(method=method, url_suffix=url_suffix, params=params, json_data=json_data,
                                      headers=headers, resp_type=resp_type,
                                      error_handler=self.exception_handler)

        return response

    @staticmethod
    def exception_handler(response: requests.models.Response):
        """
        Handle error in the response and display error message based on status code.

        :type response: ``requests.models.Response``
        :param response: response from API.

        :raises: raise DemistoException based on status code abd response.
        """

        err_msg = ""
        if response.status_code in HTTP_ERRORS:
            err_msg = HTTP_ERRORS[response.status_code]

        if response.status_code not in HTTP_ERRORS or response.status_code in [400, 404]:
            if response.status_code not in [400, 404]:
                err_msg = response.reason

            try:
                # Try to parse json error response
                error_entry = response.json().get("errors")

                if error_entry:
                    err_details = ','.join([entry.get('detail') for entry in error_entry if entry.get('detail')])
                    if err_details:
                        err_msg = f"{err_msg}\nDetails: {err_details}"
            except (ValueError, AttributeError):
                if response.text:
                    err_msg = f"{err_msg}\nDetails: {response.text}"

        raise DemistoException(err_msg)

    @staticmethod
    def set_integration_context(resp) -> Any:
        """
        set API token and expiry time in integration configuration context.
        Will raise value error if api-token is not found.

        :param resp: resp from API.
        :return: integration context
        """

        integration_context = {}
        api_token = resp.get('access_token')
        if api_token:
            integration_context['api_token'] = "Bearer " + api_token
            integration_context['valid_until'] = int(time.time() + resp.get("expires_in", TOKEN_EXPIRY_TIMEOUT))
        else:
            raise ValueError(MESSAGES["API_TOKEN"])
        set_integration_context(integration_context)
        return integration_context.get('api_token')

    @staticmethod
    def get_api_token() -> Any:
        """
        Retrieve API token from integration context.
        if API token is not found or expired it will return false
        """
        integration_context = get_integration_context()
        api_token = integration_context.get('api_token')
        valid_until = integration_context.get('valid_until')

        # Return API token from integration context, if found and not expired
        if api_token and valid_until and time.time() < valid_until:
            demisto.debug('[CofenseTriagev3] Retrieved api-token from integration cache.')
            return api_token
        return False


'''HELPER FUNCTIONS '''


def retrieve_fields(arg: str) -> str:
    """Strip and filter out the empty elements from the string.

    :type arg: ``str``
    :param arg: The string from which we want to filter out the empty elements.

    :return: Filtered out result.
    :rtype: ``str``

     """
    return ",".join([x.strip() for x in arg.split(",") if x.strip()])


def validate_filter_by_argument(args: Dict[str, Any], custom_args: List[str]) -> Dict[str, Any]:
    """
    Validate filters in arguments for all list commands, raise ValueError on invalid arguments.

    :type args: ``Dict[str, Any]``
    :param args: The command arguments provided by the user.

    :type custom_args: ``List[str]``
    :param custom_args: The custom command arguments provided by the user.

    :return: Parameters related to the filters.
    :rtype: ``Dict[str, Any]``
    """
    params = {}
    if args.get("filter_by"):
        try:
            filters = json.loads(args["filter_by"])
            for key, value in filters.items():
                key, value = key.strip(), value.strip()
                if not key or not value:
                    continue
                if all([False if key.startswith(arg) else True for arg in custom_args]):
                    params[f"filter[{key}]"] = value

        except (json.JSONDecodeError, json.decoder.JSONDecodeError, AttributeError):
            raise ValueError(MESSAGES["FILTER"])

    remove_nulls_from_dictionary(params)
    return params


def validate_list_command_args(args: Dict[str, str], field_type: str) -> tuple:
    """
    Validate arguments for all list commands, raise ValueError on invalid arguments.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :type field_type: ``str``
    :param field_type: The type of the field to be set in parameter for sending the request.

    :return: Parameters to send in request
    :rtype: ``Tuple[Any]``
    """

    params: Dict[str, Any] = {}
    custom_args = []
    page_size = arg_to_number(args.get("page_size"))
    if page_size is not None:
        if page_size <= 0 or page_size > 200:
            raise ValueError(MESSAGES['PAGE_SIZE'].format(page_size))
        params["page[size]"] = page_size

    page_number = arg_to_number(args.get("page_number"))
    if page_number is not None:
        if page_number <= 0:
            raise ValueError(MESSAGES['PAGE_NUMBER'].format(page_number))
        params["page[number]"] = page_number

    if args.get("sort_by"):
        params["sort"] = retrieve_fields(args["sort_by"])

    if args.get("fields_to_retrieve"):
        params[f"fields[{field_type}]"] = retrieve_fields(args["fields_to_retrieve"])

    if args.get("created_at"):
        created_at = arg_to_datetime(args["created_at"])
        params["filter[created_at_gteq]"] = created_at
        custom_args.append("created_at")

    if args.get("updated_at"):
        updated_at = arg_to_datetime(args["updated_at"])
        params["filter[updated_at_gteq]"] = updated_at
        custom_args.append("updated_at")

    return params, custom_args


def validate_fetch_incidents_parameters(params: dict) -> dict:
    """
    Validate fetch incidents params, throw ValueError on non-compliant  arguments

    :param params: dictionary of parameters to be tested for fetch_incidents

    :rtype: ``dict``
    return: dictionary containing valid parameters
    """
    fetch_params: Dict[str, Any] = {}
    custom_args = []

    max_fetch = arg_to_number(params.get("max_fetch", DEFAULT_MAX_FETCH))
    if (max_fetch is None) or (not 0 < max_fetch <= 200):
        raise ValueError(MESSAGES["INVALID_MAX_FETCH"].format(max_fetch))
    fetch_params["page[size]"] = max_fetch

    first_fetch = params.get("first_fetch")
    first_fetch_time = arg_to_datetime(first_fetch)
    if first_fetch_time is None:
        raise ValueError(MESSAGES["INVALID_FIRST_FETCH"])
    fetch_params["filter[created_at_gteq]"] = first_fetch_time.strftime(DATE_FORMAT)

    locations = params.get('mailbox_location', [])
    if locations:
        mailbox_location = retrieve_fields(','.join(locations))
        custom_args.append("location")
        fetch_params["filter[location]"] = mailbox_location

    priorities = params.get("match_priority", [])
    if priorities:
        match_priority = retrieve_fields(','.join(priorities))
        for priority in match_priority.split(","):
            arg_to_number(priority)
        custom_args.append("match_priority")
        fetch_params["filter[match_priority]"] = match_priority

    if params.get('tags'):
        tags = retrieve_fields(params.get("tags", ""))
        custom_args.append("tags")
        fetch_params["filter[tags_any]"] = tags

    if params.get('categorization_tags'):
        categorization_tags = retrieve_fields(params.get("categorization_tags", ""))
        custom_args.append("categorization_tags")
        fetch_params["filter[categorization_tags_any]"] = categorization_tags

    fetch_params.update(validate_filter_by_argument(params, custom_args))

    remove_nulls_from_dictionary(fetch_params)
    return fetch_params


def validate_list_threat_indicator_args(args: Dict[str, str]) -> Dict[str, Any]:
    """
    Validate arguments for cofense-threat-indicator-list command, raise ValueError on invalid arguments.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Parameters to send in request
    :rtype: ``Dict[str, Any]``
    """
    params, custom_args = validate_list_command_args(args, "threat_indicators")

    threat_levels = retrieve_fields(args.get("threat_level", ""))
    if threat_levels:
        custom_args.append("threat_level")
        params["filter[threat_level]"] = threat_levels

    threat_types = retrieve_fields(args.get("threat_type", ""))
    if args.get("threat_type"):
        custom_args.append("threat_type")
        params["filter[threat_type]"] = threat_types

    threat_values = retrieve_fields(args.get("threat_value", ""))
    if threat_values:
        custom_args.append("threat_value")
        params["filter[threat_value]"] = threat_values

    threat_sources = retrieve_fields(args.get("threat_source", ""))
    if threat_sources:
        custom_args.append("threat_source")
        params["filter[threat_source]"] = threat_sources

    params.update(validate_filter_by_argument(args, custom_args))

    remove_nulls_from_dictionary(params)

    return params


def prepare_hr_for_threat_indicators(results: List[Dict[str, Any]]) -> str:
    """
    Parse and convert the threat indicators in response into human-readable markdown string.

    :type results: ``List[Dict[str, Any]]``
    :param results: Details of threat indicators.

    :return: Human Readable string containing threat indicators.
    :rtype: ``str``
    """
    threat_indicators_hr = []
    for res in results:
        attributes = res.get("attributes")
        hr = {"Threat Indicator ID": res.get("id", "")}

        if attributes:
            hr["Threat Level"] = attributes.get("threat_level", "")
            hr["Threat Type"] = attributes.get("threat_type", "")
            hr["Threat Value"] = attributes.get("threat_value", "")
            hr["Threat Source"] = attributes.get("threat_source", "")
            hr[CREATED_AT] = attributes.get("created_at", "")
            hr[UPDATED_AT] = attributes.get("updated_at", "")
        threat_indicators_hr.append(hr)

    return tableToMarkdown("Threat Indicator(s)", threat_indicators_hr,
                           headers=["Threat Indicator ID", "Threat Level", "Threat Type", "Threat Value",
                                    "Threat Source", CREATED_AT, UPDATED_AT], removeNull=True)


def prepare_hr_for_reports(reports: List[Dict[str, Any]]) -> str:
    """
    Prepare human readable for list reports command.
    :param reports:The report data.
    :return: Human readable.
    """
    hr_list = []
    for report in reports:
        hr_record = {
            'Report ID': report.get('id', ''),
        }
        attributes = report.get('attributes')
        if attributes:
            hr_record['From Address'] = attributes.get('from_address', '')
            hr_record['Subject'] = attributes.get('subject', '')
            hr_record['Match Priority'] = attributes.get('match_priority', '')
            hr_record['Location'] = attributes.get('location', '')
            hr_record['MD5'] = attributes.get('md5', '')
            hr_record['SHA256'] = attributes.get('sha256', '')
            hr_record[CREATED_AT] = attributes.get('created_at', '')

        hr_list.append(hr_record)

    return tableToMarkdown('Report(s)', hr_list, ['Report ID', 'From Address', 'Subject', 'Match Priority', 'Location',
                                                  'MD5', 'SHA256', CREATED_AT], removeNull=True)


def prepare_hr_for_categories(categories: List[Dict[str, Any]]) -> str:
    """
    Prepare human readable for list Categories command.
    :param categories:The category data.
    :return: Human readable.
    """
    hr_list = []
    for category in categories:
        hr_record = {
            'Category ID': category.get('id', ''),
        }
        attributes = category.get('attributes')
        if attributes:
            hr_record['Name'] = attributes.get('name', '')
            hr_record['Malicious'] = attributes.get('malicious', '')
            hr_record['Archived'] = attributes.get('archived', '')
            hr_record[CREATED_AT] = attributes.get('created_at', '')
            hr_record[UPDATED_AT] = attributes.get('updated_at', '')

        hr_list.append(hr_record)

    return tableToMarkdown('Categories', hr_list, ['Category ID', 'Name', 'Malicious', 'Archived', CREATED_AT,
                                                   UPDATED_AT], removeNull=True)


def prepare_hr_for_clusters(clusters: List[Dict[str, Any]]) -> str:
    """
    Prepare human readable for list clusters command.
    :param clusters:The cluster data.
    :return: Human readable.
    """
    hr_list = []
    for cluster in clusters:
        hr_record = {
            'Cluster ID': cluster.get('id', ''),
        }
        attributes = cluster.get('attributes')
        if attributes:
            hr_record['Unprocessed Report'] = attributes.get('unprocessed_reports_count', '')
            hr_record['Total Report Count'] = attributes.get('total_reports_count', '')
            hr_record['Match Priority'] = attributes.get('match_priority', '')
            hr_record['Tags'] = attributes.get('tags', '')
            hr_record['Host Source'] = attributes.get('host_source', '')
            hr_record['Average Reporter Reputation Score'] = attributes.get('average_reporter_reputation', '')
            hr_record['VIP Reporter count'] = attributes.get('vip_reporters_count', '')
            hr_record[CREATED_AT] = attributes.get('created_at', '')
            hr_record[UPDATED_AT] = attributes.get('updated_at', '')

        hr_list.append(hr_record)

    return tableToMarkdown('Cluster(s)', hr_list, ['Cluster ID', 'Unprocessed Report', 'Total Report Count',
                                                   'Match Priority', 'Tags', 'Host Source',
                                                   'Average Reporter Reputation Score', 'VIP Reporter count',
                                                   CREATED_AT, UPDATED_AT], removeNull=True)


def prepare_hr_for_rules(rules: List[Dict[str, Any]]) -> str:
    """
    Prepare human readable for list rules command.
    :param rules:The rule data.
    :return: Human readable.
    """
    hr_list = []
    for rule in rules:
        hr_record = {
            'Rule ID': rule.get('id', ''),
        }
        attributes = rule.get('attributes')
        if attributes:
            hr_record['Rule Name'] = attributes.get('name', '')
            hr_record['Description'] = attributes.get('description', '')
            hr_record['Active'] = attributes.get('active', '')
            hr_record['Priority'] = attributes.get('priority', '')
            hr_record['Scope'] = attributes.get('scope', '')
            hr_record['Author Name'] = attributes.get('author_name', '')
            hr_record['Rule Context'] = attributes.get('rule_context', '')
            hr_record['Created At'] = attributes.get('created_at', '')
            hr_record['Updated At'] = attributes.get('updated_at', '')

        hr_list.append(hr_record)

    return tableToMarkdown('Rule(s)', hr_list, ['Rule ID', 'Rule Name', 'Description', 'Active', 'Priority', 'Scope',
                                                'Author Name', 'Rule Context', 'Created At', 'Updated At'],
                           removeNull=True)


def validate_tags_argument(args: Dict[str, str]) -> Dict:
    """
    Validate tags argument.
    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Parameters to send in request
    :rtype: ``Dict[str, str]``
    """
    params = {}
    tags = retrieve_fields(args.get("tags", ""))
    if tags:
        params["filter[tags_any]"] = tags

    return params


def validate_match_priority_argument(args: Dict[str, str]) -> Dict:
    """
    Validate match_priority argument.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Parameters to send in request
    :rtype: ``Dict[str, str]``
    """
    params = {}
    match_priority = retrieve_fields(args.get("match_priority", ""))
    if match_priority:
        for priority in match_priority.split(","):
            arg_to_number(priority)
        params["filter[match_priority]"] = match_priority
    return params


def validate_list_report_args(args: Dict[str, str]) -> Dict[str, Any]:
    """
    Validate arguments for cofense-report-list command, raise ValueError on invalid arguments.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Parameters to send in request
    :rtype: ``Dict[str, str]``
    """

    params, custom_args = validate_list_command_args(args, "reports")

    tags = validate_tags_argument(args)
    if tags:
        params.update(tags)
        custom_args.append("tags")

    match_priority = validate_match_priority_argument(args)
    if match_priority:
        params.update(match_priority)
        custom_args.append("match_priority")

    categorization_tags = retrieve_fields(args.get("categorization_tags", ""))
    if categorization_tags:
        custom_args.append("categorization_tags")
        params["filter[categorization_tags_any]"] = categorization_tags

    mailbox_location = retrieve_fields(args.get("report_location", ""))
    if mailbox_location:
        custom_args.append("location")
        params["filter[location]"] = mailbox_location

    params.update(validate_filter_by_argument(args, custom_args))

    remove_nulls_from_dictionary(params)

    return params


def validate_list_category_args(args: Dict[str, str]) -> Dict[str, Any]:
    """
    Validate arguments for cofense-category-list command, raise ValueError on invalid arguments.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Parameters to send in request
    :rtype: ``Dict[str, str]``
    """
    params, custom_args = validate_list_command_args(args, "categories")

    is_malicious = args.get("is_malicious", "")
    if is_malicious:
        is_malicious = "true" if argToBoolean(is_malicious) else "false"
        custom_args.append("malicious")
        params["filter[malicious]"] = is_malicious

    names = retrieve_fields(args.get("name", ""))
    if names:
        custom_args.append("name")
        params["filter[name]"] = names

    scores = retrieve_fields(args.get("score", ""))
    if scores:
        for score in scores.split(","):
            arg_to_number(score)
        custom_args.append("score")
        params["filter[score]"] = scores

    params.update(validate_filter_by_argument(args, custom_args))

    remove_nulls_from_dictionary(params)

    return params


def validate_list_cluster_args(args: Dict[str, str]) -> Dict[str, Any]:
    """
    Validate arguments for cofense-cluster-list command, raise ValueError on invalid arguments.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Parameters to send in request
    :rtype: ``Dict[str, str]``
    """
    params, custom_args = validate_list_command_args(args, "clusters")

    match_priority = validate_match_priority_argument(args)
    if match_priority:
        params.update(match_priority)
        custom_args.append("match_priority")

    tags = validate_tags_argument(args)
    if tags:
        params.update(tags)
        custom_args.append("tags")

    total_reports_count = retrieve_fields(args.get("total_reports_count", ""))
    if total_reports_count:
        for report_count in total_reports_count.split(","):
            arg_to_number(report_count)
        custom_args.append("total_reports_count")
        params["filter[total_reports_count]"] = total_reports_count

    params.update(validate_filter_by_argument(args, custom_args))

    remove_nulls_from_dictionary(params)

    return params


def validate_list_url_args(args: Dict[str, str]) -> Dict[str, Any]:
    """
    Validate arguments for cofense-url-list command, raise ValueError on invalid arguments.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Parameters to send in request
    :rtype: ``Dict[str, Any]``
    """
    params, custom_args = validate_list_command_args(args, "urls")

    risk_score = retrieve_fields(args.get("risk_score", ""))
    if risk_score:
        for score in risk_score.split(","):
            arg_to_number(score)
        custom_args.append("risk_score")
        params["filter[risk_score]"] = risk_score

    params.update(validate_filter_by_argument(args, custom_args))

    remove_nulls_from_dictionary(params)

    return params


def prepare_hr_for_urls(results: List[Dict[str, Any]]) -> str:
    """
    Parse and convert the urls in the response into human-readable markdown string.

    :type results: ``List[Dict[str, Any]]``
    :param results: Details of urls.

    :return: Human Readable string containing information of urls.
    :rtype: ``str``
    """
    urls_hr = []
    for res in results:
        attributes = res.get("attributes")
        hr = {"URL ID": res.get("id", "")}

        if attributes:
            hr["URL"] = attributes.get("url", "")
            hr["Risk Score"] = attributes.get("risk_score", "")
            hr[CREATED_AT] = attributes.get("created_at", "")
            hr[UPDATED_AT] = attributes.get("updated_at", "")
        urls_hr.append(hr)

    return tableToMarkdown("URL(s)", urls_hr,
                           headers=["URL ID", "URL", "Risk Score", CREATED_AT, UPDATED_AT], removeNull=True)


def validate_list_rule_args(args: Dict[str, str]) -> Dict[str, Any]:
    """
    Validate arguments for cofense-rule-list command, raise ValueError on invalid arguments.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Parameters to send in request
    :rtype: ``Dict[str, str]``
    """
    params, custom_args = validate_list_command_args(args, "rules")

    names = retrieve_fields(args.get("name", ""))
    if names:
        custom_args.append("name")
        params["filter[name]"] = names

    priority = retrieve_fields(args.get("priority", ""))
    if priority:
        for score in priority.split(","):
            arg_to_number(score)
        custom_args.append("priority")
        params["filter[priority]"] = priority

    tags = validate_tags_argument(args)
    if tags:
        params.update(tags)
        custom_args.append("tags")

    scope = retrieve_fields(args.get("scope", ""))
    if scope:
        custom_args.append("scope")
        params["filter[scope]"] = scope

    active = args.get("active", "")
    if active:
        active = "true" if argToBoolean(active) else "false"
        custom_args.append("active")
        params["filter[active]"] = active

    author_name = retrieve_fields(args.get("author_name", ""))
    if author_name:
        custom_args.append("author_name")
        params["filter[author_name]"] = author_name

    rule_context = retrieve_fields(args.get("rule_context", ""))
    if rule_context:
        custom_args.append("rule_context")
        params["filter[rule_context]"] = rule_context

    params.update(validate_filter_by_argument(args, custom_args))

    remove_nulls_from_dictionary(params)

    return params


def validate_create_threat_indicator_args(args: Dict[str, str]) -> Dict[str, Any]:
    """
    Validate arguments for cofense-threat-indicator-create command, raise ValueError on invalid arguments.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Parameters to send in request
    :rtype: ``Dict[str, str]``
    """
    params = dict()
    if not args.get("threat_level"):
        raise ValueError(MESSAGES["REQUIRED_ARGUMENT"].format("threat_level"))
    params["threat_level"] = args["threat_level"]

    if not args.get("threat_type"):
        raise ValueError(MESSAGES["REQUIRED_ARGUMENT"].format("threat_type"))
    params["threat_type"] = args["threat_type"]

    if not args.get("threat_value", ""):
        raise ValueError(MESSAGES["REQUIRED_ARGUMENT"].format("threat_value"))
    params["threat_value"] = args["threat_value"]

    if not args.get("threat_source"):
        params["threat_source"] = DEFAULT_THREAT_SOURCE
    else:
        params["threat_source"] = args["threat_source"]

    return params


def validate_list_reporter_args(args: Dict[str, str]) -> Dict[str, Any]:
    """
    Validate arguments for cofense-reporter-list command, raise ValueError on invalid arguments.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Parameters to send in request
    :rtype: ``Dict[str, Any]``
    """

    params, custom_args = validate_list_command_args(args, "reporters")

    reputation_score = retrieve_fields(args.get("reputation_score", ""))
    if reputation_score:
        for score in reputation_score.split(","):
            arg_to_number(score)
        custom_args.append("reputation_score")
        params["filter[reputation_score]"] = reputation_score

    vip = args.get("vip", "")
    if vip:
        vip = "true" if argToBoolean(vip) else "false"
        custom_args.append("vip")
        params["filter[vip]"] = vip

    emails = retrieve_fields(args.get("email", ""))
    if emails:
        custom_args.append("email")
        params["filter[email]"] = emails

    params.update(validate_filter_by_argument(args, custom_args))

    remove_nulls_from_dictionary(params)

    return params


def prepare_hr_for_reporters(results: List[Dict[str, Any]]) -> str:
    """
    Parse and convert the reporters in the response into human-readable markdown string.

    :type results: ``List[Dict[str, Any]]``
    :param results: Details of reporters.

    :return: Human Readable string containing information of reporters.
    :rtype: ``str``
    """
    reporters_hr = []
    for res in results:
        attributes = res.get("attributes")
        hr = {"Reporter ID": res.get("id", "")}

        if attributes:
            hr["Reporter Email"] = attributes.get("email", "")
            hr["Reports Count"] = attributes.get("reports_count", "")
            hr["Reputation Score"] = attributes.get("reputation_score", "")
            hr["VIP"] = attributes.get("vip", "")
            hr["Last Reported At"] = attributes.get("last_reported_at", "")
            hr[CREATED_AT] = attributes.get("created_at", "")
            hr[UPDATED_AT] = attributes.get("updated_at", "")
        reporters_hr.append(hr)

    return tableToMarkdown("Reporter(s)", reporters_hr,
                           headers=["Reporter ID", "Reporter Email", "Reports Count", "Reputation Score", "VIP",
                                    "Last Reported At", CREATED_AT, UPDATED_AT], removeNull=True)


def validate_categorize_report_args(args: Dict[str, str]) -> Dict[str, Any]:
    """
    Validate arguments for cofense-report-categorize command, raise ValueError on invalid arguments.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :raises: ValueError if the required arguments are missing
    """

    if not args.get("id"):
        raise ValueError(MESSAGES["REQUIRED_ARGUMENT"].format("id"))
    arg_to_number(args.get("id"))

    if not args.get("category_id"):
        raise ValueError(MESSAGES["REQUIRED_ARGUMENT"].format("category_id"))
    arg_to_number(args.get("category_id"))

    params: Dict[str, Any] = {"category_id": args["category_id"]}

    categorization_tags = retrieve_fields(args.get("categorization_tags", ""))
    if categorization_tags:
        params["categorization_tags"] = categorization_tags.split(",")  # type: ignore

    return params


def validate_list_attachment_payload_args(args: Dict[str, str]) -> Dict[str, Any]:
    """
    Validate arguments for cofense-attachment-payload-list command, raise ValueError on invalid arguments.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Parameters to send in request
    :rtype: ``Dict[str, Any]``
    """
    params, custom_args = validate_list_command_args(args, "attachment_payloads")

    risk_score = retrieve_fields(args.get("risk_score", ""))
    if risk_score:
        for score in risk_score.split(","):
            arg_to_number(score)
        custom_args.append("risk_score")
        params["filter[risk_score]"] = risk_score

    params.update(validate_filter_by_argument(args, custom_args))

    remove_nulls_from_dictionary(params)

    return params


def prepare_hr_for_attachment_payloads(results: List[Dict[str, Any]]) -> str:
    """
    Parse and convert the attachment payloads in the response into human-readable markdown string.

    :type results: ``List[Dict[str, Any]]``
    :param results: Details of urls.

    :return: Human Readable string containing information of attachment payloads.
    :rtype: ``str``
    """
    payloads_hr = []
    for res in results:
        attributes = res.get("attributes")
        hr = {"Attachment Payload ID": res.get("id", "")}

        if attributes:
            hr["Mime Type"] = attributes.get("mime_type", "")
            hr["MD5"] = attributes.get("md5", "")
            hr["SHA256"] = attributes.get("sha256", "")
            hr["Risk Score"] = attributes.get("risk_score", "")
            hr[CREATED_AT] = attributes.get("created_at", "")
            hr[UPDATED_AT] = attributes.get("updated_at", "")
        payloads_hr.append(hr)

    return tableToMarkdown("Attachment Payload(s)", payloads_hr,
                           headers=["Attachment Payload ID", "Mime Type", "MD5", "SHA256", "Risk Score", CREATED_AT,
                                    UPDATED_AT], removeNull=True)


def validate_comment_list_args(args: Dict[str, str]) -> Dict[str, Any]:
    """
    Validate arguments for cofense-comment-list command, raise ValueError on invalid arguments.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Parameters to send in request
    :rtype: ``Dict[str, str]``
    """
    params, custom_args = validate_list_command_args(args, "comments")

    body_format = retrieve_fields(args.get("body_format", ""))
    if body_format:
        if body_format.lower() not in BODY_FORMAT:
            raise ValueError(MESSAGES["BODY_FORMAT"])
        custom_args.append("body_format")
        params["filter[body_format]"] = body_format

    tags = validate_tags_argument(args)
    if tags:
        params.update(tags)
        custom_args.append("tags")

    params.update(validate_filter_by_argument(args, custom_args))

    remove_nulls_from_dictionary(params)

    return params


def prepare_hr_for_comments(comments: List[Dict[str, Any]]) -> str:
    """
    Parse and convert the comments in the response into human-readable markdown string.

    :type comments: ``List[Dict[str, Any]]``
    :param comments: Details of urls.

    :return: Human Readable string containing information of comments.
    :rtype: ``str``
    """

    hr = []
    for comment in comments:
        data = {
            'Comment ID': comment.get('id', ''),
        }
        attributes = comment.get('attributes')
        if attributes:
            data['Body Format'] = attributes.get('body_format', '')
            if data['Body Format'] == "json":
                data['Body'] = attributes.get('body', {}).get('properties', {}).get('summary', {}).get('type', '')
            else:
                data['Body'] = attributes.get('body', '')
            data['Tags'] = attributes.get('tags', [])
            data['Created At'] = attributes.get('created_at', '')
            data['Updated At'] = attributes.get('updated_at', '')

        relationships = comment.get("relationships")
        if relationships:
            data['Associated To'] = relationships.get('commentable', {}).get('data', {}).get('type', '')
            data['Associated To ID'] = relationships.get('commentable', {}).get('data', {}).get('id', '')
        hr.append(data)

    return tableToMarkdown('Comment(s)', hr, ['Comment ID', 'Body Format', 'Body', 'Tags', 'Created At', 'Updated At',
                                              'Associated To', 'Associated To ID'], removeNull=True)


def validate_get_integration_submission_args(args: Dict[str, str]) -> Dict[str, Any]:
    """
    Validate arguments for cofense-integration-submission-get command, raise ValueError on invalid arguments.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Parameters to send in request
    :rtype: ``Dict[str, Any]``
    """

    params, custom_args = validate_list_command_args(args, "integration_submissions")

    status = retrieve_fields(args.get("status", ""))
    if status:
        custom_args.append("status")
        params["filter[status]"] = status

    kind = retrieve_fields(args.get("kind", ""))
    if kind:
        custom_args.append("kind")
        params["filter[kind]"] = kind

    risk_score = retrieve_fields(args.get("risk_score", ""))
    if risk_score:
        for score in risk_score.split(","):
            arg_to_number(score)
        custom_args.append("risk_score")
        params["filter[risk_score]"] = risk_score

    params.update(validate_filter_by_argument(args, custom_args))

    remove_nulls_from_dictionary(params)

    return params


def prepare_hr_for_integration_submission(results: List[Dict[str, Any]]) -> str:
    """
    Parse and convert integration submission in response into human-readable markdown string.

    :type results: ``List[Dict[str, Any]]``
    :param results: Details of threat indicators.

    :return: Human Readable string containing threat indicators.
    :rtype: ``str``
    """
    integration_submission_hr = []
    for res in results:
        attributes = res.get("attributes")
        hr = {"Integration Submission ID": res.get("id", "")}

        if attributes:
            hr["Status"] = attributes.get("status", "")
            hr["Kind"] = attributes.get("kind", "")
            hr["Risk Score"] = attributes.get("risk_score", "")
            hr[CREATED_AT] = attributes.get("created_at", "")
            hr[UPDATED_AT] = attributes.get("updated_at", "")
        integration_submission_hr.append(hr)

    return tableToMarkdown("Integration Submission(s)", integration_submission_hr,
                           headers=["Integration Submission ID", "Status", "Kind", "Risk Score",
                                    CREATED_AT, UPDATED_AT], removeNull=True)


def check_fetch_incident_configuration(fetch_params, params):
    """ Raises an exception if any setting related to fetch incident is configured incorrectly."""
    location = fetch_params.get('filter[location]', "")
    if not location:
        return

    for key, value in fetch_params.items():
        if key.startswith("filter[tags") and (
                "Inbox" not in location and "Reconnaissance" not in location):
            raise ValueError(MESSAGES["INVALID_LOCATION_FOR_TAGS"])

        if key.startswith("filter[categorization_tags") and "Processed" not in location:
            raise ValueError(MESSAGES["INVALID_LOCATION_FOR_CATEGORIZATION_TAGS"])

    if params.get('category_id') and 'Processed' not in location:
        raise ValueError(MESSAGES["INVALID_LOCATION_FOR_CATEGORY_ID"])


def validate_update_threat_indicator_args(args: Dict[str, str]) -> Dict[str, Any]:
    """
    Validate arguments for cofense-threat-indicator-update command, raise ValueError on invalid arguments.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Parameters to send in request
    :rtype: ``Dict[str, str]``
    """
    params = dict()

    if not args.get("id", ""):
        raise ValueError(MESSAGES["REQUIRED_ARGUMENT"].format("id"))

    if not args.get("threat_level"):
        raise ValueError(MESSAGES["REQUIRED_ARGUMENT"].format("threat_level"))
    params["threat_level"] = args["threat_level"]

    if args.get("threat_source"):
        params["threat_source"] = args["threat_source"]

    return params


''' COMMAND FUNCTIONS '''


def test_module(client: Client, params: dict) -> str:
    """Tests API connectivity and authentication

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    client.http_request(URL_SUFFIX["SYSTEM_STATUS"])
    is_fetch = params.get("isFetch")
    if is_fetch:
        fetch_incidents(client, {}, params)
    return 'ok'


def cofense_threat_indicator_list_command(client: Client, args: Dict[str, str]) -> CommandResults:
    """
    Retrieves the list of threat indicators based on the filter values provided in the command arguments.

    :type client: ``Client``
    :param client: Client object to be used.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Standard command result or no records found message.
    :rtype: ``CommandResults``
    """

    params = validate_list_threat_indicator_args(args)
    url_suffix = URL_SUFFIX["THREAT_INDICATORS"]

    # Appending the id to the url_suffix if id exists
    threat_indicator_id = args.get("id")
    if threat_indicator_id:
        url_suffix = f"{url_suffix}/{threat_indicator_id}"

    # Sending http request
    response = client.http_request(url_suffix, params=params)

    result = response.get("data")

    # Returning if data is empty or not present
    if not result:
        return CommandResults(readable_output=MESSAGES["NO_RECORDS_FOUND"].format("threat indicators"))

    if isinstance(result, dict):
        result = [result]

    # Creating the Human Readable
    hr_response = prepare_hr_for_threat_indicators(result)

    # Creating the Context data
    context_data = remove_empty_elements(result)

    return CommandResults(outputs_prefix=OUTPUT_PREFIX["THREAT_INDICATOR"],
                          outputs_key_field="id",
                          outputs=context_data,
                          readable_output=hr_response,
                          raw_response=response
                          )


def cofense_report_list_command(client, args: Dict[str, str]) -> CommandResults:
    """
    List reports from Cofense Triage.

    :type client: ``Client``
    :param client: Client object to be used.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Standard command result or no records found message.
    :rtype: ``CommandResults``
    """

    report_id = args.get('id')
    category_id = args.get('category_id')
    cluster_id = args.get('cluster_id')

    url_suffix = URL_SUFFIX['REPORTS']
    if report_id:
        url_suffix = f"{URL_SUFFIX['REPORTS']}/{report_id}"
    elif category_id:
        url_suffix = URL_SUFFIX['REPORTS_BY_CATEGORY'].format(category_id)
    elif cluster_id:
        url_suffix = URL_SUFFIX['REPORTS_BY_CLUSTER'].format(cluster_id)

    params = validate_list_report_args(args)

    response = client.http_request(url_suffix, params=params)

    total_records = response.get('data', [])

    if not total_records:
        return CommandResults(readable_output=MESSAGES['NO_RECORDS_FOUND'].format('report(s)'))

    if isinstance(total_records, dict):
        total_records = [total_records]

    # Creating entry context
    context = remove_empty_elements(total_records)

    # Creating human-readable
    readable_hr = prepare_hr_for_reports(total_records)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["REPORT"],
        outputs_key_field='id',
        outputs=context,
        readable_output=readable_hr,
        raw_response=response
    )


def cofense_report_download_command(client: Client, args: Dict[str, str]) -> dict:
    """
    Downloads the raw email for a specific report.

    :type client: ``Client``
    :param client: Client object to be used.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: File Result
    :rtype: ``dict``
    """

    report_id = args.get("id")
    if not report_id:
        raise ValueError(MESSAGES["REQUIRED_ARGUMENT"].format("id"))
    # Appending the id to the url_suffix
    url_suffix = URL_SUFFIX["REPORT_DOWNLOAD"].format(report_id)
    headers = {
        'Accept': "text/plain"
    }
    # Sending http request
    raw_response = client.http_request(url_suffix, resp_type="content", headers=headers)
    filename = f"Report ID - {report_id}.eml"
    return fileResult(filename, data=raw_response, file_type=entryTypes["file"])

def cofense_report_image_download_command(client: Client, args: Dict[str, str]) -> dict:
    """
    Downloads the image for a specific report.

    :type client: ``Client``
    :param client: Client object to be used.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: File Result
    :rtype: ``dict``
    """

    report_id = args.get("id")
    if not report_id:
        raise ValueError(MESSAGES["REQUIRED_ARGUMENT"].format("id"))

    image_type = args.get("type", DEFAULT_REPORT_IMAGE_TYPE).lower()
    if not image_type:
        image_type = DEFAULT_REPORT_IMAGE_TYPE

    if image_type not in VALID_IMAGE_TYPE:
        raise ValueError(MESSAGES["INVALID_IMAGE_TYPE"])

    # Appending the id and type to the url_suffix
    url_suffix = URL_SUFFIX["REPORT_IMAGE_DOWNLOAD"].format(report_id, image_type)
    headers = {
        "Accept": f"image/{image_type if image_type == DEFAULT_REPORT_IMAGE_TYPE else 'jpeg'}"
    }
    # Sending http request
    raw_response = client.http_request(url_suffix, resp_type="content", headers=headers)

    filename = f"Report ID - {report_id}.{image_type}"
    return fileResult(filename, data=raw_response, file_type=entryTypes["image"])


def fetch_incidents(client: Client, last_run: dict, params: Dict) -> Tuple[dict, list]:
    """Fetches incidents from Cofense API.

    :type client: ``Client``
    :param client: client to use

    :type last_run: ``Dict[str, str]``
    :param last_run: last run returned by function demisto.getLastRun

    :type params: ``Dict[str, str]``
    :param params: arguments for fetch-incident.

    :rtype: ``Tuple``
    :return: tuple of dictionary of next run and list of fetched incidents
    """
    fetch_params = validate_fetch_incidents_parameters(params)

    check_fetch_incident_configuration(fetch_params, params)

    if last_run.get('id'):
        fetch_params["filter[id_gt]"] = last_run.get('id')
        del fetch_params["filter[created_at_gteq]"]

    category_id = params.get('category_id')
    if category_id:
        url_suffix = URL_SUFFIX["REPORTS_BY_CATEGORY"].format(category_id)
    else:
        url_suffix = URL_SUFFIX["REPORTS"]

    response = client.http_request(url_suffix, params=fetch_params)

    results = response.get('data', [])

    next_run = last_run
    incidents = []
    for result in results:
        result['mirror_direction'] = MIRROR_DIRECTION.get(params.get('mirror_direction', 'None'))
        result['mirror_instance'] = demisto.integrationInstance()
        incidents.append({
            'name': result.get('attributes').get('subject', ''),
            'occurred': result.get('attributes').get('created_at'),
            'rawJSON': json.dumps(result)
        })

    if results:
        next_run['id'] = results[-1].get('id')

    return next_run, incidents


def cofense_report_categorize_command(client: Client, args: Dict[str, str]) -> CommandResults:
    """Categorizes a report into a specific category provided by the user.

    :type client: ``Client``
    :param client: Client object to be used.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Standard command result.
    :rtype: ``CommandResults``
    """

    params = validate_categorize_report_args(args)
    url_suffix = URL_SUFFIX["REPORT_CATEGORIZE"].format(args["id"])

    client.http_request(url_suffix, method="POST",
                        headers={
                            'Content-Type': TYPE_HEADER
                        }, json_data={"data": params}, resp_type="response")

    return CommandResults(readable_output=f"Report with ID = {args['id']} is categorized successfully.")


def cofense_category_list_command(client, args: Dict[str, str]) -> CommandResults:
    """
    List categories from Cofense Triage.

    :param client:Client object.
    :param args: Command argument.
    :return: Command Result.
    """

    category_id = args.get('id')
    url_suffix = f"{URL_SUFFIX['CATEGORY']}/{category_id}" if category_id else URL_SUFFIX['CATEGORY']

    params = validate_list_category_args(args)

    response = client.http_request(url_suffix, params=params)

    total_records = response.get('data', [])

    if not total_records:
        return CommandResults(readable_output=MESSAGES['NO_RECORDS_FOUND'].format('categories'))

    if isinstance(total_records, dict):
        total_records = [total_records]

    # Creating entry context
    context = remove_empty_elements(total_records)

    # Creating human-readable
    readable_hr = prepare_hr_for_categories(total_records)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["CATEGORY"],
        outputs_key_field='id',
        outputs=context,
        readable_output=readable_hr,
        raw_response=response
    )


def cofense_rule_list_command(client, args: Dict[str, str]) -> CommandResults:
    """
    List rules from Cofense Triage.

    :param client:Client object.
    :param args: Command argument.
    :return: Command Result.
    """

    rule_id = args.get('id')
    url_suffix = f"{URL_SUFFIX['RULE']}/{rule_id}" if rule_id else URL_SUFFIX['RULE']

    params = validate_list_rule_args(args)

    response = client.http_request(url_suffix, params=params)

    total_records = response.get('data', [])

    if not total_records:
        return CommandResults(readable_output=MESSAGES['NO_RECORDS_FOUND'].format('rule(s)'))

    if isinstance(total_records, dict):
        total_records = [total_records]

    # Creating entry context
    context = remove_empty_elements(total_records)

    # Creating human-readable
    readable_hr = prepare_hr_for_rules(total_records)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["RULE"],
        outputs_key_field='id',
        outputs=context,
        readable_output=readable_hr,
        raw_response=response
    )


def cofense_url_list_command(client: Client, args: Dict[str, str]) -> CommandResults:
    """
    Retrieves URLs based on the filter values provided in the command arguments.
    URLs are the threats (or non-threat)  that are detected in the Reported emails.

    :type client: ``Client``
    :param client: Client object to be used.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Standard command result.
    :rtype: ``CommandResults``
    """

    params = validate_list_url_args(args)
    url_suffix = URL_SUFFIX["URLS"]

    # Appending the id to the url_suffix if id exists
    url_id = args.get("id")
    if url_id:
        url_suffix = f"{url_suffix}/{url_id}"

    # Sending http request
    response = client.http_request(url_suffix, params=params)

    result = response.get("data")

    # Returning if data is empty or not present
    if not result:
        return CommandResults(readable_output=MESSAGES["NO_RECORDS_FOUND"].format("URLs"))

    if isinstance(result, dict):
        result = [result]

    # Creating the Human Readable
    hr_response = prepare_hr_for_urls(result)

    # Creating the Context data
    context_data = remove_empty_elements(result)

    return CommandResults(outputs_prefix=OUTPUT_PREFIX["URL"],
                          outputs_key_field="id",
                          outputs=context_data,
                          readable_output=hr_response,
                          raw_response=response
                          )


def cofense_threat_indicator_create_command(client: Client, args: Dict[str, str]) -> CommandResults:
    """
    Creates a threat indicator based on the values provided in the command arguments.

    :type client: ``Client``
    :param client: Client object to be used.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Standard command result or no records found message.
    :rtype: ``CommandResults``
    """

    params = validate_create_threat_indicator_args(args)

    # Sending http request
    response = client.http_request(URL_SUFFIX["THREAT_INDICATORS"], method="POST",
                                   headers={'Content-Type': TYPE_HEADER},
                                   json_data={"data": {
                                       "type": "threat_indicators",
                                       "attributes": params
                                   }})

    result = response.get("data")
    if isinstance(result, dict):
        result = [result]

    # Creating the Human Readable
    hr_response = prepare_hr_for_threat_indicators(result)

    # Creating the Context data
    context_data = remove_empty_elements(result)

    return CommandResults(outputs_prefix=OUTPUT_PREFIX["THREAT_INDICATOR"],
                          outputs_key_field="id",
                          outputs=context_data,
                          readable_output=hr_response,
                          raw_response=response
                          )


def cofense_integration_submission_get_command(client: Client, args: Dict[str, str]) -> CommandResults:
    """
        Retrieves integration submission based on the filter values provided in the command arguments.

        :type client: ``Client``
        :param client: Client object to be used.

        :type args: ``Dict[str, str]``
        :param args: The command arguments provided by the user.

        :return: Standard command result or no records found message.
        :rtype: ``CommandResults``
        """
    integration_submission_id = args.get("id")
    if not integration_submission_id:
        raise ValueError(MESSAGES["REQUIRED_ARGUMENT"].format("integration_submission_id"))

    integration_submission_type = args.get("type", "urls")
    if not integration_submission_type:
        integration_submission_type = "urls"
    if integration_submission_type not in INTEGRATION_SUBMISSION_TYPE:
        raise ValueError(MESSAGES["INTEGRATION_SUBMISSION_TYPE"])
    params = validate_get_integration_submission_args(args)
    url_suffix = URL_SUFFIX["INTEGRATION_SUBMISSION"].format(integration_submission_type, integration_submission_id)

    # Sending http request
    response = client.http_request(url_suffix, params=params)

    result = response.get("data")

    # Returning if data is empty or not present
    if not result:
        return CommandResults(readable_output=MESSAGES["NO_RECORDS_FOUND"].format("integration submissions"))

    if isinstance(result, dict):
        result = [result]

    # Creating the Human Readable
    hr_response = prepare_hr_for_integration_submission(result)

    # Creating the Context data
    context_data = remove_empty_elements(result)

    return CommandResults(outputs_prefix=OUTPUT_PREFIX["INTEGRATION_SUBMISSION"],
                          outputs_key_field="id",
                          outputs=context_data,
                          readable_output=hr_response,
                          raw_response=response
                          )


def cofense_reporter_list_command(client: Client, args: Dict[str, str]) -> CommandResults:
    """
    Retrieves the reporters that match the provided parameters.
    Reporters are employees of an organization who send, or report, suspicious emails to Cofense Triage.

    :type client: ``Client``
    :param client: Client object to be used.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Standard command result.
    :rtype: ``CommandResults``
    """

    params = validate_list_reporter_args(args)
    url_suffix = URL_SUFFIX["REPORTERS"]

    # Appending the id to the url_suffix if id exists
    reporter_id = args.get("id")
    if reporter_id:
        url_suffix = f"{url_suffix}/{reporter_id}"

    # Sending http request
    response = client.http_request(url_suffix, params=params)

    result = response.get("data")

    # Returning if data is empty or not present
    if not result:
        return CommandResults(readable_output=MESSAGES["NO_RECORDS_FOUND"].format("reporters"))

    if isinstance(result, dict):
        result = [result]

    # Creating the Human Readable
    hr_response = prepare_hr_for_reporters(result)

    # Creating the Context data
    context_data = remove_empty_elements(result)

    return CommandResults(outputs_prefix=OUTPUT_PREFIX["REPORTER"],
                          outputs_key_field="id",
                          outputs=context_data,
                          readable_output=hr_response,
                          raw_response=response
                          )


def cofense_attachment_payload_list_command(client: Client, args: Dict[str, str]) -> CommandResults:
    """
    Retrieves attachment payloads based on the filter values provided in the command arguments.
    Attachment payloads identify the MIME type and MD5 and SHA256 hash signatures of a reported email.

    :type client: ``Client``
    :param client: Client object to be used.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Standard command result.
    :rtype: ``CommandResults``
    """

    params = validate_list_attachment_payload_args(args)
    url_suffix = URL_SUFFIX["ATTACHMENT_PAYLOAD"]

    # Appending the id to the url_suffix if id exists
    payload_id = args.get("id")
    if payload_id:
        url_suffix = f"{url_suffix}/{payload_id}"

    # Sending http request
    response = client.http_request(url_suffix, params=params)

    result = response.get("data")

    # Returning if data is empty or not present
    if not result:
        return CommandResults(readable_output=MESSAGES["NO_RECORDS_FOUND"].format("attachment payloads"))

    if isinstance(result, dict):
        result = [result]

    # Creating the Human Readable
    hr_response = prepare_hr_for_attachment_payloads(result)

    # Creating the Context data
    context_data = remove_empty_elements(result)

    return CommandResults(outputs_prefix=OUTPUT_PREFIX["ATTACHMENT_PAYLOAD"],
                          outputs_key_field="id",
                          outputs=context_data,
                          readable_output=hr_response,
                          raw_response=response
                          )


def cofense_comment_list_command(client: Client, args: Dict[str, str]) -> CommandResults:
    """
    Retrieves comments based on the filter values provided in the command arguments.

    :type client: ``Client``
    :param client: Client object to be used.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Standard command result or no records found message.
    :rtype: ``CommandResults``
    """

    comment_id = arg_to_number(args.get('id'))
    report_id = arg_to_number(args.get('report_id'))
    threat_indicator_id = arg_to_number(args.get('threat_indicator_id'))

    url_suffix = URL_SUFFIX['COMMENTS']
    if comment_id:
        url_suffix = f"{URL_SUFFIX['COMMENTS']}/{comment_id}"
    elif report_id:
        url_suffix = f"{URL_SUFFIX['REPORTS']}/{report_id}/comments"
    elif threat_indicator_id:
        url_suffix = f"{URL_SUFFIX['THREAT_INDICATORS']}/{threat_indicator_id}/comments"

    params = validate_comment_list_args(args)
    response = client.http_request(url_suffix=url_suffix, params=params)

    total_records = response.get('data', [])

    if not total_records:
        return CommandResults(readable_output=MESSAGES['NO_RECORDS_FOUND'].format('comment(s)'))

    if isinstance(total_records, dict):
        total_records = [total_records]

    # Creating the Context data
    context_data = remove_empty_elements(total_records)

    # Creating the Human Readable
    hr_response = prepare_hr_for_comments(total_records)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["COMMENT"],
        outputs_key_field="id",
        outputs=context_data,
        readable_output=hr_response,
        raw_response=response
    )


def cofense_cluster_list_command(client: Client, args: Dict[str, str]) -> CommandResults:
    """
    List clusters from Cofense Triage.

    :type client: ``Client``
    :param client: Client object to be used.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Standard command result or no records found message.
    :rtype: ``CommandResults``
    """

    cluster_id = args.get('id')

    url_suffix = f"{URL_SUFFIX['CLUSTER']}/{cluster_id}" if cluster_id else URL_SUFFIX['CLUSTER']

    params = validate_list_cluster_args(args)

    response = client.http_request(url_suffix, params=params)

    total_records = response.get('data', [])

    if not total_records:
        return CommandResults(readable_output=MESSAGES['NO_RECORDS_FOUND'].format('cluster(s)'))

    if isinstance(total_records, dict):
        total_records = [total_records]

    # Creating entry context
    context = remove_empty_elements(total_records)

    # Creating human-readable
    readable_hr = prepare_hr_for_clusters(total_records)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["CLUSTER"],
        outputs_key_field='id',
        outputs=context,
        readable_output=readable_hr,
        raw_response=response
    )


def get_remote_data_command(client: Client, args: Dict[str, str]) -> GetRemoteDataResponse:
    """
    Get the updated incident data

    :type client: ``Client``
    :param client: Client object to be used.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Standard command result.
    :rtype: ``GetRemoteDataResponse``
    """

    parsed_args = GetRemoteDataArgs(args)

    responded_incident = client.http_request(URL_SUFFIX["REPORT_ID"].format(parsed_args.remote_incident_id))

    result = responded_incident.get('data', {})
    result = remove_empty_elements(result)

    report_last_updated = arg_to_datetime(result.get('attributes', {}).get('updated_at', ""), is_utc=True)
    incident_last_updated = arg_to_datetime(parsed_args.last_update, is_utc=True)

    if report_last_updated < incident_last_updated:  # type: ignore
        demisto.debug(f'[CofenseTriagev3]: Incident {parsed_args.remote_incident_id} is already up to date')
        return GetRemoteDataResponse({}, [])

    return GetRemoteDataResponse(result, [])


def get_modified_remote_data_command(client: Client, args: Dict[str, str]) -> GetModifiedRemoteDataResponse:
    """
    Queries for incidents that were modified since the last update.

    :type client: ``Client``
    :param client: Client object to be used.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Standard command result.
    :rtype: ``GetModifiedRemoteDataResponse``
    """
    remote_args = GetModifiedRemoteDataArgs(args)
    last_update_utc = arg_to_datetime(remote_args.last_update, is_utc=True).strftime(DATE_FORMAT)  # type:ignore

    params = {
        'filter[updated_at_gt]': last_update_utc
    }
    raw_incidents = client.http_request(URL_SUFFIX["REPORTS"], params=params)
    results = raw_incidents.get("data", [])
    modified_incident_ids = list()
    for result in results:
        incident_id = result.get('id')
        modified_incident_ids.append(incident_id)

    return GetModifiedRemoteDataResponse(modified_incident_ids)


def cofense_threat_indicator_update_command(client: Client, args: Dict[str, str]) -> CommandResults:
    """
    Updates a threat indicator based on the values provided in the command arguments.

    :type client: ``Client``
    :param client: Client object to be used.

    :type args: ``Dict[str, str]``
    :param args: The command arguments provided by the user.

    :return: Standard command result or no records found message.
    :rtype: ``CommandResults``
    """

    params = validate_update_threat_indicator_args(args)
    id = args["id"]

    # Sending http request
    response = client.http_request(f"{URL_SUFFIX['THREAT_INDICATORS']}/{id}", method="PUT",
                                   headers={'Content-Type': TYPE_HEADER},
                                   json_data={"data": {
                                       "id": id,
                                       "type": "threat_indicators",
                                       "attributes": params
                                   }})

    result = response.get("data")
    if isinstance(result, dict):
        result = [result]

    # Creating the Human Readable
    hr_response = prepare_hr_for_threat_indicators(result)

    # Creating the Context data
    context_data = remove_empty_elements(result)

    return CommandResults(outputs_prefix=OUTPUT_PREFIX["THREAT_INDICATOR"],
                          outputs_key_field="id",
                          outputs=context_data,
                          readable_output=hr_response,
                          raw_response=response
                          )


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions
    """
    # Commands dictionary
    commands: Dict[str, Callable] = {
        'cofense-report-list': cofense_report_list_command,
        'cofense-threat-indicator-list': cofense_threat_indicator_list_command,
        'cofense-report-download': cofense_report_download_command,
        'cofense-report-categorize': cofense_report_categorize_command,
        'cofense-category-list': cofense_category_list_command,
        'cofense-url-list': cofense_url_list_command,
        'cofense-rule-list': cofense_rule_list_command,
        'cofense-threat-indicator-create': cofense_threat_indicator_create_command,
        'cofense-reporter-list': cofense_reporter_list_command,
        'cofense-attachment-payload-list': cofense_attachment_payload_list_command,
        'cofense-integration-submission-get': cofense_integration_submission_get_command,
        'cofense-comment-list': cofense_comment_list_command,
        'cofense-cluster-list': cofense_cluster_list_command,
        'cofense-threat-indicator-update': cofense_threat_indicator_update_command,
        'cofense-report-image-download': cofense_report_image_download_command
    }
    command = demisto.command()
    demisto.debug(f'[CofenseTriagev3] Command being called is {command}')

    params = demisto.params()

    # get the service API url
    base_url = params.get('url')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    credentials = params.get("credentials", {})
    client_id = credentials.get('identifier').strip()
    client_secret = credentials.get('password')

    try:

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            client_id=client_id,
            client_secret=client_secret
        )

        # Trim the arguments
        args = demisto.args()
        for arg in args:
            if isinstance(args[arg], str):
                args[arg] = args[arg].strip()

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client, params))

        elif command == 'fetch-incidents':
            last_run = demisto.getLastRun()
            next_run, incidents = fetch_incidents(client, last_run, params)
            demisto.incidents(incidents)
            demisto.setLastRun(next_run)

        elif demisto.command() == 'get-remote-data':
            return_results(get_remote_data_command(client, args))

        elif demisto.command() == 'get-modified-remote-data':
            return_results(get_modified_remote_data_command(client, args))

        elif command in commands:
            return_results(commands[command](client, args))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
