import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
"""Main Integration file for CyCognito."""
from typing import Tuple
import pycountry
import urllib3
from requests import Response
from CommonServerUserPython import *  # noqa

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
API_DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
HR_DATE_FORMAT = '%d %b %Y, %I:%M %p'
BASE_URL = 'https://api.platform.cycognito.com/v1'
MAX_PAGE_SIZE = 1000
DEFAULT_COUNT = 50
DEFAULT_SORT_ORDER = 'desc'
DEFAULT_OFFSET = 0
VALID_INVESTIGATION_STATUS = ['uninvestigated', 'investigating', 'investigated']
VALID_ASSET_TYPES = ["ip", "domain", "cert", "webapp", "iprange"]
VALID_SEVERITY = ['low', 'medium', 'high', 'critical']
VALID_ISSUE_TYPES = ['Abandoned Asset', 'Certificate Validity', 'Cryptographic Vulnerability', 'E-mail Security',
                     'Exposed Asset', 'Exposed Data', 'Exposed Dev Environment', 'Information Gathering',
                     'Phishing Threat', 'Potential Imposter Asset', 'Security Hygiene', 'Unmaintained Asset',
                     'Unsafe Authentication', 'Vulnerable Software', 'Weak Encryption', 'XSS']
VALID_OPERATORS = [
    'is', 'not', 'in', 'not-in', 'key-of', 'not-key-of', 'between', 'not-between', 'within-range', 'not-within-range',
    'contains']
AVAILABLE_SECURITY_GRADE = ["a", "b", "c", "d", "f"]
AVAILABLE_STATUS_TYPES = ["new", "changed", "normal"]
MIRROR_DIRECTION = {
    'None': None,
    'Incoming': 'In',
    'Outgoing': 'Out',
    'Incoming and Outgoing': 'Both'
}
ERRORS = {
    'NO_RECORDS': 'No Record Found.',
    'INVALID_SINGLE_SELECT_PARAM': '{} is an invalid value for {}. Possible values are: {}.',
    'INVALID_MULTI_SELECT_PARAM': "Invalid value for {}. Possible comma separated values are {}.",
    'INVALID_PAGE_SIZE': '{} is invalid value for count. Value must be in 1 to 1000.',
    'INVALID_ADVANCED_FILTER': '{} is in invalid format for advanced_filter. '
                               'Please find the accepted format in argument\'s help text.',
    'INVALID_ARGUMENT': 'Invalid argument(s) provided. Please find accepted formats in argument\'s help text.',
    'INVALID_REQUIRED_PARAMETER': '{} is a required field. Please provide correct input.',
    'INVALID_OPERATOR': '{} is invalid value for operator. Possible Values of operators are: {}.',
    'INVALID_COUNTRY_ERROR': '{} is an invalid country name.'
}
INVESTIGATION_STATUS_HR = "Investigation Status"
AFFECTED_ASSET_HR = "Affected Asset"
FIRST_DETECTED_HR = "First Detected"
LAST_DETECTED_HR = "Last Detected"
ISSUE_TYPE_HR = "Issue Type"
ISSUE_STATUS_HR = "Issue Status"
ASSET_ID_HR = "Asset ID"
ASSET_TYPE_HR = "Asset Type"
HOSTING_TYPE_HR = "Hosting Type"
ASSET_OUTPUT_PREFIX = "CyCognito.Asset"
ISSUE_OUTPUT_PREFIX = "CyCognito.Issue"

''' CLIENT CLASS '''


class CyCognitoClient(BaseClient):
    """CyCognitoClient class to interact with the service API."""

    def get_issue(self, issue_instance_id: str) -> Response:
        """Get an issue from Cycognito.

        :type issue_instance_id: ``str``
        :param issue_instance_id: Unique issue ID of the instance.

        :rtype: ``Response``
        :return: Response of API.
        """
        return self._http_request(method='GET', url_suffix=f'/issues/issue/{issue_instance_id}', resp_type="response")

    def get_asset(self, asset_type: str, asset_id: str):
        """Get an asset from Cycognito.

        :type asset_type: str
        :param asset_type: Asset type to use

        :type asset_id: str
        :param asset_id: ID of the asset

        :return: Asset details.
        """
        return self._http_request(method='GET', url_suffix=f'/assets/{asset_type}/{asset_id}', resp_type="response")

    def change_issue_investigation_status(self, params: Dict[str, Any]) -> Response:
        """Change investigation status of an issue.

        :type params: ``Dict[str, Any]``
        :param params: Params passed by user.

        :rtype: ``Response``
        :return: Response of API.
        """
        json_data = {"investigation_status": params['investigation_status']}
        return self._http_request(method='PUT',
                                  url_suffix=f'/issues/issue/{params["issue_instance_id"]}/investigation-status',
                                  json_data=json_data, resp_type="response")

    def change_asset_investigation_status(self, params: Dict[str, Any]):
        """Change investigation status of an asset.

        :type params: ``Dict[str, Any]``
        :param params: Params passed by user.

        :rtype: ``Response``
        :return: Response of API.
        """
        return self._http_request(method='PUT',
                                  url_suffix=f"/assets/{params['asset_type']}/{params['asset_id']}/investigation-status",
                                  resp_type="response",
                                  json_data={'investigation_status': params['investigation_status']})

    def list_issues(self, filters: List, count: int = None, offset: int = None, sort_order: str = None,
                    sort_by: str = None, search: str = None) -> Response:
        """List issues from Cycognito.

        :type count: ``int``
        :param count: Number of the issues to fetch.

        :type offset: ``int``
        :param offset: Number of pages to skip.

        :type sort_order: ``str``
        :param sort_order: Order in which to sort result.

        :type sort_by: ``str``
        :param sort_by: field on which to sort result.

        :type search: ``str``
        :param search: Search string to perform plain text search.

        :type filters: ``List``
        :param filters: Body parameters for filter result.

        :rtype: ``Response``
        :return: Response of API.
        """
        query_params = {
            "count": count, "q": search, "offset": offset, "sort-by": sort_by, "sort-order": sort_order
        }
        remove_nulls_from_dictionary(query_params)
        return self._http_request(method='POST', url_suffix='/issues', params=query_params,
                                  json_data=filters, resp_type="response")

    def list_assets(self, filters: List, asset_type: str, count: int = None, search: str = None, offset: int = None,
                    sort_by: str = None, sort_order: str = None) -> Any:
        """List assets from Cycognito.

        :type asset_type: ``str``
        :param asset_type: Type of the asset.

        :type count: ``int``
        :param count: Number of the issues to fetch.

        :type offset: ``int``
        :param offset: Number of pages to skip.

        :type sort_order: ``str``
        :param sort_order: Order in which to sort result.

        :type sort_by: ``str``
        :param sort_by: field on which to sort result.

        :type search: ``str``
        :param search: Search string to perform plain text search.

        :type filters: ``List``
        :param filters: Body parameters for filter result.

        :rtype: ``Response``
        :return: Response of API.
        """
        query_params = {"count": count, "q": search, "offset": offset, "sort-by": sort_by, "sort-order": sort_order}
        remove_nulls_from_dictionary(query_params)
        return self._http_request(method='POST', url_suffix=f'assets/{asset_type}', params=query_params,
                                  json_data=filters, resp_type="response")


''' HELPER FUNCTIONS '''


def validate_response(response: Response) -> Dict:
    """Validate Response Status Code.

    :type response: ``Response``
    :param response: Response from API.

    :rtype: ``Dict``
    :return: Response JSON.
    """
    if response.status_code == 404:
        raise DemistoException(ERRORS['NO_RECORDS'])
    if response.status_code == 400:
        raise DemistoException(ERRORS['INVALID_ARGUMENT'])
    return remove_empty_elements(response.json())


def validate_arguments_for_asset_get(asset_type: str, asset_id: str):
    """Validate arguments for cycognito-asset-get command.

    :type asset_type: ``str``
    :param asset_type: Type of the asset.

    :type asset_id: ``str``
    :param asset_id: ID of the asset.
    """
    if not asset_type:
        raise ValueError(ERRORS['INVALID_REQUIRED_PARAMETER'].format('asset_type'))

    if not asset_id:
        raise ValueError(ERRORS['INVALID_REQUIRED_PARAMETER'].format('asset_id'))

    if asset_type not in VALID_ASSET_TYPES:
        raise ValueError(ERRORS['INVALID_SINGLE_SELECT_PARAM'].format(asset_type, 'asset_type', VALID_ASSET_TYPES))


def trim_spaces_from_args(args: Dict) -> Dict:
    """Trim spaces from values of the args dict.

    :type args: ``Dict``
    :param args: Dict to trim spaces from.

    :rtype: ``Dict``
    :return: Arguments after trim spaces.
    """
    for key, val in args.items():
        if isinstance(val, str):
            args[key] = val.strip()

    return args


def convert_country_names_to_alpha_3_codes(locations: List[str]):
    """Convert location into alpha-3 codes.

    :type locations: List[str]
    :param locations: Locations to be converted into alpha-3 codes.

    :rtype: List[str]
    :returns: List of locations converted into alpha-3 codes.
    """
    if not locations:
        return []

    converted_locations = []
    for location in filter(None, locations):
        try:
            converted_locations.append(pycountry.countries.search_fuzzy(location)[0].alpha_3)  # type: ignore[attr-defined]
        except LookupError:
            raise ValueError(ERRORS['INVALID_COUNTRY_ERROR'].format(location))

    return converted_locations


def convert_alpha_3_codes_to_country_names(locations: List[str]):
    """Convert alpha-3 code location to country name.

    :type locations: List[str]
    :param locations: Locations to be converted into country name

    :rtype: List[str]
    :returns: List of locations converted into country name.
    """
    if not locations:
        return []

    converted_locations = []
    for location in filter(None, locations):
        try:
            converted_locations.append(pycountry.countries.search_fuzzy(location)[0].name)  # type: ignore[attr-defined]
        except LookupError:
            raise ValueError(ERRORS['INVALID_COUNTRY_ERROR'].format(location))

    return converted_locations


def validate_params_for_issue_investigation_status_change(args: Dict[str, Any]) -> Dict[str, Any]:
    """Validate arguments for cycognito-issue-investigation-status-change command.

    :type args: ``Dict[str, Any]``
    :param args: Arguments provided by user.

    :rtype: ``Dict[str, Any]``
    :return: Validated argument.
    """
    issue_instance_id = args.get("issue_instance_id", '').lower()
    investigation_status = args.get("investigation_status", '').lower()
    if investigation_status not in VALID_INVESTIGATION_STATUS:
        raise ValueError(ERRORS['INVALID_SINGLE_SELECT_PARAM'].format(investigation_status, 'investigation_status',
                                                                      VALID_INVESTIGATION_STATUS))

    return assign_params(issue_instance_id=issue_instance_id, investigation_status=investigation_status)


def validate_params_for_asset_investigation_status_change(args: Dict[str, Any]) -> Dict[str, Any]:
    """Validate arguments for cycognito-asset-investigation-status-change command.

    :type args: ``Dict[str, Any]``
    :param args: Argument provided by user.

    :rtype: ``Dict[str, Any]``
    :return: Validated argument.
    """
    asset_id = args.get('asset_id', "").lower()
    asset_type = args.get('asset_type', "").lower()
    investigation_status = args.get('investigation_status', "").lower()
    if investigation_status not in VALID_INVESTIGATION_STATUS:
        raise ValueError(ERRORS['INVALID_SINGLE_SELECT_PARAM'].format(investigation_status, 'investigation_status',
                                                                      VALID_INVESTIGATION_STATUS))
    if not asset_type:
        raise ValueError(ERRORS['INVALID_REQUIRED_PARAMETER'].format('asset_type'))

    if not asset_id:
        raise ValueError(ERRORS['INVALID_REQUIRED_PARAMETER'].format('asset_id'))

    if asset_type not in VALID_ASSET_TYPES:
        raise ValueError(ERRORS['INVALID_SINGLE_SELECT_PARAM'].format(asset_type, 'asset_type', VALID_ASSET_TYPES))

    return assign_params(asset_type=asset_type, asset_id=asset_id, investigation_status=investigation_status)


def prepare_hr_for_issue_get(response: Dict) -> str:
    """Prepare Human Readable output for cycognito-issue-get command.

    :type response: ``Dict``
    :param response: Response from the API.

    :rtype: ``str``
    :return: Human readable output.
    """
    link = f"https://platform.cycognito.com/issues/issue/{response.get('id', '').replace('issue/', '')}/info"
    hr_output = [{
        "Title": response.get("title"),
        AFFECTED_ASSET_HR: response.get("affected_asset"),
        "Detection Complexity": response.get("detection_complexity"),
        INVESTIGATION_STATUS_HR: response.get("investigation_status"),
        "Exploitation Score": response.get("exploitation_score"),
        FIRST_DETECTED_HR: None if not response.get("first_detected") else arg_to_datetime(
            response.get("first_detected")).strftime(HR_DATE_FORMAT),  # type: ignore
        LAST_DETECTED_HR: None if not response.get("last_detected") else arg_to_datetime(
            response.get("last_detected")).strftime(HR_DATE_FORMAT),  # type: ignore
        "Organizations": ", ".join(response.get("organizations", [])),
        "Locations": ", ".join(convert_alpha_3_codes_to_country_names(response.get("locations", []))),
        "Potential Threat": response.get('potential_threat'),
        "Severity": response.get("severity"),
        ISSUE_TYPE_HR: response.get("issue_type"),
        ISSUE_STATUS_HR: response.get("issue_status"),
        "Remediation Steps": " ".join(response.get("remediation_steps", [])),
        "Potential Impact": ", ".join(response.get("potential_impact", [])),
        "Tags": ", ".join(response.get("tags", [])),
        "References": response.get("references"),
        "Summary": None if not response.get("summary") else response.get("summary").replace("| ", ""),  # type: ignore
        "Link to Platform": f"[Click Here]({link})"
    }]

    headers = ["Title", AFFECTED_ASSET_HR, "Detection Complexity", INVESTIGATION_STATUS_HR, "Exploitation Score",
               FIRST_DETECTED_HR, LAST_DETECTED_HR, "Organizations", "Locations", "Potential Threat", "Severity",
               ISSUE_TYPE_HR, ISSUE_STATUS_HR, "Remediation Steps", "Potential Impact", "Tags", "References",
               "Summary", "Link to Platform"]

    heading = f"Issue detail:\n#### ID: {response['id'].replace('issue/', '')}"

    return tableToMarkdown(heading, hr_output, headers=headers, removeNull=True)


def prepare_hr_for_asset_get(response) -> str:
    """Prepare Human Readable output for asset-get command.

    :type response: ``Dict``
    :param response: Response from the API.

    :rtype: ``str``
    :return: Human readable output.
    """
    first_seen, last_seen, expiration = "", "", ""
    if response.get('first_seen'):
        first_seen = arg_to_datetime(response.get('first_seen')).strftime(HR_DATE_FORMAT)  # type: ignore

    if response.get('last_seen'):
        last_seen = arg_to_datetime(response.get('last_seen')).strftime(HR_DATE_FORMAT)  # type: ignore

    if response.get('expiration'):
        expiration = arg_to_datetime(response.get('expiration')).strftime(HR_DATE_FORMAT)  # type: ignore

    hr_output_asset_details = [
        {
            ASSET_ID_HR: response.get('id').split('/', 1)[-1],
            ASSET_TYPE_HR: response.get('type'),
            HOSTING_TYPE_HR: response.get('hosting_type'),
            'Alive': response.get('alive'),
            'Locations': ", ".join(convert_alpha_3_codes_to_country_names(response.get("locations", []))),
            'IP Addresses': response.get('ip_addresses'),
            'First Seen': first_seen,
            'Last Seen': last_seen,
            'Status': response.get('status'),
            'Security Grade': response.get('security_grade'),
            'Tags': response.get('tags'),
            'Sub Domains': response.get('sub_domains'),
            'Domain Names': response.get('domain_names'),
            'Organizations': ", ".join(response.get('organizations', [])),
            INVESTIGATION_STATUS_HR: response.get('investigation_status'),
            'Severe Issues': response.get('severe_issues'),
            'Open Ports': ", ".join(
                [f"{port_info.get('protocol', '').upper()} - {port_info.get('port')}" for port_info in
                 response.get('open_ports', [])])
        }
    ]

    hr_output_certificate_details = [
        {
            'Certificate Signature': response.get('id', '').split('/', 1)[-1],
            'Expiration Time': expiration,
            'Subject Organization Unit': response.get("subject_organization_unit"),
            'Subject Common Name': response.get('subject_common_name'),
            'Subject Locality': response.get('subject_locality'),
            'Subject Organization': response.get('subject_organization'),
            'Subject Country': response.get('subject_country'),
            'Issuer Organization Unit': response.get('issuer_organization_unit'),
            'Issuer Common Name': response.get('issuer_common_name'),
            'Issuer Locality': response.get('issuer_common_name'),
            'Issuer Organization': response.get('issuer_organization'),
            'Issuer Country': response.get('issuer_country'),
        }
    ]

    headers_asset = [ASSET_ID_HR, ASSET_TYPE_HR, HOSTING_TYPE_HR, 'Alive', 'Locations', "IP Addresses",
                     "First Seen", "Last Seen", "Status", "Security Grade", "Tags", "Sub Domains",
                     "Domain Names", "Organizations", "Severe Issues", INVESTIGATION_STATUS_HR, "Open Ports"]

    headers_certificate = ["Certificate Signature", "Expiration Time", "Subject Organization Unit",
                           "Subject Common Name", "Subject Locality", "Subject Organization", "Subject Country",
                           "Issuer Organization Unit", "Issuer Common Name", "issuer Locality", "Issuer Organization",
                           "Issuer Country"]

    if response.get('type') == 'cert':
        return tableToMarkdown("Asset Details:", hr_output_asset_details,
                               headers=headers_asset,
                               removeNull=True) + "\n" + tableToMarkdown(
            "Certificate Details:", hr_output_certificate_details,
            headers=headers_certificate, removeNull=True)
    else:
        return tableToMarkdown("Asset Details:", hr_output_asset_details,
                               headers=headers_asset,
                               removeNull=True)


def prepare_context_for_issue_investigation_status_change(valid_response: Dict[str, Any],
                                                          params: Dict[str, Any]) -> Dict[str, Any]:
    """Prepare Context output for cycognito-issue-investigation-status-change command.

    :type valid_response: ``Dict[str, Any]``
    :param valid_response: Validated Response.

    :type params: ``Dict[str, Any]``
    :param params: Validated argument.

    :rtype: ``Dict[str, Any]``
    :return: Context Output.
    """
    response = {'id': f"issue/{params['issue_instance_id']}"}
    if valid_response.get("updated"):
        response['investigation_status'] = params['investigation_status']
        response['action_status'] = 'Success'
    else:
        response['action_status'] = 'Failure'

    return response


def prepare_context_for_asset_investigation_status(valid_response: Dict[str, Any], params: Dict[str, Any]) \
        -> Dict[str, Any]:
    """Prepare Context output for cycognito-asset-investigation-status-change command.

    :type valid_response: ``Dict[str, Any]``
    :param valid_response: Validated Response.

    :type params: ``Dict[str, Any]``
    :param params: Validated argument.

    :rtype: ``Dict[str, Any]``
    :return: Context Output.
    """
    response = {'id': f"{params['asset_type']}/{params['asset_id']}"}
    if valid_response.get('updated'):
        response['asset_type'] = params['asset_type']
        response['investigation_status'] = params['investigation_status']
        response['action_status'] = 'Success'
    else:
        response['action_status'] = 'Failure'

    return response


def prepare_hr_for_issue_investigation_status_change(valid_response: Dict[str, Any], params: Dict[str, Any]) -> str:
    """Prepare Human Readable output for cycognito-issue-investigation-status-change command.

    :type valid_response: ``Dict[str, Any]``
    :param valid_response: Validated Response.

    :type params: ``Dict[str, Any]``
    :param params: Validated argument.

    :rtype: ``str``
    :return: Human readable output.
    """
    if valid_response.get('updated'):
        action_status = 'Success'
        heading = f'Investigation status for {params.get("issue_instance_id")} has been successfully updated.'
    else:
        action_status = 'Failure'
        heading = f'Investigation status for {params.get("issue_instance_id")} has failed to update.'

    hr_output = [
        {
            "Issue ID": params.get("issue_instance_id"),
            INVESTIGATION_STATUS_HR: params.get("investigation_status", "").title(),
            "Action Status": action_status
        }
    ]

    headers = ["Issue ID", INVESTIGATION_STATUS_HR, "Action Status"]

    return tableToMarkdown(heading, hr_output, headers=headers, removeNull=True)


def prepare_hr_for_asset_investigation_status(valid_response: Dict[str, Any], params: Dict[str, Any]) -> str:
    """Prepare Human Readable output for asset-change-investigation-status command.

    :type valid_response: ``Dict[str, Any]``
    :param valid_response: Validated Response.

    :type params: ``Dict[str, Any]``
    :param params: Validated argument.

    :rtype: ``str``
    :return: Human readable output.
    """
    if valid_response.get('updated'):
        action_status = 'Success'
        heading = f"Investigation status for {params.get('asset_id')} has been successfully updated."
    else:
        action_status = 'Failure'
        heading = f"Investigation status for {params.get('asset_id')} has failed to update."

    hr_output = [
        {
            ASSET_TYPE_HR: params.get('asset_type'),
            ASSET_ID_HR: params.get('asset_id'),
            'Investigation Status': params.get('investigation_status', "").title(),
            'Action Status': action_status
        }
    ]

    headers = [ASSET_TYPE_HR, ASSET_ID_HR, INVESTIGATION_STATUS_HR, 'Action Status']

    return tableToMarkdown(heading, hr_output, headers=headers, removeNull=True)


def validate_params_for_list_issues(count: Optional[int] = None, sort_order: str = None, severity: List = None,
                                    investigation_status: str = None, issue_type: List = None):
    """Validate arguments for cycognito-issues-list command.

    :type count: ``Optional[int]``
    :param count: Number of the issues to fetch.

    :type sort_order: ``str``
    :param sort_order: Order in which to sort result.

    :type severity: ``List``
    :param severity: Severity of issues.

    :type investigation_status: ``str``
    :param investigation_status: Investigation status of the issue.

    :type issue_type: ``List``
    :param issue_type: Type of the issue.
    """
    if count and (count < 1 or count > MAX_PAGE_SIZE):
        raise ValueError(ERRORS['INVALID_PAGE_SIZE'].format(count))

    if sort_order and sort_order not in ['asc', 'desc']:
        raise ValueError(ERRORS['INVALID_SINGLE_SELECT_PARAM'].format(sort_order, 'sort_order', ["asc", "desc"]))

    if severity and not set(severity).issubset(VALID_SEVERITY):  # type: ignore
        raise ValueError(ERRORS['INVALID_MULTI_SELECT_PARAM'].format('Severity', VALID_SEVERITY))

    if investigation_status and investigation_status not in VALID_INVESTIGATION_STATUS:
        raise ValueError(ERRORS['INVALID_SINGLE_SELECT_PARAM'].format(investigation_status, INVESTIGATION_STATUS_HR,
                                                                      VALID_INVESTIGATION_STATUS))

    if issue_type and not set(issue_type).issubset(VALID_ISSUE_TYPES):  # type: ignore
        raise ValueError(ERRORS['INVALID_MULTI_SELECT_PARAM'].format('Issue Type', VALID_ISSUE_TYPES))


def validate_params_for_list_assets(asset_type: str = None, count: Optional[int] = None, sort_order: str = None,
                                    security_grade: List[str] = None, status: List[str] = None) -> None:
    """Validate arguments for cycognito-assets-list command.

    :type asset_type: ``str``
    :param asset_type: Type of the asset.

    :type count: ``Optional[int]``
    :param count: Number of the assets to fetch.

    :type sort_order: ``str``
    :param sort_order: Order in which to sort result.

    :type security_grade: ``str``
    :param count: Security rating of the asset.

    :type status: ``str``
    :param status: status of the asset.
    """
    if not asset_type:
        raise ValueError(ERRORS['INVALID_REQUIRED_PARAMETER'].format('asset_type'))

    if asset_type not in VALID_ASSET_TYPES:
        raise ValueError(ERRORS['INVALID_SINGLE_SELECT_PARAM'].format(asset_type, 'asset_type', VALID_ASSET_TYPES))

    if count and (count < 1 or count > MAX_PAGE_SIZE):
        raise ValueError(ERRORS['INVALID_PAGE_SIZE'].format(count))

    if sort_order and sort_order not in ['asc', 'desc']:
        raise ValueError(ERRORS['INVALID_SINGLE_SELECT_PARAM'].format(sort_order, 'sort_order', ['asc', 'desc']))

    if not set(security_grade).issubset(AVAILABLE_SECURITY_GRADE):  # type: ignore
        raise ValueError(ERRORS['INVALID_MULTI_SELECT_PARAM'].format('security_grade', list(
            map(lambda x: x.upper(), AVAILABLE_SECURITY_GRADE))))

    if not set(status).issubset(AVAILABLE_STATUS_TYPES):  # type: ignore
        raise ValueError(ERRORS['INVALID_MULTI_SELECT_PARAM'].format('status', AVAILABLE_STATUS_TYPES))


def prepare_body_filters_for_list_issues(advanced_filter: List, organizations: List[str] = None,
                                         locations: List[str] = None,
                                         first_detected: str = None, last_detected: str = None,
                                         issue_type: List[str] = None) -> List[Dict]:
    """Prepare body params for cycognito-issues-list command.

    :type organizations: ``List[str]``
    :param organizations: To retrieve issues related to specific organizations.

    :type locations: ``List[str]``
    :param locations: To retrieve issues related to specific locations.

    :type first_detected: ``str``
    :param first_detected: To retrieve issues from a specific first detected time.

    :type last_detected: ``str``
    :param last_detected: To retrieve issues from a specific last detected time.

    :type issue_type: ``List[str]``
    :param issue_type: To retrieve issues of a specific issue type.

    :type advanced_filter: ``List``
    :param advanced_filter: To filter data by any response field.

    :rtype: ``List[Dict]``
    :return: Body parameters for filter result.
    """
    filter_fields = []

    for filter_dict in advanced_filter:

        filter_fields.append(filter_dict.get('field'))

        if filter_dict.get('op') not in VALID_OPERATORS:
            raise ValueError(ERRORS['INVALID_OPERATOR'].format(filter_dict.get('op'), VALID_OPERATORS))

    fields_with_in_operator = ['organizations', 'locations', 'issue_type']
    values_with_in_operator = [organizations, locations, issue_type]

    for field, value in zip(fields_with_in_operator, values_with_in_operator):
        if value and field not in filter_fields:
            advanced_filter.append({
                'field': field,
                'op': 'in',
                'values': value
            })

    if first_detected and first_detected not in filter_fields:
        advanced_filter.append({
            'field': 'first_detected',
            'op': 'between',
            'values': [
                [first_detected, arg_to_datetime(time.time()).strftime(DATE_FORMAT)]  # type: ignore
            ]
        })

    if last_detected and last_detected not in filter_fields:
        advanced_filter.append({
            'field': 'last_detected',
            'op': 'between',
            'values': [
                [last_detected, arg_to_datetime(time.time()).strftime(DATE_FORMAT)]  # type: ignore
            ]
        })

    return advanced_filter


def prepare_body_filters_for_list_assets(asset_type: str, organizations: List[str], locations: List[str],
                                         first_seen: str,
                                         last_seen: str, security_grade: List[str], status: List[Any],
                                         advanced_filter: List) -> List[Dict]:
    """Prepare body params for cycognito-assets-list command.

    :type asset_type: ``str``
    :param asset_type: To retrieve assets related to specific asset type.

    :type organizations: ``List[str]``
    :param organizations: To retrieve assets related to specific organizations.

    :type locations: ``List[str]``
    :param locations: To retrieve assets related to specific locations.

    :type first_seen: ``str``
    :param first_seen: To retrieve assets from a specific first seen time.

    :type last_seen: ``str``
    :param last_seen: To retrieve assets from a specific last seen time.

    :type security_grade: ``List[str]``
    :param security_grade: To retrieve assets of a specific security rating.

    :type status: ``List[str]``
    :param status: To retrieve assets of a specific status.

    :type advanced_filter: ``List``
    :param advanced_filter: To filter data by any response field.

    :rtype: ``List[Dict]``
    :return: Body parameters for filter result.
    """
    filter_fields = []
    for filter_dict in advanced_filter:
        filter_fields.append(filter_dict.get('field'))
        if filter_dict.get('op') not in VALID_OPERATORS:
            raise ValueError(ERRORS['INVALID_OPERATOR'].format(filter_dict.get('op'), VALID_OPERATORS))

    fields_with_in_operator = ['organizations', 'locations', 'security_grade', 'status']
    values_with_in_operator = [organizations, locations, security_grade, status]

    for field, value in zip(fields_with_in_operator, values_with_in_operator):
        if value and field not in filter_fields:
            advanced_filter.append({
                'field': field,
                'op': 'in',
                'values': value
            })

    if first_seen and first_seen not in filter_fields:
        advanced_filter.append({
            'field': 'first_seen',
            'op': 'between',
            'values': [
                [first_seen, arg_to_datetime(time.time()).strftime(DATE_FORMAT)]  # type: ignore
            ]
        })

    if last_seen and last_seen not in filter_fields:
        advanced_filter.append({
            'field': 'last_seen',
            'op': 'between',
            'values': [

                [last_seen, arg_to_datetime(time.time()).strftime(DATE_FORMAT)]  # type: ignore
            ]
        })

    return advanced_filter


def prepare_hr_for_list_issues(response: Dict) -> str:
    """Prepare Human Readable output for cycognito-issues-list command.

    :type response: ``Dict``
    :param response: Response from API.

    :rtype: ``str``
    :return: Human readable output.
    """
    hr_output = []

    for issue in response:
        hr_output.append({
            "ID": issue.get('id', '').replace('issue/', ''),
            "Title": issue.get('title'),
            AFFECTED_ASSET_HR: issue.get('affected_asset'),
            FIRST_DETECTED_HR: None if not issue.get("first_detected") else arg_to_datetime(
                issue.get("first_detected")).strftime(HR_DATE_FORMAT),  # type: ignore
            LAST_DETECTED_HR: None if not issue.get("last_detected") else arg_to_datetime(
                issue.get("last_detected")).strftime(HR_DATE_FORMAT),  # type: ignore
            "Organizations": ", ".join(issue.get("organizations", [])),
            "Locations": ", ".join(convert_alpha_3_codes_to_country_names(issue.get("locations", []))),
            ISSUE_STATUS_HR: issue.get("issue_status"),
            ISSUE_TYPE_HR: issue.get("issue_type"),
            INVESTIGATION_STATUS_HR: issue.get("investigation_status"),
            "Severity": issue.get("severity"),
            "Severity Score": issue.get("severity_score")
        })

    headers = ["ID", "Title", "Severity Score", "Severity", AFFECTED_ASSET_HR, ISSUE_TYPE_HR, ISSUE_STATUS_HR,
               "Organizations", INVESTIGATION_STATUS_HR, FIRST_DETECTED_HR, LAST_DETECTED_HR, "Locations"]

    return tableToMarkdown("Issues:", hr_output, headers=headers, removeNull=True)


def prepare_hr_for_list_assets(response: Dict, asset_type: str) -> str:
    """Prepare Human Readable output for cycognito-assets-list command.

    :type response: ``Dict``
    :param response: Response from API.

    :type asset_type: ``str``
    :param asset_type: Type of the asset.

    :rtype: ``str``
    :return: Human readable output.
    """
    hr_outputs = []
    for asset in response:
        first_seen = arg_to_datetime(asset.get('first_seen'), arg_name='first_seen')  # type: ignore
        last_seen = arg_to_datetime(asset.get('last_seen'), arg_name='last_seen')  # type: ignore
        if first_seen:
            first_seen: str = first_seen.strftime(HR_DATE_FORMAT)  # type: ignore
        if last_seen:
            last_seen: str = last_seen.strftime(HR_DATE_FORMAT)  # type: ignore

        hr_outputs.append({
            ASSET_ID_HR: asset.get('id', '').split('/', 1)[-1],
            HOSTING_TYPE_HR: asset.get('hosting_type'),
            'First Seen': first_seen,
            'Last Seen': last_seen,
            'Domain Names': ", ".join(asset.get('domain_names', [])),
            'Domains': ", ".join(asset.get('domains', [])),
            'Security Grade': asset.get('security_grade'),
            'Common Name': asset.get('subject_common_name'),
            'Status': asset.get('status'),
            'Organizations': ", ".join(asset.get('organizations', [])),
            'Locations': ", ".join(convert_alpha_3_codes_to_country_names(asset.get("locations", []))),
            INVESTIGATION_STATUS_HR: asset.get('investigation_status'),
            'Severe Issues': asset.get('severe_issues')
        })

    headers = [ASSET_ID_HR, "Security Grade", "Status", "Organizations", INVESTIGATION_STATUS_HR, "Severe Issues",
               "Common Name", "Domain Names", "Domains", "First Seen", "Last Seen", HOSTING_TYPE_HR,
               "Locations"]

    return tableToMarkdown(
        f"Asset List:\n Assets Type: {asset_type.title() if asset_type != 'ip' else asset_type.upper()}", hr_outputs,
        headers=headers,
        removeNull=True)


def prepare_advance_filter_for_fetch_incident(severity: List, investigation_status: str, advanced_filter: List) -> List:
    """Prepare advance json for fetch incident.

    :type severity: ``List``
    :param severity: Valid severity list to filter response.

    :type investigation_status: ``str``
    :param investigation_status: To filter response according investigation status.

    :type advanced_filter: ``List``
    :param advanced_filter: Advance json to filter response.

    :rtype: ``List``
    :return: Advance json for fetch incidents.
    """
    if severity:
        advanced_filter.append({
            'field': 'severity',
            'op': 'in',
            'values': severity
        })

    if investigation_status:
        advanced_filter.append({
            'field': 'investigation_status',
            'op': 'in',
            'values': [investigation_status]
        })

    return advanced_filter


''' COMMAND FUNCTIONS '''


def test_module(client: CyCognitoClient) -> str:
    """Tests API connectivity and authentication.

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises:
     exceptions if something goes wrong.

    :type client: ``CyCognitoClient``
    :param client: CyCognitoClient to be used.

    :rtype: ``str``
    :return: 'ok' if test passed, anything else will fail the test.
    """
    params = demisto.params()
    is_fetch = params.get('isFetch', False)
    if is_fetch:
        fetch_incidents(client, {}, params, is_test=True)
    else:
        client.list_issues(count=1, filters=[])  # body is required
    return 'ok'


def fetch_incidents(client: CyCognitoClient, last_run: Dict[str, Any], params: Dict[str, Any], is_test: bool = False) -> \
        Tuple[Dict, List]:
    """Fetch issues list incidents.

    :type client: ``CyCognitoClient``
    :param client: CyCognitoClient to be used.

    :type last_run: ``Dict[str, Any]``
    :param last_run: last run object obtained from demisto.getLastRun().

    :type params: `Dict[str, Any]``
    :param params: Arguments to be used for fetch incident.

    :type is_test: ``bool``
    :param is_test: If test_module called fetch_incident.

    :rtype: ``Tuple[Dict, List]``
    :return: Tuple of last run object and list of fetched incidents.
    """
    count = arg_to_number(params.get('max_fetch'), arg_name='Max Fetch')  # type: ignore
    first_fetch = arg_to_datetime(params.get('first_fetch', '3 days'), arg_name='First Fetch').strftime(  # type: ignore
        DATE_FORMAT)
    offset = last_run.get('offset', 0)
    first_detected = last_run.get('last_fetch', first_fetch)

    issue_type = argToList(params.get('issue_type'))
    locations = convert_country_names_to_alpha_3_codes(argToList(params.get('locations', '')))
    severity = argToList(params.get('severity_filter'))
    investigation_status = params.get('investigation_status', 'uninvestigated')
    advanced_filter = params.get('advanced_filter')

    if not count:
        raise ValueError(ERRORS['INVALID_REQUIRED_PARAMETER'].format('Max Fetch'))

    if not advanced_filter:
        advanced_filter = '[]'

    try:
        advanced_filter = json.loads(advanced_filter)
        if isinstance(advanced_filter, dict):
            advanced_filter = [advanced_filter]
    except json.JSONDecodeError:
        raise ValueError(ERRORS['INVALID_ADVANCED_FILTER'].format(advanced_filter))

    validate_params_for_list_issues(count=count, severity=severity, investigation_status=investigation_status,
                                    issue_type=issue_type)

    advanced_filter = prepare_advance_filter_for_fetch_incident(severity=severity,
                                                                investigation_status=investigation_status,
                                                                advanced_filter=advanced_filter)

    filters = prepare_body_filters_for_list_issues(locations=locations, issue_type=issue_type,
                                                   first_detected=first_detected, advanced_filter=advanced_filter)

    response = client.list_issues(filters=filters, count=count, offset=offset, sort_by='first_detected',
                                  sort_order='asc')
    valid_response = validate_response(response)

    if is_test:
        return {}, []

    next_run = last_run.copy()

    incidents = []

    demisto.debug(f"\n\n[+] CyCognito: Params -> {params}\n\n")

    for issue in valid_response:
        issue.update({
            'mirror_direction': MIRROR_DIRECTION.get(params.get('mirror_direction', 'None')),
            'mirror_instance': demisto.integrationInstance()
        })
        occurred_date = dateparser.parse(issue.get("first_detected"))  # type: ignore
        incidents.append(
            {
                "name": f"{issue.get('id').replace('issue/', '')} {issue.get('title')}",
                "occurred": occurred_date.strftime(DATE_FORMAT),  # type: ignore
                "rawJSON": json.dumps(issue),
            }
        )
    demisto.debug(f"Total {len(incidents)} incident fetched.")
    if valid_response:
        if len(valid_response) < count:  # type: ignore
            last_fetch_time = dateparser.parse(valid_response[-1].get('first_detected')) + timedelta(  # type: ignore
                milliseconds=1)
            next_run['last_fetch'] = last_fetch_time.strftime(API_DATE_FORMAT)  # type: ignore
            next_run['offset'] = 0
        else:
            next_run['offset'] = offset + 1
            next_run['last_fetch'] = first_detected

    return next_run, incidents


def get_remote_data_command(client: CyCognitoClient, args: Dict[str, Any]):
    """Get updated remote data.

    :type client: ``CyCognitoClient``
    :param client: CyCognitoClient to be used.

    :type args: `Dict[str, Any]``
    :param args: Arguments to be used for get-remote-data command.
    """
    parsed_args = GetRemoteDataArgs(args)

    demisto.debug(f'\n\n[+] CyCognito: Running get_remote_data_command for incident {parsed_args.remote_incident_id}')
    responded_incident = client.get_issue(parsed_args.remote_incident_id)
    demisto.debug(f"[+] CyCognito: response {responded_incident.json()}")
    return GetRemoteDataResponse(responded_incident.json(), [])


def update_remote_system_command(client: CyCognitoClient, args: Dict[str, Any]):
    """Update investigation status change to remote system.

    :type client: ``CyCognitoClient``
    :param client: CyCognitoClient to be used.

    :type args: `Dict[str, Any]``
    :param args: Arguments to be used for update-remote-system command.
    """
    parsed_args = UpdateRemoteSystemArgs(args)

    demisto.debug(
        f'\n\n[+] CyCognito: Update - Running update_remote_system_command for incident {parsed_args.remote_incident_id}')
    demisto.debug(f"[+] CyCognito: parsed_args -> {parsed_args}")
    if parsed_args.delta:
        demisto.debug(
            f'[+] CyCognito: Delta keys for incident {parsed_args.remote_incident_id} are {str(parsed_args.delta)}')
    if not parsed_args.delta.get('cycognitoinvestigationstatus'):
        demisto.debug(f'[+] CyCognito: No Update necessary for incident {parsed_args.remote_incident_id}')
        return parsed_args.remote_incident_id

    demisto.debug(f"[+] CyCognito: Delta keys -> {str(list(parsed_args.delta.keys()))}")

    params = {
        'investigation_status': parsed_args.delta['cycognitoinvestigationstatus'],
        'issue_instance_id': parsed_args.remote_incident_id
    }
    demisto.debug(f"[+] CyCognito: params -> {params}")
    updated_incident = client.change_issue_investigation_status(params)
    updated_incident = prepare_context_for_issue_investigation_status_change(updated_incident.json(), params)
    return updated_incident.get('id', '').replace('issue/', '')


def cycognito_issue_get_command(client: CyCognitoClient, args: Dict[str, Any]) -> CommandResults:
    """Retrieve information about an issue associated with a particular asset.

    :type client: ``CyCognitoClient``
    :param client: CyCognitoClient to be used.

    :type args: ``Dict[str, Any]``
    :param args: Arguments provided by user.

    :rtype: ``CommandResults``
    :return: Standard command result.
    """
    issue_instance_id = args.get("issue_instance_id", '').lower()

    response = client.get_issue(issue_instance_id)
    valid_response = validate_response(response)

    valid_response["id"] = f"issue/{issue_instance_id}"

    hr_output = prepare_hr_for_issue_get(valid_response)

    return CommandResults(
        outputs_prefix=ISSUE_OUTPUT_PREFIX,
        outputs_key_field="id",
        outputs=valid_response,
        readable_output=hr_output,
        raw_response=response.json(),
    )


def cycognito_asset_get_command(client: CyCognitoClient, args: Dict[str, Any]):
    """Retrieve a particular asset based on the specified type.

    :type client: ``CyCognitoClient``
    :param client: CyCognitoClient to use

    :type args: ``dict``
    :param args: arguments obtained from demisto.args()

    :return: CommandResult object
    """
    asset_id = args.get('asset_id', "").lower()
    asset_type = args.get('asset_type', "").lower()
    validate_arguments_for_asset_get(asset_type, asset_id)
    response = client.get_asset(asset_type, asset_id)
    validated_response = validate_response(response)
    readable_output = prepare_hr_for_asset_get(validated_response)

    return CommandResults(
        outputs_prefix=ASSET_OUTPUT_PREFIX,
        outputs_key_field="id",
        outputs=validated_response,
        readable_output=readable_output,
        raw_response=response.json()
    )


def cycognito_issue_investigation_status_change_command(client: CyCognitoClient,
                                                        args: Dict[str, Any]) -> CommandResults:
    """Modify the investigation status of the specified issue.

    :type client: ``CyCognitoClient``
    :param client: CyCognitoClient to be used.

    :type args: ``Dict[str, Any]``
    :param args: Arguments provided by user.

    :rtype: ``CommandResults``
    :return: Standard command result.
    """
    params = validate_params_for_issue_investigation_status_change(args)

    response = client.change_issue_investigation_status(params)
    valid_response = validate_response(response)

    context_data = prepare_context_for_issue_investigation_status_change(valid_response, params)
    hr_output = prepare_hr_for_issue_investigation_status_change(valid_response, params)

    return CommandResults(
        outputs_prefix=ISSUE_OUTPUT_PREFIX,
        outputs_key_field="id",
        outputs=context_data,
        readable_output=hr_output,
        raw_response=response.json(),
    )


def cycognito_asset_investigation_status_change_command(client: CyCognitoClient, args: Dict[str, Any]):
    """Modify the investigation status of the asset.

    :type client: ``CyCognitoClient``
    :param client: CyCognitoClient to use

    :type args: ``dict``
    :param args: arguments obtained from demisto.args()

    :return: CommandResult object
    """
    params = validate_params_for_asset_investigation_status_change(args)
    response = client.change_asset_investigation_status(params)
    validated_response = validate_response(response)
    context_data = prepare_context_for_asset_investigation_status(validated_response, params)
    readable_output = prepare_hr_for_asset_investigation_status(validated_response, params)

    return CommandResults(
        outputs_prefix=ASSET_OUTPUT_PREFIX,
        outputs_key_field="id",
        outputs=context_data,
        readable_output=readable_output,
        raw_response=response.json()
    )


def cycognito_issues_list_command(client: CyCognitoClient, args: Dict[str, Any]) -> CommandResults:
    """Retrieve the list of the issues that meet the specified filter criteria.

    :type client: ``CyCognitoClient``
    :param client: CyCognitoClient to be used.

    :type args: ``Dict[str, Any]``
    :param args: Arguments provided by user.

    :rtype: ``CommandResults``
    :return: Standard command result.
    """
    count = arg_to_number(args.get('count', DEFAULT_COUNT), arg_name='count')
    offset = max(arg_to_number(args.get('offset', DEFAULT_OFFSET), arg_name='offset'), 0)  # type: ignore
    search = args.get('search', '')
    first_detected = args.get('first_detected', '')
    last_detected = args.get('last_detected', '')
    organizations = argToList(args.get('organizations', '').lower())
    locations = argToList(args.get('locations', ''))
    issue_type = argToList(args.get('issue_type', ''))
    sort_by = args.get('sort_by', '').lower()
    sort_order = args.get('sort_order', DEFAULT_SORT_ORDER).lower()
    advanced_filter = args.get('advanced_filter', '[]')

    try:
        advanced_filter = json.loads(advanced_filter)
        if isinstance(advanced_filter, dict):
            advanced_filter = [advanced_filter]
    except json.JSONDecodeError:
        raise ValueError(ERRORS['INVALID_ADVANCED_FILTER'].format(advanced_filter))

    if first_detected:
        first_detected = arg_to_datetime(first_detected, arg_name='first_detected').strftime(  # type: ignore
            DATE_FORMAT)
    if last_detected:
        last_detected = arg_to_datetime(last_detected, arg_name='last_detected').strftime(DATE_FORMAT)  # type: ignore

    validate_params_for_list_issues(count=count, sort_order=sort_order)

    filters = prepare_body_filters_for_list_issues(organizations=organizations, locations=locations,
                                                   first_detected=first_detected,
                                                   last_detected=last_detected, issue_type=issue_type,
                                                   advanced_filter=advanced_filter)

    response = client.list_issues(filters=filters, count=count, offset=offset, sort_order=sort_order,
                                  sort_by=sort_by, search=search)

    valid_response = validate_response(response)

    hr_output = prepare_hr_for_list_issues(valid_response)

    return CommandResults(
        outputs_prefix=ISSUE_OUTPUT_PREFIX,
        outputs_key_field="id",
        outputs=valid_response,
        readable_output=hr_output,
        raw_response=response.json(),
    )


def cycognito_assets_list_command(client: CyCognitoClient, args: Dict[str, Any]) -> CommandResults:
    """Retrieve the list of the assets that meet the specified filter criteria.

    :type client: ``CyCognitoClient``
    :param client: CyCognitoClient to be used.

    :type args: ``Dict[str, Any]``
    :param args: Arguments provided by user.

    :rtype: ``CommandResults``
    :return: Standard command result.
    """
    asset_type = args.get('asset_type', '').lower()
    count = arg_to_number(args.get('count', DEFAULT_COUNT), arg_name='count')
    offset = max(arg_to_number(args.get('offset', DEFAULT_OFFSET), arg_name='offset'), 0)  # type: ignore
    search = args.get('search', '')
    first_seen = args.get('first_seen', '')
    last_seen = args.get('last_seen', '')
    organizations = argToList(args.get('organizations', '').lower())
    security_grade = argToList(args.get('security_grade', '').lower())
    status = argToList(args.get('status', '').lower())
    locations = argToList(args.get('locations', ''))
    sort_by = args.get('sort_by', '').lower()
    sort_order = args.get('sort_order', DEFAULT_SORT_ORDER).lower()
    advanced_filter = args.get('advanced_filter', '[]')

    try:
        advanced_filter = json.loads(advanced_filter)
        if isinstance(advanced_filter, dict):
            advanced_filter = [advanced_filter]
    except json.JSONDecodeError:
        raise ValueError(ERRORS['INVALID_ADVANCED_FILTER'].format(advanced_filter))

    if first_seen:
        first_seen = arg_to_datetime(first_seen, arg_name='first_seen').strftime(  # type: ignore
            DATE_FORMAT)
    if last_seen:
        last_seen = arg_to_datetime(last_seen, arg_name='last_seen').strftime(DATE_FORMAT)  # type: ignore

    validate_params_for_list_assets(asset_type=asset_type, count=count, sort_order=sort_order, status=status,
                                    security_grade=security_grade)

    filters = prepare_body_filters_for_list_assets(asset_type=asset_type, organizations=organizations,
                                                   locations=locations,
                                                   security_grade=security_grade, status=status,
                                                   first_seen=first_seen, last_seen=last_seen,
                                                   advanced_filter=advanced_filter)
    response = client.list_assets(filters=filters, asset_type=asset_type, count=count, offset=offset, search=search,
                                  sort_order=sort_order, sort_by=sort_by)
    valid_response = validate_response(response)

    hr_output = prepare_hr_for_list_assets(valid_response, asset_type)

    return CommandResults(
        outputs_prefix=ASSET_OUTPUT_PREFIX,
        outputs_key_field="id",
        outputs=valid_response,
        readable_output=hr_output,
        raw_response=response.json(),
    )


def main():
    """Parse params and runs command functions."""
    params = demisto.params()
    api_key = params.pop('api_key')

    verify_certificate = not params.get('insecure', False)
    proxy = argToBoolean(params.get('proxy', False))

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:

        headers = {
            "Authorization": api_key
        }
        client = CyCognitoClient(
            base_url=BASE_URL,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy,
            ok_codes=(404, 200, 400)
        )
        if command == 'test-module':
            return_results(test_module(client))
        elif demisto.command() == 'fetch-incidents':
            last_run = demisto.getLastRun()
            next_run, incidents = fetch_incidents(client, last_run, params)
            demisto.info(f"Fetched {len(incidents)} new incidents")
            demisto.incidents(incidents)
            demisto.setLastRun(next_run)
        elif demisto.command() == 'get-remote-data':
            return_results(get_remote_data_command(client, demisto.args()))
        elif demisto.command() == 'update-remote-system':
            return_results(update_remote_system_command(client, demisto.args()))
        else:
            CYCOGNITO_COMMANDS = {
                'cycognito-issue-get': cycognito_issue_get_command,
                'cycognito-issues-list': cycognito_issues_list_command,
                'cycognito-issue-investigation-status-change': cycognito_issue_investigation_status_change_command,
                'cycognito-asset-get': cycognito_asset_get_command,
                'cycognito-assets-list': cycognito_assets_list_command,
                'cycognito-asset-investigation-status-change': cycognito_asset_investigation_status_change_command,
            }
            if CYCOGNITO_COMMANDS.get(command):
                args = demisto.args()
                remove_nulls_from_dictionary(trim_spaces_from_args(args))
                return_results(CYCOGNITO_COMMANDS[command](client, args))
            else:
                raise NotImplementedError(f'Command {command} is not implemented')
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
