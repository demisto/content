import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
"""Implementation file for Cofense Vision Integration."""

import traceback
from typing import Any, Dict, Optional, Callable

import urllib3
from requests import Response

from CommonServerUserPython import *  # noqa

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR
HR_DATE_FORMAT = '%m/%d/%Y, %I:%M %p %Z'
API_SUFFIX = "/api/v4"
API_ENDPOINTS = {
    "AUTHENTICATION": "/uaa/oauth/token",
    "GET_ALL_SEARCHES": API_SUFFIX + "/searches",
    "GET_ATTACHMENT": API_SUFFIX + "/attachment",
    "GET_MESSAGE": API_SUFFIX + "/messages",
    "GET_MESSAGE_METADATA": API_SUFFIX + "/messages/metadata",
    "GET_QUARANTINE_JOBS": API_SUFFIX + "/quarantineJobs/filter",
    "GET_MESSAGE_TOKEN": API_SUFFIX + "/messages",
    "QUARANTINE_JOB": API_SUFFIX + "/quarantineJobs",
    "RESTORE_QUARANTINE_JOB": API_SUFFIX + "/quarantineJobs/{}/restore",
    "GET_MESSAGE_SEARCH": API_SUFFIX + "/searches/{}",
    "APPROVE_QUARANTINE_JOB": API_SUFFIX + "/quarantineJobs/{}/approve",
    "GET_SEARCH_RESULTS": API_SUFFIX + "/searches/{}/results",
    "IOC_REPOSITORY": "/iocrepository/v1/iocs",
    "STOP_QUARANTINE_JOB": API_SUFFIX + "/quarantineJobs/{}/stop",
    "CREATE_MESSAGE_SEARCH": API_SUFFIX + "/searches",
    "GET_LAST_IOC": "/iocrepository/v1/iocs/last",
    "GET_IOCS": "/iocrepository/v1/iocs",
    "GET_SEARCHABLE_HEADERS": API_SUFFIX + "/config/searchableHeaders"
}
ERROR_MESSAGE = {
    'INVALID_FORMAT': "{} is an invalid format for {}. Supported format is: {}",
    'INVALID_PAGE_VALUE': 'Page number must be a non-zero and positive numeric value.',
    'INVALID_PAGE_SIZE_RANGE': 'Page size should be in the range from 1 to 2000.',
    'UNSUPPORTED_FIELD': "{} is not a supported value for {}. Supported values for {} are: {}.",
    'UNSUPPORTED_FIELD_FOR_IOCS_LIST': "{} is not a supported value for {}. Supported value for {} is: {}.",
    'INVALID_REQUIRED_PARAMETER_HASH': 'At least one of the hash values (md5 or sha256) is required.',
    'INVALID_ARGUMENT': '{} is an invalid value for {}.',
    'MISSING_REQUIRED_PARAM': "{} is a required parameter. Please provide correct value.",
    'INVALID_QUARANTINE_JOB_PARAM': "{} must be a non-zero positive integer number.",
    'INVALID_SEARCH_ID': 'ID must be a non-zero positive integer number.',
    "INVALID_QUARANTINE_JOB_ID": "Quarantine Job ID must be a non-zero positive integer number.",
    'INVALID_SEARCH_LENGTH': "Maximum 3 values are allowed to create a search for {} parameter."
}
IOC_TYPES = {'domain': DBotScoreType.DOMAIN, 'md5': DBotScoreType.FILE, 'sender': DBotScoreType.EMAIL,
             'sha256': DBotScoreType.FILE, 'subject': DBotScoreType.CUSTOM, 'url': DBotScoreType.URL}
SUPPORTED_HASH = ['MD5', 'SHA256']
SUPPORTED_CRITERIA = ['ANY', 'ALL']
SUPPORTED_HASH_VALUE_FORMAT = 'hashtype1:hashvalue1,hashtype2:hashvalue2'
SUPPORTED_QUARANTINE_EMAILS_FORMAT = "internetMessageID1:recipientAddress1,internetMessageID2:recipientAddress2"
SUPPORTED_HEADERS_FORMAT = 'key1:value1,key2:value1:value2:value3'
SUPPORTED_SORT_FORMAT = 'propertyName1:sortOrder1,propertyName2:sortOrder2'
SUPPORTED_SORT_FORMAT_FOR_IOCS_LIST = "propertyName:sortOrder"
STATUS = ['NEW', 'PENDING_APPROVAL', 'QUEUED', 'RUNNING', 'COMPLETED', 'FAILED']
THREAT_TYPES = ['domain', 'md5', 'sender', 'sha256', 'subject', 'url']
SUPPORTED_SORT = {
    'order_by': ['asc', 'desc'],
    'quarantine_jobs_list': ['id', 'createdBy', 'createdDate', 'modifiedBy', 'modifiedDate', 'stopRequested'],
    'message_searches_list': ['id', 'createdBy', 'createdDate', 'modifiedBy', 'modifiedDate', 'receivedAfterDate',
                              'receivedBeforeDate'],
    'message_search_result_get': ['id', 'subject', 'createdOn', 'sentOn', 'htmlBody', 'md5', 'sha1', 'sha256'],
    "iocs_list": ["updatedAt"],
}
MAX_PAGE_SIZE = 2000
SPECIAL_CHARACTERS_MARKDOWN = ['#', '*', '`', '<', '>', '_', '-', '(', ')', '[', ']', '!', '+', '.', '{', '}', '~', '=',
                               '|', '\\']
DEFAULT_SORT_VALUE = "id:asc"
RECEIVED_ON = "Received On"
SENT_ON = "Sent On"
INTERNET_MESSAGE_ID = "Internet Message ID"
MATCHING_IOCS = "Matching IOCs"
MATCHING_SOURCES = "Matching Sources"
CREATED_BY = "Created By"
CREATED_DATE = "Created Date"
MODIFIED_BY = "Modified By"
MODIFIED_DATE = "Modified Date"
SEARCH_ID = "Search ID"
LAST_MODIFIED_BY = "Last Modified By"
LAST_MODIFIED_DATE = "Last Modified Date"
LAST_ACTION = "Last Action"
COMPLETED_DATE = "Completed Date"
THREAT_TYPE = "Threat Type"
THREAT_VALUE = "Threat Value"
THREAT_LEVEL = "Threat Level"
CREATED_AT = "Created At"
UPDATED_AT = "Updated At"
EXPIRES_AT = "Expires At"
MATCH_COUNT = "Match Count"
QUARANTINE_COUNT = "Quarantine Count"
FIRST_QUARANTINED_AT = "First Quarantined At"
LAST_QUARANTINE_AT = "Last Quarantined At"
QUARANTINE_JOB_OUTPUT_PREFIX = "Cofense.QuarantineJob"
SEARCH_OUTPUT_PREFIX = "Cofense.Search"
IOC_OUTPUT_PREFIX = "Cofense.IOC"
ATTACHMENT_FILE_NAMES = "Attachment File Names"
INCLUDED_MIME_TYPES = "Included MIME Types"
EXCLUDED_MIME_TYPES = "Excluded MIME Types"
HASH_TYPE = "Hash Type"
WHITELIST_URLS = "Whitelist URLs"
DATE_RANGE = "Date Range"
HEADERS = "Header Key/Value"
PARTIAL_INGEST = "Partial Ingest"
APPLICATION_JSON = "application/json"
""" CLIENT CLASS """


class VisionClient(BaseClient):
    """Client class to interact with the service API."""

    def __init__(self, base_url: str, client_id: str, client_secret: str, verify: bool, proxy: bool,
                 threat_levels_good: list, threat_levels_suspicious: list, threat_levels_bad: list) -> None:
        """
        Prepare constructor for Client class.

        Calls the constructor of BaseClient class and updates
        the header with the authentication token.

        Args:
            base_url (str): The url of Cofense Vision instance.
            client_id (str): The Client ID to use for authentication.
            client_secret (str): The Client Secret to use for authentication.
            verify (bool): True if verify SSL certificate is checked in integration configuration, False otherwise.
            proxy (bool): True if proxy is checked in integration configuration, False otherwise.
            threat_levels_good (list): List of threat levels provided by user to map DbotScore as Good.
            threat_levels_suspicious (list): List of threat levels provided by user to map DbotScore as Suspicious.
            threat_levels_bad(list): List of threat levels provided by user to map DbotScore as Bad.
        """
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)

        # Setting up access token in headers.
        self._headers: Dict[str, Any] = {
            "Authorization": f"Bearer {self.get_access_token(client_id=client_id, client_secret=client_secret)}"
        }
        self.threat_levels_good = [level.lower() for level in threat_levels_good] + ['low']
        self.threat_levels_suspicious = [level.lower() for level in threat_levels_suspicious] + ['suspicious',
                                                                                                 'moderate',
                                                                                                 'substantial']
        self.threat_levels_bad = [level.lower() for level in threat_levels_bad] + ['malicious', 'severe', 'critical',
                                                                                   'high']

    def authenticate(self, client_id: str, client_secret: str) -> tuple[str, int]:
        """
        Get the access token from the Cofense API.

        Args:
            client_id (str): The Client ID to use for authentication.
            client_secret (str): The Client Secret to use for authentication.

        Returns:
            tuple[str,int]: The token and its expiration time in seconds received from the API.
        """
        demisto.info("[CofenseVision] Generating new authentication token.")

        req_headers = {
            "cache-control": "no-cache",
            "content-type": "application/x-www-form-urlencoded",
        }
        req_body = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
        }
        response = self._http_request(
            method="POST",
            url_suffix=API_ENDPOINTS["AUTHENTICATION"],
            data=req_body,
            headers=req_headers,
            error_handler=error_handler
        )
        token = response.get("access_token")
        expires_in = response.get("expires_in")

        return token, expires_in

    def get_access_token(self, client_id: str, client_secret: str) -> str:
        """Return the token stored in integration context.

        If the token has expired or is not present in the integration context
        (in the first case), it calls the Authentication function, which
        generates a new token and stores it in the integration context.

        Args:
            client_id (str): The Client ID to use for authentication.
            client_secret (str): The Client Secret to use for authentication.

        Returns:
            str: Authentication token stored in integration context.
        """
        integration_context = get_integration_context()
        token = integration_context.get("access_token")
        valid_until = integration_context.get("valid_until")
        time_now = int(time.time())

        # If token exists and is valid, then return it.
        if (token and valid_until) and (time_now < valid_until):
            demisto.info("[CofenseVision] Token returned from integration context.")
            return token

        # Otherwise, generate a new token and store it.
        token, expires_in = self.authenticate(client_id=client_id, client_secret=client_secret)
        integration_context = {
            "access_token": token,
            "valid_until": time_now + expires_in,  # Token expiration time - 30 mins
        }
        set_integration_context(integration_context)

        return token

    def get_attachment(self, md5: Optional[str] = None, sha256: Optional[str] = None) -> Response:
        """Get an attachment of an email from API.

        Args:
            md5(Optional[str]): MD5 hash of attachment file.
            sha256(Optional[str]): SHA256 hash of an attachment.

        Returns:
            Response: Response from API.
        """
        params = assign_params(md5=md5, sha256=sha256)
        return self._http_request(method='GET', url_suffix=API_ENDPOINTS["GET_ATTACHMENT"], resp_type='Response',
                                  params=params, error_handler=error_handler)

    def get_message(self, token: str) -> Response:
        """Get the message zip file, which contains the email's content.

        Args:
            token(str): One time token to access email content.

        Returns:
            Response: Response from API.
        """
        return self._http_request(method='GET', url_suffix=API_ENDPOINTS["GET_MESSAGE"], resp_type='response',
                                  params={"token": token}, error_handler=error_handler)

    def get_message_metadata(self, internet_message_id: str, recipient_address: str) -> Dict[str, Any]:
        """Get content of message that matches specified ID and Recipient Address.

        Args:
            internet_message_id(str): ID of an email assigned by the message transfer agent.
            recipient_address(str): Email address of the recipient of an email.

        Returns:
            Dict[str, Any]: Response from API.
        """
        params = assign_params(internetMessageId=internet_message_id, recipientAddress=recipient_address)
        return self._http_request(method='GET', url_suffix=API_ENDPOINTS["GET_MESSAGE_METADATA"], params=params,
                                  error_handler=error_handler)

    def get_message_token(self, internet_message_id: str, recipient_address: str, password: str = None) -> str:
        """Retrieve the one time message token from the Cofense Vision API.

        Args:
            internet_message_id (str): Unique identifier of the email address.
            recipient_address (str): Email address of the recipient of the email.
            password (str, optional): Password to protect the zip file containing the email. Defaults to None.

        Returns:
            str: One time token
        """
        req_data = assign_params(internetMessageId=internet_message_id, recipientAddress=recipient_address,
                                 password=password)

        return self._http_request(method="POST", url_suffix=API_ENDPOINTS["GET_MESSAGE_TOKEN"], json_data=req_data,
                                  resp_type="text", error_handler=error_handler)

    def quarantine_jobs_list(self, page: Optional[int], size: Optional[int], sort: str,
                             exclude_quarantine_emails: bool,
                             body: dict) -> Dict[str, Any]:
        """Get quarantine jobs.

        Args:
            page: Page offset to start listing quarantine jobs from.
            size: The number of results to retrieve per page.
            sort: The name-value pair defining the order of the response.
            exclude_quarantine_emails: Whether to remove or not remove quarantined emails from the response.
            body: Body to send in API call.

        Returns:
            Dict: Response from API.

        """
        query = f'?page={page}&size={size}&excludeQuarantineEmails={exclude_quarantine_emails}&{sort}'
        return self._http_request(method="POST", url_suffix=API_ENDPOINTS["GET_QUARANTINE_JOBS"] + query,
                                  json_data=body, error_handler=error_handler)

    def delete_quarantine_job(self, job_id: str):
        """Delete the quarantine job specified by the user.

        Args:
            job_id: ID of the quarantine job to delete.
        """
        self._http_request(method="DELETE",
                           url_suffix=API_ENDPOINTS["QUARANTINE_JOB"] + "/" + str(job_id),
                           empty_valid_codes=[200], return_empty_response=True, error_handler=error_handler)

    def create_quarantine_job(self, requests_body: Dict[str, Any]) -> Dict[str, Any]:
        """Create a quarantine job using internet message id and recipient's address of emails.

        Args:
            requests_body(Dict[str, Any]): Required body parameter.

        Returns:
            Dict[str, Any]: Response from API.
        """
        headers = {"Content-Type": APPLICATION_JSON, **self._headers}
        return self._http_request(method="POST", url_suffix=API_ENDPOINTS["QUARANTINE_JOB"], headers=headers,
                                  json_data=requests_body, error_handler=error_handler)

    def create_search(self, requests_body: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new search based on user specified arguments.

        Args:
            requests_body(Dict[str, Any]): Required body parameter to create a search.

        Returns:
            Dict[str, Any]: Response from API.
        """
        return self._http_request(method="POST", url_suffix=API_ENDPOINTS["CREATE_MESSAGE_SEARCH"],
                                  json_data=requests_body, error_handler=error_handler)

    def get_search(self, search_id: int) -> Dict[str, Any]:
        """Get Search using search id provided by cofense vision.

        Args:
            search_id(int): search id provided by cofense vision.

        Returns:
            Dict[str, Any]: Response from API.
        """
        return self._http_request(method="GET", url_suffix=API_ENDPOINTS["GET_MESSAGE_SEARCH"].format(search_id),
                                  error_handler=error_handler)

    def restore_quarantine_job(self, id: str) -> None:
        """Restore the emails quarantined by the job identified by id.

        Args:
            id (str): The id of the quarantine job.
        """
        self._http_request(method="PUT", url_suffix=API_ENDPOINTS["RESTORE_QUARANTINE_JOB"].format(id),
                           return_empty_response=True, empty_valid_codes=(200,), error_handler=error_handler)

    def list_searches(self, page: int = None, size: int = None, sort: str = None) -> Dict[str, Any]:
        """List message searches.

        Args:
             page(int): Page offset to start listing quarantine jobs from.
             size(int): The number of results to retrieve per page.
             sort(str): The name-value pair defining the order of the response.

        Returns:
            Dict[str, Any]: Response from API.
        """
        query = f'?page={page}&size={size}&{sort}'
        return self._http_request(method="GET", url_suffix=API_ENDPOINTS["GET_ALL_SEARCHES"] + query,
                                  error_handler=error_handler)

    def get_quarantine_job(self, job_id: str) -> Dict[str, Any]:
        """Get the quarantine job with specified ID.

        Args:
            job_id: ID of an quarantine job.

        Returns:
            Dict: Response from API.
        """
        return self._http_request(method="GET", url_suffix=API_ENDPOINTS["QUARANTINE_JOB"] + "/" + str(job_id),
                                  error_handler=error_handler)

    def approve_quarantine_job(self, id: str, message_count: int = None) -> None:
        """Approve the quarantine job identified by its unique ID.

        Args:
            id (str): The unique ID of the quarantine job.
            message_count (int): The number of messages to approve.
        """
        params = assign_params(messageCount=message_count)
        self._http_request(method="PUT", url_suffix=API_ENDPOINTS["APPROVE_QUARANTINE_JOB"].format(id),
                           params=params, return_empty_response=True, empty_valid_codes=[200],
                           error_handler=error_handler)

    def get_search_results(self, search_id: int, page: int = None, size: int = None, sort: str = None) -> \
            Dict[str, Any]:
        """List message searches.

        Args:
             search_id(int): ID of the search to retrieve result.
             page(int): Page offset to start listing quarantine jobs from.
             size(int): The number of results to retrieve per page.
             sort(str): The name-value pair defining the order of the response.

        Returns:
            Dict[str, Any]: Response from API.
        """
        query = f'?page={page}&size={size}&{sort}'
        return self._http_request(method="GET",
                                  url_suffix=API_ENDPOINTS["GET_SEARCH_RESULTS"].format(search_id) + query,
                                  error_handler=error_handler)

    def delete_ioc(self, source, ioc_id):
        """Delete an IOC identified by hash value and specified source.

        Args:
            source: The source which ingested the IOC.
            ioc_id: ID as hash of the IOC to delete.

        Returns:
            Dict[str, Any]: Response from API.
        """
        headers = {"X-Cofense-IOC-Source": source, **self._headers}
        return self._http_request(method="DELETE", url_suffix=API_ENDPOINTS["IOC_REPOSITORY"] + "/" + str(ioc_id),
                                  headers=headers, error_handler=error_handler)

    def stop_quarantine_job(self, id: str) -> dict[str, Any]:
        """Stop the quarantine job identified by the given id.

        Args:
            id (str): ID of the quarantine job to be stopped.

        Returns:
            dict[str, Any]: Response from API.
        """
        return self._http_request(method="PUT", url_suffix=API_ENDPOINTS["STOP_QUARANTINE_JOB"].format(id),
                                  error_handler=error_handler)

    def get_last_ioc(self, source: str) -> Dict[str, Any]:
        """Get the last updated IOC from ioc-source.

        Args:
            source(str): IOC source to fetch last updated ioc.

        Returns:
            Dict[str, Any]: Response from API.
        """
        headers = {"X-Cofense-IOC-Source": source, **self._headers}
        return self._http_request(method="GET", url_suffix=API_ENDPOINTS["GET_LAST_IOC"], headers=headers,
                                  error_handler=error_handler)

    def update_iocs(self, source, body) -> Dict[str, Any]:
        """Update the IOC with specified source and ID.

        Args:
            source: Source of the IOC to update.
            body: The json_data to pass in API call.

        Returns:
            Dict: Response from API.
        """
        headers = {"Content-Type": APPLICATION_JSON, "X-Cofense-IOC-Source": source, **self._headers}
        return self._http_request(method="PUT", url_suffix=API_ENDPOINTS["IOC_REPOSITORY"], headers=headers,
                                  json_data=body, error_handler=error_handler)

    def update_ioc(self, md5_id, body) -> Dict[str, Any]:
        """Update the IOC with specified ID.

        Args:
            md5_id: ID as hash of the IOC to update.
            body: The json_data to pass in API call.

        Returns:
            Dict: Response from API.
        """
        headers = {"Content-Type": APPLICATION_JSON, **self._headers}
        return self._http_request(method="PUT", url_suffix=API_ENDPOINTS["IOC_REPOSITORY"] + "/" + str(md5_id),
                                  headers=headers, json_data=body, error_handler=error_handler)

    def list_iocs(self, source: str, page: int, size: int, include_expired: bool, since: Optional[str],
                  sort_string: Optional[str]) -> dict[str, Any]:
        """List the IOCs from the source given by the user.

        Args:
            source (str): The name of the source.
            page (int): The page offset to start listing IOCs from.
            size (int): The number of results to retrieve per page.
            include_expired (bool): Whether to include expired IOCs or not.
            since (str): List the IOCs added after this particular date.
            sort_string (str): The name-value pair defining the order of the response.

        Returns:
            (dict[str, Any]): Response from the API.
        """
        headers = {"X-Cofense-IOC-Source": source, **self._headers}
        query = f"?page={page}&size={size}&includeExpired={include_expired}"
        if since:
            query += f"&since={since}"
        if sort_string:
            query += f"&{sort_string}"
        return self._http_request(method="GET", url_suffix=API_ENDPOINTS["GET_IOCS"] + query, headers=headers,
                                  error_handler=error_handler)

    def get_ioc(self, source, ioc_id):
        """Get an IOC identified by hash value.

        Args:
            source: The source which ingested the IOC.
            ioc_id: ID as hash of the IOC.

        Returns:
            Dict[str, Any]: Response from API.
        """
        headers = {"X-Cofense-IOC-Source": source, **self._headers}
        return self._http_request(method="GET", url_suffix=API_ENDPOINTS["IOC_REPOSITORY"] + "/" + str(ioc_id),
                                  headers=headers, error_handler=error_handler)

    def list_searchable_headers(self) -> Dict[str, Any]:
        """Get list of searchable header keys.

        Returns:
            Dict[str, Any]: Response from API.
        """
        return self._http_request(method="GET", url_suffix=API_ENDPOINTS["GET_SEARCHABLE_HEADERS"],
                                  error_handler=error_handler)


""" HELPER FUNCTIONS """


def trim_spaces_from_args(args: Dict) -> Dict:
    """Trim spaces from values of the args dict.

    Args:
        args(Dict): Dict to trim spaces from.

    Returns:
        Dict: Arguments after trim spaces.
    """
    for key, val in args.items():
        if isinstance(val, str):
            args[key] = val.strip()

    return args


def error_handler(response: Response):
    """Error Handler function.

    Args:
         response(Response): Response object from API.
    """
    err_msg = 'Error in API call [{}].'.format(response.status_code)
    try:
        error_entry = response.json()
        if response.status_code == 401:
            err_msg += '\n{} : {}.'.format(error_entry.get('error'), error_entry.get('error_description'))
        else:
            err_msg += '\n{} : {}.'.format(error_entry.get('status'), ". ".join(error_entry.get('details', [])))
        raise DemistoException(err_msg, res=response)
    except ValueError:
        err_msg += '\n{}'.format(response.text)
        raise DemistoException(err_msg, res=response)


def arg_to_list_with_filter_null_values(argument: Optional[Any]) -> List:
    """Filter Null values from and convert string of args to python list.

    Args:
        argument: Argument provided by user.

    Returns:
        List: List of arguments.
    """
    list_of_args: List = list(filter(None, argToList(argument)))
    return list(filter(None, arg_to_list(list_of_args)))


def arg_to_list(argument: Optional[Any]) -> List:
    """Convert a string representation of args to a python list.

    Args:
        argument: Argument provided by user.

    Returns:
        List: List of arguments.
    """
    list_of_args = argToList(argument)
    arguments = []
    arg = ""

    for argument in list_of_args:
        if argument and isinstance(argument, str):
            if argument[-1] != '\\':
                arguments.append(arg + argument)
                arg = ""
            else:
                arg += argument.replace('\\', ',')
        else:
            arguments.append(argument)
    if arg:
        arguments.append(arg)
    return arguments


def validate_required_parameters(**kwargs) -> None:
    """
    Raise an error for a required parameter.

    Enter your required parameters as keyword arguments to check
    whether they hold a value or not.

    Args:
        **kwargs: keyword arguments to check the required values for.

    Raises:
        ValueError: if the value of the parameter is "", [], (), {}, None.
    """
    for key, value in kwargs.items():
        if not value:
            raise ValueError(ERROR_MESSAGE["MISSING_REQUIRED_PARAM"].format(key))


def validate_quarantine_job_id(id: str):
    """
    Validate the quarantine job id.

    Checks whether the provided id is a valid non-zero positive integer number or not.

    Args:
        id (str): Quarantine job id to validate.

    Raises:
        ValueError: If job id is negative or zero integer number.
    """
    validate_required_parameters(id=id)

    if arg_to_number(id, arg_name="id") <= 0:  # type: ignore
        raise ValueError(ERROR_MESSAGE["INVALID_QUARANTINE_JOB_PARAM"].format("id"))


def validate_params_for_attachment_get(md5: Optional[str] = None, sha256: Optional[str] = None):
    """Validate arguments for cofense-message-attachment-get command.

    Args:
        md5(Optional[str]): MD5 hash of attachment file.
        sha256(Optional[str]): SHA256 hash of an attachment.
    """
    if not md5 and not sha256:
        raise ValueError(ERROR_MESSAGE['INVALID_REQUIRED_PARAMETER_HASH'])
    if md5 and get_hash_type(md5) != 'md5':
        raise ValueError(ERROR_MESSAGE['INVALID_ARGUMENT'].format(md5, 'md5 hash'))
    if sha256 and get_hash_type(sha256) != 'sha256':
        raise ValueError(ERROR_MESSAGE['INVALID_ARGUMENT'].format(sha256, 'sha256 hash'))


def escape_special_characters(hr_dict: Dict) -> Dict:
    """Escape special characters to show in hr output.

    Args:
        hr_dict(Dict): Dictionary of human-readable response.

    Returns:
        Dict: human-readable response with escaped special characters.
    """
    hr_output = {}
    for key, value in hr_dict.items():
        if isinstance(value, str):
            hr_output[key] = "".join(
                ["\\" + str(char) if char in SPECIAL_CHARACTERS_MARKDOWN else str(char) for char in value])
        elif isinstance(value, list):
            hr_output[key] = []  # type: ignore
            for element in value:
                hr_output[key].append("".join(  # type: ignore
                    ["\\" + str(char) if char in SPECIAL_CHARACTERS_MARKDOWN else str(char) for char in element]))
        else:
            hr_output[key] = value
    return hr_output


def prepare_hr_for_message_metadata_get(message: Dict[str, Any]) -> str:
    """Prepare Human Readable for cofense-message-metadata-get command.

    Args:
        message(Dict[str, Any]: Message response from API.

    Returns:
        str: Human readable output.
    """
    hr_outputs = escape_special_characters({
        "ID": message.get('id'),
        "Subject": message.get('subject'),
        RECEIVED_ON: None if not message.get('receivedOn') else arg_to_datetime(
            message.get('receivedOn')).strftime(HR_DATE_FORMAT),  # type: ignore
        SENT_ON: None if not message.get('sentOn') else arg_to_datetime(
            message.get('sentOn')).strftime(HR_DATE_FORMAT),  # type: ignore
        "Delivered On": None if not message.get('deliveredOn') else arg_to_datetime(
            message.get('deliveredOn')).strftime(HR_DATE_FORMAT),  # type: ignore
        "Processed On": None if not message.get('processedOn') else arg_to_datetime(
            message.get('processedOn')).strftime(HR_DATE_FORMAT),  # type: ignore
        "Sender": [sender.get('address') for sender in message.get('from', [])],
        "Recipients": [recipient.get('address') for recipient in message.get('recipients', [])],
        "MD5": message.get('md5'),
        "SHA1": message.get('sha1'),
        "SHA256": message.get('sha256'),
        INTERNET_MESSAGE_ID: message.get('internetMessageId'),
        MATCHING_IOCS: message.get('matchingIOCs'),
        MATCHING_SOURCES: message.get('matchingSources')
    })

    headers = ["ID", "Subject", RECEIVED_ON, SENT_ON, "Delivered On", "Processed On", "Sender", "Recipients",
               "MD5", "SHA1", "SHA256", INTERNET_MESSAGE_ID, MATCHING_IOCS, MATCHING_SOURCES]

    return tableToMarkdown("Message Metadata:", hr_outputs, headers=headers, removeNull=True)


def prepare_hr_for_message_token_get(response: Dict[str, Any]) -> str:
    """Prepare human-readable string for cofense-message-token-get command.

    Args:
      response (Dict[str, Any]): Response from the command function.

    Returns:
      str: Human readable string.
    """
    hr_outputs = escape_special_characters({
        INTERNET_MESSAGE_ID: response.get("internetMessageId"),
        "Recipient's Address": response.get("recipient", {}).get("address"),
        "Token": response.get("token"),
    })

    headers = [INTERNET_MESSAGE_ID, "Recipient's Address", "Token"]

    return tableToMarkdown("One-time token:", hr_outputs, headers=headers, removeNull=True)


def validate_sort(sort_list: list, command: str):
    """Check for valid property name and sort order.

    Args:
        sort_list(List): List of PropertyName:Order for sorting results.
        command(str): Command name for sort.
    """
    for sort_by in sort_list:
        # Checking whether the format is correct or not.
        if len(list(filter(None, sort_by.split(':')))) != 2:
            sort_by = sort_by if sort_by else "None"
            raise ValueError(ERROR_MESSAGE['INVALID_FORMAT'].format(sort_by, 'sort',
                                                                    SUPPORTED_SORT_FORMAT_FOR_IOCS_LIST
                                                                    if command == "iocs_list"
                                                                    else SUPPORTED_SORT_FORMAT))

        property_name, sort_order = sort_by.split(':')

        # Checking whether the property name and sort order values are correct or not.
        if (property_name[0].lower() + property_name[1:]) not in SUPPORTED_SORT[command]:
            message = ERROR_MESSAGE["UNSUPPORTED_FIELD_FOR_IOCS_LIST"] if command == "iocs_list" else ERROR_MESSAGE[
                "UNSUPPORTED_FIELD"]

            raise ValueError(
                message.format(property_name, 'property name', 'property name', ', '.join(SUPPORTED_SORT[command])))

        if sort_order.lower() not in SUPPORTED_SORT['order_by']:
            raise ValueError(
                ERROR_MESSAGE['UNSUPPORTED_FIELD'].format(sort_order, 'sort order', 'sort order',
                                                          ', '.join(SUPPORTED_SORT['order_by'])))


def validate_page_size(page_size: Optional[int]):
    """Validate that page size parameter is in numeric format or not.

    Args:
        page_size: This value will be checked to be numeric and within range.
    """
    if not page_size or not str(page_size).isdigit() or int(page_size) <= 0 or int(page_size) > MAX_PAGE_SIZE:
        raise ValueError(ERROR_MESSAGE["INVALID_PAGE_SIZE_RANGE"])


def prepare_sort_query(sort_list: list, command: str) -> str:
    """Prepare sort query for list commands.

    Args:
        sort_list: List of PropertyName:Order for sorting results.
        command(str): Command name for sort.

    Returns:
        str: sort query to append in url.
    """
    validate_sort(sort_list, command)
    sort_by = ''
    for sort_property_order in sort_list:
        sort_by += 'sort=' + sort_property_order + '&'

    sort_by = sort_by[:-1]
    sort_by = sort_by.replace(':', ',')
    return sort_by


def prepare_hr_for_message_searches_list(response: Dict[str, Any]) -> str:
    """Prepare Human Readable for cofense-message-searches-list command.

    Args:
        response(Dict[str, Any]: Message response from API.

    Returns:
        str: Human readable output.
    """
    hr_output = []

    for search in response.get('searches', []):
        received_before_date = None if not response.get('receivedBeforeDate') else arg_to_datetime(
            response.get('receivedBeforeDate')).strftime(HR_DATE_FORMAT)  # type: ignore
        received_after_date = None if not response.get('receivedAfterDate') else arg_to_datetime(
            response.get('receivedAfterDate')).strftime(HR_DATE_FORMAT)  # type: ignore

        date_range = ""
        if received_after_date:
            date_range = date_range + f"From: {received_after_date}\n"
        if received_before_date:
            date_range = date_range + f"To: {received_before_date}"

        hr_output.append(escape_special_characters({
            "ID": search.get('id'),
            CREATED_BY: search.get('createdBy'),
            CREATED_DATE: None if not search.get('createdDate') else arg_to_datetime(
                search.get('createdDate')).strftime(HR_DATE_FORMAT),  # type: ignore
            MODIFIED_BY: search.get('modifiedBy'),
            MODIFIED_DATE: None if not search.get('modifiedDate') else arg_to_datetime(
                search.get('modifiedDate')).strftime(HR_DATE_FORMAT),  # type: ignore
            "Senders": search.get('senders'),
            "Recipient": search.get('recipient'),
            "Subjects": search.get('subjects'),
            ATTACHMENT_FILE_NAMES: search.get('attachmentNames'),
            INCLUDED_MIME_TYPES: search.get('attachmentMimeTypes'),
            EXCLUDED_MIME_TYPES: search.get('attachmentExcludeMimeTypes'),
            HASH_TYPE: [f"{attachmentHashes.get('hashType')}-{attachmentHashes.get('hashString')}" for
                        attachmentHashes
                        in search.get('attachmentHashCriteria', {}).get('attachmentHashes', [])],
            "Domains": search.get('domainCriteria', {}).get('domains'),
            WHITELIST_URLS: search.get('domainCriteria', {}).get('whiteListUrls'),
            DATE_RANGE: date_range,
            "URL": search.get('url'),
            HEADERS: [f"{header.get('key')}: {header.get('values')}" for header in
                      search.get('headers', [])],
            INTERNET_MESSAGE_ID: search.get('internetMessageId'),
            PARTIAL_INGEST: search.get('partialIngest')
        }))

    headers = ["ID", CREATED_BY, CREATED_DATE, MODIFIED_BY, MODIFIED_DATE, "Senders", "Recipient",
               "Subjects", ATTACHMENT_FILE_NAMES, INCLUDED_MIME_TYPES, EXCLUDED_MIME_TYPES, HASH_TYPE,
               "Domains", WHITELIST_URLS, DATE_RANGE, "URL", HEADERS, INTERNET_MESSAGE_ID,
               PARTIAL_INGEST]

    return tableToMarkdown("Message Searches:", hr_output, headers, removeNull=True)


def prepare_body_for_qurantine_jobs_list_command(args: Dict[str, Any]) -> Dict:
    """Prepare body to be passed in API request for cofense_quarantine_jobs_list_command.

    Args:
        args: Arguments provided by user.

    Returns:
        Dict: Body for API request.

    """
    filter_options = {}
    if args.get('auto_quarantine'):
        filter_options["autoQuarantine"] = argToBoolean(args.get('auto_quarantine'))

    if args.get('include_status'):
        filter_options["includeStatus"] = arg_to_list(args.get('include_status'))
        for status in filter_options["includeStatus"]:
            if status not in STATUS:
                raise ValueError(
                    ERROR_MESSAGE['UNSUPPORTED_FIELD'].format(status, 'status', 'status', ', '.join(STATUS)))

    if args.get('exclude_status'):
        filter_options["excludeStatus"] = arg_to_list(args.get('exclude_status'))
        for status in filter_options["excludeStatus"]:
            if status not in STATUS:
                raise ValueError(
                    ERROR_MESSAGE['UNSUPPORTED_FIELD'].format(status, 'status', 'status', ', '.join(STATUS)))

    if args.get('iocs'):
        filter_options["iocs"] = arg_to_list(args.get('iocs'))

    if args.get('modified_date_after'):
        filter_options["modifiedDateAfter"] = arg_to_datetime(args.get('modified_date_after'),
                                                              arg_name='modified_date_after')
        filter_options["modifiedDateAfter"] = filter_options["modifiedDateAfter"].strftime(DATE_FORMAT)  # type: ignore

    if args.get('sources'):
        filter_options["sources"] = arg_to_list(args.get('sources'))

    return {'filterOptions': filter_options}


def prepare_hr_for_quarantine_jobs_list(response: Dict[str, Any]) -> str:
    """Prepare Human Readable for cofense-quarantine_jobs_list command.

    Args:
        response: Message response from API.

    Returns:
        str: Human readable output.
    """
    hr_outputs = []
    for quarantine_job in response.get('quarantineJobs', []):
        hr_outputs.append(escape_special_characters({
            "ID": quarantine_job.get('id'),
            SEARCH_ID: quarantine_job.get('searchId'),
            CREATED_BY: quarantine_job.get('createdBy'),

            CREATED_DATE: None if not quarantine_job.get('createdDate') else arg_to_datetime(
                quarantine_job.get('createdDate')).strftime(HR_DATE_FORMAT),  # type: ignore

            LAST_MODIFIED_BY: quarantine_job.get('modifiedBy'),

            LAST_MODIFIED_DATE: None if not quarantine_job.get('modifiedDate') else arg_to_datetime(
                quarantine_job.get('modifiedDate')).strftime(HR_DATE_FORMAT),  # type: ignore

            LAST_ACTION: quarantine_job.get('quarantineJobRuns', [])[-1].get('jobRunType'),
            "Status": quarantine_job.get('quarantineJobRuns', [])[-1].get('status'),

            COMPLETED_DATE: None if not quarantine_job.get('quarantineJobRuns', [])[-1].get('completedDate')
            else arg_to_datetime(quarantine_job.get('quarantineJobRuns', [])[-1]
                                 .get('completedDate')).strftime(HR_DATE_FORMAT),  # type: ignore

            "Messages": quarantine_job.get('emailCount'),
            MATCHING_IOCS: quarantine_job.get('matchingIOCs'),
            MATCHING_SOURCES: quarantine_job.get('matchingSources')
        }))

    headers = ["ID", SEARCH_ID, CREATED_BY, CREATED_DATE, LAST_MODIFIED_BY, LAST_MODIFIED_DATE, LAST_ACTION,
               "Status", COMPLETED_DATE, "Messages", MATCHING_IOCS, MATCHING_SOURCES]

    return tableToMarkdown("Quarantine Job:", hr_outputs, headers=headers, removeNull=True)


def prepare_requests_body_for_quarantine_job_create(quarantine_emails: List) -> Dict[str, Any]:
    """Prepare requests body for cofence-quarantine-job-create command.

    Args:
        quarantine_emails(List): List of quarantine emails for job creation.

    Returns:
        Dict[str, Any]: Returns prepared requests body.
    """
    data = []

    for email in quarantine_emails:
        if len(list(filter(None, email.split(":")))) != 2:
            raise ValueError(ERROR_MESSAGE['INVALID_FORMAT'].format(
                email, "quarantine_emails", SUPPORTED_QUARANTINE_EMAILS_FORMAT
            ))
        data.append({
            "recipientAddress": email.split(":")[1].strip(),
            "internetMessageId": email.split(":")[0].strip()
        })

    return {"quarantineEmails": data}


def prepare_hr_for_quarantine_job_create(response: Dict[str, Any]) -> str:
    """Prepare Human Readable for cofence-quarantine-job-create command.

    Args:
        response(Dict[str, Any]): Response from API.

    Returns:
        str: Human readable output.
    """
    hr_outputs = escape_special_characters({
        "ID": response.get('id'),
        CREATED_BY: response.get('createdBy'),
        CREATED_DATE: None if not response.get('createdDate') else arg_to_datetime(
            response.get('createdDate')).strftime(HR_DATE_FORMAT),  # type: ignore
        LAST_MODIFIED_BY: response.get('modifiedBy'),
        LAST_MODIFIED_DATE: None if not response.get('modifiedDate') else arg_to_datetime(
            response.get('modifiedDate')).strftime(HR_DATE_FORMAT),  # type: ignore
        "Messages": response.get('emailCount'),
        MATCHING_IOCS: response.get('matchingIOCs'),
        MATCHING_SOURCES: response.get('matchingSources'),
        SEARCH_ID: response.get('searchId')
    })

    headers = ["ID", SEARCH_ID, CREATED_BY, CREATED_DATE, LAST_MODIFIED_BY, LAST_MODIFIED_DATE, "Messages",
               MATCHING_IOCS, MATCHING_SOURCES]

    heading = "Quarantine job create:\n#### Quarantine job has been created successfully."

    return tableToMarkdown(heading, hr_outputs, headers=headers, removeNull=True)


def prepare_hr_for_ioc_delete(response: Dict[str, Any]) -> str:
    """Prepare Human Readable for cofence-ioc-delete command.

    Args:
        response(Dict[str, Any]: Response from API.

    Returns:
        str: Human readable output.
    """
    hr_outputs = escape_special_characters({
        "ID": response.get('id'),
        THREAT_TYPE: response.get('attributes', {}).get('threat_type'),
        THREAT_VALUE: response.get('attributes', {}).get('threat_value'),
        "Action Status": "Success"
    })

    headers = ['ID', THREAT_TYPE, THREAT_VALUE, 'Action Status']
    heading = ' IOC with value "{}" has been deleted successfully.'.format(hr_outputs["ID"])

    return tableToMarkdown(heading, hr_outputs, headers=headers, removeNull=True)


def validate_search_id(search_id: Optional[int]):
    """Validate Cofense Search ID.

    Args:
        search_id(Optional[int]): ID assigned by cofense vision.
    """
    validate_required_parameters(id=search_id)
    if arg_to_number(search_id, arg_name="id") <= 0:  # type: ignore
        raise ValueError(ERROR_MESSAGE['INVALID_SEARCH_ID'])


def prepare_hr_for_message_search_get(response: Dict[str, Any]) -> str:
    """Prepare Human Readable output for cofense-message-search-get commnad.

    Args:
        response(Dict[str, Any]): Response from API.

    Returns:
        str: Human readable output.
    """
    received_before_date = None if not response.get('receivedBeforeDate') else arg_to_datetime(
        response.get('receivedBeforeDate')).strftime(HR_DATE_FORMAT)  # type: ignore
    received_after_date = None if not response.get('receivedAfterDate') else arg_to_datetime(
        response.get('receivedAfterDate')).strftime(HR_DATE_FORMAT)  # type: ignore

    date_range = ""
    if received_after_date:
        date_range = date_range + f"From: {received_after_date}\n"
    if received_before_date:
        date_range = date_range + f"To: {received_before_date}"

    hr_outputs = escape_special_characters({
        "ID": response.get('id'),
        CREATED_BY: response.get('createdBy'),
        CREATED_DATE: None if not response.get('createdDate') else arg_to_datetime(
            response.get('createdDate')).strftime(HR_DATE_FORMAT),  # type: ignore
        MODIFIED_BY: response.get('modifiedBy'),
        MODIFIED_DATE: None if not response.get('modifiedDate') else arg_to_datetime(
            response.get('modifiedDate')).strftime(HR_DATE_FORMAT),  # type: ignore
        "Senders": response.get('senders'),
        "Recipient": response.get('recipient'),
        "Subjects": response.get('subjects'),
        ATTACHMENT_FILE_NAMES: response.get('attachmentNames'),
        INCLUDED_MIME_TYPES: response.get('attachmentMimeTypes'),
        EXCLUDED_MIME_TYPES: response.get('attachmentExcludeMimeTypes'),
        HASH_TYPE: [f"{attachmentHashes.get('hashType')}-{attachmentHashes.get('hashString')}" for attachmentHashes
                    in response.get('attachmentHashCriteria', {}).get('attachmentHashes', [])],
        "Domains": response.get('domainCriteria', {}).get('domains'),
        WHITELIST_URLS: response.get('domainCriteria', {}).get('whiteListUrls'),
        DATE_RANGE: date_range,
        "URL": response.get('url'),
        HEADERS: [f"{header.get('key')}: {header.get('values')}" for header in response.get('headers', [])],
        INTERNET_MESSAGE_ID: response.get('internetMessageId'),
        PARTIAL_INGEST: response.get('partialIngest')
    })

    headers = ["ID", CREATED_BY, CREATED_DATE, MODIFIED_BY, MODIFIED_DATE, "Senders", "Recipient",
               "Subjects", ATTACHMENT_FILE_NAMES, INCLUDED_MIME_TYPES, EXCLUDED_MIME_TYPES, HASH_TYPE,
               "Domains", WHITELIST_URLS, DATE_RANGE, "URL", HEADERS, INTERNET_MESSAGE_ID,
               PARTIAL_INGEST]

    return tableToMarkdown("Message Search:", hr_outputs, headers, removeNull=True)


def prepare_hr_for_quarantine_job_get(response: Dict[str, Any]) -> str:
    """Prepare Human Readable for cofense-quarantine_jobs_get command.

    Args:
        response: Message response from API.

    Returns:
        str: Human readable output.
    """
    hr_outputs = escape_special_characters({
        "ID": response.get('id'),
        SEARCH_ID: response.get('searchId'),
        CREATED_BY: response.get('createdBy'),

        CREATED_DATE: None if not response.get('createdDate') else arg_to_datetime(
            response.get('createdDate')).strftime(HR_DATE_FORMAT),  # type: ignore

        LAST_MODIFIED_BY: response.get('modifiedBy'),

        LAST_MODIFIED_DATE: None if not response.get('modifiedDate') else arg_to_datetime(
            response.get('modifiedDate')).strftime(HR_DATE_FORMAT),  # type: ignore

        LAST_ACTION: response.get('quarantineJobRuns', [])[-1].get('jobRunType'),
        "Status": response.get('quarantineJobRuns', [])[-1].get('status'),

        COMPLETED_DATE: None if not response.get('quarantineJobRuns', [])[-1].get(
            'completedDate') else arg_to_datetime(
            response.get('quarantineJobRuns', [])[-1].get('completedDate')).strftime(HR_DATE_FORMAT),  # type: ignore

        "Messages": response.get('emailCount'),
        MATCHING_IOCS: response.get('matchingIOCs'),
        MATCHING_SOURCES: response.get('matchingSources')
    })

    headers = ["ID", SEARCH_ID, CREATED_BY, CREATED_DATE, LAST_MODIFIED_BY, LAST_MODIFIED_DATE, LAST_ACTION,
               "Status", COMPLETED_DATE, "Messages", MATCHING_IOCS, MATCHING_SOURCES]

    return tableToMarkdown("Quarantine Job:", hr_outputs, headers=headers, removeNull=True)


def prepare_hr_for_quarantine_job_delete(job_id: str) -> str:
    """Prepare Human Readable for cofense-quarantine-job-delete command.

    Args:
        job_id: ID of the quarantine job that is deleted.

    Returns:
        str: Human readable output.
    """
    return "## Quarantine Job with ID {} is successfully deleted.".format(job_id)


def prepare_context_for_message_search_results_get_command(response: Dict[str, Any]) -> Dict[str, Any]:
    """Prepare context data for cofense-message-search-results-get command.

    Args:
        response(Dict[str, Any]): Response from API.

    Returns:
        Dict[str, Any]: Context data.
    """
    context_data = {
        "Message": response.get('messages', []),
        **response.get('search', {})
    }
    return remove_empty_elements(context_data)


def prepare_hr_for_message_search_results_get_command(response: Dict[str, Any]) -> str:
    """Prepare Human Readable for cofense-message-search-results-get command.

    Args:
        response(Dict[str, Any]): Response from API.

    Returns:
        str: Human readable output.
    """
    search = response.get('search', {})
    hr_outputs_results = []

    for message in response.get('messages', []):
        attachments = []
        for attachment in message.get('attachments', []):
            attachments.append(f"File Name: {attachment.get('filename')}\n"
                               f"MD5: {attachment.get('md5')}\nSHA256: {attachment.get('sha256')}")
        hr_output_results = (escape_special_characters({
            "Database ID": message.get('id'),
            INTERNET_MESSAGE_ID: message.get('internetMessageId'),
            "Subject": message.get('subject'),
            SENT_ON: None if not message.get('sentOn') else arg_to_datetime(
                message.get('sentOn')).strftime(HR_DATE_FORMAT),  # type: ignore
            RECEIVED_ON: None if not message.get('receivedOn') else arg_to_datetime(
                message.get('receivedOn')).strftime(HR_DATE_FORMAT),  # type: ignore
            "Sender": [sender.get('address') for sender in message.get('from', [])],
            "Recipient": [recipient.get('address') for recipient in message.get('recipients', [])]
        }))

        hr_output_results["Attachments"] = "\n\n\n".join(attachments)
        hr_outputs_results.append(hr_output_results)

    headers_for_results = ["Database ID", INTERNET_MESSAGE_ID, "Subject", SENT_ON, RECEIVED_ON, "Sender", "Recipient",
                           "Attachments"]

    return prepare_hr_for_message_search_get(search) + '\n' + tableToMarkdown("Message Search Results:",
                                                                              hr_outputs_results, headers_for_results,
                                                                              removeNull=True)


def prepare_hr_for_quarantine_job_stop(response: dict[str, Any]) -> str:
    """Prepare human-readable string for cofense-quarantine-job-stop command.

    Args:
        response (dict[str, Any]): Response from the API.

    Returns:
        str: Human-readable markdown string.
    """
    created_date = response.get('createdDate')
    modified_date = response.get('modifiedDate')
    completed_date = response.get('quarantineJobRuns', [])[-1].get('completedDate')

    if created_date:
        created_date = arg_to_datetime(created_date).strftime(HR_DATE_FORMAT)  # type: ignore

    if modified_date:
        modified_date = arg_to_datetime(modified_date).strftime(HR_DATE_FORMAT)  # type: ignore

    if completed_date:
        completed_date = arg_to_datetime(completed_date).strftime(HR_DATE_FORMAT)  # type: ignore

    hr_output = escape_special_characters({
        "ID": response.get('id'),
        CREATED_BY: response.get('createdBy'),
        CREATED_DATE: created_date,
        LAST_MODIFIED_BY: response.get('modifiedBy'),
        LAST_MODIFIED_DATE: modified_date,
        LAST_ACTION: response.get('quarantineJobRuns', [])[-1].get('jobRunType'),
        "Status": response.get('quarantineJobRuns', [])[-1].get('status'),
        COMPLETED_DATE: completed_date,
        "Messages": response.get('emailCount'),
        MATCHING_IOCS: response.get('matchingIOCs'),
        MATCHING_SOURCES: response.get('matchingSources'),
        "Stopped Quarantine": response.get('stopRequested')
    })
    headers = ["ID", CREATED_BY, CREATED_DATE, LAST_MODIFIED_BY, LAST_MODIFIED_DATE, LAST_ACTION,
               "Status", COMPLETED_DATE, "Messages", MATCHING_IOCS, MATCHING_SOURCES, "Stopped Quarantine"]

    title = f"Quarantine job with ID {response.get('id')} has been successfully stopped."

    return tableToMarkdown(title, hr_output, headers=headers, removeNull=True)


def validate_create_search_parameter_allowed_search_length(**kwargs: Optional[List]):
    """Validate search values length should not be greater than three.

    Args:
        kwargs(Optional[List]): Dictionary of arguments for validating it's length.
    """
    for key, value in kwargs.items():
        if len(value) > 3:  # type: ignore
            raise ValueError(ERROR_MESSAGE['INVALID_SEARCH_LENGTH'].format(key))


def validate_arguments_for_message_search_create(**kwargs):
    """Validate Arguments for cofense-message-search-create command.

    Args:
        kwargs: Dictionary of arguments for validation.
    """
    validate_create_search_parameter_allowed_search_length(subjects=kwargs.get("subjects"),
                                                           senders=kwargs.get("senders"),
                                                           attachment_names=kwargs.get("attachment_names"),
                                                           attachment_hashes=kwargs.get("attachment_hashes"),
                                                           attachment_mime_types=kwargs.get("attachment_mime_types"),
                                                           attachment_exclude_mime_types=kwargs.get(
                                                               "attachment_exclude_mime_types"),
                                                           domains=kwargs.get("domains"),
                                                           whitelist_urls=kwargs.get("whitelist_urls"),
                                                           headers=kwargs.get("headers"))

    # validate supported options for attachment_hash_criteria
    attachment_hash_criteria = kwargs.get('attachment_hash_criteria', 'ANY')
    if attachment_hash_criteria.upper() not in SUPPORTED_CRITERIA:
        raise ValueError(
            ERROR_MESSAGE['UNSUPPORTED_FIELD'].format(attachment_hash_criteria, 'attachment_hash_match_criteria',
                                                      'attachment_hash_match_criteria', SUPPORTED_CRITERIA))

    # validate supported options for domain_match_criteria
    domain_match_criteria = kwargs.get('domain_match_criteria', 'ANY')
    if domain_match_criteria.upper() not in SUPPORTED_CRITERIA:
        raise ValueError(
            ERROR_MESSAGE['UNSUPPORTED_FIELD'].format(domain_match_criteria, 'domain_match_criteria',
                                                      'domain_match_criteria', SUPPORTED_CRITERIA))

    # validate attachment_hashes format
    attachment_hashes = kwargs.get('attachment_hashes', [])
    for attachment_hash in attachment_hashes:
        if len(list(filter(None, attachment_hash.split(':')))) != 2:
            raise ValueError(
                ERROR_MESSAGE['INVALID_FORMAT'].format(attachment_hash, 'attachment_hashes',
                                                       SUPPORTED_HASH_VALUE_FORMAT))

        hash_type = attachment_hash.split(':')[0]
        hash_value = attachment_hash.split(':')[1]
        if hash_type.upper() not in SUPPORTED_HASH:
            raise ValueError(ERROR_MESSAGE['UNSUPPORTED_FIELD'].format(hash_type, 'hash', 'hash', SUPPORTED_HASH))
        if hash_type.lower() != get_hash_type(hash_value):
            raise ValueError(ERROR_MESSAGE['INVALID_ARGUMENT'].format(hash_value, hash_type))

    # validate headers format
    headers = kwargs.get('headers', [])
    for header in headers:
        if len(list(filter(None, header.split(":")))) < 2:
            raise ValueError(ERROR_MESSAGE['INVALID_FORMAT'].format(header, 'headers', SUPPORTED_HEADERS_FORMAT))


def prepare_requests_body_for_message_search_create(**kwargs) -> Dict[str, Any]:
    """Prepare required body parameter for cofense-message-search-create command.

    Args:
        kwargs: Arguments to prepare request body.

    Returns:
        Dict[str, Any]: Required body parameter.
    """
    attachment_hashes = []
    for attachment_hash in kwargs.get('attachment_hashes', []):
        attachment_hashes.append({
            "hashType": attachment_hash.split(":", 1)[0].upper(),
            "hashString": attachment_hash.split(":", 1)[1]
        })

    attachment_hash_criteria = {
        "type": kwargs.get('attachment_hash_match_criteria', 'ANY').upper(),
        "attachmentHashes": attachment_hashes
    }

    domain_criteria = {
        "type": kwargs.get('domain_match_criteria', 'ANY').upper(),
        "domains": kwargs.get('domains'),
        "whiteListUrls": kwargs.get('whitelist_urls')
    }

    headers = []
    for header in kwargs.get('headers', []):
        headers.append({
            "key": header.split(':', 1)[0],
            "values": argToList(header.split(':', 1)[1], ':')
        })

    return assign_params(subjects=kwargs.get('subjects'), senders=kwargs.get('senders'),
                         attachmentNames=kwargs.get('attachment_names'),
                         attachmentHashCriteria=attachment_hash_criteria,
                         attachmentMimeTypes=kwargs.get('attachment_mime_types'),
                         attachmentExcludeMimeTypes=kwargs.get('attachment_exclude_mime_types'),
                         domainCriteria=domain_criteria, headers=headers,
                         internetMessageId=kwargs.get('internet_message_id'),
                         partialIngest=kwargs.get('partial_ingest'),
                         receivedAfterDate=kwargs.get('received_after_date'),
                         receivedBeforeDate=kwargs.get('received_before_date'),
                         recipient=kwargs.get('recipient'), url=kwargs.get('url'))


def prepare_hr_for_message_search_create_command(response: Dict[str, Any]) -> str:
    """Prepare Human Readable output for cofense-message-search-create command.

    Args:
        response: Response from API.

    Returns:
        str: Human readable output.
    """
    received_before_date = None if not response.get('receivedBeforeDate') else arg_to_datetime(
        response.get('receivedBeforeDate')).strftime(HR_DATE_FORMAT)  # type: ignore
    received_after_date = None if not response.get('receivedAfterDate') else arg_to_datetime(
        response.get('receivedAfterDate')).strftime(HR_DATE_FORMAT)  # type: ignore

    date_range = ""
    if received_after_date:
        date_range = date_range + f"From: {received_after_date}\n"
    if received_before_date:
        date_range = date_range + f"To: {received_before_date}"

    hr_outputs = escape_special_characters({
        "ID": response.get('id'),
        CREATED_BY: response.get('createdBy'),
        CREATED_DATE: None if not response.get('createdDate') else arg_to_datetime(
            response.get('createdDate')).strftime(HR_DATE_FORMAT),  # type: ignore
        MODIFIED_BY: response.get('modifiedBy'),
        MODIFIED_DATE: None if not response.get('modifiedDate') else arg_to_datetime(
            response.get('modifiedDate')).strftime(HR_DATE_FORMAT),  # type: ignore
        "Senders": response.get('senders'),
        "Recipient": response.get('recipient'),
        "Subjects": response.get('subjects'),
        ATTACHMENT_FILE_NAMES: response.get('attachmentNames'),
        INCLUDED_MIME_TYPES: response.get('attachmentMimeTypes'),
        EXCLUDED_MIME_TYPES: response.get('attachmentExcludeMimeTypes'),
        HASH_TYPE: [f"{attachmentHashes.get('hashType')}-{attachmentHashes.get('hashString')}" for attachmentHashes
                    in response.get('attachmentHashCriteria', {}).get('attachmentHashes', [])],
        "Domains": response.get('domainCriteria', {}).get('domains'),
        WHITELIST_URLS: response.get('domainCriteria', {}).get('whiteListUrls'),
        DATE_RANGE: date_range,
        "URL": response.get('url'),
        HEADERS: [f"{header.get('key')}: {header.get('values')}" for header in response.get('headers', [])],
        INTERNET_MESSAGE_ID: response.get('internetMessageId'),
        PARTIAL_INGEST: response.get('partialIngest')
    })

    headers = ["ID", CREATED_BY, CREATED_DATE, MODIFIED_BY, MODIFIED_DATE, "Senders", "Recipient",
               "Subjects", ATTACHMENT_FILE_NAMES, INCLUDED_MIME_TYPES, EXCLUDED_MIME_TYPES, HASH_TYPE,
               "Domains", WHITELIST_URLS, DATE_RANGE, "URL", HEADERS, INTERNET_MESSAGE_ID,
               PARTIAL_INGEST]

    heading = f"Message search with ID {response.get('id')} has been created successfully."

    return tableToMarkdown(heading, hr_outputs, headers, removeNull=True)


def prepare_hr_for_last_ioc_get_command(response: Dict[str, Any]) -> str:
    """Prepare Human Readable for cofence-last-updated-ioc-get command.

    Args:
        response(Dict[str, Any]): Response from API.

    Returns:
        str: Human readable output.
    """
    data = response.get('data', {})
    metadata = data.get('metadata', {}).get('quarantine', {})

    hr_outputs = escape_special_characters({
        "ID": data.get('id'),
        THREAT_TYPE: data.get('attributes', {}).get('threat_type'),
        THREAT_VALUE: data.get('attributes', {}).get('threat_value'),
        CREATED_AT: None if not metadata.get('created_at') else arg_to_datetime(
            metadata.get('created_at')).strftime(HR_DATE_FORMAT),  # type: ignore
        EXPIRES_AT: None if not metadata.get('expires_at') else arg_to_datetime(
            metadata.get('expires_at')).strftime(HR_DATE_FORMAT),  # type: ignore
        MATCH_COUNT: metadata.get('match_count'),
        QUARANTINE_COUNT: metadata.get('quarantine_count'),
        FIRST_QUARANTINED_AT: None if not metadata.get('first_quarantined_at') else arg_to_datetime(
            metadata.get('first_quarantined_at')).strftime(HR_DATE_FORMAT),  # type: ignore
        LAST_QUARANTINE_AT: None if not metadata.get('last_quarantined_at') else arg_to_datetime(
            metadata.get('last_quarantined_at')).strftime(HR_DATE_FORMAT),  # type: ignore
    })

    headers = ["ID", THREAT_TYPE, THREAT_VALUE, CREATED_AT, EXPIRES_AT, MATCH_COUNT, QUARANTINE_COUNT,
               FIRST_QUARANTINED_AT, LAST_QUARANTINE_AT]

    return tableToMarkdown("Last IOC:", hr_outputs, headers, removeNull=True)


def prepare_and_validate_body_for_iocs_update(request_body: List) -> Dict[str, Any]:
    """Prepare and validate body parameters to be passed in API request for cofense_iocs_update_command.

    Args:
        request_body(List): Request body parameter passed by user.

    Returns:
        Dict: Body for API request.
    """
    data = []
    for body in request_body:
        threat_type = body.get('threat_type')
        if threat_type and threat_type.lower() not in THREAT_TYPES:
            raise ValueError(
                ERROR_MESSAGE['UNSUPPORTED_FIELD'].format(threat_type, 'threat type', 'threat type', THREAT_TYPES))

        threat_value = body.get('threat_value')
        threat_level = body.get('threat_level')
        source_id = body.get('source_id')

        created_at = body.get('created_at')
        if created_at:
            created_at = arg_to_datetime(created_at, arg_name='created_at').strftime(DATE_FORMAT)  # type: ignore

        updated_at = body.get('updated_at')
        if updated_at:
            updated_at = arg_to_datetime(updated_at, arg_name='updated_at').strftime(DATE_FORMAT)  # type: ignore
        else:
            updated_at = datetime.now().strftime(DATE_FORMAT)

        requested_expiration = body.get('requested_expiration')
        if requested_expiration:
            requested_expiration = arg_to_datetime(requested_expiration,
                                                   arg_name='requested_expiration').strftime(  # type: ignore
                DATE_FORMAT)

        validate_required_parameters(threat_type=threat_type, threat_value=threat_value,
                                     threat_level=threat_level, source_id=source_id, created_at=created_at,
                                     updated_at=updated_at)

        updated_ioc = {
            "type": "ioc",
            "attributes": {
                "threat_type": threat_type,
                "threat_value": threat_value
            },
            "metadata": {
                "source": {
                    "threat_level": threat_level,
                    "id": source_id,
                    "requested_expiration": requested_expiration,
                    "created_at": created_at,
                    "updated_at": updated_at
                },
            }
        }
        data.append(remove_empty_elements(updated_ioc))

    return {"data": data}


def prepare_body_for_ioc_update(expires_at: str) -> Dict[str, Any]:
    """Prepare body to be passed in API request for cofense_ioc_update_command.

    Args:
        expires_at: Expiration date and time.

    Returns:
        Dict: Body for API request.
    """
    updated_iocs = {
        "type": "ioc",
        "metadata": {
            "quarantine": {
                "expires_at": expires_at
            },
        }
    }
    return {"data": updated_iocs}


def prepare_hr_for_update_iocs(response: Dict) -> str:
    """Prepare Human Readable for cofense-iocs-update command.

    Args:
        response: Message response from API.

    Returns:
        str: Human readable output.
    """
    threat_value = response.get('attributes', {}).get('threat_value')
    threat_level = response.get('metadata', {}).get('source', {}).get('threat_level')
    hr_outputs = escape_special_characters({
        "ID": response.get('id'),
        THREAT_TYPE: response.get('attributes', {}).get('threat_type'),
        THREAT_VALUE: threat_value,
        THREAT_LEVEL: threat_level,

        CREATED_AT: None if not response.get('metadata', {}).get('source', {}).get(
            'created_at') else arg_to_datetime(response.get('metadata', {}).get(
                'source', {}).get('created_at')).strftime(HR_DATE_FORMAT),  # type: ignore

        UPDATED_AT: None if not response.get('metadata', {}).get('source', {}).get(
            'updated_at') else arg_to_datetime(response.get('metadata', {}).get(
                'source', {}).get('updated_at')).strftime(HR_DATE_FORMAT),  # type: ignore

        "Requested Expiration": arg_to_datetime(
            response.get('metadata', {}).get('source', {}).get(
                'requested_expiration')).strftime(HR_DATE_FORMAT)  # type: ignore
    })

    headers = ["ID", THREAT_TYPE, THREAT_VALUE, THREAT_LEVEL, CREATED_AT, UPDATED_AT, "Requested Expiration"]

    return tableToMarkdown("IOC {} updated successfully.".format(response.get('id')), hr_outputs, headers=headers,
                           removeNull=True)


def prepare_hr_for_update_ioc(response: Dict[str, Any]) -> str:
    """Prepare Human Readable for cofense-ioc-update command.

    Args:
        response: Message response from API.

    Returns:
        str: Human readable output.
    """
    ioc_id = response.get('id')
    threat_value = response.get('attributes', {}).get('threat_value')
    hr_output = (escape_special_characters({
        "ID": response.get('id'),
        THREAT_TYPE: response.get('attributes', {}).get('threat_type'),
        THREAT_VALUE: threat_value,

        CREATED_AT: None if not response.get('metadata', {}).get('quarantine', {}).get(
            'created_at') else arg_to_datetime(response.get('metadata', {}).get(
                'quarantine', {}).get('created_at')).strftime(HR_DATE_FORMAT),  # type: ignore

        EXPIRES_AT: None if not response.get('metadata', {}).get('quarantine', {}).get(
            'expires_at') else arg_to_datetime(response.get('metadata', {}).get(
                'quarantine', {}).get('expires_at')).strftime(HR_DATE_FORMAT),  # type: ignore
    }))

    headers = ["ID", THREAT_TYPE, THREAT_VALUE, CREATED_AT, EXPIRES_AT]

    return tableToMarkdown(f"IOC with value {ioc_id} has been updated successfully.", hr_output,
                           headers=headers, removeNull=True)


def prepare_hr_for_get_ioc(response: Dict[str, Any]) -> str:
    """Prepare Human Readable for cofense-ioc-get command.

    Args:
        response: Message response from API.

    Returns:
        str: Human readable output.
    """
    threat_value = response.get('attributes', {}).get('threat_value')
    hr_output = (escape_special_characters({
        "ID": response.get('id'),
        THREAT_TYPE: response.get('attributes', {}).get('threat_type'),
        THREAT_VALUE: threat_value,

        CREATED_AT: None if not response.get('metadata', {}).get('quarantine', {}).get(
            'created_at') else arg_to_datetime(response.get('metadata', {}).get(
                'quarantine', {}).get('created_at')).strftime(HR_DATE_FORMAT),  # type: ignore

        EXPIRES_AT: None if not response.get('metadata', {}).get('quarantine', {}).get(
            'expires_at') else arg_to_datetime(response.get('metadata', {}).get(
                'quarantine', {}).get('expires_at')).strftime(HR_DATE_FORMAT),  # type: ignore
    }))

    headers = ["ID", THREAT_TYPE, THREAT_VALUE, CREATED_AT, EXPIRES_AT]

    return tableToMarkdown("IOC:", hr_output, headers=headers, removeNull=True)


def validate_arguments_for_iocs_list(source: str, page: Optional[int], size: Optional[int]) -> None:
    """Validate arguments for cofense-iocs-list command.

    Args:
        source (str): The name of the source.
        page (Optional[int]): page offset to start listing quarantine jobs from.
        size (Optional[int]): The number of results to retrieve per page.
    """
    validate_required_parameters(source=source)
    validate_page_size(page_size=size)

    if int(page) < 0:  # type: ignore
        raise ValueError(ERROR_MESSAGE["INVALID_PAGE_VALUE"])


def prepare_hr_for_iocs_list(response: dict[str, Any]) -> str:
    """Prepare human-readable string for cofense-iocs-list command.

    Args:
        response (dict[str, Any]): Response from the API.

    Returns:
        str: Human-readable markdown string for cofense-iocs-list command.
    """
    created_at = response.get("metadata", {}).get("source", {}).get("created_at")
    expires_at = response.get("metadata", {}).get("source", {}).get("expires_at")
    updated_at = response.get("metadata", {}).get("source", {}).get("updated_at")
    first_quarantined_at = response.get("metadata", {}).get("quarantine", {}).get("first_quarantined_at")
    last_quarantined_at = response.get("metadata", {}).get("quarantine", {}).get("last_quarantined_at")

    if created_at:
        created_at = arg_to_datetime(created_at).strftime(HR_DATE_FORMAT)  # type: ignore

    if expires_at:
        expires_at = arg_to_datetime(expires_at).strftime(HR_DATE_FORMAT)  # type: ignore

    if updated_at:
        updated_at = arg_to_datetime(updated_at).strftime(HR_DATE_FORMAT)  # type: ignore

    if first_quarantined_at:
        first_quarantined_at = arg_to_datetime(first_quarantined_at).strftime(HR_DATE_FORMAT)  # type: ignore

    if last_quarantined_at:
        last_quarantined_at = arg_to_datetime(last_quarantined_at).strftime(HR_DATE_FORMAT)  # type: ignore

    hr_outputs = escape_special_characters({
        "ID": response.get("id"),
        THREAT_TYPE: response.get("attributes", {}).get("threat_type"),
        THREAT_VALUE: response.get('attributes', {}).get('threat_value'),
        THREAT_LEVEL: response.get("metadata", {}).get("source", {}).get("threat_level"),
        UPDATED_AT: updated_at,
        CREATED_AT: created_at,
        EXPIRES_AT: expires_at,
        MATCH_COUNT: response.get("metadata", {}).get("quarantine", {}).get("match_count"),
        QUARANTINE_COUNT: response.get("metadata", {}).get("quarantine", {}).get("quarantine_count"),
        FIRST_QUARANTINED_AT: first_quarantined_at,
        LAST_QUARANTINE_AT: last_quarantined_at
    })

    headers = ["ID", THREAT_TYPE, THREAT_VALUE, THREAT_LEVEL, UPDATED_AT, CREATED_AT, EXPIRES_AT,
               MATCH_COUNT, QUARANTINE_COUNT, FIRST_QUARANTINED_AT, LAST_QUARANTINE_AT]

    return tableToMarkdown("IOC:", hr_outputs, headers, removeNull=True)


def get_standard_context(client: VisionClient, ioc: Dict) -> Optional[Common.Indicator]:
    """Get the standard context for IOC.

    Args:
        client(VisionClient): VisionClient to be used.
        ioc(Dict): ioc details returned from API.

    Returns:
        Optional[Common.Indicator]: Standard context.
    """
    if not ioc or not ioc.get('id'):
        return None

    ioc = remove_empty_elements(ioc)

    threat_type = ioc.get('attributes', {}).get('threat_type', '').lower()
    threat_value = ioc.get('attributes', {}).get('threat_value', '')

    threat_level = ioc.get("metadata", {}).get("source", {}).get("threat_level")
    score = 0
    if threat_level:
        if threat_level.lower() in client.threat_levels_bad:
            score = 3
        elif threat_level.lower() in client.threat_levels_suspicious:
            score = 2
        elif threat_level.lower() in client.threat_levels_good:
            score = 1

    dbot_score = Common.DBotScore(
        indicator=ioc['id'],
        indicator_type=IOC_TYPES[threat_type],
        integration_name='Cofense Vision',
        score=score
    )
    if threat_type == "url":
        return Common.URL(
            url=threat_value,
            dbot_score=dbot_score
        )
    elif threat_type == "domain":
        return Common.Domain(
            domain=threat_value,
            dbot_score=dbot_score
        )
    elif threat_type == "sender":
        return Common.EMAIL(
            address=threat_value,
            dbot_score=dbot_score
        )
    elif threat_type == "md5":
        return Common.File(
            md5=threat_value,
            dbot_score=dbot_score
        )
    elif threat_type == "sha256":
        return Common.File(
            sha256=threat_value,
            dbot_score=dbot_score
        )
    return None


""" COMMAND FUNCTIONS """


def test_module(client: VisionClient) -> str:
    """Tests API connectivity and authentication.

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.

    Raises:
     exceptions if something goes wrong.

    Args:
        client (VisionClient): client to use for testing.

    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    client.list_searches(size=2)
    return "ok"


def cofense_message_metadata_get_command(client: VisionClient, args: Dict[str, Any]) -> CommandResults:
    """Retrieve the full content of a message.

    Args:
        client(VisionClient): VisionClient to be used.
        args(Dict[str, Any]): Arguments provided by user.

    Returns:
        CommandResults: Standard Command Result.
    """
    internet_message_id = args.get('internet_message_id', '')
    recipient_address = args.get('recipient_address', '')

    response = client.get_message_metadata(internet_message_id, recipient_address)
    hr_output = prepare_hr_for_message_metadata_get(remove_empty_elements(response))

    return CommandResults(
        outputs_prefix="Cofense.Message",
        outputs_key_field="id",
        outputs=remove_empty_elements(response),
        readable_output=hr_output,
        raw_response=response,
    )


def cofense_message_get_command(client: VisionClient, args: Dict[str, Any]) -> Dict:
    """Fetch full content of an email and returns a zip file of an email using a token.

    Args:
        client(VisionClient): VisionClient to be used.
        args(Dict[str, Any]): Arguments provided by user.

    Returns:
        Dict: A Demisto war room entry.
    """
    token = args.get('token', '')

    response = client.get_message(token)
    return fileResult(filename='message.zip', data=response.content)


def cofense_message_attachment_get_command(client: VisionClient, args: Dict[str, Any]) -> Dict:
    """Fetch an attachment by using its MD5 or SHA256 hash and returns the attachment.

    Args:
        client(VisionClient): VisionClient to be used.
        args(Dict[str, Any]): Arguments provided by user.

    Returns:
        Dict: A Demisto war room entry.
    """
    file_name = args.get('file_name')
    md5 = args.get('md5')
    sha256 = args.get('sha256')

    validate_required_parameters(file_name=file_name, md5=md5)

    validate_params_for_attachment_get(md5, sha256)

    response = client.get_attachment(md5, sha256)

    return fileResult(filename=file_name, data=response.content)


def cofense_message_token_get_command(client: VisionClient, args: dict[str, str]) -> CommandResults:
    """
    Command function for cofense-message-token-get command.

    Retrieve the one time token required for getting the message from the Cofense API.

    Args:
        client (VisionClient): The client object to be used for API call.
        args (dict[str, str]): The arguments required for the command.

    Returns:
        CommandResults: Standard CommandResults object.
    """
    internet_message_id: str = args.get("internet_message_id", "")
    recipient_address: str = args.get("recipient_address", "")
    password: str = args.get("password", "")

    validate_required_parameters(internet_message_id=internet_message_id, recipient_address=recipient_address)

    token = client.get_message_token(
        internet_message_id=internet_message_id, recipient_address=recipient_address, password=password
    )

    context_data = {
        "token": token,
        "internetMessageId": internet_message_id,
        "recipient": {
            "address": recipient_address
        },
    }

    hr_output = prepare_hr_for_message_token_get(response=context_data)

    return CommandResults(
        outputs_prefix="Cofense.Message",
        outputs=remove_empty_elements(context_data),
        outputs_key_field="internetMessageId",
        readable_output=hr_output,
    )


def cofense_quarantine_job_get_command(client: VisionClient, args: dict[str, Any]) -> CommandResults:
    """
    Retrieve quarantine job identified by its unique ID.

    Args:
        client (VisionClient): The client object to be used for API call.
        args (dict[str, str]): The arguments required for the command.

    Returns:
        CommandResults: Standard CommandResults object.
    """
    job_id = args.get('id', '')
    validate_quarantine_job_id(id=job_id)

    response = client.get_quarantine_job(job_id=job_id)

    hr_output = prepare_hr_for_quarantine_job_get(response)

    return CommandResults(
        outputs_prefix=QUARANTINE_JOB_OUTPUT_PREFIX,
        outputs_key_field="id",
        outputs=remove_empty_elements(response),
        readable_output=hr_output,
        raw_response=response,
    )


def cofense_quarantine_jobs_list_command(client: VisionClient, args: Dict[str, Any]) -> CommandResults:
    """Filter and return a paginated list of matching quarantine jobs.

    Args:
        client: VisionClient to be used.
        args: Arguments provided by user.

    Returns:
        CommandResults: Standard Command Result.
    """
    exclude_quarantine_emails = argToBoolean(args.get('exclude_quarantine_emails', False))

    page = arg_to_number(args.get('page', 0))
    if int(page) < 0:  # type: ignore
        raise ValueError(ERROR_MESSAGE['INVALID_PAGE_VALUE'])

    size = arg_to_number(args.get('size', 50))
    validate_page_size(size)

    sort = prepare_sort_query(arg_to_list(args.get('sort', DEFAULT_SORT_VALUE)), 'quarantine_jobs_list')

    body = prepare_body_for_qurantine_jobs_list_command(args)

    response = client.quarantine_jobs_list(
        page=page, size=size, sort=sort, exclude_quarantine_emails=exclude_quarantine_emails, body=body)

    hr_output = prepare_hr_for_quarantine_jobs_list(response)

    return CommandResults(
        outputs_prefix=QUARANTINE_JOB_OUTPUT_PREFIX,
        outputs_key_field="id",
        outputs=remove_empty_elements(response.get('quarantineJobs')),
        readable_output=hr_output,
        raw_response=response,
    )


def cofense_quarantine_job_create_command(client: VisionClient, args: Dict[str, Any]) -> CommandResults:
    """Create a new quarantine job using internet message id and recipient's address.

    Args:
        client(VisionClient): VisionClient to be used.
        args(Dict[str, Any]): Arguments provided by user.

    Returns:
        CommandResults: Standard command result.
    """
    quarantine_emails: List = arg_to_list_with_filter_null_values(args.get('quarantine_emails'))
    validate_required_parameters(quarantine_emails=quarantine_emails)
    requests_body = prepare_requests_body_for_quarantine_job_create(quarantine_emails)

    response = client.create_quarantine_job(requests_body)

    hr_output = prepare_hr_for_quarantine_job_create(remove_empty_elements(response))

    return CommandResults(
        outputs_prefix=QUARANTINE_JOB_OUTPUT_PREFIX,
        outputs_key_field="id",
        outputs=remove_empty_elements(response),
        readable_output=hr_output,
        raw_response=response,
    )


def cofense_message_search_results_get_command(client: VisionClient, args: Dict[str, Any]) -> CommandResults:
    """Retrieve list of paginated search results.

    Args:
        client(VisionClient): VisionClient to be used.
        args(Dict[str, Any]): Arguments provided by user.

    Returns:
        CommandResults: Standard CommandResults object.
    """
    search_id = args.get('id', '')
    validate_search_id(search_id)

    page = arg_to_number(args.get('page', 0), arg_name='page')
    size = arg_to_number(args.get('size', 50), arg_name='size')

    if int(page) < 0:  # type: ignore
        raise ValueError(ERROR_MESSAGE['INVALID_PAGE_VALUE'])
    validate_page_size(size)

    sort = prepare_sort_query(arg_to_list(args.get('sort', DEFAULT_SORT_VALUE)), "message_search_result_get")

    response = client.get_search_results(search_id=search_id, page=page, size=size, sort=sort)
    context_data = prepare_context_for_message_search_results_get_command(response)
    hr_output = prepare_hr_for_message_search_results_get_command(remove_empty_elements(response))

    return CommandResults(
        outputs_prefix=SEARCH_OUTPUT_PREFIX,
        outputs_key_field="id",
        outputs=context_data,
        readable_output=hr_output,
        raw_response=response,
    )


def cofense_message_searches_list_command(client: VisionClient, args: Dict[str, Any]) -> CommandResults:
    """Retrieve list of paginated search results.

    Args:
        client(VisionClient): VisionClient to be used.
        args(Dict[str, Any]): Arguments provided by user.

    Returns:
        CommandResults: Standard CommandResults object.
    """
    page = arg_to_number(args.get('page', 0), arg_name='page')
    size = arg_to_number(args.get('size', 50), arg_name='size')

    if int(page) < 0:  # type: ignore
        raise ValueError(ERROR_MESSAGE['INVALID_PAGE_VALUE'])
    validate_page_size(size)

    sort = prepare_sort_query(arg_to_list(args.get('sort', DEFAULT_SORT_VALUE)), "message_searches_list")

    response = client.list_searches(page=page, size=size, sort=sort)
    hr_output = prepare_hr_for_message_searches_list(remove_empty_elements(response))

    return CommandResults(
        outputs_prefix=SEARCH_OUTPUT_PREFIX,
        outputs_key_field="id",
        outputs=remove_empty_elements(response.get('searches')),
        readable_output=hr_output,
        raw_response=response,
    )


def cofense_quarantine_job_restore_command(client: VisionClient, args: Dict[str, Any]) -> CommandResults:
    """Restore emails quarantined by the job identified by its ID.

    Args:
        client (VisionClient): VisionClient to be used.
        args (Dict[str, Any]): Arguments provided by user.

    Returns:
        CommandResults: Standard command result object.
    """
    job_id = args.get("id", "")
    validate_quarantine_job_id(id=job_id)

    client.restore_quarantine_job(id=job_id)

    context_data = {
        "id": job_id,
        "isRestored": True
    }

    hr_output = f"## Emails quarantined by the quarantine job ID {job_id} have been successfully restored."

    return CommandResults(
        outputs_prefix=QUARANTINE_JOB_OUTPUT_PREFIX,
        outputs=remove_empty_elements(context_data),
        outputs_key_field="id",
        readable_output=hr_output
    )


def cofense_message_search_get_command(client: VisionClient, args: Dict[str, Any]) -> CommandResults:
    """Retrieve the search identified by id.

    Args:
        client(VisionClient): VisionClient to be used.
        args(Dict[str, Any]): Arguments provided by user.

    Returns:
        CommandResults: Standard CommandResults object.
    """
    search_id = args.get("id", "")
    validate_search_id(search_id)

    response = client.get_search(search_id)
    hr_output = prepare_hr_for_message_search_get(remove_empty_elements(response))

    return CommandResults(
        outputs_prefix=SEARCH_OUTPUT_PREFIX,
        outputs_key_field="id",
        outputs=remove_empty_elements(response),
        readable_output=hr_output,
        raw_response=response,
    )


def cofense_quarantine_job_approve_command(client: VisionClient, args: dict[str, str]) -> CommandResults:
    """Approve the quarantine job identified by its unique ID.

    Args:
        client (VisionClient): Client object to be used.
        args (dict[str, str]): Arguments provided by the user.

    Returns:
        CommandResults: Standard command results object
    """
    job_id = args.get("id", "")
    message_count = arg_to_number(args.get("message_count", ""), arg_name="message_count")

    # Validate arguments (id and message_count)
    validate_quarantine_job_id(id=job_id)
    if message_count is not None and message_count <= 0:
        raise ValueError(ERROR_MESSAGE["INVALID_QUARANTINE_JOB_PARAM"].format("message_count"))

    client.approve_quarantine_job(id=job_id, message_count=message_count)

    context_data = {
        "id": job_id,
        "isApproved": True
    }

    hr_output = f"## Quarantine Job with ID {job_id} has been approved successfully."

    return CommandResults(
        outputs_prefix=QUARANTINE_JOB_OUTPUT_PREFIX,
        outputs_key_field="id",
        outputs=remove_empty_elements(context_data),
        readable_output=hr_output,
    )


def cofense_quarantine_job_delete_command(client: VisionClient, args: Dict[str, Any]) -> CommandResults:
    """Delete the quarantine job identified by its unique ID.

    Args:
        client(VisionClient): VisionClient to be used.
        args(Dict[str, Any]): Arguments provided by user.

    Returns:
        CommandResults: Standard Command Result.
    """
    job_id = args.get('id', '')
    validate_quarantine_job_id(id=job_id)

    client.delete_quarantine_job(job_id)

    response = {
        "id": job_id,
        "isDeleted": True
    }

    hr_output = prepare_hr_for_quarantine_job_delete(job_id)

    return CommandResults(
        outputs_prefix=QUARANTINE_JOB_OUTPUT_PREFIX,
        outputs_key_field="id",
        outputs=response,
        readable_output=hr_output,
        raw_response=''
    )


def cofense_ioc_delete_command(client: VisionClient, args: Dict[str, Any]) -> CommandResults:
    """Delete a single active or expired IOC from the local IOC Repository.

    Args:
        client(VisionClient): VisionClient to be used.
        args(Dict[str, Any]): Arguments provided by user.

    Returns:
        CommandResults: Standard command result.
    """
    source = args.get('source')
    ioc_id = args.get('id')
    validate_required_parameters(source=source, id=ioc_id)

    response = client.delete_ioc(source, ioc_id)

    if response:
        response = {
            'deleted': True,
            **response.get('data', {})
        }

    hr_output = prepare_hr_for_ioc_delete(response)

    return CommandResults(
        outputs_prefix=IOC_OUTPUT_PREFIX,
        outputs=remove_empty_elements(response),
        readable_output=hr_output,
        raw_response=response,
        outputs_key_field="id",
        indicator=get_standard_context(client, response)
    )


def cofense_quarantine_job_stop_command(client: VisionClient, args: dict[str, Any]) -> CommandResults:
    """Stop a quarantine job identified by its unique ID.

    Args:
        client (VisionClient): client object to be used.
        args (dict[str, Any]): arguments provided by the user.

    Returns: Standard command results.

    """
    job_id = args.get("id", "")

    validate_quarantine_job_id(id=job_id)

    response = client.stop_quarantine_job(id=job_id)

    hr_output = prepare_hr_for_quarantine_job_stop(response=response)

    return CommandResults(
        outputs_prefix=QUARANTINE_JOB_OUTPUT_PREFIX,
        outputs_key_field="id",
        outputs=remove_empty_elements(response),
        raw_response=response,
        readable_output=hr_output
    )


def cofense_message_search_create_command(client: VisionClient, args: Dict[str, Any]) -> CommandResults:
    """Create a search based on user specified arguments.

    Args:
        client(VisionClient): VisionClient to be used.
        args(Dict[str, Any]): Arguments provided by user.

    Returns:
        CommandResults: Standard command result.
    """
    subjects: List = arg_to_list_with_filter_null_values(args.get('subjects'))
    senders: List = arg_to_list_with_filter_null_values(args.get('senders'))
    attachment_names: List = arg_to_list_with_filter_null_values(args.get('attachment_names'))
    attachment_hash_criteria: str = args.get('attachment_hash_match_criteria', 'ANY')
    attachment_hashes: List = arg_to_list_with_filter_null_values(args.get('attachment_hashes'))
    attachment_mime_types: List = arg_to_list_with_filter_null_values(args.get('attachment_mime_types'))
    attachment_exclude_mime_types: List = arg_to_list_with_filter_null_values(args.get('attachment_exclude_mime_types'))
    domain_match_criteria: str = args.get('domain_match_criteria', 'ANY')
    domains: List = arg_to_list_with_filter_null_values(args.get('domains'))
    whitelist_urls: List = arg_to_list_with_filter_null_values(args.get('whitelist_urls'))
    headers: List = arg_to_list_with_filter_null_values(args.get('headers'))
    internet_message_id = args.get('internet_message_id')
    partial_ingest: bool = argToBoolean(args.get('partial_ingest', False))
    received_after_date = args.get('received_after_date')
    received_before_date = args.get('received_before_date')
    recipient = args.get('recipient')
    url = args.get('url')

    if received_after_date:
        received_after_date = arg_to_datetime(received_after_date, arg_name='received_after_date')
        received_after_date = received_after_date.strftime(DATE_FORMAT)  # type: ignore

    if received_before_date:
        received_before_date = arg_to_datetime(received_before_date, arg_name='received_before_date')
        received_before_date = received_before_date.strftime(DATE_FORMAT)  # type: ignore

    validate_arguments_for_message_search_create(subjects=subjects, senders=senders,
                                                 attachment_names=attachment_names,
                                                 attachment_hashes=attachment_hashes,
                                                 attachment_hash_criteria=attachment_hash_criteria,
                                                 domain_match_criteria=domain_match_criteria,
                                                 attachment_mime_types=attachment_mime_types,
                                                 attachment_exclude_mime_types=attachment_exclude_mime_types,
                                                 domains=domains, whitelist_urls=whitelist_urls,
                                                 headers=headers)

    body = prepare_requests_body_for_message_search_create(subjects=subjects, senders=senders,
                                                           attachment_names=attachment_names,
                                                           attachment_hash_match_criteria=attachment_hash_criteria,
                                                           attachment_hashes=attachment_hashes,
                                                           attachment_mime_types=attachment_mime_types,
                                                           attachment_exclude_mime_types=attachment_exclude_mime_types,
                                                           domain_match_criteria=domain_match_criteria,
                                                           domains=domains, whitelist_urls=whitelist_urls,
                                                           headers=headers, internet_message_id=internet_message_id,
                                                           partial_ingest=partial_ingest,
                                                           received_after_date=received_after_date,
                                                           received_before_date=received_before_date,
                                                           recipient=recipient, url=url)

    response = client.create_search(body)
    hr_output = prepare_hr_for_message_search_create_command(remove_empty_elements(response))

    return CommandResults(
        outputs_prefix=SEARCH_OUTPUT_PREFIX,
        outputs_key_field="id",
        outputs=remove_empty_elements(response),
        readable_output=hr_output,
        raw_response=response,
    )


def cofense_last_ioc_get_command(client: VisionClient, args: Dict[str, Any]) -> CommandResults:
    """Synchronize the ioc source and returns last updated IOCs.

    Args:
        client(VisionClient): VisionClient to be used.
        args(Dict[str, Any]): Arguments provided by user.

    Returns:
        CommandResults: Standard command result.
    """
    ioc_source = args.get('source', '')
    validate_required_parameters(source=ioc_source)

    response = client.get_last_ioc(ioc_source)

    hr_output = prepare_hr_for_last_ioc_get_command(remove_empty_elements(response))

    return CommandResults(
        outputs_prefix=IOC_OUTPUT_PREFIX,
        outputs_key_field="id",
        outputs=remove_empty_elements(response.get('data')),
        readable_output=hr_output,
        raw_response=response,
        indicator=get_standard_context(client, response.get('data', {}))
    )


def cofense_iocs_update_command(client: VisionClient, args: dict[str, Any]) -> List[CommandResults]:
    """Update the IOCs stored in the local IOC repository.

    Args:
       client (VisionClient): Client object to be used.
       args (dict[str, str]): Arguments provided by the user.

    Returns:
       List[CommandResults]: Standard command results object
    """
    source = args.get('source')
    iocs_json = args.get('iocs_json')
    if not iocs_json:
        iocs_json = json.dumps([{
            "threat_type": args.get("threat_type"),
            "threat_value": args.get("threat_value"),
            "threat_level": args.get("threat_level"),
            "source_id": args.get("source_id"),
            "created_at": args.get("created_at"),
            "updated_at": args.get("updated_at"),
            "requested_expiration": args.get("requested_expiration")
        }])
    validate_required_parameters(iocs_json=iocs_json, source=source)

    try:
        iocs_json = json.loads(iocs_json)  # type: ignore
        if isinstance(iocs_json, dict):
            iocs_json = [iocs_json]
    except json.JSONDecodeError:
        raise ValueError('{} is an invalid JSON format'.format(iocs_json))

    body = prepare_and_validate_body_for_iocs_update(iocs_json)

    response = client.update_iocs(source, body)

    command_results = []
    for ioc in response.get('data', []):
        command_results.append(CommandResults(
            outputs_prefix=IOC_OUTPUT_PREFIX,
            outputs_key_field="id",
            outputs=remove_empty_elements(ioc),
            readable_output=prepare_hr_for_update_iocs(ioc),
            raw_response=ioc,
            indicator=get_standard_context(client, ioc)
        ))

    return command_results if command_results else CommandResults(  # type: ignore
        readable_output=tableToMarkdown("IOC:", [])
    )


def cofense_ioc_update_command(client: VisionClient, args: dict[str, Any]) -> CommandResults:
    """Update a single IOC stored in the local IOC repository.

    Args:
       client (VisionClient): Client object to be used.
       args (dict[str, str]): Arguments provided by the user.

    Returns:
       CommandResults: Standard command results object
    """
    md5_id = args.get('id')

    expires_at = args.get('expires_at')
    if expires_at:
        expires_at = arg_to_datetime(expires_at, arg_name='expires_at').strftime(DATE_FORMAT)  # type: ignore

    validate_required_parameters(id=md5_id, expires_at=expires_at)

    body = prepare_body_for_ioc_update(expires_at)  # type: ignore

    response = client.update_ioc(md5_id, body)

    response = response.get('data', {})

    hr_output = prepare_hr_for_update_ioc(response)  # type: ignore

    return CommandResults(
        outputs_prefix=IOC_OUTPUT_PREFIX,
        outputs_key_field="id",
        outputs=remove_empty_elements(response),
        readable_output=hr_output,
        raw_response=response,
        indicator=get_standard_context(client, response)
    )


def cofense_iocs_list_command(client: VisionClient, args: dict[str, Any]) -> List[CommandResults]:
    """List the IOCs.

    Args:
        client (VisionClient): client object to be used.
        args (dict[str, Any]): arguments provided by the user.

    Returns:
        List[CommandResults]: Standard command results.
    """
    source = args.get("source", "")
    page = arg_to_number(args.get("page", 0), arg_name="page")
    size = arg_to_number(args.get("size", 50), arg_name="size")
    validate_arguments_for_iocs_list(source=source, page=page, size=size)

    include_expired = argToBoolean(args.get("include_expired", False))
    since = args.get("since")
    sort = prepare_sort_query(arg_to_list(args.get("sort", "")), command="iocs_list")

    if since:
        since = arg_to_datetime(since, arg_name='since')
        since = since.strftime(DATE_FORMAT)  # type: ignore

    response = client.list_iocs(source=source, page=page, size=size, since=since,  # type: ignore
                                include_expired=include_expired, sort_string=sort)

    command_results = []
    for ioc in response.get('data', []):
        command_results.append(CommandResults(
            outputs_prefix=IOC_OUTPUT_PREFIX,
            outputs_key_field="id",
            outputs=remove_empty_elements(ioc),
            readable_output=prepare_hr_for_iocs_list(ioc),
            raw_response=ioc,
            indicator=get_standard_context(client, ioc)))

    return command_results if command_results else CommandResults(  # type: ignore
        readable_output=tableToMarkdown("IOC:", [])
    )


def cofense_ioc_get_command(client: VisionClient, args: dict[str, Any]) -> CommandResults:
    """Get a single IOC stored in the local IOC repository.

    Args:
       client (VisionClient): Client object to be used.
       args (dict[str, str]): Arguments provided by the user.

    Returns:
       CommandResults: Standard command results object
    """
    md5_id = args.get('id')
    source = args.get('source')

    validate_required_parameters(id=md5_id)

    response = client.get_ioc(source, md5_id)

    response = response.get('data', {})

    hr_output = prepare_hr_for_get_ioc(response)  # type: ignore

    return CommandResults(
        outputs_prefix=IOC_OUTPUT_PREFIX,
        outputs_key_field="id",
        outputs=remove_empty_elements(response),
        readable_output=hr_output,
        raw_response=response,
        indicator=get_standard_context(client, response)
    )


def cofense_searchable_headers_list_command(client: VisionClient):
    """Retrieve list of configured header keys which are available to create a search.

    Args:
        client(VisionClient): VisionClient to be used.

    Returns:
        CommandResults: Standard Command Result.
    """
    response = client.list_searchable_headers()

    hr_output = tableToMarkdown("Available headers to create a search:", {"Headers": response.get("headers")},
                                ["Headers"], removeNull=True)

    context_data = {
        "name": "searchableHeaders",
        "value": response.get('headers', [])
    }

    return CommandResults(
        outputs_prefix="Cofense.Config",
        outputs_key_field="name",
        outputs=context_data,
        readable_output=hr_output,
        raw_response=response
    )


def main():
    """Parse params and runs command functions."""
    params = demisto.params()

    base_url = params.get("url")
    client_id = params.get("credentials", {}).get("identifier").strip()
    client_secret = params.get("credentials", {}).get("password")
    verify_certificate = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))
    threat_levels_good = argToList(params.get('threat_levels_good', []))
    threat_levels_suspicious = argToList(params.get('threat_levels_suspicious', []))
    threat_levels_bad = argToList(params.get('threat_levels_bad', []))

    COFENSE_COMMANDS: Dict[str, Callable] = {
        'cofense-message-metadata-get': cofense_message_metadata_get_command,
        'cofense-message-get': cofense_message_get_command,
        'cofense-message-attachment-get': cofense_message_attachment_get_command,
        'cofense-message-token-get': cofense_message_token_get_command,
        'cofense-quarantine-jobs-list': cofense_quarantine_jobs_list_command,
        'cofense-quarantine-job-create': cofense_quarantine_job_create_command,
        'cofense-quarantine-job-restore': cofense_quarantine_job_restore_command,
        'cofense-message-searches-list': cofense_message_searches_list_command,
        'cofense-message-search-get': cofense_message_search_get_command,
        'cofense-quarantine-job-get': cofense_quarantine_job_get_command,
        'cofense-quarantine-job-approve': cofense_quarantine_job_approve_command,
        'cofense-quarantine-job-delete': cofense_quarantine_job_delete_command,
        'cofense-message-search-results-get': cofense_message_search_results_get_command,
        'cofense-ioc-delete': cofense_ioc_delete_command,
        'cofense-quarantine-job-stop': cofense_quarantine_job_stop_command,
        'cofense-message-search-create': cofense_message_search_create_command,
        'cofense-last-ioc-get': cofense_last_ioc_get_command,
        'cofense-iocs-update': cofense_iocs_update_command,
        'cofense-ioc-update': cofense_ioc_update_command,
        'cofense-iocs-list': cofense_iocs_list_command,
        'cofense-ioc-get': cofense_ioc_get_command,
    }

    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    try:
        client = VisionClient(
            base_url=base_url,
            client_id=client_id,
            client_secret=client_secret,
            verify=verify_certificate,
            proxy=proxy,
            threat_levels_good=threat_levels_good,
            threat_levels_suspicious=threat_levels_suspicious,
            threat_levels_bad=threat_levels_bad,
        )

        if command == "test-module":
            return_results(test_module(client))
        elif COFENSE_COMMANDS.get(command):
            args = demisto.args()
            remove_nulls_from_dictionary(trim_spaces_from_args(args))
            return_results(COFENSE_COMMANDS[command](client, args))
        elif command == 'cofense-searchable-headers-list':
            return_results(cofense_searchable_headers_list_command(client))
        else:
            raise NotImplementedError(f'Command {command} is not implemented')

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
