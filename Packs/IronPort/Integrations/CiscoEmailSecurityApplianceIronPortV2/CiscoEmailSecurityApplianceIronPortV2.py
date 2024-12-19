import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from collections.abc import Callable

import uuid
import ast

DEFAULT_FETCH = 50
TIMESTAMP_FORMAT = "%d %b %Y %H:%M:%S (%Z +00:00)"
QUARANTINE_TIMESTAMP_FORMAT = "%d %b %Y %H:%M (%Z +00:00)"

DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
CISCO_TIME_FORMAT = "%Y-%m-%dT%H:%M:00.000Z"
CISCO_REPORTING_TIME_FORMAT = "%Y-%m-%dT%H:00:00.000Z"

MIN_PAGE_NUMBER = 1
MIN_LIMIT = 1
MIN_PAGE_SIZE = 1
MAX_PAGE_SIZE = 100
REQUEST_MAX_PULL = 100

QUARANTINE_TYPE = "spam"
VIEW_ACTION = "view"
RELEASE_ACTION = "release"
ADD_ACTION = "add"
APPEND_ACTION = "append"
EDIT_ACTION = "edit"
DEFAULT_MODE_DICTIONARIES = 'cluster'


class Client(BaseClient):
    """Client class to interact with Cisco ESA API."""

    def __init__(
        self,
        server_url: str,
        username: str,
        password: str,
        verify: bool,
        proxy: bool,
        jwt_token_expiration_period: int = 30,
    ):
        super().__init__(base_url=server_url, headers={}, verify=verify, proxy=proxy)
        self.username = username
        self.password = password
        self.jwt_token_expiration_period = jwt_token_expiration_period
        self.handle_request_headers()

    def handle_request_headers(self, force_retrieve_jwt: bool = False):
        """Retrieve and save to integration context JWT token for authorized client class API requests."""
        integration_context = get_integration_context()
        jwt_token = integration_context.get("jwt_token")
        jwt_token_issued_time = integration_context.get("jwt_token_issued_time", 0.0)
        current_time = datetime.now().timestamp()
        next_refresh = (
            datetime.fromtimestamp(jwt_token_issued_time)
            + timedelta(minutes=self.jwt_token_expiration_period - 0.2)
        ).timestamp()
        if force_retrieve_jwt or not jwt_token or current_time > next_refresh:
            jwt_token = self.retrieve_jwt_token()
            set_integration_context(
                {"jwt_token": jwt_token, "jwt_token_issued_time": current_time}
            )
        self._headers["jwtToken"] = jwt_token

    def retrieve_jwt_token(self) -> str:
        """
        Retrieve JWT token from Cisco ESA.

        Returns:
            str: JWT token from Cisco ESA.
        """
        data = {
            "data": {
                "userName": b64_encode(self.username),
                "passphrase": b64_encode(self.password),
            }
        }
        try:
            response = super()._http_request("POST", "login", json_data=data)
            return dict_safe_get(response, ["data", "jwtToken"])

        except DemistoException as e:
            if e.res.status_code == 401:
                raise Exception(
                    "Authorization Error: make sure username and password are set correctly."
                ) from e
            raise e

    def _http_request(self, *args, **kwargs):
        try:
            return super()._http_request(*args, **kwargs)
        except DemistoException as e:
            if e.res.status_code == 401:
                self._session.cookies.clear()
                self.handle_request_headers(force_retrieve_jwt=True)
                return super()._http_request(*args, **kwargs)
            raise e

    def spam_quarantine_message_search_request(
        self,
        quarantine_type: str,
        start_date: str,
        end_date: str,
        offset: int,
        limit: int,
        filter_by: str = None,
        filter_operator: str = None,
        filter_value: str = None,
        recipient_filter_operator: str = None,
        recipient_filter_value: str = None,
        order_by: str = None,
        order_dir: str = None,
    ) -> Dict[str, Any]:
        """
        Search spam quarantine messages.

        Args:
            quarantine_type (str): Quarantine type.
            start_date (str): Start date in ISO format.
            end_date (str): End date in ISO format.
            offset (int): Offset of results to skip.
            limit (int): Limit of results to retrieve.
            filter_by (str, Optional): Filter by field.
                Required if filter_operator/filter_value are specified. Defaults to None.
            filter_operator (str, Optional): Filter operator.
                Required if filter_by/filter_value are specified. Defaults to None.
            filter_value (str, Optional): Filter value.
                Required if filter_by/filter_operator are specified. Defaults to None.
            recipient_filter_operator (str, Optional): Recipient filter operator.
                Required if recipient_filter_value is specified. Defaults to None.
            recipient_filter_value (str, Optional): Recipient address filter.
                Required if recipient_filter_operator is specified. Defaults to None.
            order_by (str, Optional): Results order by field.
                Required if order_dir is specified. Defaults to None.
            order_dir (str, Optional): Results order direction.
                Required if order_by is specified. Defaults to None.

        Returns:
            Dict[str, Any]: API response from Cisco ESA.
        """
        params = assign_params(
            quarantineType=quarantine_type,
            startDate=start_date,
            endDate=end_date,
            filterBy=filter_by,
            filterOperator=filter_operator,
            filterValue=filter_value,
            envelopeRecipientFilterOperator=recipient_filter_operator,
            envelopeRecipientFilterValue=recipient_filter_value,
            offset=offset,
            limit=limit,
            orderBy=order_by,
            orderDir=order_dir,
        )

        return self._http_request("GET", "quarantine/messages", params=params)

    def spam_quarantine_message_get_request(
        self, quarantine_type: str, message_id: str
    ) -> Dict[str, Any]:
        """
        Get spam quarantine message.

        Args:
            quarantine_type (str): Quarantine Type.
            message_id (str): Message ID.

        Returns:
            Dict[str, Any]: API response from Cisco ESA.
        """
        params = assign_params(quarantineType=quarantine_type, mid=message_id)

        return self._http_request("GET", "quarantine/messages/details", params=params)

    def spam_quarantine_message_release_request(
        self, action: str, quarantine_type: str, message_ids: List[int]
    ) -> Dict[str, Any]:
        """
        Release spam quarantine message.

        Args:
            action (str): Release action.
            quarantine_type (str): Quarantine type.
            message_ids (List[int]): Message IDs list.

        Returns:
            Dict[str, Any]: API response from Cisco ESA.
        """
        data = assign_params(
            action=action, mids=message_ids, quarantineType=quarantine_type
        )

        return self._http_request("POST", "quarantine/messages", json_data=data)

    def spam_quarantine_message_delete_request(
        self, quarantine_type: str, message_ids: List[int]
    ) -> Dict[str, Any]:
        """
        Delete spam quarantine message.

        Args:
            quarantine_type (str): Quarantine type.
            message_ids (List[int]): Message IDs list.

        Returns:
            Dict[str, Any]: API response from Cisco ESA.
        """
        data = assign_params(mids=message_ids, quarantineType=quarantine_type)

        return self._http_request("DELETE", "quarantine/messages", json_data=data)

    def list_entry_get_request(
        self,
        entry_type: str,
        action: str,
        limit: int,
        offset: int,
        quarantine_type: str,
        view_by: str,
        order_by: str = None,
        order_dir: str = None,
        search: str = None,
    ) -> Dict[str, Any]:
        """
        List spam quarantine blocklist/safelist.

        Args:
            entry_type (str): Blocklist/Safelist list type.
            action (str): List action.
            limit (int): Limit of results to retrieve.
            offset (int): Offset of results to skip.
            quarantine_type (str): Quarantine type.
            view_by (str): View list entry results by recipient/sender.
            order_by (str, Optional): Results order by field.
                Required if order_dir is specified. Defaults to None.
            order_dir (str, Optional): Results order direction.
                Required if order_by is specified. Defaults to None.
            search (str, Optional): Search for results in blocklist/safelist. Defaults to None.

        Returns:
            Dict[str, Any]: API response from Cisco ESA.
        """
        params = assign_params(
            action=action,
            limit=limit,
            offset=offset,
            orderBy=order_by,
            orderDir=order_dir,
            quarantineType=quarantine_type,
            viewBy=view_by,
            search=search,
        )

        return self._http_request("GET", f"quarantine/{entry_type}", params=params)

    def list_entry_add_request(
        self,
        entry_type: str,
        quarantine_type: str,
        action: str,
        view_by: str,
        recipient_addresses: List[str] = None,
        sender_list: List[str] = None,
        sender_addresses: List[str] = None,
        recipient_list: List[str] = None,
    ) -> Dict[str, Any]:
        """
        Add spam quarantine blocklist/safelist entries.

        Args:
            entry_type (str): Blocklist/Safelist list type.
            quarantine_type (str): Quarantine type.
            action (str): Add action.
            view_by (str): Add list entry results by recipient/sender.
            recipient_addresses (List[str], Optional): Recipient addresses list to add. Defaults to None.
            sender_list (List[str], Optional): Sender addresses list to add. Defaults to None.
            sender_addresses (List[str], Optional): Sender addresses list to add. Defaults to None.
            recipient_list (List[str], Optional): Recipient addresses list to add. Defaults to None.

        Returns:
            Dict[str, Any]: API response from Cisco ESA.
        """

        data = assign_params(
            action=action,
            quarantineType=quarantine_type,
            viewBy=view_by,
            recipientAddresses=recipient_addresses,
            senderAddresses=sender_addresses,
            recipientList=recipient_list,
            senderList=sender_list,
        )

        return self._http_request("POST", f"quarantine/{entry_type}", json_data=data)

    def list_entry_append_request(
        self,
        entry_type: str,
        quarantine_type: str,
        action: str,
        view_by: str,
        recipient_addresses: List[str] = None,
        sender_list: List[str] = None,
        sender_addresses: List[str] = None,
        recipient_list: List[str] = None,
    ) -> Dict[str, Any]:
        """
        Append spam quarantine blocklist/safelist entries.

        Args:
            entry_type (str): Blocklist/Safelist list type.
            quarantine_type (str): Quarantine type.
            action (str): Append action.
            view_by (str): Append list entry results by recipient/sender.
            recipient_addresses (List[str], Optional): Recipient addresses list to append. Defaults to None.
            sender_list (List[str], Optional): Sender addresses list to append. Defaults to None.
            sender_addresses (List[str], Optional): Sender addresses list to append. Defaults to None.
            recipient_list (List[str], Optional): Recipient addresses list to append. Defaults to None.

        Returns:
            Dict[str, Any]: API response from Cisco ESA.
        """

        data = assign_params(
            action=action,
            quarantineType=quarantine_type,
            viewBy=view_by,
            recipientAddresses=recipient_addresses,
            senderAddresses=sender_addresses,
            recipientList=recipient_list,
            senderList=sender_list,
        )

        return self._http_request("POST", f"quarantine/{entry_type}", json_data=data)

    def list_entry_edit_request(
        self,
        entry_type: str,
        quarantine_type: str,
        action: str,
        view_by: str,
        recipient_addresses: List[str] = None,
        sender_list: List[str] = None,
        sender_addresses: List[str] = None,
        recipient_list: List[str] = None,
    ) -> Dict[str, Any]:
        """
        Edit spam quarantine blocklist/safelist entries.

        Args:
            entry_type (str): Blocklist/Safelist list type.
            quarantine_type (str): Quarantine type.
            action (str): Edit action.
            view_by (str): Edit list entry results by recipient/sender.
            recipient_addresses (List[str], Optional): Recipient addresses list to edit Defaults to None.
            sender_list (List[str], Optional): Sender addresses list to edit Defaults to None.
            sender_addresses (List[str], Optional): Sender addresses list to edit Defaults to None.
            recipient_list (List[str], Optional): Recipient addresses list to edit Defaults to None.

        Returns:
            Dict[str, Any]: API response from Cisco ESA.
        """
        data = assign_params(
            action=action,
            quarantineType=quarantine_type,
            viewBy=view_by,
            recipientAddresses=recipient_addresses,
            senderAddresses=sender_addresses,
            recipientList=recipient_list,
            senderList=sender_list,
        )

        return self._http_request("POST", f"quarantine/{entry_type}", json_data=data)

    def list_entry_delete_request(
        self,
        entry_type: str,
        quarantine_type: str,
        view_by: str,
        recipient_list: List[str] = None,
        sender_list: List[str] = None,
    ) -> Dict[str, Any]:
        """
        Delete spam quarantine blocklist/safelist entries.

        Args:
            entry_type (str): Blocklist/Safelist list type.
            quarantine_type (str): Quarantine type.
            view_by (str): Delete list entry results by recipient/sender.
            recipient_list (List[str], Optional): Recipient list to delete. Defaults to None.
            sender_list (List[str], Optional): Sender list to delete. Defaults to None.

        Returns:
            Dict[str, Any]: API response from Cisco ESA.
        """
        data = assign_params(
            quarantineType=quarantine_type,
            recipientList=recipient_list,
            senderList=sender_list,
            viewBy=view_by,
        )

        return self._http_request("DELETE", f"quarantine/{entry_type}", json_data=data)

    def message_search_request(
        self,
        start_date: str,
        end_date: str,
        offset: int,
        limit: int,
        search_option: str,
        cisco_host: str,
        sender_filter_operator: str = None,
        sender_filter_value: str = None,
        recipient_filter_operator: str = None,
        recipient_filter_value: str = None,
        subject_filter_operator: str = None,
        subject_filter_value: str = None,
        attachment_name_operator: str = None,
        attachment_name_value: str = None,
        file_sha_256: str = None,
        custom_query: str = None,
    ) -> Dict[str, Any]:
        """
        Search tracking messages.

        Args:
            start_date (str): Start date in ISO format.
            end_date (str): End date in ISO format.
            offset (int): Offset of results to skip.
            limit (int): Limit of results to retrieve.
            search_option (str): Messages option.
            cisco_host (str): Cisco host.
            sender_filter_operator (str, Optional): Sender filter operator.
                Required if sender_filter_value is specified. Defaults to None.
            sender_filter_value (str, Optional): Sender address filter.
                Required if sender_filter_operator is specified. Defaults to None.
            recipient_filter_operator (str, Optional): Recipient filter operator.
                Required if recipient_filter_value is specified. Defaults to None.
            recipient_filter_value (str, Optional): Recipient address filter.
                Required if recipient_filter_operator is specified. Defaults to None.
            subject_filter_operator (str, Optional): Subject filter operator.
                Required if subject_filter_value is specified. Defaults to None.
            subject_filter_value (str, Optional): Subject address filter.
                Required if subject_filter_operator is specified. Defaults to None.
            attachment_name_operator (str, Optional): Attachment name operator.
                Required if attachment_name_value is specified. Defaults to None.
            attachment_name_value (str, Optional): Attachment name filter.
                Required if attachment_name_operator is specified. Defaults to None.
            file_sha_256 (str, Optional): SHA256 must be 64 characters long
            and can contain only "0-9" and "a-f" symbols.
            e.g. e0d123e5f316bef78bfdf5a008837577e0d123e5f316bef78bfdf5a008837577. Defaults to None.
            custom_query (str, Optional): Custom query for cisco ESA advanced filters. Defaults to None.
        Returns:
            Dict[str, Any]: API response from Cisco ESA.
        """
        params = assign_params(
            envelopeSenderfilterOperator=sender_filter_operator,
            envelopeSenderfilterValue=sender_filter_value,
            envelopeRecipientfilterOperator=recipient_filter_operator,
            envelopeRecipientfilterValue=recipient_filter_value,
            subjectfilterOperator=subject_filter_operator,
            subjectfilterValue=subject_filter_value,
            ciscoHost=cisco_host,
            searchOption=search_option,
            offset=offset,
            limit=limit,
            fileSha256=file_sha_256,
            attachmentNameOperator=attachment_name_operator,
            attachmentNameValue=attachment_name_value,
            **format_custom_query_args(custom_query),
        )

        return self._http_request(
            "GET",
            f"message-tracking/messages?startDate={start_date}&endDate={end_date}",
            params=params,
        )

    def message_details_get_request(
        self,
        serial_number: str,
        message_ids: List[int],
        injection_connection_id: int = None,
    ) -> Dict[str, Any]:
        """
        Get message details.

        Args:
            serial_number (str): mail Gateway serial number.
            message_id (List[int]): Message ID List.
            injection_connection_id (int, Optional): ICID, injection connection ID. Defaults to None.

        Returns:
            Dict[str, Any]: API response from Cisco ESA.
        """
        params = assign_params(
            serialNumber=serial_number,
            mid=message_ids,
            icid=injection_connection_id,
        )

        return self._http_request("GET", "message-tracking/details", params=params)

    def message_amp_details_get_request(
        self, serial_number: str, message_ids: List[int]
    ) -> Dict[str, Any]:
        """
        Get message AMP report details.

        Args:
            serial_number (str): mail Gateway serial number.
            message_id (List[int]): Message ID List.

        Returns:
            Dict[str, Any]: API response from Cisco ESA.
        """
        params = assign_params(
            serialNumber=serial_number,
            mid=message_ids,
        )

        return self._http_request("GET", "message-tracking/amp-details", params=params)

    def message_dlp_details_get_request(
        self, serial_number: str, message_ids: List[int]
    ) -> Dict[str, Any]:
        """
        Get message DLP report details.

        Args:
            serial_number (str): mail Gateway serial number.
            message_id (List[int]): Message ID List.

        Returns:
            Dict[str, Any]: API response from Cisco ESA.
        """
        params = assign_params(
            serialNumber=serial_number,
            mid=message_ids,
        )

        return self._http_request("GET", "message-tracking/dlp-details", params=params)

    def message_url_details_get_request(
        self, serial_number: str, message_ids: List[int]
    ) -> Dict[str, Any]:
        """
        Get message URL report details.

        Args:
            serial_number (str): mail Gateway serial number.
            message_id (List[int]): Message ID List.

        Returns:
            Dict[str, Any]: API response from Cisco ESA.
        """
        params = assign_params(
            serialNumber=serial_number,
            mid=message_ids,
        )

        return self._http_request("GET", "message-tracking/url-details", params=params)

    def report_get_request(
        self,
        report_type: str,
        start_date: str,
        end_date: str,
        device_type: str,
        order_by: str = None,
        order_dir: str = None,
        top: str = None,
        filter_value: str = None,
        filter_by: str = None,
        filter_operator: str = None,
    ) -> Dict[str, Any]:
        """
        Get statistics reports.

        Args:
            report_type (str): Report type.
            start_date (str): Start date.
            end_date (str): End date.
            device_type (str): Device type.
            order_by (str, optional): Order results by field. Defaults to None.
            order_dir (str, optional): Order direction. Defaults to None.
            top (str, optional): Number of records with the highest values to return. Defaults to None.
            filter_value (str, optional): Filter value. Defaults to None.
            filter_by (str, optional): Filter by field. Defaults to None.
            filter_operator (str, optional): Filter operator. Defaults to None.

        Returns:
            Dict[str, Any]: API response from Cisco ESA.
        """
        params = assign_params(
            startDate=start_date,
            endDate=end_date,
            device_type=device_type,
            orderBy=order_by,
            orderDir=order_dir,
            top=top,
            filterValue=filter_value,
            filterBy=filter_by,
            filterOperator=filter_operator,
        )

        return self._http_request("GET", f"reporting/{report_type}", params=params)

    def dictionary_list_request(
        self,
        dictionary_name: Optional[str],
        mode: str,
        host_name: Optional[str],
        group_name: Optional[str]
    ) -> Dict[str, Any]:

        endpoint = "config/dictionaries"
        if dictionary_name:
            endpoint += f"/{dictionary_name}"

        params = assign_params(
            device_type="esa",
            mode=mode,
            host_name=host_name,
            group_name=group_name,
        )
        return self._http_request(
            "GET",
            endpoint,
            params=params,
        )

    def dictionary_add_request(
        self,
        dictionary_name: str,
        mode: str,
        host_name: Optional[str],
        group_name: Optional[str],
        whole_words: int,
        words: list,
        ignore_case_sensitive: int,
    ) -> Dict[str, Any]:

        params = assign_params(
            device_type="esa",
            mode=mode,
            host_name=host_name,
            group_name=group_name,
        )

        json_data = {
            'data': {
                "ignorecase": ignore_case_sensitive,
                "wholewords": whole_words,
                "words": words,
                "encoding": "utf-8",
            }
        }

        return self._http_request(
            "POST",
            f"config/dictionaries/{dictionary_name}",
            params=params,
            json_data=json_data
        )

    def dictionary_edit_request(
        self,
        dictionary_name: str,
        mode: str,
        host_name: Optional[str],
        group_name: Optional[str],
        whole_words: int,
        words: list,
        ignore_case_sensitive: int,
        updated_name: Optional[str]
    ) -> Dict[str, Any]:

        params = assign_params(
            device_type="esa",
            mode=mode,
            host_name=host_name,
            group_name=group_name,
        )

        json_data = {
            'data': {
                "ignorecase": ignore_case_sensitive,
                "wholewords": whole_words,
                "words": words,
                "encoding": "utf-8",
            }
        }
        if updated_name:
            json_data['data']['name'] = updated_name

        return self._http_request(
            "PUT",
            f"config/dictionaries/{dictionary_name}",
            params=params,
            json_data=json_data
        )

    def dictionary_delete_request(
        self,
        dictionary_name: str,
        mode: str,
        host_name: Optional[str],
        group_name: Optional[str]
    ) -> Dict[str, Any]:

        params = assign_params(
            device_type="esa",
            mode=mode,
            host_name=host_name,
            group_name=group_name,
        )
        return self._http_request(
            "DELETE",
            f"config/dictionaries/{dictionary_name}",
            params=params,
        )

    def dictionary_words_add_request(
        self,
        dictionary_name: str,
        mode: str,
        host_name: Optional[str],
        group_name: Optional[str],
        words: list
    ) -> Dict[str, Any]:

        params = assign_params(
            device_type="esa",
            mode=mode,
            host_name=host_name,
            group_name=group_name,
        )

        json_data = {
            'data': {
                "words": words,
            }
        }

        return self._http_request(
            "POST",
            f"config/dictionaries/{dictionary_name}/words",
            params=params,
            json_data=json_data
        )

    def dictionary_words_delete_request(
        self,
        dictionary_name: str,
        mode: str,
        host_name: Optional[str],
        group_name: Optional[str],
        words: list
    ) -> Dict[str, Any]:

        params = assign_params(
            device_type="esa",
            mode=mode,
            host_name=host_name,
            group_name=group_name,
        )

        json_data = {
            'data': {
                "words": words,
            }
        }

        return self._http_request(
            "DELETE",
            f"config/dictionaries/{dictionary_name}/words",
            params=params,
            json_data=json_data
        )


def format_custom_query_args(custom_query: str = None) -> Dict[str, Any]:
    """
    Format custom query arguments for tracking message advanced filters.

    Args:
        custom_query (str, optional): Custom query of advanced filters. Defaults to None.

    Returns:
        Dict[str, Any]: Formatted dictionary of custom query arguments.
    """
    try:
        if custom_query:
            return dict(field.split("=") for field in custom_query.split(";"))
        else:
            return {}
    except ValueError:
        raise ValueError(
            'Please validate the format of argument "custom_query". '
            'For example: "key1=value1;key2=value2".'
        )


def format_datetime(time_expression: str) -> str:
    """
    Format string from time expression to Cisco ESA datetime format.

    Args:
        time_expression (str): Time expression or ISO format datetime.

    Returns:
        str: Datetime formatted string.
    """
    return arg_to_datetime(time_expression).strftime(CISCO_TIME_FORMAT)  # type: ignore


def format_reporting_datetime(time_expression: str) -> str:
    """
    Format string from time expression to Cisco ESA reporting datetime format.

    Args:
        time_expression (str): Time expression or ISO format datetime.

    Returns:
        str: Datetime formatted string.
    """
    return arg_to_datetime(time_expression).strftime(CISCO_REPORTING_TIME_FORMAT)  # type: ignore


def format_timestamp(timestamp: str, output_format: str = DATETIME_FORMAT) -> str:
    """
    Format Cisco ESA timestamp to datetime string.

    Args:
        timestamp (str): Cisco ESA timestamp.
        output_format (str): The format of the return date.

    Returns:
        str: Datetime formatted string.
    """
    try:
        try:
            datetime_res = arg_to_datetime(timestamp)
        except ValueError:
            datetime_res = arg_to_datetime(timestamp.replace("GMT ", "GMT"))
        return datetime_res.strftime(output_format)  # type: ignore
    except:  # noqa: E722
        return timestamp


def format_number_list_argument(number_list_string: str) -> List[int]:
    """
    Format number list argument to list of integer type.

    Args:
        number_list_string (str): Number list argument.

    Returns:
        List[int]: List of integers.
    """
    return [arg_to_number(number) for number in argToList(number_list_string)]  # type: ignore


def validate_pagination_arguments(
    page: Optional[int] = None,
    page_size: Optional[int] = None,
    limit: Optional[int] = None,
):
    """
    Validate pagination arguments, raise error if argument is not valid.

    Args:
        page (int): Page.
        page_size (int): Page Size.
        limit (int): Limit.
    """
    if page and page_size:
        if page_size < MIN_PAGE_SIZE or page_size > MAX_PAGE_SIZE:
            raise ValueError(
                f"page size argument must be greater than or equal to {MIN_PAGE_SIZE} "
                f"and smaller or equal to {MAX_PAGE_SIZE}."
            )

        if page < MIN_PAGE_NUMBER:
            raise ValueError(
                f"page argument must be equal or greater than {MIN_PAGE_NUMBER}."
            )
    else:
        if limit and limit < MIN_LIMIT:
            raise ValueError(
                f"limit argument must be equal or greater than {MIN_LIMIT}."
            )


def validate_related_arguments(
    args: Dict[str, Any], related_arguments_list: List[List[str]]
):
    """
    Validate correct usage of arguments that are related to each other.

    Args:
        args (Dict[str, Any]): Command arguments.
        related_arguments_list (List[List[str]]): Related arguments list.
    """
    args = {key: value for key, value in args.items() if value != ""}
    for related_arguments in related_arguments_list:
        exist_list = [argument in args for argument in related_arguments]
        if not all(exist_list) and any(exist_list):
            raise ValueError(
                f"{', '.join(related_arguments)} arguments should be used together but one or more are empty."
            )


def format_list_entry_arguments(view_by: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Format list entry arguments.

    Args:
        view_by (str): View by recipient/sender.
        args (Dict[str, Any]): Command arguments to format.

    Returns:
        Dict[str, Any]: Formatted list entry arguments.
    """
    if view_by == "recipient":
        if args.get("recipient_addresses") and args.get("sender_list"):
            args["sender_addresses"] = None
            args["recipient_list"] = None
        else:
            raise DemistoException(
                "Please specify recipient_addresses and sender_list arguments when using view_by recipient."
            )
    elif view_by == "sender":
        if args.get("sender_addresses") and args.get("recipient_list"):
            args["recipient_addresses"] = None
            args["sender_list"] = None
        else:
            raise DemistoException(
                "Please specify sender_addresses and recipient_list arguments when using view_by sender."
            )
    else:
        raise DemistoException(
            f'Please check the value of argument "view_by". Valid values are recipient/sender, got {view_by}.'
        )

    return args


def pagination(request_command: Callable, args: Dict[str, Any], **kwargs) -> tuple:
    """
    Executing Manual Pagination (using the page and page size arguments)
    or Automatic Pagination (display a number of total results).

    Args:
        request_command (Callable): The command to execute.
        args (Dict[str, Any]): The command arguments.

    Returns:
        Tuple: output, pagination message for Command Results.
    """
    page = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size"))
    limit = arg_to_number(args.get("limit"))

    validate_pagination_arguments(page, page_size, limit)

    if page and page_size:
        offset = page_size * (page - 1)
        output = request_command(offset=offset, limit=page_size, **kwargs).get("data")
        pagination_message = f"Showing page {page}.\n Current page size: {page_size}."
    elif limit:
        output = []
        offset = 0
        while limit > 0:
            page_size = limit if limit <= REQUEST_MAX_PULL else REQUEST_MAX_PULL
            output.extend(
                request_command(offset=offset, limit=page_size, **kwargs).get("data")
            )
            limit -= REQUEST_MAX_PULL
            offset += REQUEST_MAX_PULL
        pagination_message = f"Showing {len(output)} rows." if len(output) > 0 else None  # type: ignore
    else:
        pagination_message = "No pagination information"
        output = []
        demisto.debug(f"No pagination parameters {pagination_message=} {output=}")

    return output, pagination_message


def check_dictionary_mode_args(mode: str, host_name: str, group_name: str) -> tuple:
    """
    Check the validity of cluster parameters and return appropriate values based on the mode.

    Args:
        mode (str): The cluster mode, which can be either "group" or "machine".
        host_name (str): The name of the host, required when the mode is "machine".
        group_name (str): The name of the group, required when the mode is "group".

    Returns:
            - Raises a DemistoException if the required parameters are missing based on the mode:
                - If the mode is "group" and no group_name is provided.
                - If the mode is "machine" and no host_name is provided.
            - If both parameters are provided, returns:
                - (None, group_name) if the mode is "group".
                - (host_name, None) if the mode is not "group".
            - Else: returns (host_name, group_name) as they are.
    """

    if mode == "group" and not group_name:
        raise DemistoException("Please specify a group name for a cluster from type group.")

    if mode == "machine" and not host_name:
        raise DemistoException("Please specify a host name for a cluster from type machine.")

    return (None, group_name) if mode == "group" else (host_name, None)


def convert_words_to_list(words: str) -> List[list]:
    """
    Convert a string of words into a list of lists.

    Args:
        words (str): A string containing a list of words.

    Returns:
        List[str]: A list of lists containing words and their associated values.

    Raises:
        DemistoException: If the input string is not formatted correctly, with a message indicating the correct pattern.
                          This pattern is used for adding or editing dictionary entries or adding words, not for deleting words.
    """
    try:
        converted_list = list(ast.literal_eval(words))
        if isinstance(converted_list[0], str):
            return [converted_list]
        return converted_list
    except Exception:
        raise DemistoException("Words list is not defined correctly. Please use the following pattern: ['word1',3],['word2'].")


def spam_quarantine_message_search_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    """
    Search spam quarantine messages.

    Args:
        client (Client): Cisco ESA API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: readable outputs for XSOAR.
    """
    quarantine_type = QUARANTINE_TYPE
    start_date = format_datetime(args["start_date"])
    end_date = format_datetime(args["end_date"])
    filter_by = args.get("filter_by")
    filter_operator = args.get("filter_operator")
    filter_value = args.get("filter_value")
    recipient_filter_operator = args.get("recipient_filter_operator")
    recipient_filter_value = args.get("recipient_filter_value")
    order_by = args.get("order_by")
    order_dir = args.get("order_dir")

    validate_related_arguments(
        args=args,
        related_arguments_list=[
            ["filter_by", "filter_operator", "filter_value"],
            ["recipient_filter_operator", "recipient_filter_value"],
            ["order_by", "order_dir"],
        ],
    )

    output, pagination_message = pagination(
        client.spam_quarantine_message_search_request,
        args=args,
        quarantine_type=quarantine_type,
        start_date=start_date,
        end_date=end_date,
        filter_by=filter_by,
        filter_operator=filter_operator,
        filter_value=filter_value,
        recipient_filter_operator=recipient_filter_operator,
        recipient_filter_value=recipient_filter_value,
        order_by=order_by,
        order_dir=order_dir,
    )

    spam_quarantine_message_lists = [
        dict(message.get("attributes", {}), **{"mid": message.get("mid")})
        for message in output
    ]

    readable_output = tableToMarkdown(
        name="Spam Quarantine Messages List",
        metadata=pagination_message,
        t=spam_quarantine_message_lists,
        headers=["mid", "date", "fromAddress", "toAddress", "subject", "size"],
        headerTransform=pascalToSpace,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="CiscoESA.SpamQuarantineMessage",
        outputs_key_field="mid",
        outputs=spam_quarantine_message_lists,
        raw_response=spam_quarantine_message_lists,
    )


def spam_quarantine_message_get_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    """
    Get spam quarantine message details.

    Args:
        client (Client): Cisco ESA API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: readable outputs for XSOAR.
    """
    quarantine_type = QUARANTINE_TYPE
    message_id = args["message_id"]

    response: Dict[str, Any] = client.spam_quarantine_message_get_request(
        quarantine_type, message_id
    ).get("data", {})

    new_message = dict(response.get("attributes", {}), **{"mid": response.get("mid")})
    readable_message = (
        f'Found spam quarantine message with ID: {new_message.get("mid")}'
    )

    readable_output = tableToMarkdown(
        name="Spam Quarantine Message",
        metadata=readable_message,
        t=new_message,
        headers=["mid", "fromAddress", "toAddress", "date", "subject", "attachments"],
        headerTransform=pascalToSpace,
        removeNull=True,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="CiscoESA.SpamQuarantineMessage",
        outputs_key_field="mid",
        outputs=new_message,
        raw_response=response,
    )


def spam_quarantine_message_release_command(
    client: Client, args: Dict[str, Any]
) -> List[CommandResults]:
    """
    Release spam quarantine message.

    Args:
        client (Client): Cisco ESA API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        List[CommandResults]: readable outputs for XSOAR.
    """
    action = RELEASE_ACTION
    quarantine_type = QUARANTINE_TYPE
    message_ids = format_number_list_argument(args["message_ids"])

    command_results_list = []

    for message_id in message_ids:
        response = client.spam_quarantine_message_release_request(
            action, quarantine_type, [message_id]
        )

        if dict_safe_get(response, ["data", "totalCount"]) == 1:
            readable_output = f"Quarantined message {message_id} successfully released."
        else:
            readable_output = f"Quarantined message {message_id} not found."

        command_results_list.append(CommandResults(readable_output=readable_output))

    return command_results_list


def spam_quarantine_message_delete_command(
    client: Client, args: Dict[str, Any]
) -> List[CommandResults]:
    """
    Delete spam quarantine message details.

    Args:
        client (Client): Cisco ESA API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        List[CommandResults]: readable outputs for XSOAR.
    """
    quarantine_type = QUARANTINE_TYPE
    message_ids = format_number_list_argument(args["message_ids"])

    command_results_list = []

    for message_id in message_ids:
        response = client.spam_quarantine_message_delete_request(
            quarantine_type, [message_id]
        )

        if dict_safe_get(response, ["data", "totalCount"]) == 1:
            readable_output = f"Quarantined message {message_id} successfully deleted."
        else:
            readable_output = f"Quarantined message {message_id} not found."

        command_results_list.append(CommandResults(readable_output=readable_output))

    return command_results_list


def list_entry_get_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    List spam quarantine blocklist/safelist.

    Args:
        client (Client): Cisco ESA API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: readable outputs for XSOAR.
    """
    entry_type: str = args["entry_type"]
    action = VIEW_ACTION
    order_by = args.get("order_by")
    order_dir = args.get("order_dir")
    quarantine_type = QUARANTINE_TYPE
    view_by = args.get("view_by")
    search = args.get("search")

    validate_related_arguments(
        args=args, related_arguments_list=[["order_by", "order_dir"]]
    )

    output, pagination_message = pagination(
        client.list_entry_get_request,
        args=args,
        entry_type=entry_type,
        action=action,
        quarantine_type=quarantine_type,
        view_by=view_by,
        order_by=order_by,
        order_dir=order_dir,
        search=search,
    )

    readable_output = tableToMarkdown(
        name=f"{entry_type.title()} Entries",
        metadata=pagination_message,
        t=output,
        headers=["recipientAddress", "senderList"]
        if view_by == "recipient"
        else ["senderAddress", "recipientList"],
        headerTransform=pascalToSpace,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f"CiscoESA.ListEntry.{entry_type.title()}",
        outputs_key_field="recipientAddress"
        if view_by == "recipient"
        else "senderAddress",
        outputs=output,
        raw_response=output,
    )


def list_entry_add_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Add spam quarantine blocklist/safelist entries.

    Args:
        client (Client): Cisco ESA API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: readable outputs for XSOAR.
    """
    entry_type = args["entry_type"]
    quarantine_type = QUARANTINE_TYPE
    action = ADD_ACTION
    view_by = args["view_by"]

    formatted_arguments = format_list_entry_arguments(view_by=view_by, args=args)

    recipient_addresses = argToList(formatted_arguments.get("recipient_addresses"))
    sender_list = argToList(formatted_arguments.get("sender_list"))
    sender_addresses = argToList(formatted_arguments.get("sender_addresses"))
    recipient_list = argToList(formatted_arguments.get("recipient_list"))

    response = client.list_entry_add_request(
        entry_type=entry_type,
        quarantine_type=quarantine_type,
        action=action,
        view_by=view_by,
        recipient_addresses=recipient_addresses,
        sender_list=sender_list,
        sender_addresses=sender_addresses,
        recipient_list=recipient_list,
    )

    if view_by == "recipient":
        readable_output = (
            f'Successfully added {", ".join(sender_list)} senders to '
            f'{", ".join(recipient_addresses)} recipients in {entry_type}.'
        )
    else:
        readable_output = (
            f'Successfully added {", ".join(recipient_list)} recipients to '
            f'{", ".join(sender_addresses)} senders in {entry_type}.'
        )

    return CommandResults(readable_output=readable_output, raw_response=response)


def list_entry_append_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Append spam quarantine blocklist/safelist entries.

    Args:
        client (Client): Cisco ESA API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: readable outputs for XSOAR.
    """
    entry_type = args["entry_type"]
    quarantine_type = QUARANTINE_TYPE
    action = APPEND_ACTION
    view_by = args["view_by"]

    formatted_arguments = format_list_entry_arguments(view_by=view_by, args=args)

    recipient_addresses = argToList(formatted_arguments.get("recipient_addresses"))
    sender_list = argToList(formatted_arguments.get("sender_list"))
    sender_addresses = argToList(formatted_arguments.get("sender_addresses"))
    recipient_list = argToList(formatted_arguments.get("recipient_list"))

    response = client.list_entry_append_request(
        entry_type=entry_type,
        quarantine_type=quarantine_type,
        action=action,
        view_by=view_by,
        recipient_addresses=recipient_addresses,
        sender_list=sender_list,
        sender_addresses=sender_addresses,
        recipient_list=recipient_list,
    )

    if view_by == "recipient":
        readable_output = (
            f'Successfully appended {", ".join(sender_list)} senders to '
            f'{", ".join(recipient_addresses)} recipients in {entry_type}.'
        )
    else:
        readable_output = (
            f'Successfully appended {", ".join(recipient_list)} recipients to '
            f'{", ".join(sender_addresses)} senders in {entry_type}.'
        )

    return CommandResults(readable_output=readable_output, raw_response=response)


def list_entry_edit_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Edit spam quarantine blocklist/safelist entries.

    Args:
        client (Client): Cisco ESA API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: readable outputs for XSOAR.
    """
    entry_type = args["entry_type"]
    quarantine_type = QUARANTINE_TYPE
    action = EDIT_ACTION
    view_by = args["view_by"]

    formatted_arguments = format_list_entry_arguments(view_by=view_by, args=args)

    recipient_addresses = argToList(formatted_arguments.get("recipient_addresses"))
    sender_list = argToList(formatted_arguments.get("sender_list"))
    sender_addresses = argToList(formatted_arguments.get("sender_addresses"))
    recipient_list = argToList(formatted_arguments.get("recipient_list"))

    response = client.list_entry_edit_request(
        entry_type=entry_type,
        quarantine_type=quarantine_type,
        action=action,
        view_by=view_by,
        recipient_addresses=recipient_addresses,
        sender_list=sender_list,
        sender_addresses=sender_addresses,
        recipient_list=recipient_list,
    )

    if view_by == "recipient":
        readable_output = (
            f"Successfully edited {', '.join(recipient_addresses)} recipients' senders to "
            f"{', '.join(sender_list)} in {entry_type}."
        )
    else:
        readable_output = (
            f"Successfully edited {', '.join(sender_addresses)} senders' recipients to "
            f"{', '.join(recipient_list)} in {entry_type}."
        )

    return CommandResults(readable_output=readable_output, raw_response=response)


def list_entry_delete_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Delete spam quarantine blocklist/safelist entries.

    Args:
        client (Client): Cisco ESA API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: readable outputs for XSOAR.
    """
    entry_type = args["entry_type"]
    quarantine_type = QUARANTINE_TYPE
    view_by = args["view_by"]
    recipient_list = argToList(args.get("recipient_list"))
    sender_list = argToList(args.get("sender_list"))

    if view_by == "recipient":
        if recipient_list:
            sender_list = None
        else:
            raise DemistoException(
                "Please specify recipient_list argument when using view_by recipient."
            )
    else:
        if sender_list:
            recipient_list = None
        else:
            raise DemistoException(
                "Please specify sender_list argument when using view_by sender."
            )

    response = client.list_entry_delete_request(
        entry_type=entry_type,
        quarantine_type=quarantine_type,
        view_by=view_by,
        recipient_list=recipient_list,
        sender_list=sender_list,
    )

    deleted_entries = ", ".join(
        recipient_list if view_by == "recipient" else sender_list
    )

    return CommandResults(
        readable_output=f"Successfully deleted {deleted_entries} {view_by}s from {entry_type}.",
        raw_response=response,
    )


def message_search_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Search tracking messages.

    Args:
        client (Client): Cisco ESA API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: readable outputs for XSOAR.
    """
    start_date = format_datetime(args["start_date"])
    end_date = format_datetime(args["end_date"])
    sender_filter_operator = args.get("sender_filter_operator")
    sender_filter_value = args.get("sender_filter_value")
    recipient_filter_operator = args.get("recipient_filter_operator")
    recipient_filter_value = args.get("recipient_filter_value")
    subject_filter_operator = args.get("subject_filter_operator")
    subject_filter_value = args.get("subject_filter_value")
    attachment_name_operator = args.get("attachment_name_operator")
    attachment_name_value = args.get("attachment_name_value")
    cisco_host = "All_Hosts"
    search_option = "messages"
    file_sha_256 = args.get("file_sha_256")
    custom_query = args.get("custom_query")

    validate_related_arguments(
        args=args,
        related_arguments_list=[
            ["sender_filter_operator", "sender_filter_value"],
            ["recipient_filter_operator", "recipient_filter_value"],
            ["subject_filter_operator", "subject_filter_value"],
            ["attachment_name_operator", "attachment_name_value"],
            ["order_by", "order_dir"],
        ],
    )

    output, pagination_message = pagination(
        client.message_search_request,
        args=args,
        start_date=start_date,
        end_date=end_date,
        sender_filter_operator=sender_filter_operator,
        sender_filter_value=sender_filter_value,
        recipient_filter_operator=recipient_filter_operator,
        recipient_filter_value=recipient_filter_value,
        subject_filter_operator=subject_filter_operator,
        subject_filter_value=subject_filter_value,
        attachment_name_operator=attachment_name_operator,
        attachment_name_value=attachment_name_value,
        cisco_host=cisco_host,
        search_option=search_option,
        file_sha_256=file_sha_256,
        custom_query=custom_query,
    )

    messages_lists = [
        dict(
            message.get("attributes", {}),
            **{
                "timestamp": format_timestamp(
                    dict_safe_get(message, ["attributes", "timestamp"])
                ),
                "unique_message_id": "".join(
                    map(str, dict_safe_get(message, ["attributes", "mid"]))
                ),
            },
        )
        for message in output
    ]

    readable_output = tableToMarkdown(
        name="Messages List",
        metadata=pagination_message,
        t=messages_lists,
        headers=[
            "mid",
            "allIcid",
            "serialNumber",
            "sender",
            "recipient",
            "subject",
            "messageStatus",
            "timestamp",
            "senderIp",
            "sbrs",
        ],
        headerTransform=pascalToSpace,
        removeNull=True,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="CiscoESA.Message",
        outputs_key_field="unique_message_id",
        outputs=messages_lists,
        raw_response=messages_lists,
    )


def message_details_get_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Get message details.

    Args:
        client (Client): Cisco ESA API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: readable outputs for XSOAR.
    """
    serial_number = args["serial_number"]
    message_ids = format_number_list_argument(args["message_ids"])
    injection_connection_id = arg_to_number(args.get("injection_connection_id"))

    response = (
        client.message_details_get_request(
            serial_number=serial_number,
            message_ids=message_ids,
            injection_connection_id=injection_connection_id,
        )
        .get("data", {})
        .get("messages", {})
    )

    mid = response.get("mid")
    if not mid or "N/A" in mid:
        raise DemistoException(
            f'Message ID {", ".join(map(str, message_ids))} was not found.\n'
            f"Please check message IDs or Serial Number."
        )

    response["timestamp"] = format_timestamp(response.get("timestamp"))
    response["unique_message_id"] = "".join(map(str, response.get("mid")))

    for event in response.get("summary", ()):
        event["timestamp"] = format_timestamp(event.get("timestamp"))

    readable_output = tableToMarkdown(
        name="Message Details",
        metadata=f'Found message with ID {", ".join(map(str, response.get("mid")))}.',
        t=response,
        headers=[
            "mid",
            "allIcid",
            "subject",
            "sender",
            "recipient",
            "timestamp",
            "messageSize",
            "sendingHostSummary",
            "messageStatus",
            "direction",
            "mailPolicy",
            "senderGroup",
            "showAMP",
            "showDLP",
            "showURL",
        ],
        headerTransform=pascalToSpace,
    )

    summary_readable_output = tableToMarkdown(
        name="Message Summary",
        t=response.get("summary"),
        headers=["description", "timestamp", "lastEvent"],
        headerTransform=pascalToSpace,
        removeNull=True,
    )

    return CommandResults(
        readable_output=readable_output + summary_readable_output,
        outputs_prefix="CiscoESA.Message",
        outputs_key_field="unique_message_id",
        outputs=response,
        raw_response=response,
    )


def message_amp_details_get_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    """
    Get message AMP report details.

    Args:
        client (Client): Cisco ESA API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: readable outputs for XSOAR.
    """
    serial_number = args["serial_number"]
    message_ids = format_number_list_argument(args["message_ids"])

    response = (
        client.message_amp_details_get_request(
            serial_number=serial_number, message_ids=message_ids
        )
        .get("data", {})
        .get("messages", {})
    )

    mid = response.get("mid")
    if not mid or "N/A" in mid:
        raise DemistoException(
            f'Message ID {", ".join(map(str, message_ids))} was not found.\n'
            f"Please check message IDs or Serial Number."
        )

    response["timestamp"] = format_timestamp(response.get("timestamp"))

    readable_output = tableToMarkdown(
        name="Message AMP Report Details",
        metadata=f'Found AMP details for message ID {", ".join(map(str, response.get("mid")))}.',
        t=response,
        headers=[
            "mid",
            "allIcid",
            "subject",
            "sender",
            "recipient",
            "attachments",
            "timestamp",
            "messageSize",
            "messageStatus",
            "direction",
            "senderGroup",
        ],
        headerTransform=pascalToSpace,
    )

    amp_summary: List[Dict[str, Any]] = response.get("ampDetails")
    if amp_summary:
        for event in amp_summary:
            timestamp = event.get("timestamp")
            if timestamp:
                event["timestamp"] = format_timestamp(timestamp)

    summary_readable_output = tableToMarkdown(
        name="Message AMP Report Details Summary",
        t=amp_summary,
        headers=["description", "timestamp"],
        headerTransform=pascalToSpace,
        removeNull=True,
    )

    return CommandResults(
        readable_output=readable_output + summary_readable_output,
        outputs_prefix="CiscoESA.AMPDetail",
        outputs_key_field="mid",
        outputs=response,
        raw_response=response,
    )


def message_dlp_details_get_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    """
    Get message DLP report details.

    Args:
        client (Client): Cisco ESA API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: readable outputs for XSOAR.
    """
    serial_number = args["serial_number"]
    message_ids = format_number_list_argument(args["message_ids"])

    response = (
        client.message_dlp_details_get_request(
            serial_number=serial_number, message_ids=message_ids
        )
        .get("data", {})
        .get("messages", {})
    )

    mid = response.get("mid")
    if not mid or "N/A" in mid:
        raise DemistoException(
            f'Message ID {", ".join(map(str, message_ids))} was not found.\n'
            f"Please check message IDs or Serial Number."
        )

    response["timestamp"] = format_timestamp(response.get("timestamp"))

    readable_output = tableToMarkdown(
        name="Message DLP Report Details",
        metadata=f'Found DLP details for message ID {", ".join(map(str, response.get("mid")))}.',
        t=response,
        headers=[
            "mid",
            "allIcid",
            "subject",
            "sender",
            "recipient",
            "attachments",
            "timestamp",
            "messageSize",
            "messageStatus",
            "direction",
            "senderGroup",
        ],
        headerTransform=pascalToSpace,
        removeNull=True,
    )

    dlp_summary: List[Dict[str, Any]] = response.get("dlpDetails")

    summary_readable_output = tableToMarkdown(
        name="Message DLP Report Details Summary",
        t=dlp_summary,
        headers=["mid", "violationSeverity", "riskFactor", "dlpPolicy"],
        headerTransform=pascalToSpace,
    )

    return CommandResults(
        readable_output=readable_output + summary_readable_output,
        outputs_prefix="CiscoESA.DLPDetail",
        outputs_key_field="mid",
        outputs=response,
        raw_response=response,
    )


def message_url_details_get_command(
    client: Client, args: Dict[str, Any]
) -> CommandResults:
    """
    Get message URL report details.

    Args:
        client (Client): Cisco ESA API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: readable outputs for XSOAR.
    """
    serial_number = args["serial_number"]
    message_ids = format_number_list_argument(args["message_ids"])

    response = (
        client.message_url_details_get_request(
            serial_number=serial_number, message_ids=message_ids
        )
        .get("data", {})
        .get("messages", {})
    )

    mid = response.get("mid")
    if not mid or "N/A" in mid:
        raise DemistoException(
            f'Message ID {", ".join(map(str, message_ids))} was not found.\n'
            f"Please check message IDs or Serial Number."
        )

    response["timestamp"] = format_timestamp(response.get("timestamp"))

    url_summary: List[Dict[str, Any]] = response.get("urlDetails")
    if url_summary:
        for event in url_summary:
            timestamp = event.get("timestamp")
            if timestamp:
                event["timestamp"] = format_timestamp(timestamp)

    readable_output = tableToMarkdown(
        name="Message URL Report Details",
        metadata=f'Found URL details for message ID {", ".join(map(str, response.get("mid")))}.',
        t=response,
        headers=[
            "mid",
            "allIcid",
            "subject",
            "sender",
            "recipient",
            "attachments",
            "timestamp",
            "messageSize",
            "messageStatus",
            "direction",
            "senderGroup",
        ],
        headerTransform=pascalToSpace,
    )

    summary_readable_output = tableToMarkdown(
        name="Message URL Report Details Summary",
        t=url_summary,
        headers=["description", "timestamp"],
        headerTransform=pascalToSpace,
        removeNull=True,
    )

    return CommandResults(
        readable_output=readable_output + summary_readable_output,
        outputs_prefix="CiscoESA.URLDetail",
        outputs_key_field="mid",
        outputs=response,
        raw_response=response,
    )


def report_get_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Get statistics reports.

    Args:
        client (Client): Cisco ESA API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: readable outputs for XSOAR.
    """
    report_type = args.get("custom_report_type", args.get("report_type"))
    start_date = format_reporting_datetime(args["start_date"])
    end_date = format_reporting_datetime(args["end_date"])
    device_type = "esa"
    order_by = args.get("order_by")
    order_dir = args.get("order_dir")
    top = args.get("top")
    filter_value = args.get("filter_value")
    filter_by = args.get("filter_by")
    filter_operator = args.get("filter_operator")

    response: Dict[str, Any] = client.report_get_request(
        report_type=report_type,
        start_date=start_date,
        end_date=end_date,
        device_type=device_type,
        order_by=order_by,
        order_dir=order_dir,
        top=top,
        filter_value=filter_value,
        filter_by=filter_by,
        filter_operator=filter_operator,
    ).get("data", {})

    response["uuid"] = str(uuid.uuid4())

    try:
        table = {
            k: v
            for results in response.get("resultSet", [{}])
            for k, v in results.items()
        }
    except Exception:
        table = response.get("resultSet", response)

    readable_output = tableToMarkdown(
        name=f'Report type: {response.get("type")}',
        metadata=f'Report UUID: {response["uuid"]}',
        t=table,
        headerTransform=string_to_table_header,
        removeNull=True,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="CiscoESA.Report",
        outputs_key_field="uuid",
        outputs=response,
        raw_response=response,
    )


def dictionary_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieve dictionary configuration details.

    Args:
        client (Client): Cisco ESA API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: Readable outputs for XSOAR, including dictionary configuration details.
    """
    mode = args.get("mode", DEFAULT_MODE_DICTIONARIES)
    host_name = args.get("host_name", "")
    group_name = args.get("group_name", "")
    dictionary_name = args.get("dictionary_name", "")

    host_name, group_name = check_dictionary_mode_args(mode, host_name, group_name)
    response = client.dictionary_list_request(dictionary_name=dictionary_name,
                                              mode=mode,
                                              host_name=host_name,
                                              group_name=group_name
                                              )

    if dictionary_name:
        name = f'Information for Dictionary: {dictionary_name}'
    else:
        name = f'Information for All Configured Dictionaries in mode: {mode}'

    readable_output = tableToMarkdown(
        name=name,
        t=response.get('data'),
        removeNull=True,
        headers=["name", "words", "ignorecase", "wholewords", "words_count", "encoding"]
    )

    return CommandResults(
        outputs_prefix="CiscoESA.Dictionary",
        outputs=response.get('data'),
        raw_response=response,
        readable_output=readable_output
    )


def dictionary_add_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Add a new dictionary configuration.

    Args:
        client (Client): Cisco ESA API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: Readable outputs for XSOAR, indicating the successful addition of the dictionary.
    """
    mode = args.get("mode", DEFAULT_MODE_DICTIONARIES)
    host_name = args.get("host_name", "")
    group_name = args.get("group_name", "")
    dictionary_name = args.get("dictionary_name", "")
    whole_words = args.get("whole_words", True)
    words = args.get("words", "")
    ignore_case_sensitive = args.get("ignore_case_sensitive", False)

    host_name, group_name = check_dictionary_mode_args(mode, host_name, group_name)
    ignore_case_sensitive = int(argToBoolean(ignore_case_sensitive))  # will be sent to the api as 0 or 1
    whole_words = int(argToBoolean(whole_words))  # will be sent to the api as 0 or 1
    words = convert_words_to_list(words)

    response = client.dictionary_add_request(dictionary_name=dictionary_name,
                                             mode=mode,
                                             host_name=host_name,
                                             group_name=group_name,
                                             whole_words=whole_words,
                                             words=words,
                                             ignore_case_sensitive=ignore_case_sensitive,
                                             )
    return CommandResults(
        readable_output=f"{dictionary_name} was added successfully.",
        raw_response=response,
    )


def dictionary_edit_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Edit an existing dictionary configuration.

    Args:
        client (Client): Cisco ESA API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: Readable outputs for XSOAR, indicating the successful update of the dictionary.
    """
    mode = args.get("mode", DEFAULT_MODE_DICTIONARIES)
    host_name = args.get("host_name", "")
    group_name = args.get("group_name", "")
    dictionary_name = args.get("dictionary_name", "")
    updated_name = args.get("updated_name", "")
    whole_words = args.get("whole_words", True)
    words = args.get("words", "")
    ignore_case_sensitive = args.get("ignore_case_sensitive", False)

    host_name, group_name = check_dictionary_mode_args(mode, host_name, group_name)
    ignore_case_sensitive = int(argToBoolean(ignore_case_sensitive))  # will be sent to the api as 0 or 1
    whole_words = int(argToBoolean(whole_words))  # will be sent to the api as 0 or 1
    words = convert_words_to_list(words)

    response = client.dictionary_edit_request(dictionary_name=dictionary_name,
                                              mode=mode,
                                              host_name=host_name,
                                              group_name=group_name,
                                              whole_words=whole_words,
                                              words=words,
                                              ignore_case_sensitive=ignore_case_sensitive,
                                              updated_name=updated_name
                                              )
    return CommandResults(
        readable_output=f"{dictionary_name} has been successfully updated.",
        raw_response=response,
    )


def dictionary_delete_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Delete an existing dictionary configuration.

    Args:
        client (Client): Cisco ESA API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: Readable outputs for XSOAR, indicating the successful deletion of the dictionary.
    """
    mode = args.get("mode", DEFAULT_MODE_DICTIONARIES)
    host_name = args.get("host_name", "")
    group_name = args.get("group_name", "")
    dictionary_name = args.get("dictionary_name", "")

    host_name, group_name = check_dictionary_mode_args(mode, host_name, group_name)

    response = client.dictionary_delete_request(dictionary_name=dictionary_name,
                                                mode=mode,
                                                host_name=host_name,
                                                group_name=group_name
                                                )

    return CommandResults(
        readable_output=f"{dictionary_name} deleted successfully.",
        raw_response=response,
    )


def dictionary_words_add_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Add words to an existing dictionary configuration.

    Args:
        client (Client): Cisco ESA API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: Readable outputs for XSOAR, indicating the successful addition of words to the dictionary.
    """
    mode = args.get("mode", DEFAULT_MODE_DICTIONARIES)
    host_name = args.get("host_name", "")
    group_name = args.get("group_name", "")
    dictionary_name = args.get("dictionary_name", "")
    words = args.get("words", "")

    host_name, group_name = check_dictionary_mode_args(mode, host_name, group_name)
    words = convert_words_to_list(words)

    response = client.dictionary_words_add_request(dictionary_name=dictionary_name,
                                                   mode=mode,
                                                   host_name=host_name,
                                                   group_name=group_name,
                                                   words=words
                                                   )

    return CommandResults(
        readable_output=f"Added successfully to {dictionary_name}.",
        raw_response=response,
    )


def dictionary_words_delete_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Delete words from an existing dictionary configuration.

    Args:
        client (Client): Cisco ESA API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: Readable outputs for XSOAR, indicating the successful deletion of words from the dictionary.
    """
    mode = args.get("mode", DEFAULT_MODE_DICTIONARIES)
    host_name = args.get("host_name", "")
    group_name = args.get("group_name", "")
    dictionary_name = args.get("dictionary_name", "")
    words = argToList(args.get("words", ""))

    host_name, group_name = check_dictionary_mode_args(mode, host_name, group_name)

    response = client.dictionary_words_delete_request(dictionary_name=dictionary_name,
                                                      mode=mode,
                                                      host_name=host_name,
                                                      group_name=group_name,
                                                      words=words)

    return CommandResults(
        readable_output=f"Words deleted successfully from {dictionary_name}.",
        raw_response=response,
    )


def fetch_incidents(
    client: Client,
    max_fetch: int,
    first_fetch: str,
    last_run: Dict[str, Any],
    filter_by: str = None,
    filter_operator: str = None,
    filter_value: str = None,
    recipient_filter_operator: str = None,
    recipient_filter_value: str = None,
) -> tuple:
    """
    Fetch Cisco ESA quarantined messages as incidents.

    Args:
        client (Client): Cisco ESA API client.
        max_fetch (int): Max number of messages to fetch.
        first_fetch (str): From which time to fetch.
        last_run (Dict[str, Any]): Last run info.
        filter_by (str, optional): Filter results by message field. Defaults to None.
        filter_operator (str, optional): Filter operator. Defaults to None.
        filter_value (str, optional): Filter value. Defaults to None.
        recipient_filter_operator (str, optional): Recipient filter operator. Defaults to None.
        recipient_filter_value (str, optional): Recipient filter value. Defaults to None.

    Returns:
        tuple: Incidents and last run info.
    """
    start_time = last_run.get("start_time")
    start_date = (
        format_timestamp(start_time, output_format=CISCO_TIME_FORMAT)
        if start_time
        else format_datetime(first_fetch)
    )
    end_date = format_datetime("now")
    quarantine_type = QUARANTINE_TYPE
    offset = last_run.pop("offset", 0) or 0
    order_by = "date"
    order_dir = "asc"

    quarantine_messages: List[
        Dict[str, Any]
    ] = client.spam_quarantine_message_search_request(
        quarantine_type=quarantine_type,
        start_date=start_date,
        end_date=end_date,
        offset=offset,
        limit=max_fetch,
        filter_by=filter_by,
        filter_operator=filter_operator,
        filter_value=filter_value,
        recipient_filter_operator=recipient_filter_operator,
        recipient_filter_value=recipient_filter_value,
        order_by=order_by,
        order_dir=order_dir,
    ).get(
        "data", []
    )

    data_length = len(quarantine_messages)
    incidents: List[Dict[str, Any]] = []
    last_minute_incident_ids = last_run.get("last_minute_incident_ids", [])
    for incident in quarantine_messages:
        incident_datetime = format_timestamp(
            dict_safe_get(incident, ["attributes", "date"])
        )
        message_id = incident.get("mid")
        if (
            message_id
            and message_id not in last_minute_incident_ids
            and start_date < incident_datetime
        ):
            quarantine_message: Dict[
                str, Any
            ] = client.spam_quarantine_message_get_request(
                quarantine_type=quarantine_type, message_id=message_id
            ).get(
                "data", {}
            )

            incident_details = dict(
                quarantine_message.get("attributes", {}),
                **{"mid": quarantine_message.get("mid")},
            )
            incidents.append(
                {
                    "name": incident_details.get("subject"),
                    "occurred": incident_datetime,
                    "rawJSON": json.dumps(incident_details, ensure_ascii=False),
                }
            )

    if incidents:
        start_time = incidents[-1].get("occurred")
        last_run["start_time"] = start_time
        new_fetched_tickets = [
            json.loads(incident.get("rawJSON", {})).get("mid")
            for incident in incidents
            if incident.get("occurred") == start_time
        ]
        if offset == 0:
            last_run["last_minute_incident_ids"] = new_fetched_tickets
        else:
            last_run["last_minute_incident_ids"].extend(new_fetched_tickets)
    # In case that all the incidents where dropped
    if data_length != 0 and not incidents:
        last_run["offset"] = offset + max_fetch
    return incidents, last_run


def test_module(client: Client, **kwargs) -> str:
    """
    Validates the correctness of the instance parameters and connectivity to Cisco ESA API service.

    Args:
        client (Client): Cisco ESA API client.
    """
    arg_to_datetime(kwargs.get("first_fetch"))

    validate_related_arguments(
        kwargs,
        [
            ["filter_by", "filter_operator", "filter_value"],
            ["recipient_filter_operator", "recipient_filter_value"],
        ],
    )

    start_date = format_datetime("1 month")
    end_date = format_datetime("now")
    offset = 0
    limit = 1
    search_option = "messages"
    cisco_host = "All_Hosts"

    client.message_search_request(
        start_date=start_date,
        end_date=end_date,
        offset=offset,
        limit=limit,
        search_option=search_option,
        cisco_host=cisco_host,
    )

    return "ok"


def main() -> None:
    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()

    base_url = params.get("base_url")
    username = params.get("credentials", {}).get("identifier")
    password = params.get("credentials", {}).get("password")

    max_fetch = arg_to_number(params.get("max_fetch", DEFAULT_FETCH))
    first_fetch = params.get("first_fetch")
    filter_by = params.get("filter_by")
    filter_operator = params.get("filter_operator")
    filter_value = params.get("filter_value")
    recipient_filter_operator = params.get("recipient_filter_operator")
    recipient_filter_value = params.get("recipient_filter_value")

    verify_certificate: bool = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    jwt_token_expiration_period = int(params.get("jwt_token_expiration_period") or 30)
    command = demisto.command()
    commands = {
        "cisco-esa-spam-quarantine-message-search": spam_quarantine_message_search_command,
        "cisco-esa-spam-quarantine-message-get": spam_quarantine_message_get_command,
        "cisco-esa-spam-quarantine-message-release": spam_quarantine_message_release_command,
        "cisco-esa-spam-quarantine-message-delete": spam_quarantine_message_delete_command,
        "cisco-esa-list-entry-get": list_entry_get_command,
        "cisco-esa-list-entry-add": list_entry_add_command,
        "cisco-esa-list-entry-append": list_entry_append_command,
        "cisco-esa-list-entry-edit": list_entry_edit_command,
        "cisco-esa-list-entry-delete": list_entry_delete_command,
        "cisco-esa-message-search": message_search_command,
        "cisco-esa-message-details-get": message_details_get_command,
        "cisco-esa-message-amp-details-get": message_amp_details_get_command,
        "cisco-esa-message-dlp-details-get": message_dlp_details_get_command,
        "cisco-esa-message-url-details-get": message_url_details_get_command,
        "cisco-esa-report-get": report_get_command,
        "cisco-esa-dictionary-list": dictionary_list_command,
        "cisco-esa-dictionary-add": dictionary_add_command,
        "cisco-esa-dictionary-edit": dictionary_edit_command,
        "cisco-esa-dictionary-delete": dictionary_delete_command,
        "cisco-esa-dictionary-words-add": dictionary_words_add_command,
        "cisco-esa-dictionary-words-delete": dictionary_words_delete_command,
    }
    try:
        client: Client = Client(
            urljoin(base_url, "/esa/api/v2.0"),
            username,
            password,
            verify_certificate,
            proxy,
            jwt_token_expiration_period,
        )

        if command == "test-module":
            return_results(
                test_module(
                    client,
                    max_fetch=max_fetch,
                    first_fetch=first_fetch,
                    filter_by=filter_by,
                    filter_operator=filter_operator,
                    filter_value=filter_value,
                    recipient_filter_operator=recipient_filter_operator,
                    recipient_filter_value=recipient_filter_value,
                )
            )
        elif command == "fetch-incidents":
            incidents, last_run = fetch_incidents(
                client,
                max_fetch,  # type: ignore
                first_fetch,  # type: ignore
                demisto.getLastRun(),
                filter_by,
                filter_operator,
                filter_value,
                recipient_filter_operator,
                recipient_filter_value,
            )

            demisto.setLastRun(last_run)
            demisto.incidents(incidents)
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f"{command} command is not implemented.")

    except Exception as e:
        return_error(str(e))


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
