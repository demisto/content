import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


class MicrosoftStorageClient(BaseClient):
    """
    Microsoft Azure Storage API Client
    """

    def __init__(self, server_url, verify, proxy, account_sas_token, storage_account_name, api_version):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy)
        self._account_sas_token = account_sas_token
        self._storage_account_name = storage_account_name
        self._api_version = api_version
        self._base_url = server_url

    def http_request(
            self, *args, url_suffix="", params=None, resp_type='response', headers=None,
            return_empty_response=False, full_url="", **kwargs):
        """
        Overrides Base client request function.
        Create and adds to the headers the Authorization Header component before sending the request.
        Parse Azure XML response.
        Args:
            url_suffix (str): Request URL suffix.
            params (dict): Request Params.
            resp_type (str): Determines which data format to return from the HTTP request.
            headers (dict): Request Header.
            return_empty_response (bool): Return the response itself if the return_code is 201 or 204.
            full_url (str): Request full URL.
        Returns:
            Response from API according to resp_type.
        """

        if 'ok_codes' not in kwargs and not self._ok_codes:
            kwargs['ok_codes'] = (200, 201, 202, 204, 206, 404)

        if not full_url:
            # This logic will chain the SAS token along with the params
            # in order to create a valid URL for requests in Microsoft Azure Storage.
            # For example:
            # SAS token = '?sv=2020-08-04&ss=bt&spr=https&sig=t8'
            # params = '{'restype': 'directory', 'comp': 'list'}'
            # url_suffix = 'container'
            # The updated url_suffix after performing this logic will be:
            # url_suffix = 'container?sv=2020-08-04&ss=ay&spr=https&sig=s5&restype=directory&comp=list'
            params_query = self.params_dict_to_query_string(params, prefix='')
            url_suffix = f'{url_suffix}{self._account_sas_token}{params_query}'
            params = None

        default_headers = {'x-ms-version': self._api_version}

        if headers:
            default_headers.update(headers)

        response = super()._http_request(  # type: ignore[misc]
            *args, url_suffix=url_suffix, params=params, resp_type='response', headers=default_headers,
            full_url=full_url, **kwargs)

        # 206 indicates Partial Content, reason will be in the warning header.
        # In that case, logs with the warning header will be written.
        if response.status_code == 206:
            demisto.debug(str(response.headers))

        is_response_empty_and_successful = (response.status_code == 204 or response.status_code == 201)
        if is_response_empty_and_successful and return_empty_response:
            return response

        # Handle 404 errors instead of raising them as exceptions:
        if response.status_code == 404:
            try:
                error_message = response.json()
            except Exception:
                error_message = f'Not Found - 404 Response \nContent: {response.content}'
            raise NotFoundError(error_message)

        try:
            if resp_type == 'json':
                return response.json()
            if resp_type == 'text':
                return response.text
            if resp_type == 'content':
                return response.content
            if resp_type == 'xml':
                ET.parse(response.text)
            return response
        except ValueError as exception:
            raise DemistoException('Failed to parse json object from response: {}'.format(response.content), exception)

    def params_dict_to_query_string(self, params: dict = None, prefix: str = "") -> str:
        """
        Convert request params to string query.
        Args:
            params (dict): Request Params.
            prefix (str): String prefix.

        Returns:
            str: String query.

        """
        if not params:
            return ""
        query = prefix
        for key, value in params.items():
            query += f'&{key}={value}'

        return query


class NotFoundError(Exception):
    """Exception raised for 404 - Not Found errors.
    Attributes:
        message -- explanation of the error
    """

    def __init__(self, message):
        self.message = message
