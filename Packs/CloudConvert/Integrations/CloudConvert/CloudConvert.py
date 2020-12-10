import demistomock as demisto
from CommonServerPython import *

import urllib3

from typing import Any, Dict
# Disable insecure warnings
urllib3.disable_warnings()


class Client(BaseClient):

    @logger
    def __init__(self, headers, verify=False, proxy=False):
        url = 'https://api.cloudconvert.com/v2'
        super().__init__(url, headers=headers, verify=verify, proxy=proxy)

    @logger
    def upload_url(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Upload the file given as url to the API's server, for later conversion.
        Note - this operation is called 'import' by the API.
        Args:
            arguments: dict containing the request arguments, should contain the field 'url'

        Returns:
            dict containing the results of the upload action as returned from the API (status, task ID, etc.)
            ``Dict[str, Any]``
        """

        return self._http_request(
            method='POST',
            url_suffix='import/url',
            data=arguments,
            ok_codes=(200, 201, 422),
        )

    @logger
    def upload_entry_id(self, file_path: str, file_name: str) -> Dict[str, Any]:
        """
        Upload the file given as a war room entry id to the API's server, for later conversion
        Note - this operation is called 'import' by the API.

        Args:
            file_path: path to given file, derived from the entry id
            file_name: name of file, including format suffix

        Returns:
            dict containing the results of the upload action as returned from the API (status, task ID, etc.)
            ``Dict[str, Any]``
        """

        response_get_form = self._http_request(
            method='POST',
            url_suffix='import/upload'
        )
        form = dict_safe_get(response_get_form, ('data', 'result', 'form'), default_return_value={})

        port_url = form.get('url')
        params = form.get('parameters')

        if port_url is None or params is None:
            raise ValueError('Failed to initiate an upload operation')

        file_dict = {'file': (file_name, open(file_path, 'rb'))}
        self._http_request(
            method='POST',
            url_suffix=None,
            full_url=port_url,
            files=file_dict,
            empty_valid_codes=[201, 204],
            return_empty_response=True,
            data=params
        )

        # As shown, this operation has two requests
        # The data about the operation is within the first request's response,
        # So in order to keep the operation's data, we should return the first request's response,
        # But first we should remove fields that are no longer true, such as ones that indicates that
        # The second request has not been done yet
        if response_get_form.get('data'):
            response_get_form.get('data').pop('message', None)
            response_get_form.get('data').pop('result', None)

        return response_get_form

    @logger
    def convert(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert a file to desired format, given the file was priorly uploaded to the API's server
        Args:
            arguments: dict containing the request arguments, should contain the fields 'task_id' and 'output_format'

        Returns:
            dict containing the results of the convert action as returned from the API (status, task ID, etc.)
            ``Dict[str, Any]``
        """

        arguments['input'] = arguments.pop('task_id')
        return self._http_request(
            method='POST',
            url_suffix='convert',
            data=arguments,
            ok_codes=(200, 201, 422),
        )

    def check_status(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check the status of a request sent to the API's server
        Args:
            arguments: dict containing the request arguments, should contain the field 'task_id'

        Returns:
            dict containing the results of the check status action as returned from the API (status, task ID, etc.)
            ``Dict[str, Any]``
        """

        task_id = arguments.get('task_id')
        return self._http_request(
            method='GET',
            url_suffix=f'/tasks/{task_id}',
            ok_codes=(200, 201, 422),
        )

    @logger
    def download_url(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Download a converted file to a url
        Note - this operation is called 'export' by the API.
        Args:
            arguments:
                dict containing the request arguments, should contain the field 'task_id' of the desired file

        Returns:
            dict containing the results of the download action as returned from the API (status, task ID, etc.)
                    if the action was complete, the result url will be a part of this dict. If the request is pending,
                    one should retrieve the url via the 'check_status' command
            ``Dict[str, Any]``

        """

        arguments['input'] = arguments.pop('task_id')
        return self._http_request(
            method='POST',
            url_suffix='/export/url',
            data=arguments,
            ok_codes=(200, 201, 422),
        )

    @logger
    def get_file_from_url(self, url: str):
        """
        Call a GET http request in order to get the file data given as url
        Args:
            url: url containing a file

        Returns:
             request response, containing the data of the file
        """

        # Saving the headers of this client instance
        # The HTTP request that gets the file data needs to have no headers
        # Passing an empty dictionary to _http_request cause it to use this client's headers by default
        session_headers = self._headers
        self._headers = {}
        try:
            results = self._http_request(
                method='GET',
                url_suffix=None,
                full_url=url,
                headers={},
                resp_type='response',
            )
            return results.content
        finally:
            self._headers = session_headers


@logger
def raise_error_if_no_data(results: Dict[str, Any]):
    """
    This function checks if No 'data' field was returned from the request, meaning the input was invalid
    Args:
        results: a dict containing the request's results

    Returns:
        raises error if there is no 'data' field, with the matching error message returned from the server
        if no error message was given from the server, suggests the other optional errors
    """
    if results.get('data') is None:
        if results.get('message'):
            raise ValueError(results.get('message'))
        else:
            raise ValueError('No response from server, the server could be temporary unavailable or it is handling too '
                             'many requests. Please try again later.')


@logger
def upload_command(client: Client, arguments: Dict[str, Any]):
    """
    Upload a file to the API for later conversion
    Args:
        client: CloudConvert client to use
        arguments: All command arguments - either 'url' or 'entry_id'.

    Returns:
        CommandResults object containing the results of the upload action as returned from the API and its
             readable output
    """

    if arguments.get('url'):
        if arguments.get('entry_id'):
            raise ValueError('Both url and entry id were inserted - please insert only one.')
        results = client.upload_url(arguments)

    elif arguments.get('entry_id'):
        demisto.debug('getting the path of the file from its entry id')
        result = demisto.getFilePath(arguments.get('entry_id'))
        if not result:
            raise ValueError('No file was found for given entry id')
        file_path, file_name = result['path'], result['name']
        results = client.upload_entry_id(file_path, file_name)

    else:
        raise ValueError('No url or entry id specified.')

    raise_error_if_no_data(results)
    format_operation_title(results)
    results_data = results.get('data')

    readable_output = tableToMarkdown(
        'Upload Results',
        remove_empty_elements(results_data),
        headers=('id', 'operation', 'created_at', 'status'),
        headerTransform=string_to_table_header,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='CloudConvert.Task',
        outputs_key_field='id',
        raw_response=results,
        outputs=remove_empty_elements(results_data),
    )


@logger
def convert_command(client: Client, arguments: Dict[str, Any]):
    """
    Convert a file that was priorly uploaded
    Args:
        client: CloudConvert client to use
        arguments: All command arguments, the fields 'task_id' and 'output_format'

    Returns:
        CommandResults object containing the results of the convert action as returned from the API and its readable output

    """

    results = client.convert(arguments)
    raise_error_if_no_data(results)
    results_data = results.get('data')
    readable_output = tableToMarkdown(
        'Convert Results',
        remove_empty_elements(results_data),
        headers=('id', 'operation', 'created_at', 'status', 'depends_on_task_ids'),
        headerTransform=string_to_table_header,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='CloudConvert.Task',
        outputs_key_field='id',
        raw_response=results,
        outputs=remove_empty_elements(results_data),
    )


@logger
def check_status_command(client: Client, arguments: Dict[str, Any]):
    """
    Check status of an existing operation using it's task id
    Args:
        client: CloudConvert client to use
        arguments: All command arguments, the field 'task_id'
            Note: When the checked operation is 'download', the field 'create_war_room_entry' should be set according
             to the chosen download method, true if downloading as war room entry and false if not.
            This way a war room entry containing the file will be created if needed.

    Returns:
            CommandResults object containing the results of the check status action as returned from the API
         and its readable output OR if the argument create_war_room_entry is set to True, then a war room entry is also
         being created.

    """
    results = client.check_status(arguments)
    raise_error_if_no_data(results)
    format_operation_title(results)
    results_data = results.get('data', {})

    # If checking on an download to entry operation, manually change the operation name
    # This is because the 'download as entry' operation is our variation on the export to url operation,
    # hence not distinguished as a different operation by the API
    if argToBoolean(arguments.get('create_war_room_entry', False)) \
            and results_data.get('operation') == 'download/url':
        results['data']['operation'] = 'download/entry'

    # Check if an download to war room entry operation is finished
    # If it did - create the entry
    if results_data.get('status') == 'finished' \
            and argToBoolean(arguments.get('create_war_room_entry', 'False'))\
            and results_data.get('operation') == 'download/entry':
        modify_results_dict(results_data)
        url = results_data.get('url')
        file_name = results_data.get('file_name')
        file_data = client.get_file_from_url(url)
        war_room_file = fileResult(filename=file_name, data=file_data, file_type=entryTypes['entryInfoFile'])
        readable_output = tableToMarkdown('Check Status Results', remove_empty_elements(results_data),
                                          headers=('id', 'operation', 'created_at', 'status', 'depends_on_task_ids',
                                                   'file_name', 'url'),
                                          headerTransform=string_to_table_header,)
        return_results(CommandResults(
            outputs_prefix='CloudConvert.Task',
            outputs_key_field='id',
            raw_response=results,
            readable_output=readable_output,
            outputs=remove_empty_elements(results_data)
        ))
        return war_room_file

    else:

        modify_results_dict(results_data)

        readable_output = tableToMarkdown(
            'Check Status Results',
            remove_empty_elements(results_data),
            headers=('id', 'operation', 'created_at', 'status', 'depends_on_task_ids', 'file_name', 'url'),
            headerTransform=string_to_table_header,
        )

        return CommandResults(
            readable_output=readable_output,
            outputs_prefix='CloudConvert.Task',
            outputs_key_field='id',
            raw_response=results,
            outputs=remove_empty_elements(results_data),
        )


def modify_results_dict(results_data: Dict[str, Any]):
    """
    The results of the specific file converted/uploaded/downloaded are sub-values of some keys,
    so parse the results field to the outer scope of the dict
    Args:
        results_data: the dict under the 'data' field in the response's results

    """
    if results_data.get('result'):
        results_info = results_data.get('result', {}).get('files')
        if results_info:
            results_data['file_name'] = results_info[0].get('filename')
            results_data['url'] = results_info[0].get('url')
            results_data['size'] = results_info[0].get('size')


@logger
def download_command(client: Client, arguments: Dict[str, Any]):
    """
    Download a converted file back to the user, either as a url or directly as a war room entry
    Note: in order to get the resulted url/entry of the file you need to use a check-status command as well,
        since the response of the download command is usually responded before the file is fully downloaded (hence the
    'status' field is 'waiting', and not 'finished')
    Args:
        client: CloudConvert client to use
        arguments: All command arguments, the fields 'task_id', and 'download_as' (url/war_room_entry)

    Returns:
        CommandResults object containing the results of the download action as returned from the API, and its readable
    """

    # Call download as url request
    # In both url and war room entry we still first get a url
    results = client.download_url(arguments)
    raise_error_if_no_data(results)

    # If downloading as war room entry, manually change the operation name
    # This is because the 'download as entry' operation is our variation on the export to url operation,
    # hence not distinguished as a different operation by the API
    if arguments['download_as'] == 'war_room_entry':
        results['data']['operation'] = 'download/entry'
    else:
        format_operation_title(results)

    results_data = results.get('data')

    readable_output = tableToMarkdown(
        'Download Results',
        remove_empty_elements(results_data),
        headers=('id', 'operation', 'created_at', 'status', 'depends_on_task_ids'),
        headerTransform=string_to_table_header,
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='CloudConvert.Task',
        outputs_key_field='id',
        raw_response=results,
        outputs=remove_empty_elements(results_data),
    )


def test_module(client: Client):
    """
    Returning 'ok' indicates that the integration works like it suppose to. Connection to the service is successful.
    Args:
        client: CloudConvert client

    Returns:
        'ok' if test passed, anything else will fail the test
    """

    dummy_url = 'https://raw.githubusercontent.com/demisto/content/master/TestData/pdfworking.pdf'
    result = client.upload_url({'url': dummy_url})
    if result.get('data'):
        return 'ok'
    elif result.get('message') == "Unauthenticated.":
        return 'Authorization Error: make sure API Key is correctly set'
    elif result.get('message'):
        return result.get('message')
    else:
        return 'No response from server, the server could be temporary unavailable or it is handling too ' \
               'many requests. Please try again later.'


def format_operation_title(results: Dict[str, Any]):
    """
    This function is being used in order to change the titles of the operations that are done by the API and are
    returned in the response to titles that makes more sense for the users actions, and matches the API's use in
    our system.

    Args:
        results: The response from the http request

    """
    title_exchange_dict = {
        'import/url': 'upload/url',
        'import/upload': 'upload/entry',
        'export/url': 'download/url'}

    operation = results['data']['operation']

    results['data']['operation'] = title_exchange_dict[operation] if operation in title_exchange_dict.keys() \
        else operation


def main() -> None:
    try:
        command = demisto.command()
        params = demisto.params()
        api_key = params.get('apikey')
        verify = not params.get('insecure', False)
        proxy = params.get('proxy', False)
        headers = {
            'Authorization': f'Bearer {api_key}'
        }
        client = Client(headers, verify, proxy)

        if command == 'cloudconvert-upload':
            return_results(upload_command(client, demisto.args()))

        elif command == 'cloudconvert-convert':
            return_results(convert_command(client, demisto.args()))

        elif command == 'cloudconvert-check-status':
            return_results(check_status_command(client, demisto.args()))

        elif command == 'cloudconvert-download':
            return_results(download_command(client, demisto.args()))

        elif command == 'test-module':
            return_results(test_module(client))

    except Exception as e:
        err_msg = 'Task id not found or expired' if 'No query results for model' in str(e) else \
            ('No more conversion minutes for today for this user' if 'Payment Required' in str(e) else str(e))
        return_error(f'Failed to execute {command} command. Error: {err_msg}', error=traceback.format_exc())


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
