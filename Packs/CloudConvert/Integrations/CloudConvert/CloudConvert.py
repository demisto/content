import demistomock as demisto
from CommonServerPython import *

import tempfile

import urllib3

from typing import Any, Dict
# Disable insecure warnings
urllib3.disable_warnings()


class Client(BaseClient):

    def __init__(self, headers, verify=False, proxy=False):
        url = 'https://api.cloudconvert.com/v2'
        super().__init__(url, headers=headers, verify=verify, proxy=proxy)

    def import_url(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Import the file given as url to the API's server, for later conversion

        :type arguments: ``Dict[str, Any]``
        :param arguments: dict containing the request arguments, should contain the field 'url'
        :return: dict containing the results of the import action as returned from the API (status, file ID, etc.)
        :rtype: ``Dict[str, Any]``
        """
        return self._http_request(
            method='POST',
            url_suffix='import/url',
            headers=self._headers,
            data=arguments,
            timeout=25,
            ok_codes=(422, 200, 201, 500, 401)
        )

    def import_entry_id(self, file_path: str, file_name: str) -> Dict[str, Any]:
        """
        Import the file given as a war room entry id to the API's server, for later conversion

        :param file_path: path to given file, derived from the entry id
        :param file_name: name of file, including format suffix
        :return: dict containing the results of the import action as returned from the API (status, file ID, etc.)
        :rtype: ``Dict[str, Any]``
        """
        response_get_form = self._http_request(
            method='POST',
            url_suffix='import/upload',
            headers=self._headers
        )
        form = response_get_form.get('data').get('result').get('form')
        port_url = form.get('url')
        params = form.get('parameters')

        # Creating a temp file with the same data of the given file
        # This way the uploaded file has a path that the API can parse properly
        demisto.debug('creating a temp file for upload operation')
        with tempfile.TemporaryFile(suffix=file_name) as temp_file:
            with open(file_path, 'rb') as file:
                temp_file.write(file.read())
            temp_file.seek(0)
            file_dict = {file_name: temp_file}

            self._http_request(
                method='POST',
                url_suffix=None,
                full_url=port_url,
                headers=self._headers,
                files=file_dict,
                empty_valid_codes=[201, 204],
                return_empty_response=True,
                timeout=25,
                data=params
            )

        response_get_form['data'].pop('message')
        response_get_form['data'].pop('result')
        return response_get_form

    def convert(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert a file to desired format, given the file was priorly imported to the API's server

        :type arguments: ``Dict[str, Any]``
        :param arguments: dict containing the request arguments, should contain the fields 'task_id' and 'output_format'

        :return: dict containing the results of the convert action as returned from the API (status, file ID, etc.)
        :rtype: ``Dict[str, Any]``
        """
        arguments['input'] = arguments.pop('task_id')
        return self._http_request(
            method='POST',
            url_suffix='convert',
            headers=self._headers,
            data=arguments,
            timeout=25,
            ok_codes=(422, 200, 201, 500)
        )

    def check_status(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check the status of a request sent to the API's server

        :type arguments: ``Dict[str, Any]``
        :param arguments: dict containing the request arguments, should contain the field 'task_id'

        :return: dict containing the results of the check status action as returned from the API (status, file ID, etc.)
        :rtype: ``Dict[str, Any]``
        """
        task_id = arguments.get('task_id')
        return self._http_request(
            method='GET',
            url_suffix=f'/tasks/{task_id}',
            headers=self._headers,
            timeout=25,
            ok_codes=(422, 200, 201, 500)
        )

    def export_url(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Export a converted file to a url

        :type arguments: ``Dict[str, Any]``
        :param arguments: dict containing the request arguments, should contain the field 'task_id' of the desired file

        :return: dict containing the results of the export action as returned from the API (status, file ID, etc.)
                    if the action was complete, the result url will be a part of this dict. If the request is pending,
                    one should retrieve the url via the 'check_status' command
        :rtype: ``Dict[str, Any]``
        """
        arguments['input'] = arguments.pop('task_id')
        return self._http_request(
            method='POST',
            url_suffix='/export/url',
            headers=self._headers,
            data=arguments,
            timeout=25,
            ok_codes=(422, 200, 201, 500)
        )

    def get_file_from_url(self, url: str):
        """
        Call a GET http request in order to get the file data given as url
        :param url: url containing a file
        :return: request response, containing the data of the file
        """
        return self._http_request(
            method='GET',
            url_suffix=None,
            full_url=url,
            timeout=25,
            headers={'Content-Type': 'application/json'},
            resp_type='text'
        )


@logger
def import_command(client: Client, arguments: Dict[str, Any]):
    """
    Import a file to the API for later conversion
    :param client: CloudConvert client to use
    :param arguments: All command arguments - either 'url' or 'entry_id'.
    :return: CommandResults object containing the results of the import action as returned from the API and its
             readable output
    """

    if arguments.get('url'):
        results = client.import_url(arguments)
        results_data = results.get('data')
    elif arguments.get('entry_id'):
        demisto.debug('getting the path of the file from its entry id')
        result = demisto.getFilePath(arguments.get('entry_id'))
        if not result:
            raise ValueError('No file was found for given entry id')
        file_path, file_name = result['path'], result['name']
        results = client.import_entry_id(file_path, file_name)
        results_data = results.get('data')
    else:
        raise ValueError('No url or entry id specified')

    # No 'data' field was returned from the request, meaning the input was invalid
    if results_data is None:
        if results.get('message'):
            raise ValueError(results.get('message'))
        else:
            raise ValueError(
                'No response from server, check your request')

    readable_output = tableToMarkdown('Import Results', remove_empty_elements(results_data),
                                      headers=('created_at', 'id', 'operation', 'status'),
                                      headerTransform=string_to_table_header)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='CloudConvert.Task',
        outputs_key_field='id',
        outputs=results_data
    )


@logger
def convert_command(client: Client, arguments: Dict[str, Any]):
    """
    Convert a file that was priorly imported
    :param client: CloudConvert client to use
    :param arguments: All command arguments, the fields 'task_id' and 'output_format'
    :return: CommandResults object containing the results of the convert action as returned from the API and its readable output
    """
    results = client.convert(arguments)
    results_data = results.get('data')

    # No 'data' field was returned from the request, meaning the input was invalid
    if results_data is None:
        if results.get('message'):
            raise ValueError(results.get('message'))
        else:
            raise ValueError('No response from server')

    readable_output = tableToMarkdown('Convert Results', remove_empty_elements(results_data),
                                      headers=('created_at', 'depends_on_task_ids', 'id', 'operation', 'status'),
                                      headerTransform=string_to_table_header)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='CloudConvert.Task',
        outputs_key_field='id',
        outputs=results_data
    )


@logger
def check_status_command(client: Client, arguments: Dict[str, Any]):
    """
    Check status of an existing operation using it's task id
    :param client: CloudConvert client to use
    :param arguments: All command arguments, the field 'task_id'
        Note: When the checked operation is 'export to war room entry', the field 'is_entry' should be True.
        This way the results will be a war room entry containing the file.
    :return: CommandResults object containing the results of the check status action as returned from the API
     and its readable output OR if the argument is_entry is set to True, then a war room entry is returned
    """
    results = client.check_status(arguments)

    # If checking on an export to entry operation, manually change the operation name
    # For other operations, the operation matches the operation field in the API's response, so no change is needed
    if arguments.get('is_entry'):
        results['data']['operation'] = 'export/entry'
    results_data = results.get('data')

    # Check if no 'data' field was returned from the request, meaning the input was invalid
    if results_data is None:
        if results.get('message'):
            raise ValueError(results.get('message'))
        else:
            raise ValueError('No response from server, check your request')

    # Check if an export to war room entry operation is finished
    # If it did - create the entry
    if results.get('data', [{}]).get('status') == 'finished' and argToBoolean(arguments.get('is_entry', 'False')):
        url = results.get('data', {}).get('result', {}).get('files', [{}])[0].get('url')
        file_name = results.get('data', {}).get('result', {}).get('files', [{}])[0].get('filename')
        file_data = client.get_file_from_url(url)
        war_room_file = fileResult(filename=file_name, data=file_data)
        return_results(CommandResults(
            outputs_prefix='CloudConvert.Task',
            outputs_key_field='id',
            outputs=results_data
        ))
        return war_room_file

    else:
        readable_output = tableToMarkdown('Check Status Results', remove_empty_elements(results_data),
                                          headers=('created_at', 'depends_on_task_ids', 'id', 'operation', 'result',
                                                   'status'),
                                          headerTransform=string_to_table_header)
        return CommandResults(
            readable_output=readable_output,
            outputs_prefix='CloudConvert.Task',
            outputs_key_field='id',
            outputs=results_data
        )


@logger
def export_command(client: Client, arguments: Dict[str, Any]):
    """
    Export a converted file back to user, either as a url or directly to a war room entry
    Note: in order to get the resulted url/entry of the file you need to use a check-status command as well,
        since the response of the export command is usually responded before the file is fully exported (hence the
    'status' field is 'waiting', and not 'finished')
    :param client: CloudConvert client to use
    :param arguments: All command arguments, the fields 'task_id', and 'export_as' (url/war_room_entry)
    :return: CommandResults object containing the results of the export action as returned from the API, and its readable
     output.
    """
    # Call export to url request
    # In both url and war room entry we still first get a url
    results = client.export_url(arguments)
    results_data = results.get('data')

    # No 'data' field was returned from the request, meaning the input was invalid
    if results_data is None:
        if results.get('message'):
            raise ValueError(results.get('message'))
        else:
            raise ValueError('No response from server, check your request')

    # If exporting to war room entry, manually change the operation name
    if arguments['export_as'] == 'war_room_entry':
        results['data']['operation'] = 'export/entry'

    readable_output = tableToMarkdown('Export Results', remove_empty_elements(results_data),
                                      headers=('created_at', 'depends_on_task_ids', 'id', 'operation', 'status'),
                                      headerTransform=string_to_table_header)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='CloudConvert.Task',
        outputs_key_field='id',
        outputs=results_data
    )


def test_module(client: Client):
    """
    Returning 'ok' indicates that the integration works like it suppose to. Connection to the service is successful.
    :param client: CloudConvert client
    :return: 'ok' if test passed, anything else will fail the test
    """
    dummy_url = 'https://raw.githubusercontent.com/demisto/content/master/TestData/pdfworking.pdf'
    result = client.import_url({'url': dummy_url})
    if result.get('data'):
        return 'ok'
    elif result.get('message') == "Unauthenticated.":
        return 'Authorization Error: make sure API Key is correctly set'
    else:
        return 'Test failed'


def main() -> None:
    try:
        api_key = demisto.params().get('apikey')
        verify = not demisto.params().get('insecure', False)
        proxy = demisto.params().get('proxy', False)
        headers = {
            'Authorization': f'Bearer {api_key}'
        }
        client = Client(headers, verify, proxy)

        if demisto.command() == 'CloudConvert-import':
            return_results(import_command(client, demisto.args()))

        elif demisto.command() == 'CloudConvert-convert':
            return_results(convert_command(client, demisto.args()))

        elif demisto.command() == 'CloudConvert-checkstatus':
            return_results(check_status_command(client, demisto.args()))

        elif demisto.command() == 'CloudConvert-export':
            return_results(export_command(client, demisto.args()))

        elif demisto.command() == 'test-module':
            return_results(test_module(client))

    except Exception as e:
        err_msg = 'Task id not found or expired' if 'No query results for model' in str(e) else \
            ('No more conversion minutes for today for this user' if 'Payment Required' in str(e) else str(e))
        return_error(f'Failed to execute {demisto.command()} command. Error: {err_msg}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
