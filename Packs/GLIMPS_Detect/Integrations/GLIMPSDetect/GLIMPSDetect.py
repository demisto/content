import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# Imports
from CommonServerUserPython import *
from gdetect.api import HTTPExceptions, Client as gClient, logger as gLogger
from gdetect.exceptions import GDetectError
import logging
''' IMPORTS '''

from copy import copy
from urllib3 import disable_warnings

# Disable insecure warnings
disable_warnings()


class Client(BaseClient):
    """
    Client will implement the service API, should not contain Cortex XSOAR logic.
    Should do requests and return data
    """

    def __init__(self, base_url: str, api_token: str, verify: bool, proxy: bool):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        gLogger.setLevel(logging.CRITICAL)
        self.gclient = gClient(url=self._base_url, token=api_token)
        self.gclient.verify = not self._verify

    def gdetect_send(self, filepath: str) -> str:
        """Sends file to GLIMPS Detect API.

        :type filepath: ``str``
        :param filepath: File to send to GLIMPS detect

        :return: ID of the entry file to send to GLIMPS detect
        :rtype: ``str``
        """

        return self.gclient.push(filepath)

    def gdetect_get(self, uuid: str) -> Dict[str, Any]:
        """Gets GLIMPS Detect result for given uuid.

        :type uuid: ``str``
        :param uuid: GLIMPS Detect Binary UUID

        :return: dict containing the analysis results
        :rtype: ``Dict[str, Any]``
        """

        return self.gclient.get_by_uuid(uuid)


def test_module(client):
    """
    Returning the response to a dummy request. Connection to the service is successful if status_code is 200 ('ok').

    Args:
        client: GLIMPSDetect client

    Returns:
       Response to GLIMPS analysis request. Response with status code other than 200 will fail the test.
    """
    response = client.gdetect_get('00000000-0000-0000-0000-000000000000')
    return response


def gdetect_send_command(client, args):  # TO TEST
    """
    Returns GLIMPS Detect Binary UUID.

    Args:
        client: GLIMPSDetect client
        args: all command arguments

    Returns:
        GLIMPS Detect Binary UUID.

        readable_output: This will be presented in Warroom - should be in markdown syntax - human readable
        outputs: Dictionary/JSON - saved in incident context in order to be used as input for other tasks in the
                 playbook
        raw_response: Used for debugging/troubleshooting purposes - will be shown only if the command executed with
                      raw-response=true
    """
    entry_id = args.get('entryID')
    res = demisto.getFilePath(entry_id)
    if not res:
        return f'File entry: {entry_id} not found'
    filepath = res.get('path')
    uuid = client.gdetect_send(filepath)
    readable_output = f'## The file was sent successfully, UUID: {uuid}'
    outputs = {
        'entryID': entry_id,
        'uuid': uuid
    }

    results = CommandResults(
        outputs_prefix='GLIMPS.GDetect.Send',
        outputs_key_field='entryID',
        outputs=outputs,
        readable_output=readable_output,
        raw_response=uuid
    )

    return results


def gdetect_get_all_command(client, args):  # TO TEST
    """
    Returns GLIMPS Detect analysis results

    Args:
        client: GLIMPSDetect client
        args: all command arguments

    Returns:
        GLIMPS GLIMPS Detect analysis results

        readable_output: This will be presented in Warroom - should be in markdown syntax - human readable
        outputs: Dictionary/JSON - saved in incident context in order to be used as input for other tasks in the
                 playbook
        raw_response: Used for debugging/troubleshooting purposes - will be shown only if the command executed with
                      raw-response=true
    """

    uuid = args.get('uuid')
    response = client.gdetect_get(uuid)
    url = client._base_url.strip('/')
    if 'error' in response:
        readable_buffer = tableToMarkdown('Error', response, ['status', 'error'])
        if 'errors' in response:
            errors = response.get('errors')
            readable_buffer += tableToMarkdown('Errors', errors, errors.keys())
        results = CommandResults(
            outputs_prefix='GLIMPS.GDetect.All',
            outputs=response,
            raw_response=response,
            readable_output=readable_buffer
        )
        return results

    if 'token' in response:
        response.pop('sid')
        response['link'] = f"{url}/expert/en/analysis-redirect/{response.get('token')}"
    elif 'sid' in response:
        sid = response.pop('sid')
        response['link'] = f'{url}/expert/en/analysis/advanced/{sid}'
    else:
        response['link'] = f"{url}/lite/analysis/response/{response.get('uuid')}"

    raw_response = copy(response)
    readable_output = ''
    readable_buffer = ''

    if 'files' in response:
        files = response.get('files')
        for file in files:
            av_results_buffer = ''
            if 'av_results' in file:
                av_results = file.get('av_results')
                av_results_buffer = tableToMarkdown(f"AV Result for {file.get('sha256')}", av_results, ['av', 'result', 'score'])
            readable_buffer += tableToMarkdown('File', file, ['sha256', 'sha1', 'md5', 'ssdeep', 'magic', 'size', 'is_malware'])
            readable_buffer += av_results_buffer

    if 'threats' in response:
        threats = response.get('threats')
        for sha256, threat in threats.items():
            tags = threat.get('tags')
            readable_buffer += tableToMarkdown(f'Threat {sha256}', threat,
                                               ['filenames', 'score', 'magic', 'sha256', 'sha1', 'md5', 'ssdeep', 'file_size',
                                                'mime'])
            readable_buffer += tableToMarkdown(f'Tags of threat {sha256}', tags, ['name', 'value'])

    readable_output = tableToMarkdown('Results', response, ['done', 'duration',
                                                            'file_count', 'filenames', 'filetype', 'is_malware', 'link',
                                                            'malwares', 'md5', 'score', 'sha1', 'sha256', 'size', 'ssdeep',
                                                            'status', 'timestamp', 'token', 'uuid', 'error'], removeNull=True)
    readable_output += readable_buffer
    results = CommandResults(
        outputs_prefix='GLIMPS.GDetect.All',
        outputs_key_field='uuid',
        outputs=raw_response,
        raw_response=raw_response,
        readable_output=readable_output,
    )

    return results


def gdetect_get_threats_command(client, args):  # TO TEST
    """
    Returns GLIMPS Detect analysis results

    Args:
        client: GLIMPSDetect client
        args: all command arguments

    Returns:
        GLIMPS GLIMPS Detect analysis results

        readable_output: This will be presented in Warroom - should be in markdown syntax - human readable
        outputs: Dictionary/JSON - saved in incident context in order to be used as input for other tasks in the
                 playbook
        raw_response: Used for debugging/troubleshooting purposes - will be shown only if the command executed with
                      raw-response=true
    """
    uuid = args.get('uuid')
    response = client.gdetect_get(uuid)
    url = client._base_url.strip('/')
    link = ''
    if 'token' in response:
        if 'sid' in response:
            response.pop('sid')
        link = f"{url}/expert/en/analysis-redirect/{response.get('token')}"
    elif 'sid' in response:
        sid = response.pop('sid')
        link = f'{url}/expert/en/analysis/advanced/{sid}'
    else:
        link = f"{url}/lite/analysis/response/{response.get('uuid')}"

    if 'threats' not in response:
        raw_response = dict()
        raw_response['link'] = link
        raw_response['uuid'] = uuid
        raw_response['result'] = 'None'
        readable_output = '## No threats\n'
        readable_output += f'Please use !gdetect-get-all or go to the [full result]({link}) for more'
        results = CommandResults(
            outputs_prefix='GLIMPS.GDetect.Threats',
            outputs_key_field=uuid,
            outputs=raw_response,
            readable_output=readable_output,
            raw_response=raw_response
        )
        return results

    readable_output = ''
    raw_response = response.get('threats')
    for sha256, threat in response.get('threats').items():
        tags = threat.get('tags')
        readable_output += tableToMarkdown(f'Threat {sha256}', threat,
                                           ['filenames', 'score', 'magic', 'sha256', 'sha1', 'md5', 'ssdeep', 'file_size',
                                            'mime'])
        readable_output += tableToMarkdown(f'Tags of threat {sha256}', tags, ['name', 'value'])
    raw_response['link'] = link
    raw_response['uuid'] = uuid
    readable_output += f'[Link to the analysis in the GLIMPS Malware Expert interface]({link})'
    results = CommandResults(
        outputs_prefix='GLIMPS.GDetect.Threats',
        outputs_key_field='uuid',
        outputs=raw_response,
        readable_output=readable_output,
        raw_response=raw_response
    )

    return results


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    command = demisto.command()
    error = None
    try:
        client = Client(params.get('url'), params.get('api_token'), params.get('insecure'), params.get('proxy'))
        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            response = test_module(client)

            code = response.status_code
            if code == 200 or code == 404:
                return_results('ok')
            error = f'GDetect server error: {code} {HTTPExceptions.get(code, "unexpected HTTP error")}'
        elif command == 'gdetect-send':
            return_results(gdetect_send_command(client, demisto.args()))
        elif command == 'gdetect-get-all':
            return_results(gdetect_get_all_command(client, demisto.args()))
        elif command == 'gdetect-get-threats':
            return_results(gdetect_get_threats_command(client, demisto.args()))

    # Log exceptions
    except GDetectError as e:
        return_error(str(e))
    except Exception as e:
        return_error(f'Failed to execute {command} command. Error: {str(e)}')
    if error is not None:
        return_error(error)


# Start Main
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
