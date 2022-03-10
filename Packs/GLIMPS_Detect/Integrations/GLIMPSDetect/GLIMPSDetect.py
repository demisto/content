# Imports
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from gdetect import Client
''' IMPORTS '''

import json
import requests
import tempfile

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

# Class Client TO TEST


class Client(BaseClient):
    """
    Client will implement the service API, should not contain Cortex XSOAR logic.
    Should do requests and return data
    """

    def __init__(self, url: str, api_token: str, insecure: bool):
        super().__init__()
        self.url = url
        self.client = Client(url=self.url, token=api_token, insecure=insecure)

    def gdetect_send(self, filepath: str) -> str:
        """Sends file to GLIMPS Detect API.

        :type filepath: ``str``
        :param filepath: File to send to GLIMPS detect

        :return: ID of the entry file to send to GLIMPS detect
        :rtype: ``str``
        """

        return self.client.push(filepath)

    def gdetect_get(self, uuid: str) -> Dict[str, Any]:
        """Gets GLIMPS Detect result for given uuid.

        :type uuid: ``str``
        :param uuid: GLIMPS Detect Binary UUID

        :return: dict containing the analysis results
        :rtype: ``Dict[str, Any]``
        """

        return self.client.get(uuid)

# test_module TODO Checking errors


def test_module(client):
    """
    Returning 'ok' indicates that the integration works like it suppose to. Connection to the service is successful.

    Args:
        client: HelloWorld client

    Returns:
        'ok' if test passed, anything else will fail the test
    """
    with tempfile.NamedTemporaryFile() as tmp:
        result = client.gdetect_send(tmp.name)
        if 'Hello DBot' == result:  # Check errors
            return 'ok'
        else:
            return 'Test failed because ......'

# Commands TODO


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
    req = requests.get(f'/entry/download/{entry_id}')
    with tempfile.NamedTemporaryFile() as tmp:
        tmp.write(req.content)
        uuid = client.gdetect_send(tmp.name)

    # readable output will be in markdown format - https://www.markdownguide.org/basic-syntax/
    readable_output = f'## {uuid}'
    outputs = {
        'entryID': entry_id,
        'GLIMPSDetect UUID': uuid
    }

    results = CommandResults(
        outputs_prefix='GLIMPSDetect.Result',
        outputs_key_field='name',
        outputs=outputs,

        readable_output=readable_output,
        raw_response=uuid
    )

    return results


def gdetect_get_command(client, args):  # TO TEST
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
    results = client.gdetect_get(uuid)
    sid = results.pop('sid')
    results['link'] = f'{client.url}/expert/en/analysis/advanced/{sid}'
    outputs = results
    readable_output = '''
    ## GLIMPSDetect
    | PATH | VALUE |
    | ---  | --- |
    | GLIMPS.GDetect.UUID  | {uuid} |
    | GLIMPS.GDetect.SHA256  | {sha256} |
    | GLIMPS.GDetect.SHA1  | {sha1} |
    | GLIMPS.GDetect.MD5  | {md5} |
    | GLIMPS.GDetect.SSDeep  | {ssdeep} |
    | GLIMPS.GDetect.IsMalware  | {is_malware} |
    | GLIMPS.GDetect.Score  | {score} |
    | GLIMPS.GDetect.Done  | {done} |
    | GLIMPS.GDetect.Timestamp  | {timestamp} |
    | GLIMPS.GDetect.Filetype  | {filetype} |
    | GLIMPS.GDetect.Size  | {size} |
    | GLIMPS.GDetect.Filenames  | {filenames} |
    | GLIMPS.GDetect.Malwares  | {malwares} |
    '''.format(**results)
    for file in results.get('files'):
        readable_output += '''
        | GLIMPS.GDetect.File.SHA256  | {sha256} |
        | GLIMPS.GDetect.File.SHA1  | {sha1} |
        | GLIMPS.GDetect.File.MD5  | {md5} |
        | GLIMPS.GDetect.File.SSDeep  | {ssdeep} |
        | GLIMPS.GDetect.File.Magic  | {magic} |
        '''
        if file.get('is_malware'):
            for av_result in file.get('av_results'):
                readable_output += '''
                | GLIMPS.GDetect.File.AVResults.AV  | {av} |
                | GLIMPS.GDetect.File.AVResults.Result  | {result} |
                | GLIMPS.GDetect.File.AVResults.Score  | {score} |
                '''.format(**av_result)
        readable_output += '''
        | GLIMPS.GDetect.File.Size  | {size} |
        | GLIMPS.GDetect.File.IsMalware  | {is_malware} |
        '''
    readable_output += '''
    | GLIMPS.GDetect.FileCount  | {file_count} |
    | GLIMPS.GDetect.Duration  | {duration} |
    | GLIMPS.GDetect.Token  | {token} |
    | GLIMPS.GDetect.Status  | {status} |
    | GLIMPS.GDetect.Link  | {link} |
    '''.format(**results)

    results = CommandResults(
        outputs_prefix='GLIMPSDetect.Result',
        outputs_key_field='name',
        outputs=outputs,

        readable_output=readable_output,
        raw_response=outputs
    )

    return results

# Main TODO


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    try:
        client = Client(params.get('url'), params.get('api_token'), params.get('insecure'))
        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif command == 'gdetect-send':
            return_results(gdetect_send_command(client, demisto.args()))

        elif command == 'gdetect-get':
            return_results(gdetect_get_command(client, demisto.args()))

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {command} command. Error: {str(e)}')


# Start Main
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
