import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Any

import dateparser
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''


DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this HelloWorld implementation, no special attributes defined
    """

    def get_file_reputation(self, file: str) -> dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix=f'/hashes/{file}'
        )

    def get_health(self) -> dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix='/health'
        )

    def submit_file(self, files: dict[str, Any], data: dict[str, Any]) -> dict[str, Any]:
        return self._http_request(
            method='POST',
            url_suffix='/files',
            files=files,
            data=data
        )

    def submit_urls(self, data: dict[str, Any]) -> dict[str, Any]:
        return self._http_request(
            method='POST',
            url_suffix='/urls',
            files=data,
            data=None
        )

    def get_report_url(self, report_id: str, expiration: int) -> dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix=f'/presigned-url/{report_id}',
            params={
                'expiry': expiration
            }
        )

    def report_status(self, report_id: str, extended: str) -> dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix=f'/reports/{report_id}',
            params={
                'extended': extended
            }
        )

    def report_artifact(self, report_id: str, artifact_type: str) -> dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix=f'/artifacts/{report_id}',
            params={
                'type': artifact_type,
            },
            resp_type='content'
        )


''' HELPER FUNCTIONS '''


def convert_to_demisto_severity(severity: str) -> int:
    # In this case the mapping is straightforward, but more complex mappings
    # might be required in your integration, so a dedicated function is
    # recommended. This mapping should also be documented.
    return {
        'Low': 1,  # low severity
        'Medium': 2,  # medium severity
        'High': 3,  # high severity
        'Critical': 4   # critical severity
    }[severity]


def arg_to_int(arg: Any, arg_name: str, required: bool = False) -> int | None:
    if arg is None:
        if required is True:
            raise ValueError(f'Missing "{arg_name}"')
        return None
    if isinstance(arg, str):
        if arg.isdigit():
            return int(arg)
        raise ValueError(f'Invalid number: "{arg_name}"="{arg}"')
    if isinstance(arg, int):
        return arg
    raise ValueError(f'Invalid number: "{arg_name}"')


def arg_to_timestamp(arg: Any, arg_name: str, required: bool = False) -> int | None:
    if arg is None:
        if required is True:
            raise ValueError(f'Missing "{arg_name}"')
        return None

    if isinstance(arg, str) and arg.isdigit():
        # timestamp is a str containing digits - we just convert it to int
        return int(arg)
    if isinstance(arg, str):
        # we use dateparser to handle strings either in ISO8601 format, or
        # relative time stamps.
        # For example: format 2019-10-23T00:00:00 or "3 days", etc
        date = dateparser.parse(arg, settings={'TIMEZONE': 'UTC'})
        if date is None:
            # if d is None it means dateparser failed to parse it
            raise ValueError(f'Invalid date: {arg_name}')

        return int(date.timestamp())
    if isinstance(arg, int | float):
        # Convert to int if the input is a float
        return int(arg)
    raise ValueError(f'Invalid date: "{arg_name}"')


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    # INTEGRATION DEVELOPER TIP
    # Client class should raise the exceptions, but if the test fails
    # the exception text is printed to the Cortex XSOAR UI.
    # If you have some specific errors you want to capture (i.e. auth failure)
    # you should catch the exception here and return a string with a more
    # readable output (for example return 'Authentication Error, API Key
    # invalid').
    # Cortex XSOAR will print everything you return different than 'ok' as
    # an error
    try:
        #
        client.get_health()
    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return 'ok'


def get_hashes_command(client: Client, args: dict[str, Any]) -> tuple[str, dict, Any]:

    hashes = argToList(args.get('md5_hashes'))
    if len(hashes) == 0:
        raise ValueError('hash(es) not specified')

    for hash in hashes:
        if md5Regex.match(hash):
            continue
        raise Exception('Invalid hash. Only MD5 is supported.')

    dbot_score_list: list[dict[str, Any]] = []
    file_standard_list: list[dict[str, Any]] = []
    file_data_list: list[dict[str, Any]] = []

    for hash in hashes:
        file_data = client.get_file_reputation(hash)
        file_data['MD5'] = file_data['md5']
        del file_data['md5']
        # demisto.results(file_data)
        engines = file_data.get('engine_results', {})
        for key in engines:
            if engines[key].get('sha256'):
                file_data['SHA256'] = engines[key].get('sha256')
                del engines[key]['sha256']
        # If the outer `is_malicious` is set to True, assume the score should be bad
        # Otherwise, default to unknown unless at least one engine has returned a verdict besides `not_found`
        if file_data['is_malicious']:
            score = 3  # bad
        else:
            score = 0  # unknown
            for key in engines:
                verdict = engines[key].get('verdict', 'not_found')
                if verdict != "not_found" and verdict != "malicious":
                    score = 1  # good
                    break

        dbot_score = {
            'Indicator': hash,
            'Vendor': 'FireEye DoD',
            'Type': 'file',
            'Score': score
        }
        file_standard_context = {
            'MD5': hash,
        }

        if score == 3:
            # if score is bad must add DBotScore Vendor and Description
            file_standard_context['Malicious'] = {
                'Vendor': 'FireEye DoD'
            }

        filedata = {}
        filedata['FireEyeDoD'] = file_data
        filedata['MD5'] = file_data['MD5']
        del filedata['FireEyeDoD']['MD5']
        if file_data.get('SHA256'):
            dbot_score_sha256 = {
                'Indicator': file_data.get('SHA256'),
                'Vendor': 'FireEye DoD',
                'Type': 'file',
                'Score': score
            }
            dbot_score_list.append(dbot_score_sha256)
            filedata['SHA256'] = file_data['SHA256']
            file_standard_context['SHA256'] = file_data['SHA256']
            del filedata['FireEyeDoD']['SHA256']

        file_standard_list.append(file_standard_context)
        dbot_score_list.append(dbot_score)
        file_data_list.append(filedata)

    outputs = {
        'DBotScore(val.Vendor == obj.Vendor && val.Indicator == obj.Indicator)': dbot_score_list,
        outputPaths['file']: file_standard_list,
        'File(val.MD5 == obj.MD5 || val.SHA256 == obj.SHA256)': file_data_list
    }

    readable_output = tableToMarkdown('FireEye DoD Results', file_standard_list, headers=["MD5", "SHA256", "Malicious"])

    return (
        readable_output,
        outputs,
        file_data_list
    )


def generate_report_url(client: Client, args: dict[str, Any]) -> tuple[str, dict, dict]:
    report_id = str(args.get('report_id'))
    expiration = arg_to_int(arg=args.get('expiration'), arg_name='expiration', required=True)
    if expiration:
        if expiration < 1 or expiration > 8760:
            raise ValueError('Expiration must be between 1 and 8760 hours.')
    else:
        raise ValueError('Expiration not specified or not a number.')

    report = client.get_report_url(report_id=report_id, expiration=expiration)
    presigned_report_url = report.get('presigned_report_url')

    readable_output = f'Report {report_id} is available [here]({presigned_report_url})'

    return (
        readable_output,
        {},
        report
    )


def submit_file_command(client: Client, args: dict[str, Any]) -> tuple[str, dict, dict]:
    entry_id = demisto.args().get('entryID')
    file_entry = demisto.getFilePath(entry_id)  # .get('path')
    file_name = file_entry['name']
    file_path = file_entry['path']
    files = {'file': (file_name, open(file_path, 'rb'))}

    # Optional parameters to send along with the file
    optional_params = ['password', 'param', 'screenshot', 'video', 'fileExtraction', 'memoryDump', 'pcap']
    data = {}
    for param in optional_params:
        value = demisto.args().get(param)
        if value:
            data[param] = value

    scan = client.submit_file(files=files, data=data)

    scan['filename'] = file_name
    del scan['status']
    scan['overall_status'] = 'RUNNING'

    report_id = scan.get('report_id')

    readable_output = (
        f'Started analysis of {file_name} with FireEye Detection on Demand.'
        f'Results will be published to report id: {report_id}'
    )
    outputs = {
        'FireEyeDoD.Scan(val.report_id == obj.report_id)': scan
    }
    return (
        readable_output,
        outputs,
        scan
    )


def submit_urls_command(client: Client, args: dict[str, Any]) -> tuple[str, dict, dict]:
    urls = argToList(args.get('urls'))
    if len(urls) == 0:
        raise ValueError('hash(es) not specified')

    # Format the URLs into a string list, which the API understands
    formatted_urls = "[" + ",".join([url.replace(url, f'"{url}"') for url in urls]) + "]"
    data = {'urls': formatted_urls}

    scan = client.submit_urls(data=data)

    del scan['status']
    scan['overall_status'] = 'RUNNING'

    report_id = scan.get('report_id')

    readable_output = (
        f'Started analysis of {urls} with FireEye Detection on Demand.'
        f'Results will be published to report id: {report_id}'
    )
    outputs = {
        'FireEyeDoD.Scan(val.report_id == obj.report_id)': scan
    }
    return (
        readable_output,
        outputs,
        scan
    )


def get_reports_command(client: Client, args: dict[str, Any]) -> tuple[str, dict, Any]:
    report_id_list = argToList(args.get('report_ids', []))
    extended = args.get('extended_report', "False")
    screenshot = args.get('get_screenshot', "false")
    artifact = args.get('get_artifact', "")
    if len(report_id_list) == 0:
        raise ValueError('report_id(s) not specified')

    report_list: list[dict[str, Any]] = []
    for report_id in report_id_list:
        report = client.report_status(report_id=report_id, extended=extended)
        if screenshot.lower() == "true":
            screenshot = client.report_artifact(report_id=report_id, artifact_type="screenshot")
            stored_img = fileResult('screenshot.gif', screenshot)
            demisto.results({'Type': entryTypes['image'], 'ContentsFormat': formats['text'],
                             'File': stored_img['File'], 'FileID': stored_img['FileID'], 'Contents': ''})

        if artifact != "":
            artifacts = client.report_artifact(report_id=report_id, artifact_type=artifact)
            stored_artifacts = fileResult('artifacts.zip', artifacts)
            demisto.results({'Type': entryTypes['file'], 'ContentsFormat': formats['text'],
                             'File': stored_artifacts['File'], 'FileID': stored_artifacts['FileID'], 'Contents': ''})

        report_list.append(report)

    readable_output = tableToMarkdown('Scan status', report_list)
    outputs = {
        'FireEyeDoD.Scan(val.report_id == obj.report_id)': report_list
    }
    return (
        readable_output,
        outputs,
        report_list
    )


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    api_key = demisto.params().get('apikey')

    # get the service API url
    base_url = demisto.params()['url']

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not demisto.params().get('insecure', False)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = demisto.params().get('proxy', False)

    # INTEGRATION DEVELOPER TIP
    # You can use functions such as ``demisto.debug()``, ``demisto.info()``,
    # etc. to print information in the XSOAR server log. You can set the log
    # level on the server configuration
    # See: https://xsoar.pan.dev/docs/integrations/code-conventions#logging

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        headers = {
            'feye-auth-key': f'{api_key}'
        }
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)

        elif demisto.command() == 'fireeye-dod-get-hashes':
            return_outputs(*get_hashes_command(client, demisto.args()))

        elif demisto.command() == 'fireeye-dod-get-reports':
            return_outputs(*get_reports_command(client, demisto.args()))

        elif demisto.command() == 'fireeye-dod-submit-file':
            return_outputs(*submit_file_command(client, demisto.args()))

        elif demisto.command() == 'fireeye-dod-submit-urls':
            return_outputs(*submit_urls_command(client, demisto.args()))

        elif demisto.command() == 'fireeye-dod-get-report-url':
            return_outputs(*generate_report_url(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        raise e
        # demisto.error(traceback.format_exc())  # print the traceback
        # return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
