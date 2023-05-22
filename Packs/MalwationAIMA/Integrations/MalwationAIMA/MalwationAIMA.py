import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import urllib3
# disable insecure warnings
urllib3.disable_warnings()

''' GLOBAL VARIABLES '''
VERIFY_SSL = not demisto.params().get('insecure', False)

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
handle_proxy()


def test_module(params) -> str:
    """Tests API connectivity and authentication'"
    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.
    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    try:
        url = params.get('url')[:-1] if str(params.get('url')).endswith('/') \
            else params.get('url')
        credentials = params.get('apikey')
        creds = "Bearer " + credentials
        headers = {"Authorization": creds}
        url = urljoin(url, '/customer/getSubmission/7bf5ba92-30e1-4d42-821f-6d4ac94c3be1')
        response = requests.request("GET", url, headers=headers)
        status = response.status_code
        if status != 200:
            if 'UnauthorizedError' in str(response.content):
                return 'Authorization Error: make sure API Key is correctly set'
            else:
                return str(status)
    except Exception as e:
        raise e
    return 'ok'


class Client(BaseClient):
    """Client class to interact with the service API
    This Client implements API calls, and does not contain any SOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    """

    def aima_add(self, param: dict) -> Dict[str, Any]:
        """Sends the sample to AIMA url using the '/customer/addSubmission/' API endpoint

        :return: dict containing the sample uuid as returned from the API
        :rtype: ``Dict[str, Any]``
        """
        if param['file_from_zip'] == '':
            payload = {'metafields': '{ "data": { "environment":' + param['environment'] + ', "work_path":' + param[
                'work_path'] + ', "timeout":' + param['timeout'] + ', "mouse_simulation": ' + param[
                'mouse_simulation'] + ', "config_extractor": ' + param[
                'config_extractor'] + ', "https_inspection": ' + param[
                'https_inspection'] + ', "full_memory_dump": ' + param[
                'full_memory_dump'] + ', "enable_net": ' + param['enable_net'] + ' } }',
                'isPublic': '{ "data": ' + param['isPublic'] + ' }'}
        else:
            payload = {'metafields': '{ "data": { "environment":' + param['environment'] + ', "work_path":"' + param[
                'work_path'] + '", "timeout":' + param['timeout'] + ', "mouse_simulation": ' + param[
                'mouse_simulation'] + ', "config_extractor": ' + param[
                'config_extractor'] + ', "https_inspection": ' + param[
                'https_inspection'] + ', "full_memory_dump": ' + param[
                'full_memory_dump'] + ', "enable_net": ' + param['enable_net'] + ' } }',
                'isPublic': '{ "data": ' + param['isPublic'] + ' }',
                'zip': '{ "data": { "zipSelectName": "' + param['file_from_zip'] + '", "zipPassword": "' + param[
                'zip_pass'] + '" } }'}
        return self._http_request(
            method='POST',
            url_suffix='/customer/addSubmission',
            data=payload,
            files=param['files']

        )

    def aima_get(self, param: dict) -> Dict[str, Any]:
        """Gets the sample scan result from AIMA using the '/customer/getSubmission/' API endpoint

        :return: dict containing the sample scan results as returned from the API
        :rtype: ``Dict[str, Any]``
        """
        return self._http_request(
            method='GET',
            url_suffix='/customer/getSubmission/' + param['uuid']
        )

    def cap_mav_add(self, param: dict) -> Dict[str, Any]:
        """Submits the sample to AIMA url using the '/mav/upload/' API endpoint

        :return: dict containing the sample uuid as returned from the API
        :rtype: ``Dict[str, Any]``
        """
        return self._http_request(
            method='POST',
            url_suffix='/mav/upload',
            files=param['files']
        )

    def cap_mav_get(self, param: dict) -> Dict[str, Any]:
        """Gets the sample scan result from AIMA using the '/mav/filestatus/' API endpoint

        :return: dict containing the sample scan results as returned from the API
        :rtype: ``Dict[str, Any]``
        """
        return self._http_request(
            method='GET',
            url_suffix='/mav/filestatus/' + param['uuid']
        )

    def cap_static_add(self, param: dict) -> Dict[str, Any]:
        """Submits the sample to AIMA url using the '/capstatic/upload/' API endpoint """

        return self._http_request(
            method='POST',
            url_suffix='/capstatic/upload',
            files=param['files']
        )

    def cap_static_get(self, param: dict) -> Dict[str, Any]:
        """Gets the sample scan result from Malwation CAP using the '/capstatic/filestatus/' API endpoint"""

        return self._http_request(
            method='GET',
            url_suffix='/capstatic/filestatus/' + param['uuid']
        )


def aima_upload_sample(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Uploads the sample to the AIMA sandbox to analyse with required or optional selections."""

    ispublic = args.get('isPublic')

    if args.get('environment') == 'win7x64':
        environment = '1'
    else:
        environment = '2'

    if args.get('zip_pass'):
        zip_pass = args.get('zip_pass')
        file_from_zip = args.get('file_from_zip')
    else:
        zip_pass = ''
        if args.get('file_from_zip'):
            file_from_zip = args.get('file_from_zip')
        else:
            file_from_zip = ''

    work_path = args.get('work_path')
    timeout = args.get('timeout')
    mouse_simulation = args.get('mouse_simulation')
    config_extractor = args.get('config_extractor')
    https_inspection = args.get('https_inspection')
    full_memory_dump = args.get('full_memory_dump')
    enable_net = args.get('enable_net')
    file = args.get('file_path')
    file_id = args.get('entry_id')
    file_obj = demisto.getFilePath(file_id)
    file_name = encode_file_name(file_obj['name'])
    file_path = file_obj['path']

    files = [
        ('file', (file_name, open(file_path, 'rb'), 'application/octet-stream'))
    ]

    param = {
        'isPublic': ispublic,
        'environment': environment,
        'work_path': work_path,
        'timeout': timeout,
        'mouse_simulation': mouse_simulation,
        'config_extractor': config_extractor,
        'https_inspection': https_inspection,
        'full_memory_dump': full_memory_dump,
        'enable_net': enable_net,
        'file_path': file,
        'zip_pass': zip_pass,
        'file_from_zip': file_from_zip,
        'files': files
    }

    result = client.aima_add(param=param)

    readable_output = tableToMarkdown('SAMPLE UPLOADED', result)

    uuid = result['uuid']
    url = result['link']

    return CommandResults(
        readable_output=readable_output,
        outputs_key_field='results',
        outputs={'AIMA.Analysis(val.Job_ID == obj.Job_ID)': {'UUID': uuid, 'URL': url}}
    )


def aima_get_result(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Retrive the sample scan result from the AIMA sandbox.

        :type uuid: ``str``
        :param - uuid: For filtering with status
        :Available values :
        """
    uuid = args.get('uuid')

    param = {
        'uuid': uuid
    }

    result = client.aima_get(param=param)
    try:
        status = result['status']
        md5 = result['submission']['file_info']['hashes']['md5']
        sha1 = result['submission']['file_info']['hashes']['sha1']
        sha256 = result['submission']['file_info']['hashes']['sha256']
        submission_info = {'file_name': result['submission']['file_info']['original_name'],
                           'status_id': result['submission']['file_info']['status_id'],
                           'isPublic': result['submission']['file_info']['isPublic']}
        result_url = result['submission']['resultURL']
        submission_id = result['submission']['uuid']
        level = result['submissionLevel']
        output = {'AIMA.Result(val.Job_ID == obj.Job_ID)': {'STATUS': status, 'MD5': md5, 'SHA1': sha1,
                                                            'SHA256': sha256, 'LEVEL': level, 'INFO': submission_info,
                                                            'URL': result_url, 'ID': submission_id}}
        readable_output = tableToMarkdown('Submission Result',
                                          {'STATUS': status, 'MD5': md5, 'SHA1': sha1,
                                           'SHA256': sha256, 'THREAT_LEVEL': level,
                                           'FILE_NAME': result['submission']['file_info']['original_name'],
                                           'STATUS_ID': result['submission']['file_info']['status_id'],
                                           'isPublic': result['submission']['file_info']['isPublic'],
                                           'SCAN_URL': result_url, 'ID': submission_id})
    except Exception:
        status = result['status']
        output = {'AIMA.Result(val.Job_ID == obj.Job_ID)': {'STATUS': status}}
        readable_output = tableToMarkdown('Submission Result', result)

    return CommandResults(
        readable_output=readable_output,
        outputs_key_field='results',
        outputs=output
    )


def cap_mav_get_submission(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Retrive the sample scan result from the CAP MAV."""

    uuid = args.get('uuid')

    param = {
        'uuid': uuid
    }

    result = client.cap_mav_get(param=param)

    try:
        if result['detection']:
            count = result['detection']
            score = result['status']
            detections = result['scan_results']
            output = {'CAP.Mav(val.Job_ID == obj.Job_ID)': {'COUNT': count, 'SCORE': score, 'DETECTIONS': detections}}
            readable_output = tableToMarkdown('Submission Result',
                                              {'DETECTION_COUNT': count, 'SCORE': score, 'VENDOR_RESULTS': detections})

        else:
            status = result['status']
            output = {'CAP.Mav(val.Job_ID == obj.Job_ID)': {'STATUS': status}}
            readable_output = tableToMarkdown('Submission Result', result)

    except Exception:
        status = result['status']
        output = {'CAP.Mav(val.Job_ID == obj.Job_ID)': {'STATUS': status}}
        readable_output = tableToMarkdown('Submission Result', result)

    return CommandResults(
        readable_output=readable_output,
        outputs_key_field='results',
        outputs=output
    )


def cap_mav_upload_sample(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Uploads the sample to the CAP MAV to analyse."""

    file_id = args.get('entry_id')
    file_obj = demisto.getFilePath(file_id)
    file_name = encode_file_name(file_obj['name'])
    file_path = file_obj['path']

    files = [
        ('file', (file_name, open(file_path, 'rb'), 'application/octet-stream'))
    ]
    param = {
        'files': files
    }

    result = client.cap_mav_add(param=param)

    readable_output = tableToMarkdown('SAMPLE UPLOADED', result)
    uuid = result['uid']

    return CommandResults(
        readable_output=readable_output,
        outputs_key_field='results',
        outputs={'CAP.Mav(val.Job_ID == obj.Job_ID)': {'UUID': uuid}}
    )


def cap_static_get_submission(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Retrive the sample scan result from the CAP Static."""

    uuid = args.get('uuid')

    param = {
        'uuid': uuid
    }

    result = client.cap_static_get(param=param)

    readable_output = tableToMarkdown('Submission Result', result)

    try:
        if result['Score'][0]:
            score = result['Score'][0]
            weight = result['Score'][1]
            yara_rules = result["Matched YARA rules"]
            entropy = result['File Info']['Entropy']
            output = {'CAP.Static(val.Job_ID == obj.Job_ID)': {'SCORE': score, 'WEIGHT': weight, 'YARA': yara_rules,
                                                               'ENTROPY': entropy}}

        else:
            status = result['status']
            output = {'CAP.Static(val.Job_ID == obj.Job_ID)': {'STATUS': status}}
    except Exception:
        status = result['status']
        output = {'CAP.Static(val.Job_ID == obj.Job_ID)': {'STATUS': status}}

    return CommandResults(
        readable_output=readable_output,
        outputs_key_field='results',
        outputs=output
    )


def cap_static_upload_sample(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Uploads the sample to the CAP STATIC SCANNER to analyse."""

    file_id = args.get('entry_id')
    file_obj = demisto.getFilePath(file_id)
    file_name = encode_file_name(file_obj['name'])
    file_path = file_obj['path']

    files = [
        ('file', (file_name, open(file_path, 'rb'), 'application/octet-stream'))
    ]
    param = {
        'files': files
    }

    result = client.cap_static_add(param=param)

    readable_output = tableToMarkdown('SAMPLE UPLOADED', result)
    uuid = result['uid']

    return CommandResults(
        readable_output=readable_output,
        outputs_key_field='results',
        outputs={'CAP.Static(val.Job_ID == obj.Job_ID)': {'UUID': uuid}}
    )


def encode_file_name(file_name):
    """
    encodes the file name - i.e ignoring non ASCII chars and removing backslashes
    Args:
        file_name (str): name of the file
    Returns: encoded file name
    """
    return file_name.encode('ascii', 'ignore')


def main() -> None:  # pragma: no cover
    """main function, parses params and runs command functions
    :return:
    :rtype:
    """
    params = demisto.params()
    base_url = params['url']
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    ''' EXECUTION '''
    # LOG('command is %s' % (demisto.command(), ))
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    args = demisto.args()
    if 'cap' not in command:
        try:
            credentials = params.get('apikey')
            creds = "Bearer " + credentials
            headers = {'Authorization': creds}

            client = Client(
                base_url=base_url,
                verify=verify_certificate,
                headers=headers,
                proxy=proxy)

            if command == 'test-module':
                demisto.results(test_module(params))
            elif command == 'aima-upload-sample':
                return_results(aima_upload_sample(client, args))
            elif command == 'aima-get-result':
                return_results(aima_get_result(client, args))

        # Log exceptions and return errors
        except Exception as e:
            return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')
    else:
        try:
            credentials = params.get('cap_apikey')
            creds = credentials
            headers = {'api-key': creds}
            client = Client(
                base_url=base_url,
                verify=verify_certificate,
                headers=headers,
                proxy=proxy)
            if command == 'aima-cap-mav-upload-sample':
                return_results(cap_mav_upload_sample(client, args))
            elif command == 'aima-cap-mav-get-submission':
                return_results(cap_mav_get_submission(client, args))
            elif command == 'aima-cap-static-upload-sample':
                return_results(cap_static_upload_sample(client, args))
            elif command == 'aima-cap-static-get-submission':
                return_results(cap_static_get_submission(client, args))
                # Log exceptions and return errors
        except Exception as e:
            return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
