
import urllib3, requests
from typing import Dict, Any

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def threatzone_add(self, param: dict) -> Dict[str, Any]:
        """Sends the sample to ThreatZone url using the '/public-api/scan/' API endpoint

        :return: dict containing the sample uuid as returned from the API
        :rtype: ``Dict[str, Any]``
        """
        payload = []
        if param['scan_type'] == "sandbox":
            payload = [
                { "metafieldId": "environment", "value": param['environment'] },
                { "metafieldId": "private", "value": param['private'] },
                { "metafieldId": "timeout", "value": param['timeout'] },
                { "metafieldId": "work_path", "value": param['work_path'] },
                { "metafieldId": "mouse_simulation", "value": param['mouse_simulation'] },
                { "metafieldId": "https_inspection", "value": param['https_inspection'] },
                { "metafieldId": "internet_connection", "value": param['internet_connection'] },
                { "metafieldId": "raw_logs", "value": param['raw_logs'] },
                { "metafieldId": "snapshot", "value": param['snapshot'] }
            ]
        suffix = '/public-api/scan/' + param['scan_type']
        return self._http_request(
            method='POST',
            url_suffix=suffix,
            data=payload,
            files=param['files']

        )

    def threatzone_get(self, param: dict) -> Dict[str, Any]:
        """Gets the sample scan result from ThreatZone using the '/public-api/get/submission/' API endpoint

        :return: dict containing the sample scan results as returned from the API
        :rtype: ``Dict[str, Any]``
        """
        return self._http_request(
            method='GET',
            url_suffix='/public-api/get/submission/' + param['uuid']
        )

    def threatzone_get_sanitized(self, uuid):
        http = urllib3.PoolManager()
        url = f'https://app.threat.zone/download/v1/download/cdr/{uuid}'
        # this method is only for tests, sanitized file downlaod will be implemented in API side.
        headers = {
        'Cookie': "accesstoken=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI2M2YyZDE3NzI0NGJmN2Q5NzIwOWFjMTQiLCJlbWFpbCI6ImlzbWFpbHB2bzE1MzVAZ21haWwuY29tIiwiaWF0IjoxNjk0Nzg3NDkxLCJleHAiOjE2OTQ3ODkyOTEsImlzcyI6Imh0dHBzOi8vYXBwLnRocmVhdC56b25lIn0.xCSBD-L0ZKwh3WAz5GOUtu3bW_ynsZAS04-3SWca8PM; refreshtoken=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI2M2YyZDE3NzI0NGJmN2Q5NzIwOWFjMTQiLCJlbWFpbCI6ImlzbWFpbHB2bzE1MzVAZ21haWwuY29tIiwiaWF0IjoxNjk0Nzg3NDkxLCJleHAiOjE2OTQ3OTgyOTEsImlzcyI6Imh0dHBzOi8vYXBwLnRocmVhdC56b25lIn0.xGSRZ8JuD1P3-tAoFNwP7IFVX2vBJE9md4BeNrwR8us"
        }
        r = http.request('GET', url, headers=headers)
        return r.data


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
        url = urljoin(url, '/public-api/get/submission/41704f61-6f3f-4241-9e81-f13f9e532e37')
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

def encode_file_name(file_name):
    """
    encodes the file name - i.e ignoring non ASCII chars and removing backslashes
    Args:
        file_name (str): name of the file
    Returns: encoded file name
    """
    return file_name.encode('ascii', 'ignore')


def generate_dbotscore(report):
    """Creates DBotScore object based on the contents of 'report' argument
    :param:Object returned by ThreatZone API call in 'threatzone_get' function.
    :ptype: dict
    :return: A DBotScore object.
    :rtype: dict
    """
    indicator_type = 'SHA256'
    threat_text = report.get('THREAT_LEVEL')
    indicator = report.get('SHA256')
    dbot_score = {
        "DBotScore": {
            "Indicator": indicator,
            "Type": indicator_type,
            "Vendor": "ThreatZone",
            "Score": threat_text,
            "Reliability": demisto.params().get("integrationReliability")
        }
    }

    # db_score = Common.DBotScore(indicator=indicator, indicator_type=indicator_type,
    #                                 integration_name="ThreatZone", score=threat_text).to_context()
        # we are using Common.DBotScore.CONTEXT_PATH for 5.5.0+ and CONTEXT_PATH for 5.0.0
    return dbot_score

def threatzone_get_result(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Retrive the sample scan result from ThreatZone.
        :param - uuid: For filtering with status
        :type uuid: ``str``
        :return: list containing result returned from ThreatZone API and human reable output
        :rtype: ``list``
    """
    uuid = args.get('uuid')
    param = {
        'uuid': uuid
    }

    result = client.threatzone_get(param=param)
    stats = {
        1: "File received",
        2: "Submission is failed",
        3: "Submission is running",
        4: "Submission VM is ready",
        5: "Submission is finished"
    }

    levels = {
        0: "Not Measured",
        1: "Informative",
        2: "Suspicious",
        3: "Malicious"
    }
    def create_res(readable_dict, output):
        readable_output = tableToMarkdown('Submission Result', readable_dict)
        return [
            CommandResults(
                readable_output=readable_output,
                outputs_key_field='results',
                outputs=output
                )
            ]
    try:
        report_type = ""
        if result["reports"]["dynamic"]["enabled"]:
            report_type = "dynamic"
        elif result["reports"]["static"]["enabled"]:
            report_type = "static"
        elif result["reports"]["cdr"]["enabled"]:
            report_type = "cdr"

        status = result["reports"][report_type]['status']
        md5 = result['fileInfo']['hashes']['md5']
        sha1 = result['fileInfo']['hashes']['sha1']
        sha256 = result['fileInfo']['hashes']['sha256']
        submission_info = {'file_name': result['fileInfo']['name'],
                           'private': result['private']}

        submission_uuid = result['uuid']
        result_url = f"https://app.threat.zone/submission/{submission_uuid}"
        level = result['level']
        readable_dict = {
            'STATUS': stats[status],
            'MD5': md5,
            'SHA1': sha1,
            'SHA256': sha256,
            'THREAT_LEVEL': levels[level],
            'FILE_NAME': result['fileInfo']['name'],
            'PRIVATE': result['private'],
            'SCAN_URL': result_url,
            'UUID': submission_uuid
        }
        #dbot_score = generate_dbotscore(readable_dict)
        output = {
            'ThreatZone.Result(val.Job_ID == obj.Job_ID)': {
                'STATUS': status,
                'MD5': md5,
                'SHA1': sha1,
                'SHA256': sha256,
                'LEVEL': level,
                'INFO': submission_info,
                'URL': result_url,
                'UUID': submission_uuid,
                'REPORT': {report_type: result["reports"][report_type]}
            }
            #,**dbot_score
        }

        res = create_res(readable_dict, output)
        if report_type == "cdr" and status == 5:
            sanitized_file_url = f"https://app.threat.zone/download/v1/download/cdr/{submission_uuid}"
            output['ThreatZone.Result(val.Job_ID == obj.Job_ID)']["SANITIZED"] = sanitized_file_url
            readable_dict["SANITIZED"] = sanitized_file_url
            data = client.threatzone_get_sanitized(submission_uuid)
            f_res = fileResult(f"sanitized-{submission_uuid}.zip", data)
            res = create_res(readable_dict, output)
            res.append(f_res)

    except Exception as e:
        output = {'ThreatZone.Result(val.Job_ID == obj.Job_ID)': {'REPORT': result}}
        readable_output = tableToMarkdown('Submission Result', result)
        res = create_res(readable_output, output)
    return res

def threatzone_sandbox_upload_sample(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Uploads the sample to the ThreatZone sandbox to analyse with required or optional selections."""

    ispublic = args.get('isPublic')
    environment = args.get('environment')
    work_path = args.get('work_path')
    timeout = args.get('timeout')
    mouse_simulation = args.get('mouse_simulation')
    https_inspection = args.get('https_inspection')
    internet_connection = args.get('internet_connection')
    raw_logs = args.get('raw_logs')
    snapshot = args.get('snapshot')
    file_id = args.get('entry_id')
    file_obj = demisto.getFilePath(file_id)
    file_name = encode_file_name(file_obj['name'])
    file_path = file_obj['path']

    files = [
        ('file', (file_name, open(file_path, 'rb'), 'application/octet-stream'))
    ]

    param = {
        'scan_type': "sandbox",
        'environment': environment,
        'private': ispublic,
        'timeout': timeout,
        'work_path': work_path,
        'mouse_simulation': mouse_simulation,
        'https_inspection': https_inspection,
        'internet_connection': internet_connection,
        'raw_logs': raw_logs,
        'file_path': file_path,
        'snapshot': snapshot,
        'files': files
    }

    result = client.threatzone_add(param=param)
    readable_output = tableToMarkdown('SAMPLE UPLOADED', result)
    uuid = result['uuid']
    url = f"https://app.threat.zone/submission/{uuid}"
    return CommandResults(
        readable_output=readable_output,
        outputs_key_field='results',
        outputs={'ThreatZone.Analysis(val.Job_ID == obj.Job_ID)': {'UUID': uuid, 'URL': url}}
    )

def threatzone_static_upload_sample(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Uploads the sample to the ThreatZone static engine to analyse with required or optional selections."""
    file_id = args.get('entry_id')
    file_obj = demisto.getFilePath(file_id)
    file_name = encode_file_name(file_obj['name'])
    file_path = file_obj['path']
    files = [
        ('file', (file_name, open(file_path, 'rb'), 'application/octet-stream'))
    ]
    param = {
        'scan_type': "static-scan",
        'files': files
    }

    result = client.threatzone_add(param=param)
    uuid = result['uuid']
    url = f"https://app.threat.zone/submission/{uuid}"
    readable = {
        "Message": result["message"],
        "UUID": result["uuid"],
        "URL": url
    }
    readable_output = tableToMarkdown('SAMPLE UPLOADED', readable)

    return CommandResults(
        readable_output=readable_output,
        outputs_key_field='results',
        outputs={'ThreatZone.Analysis(val.Job_ID == obj.Job_ID)': {'UUID': uuid, 'URL': url}}
    )

def threatzone_cdr_upload_sample(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Uploads the sample to the ThreatZone to analyse with required or optional selections."""
    file_id = args.get('entry_id')
    file_obj = demisto.getFilePath(file_id)
    file_name = encode_file_name(file_obj['name'])
    file_path = file_obj['path']
    files = [
        ('file', (file_name, open(file_path, 'rb'), 'application/octet-stream'))
    ]
    param = {
        'scan_type': "cdr",
        'files': files
    }

    result = client.threatzone_add(param=param)
    uuid = result['uuid']
    url = f"https://app.threat.zone/submission/{uuid}"
    readable = {
        "Message": result["message"],
        "UUID": result["uuid"],
        "URL": url
    }
    readable_output = tableToMarkdown('SAMPLE UPLOADED', readable)

    return CommandResults(
        readable_output=readable_output,
        outputs_key_field='results',
        outputs={'ThreatZone.Analysis(val.Job_ID == obj.Job_ID)': {'UUID': uuid, 'URL': url}}
    )


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    params = demisto.params()
    base_url = params['url']
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    ''' EXECUTION '''
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    args = demisto.args()
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
        elif command == 'tz-sandbox-upload-sample':
             return_results(threatzone_sandbox_upload_sample(client, args))
        elif command == 'tz-static-upload-sample':
             return_results(threatzone_static_upload_sample(client, args))
        elif command == 'tz-cdr-upload-sample':
             return_results(threatzone_cdr_upload_sample(client, args))
        elif command == 'tz-get-result':
            return_results(threatzone_get_result(client, args))

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
