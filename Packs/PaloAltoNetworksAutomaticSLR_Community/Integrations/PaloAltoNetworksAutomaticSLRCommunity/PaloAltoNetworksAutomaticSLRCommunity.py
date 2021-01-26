import demistomock as demisto  # noqa: F401
import xmltodict
from CommonServerPython import *  # noqa: F401

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%d-%H-%M-%S'


class PanOSXMLAPI(BaseClient):

    def __init__(self, host, port, api_key, verify, timeout, proxy, verbose):

        # Map class parameters for the target firewall
        self.params = {
            'ngfw_host': 'https://' + host,
            'ngfw_port': port,
            'ngfw_tls_verify': verify,
            'ngfw_timeout': int(timeout),
            'ngfw_proxy': proxy,
            'ngfw_verbose': verbose
        }

        self.api_key = api_key

        # If using a custom port (e.g. when GlobalProtect Clientless and management are enabled on the same interface)
        if self.params['ngfw_port'] == '443':
            base = self.params['ngfw_host'] + '/api/'
            super().__init__(base, self.params['ngfw_tls_verify'])
        else:
            base = self.params['ngfw_host'].rstrip('/:') + ':' + self.params['ngfw_port'] + '/api/'
            super().__init__(base, self.params['ngfw_tls_verify'])

        # Use the XSOAR system proxy to route requests
        if proxy is True:
            self.proxies = handle_proxy()
        else:
            self.proxies = {}

    def get_system_info(self):
        return self.xmlapi_request_op('<show><system><info></info></system></show>')

    def xmlapi_request_op(self, cmd, response_type='response', no_validate=False):

        # Map and construct query
        params = {
            'type': 'op',
            'cmd': cmd,
            'key': self.api_key
        }

        # Execute query
        response = self._http_request(
            'POST',
            'api',
            params=params,
            resp_type=response_type,
            proxies=self.proxies,
            timeout=self.params['ngfw_timeout']
        )

        if no_validate is True:
            return response
        else:
            # Validate response from the API
            result = self.xmlapi_request_validate(response)

            if result is True:
                return response
            else:
                raise Exception(
                    'Could not validate API response! [panos_xmlapi_request_op() -> panos_xmlapi_request_validate()]')

    def xmlapi_request_validate(self, response):

        # Load result into an XML object
        result = xmltodict.parse(response.content)

        # Get API response status
        status = result['response']['@status']

        if self.params['ngfw_verbose'] is True:
            demisto.log('Got execution status back from API: ' + str(status))
            demisto.log(str(response.text))

        if "success" in status:
            return True
        else:

            message = result['response']['msg']['line']

            raise Exception('API call encountered an error, received "' + str(
                status) + ' " as status code with error message: ' + str(message))

    def get_stats_init_job_id(self):

        params = {
            'type': 'export',
            'category': 'stats-dump',
            'key': self.api_key
        }

        response = self._http_request(
            'POST',
            'api',
            params=params,
            resp_type='response',
            proxies=self.proxies,
            timeout=self.params['ngfw_timeout']
        )

        result = self.xmlapi_request_validate(response)

        if result is True:
            result = xmltodict.parse(response.content)
            job = result['response']['result']['job']
            return job
        else:
            raise Exception('Could not validate API response! [get_stats_init_job_id() -> xmlapi_request_validate()]')

    def get_stats_job_id_status(self, job_id):

        params = {
            'type': 'export',
            'category': 'stats-dump',
            'action': 'status',
            'job-id': job_id,
            'key': self.api_key
        }

        response = self._http_request(
            'POST',
            'api',
            params=params,
            resp_type='response',
            proxies=self.proxies,
            timeout=self.params['ngfw_timeout']
        )

        result = self.xmlapi_request_validate(response)

        if result is True:
            resp = xmltodict.parse(response.content)

            status = resp['response']['result']['job']['status']
            progress = resp['response']['result']['job']['progress']

            result = {
                'status': status,
                'progress': progress
            }

            return result
        else:
            raise Exception('Could not validate API response! [get_stats_job_id_status() -> xmlapi_request_validate()]')

    def get_stats_archive(self, job_id):

        # Get firewall system name, serial number
        system_info = self.get_system_info()

        resp = xmltodict.parse(system_info.content)
        system_name = resp['response']['result']['system']['devicename']
        system_serial = resp['response']['result']['system']['serial']

        time_stamp = time.strftime(DATE_FORMAT)
        output_file = str(system_name) + '-' + str(system_serial) + '-' + str(time_stamp) + '-stats_dump.tar.gz'

        if self.params['ngfw_verbose'] is True:
            demisto.log('Constructed archive name as: [`' + output_file + '`]')

        params = {
            'type': 'export',
            'category': 'stats-dump',
            'action': 'get',
            'job-id': job_id,
            'key': self.api_key
        }

        response = self._http_request(
            'GET',
            'api',
            params=params,
            resp_type='content',
            proxies=self.proxies,
            timeout=self.params['ngfw_timeout']
        )

        result = {
            'file_name': output_file,
            'file_contents': response
        }

        return result

    def dump_ngfw_params(self):
        return self.params


class PanwCSP(BaseClient):

    def __init__(self, host, csp_key, verify, timeout, proxy, verbose, account_name=None, deployment_location=None,
                 geographic_country=None, geographic_region=None, industry=None, language=None, prepared_by=None,
                 requested_by=None, send_to=None):

        self.params = {
            'csp_host': host,
            'csp_tls_verify': verify,
            'csp_timeout': int(timeout),
            'csp_proxy': proxy,
            'csp_verbose': verbose
        }

        self.slr_params = {}

        self.api_key = csp_key

        if proxy is True:
            self.proxies = handle_proxy()
        else:
            self.proxies = {}

        # The "Prepared By" name to appear on the front page of the report
        if prepared_by is not None:
            self.slr_params.update({'slr_prepared_by': prepared_by})
        else:
            raise Exception('slr_prepared_by cannot be None!')

        # The email address to appear on the front page of the report
        if requested_by is not None:
            self.slr_params.update({'slr_requested_by': requested_by})
        else:
            raise Exception('slr_requested_by cannot be None!')

        # The email address to send the completed report to
        if send_to is not None:
            self.slr_params.update({'slr_send_to': send_to})
        else:
            raise Exception('slr_send_to cannot be None!')

        # Override the SFDC details on record for the account
        if account_name is not None:
            self.slr_params.update({'slr_account_name': account_name})
        else:
            raise Exception('slr_account_name cannot be None!')

        # Override the SFDC details on record for the account
        if industry is not None:
            self.slr_params.update({'slr_industry': industry})
        else:
            raise Exception('slr_industry cannot be None!')

        # Override the SFDC details on record for the account
        if geographic_country is not None:
            self.slr_params.update({'slr_country': geographic_country})
        else:
            raise Exception('slr_country cannot be None!')

        # Override the SFDC details on record for the account
        if 'Americas' in geographic_region:
            self.slr_params.update({'slr_geographic_region': 'North America, Latin America, Canada'})
        elif 'APAC' in geographic_region:
            self.slr_params.update({'slr_geographic_region': 'Asia Pacific'})
        elif 'EMEA' in geographic_region:
            self.slr_params.update({'slr_geographic_region': 'Europe'})
        elif 'Japan' in geographic_region:
            self.slr_params.update({'slr_geographic_region': 'Japan'})
        else:
            raise Exception('Invalid parameter specified for slr_geographic_region!')

        # Override the SFDC details on record for the account
        if deployment_location is not None:
            self.slr_params.update({'slr_deployment_location': deployment_location})
        else:
            raise Exception('slr_deployment_location cannot be None!')

        # Override the SFDC details on record for the account
        if language is not None:
            self.slr_params.update({'slr_language': language})
        else:
            raise Exception('slr_language cannot be None!')

        headers = {
            'apikey': self.api_key
        }

        # Initiate the BaseClient
        super().__init__(base_url=self.params['csp_host'], verify=self.params['csp_tls_verify'], headers=headers)

    def upload_to_panw(self, file_data):
        file_handler = open(file_data['file_actual_name'], 'rb')

        file = {"files": (file_data['file_friendly_name'], file_handler, 'application/gzip')}

        payload = {
            "EmailIdList": self.slr_params['slr_send_to'],
            "RequestedBy": self.slr_params['slr_requested_by'],
            "PreparedBy": self.slr_params['slr_prepared_by'],
            "AccountName": self.slr_params['slr_account_name'],
            "Industry": self.slr_params['slr_industry'],
            "Country": self.slr_params['slr_country'],
            "GeographicRegion": self.slr_params['slr_geographic_region'],
            "DeploymentLocation": self.slr_params['slr_deployment_location'],
            "Language": self.slr_params['slr_language']
        }

        if self.params['csp_verbose'] is True:
            demisto.log('Upload -> Parameters -> [' + str(payload) + ']')
            demisto.log('Upload -> Files -> [' + str(file) + ']')

        demisto.log('Uploading ' + file_data['file_friendly_name'] + ' to Palo Alto Networks...')

        response = self._http_request(
            'POST',
            '/API/v1/Create/',
            data=payload,
            files=file,
            resp_type='json',
            proxies=self.proxies,
            timeout=self.params['csp_timeout']
        )

        return response

    def dump_csp_params(self, req_type='init'):

        if 'init' in req_type:
            return self.params
        elif 'slr' in req_type:
            return self.slr_params
        else:
            raise Exception('Invalid type passed to function, valid types are: init, slr')


def test_module(xmlapi):
    # TODO: Rewrite test-module to be more relevant
    response = xmlapi.get_system_info()
    result = xmltodict.parse(response.content)

    hostname = result['response']['result']['system']['hostname']
    serial = result['response']['result']['system']['serial']

    if hostname is not None and serial is not None:
        return demisto.results('ok')
    else:
        raise Exception('test_module() failed!')


def ngfw_get_system_info(xmlapi):
    # response = json.loads(xml2json(xmlapi.get_system_info()))

    response = xmlapi.get_system_info()
    result = xmltodict.parse(response.content)

    hostname = result['response']['result']['system']['hostname']
    serial = result['response']['result']['system']['serial']
    software = result['response']['result']['system']['sw-version']

    result = {
        'hostname': hostname,
        'serial': serial,
        'software': software
    }

    readable_output = tableToMarkdown('Firewall Information', result)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AutoSLR.ngfw_system_info',
        outputs_key_field='ngfw_system_info',
        outputs=result
    )


def get_integration_params(csp, xmlapi):
    csp_params = csp.dump_csp_params('init')
    slr_params = csp.dump_csp_params('slr')
    ngfw_params = xmlapi.dump_ngfw_params()

    raw_result = {
        **csp_params,
        **ngfw_params,
        **slr_params,
        'system_proxy': demisto.params().get('proxy'),
        'system_verbose': demisto.params().get('system_debug')
    }

    readable_output = tableToMarkdown('Integration Parameters', raw_result)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AutoSLR.params',
        outputs_key_field='params',
        outputs=raw_result
    )


def ngfw_generate_stats_dump(xmlapi):
    result = xmlapi.get_stats_init_job_id()

    readable_output = 'Successfully created stats-generate job! [ID: `' + result + '`]'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AutoSLR.generate.job_id',
        outputs_key_field='job_id',
        outputs=result
    )


def ngfw_get_stats_dump_status(xmlapi, job_id):
    state = False

    while not state:
        demisto.log('Checking status for job ID: `' + str(job_id) + '`')

        result = xmlapi.get_stats_job_id_status(job_id)

        if 'FIN' in result['status']:
            state = True
        elif 'ACT' in result['status']:
            demisto.log(
                'Job `' + str(job_id) + '` is currently executing, current progress: `' + result['progress'] + '%`')
        elif 'PEND' in result['status']:
            demisto.log('Another job is currently executing, this job is currently in the queue')
        else:
            raise Exception('Unexpected value returned from API, expected [`ACT/FIN/PEND`] got: `' + str(result) + '`')

        time.sleep(1)

    if state is True:
        readable_output = 'Successfully finished executing stats_dump generation job for job ID: `' + str(job_id) + '`'

        return CommandResults(
            readable_output=readable_output,
            outputs_prefix='AutoSLR.generate.job_status',
            outputs_key_field='job_status',
            outputs=state
        )

    else:
        raise Exception('Could not check stats_dump generation task [ID: `' + str(job_id) + '`]')


def ngfw_download_stats_dump(xmlapi, job_id):
    result = xmlapi.get_stats_archive(job_id)
    # demisto.results(fileResult(result['file_name'], result['file_contents'], entryTypes['entryInfoFile']))

    file_entry = fileResult(result['file_name'], result['file_contents'], entryTypes['entryInfoFile'])
    return file_entry


def upload_stats_to_panw(csp, input_file):
    get_path = demisto.getFilePath(input_file)

    file_data = {
        'file_friendly_name': get_path.get('name'),
        'file_actual_name': get_path.get('path')
    }

    demisto.log(
        'Got file name [' + file_data['file_friendly_name'] + '] as path [' + file_data['file_actual_name'] + ']')

    result = csp.upload_to_panw(file_data)

    send_to = demisto.params().get('slr_send_to')
    slr_id = result['Id']
    readable_output = 'Success! The SLR Report will be emailed to ' + str(send_to) + ' (SLR ID: `' + str(slr_id) + '`)'

    context = {
        'id': slr_id,
        'send_to': send_to
    }

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AutoSLR.upload',
        outputs_key_field=['id', 'send_to'],
        outputs=context
    )


def main():
    # Parse the XSOAR Integrations Parameters
    ngfw_host = demisto.params().get('ngfw_fqdn_ip')
    ngfw_port = demisto.params().get('ngfw_port')
    ngfw_api_key = demisto.params().get('ngfw_api_key')
    ngfw_timeout = demisto.params().get('ngfw_timeout')
    ngfw_tls_verify = demisto.params().get('ngfw_tls_verify')

    csp_host = 'https://riskreport.paloaltonetworks.com/'
    csp_api_key = demisto.params().get('csp_api_key')
    csp_timeout = demisto.params().get('csp_timeout')
    csp_tls_verify = demisto.params().get('csp_tls_verify')

    system_proxy = demisto.params().get('proxy')
    system_verbose = demisto.params().get('system_debug')

    account_name = demisto.params().get('slr_account_name')
    deployment_location = demisto.params().get('slr_deployment_location')
    geographic_country = demisto.params().get('slr_geographic_country')
    geographic_region = demisto.params().get('slr_geographic_region')
    industry = demisto.params().get('slr_industry')
    language = demisto.params().get('slr_language')
    prepared_by = demisto.params().get('slr_prepared_by')
    requested_by = demisto.params().get('slr_requested_by')
    send_to = demisto.params().get('slr_send_to')

    try:

        if ngfw_tls_verify is False or csp_tls_verify is False:
            requests.packages.urllib3.disable_warnings()

        # Establish PANOS XMLAPI Class Connector
        xmlapi = PanOSXMLAPI(ngfw_host, ngfw_port, ngfw_api_key, ngfw_tls_verify, ngfw_timeout, system_proxy,
                             system_verbose)

        # Establish Palo Alto Networks Customer Support Portal (CSP) Class Connector
        csp = PanwCSP(csp_host, csp_api_key, csp_tls_verify, csp_timeout, system_proxy, system_verbose, account_name,
                      deployment_location, geographic_country, geographic_region, industry, language, prepared_by,
                      requested_by, send_to)

        # Map XSOAR Commands to caller functions
        if demisto.command() == 'test-module':
            return_results(test_module(xmlapi))
        elif demisto.command() == 'autoslr-ngfw-system-info':
            return_results(ngfw_get_system_info(xmlapi))
        elif demisto.command() == 'autoslr-dump-params':
            return_results(get_integration_params(csp, xmlapi))
        elif demisto.command() == 'autoslr-ngfw-generate':
            return_results(ngfw_generate_stats_dump(xmlapi))
        elif demisto.command() == 'autoslr-ngfw-check':
            return_results(ngfw_get_stats_dump_status(xmlapi, demisto.args().get('job_id')))
        elif demisto.command() == 'autoslr-ngfw-download':
            return_results(ngfw_download_stats_dump(xmlapi, demisto.args().get('job_id')))
        elif demisto.command() == 'autoslr-csp-upload':
            return_results(upload_stats_to_panw(csp, demisto.args().get('input_file')))
        else:
            raise NotImplementedError('Command "' + str(demisto.command()) + '" is not implemented.')
    except Exception as e:
        return_error('Failed to execute: [' + str(demisto.command()) + '] Received Error: [' + str(
            e) + '] Traceback: [' + traceback.format_exc() + ']')


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
