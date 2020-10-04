import demistomock as demisto
from CommonServerPython import *
import requests
import socket
import json
import logging


# CONST
POLYSWARM_DEMISTO_VERSION = '0.1.1'
POLYSWARM_URL_RESULTS = 'https://polyswarm.network/scan/results'
ERROR_ENDPOINT = 'Error with endpoint: '

# Set Debug level
logging.basicConfig(level=logging.ERROR)


class PolyswarmAPI:
    # internal version
    POLYSWARM_API_VERSION = '0.1.0'

    def __init__(self, config):
        """
        __init__
        :param config: config with api key for connection

        :return:
        """
        self.config = config
        self.headers = {'Authorization': self.config['polyswarm_api_key']}

    def _http_request(self, method, path_url, data=None, files=None):
        """
        Send HTTP Request

        :param method: [get|post]
        :param path_url: URL for request
        :param data: data for 'post' or 'get' request
        :param files: for uploading files with 'post'

        :return: tuple (status_code, content)
        """
        # set full URL for request
        full_url = '{base_url}{path_url}'.format(base_url=self.config['base_url'],
                                                 path_url=path_url)

        logging.debug('[{method}] URL: {full_url} - params/data: {data} - files: {files} - headers: {headers}'.
                      format(method=method.upper(),
                             full_url=full_url,
                             data=data,
                             files=files,
                             headers=self.headers))

        if method.lower() == "get":
            r = requests.get(full_url,
                             params=data,
                             headers=self.headers)
        elif method.lower() == "post":
            r = requests.post(full_url,
                              data=data,
                              files=files,
                              headers=self.headers)
        r.raise_for_status()

        logging.debug('[Response] Status code: {status_code} - Content: {response}'.
                      format(status_code=r.status_code,
                             response=r.content))

        return (r.status_code, r.content)

    def search_hash(self, hash):
        """
        Search Hash

        :param hash: hash

        :return: tuple (status_code, response)
        """
        hash_type = get_hash_type(hash)

        params = {'type': hash_type,
                  'with_instances': 'true',
                  'hash': hash}

        return self._http_request('get', '/search', params)

    def rescan_hash(self, hash):
        """
        Start a rescan for a single hash

        :param hash: hash

        :return: tuple (status_code, response)
        """
        hash_type = get_hash_type(hash)

        path_url = '/consumer/{polyswarm_community}/rescan/{hash_type}/{hash}'.\
                   format(polyswarm_community=self.config['polyswarm_community'],
                          hash_type=hash_type, hash=hash)

        return self._http_request('post', path_url)

    def scan_url(self, url):
        """
        Upload URL for scan

        :param url: string

        :return: tuple (status_code, response)
        """
        path_url = '/consumer/{polyswarm_community}'.format(polyswarm_community=self.config['polyswarm_community'])

        params = {'url': url,
                  'artifact-type': 'url'}

        return self._http_request('post', path_url, params)

    def lookup(self, uuid):
        """
        UUID Lookup

        :param uuid: string

        :return: tuple (status_code, response)
        """
        path_url = '/consumer/{polyswarm_community}/uuid/{uuid}'.\
                   format(polyswarm_community=self.config['polyswarm_community'],
                          uuid=uuid)

        status_code, response = self._http_request('get', path_url)
        window_closed = json.loads(response)['result']['files'][0]['window_closed']

        # we got the results at first shot
        if window_closed:
            return (status_code, response)

        # we dont have any results already - wait for the bounty to complete
        # and try again
        time.sleep(30)  # pylint: disable=sleep-exists

        while not window_closed:
            status_code, response = self._http_request('get', path_url)
            window_closed = json.loads(response)['result']['files'][0]['window_closed']
            time.sleep(1)

        return (status_code, response)

    def search_url(self, url):
        """
        Scan URL and return scan results

        :param url: string

        :return: (status_code, response, uuid)
        """
        status_code, response = self.scan_url(url)
        uuid = json.loads(response)['result']
        status_code, response = self.lookup(uuid)

        return (status_code, response, uuid)

    def get_file(self, hash):
        """
        Download file by hash

        :param hash: File Hash for Download

        :return: tuple (status_code, response)
        """
        hash_type = get_hash_type(hash)

        return self._http_request('get', '/download/{hash_type}/{hash}'.
                                  format(hash_type=hash_type, hash=hash))

    def detonate_file(self, file_name, file_path):
        """
        Upload File to Polyswarm and get the scan results

        :param file_name: file name
        :param file_path: complete path from the file to upload

        :return: (status_code, response, uuid)
        """
        path_url = '/consumer/{polyswarm_community}'.format(polyswarm_community=self.config['polyswarm_community'])

        files = {'file': (file_name, open(file_path, 'rb'))}
        # Force re-scans if file was already submitted
        # params = { 'force': 'true' }
        params = {}  # type: Dict[str, str]

        status_code, response = self._http_request('post', path_url, params, files)
        uuid = json.loads(response)['result']
        status_code, response = self.lookup(uuid)

        return (status_code, response, uuid)

    def rescan_file(self, hash):
        """
        Rescan Hash and return scan results

        :param hash: string

        :return: (status_code, response, uuid)
        """
        status_code, response = self.rescan_hash(hash)
        uuid = json.loads(response)['result']
        status_code, response = self.lookup(uuid)

        return (status_code, response, uuid)


# Allows nested keys to be accesible
def makehash():
    import collections
    return collections.defaultdict(makehash)


# Polyswarm-Demisto Interface
class PolyswarmConnector():
    def __init__(self):
        self.config = {}  # type: Dict[str,str]
        self.config['polyswarm_api_key'] = demisto.params().get('api_key')
        self.config['base_url'] = demisto.params().get('base_url')
        self.config['polyswarm_community'] = demisto.params().get('polyswarm_community')

        self.polyswarm_api = PolyswarmAPI(self.config)

    def _get_results(self, title, total_scans, positives, uuid, artifact):
        contxt = makehash()

        permalink = '{url_results}/{uuid}'.\
            format(url_results=POLYSWARM_URL_RESULTS,
                   uuid=uuid)

        contxt['Scan_UUID'] = uuid
        contxt['Total'] = str(total_scans)
        contxt['Positives'] = str(positives)
        contxt['Permalink'] = permalink
        contxt['Artifact'] = artifact

        human_readable = {'Scan_UUID': uuid,
                          'Total': str(total_scans),
                          'Positives': str(positives),
                          'Permalink': permalink}

        ec = {'PolySwarm(val.Scan_UUID && val.Scan_UUID == obj.UUID)': contxt}

        return {'Type': entryTypes['note'],
                'ContentsFormat': formats['markdown'],
                'Contents': contxt,
                'HumanReadable': tableToMarkdown(title, human_readable),
                'EntryContext': ec}

    def test_connectivity(self):
        EICAR_HASH = '131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267'  # guardrails-disable-line

        # Polywarm API Response
        #  HTTP Response
        #   status code
        #   response
        status_code = 0
        response = ''

        try:
            status_code, response = self.polyswarm_api.search_hash(EICAR_HASH)
        except Exception:
            return False

        return True

    def file_reputation(self, param):
        file_hash = param.get('file', param.get('hash'))
        if not file_hash:
            return_error("Please specify a file hash to enrich.")
        title = 'PolySwarm File Reputation for Hash: %s' % file_hash

        # default values
        total_scans = 0
        positives = 0

        # Polywarm API Response
        #  HTTP Response
        #   status code
        #   response
        #   uuid = uuid from Polyswarm
        status_code = 0
        response = ''
        uuid = 'null'

        try:
            status_code, response = self.polyswarm_api.search_hash(file_hash)

            # load json response for iteration
            try:
                artifact_instances = json.loads(response)['result'][0]['artifact_instances']
            except Exception:
                return_error('Error in response. Details: {response}'.
                             format(response=str(response)))

            # TODO: implement rescan logic
            if not artifact_instances[0]['bounty_result']:
                return_error('Run Rescan for this hash')

            uuid = artifact_instances[0]['bounty_result']['files'][0]['submission_guid']
            assertions = artifact_instances[0]['bounty_result']['files'][0]['assertions']

            for assertion in assertions:
                for k, v in assertion.items():
                    if k == 'verdict' and v:
                        positives += 1
                total_scans += 1

            demisto.debug('Positives: {positives} - Total Scans: {total_scans}'.
                          format(positives=positives, total_scans=total_scans))

        except requests.exceptions.HTTPError as err:
            if err.response.status_code == 404:
                # sample not found
                # returning default values == 0
                pass
            else:
                return_error('{ERROR_ENDPOINT}{err}'.
                             format(ERROR_ENDPOINT=ERROR_ENDPOINT,
                                    err=err))

        return self._get_results(title, total_scans,
                                 positives, uuid,
                                 file_hash)

    def get_file(self, param):
        # Polywarm API Response
        #  HTTP Response
        #   status code
        #   response
        status_code = 0
        response = ''

        try:
            status_code, response = self.polyswarm_api.get_file(param['hash'])

            return fileResult(param['hash'], response)

        except requests.exceptions.HTTPError as err:
            if err.response.status_code == 404:
                return_error('File not found.')
            else:
                return_error('{ERROR_ENDPOINT}{err}'.
                             format(ERROR_ENDPOINT=ERROR_ENDPOINT,
                                    err=err))

    def detonate_file(self, param):
        title = 'PolySwarm File Detonation for Entry ID: %s' % param['entryID']

        # default values
        total_scans = 0
        positives = 0

        # Polywarm API Response
        #  HTTP Response
        #   status_code
        #   response
        #  Result
        #   uuid = uuid from Polyswarm
        status_code = 0
        response = ''
        uuid = ''

        try:
            file_info = demisto.getFilePath(param['entryID'])
        except Exception:
            return_error('File not found - EntryID: {entryID}'.
                         format(entryID=param['entryID']))

        try:
            status_code, response, uuid = self.polyswarm_api.detonate_file(file_info['name'],
                                                                           file_info['path'])
            # load json response for iteration
            try:
                assertions = json.loads(response)['result']['files'][0]['assertions']
            except Exception:
                return_error('Error in response. Details: {response}'.
                             format(response=str(response)))

            # iterate for getting positives and total_scan number
            for assertion in assertions:
                for k, v in assertion.items():
                    if k == 'verdict' and v:
                        positives += 1
                total_scans += 1

        except requests.exceptions.HTTPError as err:
            return_error('{ERROR_ENDPOINT}{err}'.
                         format(ERROR_ENDPOINT=ERROR_ENDPOINT,
                                err=err))

        return self._get_results(title, total_scans,
                                 positives, uuid,
                                 param['entryID'])

    def rescan_file(self, param):
        title = 'PolySwarm Rescan for Hash: %s' % param['hash']

        # default values
        total_scans = 0
        positives = 0

        # Polywarm API Response
        #  HTTP Response
        #   status_code
        #   response
        #   uuid
        status_code = 0
        response = ''
        uuid = ''

        try:
            status_code, response, uuid = self.polyswarm_api.rescan_file(param['hash'])

            # load json response for iteration
            try:
                assertions = json.loads(response)['result']['files'][0]['assertions']
            except Exception:
                return_error('Error in response. Details: {response}'.
                             format(response=str(response)))

            # iterate for getting positives and total_scan number
            for assertion in assertions:
                for k, v in assertion.items():
                    if k == 'verdict' and v:
                        positives += 1
                total_scans += 1

        except requests.exceptions.HTTPError as err:
            if err.response.status_code == 404:
                # sample not found
                # returning default values == 0
                pass
            else:
                # we got another err - report it
                return_error('{ERROR_ENDPOINT}{err}'.
                             format(ERROR_ENDPOINT=ERROR_ENDPOINT,
                                    err=err))

        return self._get_results(title, total_scans,
                                 positives, uuid,
                                 param['hash'])

    def url_reputation(self, param, artifact):
        title = 'PolySwarm %s Reputation for: %s' % (artifact.upper(),
                                                     param[artifact])

        # default values
        total_scans = 0
        positives = 0

        # Polywarm API Response
        #  HTTP Response
        #   status_code
        #   response
        #  Result
        #   uuid = uuid from Polyswarm
        status_code = 0
        response = ''
        uuid = ''

        # IP validation
        if artifact == 'ip':
            try:
                socket.inet_aton(param[artifact])
            except socket.error:
                return_error('Invalid IP Address: {ip}'.
                             format(ip=param[artifact]))

        try:
            status_code, response, uuid = self.polyswarm_api.search_url(param[artifact])

            # load json response for iteration
            try:
                assertions = json.loads(response)['result']['files'][0]['assertions']
            except Exception:
                return demisto.results('Error in response. Details: {}'.
                                       format(str(response)))

            # iterate for getting positives and total_scan number
            for assertion in assertions:
                for k, v in assertion.items():
                    if k == 'verdict' and v:
                        positives += 1
                total_scans += 1

        except requests.exceptions.HTTPError as err:
            return_error('{ERROR_ENDPOINT}{err}'.
                         format(ERROR_ENDPOINT=ERROR_ENDPOINT,
                                err=err))

        return self._get_results(title, total_scans,
                                 positives, uuid,
                                 param[artifact])

    def get_report(self, param):
        title = 'PolySwarm Report for UUID: %s' % param['scan_uuid']

        # default values
        total_scans = 0
        positives = 0

        # Polywarm API Response
        #  HTTP Response
        #   status_code
        #   response
        status_code = 0
        response = ''

        try:
            status_code, response = self.polyswarm_api.lookup(param['scan_uuid'])

            # load json response for iteration
            try:
                assertions = json.loads(response)['result']['files'][0]['assertions']
            except Exception:
                return_error('Error in response. Details: {}'.
                             format(str(response)))

            # iterate for getting positives and total_scan number
            for assertion in assertions:
                for k, v in assertion.items():
                    if k == 'verdict' and v:
                        positives += 1
                total_scans += 1

        except requests.exceptions.HTTPError as err:
            if err.response.status_code == 404:
                return_error('UUID not found.')
            else:
                return_error('{ERROR_ENDPOINT}{err}'.
                             format(ERROR_ENDPOINT=ERROR_ENDPOINT,
                                    err=err))

        return self._get_results(title, total_scans,
                                 positives,
                                 param['scan_uuid'],
                                 param['scan_uuid'])


def main():
    ''' EXECUTION '''
    LOG('command is %s' % (demisto.command(),))
    try:
        polyswarm = PolyswarmConnector()

        command = demisto.command()
        param = demisto.args()

        if command == 'test-module':
            if polyswarm.test_connectivity():
                demisto.results('ok')
            else:
                return_error('Connection Failed')
        elif command == 'file':
            demisto.results(polyswarm.file_reputation(param))
        elif command == 'get-file':
            demisto.results(polyswarm.get_file(param))
        elif command == 'file-scan':
            demisto.results(polyswarm.detonate_file(param))
        elif command == 'file-rescan':
            demisto.results(polyswarm.rescan_file(param))
        elif command == 'url':
            demisto.results(polyswarm.url_reputation(param, 'url'))
        elif command == 'url-scan':
            demisto.results(polyswarm.url_reputation(param, 'url'))
        elif command == 'ip':
            demisto.results(polyswarm.url_reputation(param, 'ip'))
        elif command == 'domain':
            demisto.results(polyswarm.url_reputation(param, 'domain'))
        elif command == 'polyswarm-get-report':
            demisto.results(polyswarm.get_report(param))

    # Log exceptions
    except Exception as e:
        LOG(e.message)
        LOG.print_log()
        raise


if __name__ in ('__builtin__', '__main__'):
    main()
