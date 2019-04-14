import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import json
import requests
from distutils.util import strtobool

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

TOKEN = demisto.params().get('token')
# Remove trailing slash to prevent wrong URL path to service
SERVER = "{server}{api_endpoint}".format(
    server=demisto.params()['url'][:-1] if (demisto.params()['url'] and demisto.params()['url'].endswith('/')) else demisto.params()['url'],
    api_endpoint='/api/bit9platform/v1')
# Should we use SSL
USE_SSL = not demisto.params().get('insecure', False)
# Service base URL
BASE_URL = SERVER + '/api/v2.0/'
# Headers to be sent in requests
HEADERS = {
    'X-Auth-Token': TOKEN,
    'Content-Type': 'application/json',
    'Accept': 'application/json'
}
# Remove proxy if not set to true in params
if not demisto.params().get('proxy'):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']


''' OUTPUT KEY DICTIONARY '''


FILE_CATALOG_TRANS_DICT = {
    'fileSize': 'Size',
    'pathName': 'Path',
    'sha1': 'SHA1',
    'sha256': 'SHA256',
    'md5': 'MD5',
    'fileName': 'Name',
    'fileType': 'Type',
    'productName': 'ProductName',
    'id': 'ID',
    'publisher': 'Publisher',
    'company': 'Company',
    'fileExtension': 'Extension'
}


''' HELPER FUNCTIONS '''


def http_request(method, url_suffix, params=None, data=None, headers=HEADERS, safe=False):
    """
        A wrapper for requests lib to send our requests and handle requests and responses better.

        :type method: ``str``
        :param method: HTTP method for the request.

        :type url_suffix: ``str``
        :param url_suffix: The suffix of the URL (endpoint)

        :type params: ``dict``
        :param params: The URL params to be passed.

        :type data: ``str``
        :param data: The body data of the request.

        :type headers: ``dict``
        :param headers: Request headers

        :type safe: ``bool``
        :param safe: If set to true will return None in case of error

        :return: Returns the http request response json
        :rtype: ``dict``
    """
    url = SERVER + url_suffix
    demisto.info("#####" + url)
    demisto.info(USE_SSL)
    try:
        res = requests.request(
            method,
            url,
            verify=USE_SSL,
            params=params,
            data=data,
            headers=headers,
        )
    except requests.exceptions.RequestException as e:
        LOG(str(e))
        return_error('Error in connection to the server. Please make sure you entered the URL correctly.')
    # Handle error responses gracefully
    if res.status_code not in {200, 201}:
        if safe:
            return None
        return_error('Error in API call [{0}] - {1}'.format(res.status_code, res.reason))
    return res.json()


def create_entry_object(contents='', ec=None, hr=''):
    """
        Creates an entry object

        :type contents: ``dict``
        :param contents: Raw response to output

        :type ec: ``dict``
        :param ec: Entry context of the entry object

        :type hr: ``str``
        :param hr: Human readable

        :return: Entry object
        :rtype: ``dict``
    """
    return {
        'Type': entryTypes['note'],
        'Contents': contents,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': hr,
        'EntryContext': ec
    }


def get_trasnformed_dict(old_dict, transformation_dict):
    """
        Returns a dictionary with the same values as old_dict, with the correlating key:value in transformation_dict

        :type old_dict: ``dict``
        :param old_dict: Old dictionary to pull values from

        :type transformation_dict: ``dict``
        :param transformation_dict: Transformation dictionary that contains oldkeys:newkeys

        :return Transformed dictionart (according to transformation_dict values)
        :rtype ``dict``
    """
    new_dict = {}
    for k in list(old_dict.keys()):
        if k in transformation_dict:
            new_dict[transformation_dict[k]] = old_dict[k]
    return new_dict


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module():
    """
    Performs basic get request to get item samples
    """
    http_request('GET', '/computer?limit=-1')


def search_file_catalog_command():
    """
    Searches for file catalog
    :return: EntryObject of the file catalog
    """
    args = demisto.args()
    url_params = {
        "limit": args.get('limit'),
        "offset": args.get('offset'),
        "query": args.get('query'),
        "sort": args.get('sort'),
        "group": args.get('group')
    }
    headers = args.get('headers')
    raw_res = search_file_catalog(url_params)
    ec = []
    for entry in raw_res:
        demisto.info(entry)
        ec.append(get_trasnformed_dict(entry, FILE_CATALOG_TRANS_DICT))
    hr = tableToMarkdown("CarbonBlack Protect File Catalog Search", ec, headers)
    demisto.results(create_entry_object(raw_res, {'File(val.SHA1 === obj.SHA1)': ec}, hr))


def search_file_catalog(url_params):
    """
    Sends the request for file catalog, and returns the result json
    :param url_params: url parameters for the request
    :return: File catalog response json
    """
    return http_request('GET', '/fileCatalog', params=url_params)


''' COMMANDS MANAGER / SWITCH PANEL '''


LOG('Command being called is {}'.format(demisto.command()))


try:
    if demisto.command() == 'test-module':
        # This is the call made when pressing the integration test button.
        test_module()
        demisto.results('ok')
    elif demisto.command() == 'cbp-fileCatalog-search':
        search_file_catalog_command()

# Log exceptions
except Exception as e:
    return_error(str(e))
