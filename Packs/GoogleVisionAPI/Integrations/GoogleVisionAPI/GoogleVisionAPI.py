import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''


import json
import base64
import httplib2
import urllib.parse
import urllib3
from apiclient import discovery
from oauth2client import service_account
from typing import Dict, List

# Disable insecure warnings
urllib3.disable_warnings()


'''GLOBAL VARS'''

PRIVATE_KEY_CONTENT = (demisto.params().get('auth_json_creds', {}).get('password')
                       or demisto.params().get('auth_json', '')).encode('utf-8')
DISABLE_SSL = demisto.params().get('insecure', False)
PROXY = demisto.params().get('proxy')
SERVICE_NAME = 'vision'
SERVICE_VERSION = 'v1'
SERVICE_SCOPES = ['https://www.googleapis.com/auth/cloud-platform', 'https://www.googleapis.com/auth/cloud-vision']


'''HELPER FUNCTIONS'''


def get_credentials():
    """
    Gets ServiceAccountCredentials from the provided auth_json file.
    """
    try:
        json_keyfile = json.loads(PRIVATE_KEY_CONTENT)
        if not isinstance(json_keyfile, dict):
            json_keyfile = json.loads(json_keyfile)
            if not isinstance(json_keyfile, dict):
                raise Exception('Something is wrong with your provided auth_json parameter. \
                Please follow the instructions to obtain a credentials JSON file.')
        return service_account.ServiceAccountCredentials.from_json_keyfile_dict(json_keyfile, scopes=SERVICE_SCOPES)
    except Exception as e:
        err_msg = 'An error occurred while trying to construct an OAuth2 ' \
                  'ServiceAccountCredentials object - {}'.format(str(e))
        return_error(err_msg)


def get_http_client_with_proxy(proxies):
    """
    Gets an HTTP client that is able to handle proxy and broken SSL.
    Default is secure but for weird test environments SSL validation might be disabled.
    """
    if not proxies or not proxies['https']:
        raise Exception('https proxy value is empty. Check Demisto server configuration')
    https_proxy = proxies['https']
    if not https_proxy.startswith('https') and not https_proxy.startswith('http'):
        https_proxy = 'https://' + https_proxy
    parsed_proxy = urllib.parse.urlparse(https_proxy)
    proxy_info = httplib2.ProxyInfo(
        proxy_type=httplib2.socks.PROXY_TYPE_HTTP,  # disable-secrets-detection
        proxy_host=parsed_proxy.hostname,
        proxy_port=parsed_proxy.port,
        proxy_user=parsed_proxy.username,
        proxy_pass=parsed_proxy.password)
    return httplib2.Http(proxy_info=proxy_info, disable_ssl_certificate_validation=DISABLE_SSL)


def get_service(proxies):
    """
    Builds a Google API server client.
    Would be simpler to use google.cloud.vision.ImageAnnotatorClient directly,
    but unfortunately it does not work with proxy and disabled SSL validation.
    """
    credentials = get_credentials()
    if PROXY or DISABLE_SSL:
        http_client = credentials.authorize(get_http_client_with_proxy(proxies))
        return discovery.build(SERVICE_NAME, SERVICE_VERSION, http=http_client)
    return discovery.build(SERVICE_NAME, SERVICE_VERSION, credentials=credentials)


def get_file_path(entry_id):
    """
    Gets the file path for the given entry id
    """
    file_obj = demisto.getFilePath(entry_id)
    return file_obj['path']


def perform_logo_detection_service_request(file_bytes, proxies, max_results=10):
    """
    Encode the given file bytes and do a remote call to Google API to retrieve the results
    """
    image_content = base64.b64encode(file_bytes)
    service_request = get_service(proxies).images().annotate(body={
        'requests': [{
            'image': {
                'content': image_content.decode('UTF-8')
            },
            'features': [{
                'type': 'LOGO_DETECTION',
                'maxResults': max_results
            }]
        }]
    })
    return service_request.execute()


def is_logo_detected(results):
    """
    Indicates logos were detected or not
    """
    if results:
        for res in results.get('responses', []):
            logo_annotations = res.get('logoAnnotations', [])
            if len(logo_annotations) > 0:
                return True
    return False


'''MAIN FUNCTIONS'''


def detect_logos(entry_id, proxies):
    """
    Detects logos in the given entry_id.
    """
    file_path = get_file_path(entry_id)
    with open(file_path, 'rb') as f:
        content = f.read()
        return perform_logo_detection_service_request(content, proxies)


def detect_logos_command(proxies):
    """
    Detects brand logos from a given entry id.
    """
    entry_ids = argToList(demisto.args().get('entry_id'))
    output: Dict[str, Dict[str, List[Dict[str, str]]]] = {'GoogleVisionAPI': {'Logo': []}}
    hit = False

    for entry_id in entry_ids:
        results = detect_logos(entry_id, proxies)
        logo_detected = is_logo_detected(results)
        if logo_detected:
            hit = True
            for res in results.get('responses', []):
                logos = res.get('logoAnnotations', [])
                if logos:
                    for logo in logos:
                        context_logo = {
                            'Description': logo['description'],
                            'MID': logo['mid'],
                            'Score': logo['score']
                        }
                        output.get('GoogleVisionAPI', {}).get('Logo', []).append(context_logo)

    if hit:
        human_readable = 'Logos found: '
        for logo in output.get('GoogleVisionAPI', {}).get('Logo', []):
            human_readable += logo.get('Description') + ', '
        human_readable = human_readable[:-2]
    else:
        human_readable = 'No Logos found'
    return_outputs(human_readable, output)


def test_module(proxies):
    """
    This is the call made when pressing the integration test button.
    """

    # a sample microsoft logo png
    content = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\xd8\x00\x00\x00.\x08\x03\x00\x00\x00}5\'\xdb\x00' \
        b'\x00\x01\x11PLTE\x00\x00\x00sssssssssssssss\xf3P"sssssssssssssssssssssssssssssssssssswxj\x00\xa4' \
        b'\xefl\xca\x00\x7f\xba\x00\xff\xb9\x00\x00\xa2\xff\xfaN\x1c\xffD%\x00\xa4\xf0\xff\xb9\x00sss\x00' \
        b'\xae\xff\xff\xba\x00\xff\xbc\x00sssz\xbb\x00\x7f\xba' \
        b'\x00ssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssss\xfbI\x1f\xf8N' \
        b'\x1d\x00\xaf\xff{\xba\x00\x7f\xba\x00\xf2P"\x7f\xba\x00\xff\xbe\x00\x7f\xba\x00\xff\xb9\x00\xff' \
        b'\xb9\x00\xff\xbc\x00\xf2P"\x00\xae\xffm\xca\x00\xff\xab\x00\x7f\xba\x00\xff\xb9\x00{' \
        b'\xba\x00\x00\xa8\xffsss\xff\xb9\x00\x7f\xba\x00\x00\xa4\xef\xf2P"\xffL\x18y\xba\x00\x00\xa4\xf4' \
        b'\xf4N#\x0b5v\xab\x00\x00\x00RtRNS\x00\xf2\x0c\xf8\xd8\x14\xc9\xfc\x1acS\xb4\xac\x9e\'\x80\xca\xd3' \
        b'\xa5\x05\xc9\xaeCC\x1e\x1c\x1e\xf3\xf3\xe4\xb4\xb4\xad\\\x1c\xc9\xc3j+\x97<\xec\xb0N1 ' \
        b'\x0f\x91\x86B6\xb9v\xceG\xe8\xde\xbe{o\x8d\xa1 ' \
        b'\xcf\xc5\x1f\xea\xe4\xdf\xd1\xcd\xc8\xb7\xa4\x9f\x8e\x89z50"\x16\xfb\x12E\xa6\x00\x00\x05' \
        b'\x12IDATh\xde\xed\x98\xe7\x96\x93@\x18\x86?\x081\xa6S\xec\x8a\x8a\xa6\x90\x04H\xd9\x90d\x93\xd8{' \
        b'\xd7\xb1{\xff\x17"\xd3!\xc0\x0f\x8f\xe0QO\x9e\x1f\xbb\xb3\xb3d\x98g\xca;\x10x\xf9\xe8L\x8a{' \
        b'g.\xc3\xeb\x87\xb7S<}\xfc\x16\xfe\x19\xce|\xc9\xe0\xc7]8\xff)\x8b\x0b\xf0\xcf\x90-v\xe5(' \
        b'\xf6\xd7r\x14;\x8a\xfd%\xfc\'b\x8b\xe9\xb89\xee\xffA1u\xe2A\xf9\xf8=\x84\xd9\x14$\xa6\xde\x19\x9b' \
        b'\xa696\xab\x90\xa4{\x1aU7\xdb*\x00\xb8\nB-(' \
        b'\x1b\xaf\x86\n\x15\xabV\x10\xc19\xb8\r\xadU\xb0\x98\x86K[(' \
        b'\x17\xd5F\xe5\x88\x9d@\x82\x19\x17\xe3W\xb4\xa1\\\xb6(\xa2\xb6\xf3\x1a[' \
        b'<\x96g\xf7\xf3\xa2\xc4\xd0"^k\xad\xa5\x18\x18\xb8\xb4\x84r!\x1b\xacA\xbb4\xdb\xe0bQb\xfbx\xad' \
        b'\x83bb\x9e\x82\xd0\x1d(\r\xd9\r\x83\x96\xeb\x08\x15)f[\xc9\xf1\x93b\xa0.|(' \
        b'\x99\xb38:\xc6\x85\x8b\x8d*\xa4)\x81\x8bEm*V:R\xacU\xb8\xd8\xb0G\xc6K0\xc4u\xe3\x1c1k\xb0j4\xe6g' \
        b'\x93\x99\xe6-\xaa\xa2\xb8\x9a\xac\x16\x01\xc4\t\xdcFc5\xb0\xe2\xb7uW\x13Q#\xc5\xe4>\x98\x14"\xe6' \
        b'\x90A\x1a\x88~(8L\x9a\\l;\xd2\x8d\x90/F\x7f\xcarY\xc7c\xba_\xeb\xdai\xf4\xab\xc27\xc8dL\x97ve' \
        b'<\x07N\xc7\xa4u5\x1e@V\x9d-\xf5\xd1\xb0C\x9e86zH\xfe\xec\xe9\x11\xa7\x1b\x92\xfa\xa7\xb8\xe5\xdf' \
        b'\x16\xb3PD\x97\xd7\xf5q\xbfA\xe7b\xed\x98\xf5\x161\xa8\xc9\t^\xb3\x01\xfe\x894<\xee:\x924-\xbe' \
        b'\xb28=\xb6\xd0GH2\x03\x809\xcaF\xf9m\xb1%I\x0b-\x1e\x1d}\xd0\x12b\x1d\x00R\x94\x84\x00\x80gU\x1f' \
        b'"&\xe6+(\x8eN\xcc\x1a\xe8@l\x82\x12\x0c\xcb\x14\xeb\x92IB+\x19\x1d\x8a\x95%\xd6E\xd4\xc1\x1c\x9e(' \
        b'\xc8`b\x15\xacS\xc3b6\x8d\xd7\xa6\xd9\xc3\x8d\xb2=c\x10\xa5\xba3\xdbP1\x97\xb5\xd12CZ\xdaEU\x8aB' \
        b'\xd6\xaaB \x1f\xaeDU6\xdc\xfb\x9aE$\xf6-\x8b,' \
        b'1\x15\x9f\xc8&\xad2i1-\xe6\xd1.\xd1U9\xa5b\x84e5\x98\xcc`O\xcau\xd6\x06fEf\x83\x9f\x82\x8d)D\x90' \
        b'\xd5\xba^\x90\xc40\x88B\x15\x02\xe8\xd0\xb8W#\xe8 ;\xa0\x06*\\\xbe{\xf9\x90\xa8\xca\x82[' \
        b'\xefo\xa5x\xf0\xc0J\x8b\xd1\xde\xd7|r;\\3\xcf\x12\x1b\x93\x05&>iq\xb1\t\xd0\xcf\xb1\x98\x96fM\x80' \
        b'\xba\x94\x95\x0bQ\xf1Y\x8a\xd0\xc7\xd0\xecT\xfc-\xa4\x98GF\x9e\xe7\x83\x06)1vs%\x96\xf3L\xac-#G' \
        b'\xbe\x05\xf8\xf8\xe2\xdaYp\xa8\xa0\xa0-\xee#6`/\xff\x1c{' \
        b'u\xffz\x8a\xfb\xd7?\xc0\x9b\'7R<\x7f\xf6.-\xc6\x02.\xe4\x9bb\x99%\xe6\xc8U%\xc5\xe4$\x99\xc9\x81' \
        b'>\xa5\xff\x1a\xd0\x1c\x11G\x89F}\x19\xea\x08\xafK+W\xec\xdc\xe7\x0c\xbe_\x82\x1b\x1f\xb3\xb8\x98' \
        b'\x16\xe3\xcd\xb9t\xad(\xd5,' \
        b'\xb1)Y\xfbi\xb1N\xec1\xccO\x1c\xf2h\x87\x07\x8c`8V\xec\x99P\x10\x92\x06~Y\xec\xe6/\x88\xc1\x86fo' \
        b'\x93DGZ\x8cM\x89\x97\x14\xe3\xd7\xc8\xeb9]\xb6}\xce\xf2Sk\x8dCw\x81K\xa7\x90\x9c\xd7y\x99btBF\x10' \
        b'\xd0;\xa5\xc5Xv\x0c~U\x0c\xe8\xf9\xcd\xe6\xcf\xfd\xf3bt7,' \
        b'\xea$:\xf2gl\x9e+\x16\x8a\xdd#\x97b\x9f\x14\xdd\xa6x\xe7\x1b\xc4\x82U\x84\xbf_\xae\x18\xb4\xf0' \
        b'`\xea4:r\xf7\xd8,W\xec$\xf9\xba\xda\x8cgI\xb5\xcd\x9e2\xac\x11^\x17b^-\x1b\x9f\xe8Y\xa98)P\xccA' \
        b'\x8cN\x96\x18\xcbf#G\x8cyO\x81\x11\x10\x83\x008;\x16\xecz"\x81\\\xfa\xadD\x893&TD\xfbi\xb1`\x94x' \
        b'\xd3V-!&;Y\xeb\x00e\xc6\xce\x86@\x8d\x05\xbb\xce\x04\r\x80\xd8,' \
        b'\xf7\xb3\xc4\xb6E\x8a\xcd\xa8\xd8<SL\xfc\xff\x0e\x9b\xa009cl2\x14\x8fM\x10[' \
        b'\x98KV\xe1\x93\x9e\xf3\xe7\x93\x9e*\x8f\xbe\xb5u ' \
        b'\xb6\xe2\xeeVQb\xbe\xfc\xfe+-&\xa7t\xd4\x9au\xcd52\x12b\xe2\xed\xa3v2\xebN\rR\x9c\xd2\xe1\x0f\xf7' \
        b'\x8d\xd5Rc\xb1\x08KD\xfc\xa36\xda6b\x8bN\x8a\xc9n\x18\xdd\xa1^\x94\x18\xdc!\xcf;\xf9b\x1d\x05' \
        b'\tRbX"A\xeb\xb0\xce\x90q)Y\xc2\xa1\x18\x8c\x11E)Ll\xc2\x15\xd2b\x03z\xb5\x96z\xd1\x94b$^$\xc3CY' \
        b'\xfb\xacX\xf1\x92z\xfa\xcb\x1c\xf0\x8a\x10\x0bB[C}\x91rJe(' \
        b'\xcb\xda:TqGj\x9a\xbd\xf1\xf9\xac0\xb5Jo\x8eG\xbfB\xae\x91\xad\xedm\xd6\xa71;\xc9;\'k\xa6\xb5\x05' \
        b'\xce\xa0\xa5\xb0\xbai\x95\x8f\xafak5\x11\xa9\x0bz\x13\xe3\x97\xc5~\x0b\xdf\xe9\xef\xea+\x15r\x188' \
        b'\xfd~\xdd\xb5@\xe2E5\xce\x00\x12\xb8uR\x97\x8b\xd7\xdf\xf5\xdd_O\xc5\x7f\x86\xa3\xd8Q\xec/\xe1(' \
        b'v\x14\xfbK8\xf7\xf9j\x8a\xcfW/\xc1\x8b\x8f\xd7\xd2\xfcCb?\x01\xc7\xf5]\n\x11\xa0Y\x98\x00\x00\x00' \
        b'\x00IEND\xaeB`\x82 '
    response = perform_logo_detection_service_request(content, proxies)
    logo_found = response.get('responses', [])[0].get('logoAnnotations', [])[0].get('description', '')
    if 'microsoft' in logo_found.lower():
        demisto.results('ok')
    else:
        return_error(str(response))


'''EXECUTION BLOCK'''


def main():
    """Main Execution Block"""
    try:
        proxies = handle_proxy()

        if demisto.command() == 'test-module':
            test_module(proxies)
        elif demisto.command() == 'google-vision-detect-logos':
            detect_logos_command(proxies)

    except Exception as e:
        if 'Quota exceeded for quota metric' in str(e):
            return_error('Quota for Google Vision API exceeded')
        else:
            return_error(str(e))


# python2 uses __builtin__ python3 uses builtins
if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
