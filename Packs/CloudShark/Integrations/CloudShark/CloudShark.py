import demistomock as demisto
from CommonServerPython import *
import requests
import collections
import urllib3

# disable insecure warnings
urllib3.disable_warnings()

BASE_URL = demisto.params().get('url')
USE_SSL = not demisto.params().get('insecure', False)
PROXY = demisto.params().get('proxy')
API_KEY = demisto.params().get('apikey')

'''HELPER FUNCTIONS'''
capture_info_outputs = {
    'id': 'CaptureID',
    'group_write?': 'GroupWrite',
    'size': 'Size',
    'data_byte_rate': 'DataByteRate',
    'tag_list': 'TagList',
    'data_bit_rate': 'DataBitRate',
    'filename': 'FileName',
    'sha1_hash': 'SHA1',
    'avg_packet_rate': 'AvgPacketRate',
    'start_time': 'StartTime',
    'created_at': 'CreatedAt',
    'avg_packet_size': 'AvgPacketSize',
    'user': 'User',
    'last_accessed': 'LastAccessed',
    'disable_autodelete': 'DisableAutodelete',
    'cap_file_id': 'CapFileID',
    'end_time': 'EndTime',
    'num_packets': 'NumPackets',
    'encapsulation': 'Encapsulation',
    'duration': 'Duration',
    'comments': 'Comments',
    'public?': 'Public',
    'data_size': 'DataSize',
    'file': 'File',
    'file_type': 'FileType',
    'file_source': 'FileSource',
    'truncated': 'Truncated',
    'group': 'Group',
}


# Translates the capture info field names to standard outputs
def transalte_capture_info(capture_info):
    translated_output = {}
    for field_name, standard_name in capture_info_outputs.items():
        if field_name in capture_info:
            translated_output[standard_name] = capture_info.get(field_name)
    return translated_output


# Allows nested keys to be accesible
def makehash():
    return collections.defaultdict(makehash)


def parse_error_response(http_response):
    try:
        response = http_response.json()
    except ValueError:
        return f'Error in API call. Recived status code: {http_response.status_code};' \
            f' Reason: {http_response.reason}; contents: {http_response.content}'
    exceptions = response.get('exceptions', '')
    if exceptions:
        return f'Call Failed. status code:{http_response.status_code}, reason: {exceptions}'


def http(method, url_suffix, params=None, data=None, files=None):
    try:
        response = requests.request(
            method,
            BASE_URL + '/api/v1/' + API_KEY + url_suffix,
            verify=USE_SSL,
            params=params,
            data=data,
            files=files)
        if response.status_code == 200:
            return response
        elif (response.status_code == 403) and (url_suffix == "/search/"):
            # API Token cannot execute API method.
            # If testing toekn is valid using the /search/ endpoint this is ok
            return response
        elif response.status_code == 404:
            return_error(parse_error_response(response))
        else:
            return_error(parse_error_response(response))
    except requests.exceptions.ConnectionError as err:
        return_error("Could not connect to CS Enterprise URL ", str(err))
    except requests.exceptions.MissingSchema:
        return_error("Invalid Schema. URL must start with http:// or https://")
    except requests.exceptions.InvalidSchema:
        return_error("Invalid Schema. URL must start with http:// or https://")


'''MAIN FUNCTIONS'''


def upload(file_entry_id, additional_tags=None, filename=None):
    # Get file
    cmd_res = demisto.getFilePath(file_entry_id)
    file_path = cmd_res.get('path')
    name = cmd_res.get('name')

    # Setup optional parameters
    params = {}
    if filename is not None:
        params['filename'] = filename
    if additional_tags is not None:
        params['additional_tags'] = additional_tags

    files = {'file': (name, open(file_path, 'rb'))}
    response = http('POST', '/upload', files=files, params=params)
    capture_id = response.json()['id']
    return capture_id


def upload_command():
    # Get arguments
    file_entry_id = demisto.args().get('file')
    filename = demisto.args().get('filename')
    additional_tags = demisto.args().get('additional_tags')

    # Create hashes
    contxt = makehash()

    # Upload capture and get capture_id
    capture_id = upload(file_entry_id, additional_tags=additional_tags, filename=filename)
    url = BASE_URL + '/captures/' + capture_id

    # Set Demisto Context
    contxt['URL']['Data'] = url
    contxt['CloudShark']['CaptureID'] = capture_id
    ec = contxt

    # Create markdown link to capture
    markdown_url = "CaptureID: " + capture_id + " - [Open Capture in CloudShark](" + url + ")"

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['markdown'],
        'Contents': ec,
        'HumanReadable': markdown_url,
        'EntryContext': ec
    })


def info(capture_id):
    url_suffix = '/info/' + capture_id
    response = http('GET', url_suffix)
    info = response.json()
    return info


def info_command():
    # Get arguments
    capture_id = demisto.args().get('capture_id')

    # Create hashes
    contxt = makehash()

    # Request meta-info from CloudShark
    file_info = info(capture_id)
    # Set Demisto Context
    capture_info = transalte_capture_info(file_info)
    contxt['CloudShark.CaptureInfo(val.CaptureID && val.CaptureID == obj.CaptureID)'] = capture_info
    ec = contxt

    # Create table with capture info
    info_table = tableToMarkdown('Capture file info', capture_info)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['markdown'],
        'Contents': file_info,
        'HumanReadable': info_table,
        'EntryContext': ec
    })


def download(capture_id):
    url_suffix = '/download/' + capture_id
    response = http('GET', url_suffix)
    filename = re.findall("filename=(.+)", response.headers['Content-Disposition'])[0]
    file = response.content
    files = {'filename': filename, 'file': file}
    return files


def download_command():
    # Get argument
    capture_id = demisto.args().get('capture_id')

    # Download file
    files = download(capture_id)

    demisto.results(fileResult(files['filename'], files['file']))


def delete(capture_id):
    url_suffix = '/delete/' + capture_id
    response = http('POST', url_suffix)
    msg = response.json()
    return msg


def delete_command():
    # Get argument
    capture_id = demisto.args().get('capture_id')

    # Create hashes
    contxt = makehash()
    human_readable = makehash()

    # Delete capture
    result = delete(capture_id)

    # Set result
    contents = result
    human_readable['Response'] = result
    contxt['CloudShark']['Result'] = result
    ec = contxt

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['markdown'],
        'Contents': contents,
        'HumanReadable': tableToMarkdown('Result', human_readable),
        'EntryContext': ec
    })


''' EXECUTION CODE '''
LOG('command is %s' % (demisto.command(),))
try:
    handle_proxy()
    # The command demisto.command() holds the command sent from the user.
    if demisto.command() == 'cloudshark-upload':
        upload_command()
    elif demisto.command() == 'cloudshark-info':
        info_command()
    elif demisto.command() == 'cloudshark-download':
        download_command()
    elif demisto.command() == 'cloudshark-delete':
        delete_command()
    elif demisto.command() == 'test-module':
        # This is the call made when pressing the integration test button.
        if API_KEY == "":
            return_error("Must enter API Token")
        response = http("GET", "/search/")
        if response.status_code == 200 or response.status_code == 403:
            # Token is valid but search method not allowed
            demisto.results('ok')
        else:
            demisto.results('Error: Server returned %s: %s' % (response.status_code, response.reason))
        sys.exit(0)
except Exception as e:
    LOG(e)
    LOG.print_log()
    raise
