import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


''' IMPORTS '''


import tempfile
from smb.SMBConnection import SMBConnection

''' GLOBAL VARS '''


USER = demisto.params()['credentials']['identifier']
PASSWORD = demisto.params()['credentials']['password']
HOSTNAME = demisto.params()['hostname']
PORT = int(demisto.params()['port'])
NBNAME = demisto.params()['nbname']
DOMAIN = demisto.params().get('domain', None)


''' HELPER FUNCTIONS '''


def split_path(path):
    delim = '/' if '/' in path else '\\'
    path = path.strip(delim)
    return path.split(delim, 1)


def connect():
    if not DOMAIN:
        conn = SMBConnection(USER, PASSWORD, 'Demisto', NBNAME, is_direct_tcp=True)
    else:
        conn = SMBConnection(USER, PASSWORD, 'Demisto', NBNAME, domain=DOMAIN, is_direct_tcp=True)
    if not conn.connect(HOSTNAME, PORT):
        return_error('Authentication failed, verify instance configuration parameters and try again.')
    return conn


''' FUNCTIONS '''


def download():
    share, path = split_path(demisto.getArg('file_path'))
    with tempfile.NamedTemporaryFile() as file_obj:
        file_attributes, filesize = conn.retrieveFile(share, path, file_obj)
        file_obj.seek(0)
        filename = path.split('/')[-1] if '/' in path else path.split('\\')[-1]
        if demisto.getArg('download_and_attach') == "yes":
            demisto.results(fileResult(filename, file_obj.read()))
        else:
            demisto.results(file_obj.read())


def upload():
    share, path = split_path(demisto.getArg('file_path'))
    entryID = demisto.getArg('entryID')
    content = demisto.getArg('content')
    if not entryID and not content:
        raise Exception("smb-upload requires one of the following arguments: content, entryID.")
    if entryID:
        file = demisto.getFilePath(entryID)
        filePath = file['path']
        with open(filePath, mode='rb') as f:
            content = f.read()

    with tempfile.NamedTemporaryFile() as file_obj:
        file_obj.write(content)
        file_obj.seek(0)
        file_bytes_transfered = conn.storeFile(share, path, file_obj)
        demisto.results("Transfered {} bytes of data.".format(file_bytes_transfered))


''' EXECUTION CODE '''


LOG('command is %s' % (demisto.command(), ))
handle_proxy()
conn = connect()
try:
    if demisto.command() == 'test-module':
        demisto.results('ok')
    elif demisto.command() == 'smb-download':
        download()
    elif demisto.command() == 'smb-upload':
        upload()
except Exception, e:
    LOG(e)
    LOG.print_log()
    return_error(e.message)
finally:
    conn.close()
