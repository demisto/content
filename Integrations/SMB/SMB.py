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


def connect(hostname, domain, user, password, nb_name, port):
    if not domain:
        connection = SMBConnection(user, password, 'Demisto', nb_name, is_direct_tcp=True)
    else:
        connection = SMBConnection(user, password, 'Demisto', nb_name, domain=domain, is_direct_tcp=True)
    if not connection.connect(hostname, port):
        return_error('Authentication failed, verify instance configuration parameters and try again.')
    return connection


''' FUNCTIONS '''


def test_module():
    if HOSTNAME and NBNAME:
        connection = connect(hostname=HOSTNAME, domain=DOMAIN, user=USER, password=PASSWORD, nb_name=NBNAME, port=PORT)
        demisto.results('ok')
        connection.close()
    else:
        demisto.results('No hostname or NetBIOS name was configured, cannot perform a connection test.')


def smb_download():
    share, path = split_path(demisto.getArg('file_path'))
    hostname = demisto.args().get('hostname') if demisto.args().get('hostname') else HOSTNAME
    nbname = demisto.args().get('nbname') if demisto.args().get('nbname') else NBNAME
    domain = demisto.args().get('domain') if demisto.args().get('domain') else DOMAIN

    if not hostname:
        return_error('No hostname was configured for the integration, cannot establish connection.')
    elif not nbname:
        return_error('No NetBIOS name was configured for the integration, cannot establish connection.')
    connection = connect(hostname=hostname, domain=domain, user=USER, password=PASSWORD, nb_name=nbname, port=PORT)
    try:
        with tempfile.NamedTemporaryFile() as file_obj:
            file_attributes, filesize = connection.retrieveFile(share, path, file_obj)
            file_obj.seek(0)
            filename = path.split('/')[-1] if '/' in path else path.split('\\')[-1]
            if demisto.getArg('download_and_attach') == "yes":
                demisto.results(fileResult(filename, file_obj.read()))
            else:
                demisto.results(file_obj.read())
    finally:
        connection.close()


def smb_upload():
    share, path = split_path(demisto.getArg('file_path'))
    entryID = demisto.getArg('entryID')
    content = demisto.getArg('content')
    hostname = demisto.args().get('hostname') if demisto.args().get('hostname') else HOSTNAME
    nbname = demisto.args().get('nbname') if demisto.args().get('nbname') else NBNAME
    domain = demisto.args().get('domain') if demisto.args().get('domain') else DOMAIN

    if not hostname:
        return_error('No hostname was configured for the integration, cannot establish connection.')
    elif not nbname:
        return_error('No NetBIOS name was configured for the integration, cannot establish connection.')
    connection = connect(hostname=hostname, domain=domain, user=USER, password=PASSWORD, nb_name=nbname, port=PORT)
    try:
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
            file_bytes_transfered = connection.storeFile(share, path, file_obj)
            demisto.results("Transfered {} bytes of data.".format(file_bytes_transfered))
    finally:
        connection.close()


''' EXECUTION CODE '''

LOG('command is %s' % (demisto.command(),))

try:
    if demisto.command() == 'test-module':
        test_module()
    elif demisto.command() == 'smb-download':
        smb_download()
    elif demisto.command() == 'smb-upload':
        smb_upload()
except Exception as e:
    return_error(str(e))
