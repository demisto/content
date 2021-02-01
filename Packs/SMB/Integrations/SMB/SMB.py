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


def smb_delete_files():
    args = demisto.args()
    share, path_pattern = split_path(args.get('file_path'))
    hostname = args.get('hostname', HOSTNAME)
    nb_name = args.get('nbname', NBNAME)
    domain = args.get('domain', DOMAIN)

    if not hostname:
        return_error('No hostname was configured for the integration, cannot establish connection.')
    elif not nb_name:
        return_error('No NetBIOS name was configured for the integration, cannot establish connection.')
    connection = connect(hostname=hostname, domain=domain, user=USER, password=PASSWORD, nb_name=nb_name, port=PORT)
    try:
        connection.deleteFiles(share, path_pattern)
        demisto.results("Deleted file {} .".format(path_pattern))
        return_outputs('Success')

    except Exception as err:
        demisto.results("The file could not be deleted from SMB : {}".format(err))
    finally:
        connection.close()


def smb_list_shares():
    args = demisto.args()
    hostname = args.get('hostname', HOSTNAME)
    nb_name = args.get('nbname', NBNAME)
    domain = args.get('domain', DOMAIN)
    share_name_list = []

    if not hostname:
        return_error('No hostname was configured for the integration, cannot establish connection.')
    elif not nb_name:
        return_error('No NetBIOS name was configured for the integration, cannot establish connection.')

    connection = connect(hostname=hostname, domain=domain, user=USER, password=PASSWORD, nb_name=nb_name, port=PORT)
    try:
        shares_list = connection.listShares()
        for share in shares_list:
            if not share.isSpecial and share.name not in ['NETLOGON', 'SYSVOL']:
                share_name_list.append(str(share.name))
        demisto.results("The list of shares on the SMB server: {}.".format(share_name_list))

    except Exception as err:
        demisto.results("No results found: {}".format(err))
    finally:
        connection.close()


def smb_list_files():
    args = demisto.args()
    file_share = args.get('file_share')
    file_path = args.get('file_path')
    hostname = args.get('hostname', HOSTNAME)
    nb_name = args.get('nbname', NBNAME)
    domain = args.get('domain', DOMAIN)

    if not hostname:
        return_error('No hostname was configured for the integration, cannot establish connection.')
    elif not nb_name:
        return_error('No NetBIOS name was configured for the integration, cannot establish connection.')

    connection = connect(hostname=hostname, domain=domain, user=USER, password=PASSWORD, nb_name=nb_name, port=PORT)
    try:
        files_list_from_server = connection.listPath(file_share, file_path)
        files_details = []
        for file in files_list_from_server:
            if file.filename not in ['.', '..']:
                files_details.append({'Name': str(file.filename),
                                      'Size': str(file.file_size),
                                      'Path': '{}/{}/{}'.format(file_share, file_path, file.filename),
                                      })
        human_readable = tableToMarkdown('Files List', files_details)
        demisto.results({
            'Type': entryTypes['note'],
            'Contents': files_details,
            'ContentsFormat': formats['json'],
            'HumanReadable': human_readable,
            'ReadableContentsFormat': formats['markdown'],
            'EntryContext': {
                "SMB.File(val.Name == obj.Name || val.Path == obj.Path)": files_details
            }
        })
    except Exception:
        demisto.results("No results found at location {}/{}".format(file_share, file_path))
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
    elif demisto.command() == 'smb-list-files':
        smb_list_files()
    elif demisto.command() == 'smb-list-shares':
        smb_list_shares()
    elif demisto.command() == 'smb-delete-files':
        smb_delete_files()
except Exception as e:
    return_error(str(e))
