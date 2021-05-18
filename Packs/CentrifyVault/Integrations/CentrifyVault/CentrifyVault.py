import re
import time

import demistomock as demisto  # noqa: F401
# IMPORTS

from CommonServerPython import *  # noqa: F401

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

"""PARAMETERS"""


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(self, token_retrieval_url, data, app_id, use_ssl, proxy):
        headers = {'X-CENTRIFY-NATIVE-CLIENT': 'true'}
        super().__init__(base_url=token_retrieval_url, headers=headers, verify=use_ssl, proxy=proxy)
        self.payload = data
        self.app_id = app_id

    def http_request(self, *args, headers=None, **kwargs):
        """
        Overrides Base client request function, retrieves and adds to headers access token before sending the request.

        Returns:
            requests.Response: The http response
        """
        bearer_token = "Bearer " + str(self.authenticate_oauth())
        default_headers = {
            'content-type': 'application/json',
            'Authorization': bearer_token,
            'X-CENTRIFY-NATIVE-CLIENT': 'true'
        }
        if headers:
            default_headers.update(headers)

        return super()._http_request(*args, headers=default_headers, **kwargs)  # type: ignore[misc]

    def authenticate_oauth(self):
        """
        Login using the credentials and store the cookie
        """
        integration_context = demisto.getIntegrationContext()
        bearer_token = integration_context.get('bearer_token')
        valid_until = integration_context.get('valid_until')
        time_now = int(time.time())
        if bearer_token and valid_until:
            if time_now < valid_until:
                # Bearer Token is still valid - did not expire yet
                return bearer_token
        response = self.get_token_request()
        bearer_token = response.get('access_token')
        t = time.time()
        expiration_time = t + 1800
        integration_context = {
            'bearer_token': bearer_token,
            'valid_until': expiration_time  # Assuming the expiration time is 30 minutes
        }
        demisto.setIntegrationContext(integration_context)
        return bearer_token

    def get_token_request(self):
        """
            Sends token request

            :rtype ``str``
            :return: bearer token
        """
        urlSuffix = '/oauth2/token/' + self.app_id
        fullUrl = f'{self._base_url}{urlSuffix}'
        body = self.payload
        headers = {
            'X-CENTRIFY-NATIVE-CLIENT': 'true'
        }
        token_response = self._http_request(method='POST', full_url=fullUrl,
                                            url_suffix='', data=body, headers=headers)
        if not token_response:
            err_msg = 'Authorization Error: User has no authorization to create a token.' \
                      ' Please make sure you entered the credentials correctly.'
            raise Exception(err_msg)
        return token_response

    def request_secret_set_id(self, url_suffix, data):
        return self.http_request(method="POST", url_suffix=url_suffix, json_data=data)

    def request_set_details(self, url_suffix, data):
        return self.http_request(method="POST", url_suffix=url_suffix, json_data=data)

    def request_delete_set(self, url_suffix, data):
        return self.http_request(method="POST", url_suffix=url_suffix, json_data=data)

    def request_create_set(self, url_suffix, data):
        return self.http_request(method="POST", url_suffix=url_suffix, json_data=data)

    def request_fetch_folderids(self, url_suffix, data):
        return self.http_request(method="POST", url_suffix=url_suffix, json_data=data)

    def request_fetch_secret_folder_id(self, url_suffix, data):
        return self.http_request(method="POST", url_suffix=url_suffix, json_data=data)

    def request_delete_folder(self, url_suffix, data):
        return self.http_request(method="POST", url_suffix=url_suffix, json_data=data)

    def request_create_folder(self, url_suffix, data):
        return self.http_request(method="POST", url_suffix=url_suffix, json_data=data)

    def request_fetch_secret(self, url_suffix, data):
        return self.http_request(method="POST", url_suffix=url_suffix, json_data=data)

    def request_fetch_secretids_set(self, url_suffix, data):
        return self.http_request(method="POST", url_suffix=url_suffix, json_data=data)

    def request_fetch_secretids_folder(self, url_suffix, data):
        return self.http_request(method="POST", url_suffix=url_suffix, json_data=data)

    def request_delete_secret(self, url_suffix, data):
        return self.http_request(method="POST", url_suffix=url_suffix, json_data=data)

    def request_add_secret_set(self, url_suffix, data):
        return self.http_request(method="POST", url_suffix=url_suffix, json_data=data)

    def request_create_secret(self, url_suffix, data):
        return self.http_request(method="POST", url_suffix=url_suffix, json_data=data)


"""Demisto Output Entry"""


def create_entry(title, data):
    md = tableToMarkdown(title, data, ['FolderName', 'SecretName', 'SecretText', 'SecretType', 'SecretDescription'])\
        if data else 'No result were found'
    if data:
        ec = {'Centrify.Secrets(val.SecretName && val.SecretName == obj.SecretName && val.FolderName &&'
              ' val.FolderName == obj.FolderName)': data}
        return {
            'ContentsFormat': formats['json'],
            'Type': entryTypes['note'],
            'Contents': data,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': md,
            'EntryContext': ec
        }
    else:
        return 'No secrets were found'


def test_module(client: Client):
    """test function
    Args:
        client:
    Returns:
        ok if successful
    """
    try:
        client.authenticate_oauth()
    except Exception as e:
        raise DemistoException(
            f"Test failed. Please check your parameters. \n {e}")
    return 'ok'


"""Fetches the Centrify set id for the setname provided"""


def fetch_secret_set_id(client: Client, setName):
    urlSuffix = '/Collection/GetObjectCollectionsAndFilters'
    payload = {"ObjectType": "DataVault", "CollectionType": "ManualBucket"}
    centrify_setid_response = client.request_secret_set_id(url_suffix=urlSuffix, data=payload)
    for set_item in centrify_setid_response.get('Result').get('Results'):
        if set_item.get('Row').get('Name') == setName:
            return set_item.get('Row').get('ID')
    return "set name not found"


"""Fetches the secret id's list for the setid provided"""


def fetch_secretids_set(client: Client, set_id, secret_ids_list):
    urlSuffix = '/Collection/GetMembers'
    payload = {"ID": set_id}
    centrify_secretids_response = client.request_fetch_secretids_set(url_suffix=urlSuffix, data=payload)
    for secret_id_item in centrify_secretids_response.get("Result"):
        secret_ids_list.append(secret_id_item['Key'])
    return secret_ids_list


"""Fetches the Centrify folder id for the foldername provided"""


def fetch_secret_folder_id(client: Client, folderName):
    urlSuffix = '/ServerManage/GetSecretFolder'
    payload = {"Name": folderName}
    centrify_folderid_response = client.request_fetch_secret_folder_id(url_suffix=urlSuffix, data=payload)
    return centrify_folderid_response.get('Result').get('Results')[0].get('Row').get('ID')


"""Fetches the secret id's list recurrsively for the folderid provided"""


def fetch_secretids_folder(client: Client, folder_id, secret_ids_list, recursive):
    urlSuffix = '/ServerManage/GetSecretsAndFolders'
    payload = {"Parent": folder_id}
    centrify_secretids_response = client.request_fetch_secretids_folder(url_suffix=urlSuffix, data=payload)
    secret_ids_count = centrify_secretids_response.get('Result').get('FullCount')
    for secret_id_item in range(secret_ids_count):
        if centrify_secretids_response.get('Result').get('Results')[secret_id_item].get('Row').get('Type') == 'Text':
            secret_ids_list.append(centrify_secretids_response.get('Result').get('Results')[secret_id_item].get('Row').get('ID'))
        else:
            if recursive:
                sub_folder_id = centrify_secretids_response.get('Result').get('Results')[secret_id_item].get('Row').get('ID')
                fetch_secretids_folder(client, sub_folder_id, secret_ids_list, recursive)
            else:
                pass
    return secret_ids_list


"""Fetches details of all the sets in Centrify Vault"""


def fetch_set_details(client: Client, set_details_list):
    urlSuffix = '/Collection/GetObjectCollectionsAndFilters'
    payload = {"ObjectType": "DataVault", "CollectionType": "ManualBucket"}
    centrify_setdetails_response = client.request_set_details(url_suffix=urlSuffix, data=payload)
    centrify_setdetails_response = centrify_setdetails_response.get('Result').get('Results')
    for set_item in centrify_setdetails_response:
        if 'Description' not in set_item['Row']:
            set_description = ""
        else:
            set_description = set_item['Row']['Description']
        set_details_list.append({'SetName': set_item['Row']['Name'], 'SetID': set_item['Row']['ID'],
                                 'SetDescription': set_description})
    return set_details_list


"""Fetches the centrify secret details for the secret response received through the fetch_secret() method"""


def centrify_secret_details(centrify_secret):
    CENTRIFY_VAULT = {}
    CENTRIFY_VAULT['FolderName'] = centrify_secret.get('Result').get('ParentPath')
    CENTRIFY_VAULT['SecretName'] = centrify_secret.get('Result').get('SecretName')
    CENTRIFY_VAULT['SecretID'] = centrify_secret.get('Result').get('_RowKey')
    CENTRIFY_VAULT['SecretText'] = centrify_secret.get('Result').get('SecretText')
    CENTRIFY_VAULT['SecretType'] = centrify_secret.get('Result').get('Type')
    if 'Description' in centrify_secret.get('Result'):
        CENTRIFY_VAULT['SecretDescription'] = centrify_secret.get('Result').get('Description')
    else:
        CENTRIFY_VAULT['SecretDescription'] = ''
    return CENTRIFY_VAULT


"""Fetches the centrify secret details for the secret id and name(optional) provided"""


def fetch_secret(client: Client, secret_id, secret_name, regex_match):
    urlSuffix = '/ServerManage/RetrieveDataVaultItemContents'
    payload = {"ID": secret_id}
    centrify_secret_response = client.request_fetch_secret(url_suffix=urlSuffix, data=payload)
    if secret_name:
        if regex_match:
            if re.search(secret_name, centrify_secret_response.get('Result').get('SecretName'), re.IGNORECASE):
                CENTRIFY_VAULT = centrify_secret_details(centrify_secret_response)
            else:
                return None
        else:
            if secret_name == centrify_secret_response.get('Result').get('SecretName'):
                CENTRIFY_VAULT = centrify_secret_details(centrify_secret_response)
            else:
                return None
    else:
        CENTRIFY_VAULT = centrify_secret_details(centrify_secret_response)
    return CENTRIFY_VAULT


"""Fetches details of all folders in list recurrsively"""


def fetch_folderids(client: Client, folder_id, folders_list):
    urlSuffix = '/ServerManage/GetSecretsAndFolders'
    payload = {"Parent": folder_id}
    centrify_folderids_response = client.request_fetch_folderids(url_suffix=urlSuffix, data=payload)
    folder_ids_count = centrify_folderids_response.get('Result').get('FullCount')
    for folder_id_item in range(folder_ids_count):
        if centrify_folderids_response.get('Result').get('Results')[folder_id_item].get('Row').get('Type') == 'Folder':
            folder_res = centrify_folderids_response.get('Result').get('Results')[folder_id_item].get('Row')
            if folder_res.get('ParentPath'):
                folder_directory = folder_res.get('ParentPath') + "\\" + folder_res.get('Name')
            else:
                folder_directory = folder_res.get('Name')
            folders_list.append({"FolderName": folder_res.get('Name'), "FolderID": folder_res.get('ID'),
                                 "ParentFolder": folder_res.get('ParentPath'),
                                 "FolderDescription": folder_res.get('Description'), "FolderDirectory": folder_directory})
            sub_folder_id = folder_res.get('ID')
            fetch_folderids(client, sub_folder_id, folders_list)
        else:
            pass
    return folders_list


"""Creates a centrify folder for the foldername, description and parent foldername(optional) provided"""


def create_folder(client: Client, folderName, description, parent_id):
    urlSuffix = '/ServerManage/AddSecretsFolder'
    payload = {"Name": folderName, "Description": description, "Parent": parent_id}
    centrify_folder_response = client.request_create_folder(url_suffix=urlSuffix, data=payload)
    if centrify_folder_response.get('success') is True:
        return "Folder Created", centrify_folder_response.get('Result')
    else:
        return centrify_folder_response.get("MessageID"), "No Folder ID"


"""Creates a centrify set for the setname provided"""


def create_set(client: Client, setName, description):
    urlSuffix = '/Collection/CreateManualCollection'
    payload = {"ObjectType": "DataVault", "Name": setName, "Description": description}
    centrify_set_response = client.request_create_set(url_suffix=urlSuffix, data=payload)
    if centrify_set_response.get('success') is True:
        return "Set Created", centrify_set_response.get('Result')
    else:
        return centrify_set_response.get("Message"), "No Set ID"


"""Creates a centrify secret in the folder for the provided foldername, secrettext, secrettype"""


def create_secret(client: Client, folderId, secret_name, secret_text, secret_type, secret_description):
    urlSuffix = '/ServerManage/AddSecret'
    payload = {"SecretName": secret_name, "SecretText": secret_text, "Type": secret_type,
               "FolderId": folderId, "Description": secret_description}
    centrify_secret_response = client.request_create_secret(url_suffix=urlSuffix, data=payload)
    if centrify_secret_response.get('success') is True:
        return "Secret Created", centrify_secret_response.get('Result')
    else:
        return centrify_secret_response.get("MessageID"), "No Secret ID"


"""Adds a secret to the set for the provided setid, secretid"""


def add_secret_set(client: Client, setId, secretId):
    urlSuffix = '/Collection/UpdateMembersCollection'
    payload = {"id": setId, "add": [{"MemberType": "Row", "Table": "DataVault", "Key": secretId}]}
    add_secretset_response = client.request_add_secret_set(url_suffix=urlSuffix, data=payload)
    if add_secretset_response.get('success') is True:
        return "Secret added to the set"
    else:
        return "Failed to add secret to the set"


"""deletes a folder from the vault for the provided folderid"""


def delete_folder(client: Client, folderId):
    urlSuffix = '/ServerManage/DeleteSecretsFolder'
    payload = {"ID": folderId}
    delete_folder_response = client.request_delete_folder(url_suffix=urlSuffix, data=payload)
    if delete_folder_response.get('success') is True:
        return "Folder Deleted"
    else:
        return "Failed to delete the folder"


"""deletes a set from the vault for the provided setid"""


def delete_set(client: Client, setId):
    urlSuffix = '/Collection/DeleteCollection'
    payload = {"ID": setId}
    delete_set_response = client.request_delete_set(url_suffix=urlSuffix, data=payload)
    if delete_set_response.get('success') is True:
        return "Set Deleted"
    else:
        return "Failed to delete the Set"


"""deletes a secret the vault for the provided secretid"""


def delete_secret(client: Client, secretId):
    urlSuffix = '/ServerManage/DeleteSecret'
    payload = {"ID": secretId}
    delete_secret_response = client.request_delete_secret(url_suffix=urlSuffix, data=payload)
    if delete_secret_response.get('success') is True:
        return "Secret Deleted"
    else:
        return "Failed to delete the Secret"


def fetch_secrets(args: dict, client: Client):
    try:
        holder_type = args.get('holderType')
        secret_name = args.get('secretName')
        secret_ids_list: list = []
        if holder_type == 'Set':
            set_name = args.get('holderName')
            setId = fetch_secret_set_id(client, set_name)
            if setId == 'set name not found':
                return_error("Set name not found. Please provide a valid set name")
            else:
                secret_ids_list = fetch_secretids_set(client, setId, secret_ids_list)
        elif holder_type == 'Folder':
            folder_name = args.get('holderName')
            if folder_name:
                folder_id = fetch_secret_folder_id(client, folder_name)
                secret_ids_list = fetch_secretids_folder(client, folder_id, secret_ids_list, True)
            else:
                folder_id = ""
                secret_ids_list = fetch_secretids_folder(client, folder_id, secret_ids_list, True)
        else:
            folder_id = ""
            secret_ids_list = fetch_secretids_folder(client, folder_id, secret_ids_list, True)
        secret_list = list()
        for secret_id in secret_ids_list:
            secret_list.append(fetch_secret(client, secret_id, secret_name, True))
        secret_list = list(filter(None, secret_list))
        return create_entry('Secrets in the Folder/Set', secret_list)
    except Exception as e:
        return_error("Wrong inputs: Please enter valid foldername/secretname/setname: ", e)


def fetch_secret_by_id(args: dict, client: Client):
    try:
        secret_id = args.get('secretId')
        secret_list: list = []
        secret_list.append(fetch_secret(client, secret_id, None, None))
        return create_entry('Secrets through the Secret ID', secret_list)
    except Exception as e:
        return_error("Wrong inputs: ", e)


def create_secret_folder(args: dict, client: Client):
    try:
        folder_name = args.get('folderName')
        parent_folder_name = args.get('parentFolderName')
        folder_description = args.get('folderDescription')
        if not folder_description:
            folder_description = ""
        if parent_folder_name:
            parent_folder_id = fetch_secret_folder_id(client, parent_folder_name)
        else:
            parent_folder_id = ""
        status, folder_id = create_folder(client, folder_name, folder_description, parent_folder_id)
        if status == "Folder Created":
            CENTRIFY_VAULT = {}
            CENTRIFY_VAULT['FolderName'] = folder_name
            CENTRIFY_VAULT['FolderID'] = folder_id
            CENTRIFY_VAULT['ParentFolderName'] = parent_folder_name
            if folder_description:
                CENTRIFY_VAULT['FolderDescription'] = folder_description
            else:
                CENTRIFY_VAULT['FolderDescription'] = ''
            fcreate = [CENTRIFY_VAULT]
            md = tableToMarkdown(status, fcreate, ['FolderName', 'FolderID', 'ParentFolderName', 'FolderDescription'])\
                if fcreate else 'No result were found'
            ec = {'Centrify.Folder(val.FolderName && val.FolderName == obj.FolderName && val.ParentFolderName &&'
                  ' val.ParentFolderName == obj.ParentFolderName)': fcreate}
            return {
                'ContentsFormat': formats['json'],
                'Type': entryTypes['note'],
                'Contents': fcreate,
                'ReadableContentsFormat': formats['markdown'],
                'HumanReadable': md,
                'EntryContext': ec
            }
        else:
            return 'No result were found: ' + status
    except Exception as e:
        return_error("Wrong inputs: ", e)


def create_vault_secret(args: dict, client: Client):
    try:
        holder_type = args.get('holderType')
        secret_name = args.get('secretName')
        secret_text = args.get('secretText')
        secret_type = args.get('secretType')
        secret_description = args.get('secretDescription')
        if not secret_description:
            secret_description = ""
        folder_id = ""
        if holder_type == 'Folder':
            folder_name = args.get('holderName')
            folder_id = fetch_secret_folder_id(client, folder_name)
        else:
            setId_list = list()
            set_name_list = list()
            if ';' in str(args.get('holderName')):
                set_name_list = str(args.get('holderName')).split(';')
                for set_item in set_name_list:
                    set_name = set_item
                    set_id = fetch_secret_set_id(client, set_name)
                    setId_list.append(set_id)
            else:
                set_name = str(args.get('holderName'))
                set_name_list.append(set_name)
                setId_list.append(fetch_secret_set_id(client, set_name))
            if 'set name not found' in setId_list:
                return_error("Set name not found. Please provide a valid set name")
        status, secret_id = create_secret(client, folder_id, secret_name, secret_text, secret_type, secret_description)
        if status == "Secret Created":
            CENTRIFY_VAULT = {}
            CENTRIFY_VAULT['holderType'] = holder_type
            if holder_type == 'Folder':
                CENTRIFY_VAULT['FolderName'] = folder_name
                CENTRIFY_VAULT['FolderID'] = folder_id
            else:
                CENTRIFY_VAULT['SetName'] = set_name_list
                CENTRIFY_VAULT['SetID'] = setId_list
                for set_id in setId_list:
                    add_secret_set(client, set_id, secret_id)
            CENTRIFY_VAULT['SecretName'] = secret_name
            CENTRIFY_VAULT['SecretID'] = secret_id
            CENTRIFY_VAULT['SecretType'] = secret_type
            CENTRIFY_VAULT['SecretDescription'] = secret_description
            screate = [CENTRIFY_VAULT]
            md = tableToMarkdown(status, screate,
                                 ['SecretName', 'FolderName', 'SetName', 'SecretType', 'SecretID', 'SecretDescription'])\
                if screate else 'No result were found'
            ec = {'Centrify.Secrets(val.SecretID && val.SecretID == obj.SecretID)': screate}
            return {
                'ContentsFormat': formats['json'],
                'Type': entryTypes['note'],
                'Contents': screate,
                'ReadableContentsFormat': formats['markdown'],
                'HumanReadable': md,
                'EntryContext': ec
            }
        else:
            return 'No result were found: ' + status
    except Exception as e:
        return_error("Wrong inputs. Please provide valid foldername/setname ", e)


def create_vault_set(args: dict, client: Client):
    try:
        set_name = args.get('setName')
        set_description = args.get('setDescription')
        if not set_description:
            set_description = ""
        status, set_id = create_set(client, set_name, set_description)
        if status == "Set Created":
            CENTRIFY_VAULT = {}
            CENTRIFY_VAULT['SetName'] = set_name
            CENTRIFY_VAULT['SetID'] = set_id
            if set_description:
                CENTRIFY_VAULT['SetDescription'] = set_description
            else:
                CENTRIFY_VAULT['SetDescription'] = ''
            set_create = [CENTRIFY_VAULT]
            md = tableToMarkdown(status, set_create, ['SetName', 'SetID', 'SetDescription']) \
                if set_create else 'No result were found'
            ec = {'Centrify.Set(val.SetID && val.SetID == obj.SetID)': set_create}
            return {
                'ContentsFormat': formats['json'],
                'Type': entryTypes['note'],
                'Contents': set_create,
                'ReadableContentsFormat': formats['markdown'],
                'HumanReadable': md,
                'EntryContext': ec
            }
        else:
            return 'No result were found: ' + status
    except Exception as e:
        return_error(e)


def fetch_vault_folders(args: dict, client: Client):
    try:
        folders_list: list = []
        folders_list = fetch_folderids(client, "", folders_list)
        if folders_list:
            md = tableToMarkdown("List of all folders", folders_list,
                                 ['FolderName', 'FolderID', 'ParentFolder', 'FolderDescription',
                                  'FolderDirectory']) if folders_list else 'No result were found'
            ec = {'Centrify.Folder(val.FolderID && val.FolderID == obj.FolderID)': folders_list}
            return {
                'ContentsFormat': formats['json'],
                'Type': entryTypes['note'],
                'Contents': folders_list,
                'ReadableContentsFormat': formats['markdown'],
                'HumanReadable': md,
                'EntryContext': ec
            }
        else:
            return 'No result were found: No folders found'
    except Exception as e:
        return_error(e)


def fetch_vault_set(args: dict, client: Client):
    try:
        set_details_list: list = []
        set_details_list = fetch_set_details(client, set_details_list)
        if set_details_list:
            md = tableToMarkdown("List of all sets", set_details_list, ['SetName', 'SetID', 'SetDescription'])\
                if set_details_list else 'No result were found'
            ec = {'Centrify.Set(val.SetID && val.SetID == obj.SetID)': set_details_list}
            return {
                'ContentsFormat': formats['json'],
                'Type': entryTypes['note'],
                'Contents': set_details_list,
                'ReadableContentsFormat': formats['markdown'],
                'HumanReadable': md,
                'EntryContext': ec
            }
        else:
            return 'No result were found: No sets found'
    except Exception as e:
        return_error(e)


def add_vault_secret_set(args: dict, client: Client):
    try:
        set_name = args.get('setName')
        secret_id = args.get('secretId')
        set_id = fetch_secret_set_id(client, set_name)
        if set_id == "set name not found":
            return_error("Set name not found. Please provide a valid set name")
        else:
            status = add_secret_set(client, set_id, secret_id)
            return status
    except Exception as e:
        return_error(e)


"""New code started"""


def delete_vault_secret(args: dict, client: Client):
    try:
        folder_name = args.get('folderName')
        secret_name = args.get('secretName')
        recursive_delete = args.get('recursiveDelete')
        regex_match = args.get('matchPartOfSecret')
        if regex_match == "Yes":
            regex_match = True
        else:
            regex_match = False
        if folder_name:
            folder_id = fetch_secret_folder_id(client, folder_name)
        else:
            folder_id = ""
        secret_ids_list: list = []
        if recursive_delete == "Yes":
            recursive_delete = True
        else:
            recursive_delete = False
        secret_ids_list = fetch_secretids_folder(client, folder_id, secret_ids_list, recursive_delete)
        delete_secret_id_list: list = []
        for secret_id in secret_ids_list:
            secret_item = fetch_secret(client, secret_id, secret_name, regex_match)
            if secret_item:
                delete_secret(client, secret_item.get('SecretID'))
                delete_secret_id_list.append(secret_item)
        if delete_secret_id_list:
            md = tableToMarkdown("List of Secrets deleted", delete_secret_id_list, ['SecretName', 'SecretID', 'FolderName'])\
                if delete_secret_id_list else 'No secrets were deleted'
            return {
                'ContentsFormat': formats['json'],
                'Type': entryTypes['note'],
                'Contents': delete_secret_id_list,
                'ReadableContentsFormat': formats['markdown'],
                'HumanReadable': md
            }
        else:
            return 'No result were found: No secrets were deleted'
    except Exception as e:
        return_error("Please enter a valid secretname/foldername: ", e)


def delete_vault_secretid(args: dict, client: Client):
    try:
        secret_id = args.get('secretId')
        delete_secret_id_list = list()
        delete_secret_id_list.append(fetch_secret(client, secret_id, None, None))
        delete_secret(client, secret_id)
        if delete_secret_id_list:
            md = tableToMarkdown("Secrets deleted", delete_secret_id_list, ['SecretName', 'SecretID', 'FolderName'])\
                if delete_secret_id_list else 'No secrets were deleted'
            return {
                'ContentsFormat': formats['json'],
                'Type': entryTypes['note'],
                'Contents': delete_secret_id_list,
                'ReadableContentsFormat': formats['markdown'],
                'HumanReadable': md
            }
        else:
            return 'No result were found: No secrets were deleted'
    except Exception as e:
        return_error("Please enter a valid secretname/foldername: ", e)


def delete_vault_folder(args: dict, client: Client):
    try:
        folder_name = args.get('folderName')
        parent_name = args.get('parentFolderName')
        if parent_name:
            folder_name = parent_name + "/" + folder_name
        folder_id = fetch_secret_folder_id(client, folder_name)
        delete_status = delete_folder(client, folder_id)
        if delete_status == "Folder Deleted":
            return str(folder_name) + " : " + str(delete_status)
        else:
            return 'No result were found: No folders found to be deleted'
    except Exception as e:
        return_error("Please enter a valid foldername: ", e)


def delete_vault_set(args: dict, client: Client):
    try:
        set_name = args.get('setName')
        set_id = fetch_secret_set_id(client, set_name)
        if set_id == "set name not found":
            return 'No result were found: Please enter a valid setname'
        else:
            delete_status = delete_set(client, set_id)
            if delete_status == "Set Deleted":
                return str(set_name) + " : " + str(delete_status)
            else:
                return 'No result were found: No sets found to be deleted'
    except Exception as e:
        return_error("Please enter a valid setname: ", e)


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    tenant_url = demisto.params().get('tenantUrl', '').rstrip('/')
    client_id = demisto.params().get('clientId')
    client_secret = demisto.params().get('clientSecret')
    scope = demisto.params().get('scope')
    app_id = demisto.params().get('appId')
    verify_certificate = demisto.params()['insecure'] is False
    proxy = demisto.params().get('proxy', False)

    payload = {'grant_type': 'client_credentials', 'client_id': client_id, 'client_secret': client_secret, 'scope': scope}

    try:
        client = Client(
            tenant_url,
            payload,
            app_id,
            verify_certificate,
            proxy)

        command = demisto.command()
        args = demisto.args()

        LOG(f'Command being called is {command}.')
        if command == 'test-module':
            result = test_module(client)

        elif demisto.command() == 'centrify-retrieve-secrets':
            result = fetch_secrets(args, client)

        elif demisto.command() == 'centrify-retrieve-secret-by-secretid':
            result = fetch_secret_by_id(args, client)

        elif demisto.command() == 'centrify-create-secretfolder':
            result = create_secret_folder(args, client)

        elif demisto.command() == 'centrify-create-secret':
            result = create_vault_secret(args, client)

        elif demisto.command() == 'centrify-create-set':
            result = create_vault_set(args, client)

        elif demisto.command() == 'centrify-retrieve-folders':
            result = fetch_vault_folders(args, client)

        elif demisto.command() == 'centrify-delete-folder':
            result = delete_vault_folder(args, client)

        elif demisto.command() == 'centrify-delete-secret':
            result = delete_vault_secret(args, client)

        elif demisto.command() == 'centrify-delete-secret-by-secretid':
            result = delete_vault_secretid(args, client)

        elif demisto.command() == 'centrify-add-secret-to-set':
            result = add_vault_secret_set(args, client)

        elif command == 'centrify-retrieve-sets':
            result = fetch_vault_set(args, client)

        elif demisto.command() == 'centrify-delete-set':
            result = delete_vault_set(args, client)

        demisto.results(result)

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', 'builtins'):
    main()
