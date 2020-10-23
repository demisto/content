import json

import demistomock as demisto  # noqa: F401
# IMPORTS
import requests
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
        headers = {
            'X-CENTRIFY-NATIVE-CLIENT': 'true'
        }
        super().__init__(base_url=token_retrieval_url, headers=headers, verify=use_ssl, proxy=proxy)
        self.payload = data
        self.app_id = app_id
        self.use_ssl = use_ssl
        # Trust environment settings for proxy configuration
        self.trust_env = proxy
        self.session = requests.Session()
        self.session.headers = headers
        if not proxy:
            self.session.trust_env = False

    def authenticate_oauth(self):
        """
        Login using the credentials and store the cookie
        """
        urlSuffix = '/oauth2/token/' + self.app_id
        response = self.http_request('POST', url_suffix=urlSuffix, full_url=self._base_url, data=self.payload)
        response_code = response.status_code
        response_json = json.loads(response.text)
        bearer_token = response_json["access_token"]
        return response_code, bearer_token

    def http_request(self, method: str, url_suffix: str = None, full_url: str = None, params: dict = None,
                     data: dict = None, headers: dict = None):
        """
        Generic request to Centrify
        """
        full_url = full_url if not url_suffix else f'{self._base_url}{url_suffix}'
        try:
            res = self.session.request(
                method,
                full_url,
                headers=self._headers,
                verify=self._verify,
                data=data,
                params=params
            )
            if not res.ok:
                raise ValueError(f'Error in API call to Centrify {res.status_code}. Reason: {res.text}')
            return res

        except requests.exceptions.ConnectTimeout as exception:
            err_msg = 'Connection Timeout Error - potential reasons might be that the Server URL parameter' \
                      ' is incorrect or that the Server is not accessible from your host.'
            raise DemistoException(err_msg, exception)

        except requests.exceptions.SSLError as exception:
            err_msg = 'SSL Certificate Verification Failed - try selecting \'Trust any certificate\' checkbox in' \
                      ' the integration configuration.'
            raise DemistoException(err_msg, exception)

        except requests.exceptions.ProxyError as exception:
            err_msg = 'Proxy Error - if the \'Use system proxy\' checkbox in the integration configuration is' \
                      ' selected, try clearing the checkbox.'
            raise DemistoException(err_msg, exception)

        except requests.exceptions.ConnectionError as exception:
            # Get originating Exception in Exception chain
            error_class = str(exception.__class__)
            err_type = '<' + error_class[error_class.find('\'') + 1: error_class.rfind('\'')] + '>'
            err_msg = f'\nError Type: {err_type}\nError Number: [{exception.errno}]\nMessage: {exception.strerror}\n ' \
                      f'Verify that the server URL parameter ' \
                      f'is correct and that you have access to the server from your host.'
            raise DemistoException(err_msg, exception)

        except Exception as exception:
            raise Exception(str(exception))


def raise_error(error):
    return {
        'Type': entryTypes['error'],
        'ContentsFormat': formats['text'],
        'Contents': str(error)
    }


"""Demisto Output Entry"""


def create_entry(title, data):
    md = tableToMarkdown(title, data, ['FolderName', 'SecretName', 'SecretText', 'SecretType',
                                       'SecretDescription']) if data else 'No result were found'
    if data:
        ec = {'Centrify.Secrets(val.SecretName===obj.SecretName and val.FolderName===obj.FolderName)': data}
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
        response_code, bearer_token = client.authenticate_oauth()
        if response_code == 200:
            # demisto.results('ok')
            return 'ok'
        else:
            return "Invalid client creds or client not allowed"
    except Exception as e:
        return "Invalid client creds or client not allowed"


def headers(bearer_token):
    headers = {
        'content-type': 'application/json',
        'Authorization': bearer_token,
        'X-CENTRIFY-NATIVE-CLIENT': 'true'
    }
    return headers


"""Fetches the Centrify set id for the setname provided"""


def fetch_secret_set_id(client: Client, setName, bearer_token):
    urlSuffix = '/Collection/GetObjectCollectionsAndFilters'
    #retrieve_set_id_url = TENANT_URL + '/Collection/GetObjectCollectionsAndFilters'
    payload = str({"ObjectType": "DataVault", "CollectionType": "ManualBucket"})
    client.session.headers = headers(bearer_token)
    centrify_setid_response = client.http_request(
        method="POST", full_url=client._base_url, url_suffix=urlSuffix, headers=client.session.headers, data=payload)
    centrify_setid_response_json = json.loads(centrify_setid_response.text)
    for set_item in centrify_setid_response_json['Result']['Results']:
        if set_item['Row']['Name'] == setName:
            return set_item['Row']['ID']
    return "set name not found"


"""Fetches the secret id's list for the setid provided"""


def fetch_secretids_set(client: Client, set_id, bearer_token, secret_ids_list):
    urlSuffix = '/Collection/GetMembers'
    #retrieve_secretids_url = TENANT_URL + '/Collection/GetMembers'
    payload = str({"ID": set_id})
    client.session.headers = headers(bearer_token)
    centrify_secretids_response = client.http_request(
        method="POST", full_url=client._base_url, url_suffix=urlSuffix, headers=client.session.headers, data=payload)
    centrify_secretids_response_json = json.loads(centrify_secretids_response.text)
    for secret_id_item in centrify_secretids_response_json["Result"]:
        secret_ids_list.append(secret_id_item['Key'])
    return secret_ids_list


"""Fetches the Centrify folder id for the foldername provided"""


def fetch_secret_folder_id(client: Client, folderName, bearer_token):
    urlSuffix = '/ServerManage/GetSecretFolder'
    #retrieve_folder_id_url = TENANT_URL + '/ServerManage/GetSecretFolder'
    payload = str({"Name": folderName})
    client.session.headers = headers(bearer_token)
    centrify_folderid_response = client.http_request(
        method="POST", full_url=client._base_url, url_suffix=urlSuffix, headers=client.session.headers, data=payload)
    centrify_folderid_response_json = json.loads(centrify_folderid_response.text)
    return centrify_folderid_response_json['Result']['Results'][0]['Row']['ID']


"""Fetches the secret id's list recurrsively for the folderid provided"""


def fetch_secretids_folder(client: Client, folder_id, bearer_token, secret_ids_list, recursive):
    urlSuffix = '/ServerManage/GetSecretsAndFolders'
    #retrieve_secretids_url = TENANT_URL + '/ServerManage/GetSecretsAndFolders'
    payload = str({"Parent": folder_id})
    client.session.headers = headers(bearer_token)
    centrify_secretids_response = client.http_request(
        method="POST", full_url=client._base_url, url_suffix=urlSuffix, headers=client.session.headers, data=payload)
    centrify_secretids_response_json = json.loads(centrify_secretids_response.text)
    secret_ids_count = centrify_secretids_response_json['Result']['FullCount']
    for secret_id_item in range(secret_ids_count):
        if centrify_secretids_response_json['Result']['Results'][secret_id_item]['Row']['Type'] == 'Text':
            secret_ids_list.append(centrify_secretids_response_json['Result']['Results'][secret_id_item]['Row']['ID'])
        else:
            if recursive:
                sub_folder_id = centrify_secretids_response_json['Result']['Results'][secret_id_item]['Row']['ID']
                fetch_secretids_folder(client, sub_folder_id, bearer_token, secret_ids_list, recursive)
            else:
                pass
    return secret_ids_list


"""Fetches details of all the sets in Centrify Vault"""


def fetch_set_details(client: Client, bearer_token, set_details_list):
    urlSuffix = '/Collection/GetObjectCollectionsAndFilters'
    payload = str({"ObjectType": "DataVault", "CollectionType": "ManualBucket"})
    client.session.headers = headers(bearer_token)
    centrify_setdetails_response = client.http_request(
        method="POST", full_url=client._base_url, url_suffix=urlSuffix, headers=client.session.headers, data=payload)
    centrify_setdetails_response_json = json.loads(centrify_setdetails_response.text)
    for set_item in centrify_setdetails_response_json['Result']['Results']:
        if 'Description' not in set_item['Row']:
            set_description = ""
        else:
            set_description = set_item['Row']['Description']
        set_details_list.append({'SetName': set_item['Row']['Name'],
                                 'SetID': set_item['Row']['ID'], 'SetDescription': set_description})
    return set_details_list


"""Fetches the centrify secret details for the secret response received through the fetch_secret() method"""


def centrify_secret_details(centrify_secret):
    CENTRIFY_VAULT = {}
    CENTRIFY_VAULT['FolderName'] = centrify_secret['Result']['ParentPath']
    CENTRIFY_VAULT['SecretName'] = centrify_secret['Result']['SecretName']
    CENTRIFY_VAULT['SecretID'] = centrify_secret['Result']['_RowKey']
    CENTRIFY_VAULT['SecretText'] = centrify_secret['Result']['SecretText']
    CENTRIFY_VAULT['SecretType'] = centrify_secret['Result']['Type']
    if 'Description' in centrify_secret['Result']:
        CENTRIFY_VAULT['SecretDescription'] = centrify_secret['Result']['Description']
    else:
        CENTRIFY_VAULT['SecretDescription'] = ''
    return CENTRIFY_VAULT


"""Fetches the centrify secret details for the secret id and name(optional) provided"""


def fetch_secret(client: Client, secret_id, bearer_token, secret_name, regex_match):
    urlSuffix = '/ServerManage/RetrieveDataVaultItemContents'
    #retrieve_secret_url = TENANT_URL + '/ServerManage/RetrieveDataVaultItemContents'
    payload = str({"ID": secret_id})
    client.session.headers = headers(bearer_token)
    centrify_secret_response = client.http_request(
        method="POST", full_url=client._base_url, url_suffix=urlSuffix, headers=client.session.headers, data=payload)
    centrify_secret_response_json = json.loads(centrify_secret_response.text)
    if secret_name:
        if regex_match:
            if re.search(secret_name, centrify_secret_response_json['Result']['SecretName'], re.IGNORECASE):
                CENTRIFY_VAULT = centrify_secret_details(centrify_secret_response_json)
            else:
                return None
        else:
            if secret_name == centrify_secret_response_json['Result']['SecretName']:
                CENTRIFY_VAULT = centrify_secret_details(centrify_secret_response_json)
            else:
                return None
    else:
        CENTRIFY_VAULT = centrify_secret_details(centrify_secret_response_json)
    return CENTRIFY_VAULT


"""Fetches details of all folders in list recurrsively"""


def fetch_folderids(client: Client, folder_id, bearer_token, folders_list):
    urlSuffix = '/ServerManage/GetSecretsAndFolders'
    #retrieve_folderids_url = TENANT_URL + '/ServerManage/GetSecretsAndFolders'
    payload = str({"Parent": folder_id})
    client.session.headers = headers(bearer_token)
    centrify_folderids_response = client.http_request(
        method="POST", full_url=client._base_url, url_suffix=urlSuffix, headers=client.session.headers, data=payload)
    centrify_folderids_response_json = json.loads(centrify_folderids_response.text)
    folder_ids_count = centrify_folderids_response_json['Result']['FullCount']
    for folder_id_item in range(folder_ids_count):
        if centrify_folderids_response_json['Result']['Results'][folder_id_item]['Row']['Type'] == 'Folder':
            folder_res = centrify_folderids_response_json['Result']['Results'][folder_id_item]['Row']
            if folder_res['ParentPath']:
                folder_directory = folder_res['ParentPath'] + "\\" + folder_res['Name']
            else:
                folder_directory = folder_res['Name']
            folders_list.append({"FolderName": folder_res['Name'], "FolderID": folder_res['ID'], "ParentFolder": folder_res['ParentPath'],
                                 "FolderDescription": folder_res['Description'], "FolderDirectory": folder_directory})
            sub_folder_id = folder_res['ID']
            fetch_folderids(client, sub_folder_id, bearer_token, folders_list)
        else:
            pass
    return folders_list


"""Creates a centrify folder for the foldername, description and parent foldername(optional) provided"""


def create_folder(client: Client, folderName, description, parent_id, bearer_token):
    urlSuffix = '/ServerManage/AddSecretsFolder'
    #create_folder_url = TENANT_URL + '/ServerManage/AddSecretsFolder'
    payload = str({"Name": folderName, "Description": description, "Parent": parent_id})
    client.session.headers = headers(bearer_token)
    centrify_folder_response = client.http_request(
        method="POST", full_url=client._base_url, url_suffix=urlSuffix, headers=client.session.headers, data=payload)
    centrify_folder_response_json = json.loads(centrify_folder_response.text)
    if centrify_folder_response.status_code == 200 and centrify_folder_response_json['success'] == True:
        return "Folder Created", centrify_folder_response_json['Result']
    else:
        return centrify_folder_response_json["MessageID"], "No Folder ID"


"""Creates a centrify set for the setname provided"""


def create_set(client: Client, setName, description, bearer_token):
    urlSuffix = '/Collection/CreateManualCollection'
    #create_set_url = TENANT_URL + '/Collection/CreateManualCollection'
    payload = str({"ObjectType": "DataVault", "Name": setName, "Description": description})
    client.session.headers = headers(bearer_token)
    centrify_set_response = client.http_request(method="POST", full_url=client._base_url,
                                                url_suffix=urlSuffix, headers=client.session.headers, data=payload)
    centrify_set_response_json = json.loads(centrify_set_response.text)
    if centrify_set_response.status_code == 200 and centrify_set_response_json['success'] == True:
        return "Set Created", centrify_set_response_json['Result']
    else:
        return centrify_set_response_json["Message"], "No Set ID"


"""Creates a centrify secret in the folder for the provided foldername, secrettext, secrettype"""


def create_secret(client: Client, folderId, secret_name, secret_text, secret_type, secret_description, bearer_token):
    urlSuffix = '/ServerManage/AddSecret'
    #create_secret_url = TENANT_URL + '/ServerManage/AddSecret'
    payload = str({"SecretName": secret_name, "SecretText": secret_text, "Type": secret_type,
                   "FolderId": folderId, "Description": secret_description})
    client.session.headers = headers(bearer_token)
    centrify_secret_response = client.http_request(
        method="POST", full_url=client._base_url, url_suffix=urlSuffix, headers=client.session.headers, data=payload)
    centrify_secret_response_json = json.loads(centrify_secret_response.text)
    if centrify_secret_response.status_code == 200 and centrify_secret_response_json['success'] == True:
        return "Secret Created", centrify_secret_response_json['Result']
    else:
        return centrify_secret_response_json["MessageID"], "No Secret ID"


"""Adds a secret to the set for the provided setid, secretid"""


def add_secret_set(client: Client, setId, secretId, bearer_token):
    urlSuffix = '/Collection/UpdateMembersCollection'
    #add_secretset_url = TENANT_URL + '/Collection/UpdateMembersCollection'
    payload = str({"id": setId, "add": [{"MemberType": "Row", "Table": "DataVault", "Key": secretId}]})
    client.session.headers = headers(bearer_token)
    add_secretset_response = client.http_request(method="POST", full_url=client._base_url,
                                                 url_suffix=urlSuffix, headers=client.session.headers, data=payload)
    add_secretset_response_json = json.loads(add_secretset_response.text)
    if add_secretset_response.status_code == 200 and add_secretset_response_json['success'] == True:
        return "Secret added to the set"
    else:
        return "Failed to add secret to the set"


"""deletes a folder from the vault for the provided folderid"""


def delete_folder(client: Client, folderId, bearer_token):
    urlSuffix = '/ServerManage/DeleteSecretsFolder'
    #delete_folder_url = TENANT_URL + '/ServerManage/DeleteSecretsFolder'
    payload = str({"ID": folderId})
    client.session.headers = headers(bearer_token)
    delete_folder_response = client.http_request(method="POST", full_url=client._base_url,
                                                 url_suffix=urlSuffix, headers=client.session.headers, data=payload)
    delete_folder_response_json = json.loads(delete_folder_response.text)
    if delete_folder_response.status_code == 200 and delete_folder_response_json['success'] == True:
        return "Folder Deleted"
    else:
        return "Failed to delete the folder"


"""deletes a set from the vault for the provided setid"""


def delete_set(client: Client, setId, bearer_token):
    urlSuffix = '/Collection/DeleteCollection'
    #delete_set_url = TENANT_URL + '/Collection/DeleteCollection'
    payload = str({"ID": setId})
    client.session.headers = headers(bearer_token)
    delete_set_response = client.http_request(method="POST", full_url=client._base_url,
                                              url_suffix=urlSuffix, headers=client.session.headers, data=payload)
    delete_set_response_json = json.loads(delete_set_response.text)
    if delete_set_response.status_code == 200 and delete_set_response_json['success'] == True:
        return "Set Deleted"
    else:
        return "Failed to delete the Set"


"""deletes a secret the vault for the provided secretid"""


def delete_secret(client: Client, secretId, bearer_token):
    urlSuffix = '/ServerManage/DeleteSecret'
    #delete_secret_url = TENANT_URL + '/ServerManage/DeleteSecret'
    payload = str({"ID": secretId})
    client.session.headers = headers(bearer_token)
    delete_secret_response = client.http_request(method="POST", full_url=client._base_url,
                                                 url_suffix=urlSuffix, headers=client.session.headers, data=payload)
    delete_secret_response_json = json.loads(delete_secret_response.text)
    if delete_secret_response.status_code == 200 and delete_secret_response_json['success'] == True:
        return "Secret Deleted"
    else:
        return "Failed to delete the Secret"


def fetch_secrets(args: dict, client: Client):
    try:
        response_code, bearer_token = client.authenticate_oauth()
        bearer_token = "Bearer " + bearer_token
        holder_type = args.get('holderType')
        secret_name = args.get('secretName')
        folder_id = ""
        secret_ids_list = list()
        if holder_type == 'Set':
            set_name = args.get('holderName')
            setId = fetch_secret_set_id(client, set_name, bearer_token)
            if setId == 'set name not found':
                return_error("Set name not found. Please provide a valid set name")
            else:
                secret_ids_list = fetch_secretids_set(client, setId, bearer_token, secret_ids_list)
        elif holder_type == 'Folder':
            folder_name = args.get('holderName')
            if folder_name:
                folder_id = fetch_secret_folder_id(client, folder_name, bearer_token)
                secret_ids_list = fetch_secretids_folder(client, folder_id, bearer_token, secret_ids_list, True)
            else:
                folder_id = ""
                secret_ids_list = fetch_secretids_folder(client, folder_id, bearer_token, secret_ids_list, True)
        else:
            folder_id = ""
            secret_ids_list = fetch_secretids_folder(client, folder_id, bearer_token, secret_ids_list, True)
        secret_list = list()
        for secret_id in secret_ids_list:
            secret_list.append(fetch_secret(client, secret_id, bearer_token, secret_name, True))
        secret_list = list(filter(None, secret_list))
        return create_entry('Secrets in the Folder/Set', secret_list)
    except Exception as e:
        return_error("Wrong inputs: Please enter valid foldername/secretname/setname")


def fetch_secret_by_id(args: dict, client: Client):
    try:
        response_code, bearer_token = client.authenticate_oauth()
        bearer_token = "Bearer " + bearer_token
        secret_id = args.get('secretId')
        secret_list = list()
        secret_list.append(fetch_secret(client, secret_id, bearer_token, None, None))
        return create_entry('Secrets through the Secret ID', secret_list)
    except Exception as e:
        return_error("Wrong inputs")


def create_secret_folder(args: dict, client: Client):
    try:
        response_code, bearer_token = client.authenticate_oauth()
        bearer_token = "Bearer " + bearer_token
        folder_name = args.get('folderName')
        parent_folder_name = args.get('parentFolderName')
        folder_description = args.get('folderDescription')
        if not folder_description:
            folder_description = ""
        if parent_folder_name:
            parent_folder_id = fetch_secret_folder_id(client, parent_folder_name, bearer_token)
        else:
            parent_folder_id = ""
        status, folder_id = create_folder(client, folder_name, folder_description, parent_folder_id, bearer_token)
        fcreate = list()
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
            md = tableToMarkdown(status, fcreate, ['FolderName', 'FolderID', 'ParentFolderName',
                                                   'FolderDescription']) if fcreate else 'No result were found'
            ec = {'Centrify.Folder(val.FolderName===obj.FolderName and val.ParentFolderName===obj.ParentFolderName)': fcreate}
            return {
                'ContentsFormat': formats['json'],
                'Type': entryTypes['note'],
                'Contents': fcreate,
                'ReadableContentsFormat': formats['markdown'],
                'HumanReadable': md,
                'EntryContext': ec
            }
        else:
            # print(status)
            return 'No result were found: ' + status
    except Exception as e:
        return_error("Wrong inputs")


def create_vault_secret(args: dict, client: Client):
    try:
        response_code, bearer_token = client.authenticate_oauth()
        bearer_token = "Bearer " + bearer_token
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
            folder_id = fetch_secret_folder_id(client, folder_name, bearer_token)
        else:
            setId_list = list()
            set_name_list = list()
            if ';' in args.get('holderName'):
                set_name_list = args.get('holderName').split(';')
                for set_item in set_name_list:
                    set_name = set_item
                    set_id = fetch_secret_set_id(client, set_name, bearer_token)
                    setId_list.append(set_id)
            else:
                set_name = args.get('holderName')
                set_name_list.append(set_name)
                setId_list.append(fetch_secret_set_id(client, set_name, bearer_token))
            if 'set name not found' in setId_list:
                return_error("Set name not found. Please provide a valid set name")
        status, secret_id = create_secret(client, folder_id, secret_name, secret_text,
                                          secret_type, secret_description, bearer_token)
        screate = list()
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
                    add_secret_set(client, set_id, secret_id, bearer_token)
            CENTRIFY_VAULT['SecretName'] = secret_name
            CENTRIFY_VAULT['SecretID'] = secret_id
            CENTRIFY_VAULT['SecretType'] = secret_type
            CENTRIFY_VAULT['SecretDescription'] = secret_description
            screate = [CENTRIFY_VAULT]
            md = tableToMarkdown(status, screate, ['SecretName', 'FolderName', 'SetName', 'SecretType',
                                                   'SecretID', 'SecretDescription']) if screate else 'No result were found'
            ec = {'Centrify.Secrets(val.SecretID===obj.SecretID)': screate}
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
        return_error("Wrong inputs. Please provide valid foldername/setname")


def create_vault_set(args: dict, client: Client):
    try:
        response_code, bearer_token = client.authenticate_oauth()
        bearer_token = "Bearer " + bearer_token
        set_name = args.get('setName')
        #parent_set = args.get('parentSet')
        set_description = args.get('setDescription')
        if not set_description:
            set_description = ""
        status, set_id = create_set(client, set_name, set_description, bearer_token)
        set_create = list()
        if status == "Set Created":
            CENTRIFY_VAULT = {}
            CENTRIFY_VAULT['SetName'] = set_name
            CENTRIFY_VAULT['SetID'] = set_id
            if set_description:
                CENTRIFY_VAULT['SetDescription'] = set_description
            else:
                CENTRIFY_VAULT['SetDescription'] = ''
            set_create = [CENTRIFY_VAULT]
            md = tableToMarkdown(status, set_create, ['SetName', 'SetID', 'SetDescription']
                                 ) if set_create else 'No result were found'
            ec = {'Centrify.Set(val.SetID===obj.SetID)': set_create}
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
        response_code, bearer_token = client.authenticate_oauth()
        bearer_token = "Bearer " + bearer_token
        folders_list = list()
        folders_list = fetch_folderids(client, "", bearer_token, folders_list)
        if folders_list:
            md = tableToMarkdown("List of all folders", folders_list, [
                                 'FolderName', 'FolderID', 'ParentFolder', 'FolderDescription', 'FolderDirectory']) if folders_list else 'No result were found'
            ec = {'Centrify.Folder(val.FolderID===obj.FolderID)': folders_list}
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
        response_code, bearer_token = client.authenticate_oauth()
        bearer_token = "Bearer " + bearer_token
        set_details_list = list()
        set_details_list = fetch_set_details(client, bearer_token, set_details_list)
        if set_details_list:
            md = tableToMarkdown("List of all sets", set_details_list, [
                                 'SetName', 'SetID', 'SetDescription']) if set_details_list else 'No result were found'
            ec = {'Centrify.Set(val.SetID===obj.SetID)': set_details_list}
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
        response_code, bearer_token = client.authenticate_oauth()
        bearer_token = "Bearer " + bearer_token
        set_name = args.get('setName')
        secret_id = args.get('secretId')
        #parent_set = args.get('parentSet')
        set_id = fetch_secret_set_id(client, set_name, bearer_token)
        if set_id == "set name not found":
            return_error("Set name not found. Please provide a valid set name")
        else:
            status = add_secret_set(client, set_id, secret_id, bearer_token)
            return status
    except Exception as e:
        return_error(e)


def delete_vault_secret(args: dict, client: Client):
    try:
        response_code, bearer_token = client.authenticate_oauth()
        bearer_token = "Bearer " + bearer_token
        folder_name = args.get('folderName')
        secret_name = args.get('secretName')
        recursive_delete = args.get('recursiveDelete')
        regex_match = args.get('matchPartOfSecret')
        if regex_match == "Yes":
            regex_match = True
        else:
            regex_match = False
        if folder_name:
            folder_id = fetch_secret_folder_id(client, folder_name, bearer_token)
        else:
            folder_id = ""
        secret_ids_list = list()
        if recursive_delete == "Yes":
            recursive_delete = True
        else:
            recursive_delete = False
        secret_ids_list = fetch_secretids_folder(client, folder_id, bearer_token, secret_ids_list, recursive_delete)
        delete_secret_id_list = list()
        for secret_id in secret_ids_list:
            secret_item = fetch_secret(client, secret_id, bearer_token, secret_name, regex_match)
            if secret_item:
                delete_secret(client, secret_item['SecretID'], bearer_token)
                delete_secret_id_list.append(secret_item)
        if delete_secret_id_list:
            md = tableToMarkdown("List of Secrets deleted", delete_secret_id_list, [
                                 'SecretName', 'SecretID', 'FolderName']) if delete_secret_id_list else 'No secrets were deleted'
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
        return_error("Please enter a valid secretname/foldername")


def delete_vault_secretid(args: dict, client: Client):
    try:
        response_code, bearer_token = client.authenticate_oauth()
        bearer_token = "Bearer " + bearer_token
        secret_id = args.get('secretId')
        delete_secret_id_list = list()
        delete_secret_id_list.append(fetch_secret(client, secret_id, bearer_token, None, None))
        delete_secret(client, secret_id, bearer_token)
        if delete_secret_id_list:
            md = tableToMarkdown("Secrets deleted", delete_secret_id_list, [
                                 'SecretName', 'SecretID', 'FolderName']) if delete_secret_id_list else 'No secrets were deleted'
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
        return_error("Please enter a valid secretname/foldername")


def delete_vault_folder(args: dict, client: Client):
    try:
        response_code, bearer_token = client.authenticate_oauth()
        bearer_token = "Bearer " + bearer_token
        folder_name = args.get('folderName')
        parent_name = args.get('parentFolderName')
        if parent_name:
            folder_name = parent_name + "/" + folder_name
        folder_id = fetch_secret_folder_id(client, folder_name, bearer_token)
        delete_status = delete_folder(client, folder_id, bearer_token)
        if delete_status == "Folder Deleted":
            return folder_name + " : " + delete_status
        else:
            return 'No result were found: No folders found to be deleted'
    except Exception as e:
        return_error("Please enter a valid foldername")


def delete_vault_set(args: dict, client: Client):
    try:
        response_code, bearer_token = client.authenticate_oauth()
        bearer_token = "Bearer " + bearer_token
        set_name = args.get('setName')
        set_id = fetch_secret_set_id(client, set_name, bearer_token)
        if set_id == "set name not found":
            return 'No result were found: Please enter a valid setname'
        else:
            delete_status = delete_set(client, set_id, bearer_token)
            if delete_status == "Set Deleted":
                return set_name + " : " + delete_status
            else:
                return 'No result were found: No sets found to be deleted'
    except Exception as e:
        return_error("Please enter a valid setname")


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    tenant_url = demisto.params().get('tenantUrl')
    client_id = demisto.params().get('clientId')
    client_secret = demisto.params().get('clientSecret')
    scope = demisto.params().get('scope')
    app_id = demisto.params().get('appId')
    #verify_certificate = not demisto.params().get('insecure', False)
    verify_certificate = demisto.params()['insecure'] is False
    proxy = demisto.params().get('proxy', False)

    if tenant_url[-1] == '/':
        tenant_url = tenant_url[:-1]

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
        sys.exit(0)

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', 'builtins'):
    main()
