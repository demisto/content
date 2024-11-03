import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from googleapiclient.discovery import build
from httplib2 import Http
import json
from oauth2client import service_account
from google.oauth2 import service_account as google_service_account
import googleapiclient.http
from googleapiclient._auth import authorized_http
import dateparser  # type: ignore
import io
import os

#  @@@@@@@@ GLOBALS @@@@@@@@

# If modifying these scopes, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/ediscovery', 'https://www.googleapis.com/auth/devstorage.full_control']
DEMISTO_MATTER = 'test_search_phishing'

ADMIN_EMAIL = demisto.params()['gsuite_credentials']['identifier']
PRIVATE_KEY_CONTENT = (
    demisto.params().get('auth_json_creds', {}).get('password')
    or demisto.params().get('auth_json'))
USE_SSL = not demisto.params().get('insecure', False)


# @@@@@@@@ HELPER FUNCS @@@@@@@@
def validate_input_values(arguments_values_to_verify, available_values):
    for value in arguments_values_to_verify:
        if value not in available_values:
            return_error(
                'Argument: \'{}\' is not one of the possible values: {}'.format(value, ', '.join(available_values)))


def get_credentials(additional_scopes=None, delegated_user=ADMIN_EMAIL):
    """Gets valid user credentials from storage.
    If nothing has been stored, or if the stored credentials are invalid,
    the OAuth2 flow is completed to obtain the new credentials.
    Returns:
        Credentials, the obtained credential.
    """
    if delegated_user == 'me':
        delegated_user = ADMIN_EMAIL
    scopes = SCOPES
    if additional_scopes is not None:
        scopes += additional_scopes
    try:
        json_keyfile = json.loads(PRIVATE_KEY_CONTENT)
        if not isinstance(json_keyfile, dict):
            json_keyfile = json.loads(json_keyfile)
        cred = service_account.ServiceAccountCredentials.from_json_keyfile_dict(json_keyfile,
                                                                                scopes=scopes)
        delegated_creds = cred.create_delegated(delegated_user)
    except Exception as e:
        LOG('An error occurred in the \'get_credentials\' function.')
        err_msg = 'An error occurred while trying to construct an OAuth2 ' \
                  f'ServiceAccountCredentials object - {str(e)}'
        return_error(err_msg)
    return delegated_creds


def connect():
    creds = get_credentials()
    try:
        service = build('vault', 'v1', http=creds.authorize(Http(disable_ssl_certificate_validation=(not USE_SSL))))
    except Exception as e:
        LOG('There was an error creating the Vault service in the \'connect\' function.')
        err_msg = f'There was an error creating the Vault service - {str(e)}'
        return_error(err_msg)
    return service


def is_matter_exist(service, matter_name):  # Not needed at the moment
    """
    Searches for existence of a matter by its name
    Note - this is case-sensitive
    :param service: Vault service object
    :param matter_name: name of the matter to be searched
    :return: True if exists, False otherwise.
    """
    existing_matters = get_open_matters(service)
    if any(matter_name == matter['name'] for matter in existing_matters):
        return True
    return False


def get_open_matters(service):
    """ Gets first 10 matters """
    open_matters = service.matters().list(state='OPEN').execute()
    return open_matters


def get_matter_by_id(service, matter_id):
    matter = service.matters().get(matterId=matter_id).execute()
    return matter


def get_matters_by_state(service, state, first_page_only=False):
    state = state.upper()
    matter_state = state if state in ('OPEN', 'CLOSED', 'DELETED') else 'STATE_UNSPECIFIED'

    request = service.matters().list(state=matter_state)
    response = request.execute()
    matter_list_results = response['matters']

    if not first_page_only:
        while response.get('nextPageToken'):
            request = service.matters().list_next(request, response)
            response = request.execute()

            for matter in response['matters']:
                matter_list_results.append(matter)

    return matter_list_results


def delete_matter(service, matter_id):
    _ = service.matters().delete(matterId=matter_id).execute()
    return get_matter_by_id(service, matter_id)  # Note - this is different that the other state updates


def close_matter(service, matter_id):
    close_response = service.matters().close(matterId=matter_id, body={}).execute()
    return close_response['matter']


def reopen_matter(service, matter_id):
    reopen_response = service.matters().reopen(matterId=matter_id, body={}).execute()
    return reopen_response['matter']


def undelete_matter(service, matter_id):
    undeleted_matter = service.matters().undelete(matterId=matter_id, body={}).execute()
    return undeleted_matter


def add_held_account(service, matter_id, hold_id, account_id):
    held_account = {'accountId': account_id}
    return service.matters().holds().accounts().create(matterId=matter_id, holdId=hold_id, body=held_account).execute()


def remove_held_account(service, matter_id, hold_id, account_id):
    return service.matters().holds().accounts().delete(matterId=matter_id, holdId=hold_id,
                                                       accountId=account_id).execute()


def remove_hold(service, matter_id, hold_id):
    return service.matters().holds().delete(matterId=matter_id, holdId=hold_id).execute()


def list_holds(service, matter_id):
    """
     Return a list of existing holds
    """
    done_paginating = False
    response = service.matters().holds().list(matterId=matter_id).execute()
    # append first page:
    the_holds = response['holds']
    # Keep paginating and appending:
    while not done_paginating:
        if 'nextPageToken' in response:
            response = service.matters().holds.list(pageSize=10, pageToken=response['nextPageToken']).execute()
            the_holds.extend(response['holds'])
        else:
            done_paginating = True
    return the_holds


def timeframe_to_utc_zulu_range(timeframe_str):
    """
    Converts a time-frame to UTC Zulu format that can be used for startTime and endTime in various Google Vault requests.
    """
    try:
        parsed_str = dateparser.parse(timeframe_str)
        end_time = datetime.utcnow().isoformat() + 'Z'  # Current time
        start_time = parsed_str.isoformat() + 'Z'  # type: ignore
        return (start_time, end_time)
    except Exception as ex:
        err_msg = str(ex)
        if 'Quota exceeded for quota metric' in err_msg:
            err_msg = 'Quota for Google Vault API exceeded'
            return_error(f'Unable to parse date correctly: {err_msg}')
        else:
            raise ex


def create_hold_query(hold_name, corpus, accounts, terms, time_frame="", start_time="", end_time=""):
    """
    Creates the query that will be used to request the creation of a new hold. Returns the ready-to-be-sent request.
    """
    # --- Sanitizing Input ---
    corpus = corpus.upper()
    if time_frame:
        start_time, end_time = timeframe_to_utc_zulu_range(time_frame)  # Making it UTC Zulu format
    elif start_time and not end_time:
        end_time = datetime.utcnow().isoformat() + 'Z'  # End time will be now, if no end time was given
    if isinstance(accounts, str):
        accounts = accounts.split(',')

    # --- Building Request ---
    request = {}
    mail_query = {}  # type: Dict[Any, Any]
    accounts_for_query = []
    if not terms:
        if start_time and end_time:
            mail_query = {'startTime': start_time, 'endTime': end_time}
    else:
        if start_time and end_time:
            mail_query = {'startTime': start_time, 'endTime': end_time, 'terms': terms}

    # --- Building all small parts into big request object ---
    request['name'] = hold_name
    request['corpus'] = corpus
    if mail_query:
        request['query'] = {'mailQuery': mail_query}  # Adding the ready mail query
    for acc_id in accounts:
        acc_entry = {'accountId': acc_id} if '@' not in acc_id else {'email': acc_id}
        accounts_for_query.append(acc_entry)
    request['accounts'] = accounts_for_query
    return request


def create_hold_mail_accounts(service, matter_id, request_body):
    """
    Creates a hold in Google Vault
    """
    return service.matters().holds().create(matterId=matter_id, body=request_body).execute()


def create_export(service, matter, request_body):
    """
    Creates an export in the given matter, with the given request_body (which is the actual JSON for the request).
    """
    return service.matters().exports().create(matterId=matter, body=request_body).execute()


def create_mail_export_query(export_name, emails, time_frame, start_time, end_time, terms, org_unit="",
                             export_pst='True', export_mbox='False', search_method='All Accounts',
                             include_drafts='True', data_scope='All Data'):
    """
    Creates the query that will be used in the request to create a mail export
    """
    org_unit_id = org_unit
    # --- Sanitizing Input ---
    exclude_drafts = 'false'
    if time_frame:
        start_time, end_time = timeframe_to_utc_zulu_range(time_frame)  # Making it UTC Zulu format
    elif start_time and not end_time:
        end_time = datetime.utcnow().isoformat() + 'Z'  # End time will be now, if no end time was given
    if isinstance(emails, str):
        emails = emails.split(',') if ',' in emails else [emails]
    if str(include_drafts).upper() == 'FALSE':
        exclude_drafts = 'true'
    if data_scope.upper() == 'HELD DATA':
        data_scope = 'HELD_DATA'
    if data_scope.upper() == 'ALL DATA':
        data_scope = 'ALL_DATA'
    if data_scope.upper() == 'UNPROCESSED DATA':
        data_scope = 'UNPROCESSED_DATA'
    if search_method.upper() == 'ORGANIZATIONAL UNIT(REQUIRES OU ARGUMENT)':
        search_method = 'ORG_UNIT'
    if search_method.upper() == 'ALL ACCOUNTS':
        search_method = 'ENTIRE_ORG'
    if search_method.upper() == 'SPECIFIC ACCOUNTS(REQUIRES EMAILS ARGUMENT)':
        search_method = 'ACCOUNT'

    # --- Building Request ---
    request = {}
    query = {}
    emails_for_query = []
    account_info = {'emails': []}  # type: Dict[Any, Any]
    org_unit_info = {'orgUnitId': org_unit_id}
    corpus = 'MAIL'
    export_format = 'PST'  # Default
    if export_mbox.upper() == 'TRUE':
        export_format = 'MBOX'
    mail_options = {
        'exportFormat': export_format
    }

    # --- Building all small parts into big request object ---
    query['dataScope'] = data_scope
    query['searchMethod'] = search_method
    query['corpus'] = corpus
    query['mailOptions'] = {'excludeDrafts': exclude_drafts}
    if start_time and end_time:
        query['startTime'] = start_time
        query['endTime'] = end_time
    if terms:
        query['terms'] = terms
    if emails:  # If user specified emails
        for email in emails:  # Go over all of them
            emails_for_query.append(email)  # Add them to the list
        account_info['emails'] = emails_for_query  # Add the list to the account_info dictionary
        query['accountInfo'] = account_info  # Add the account_info dictionary into the query object
    if search_method == 'ORG_UNIT':
        query['orgUnitInfo'] = org_unit_info
    request['query'] = query  # Adding query AFTER IT'S COMPLETED
    request['exportOptions'] = {'mailOptions': mail_options}
    request['name'] = export_name
    return request


def create_drive_export_query(export_name, emails, team_drives, time_frame, start_time, end_time, terms, org_unit="",
                              search_method='Specific Accounts(requires emails argument)', include_teamdrives='True',
                              data_scope='All Data'):
    """
    Creates the query that will be used in the request to create a groups export
    """
    org_unit_id = org_unit
    # --- Sanitizing Input ---
    include_teamdrives = 'true'
    if time_frame:
        start_time, end_time = timeframe_to_utc_zulu_range(time_frame)  # Making it UTC Zulu format
    elif start_time and not end_time:
        end_time = datetime.utcnow().isoformat() + 'Z'  # End time will be now, if no end time was given
    if isinstance(emails, str):  # If emails were specified, making it a list:
        emails = emails.split(',') if ',' in emails else [emails]
    if isinstance(team_drives, str):  # If team_drives were specified, making it a list:
        team_drives = team_drives.split(',') if ',' in team_drives else [team_drives]
    if str(include_teamdrives).upper() == 'FALSE':
        include_teamdrives = 'false'
    if data_scope.upper() == 'HELD DATA':
        data_scope = 'HELD_DATA'
    if data_scope.upper() == 'ALL DATA':
        data_scope = 'ALL_DATA'
    if data_scope.upper() == 'UNPROCESSED DATA':
        data_scope = 'UNPROCESSED_DATA'
    if search_method.upper() == 'ORGANIZATIONAL UNIT(REQUIRES OU ARGUMENT)':
        search_method = 'ORG_UNIT'
    if search_method.upper() == 'SPECIFIC ACCOUNTS(REQUIRES EMAILS ARGUMENT)':
        search_method = 'ACCOUNT'
    if search_method.upper() == 'TEAM DRIVE':
        search_method = 'TEAM_DRIVE'

    # --- Building Request ---
    request = {}
    query = {}
    emails_for_query = []
    teamdrives_for_query = []
    account_info = {'emails': []}  # type: Dict[Any, Any]
    teamdrive_info = {'teamDriveIds': []}  # type: Dict[Any, Any]
    org_unit_info = {'orgUnitId': org_unit_id}
    corpus = 'DRIVE'

    # --- Building all small parts into big request object ---
    query['dataScope'] = data_scope
    query['searchMethod'] = search_method
    query['corpus'] = corpus
    query['driveOptions'] = {'includeTeamDrives': include_teamdrives}
    if start_time and end_time:
        query['startTime'] = start_time
        query['endTime'] = end_time
    if terms:
        query['terms'] = terms
    if emails:  # If user specified emails
        for email in emails:  # Go over all of them
            emails_for_query.append(email)  # Add them to the list
        account_info['emails'] = emails_for_query  # Add the list to the account_info dictionary
    if team_drives and include_teamdrives.upper() == 'TRUE':  # If user specified team_drives and not emails
        for teamdrive_id in team_drives:
            teamdrives_for_query.append(teamdrive_id)
        teamdrive_info['teamDriveIds'] = teamdrives_for_query
    if search_method == 'ORG_UNIT':
        query['orgUnitInfo'] = org_unit_info
    if search_method == 'TEAM_DRIVE':
        query['teamDriveInfo'] = teamdrive_info
    if search_method == 'ACCOUNT':
        # Add the account_info dictionary into the query object.
        # This line SHOULD NOT exist if the user wants to use team_drives.
        query['accountInfo'] = account_info
    request['query'] = query  # Adding query AFTER IT'S COMPLETED
    request['name'] = export_name
    return request


def create_groups_export_query(export_name, emails, time_frame, start_time, end_time, terms, search_method,
                               export_pst='True', export_mbox='False', data_scope='All Data'):
    """
    Creates the query that will be used in the request to create a groups export
    """
    # --- Sanitizing Input ---
    if time_frame:
        start_time, end_time = timeframe_to_utc_zulu_range(time_frame)  # Making it UTC Zulu format
    elif start_time and not end_time:
        end_time = datetime.utcnow().isoformat() + 'Z'  # End time will be now, if no end time was given
    if isinstance(emails, str):
        emails = emails.split(',') if ',' in emails else [emails]
    if data_scope.upper() == 'HELD DATA':
        data_scope = 'HELD_DATA'
    if data_scope.upper() == 'ALL DATA':
        data_scope = 'ALL_DATA'
    if data_scope.upper() == 'UNPROCESSED DATA':
        data_scope = 'UNPROCESSED_DATA'

    # --- Building Request ---
    request = {}
    query = {}
    emails_for_query = []
    account_info = {'emails': []}  # type: Dict[Any, Any]
    corpus = 'GROUPS'
    export_format = 'PST'  # Default
    if export_mbox.upper() == 'TRUE':
        export_format = 'MBOX'
    groups_options = {
        'exportFormat': export_format
    }

    # --- Building all small parts into big request object ---
    query['dataScope'] = data_scope
    query['searchMethod'] = search_method
    query['corpus'] = corpus
    if start_time and end_time:
        query['startTime'] = start_time
        query['endTime'] = end_time
    if terms:
        query['terms'] = terms
    if emails:  # If user specified emails
        for email in emails:  # Go over all of them
            emails_for_query.append(email)  # Add them to the list
        account_info['emails'] = emails_for_query  # Add the list to the account_info dictionary
        query['accountInfo'] = account_info  # Add the account_info dictionary into the query object
    request['query'] = query  # Adding query AFTER IT'S COMPLETED
    request['exportOptions'] = {'groupsOptions': groups_options}
    request['name'] = export_name
    return request


def get_export_by_id(service, matter_id, export_id):
    return service.matters().exports().get(matterId=matter_id, exportId=export_id).execute()


def list_held_accounts(service, matter_id, hold_id):
    return service.matters().holds().accounts().list(matterId=matter_id, holdId=hold_id).execute()['accounts']


def remove_held_accounts(service, matter_id, hold_id):
    pass


def download_storage_object(object_ID, bucket_name):
    service = connect_to_storage()
    req = service.objects().get_media(bucket=bucket_name, object=object_ID)  # pylint: disable=no-member
    out_file = io.BytesIO()
    downloader = googleapiclient.http.MediaIoBaseDownload(out_file, req)
    done = False
    while not done:
        done = downloader.next_chunk()[1]
    return out_file


def get_storage_credentials():
    try:
        privateKeyJson = json.loads(PRIVATE_KEY_CONTENT)
        if not isinstance(privateKeyJson, dict):
            privateKeyJson = json.loads(privateKeyJson)
        crads = google_service_account.Credentials.from_service_account_info(privateKeyJson, scopes=SCOPES,
                                                                             subject=ADMIN_EMAIL)
    except Exception as e:
        LOG('An error occurred in the \'get_storage_credentials\' function.')
        err_msg = 'An error occurred while trying to construct an OAuth2 ' \
                  f'Storage Credentials object - {str(e)}'
        return_error(err_msg)
    return crads


def connect_to_storage():
    try:
        creds = get_storage_credentials()
        ptth = authorized_http(creds)
        ptth.disable_ssl_certificate_validation = (not USE_SSL)
        service = build('storage', 'v1', http=ptth)
    except Exception as e:
        LOG('There was an error creating the Storage service in the \'connect_to_storage\' function.')
        err_msg = f'There was an error creating the Storage service - {str(e)}'
        return_error(err_msg)
    return service


def get_object_mame_by_type(objectsArr, extension):
    for file in objectsArr:
        objName = str(file.get('objectName'))
        if (objName.endswith(extension)):
            return objName
    return None


def build_key_val_pair(tagDict):
    demisto.info('this is value: ')
    demisto.info(tagDict['@TagName'])
    demisto.info('this is key: ')
    demisto.info(tagDict['@TagValue'])

    key = filter(str.isalnum, str(tagDict['@TagName']))
    value = tagDict['@TagValue'].encode('utf-8')
    keyValPair = {key: value}
    return keyValPair


def build_document_dict(document):
    file_info = document['Files']['File']['ExternalFile']
    newDocumentDict = {
        'DocType': os.path.splitext(file_info['@FileName'])[1][1:].strip().lower(),
        'MD5': file_info['@Hash']
    }
    tags = document['Tags']['Tag']
    for currentTagDict in tags:
        newDocumentDict.update(build_key_val_pair(currentTagDict))
    return newDocumentDict


def build_dict_list(documentsArr):
    documentsDictList = []
    for document in documentsArr:
        currentDocumentDict = build_document_dict(document)
        documentsDictList.append(currentDocumentDict)

    return documentsDictList


def get_current_matter_from_context(matter_id):
    context_matter = demisto.dt(demisto.context(), f'GoogleVault.Matter(val.MatterID === "{matter_id}")')

    context_matter = context_matter[0] if type(context_matter) is list else context_matter

    if not context_matter:
        context_matter = {
            'MatterID': matter_id,
            'Export': []
        }
    return context_matter


def populate_matter_with_export(current_matter, current_export):
    # add new export to matter

    exports = current_matter.get('Export', [])
    if type(exports) is dict:
        exports = [exports]

    # remove duplicate export after new updated exports were entered
    filtered_export = [export for export in exports if export['ExportID'] != current_export['ExportID']]
    filtered_export.append(current_export)
    current_matter['Export'] = filtered_export

    return current_matter


# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ ACTUAL FUNCS @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
# @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@


def list_matters_command():
    """
    Lists all matters in the project, with their corresponding state.
    """
    try:
        service = connect()
        state = demisto.args().get('state', 'STATE_UNSPECIFIED')
        validate_input_values([state], ['All', 'Open', 'Closed', 'Deleted', 'STATE_UNSPECIFIED', ''])
        matters = (get_matters_by_state(service, state))

        if not matters:
            demisto.results('No matters found.')
        else:
            output = []
            context_output = []
            for matter in matters:
                output.append({
                    'Matter Name': matter.get('name'),
                    'Matter ID': matter.get('matterId'),
                    'Matter State': matter.get('state')
                })
                context_output.append({
                    'Name': matter.get('name'),
                    'MatterID': matter.get('matterId'),
                    'State': matter.get('state')  # Getting new state
                })
            markdown = ''  # Use this to add extra line
            title = ""
            title = 'Here are all your matters' if state == 'All' or not state else f'Here are your {state.lower()} matters'
            markdown += tableToMarkdown(title, output, ['Matter Name', 'Matter ID', 'Matter State'])

            demisto.results({
                'Type': entryTypes['note'],
                'ContentsFormat': formats['json'],
                'Contents': matters,
                'HumanReadable': markdown,
                'EntryContext': {
                    'GoogleVault.Matter(val.MatterID === obj.MatterID)': context_output
                }
            })
    except Exception as ex:
        err_msg = str(ex)
        if 'Quota exceeded for quota metric' in err_msg:
            err_msg = 'Quota for Google Vault API exceeded'
            return_error(f'Unable to list matters. Error: {err_msg}')
        else:
            raise ex


def create_matter_command():
    try:
        service = connect()
        matter_name = demisto.getArg('name')
        matter_description = demisto.getArg('description')
        matter_content = {
            'name': matter_name,
            'description': matter_description,
        }
        matter = service.matters().create(body=matter_content).execute()  # pylint: disable=no-member
        markdown = ""
        if matter_description:
            markdown = 'Matter: {} was created successfully with description: {}.\nID: {}.'.format(matter_name,
                                                                                                   matter_description,
                                                                                                   matter.get(
                                                                                                       'matterId'))
        else:
            markdown = 'Matter: {} was created successfully without a description.\nID: {}.'.format(matter_name,
                                                                                                    matter.get(
                                                                                                        'matterId'))
        title = 'Matter creation successful.'
        markdown_matter = []
        markdown_matter.append({
            'Matter Name': matter.get('name'),
            'Matter ID': matter.get('matterId'),
            'Matter State': matter.get('state')
        })
        markdown += tableToMarkdown(title, markdown_matter, ['Matter Name', 'Matter ID',
                                                             'Matter State'])  # Why is the title displayed in a weird way?

        output_context = []
        output_context.append({
            'Name': matter.get('name'),
            'MatterID': matter.get('matterId'),
            'State': matter.get('state')
        })

        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': matter,
            'HumanReadable': markdown,
            'EntryContext': {
                'GoogleVault.Matter(val.MatterID === obj.MatterID)': output_context
            }
        })
    except Exception as ex:
        err_msg = str(ex)
        if 'Quota exceeded for quota metric' in err_msg:
            err_msg = 'Quota for Google Vault API exceeded'
            return_error(f'Unable to create matter. Error: {err_msg}')
        else:
            raise ex


def update_matter_state_command():
    """
    * Note: This updates context only if a change in the current state was successful
    """
    try:
        service = connect()
        matter_id = demisto.getArg('matterID')
        wanted_state = demisto.getArg('state')

        validate_input_values([wanted_state], ['CLOSE', 'DELETE', 'REOPEN', 'UNDELETE'])
        matter_found = get_matter_by_id(service, matter_id)
        current_state = matter_found.get('state')

        if current_state:  # if a matter was found with that ID:
            context_output = []
            result_of_update = ""
            # Dealing with CLOSE:
            if wanted_state == 'CLOSE':
                if current_state == 'DELETED':
                    result_of_update = 'Matter is deleted and so it cannot be closed. It is possible to re-open it ' \
                                       'and then close.'
                elif current_state == 'CLOSED':
                    demisto.results('Matter is already closed.')
                elif current_state == 'OPEN':
                    try:
                        close_response = close_matter(service, matter_id)
                        result_of_update = 'Matter was successfully closed.'
                    except Exception as ex:
                        if 'Matters have users on hold' in str(ex):
                            demisto.debug(f'{ex}')
                            return_error('The matter has holds that prevent it from being closed.')
                        elif 'Quota exceeded for quota metric' in str(ex):
                            return_error('Quota for Google Vault API exceeded')
                        else:
                            raise ex

            # Dealing with DELETE:
            elif wanted_state == 'DELETE':
                if current_state == 'OPEN':
                    try:
                        # Todo: check if contains holds. If it does, return error to user
                        close_response = close_matter(service, matter_id)  # noqa: F841
                        _ = delete_matter(service, matter_id)
                        result_of_update = f'Matter was {current_state} and is now DELETED.'
                    except Exception as ex:
                        if 'Matters have users on hold' in str(ex):
                            demisto.debug(f'{ex}')
                            return_error('The matter has holds that prevent it from being deleted.')
                        elif 'Quota exceeded for quota metric' in str(ex):
                            return_error('Quota for Google Vault API exceeded')
                        else:
                            raise ex

                elif current_state == 'CLOSED':
                    try:
                        _ = delete_matter(service, matter_id)
                        result_of_update = f'Matter was {current_state} and is not DELETED.'
                    except Exception as ex:
                        if 'Matters have users on hold' in str(ex):
                            demisto.debug(f'{ex}')
                            return_error('The matter has holds that prevent it from being deleted.')
                        elif 'Quota exceeded for quota metric' in str(ex):
                            return_error('Quota for Google Vault API exceeded')
                        else:
                            raise ex

                elif current_state == 'DELETED':
                    demisto.results('Matter is already deleted.')

            # Dealing with REOPEN:
            elif wanted_state == 'REOPEN':
                if current_state == 'OPEN':
                    demisto.results('Matter is already open.')
                elif current_state == 'CLOSED':
                    _ = reopen_matter(service, matter_id)
                    result_of_update = f'Matter was {current_state} and is now OPEN.'
                elif current_state == 'DELETED':
                    _ = undelete_matter(service, matter_id)
                    _ = reopen_matter(service, matter_id)
                    result_of_update = f'Matter was {current_state} and is now OPEN.'

            # Dealing with UNDELETE:
            elif wanted_state == 'UNDELETE':
                if current_state == 'OPEN':
                    demisto.results('Matter is already open.')
                elif current_state == 'CLOSED':
                    demisto.results('Matter is closed at the moment.')
                elif current_state == 'DELETED':
                    _ = undelete_matter(service, matter_id)
                    result_of_update = f'Matter was {current_state} and is now CLOSED.'

            if result_of_update:  # If an update was done then update context:
                context_output.append({
                    'Name': matter_found.get('name'),
                    'MatterID': matter_found.get('matterId'),
                    'State': get_matter_by_id(service, matter_id).get('state')  # Getting new state
                })

                demisto.results({
                    'Type': entryTypes['note'],
                    'ContentsFormat': formats['text'],
                    'Contents': result_of_update,
                    'EntryContext': {
                        'GoogleVault.Matter(val.MatterID === obj.MatterID)': context_output
                    }
                })
        else:
            demisto.results('No matter was found with that ID.')  # Todo: never gets here. Gotta catch the exception
    except Exception as ex:
        err_msg = str(ex)
        if 'Quota exceeded for quota metric' in err_msg:
            err_msg = 'Quota for Google Vault API exceeded'
            return_error(f'Unable to update matter. Error: {err_msg}')
        else:
            raise ex


def add_account_to_hold_command():  # Todo: Not sure if context is good (It works, but maybe not according to conventions)
    try:
        service = connect()
        matter_id = demisto.getArg('matterID')
        hold_id = demisto.getArg('holdID')
        account_id = demisto.getArg('accountID')
        _ = add_held_account(service, matter_id, hold_id, account_id)

        msg_to_usr = f'Account {account_id} was successfully added to hold {hold_id} in matter {matter_id}'
        context_output = []
        context_output.append({
            'ID': hold_id,
            'matterID': matter_id,
            'HeldAccount': {
                'accountID': account_id,
                'IsHeld': True
            }
        })

        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['text'],
            'Contents': msg_to_usr,
            'EntryContext': {
                'GoogleVault.Hold(val.ID === obj.ID)': context_output
            }
        })
    except Exception as ex:
        err_msg = str(ex)
        if 'Quota exceeded for quota metric' in err_msg:
            err_msg = 'Quota for Google Vault API exceeded'
            return_error(f'Unable to add account to hold. Error: {err_msg}')
        else:
            raise ex


def search_matter_command():
    """
    * This can be highly optimized. What it currently does is search ALL matters and then filter by name / ID
    * If a matter with an ID is found, there's no need to keep on searching. This can be optimized too.
    * Note - this is case INSENSITIVE. Searching for 'MatTER1' will find 'matter1' too.
    """
    try:
        service = connect()
        wanted_name = demisto.getArg('matterName')
        wanted_id = demisto.getArg('matterID')
        if wanted_name or wanted_id:
            if wanted_name:
                wanted_name = wanted_name.lower()
            if wanted_id:
                wanted_id = wanted_id.lower()
        else:
            demisto.results('No name or ID were specified. Please specify at least one of them.')
            sys.exit(0)
        matters = get_matters_by_state(service, state='STATE_UNSPECIFIED')
        output = []
        markdown_matters = []
        found_anything = False
        for matter in matters:
            if matter.get('name').lower() == wanted_name or matter.get('matterId').lower() == wanted_id:
                found_anything = True
                markdown_matters.append({
                    'Matter Name': matter.get('name'),
                    'Matter ID': matter.get('matterId'),
                    'Matter State': matter.get('state')
                })
                output.append({
                    'Name': matter.get('name'),
                    'MatterID': matter.get('matterId'),
                    'State': matter.get('state')
                })
        if not found_anything:  # If finished for loop through matters and no matter was found
            demisto.results('No matters found.')
        else:
            markdown = ''  # Use this to add extra line
            if wanted_name:
                title = f'Here are matters that have the name {wanted_name}'
            else:
                title = f'Here is the matter with ID {wanted_id}'
            markdown += tableToMarkdown(title, markdown_matters, ['Matter Name', 'Matter ID', 'Matter State'])
            demisto.results({
                'Type': entryTypes['note'],
                'ContentsFormat': formats['json'],
                'Contents': markdown_matters,
                'HumanReadable': markdown,
                'EntryContext': {
                    'GoogleVault.Matter(val.MatterID === obj.MatterID)': output
                }
            })
    except Exception as ex:
        err_msg = str(ex)
        if 'Quota exceeded for quota metric' in err_msg:
            err_msg = 'Quota for Google Vault API exceeded'
            return_error(f'Unable to search matter. Error: {err_msg}')
        else:
            raise ex


def remove_account_from_hold_command():
    try:
        service = connect()
        matter_id = demisto.getArg('matterID')
        hold_id = demisto.getArg('holdID')
        account_id = demisto.getArg('accountID')
        _ = remove_held_account(service, matter_id, hold_id, account_id)

        msg_to_usr = f'Account {account_id} was successfully removed from hold {hold_id} in matter {matter_id}'
        context_output = []
        context_output.append({
            'matterID': matter_id,
            'ID': hold_id,
            'HeldAccount': {  # Does this allow only 1 HeldAccount to exist in a hold?
                'ID': account_id,
                'IsHeld': False
            },
        })
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['text'],
            'Contents': msg_to_usr,
            'EntryContext': {
                'GoogleVault.Hold(val.ID === obj.ID)': context_output
            }
        })
    except Exception as ex:
        err_msg = str(ex)
        if 'Quota exceeded for quota metric' in err_msg:
            err_msg = 'Quota for Google Vault API exceeded'
            return_error(f'Unable to remove account from hold. Error: {err_msg}')
        else:
            raise ex


def delete_hold_command():
    try:
        service = connect()
        matter_id = demisto.getArg('matterID')
        hold_id = demisto.getArg('holdID')
        _ = remove_hold(service, matter_id, hold_id)
        msg_to_usr = f'Hold {hold_id} was successfully deleted from matter {matter_id}'
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['text'],
            'Contents': msg_to_usr,
        })

    except Exception as ex:
        err_msg = str(ex)
        if 'Quota exceeded for quota metric' in err_msg:
            err_msg = 'Quota for Google Vault API exceeded'
            return_error(f'Unable to delete hold. Error: {err_msg}')
        else:
            raise ex


def list_holds_command():
    try:
        service = connect()
        matter_id = demisto.getArg('matterID')
        holds = list_holds(service, matter_id)
        if not holds:
            demisto.results('No holds found.')
        else:
            output = []
            context_output = []
            for hold in holds:
                output.append({
                    'Matter ID': matter_id,
                    'Hold Name': hold.get('name'),
                    'Hold ID': hold.get('holdId')
                })
                context_output.append({
                    'name': hold.get('name'),
                    'ID': hold.get('holdId'),
                    'MatterID': matter_id
                })
            markdown = ''  # Use this to add extra line
            title = f'Here are all the holds under matter {matter_id}.'
            markdown += tableToMarkdown(title, output, ['Hold Name', 'Hold ID', 'Matter ID'])

            demisto.results({
                'Type': entryTypes['note'],
                'ContentsFormat': formats['json'],
                'Contents': holds,
                'HumanReadable': markdown,
                'EntryContext': {
                    'GoogleVault.Hold(val.ID === obj.ID)': context_output
                }
            })
    except Exception as ex:
        err_msg = str(ex)
        if 'Quota exceeded for quota metric' in err_msg:
            err_msg = 'Quota for Google Vault API exceeded'
            return_error(f'Unable to list holds. Error: {err_msg}')
        else:
            raise ex


def create_hold_command():
    service = connect()
    matter_id = demisto.getArg('matterID')
    hold_name = demisto.getArg('holdName')
    corpus = demisto.getArg('corpus')
    accounts = demisto.getArg('accountID')
    time_frame = demisto.getArg('timeFrame')
    start_time = demisto.getArg('startTime')
    end_time = demisto.getArg('endTime')
    terms = demisto.getArg('terms')

    validate_input_values([corpus], ['Mail', 'Drive', 'Groups'])
    query = create_hold_query(hold_name, corpus, accounts, time_frame, start_time, end_time, terms)
    try:
        response = create_hold_mail_accounts(service, matter_id, query)
    except Exception as ex:
        err_msg = str(ex)
        if 'Quota exceeded for quota metric' in err_msg:
            err_msg = 'Quota for Google Vault API exceeded'
            return_error(f'Unable to create hold. Error: {err_msg}')
        else:
            raise ex

    hold_id = response['holdId']
    output = []
    context_output = []
    output.append({
        'Hold Name': hold_name,
        'Hold ID': hold_id
    })
    context_output.append({
        'name': hold_name,
        'ID': hold_id,
        'matterID': matter_id
    })
    markdown = ''  # Use this to add extra line
    title = 'Here are the details of your newly created hold:'
    markdown += tableToMarkdown(title, output, ['Hold Name', 'Hold ID'])
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': {'Hold Name': hold_name, 'Hold ID': hold_id},
        'HumanReadable': markdown,
        'EntryContext': {
            'GoogleVault.Hold(val.ID === obj.ID)': context_output
        }
    })


def create_mail_export_command():
    """
    Creates a mail export in Google Vault
    """
    service = connect()
    matter_id = demisto.getArg('matterID')
    export_name = demisto.getArg('exportName')
    data_scope = demisto.getArg('dataScope')
    search_method = demisto.getArg('searchMethod')
    emails = demisto.getArg('emails')
    include_drafts = demisto.getArg('includeDrafts')
    start_time = demisto.getArg('startTime')
    end_time = demisto.getArg('endTime')
    time_frame = demisto.getArg('timeFrame')
    terms = demisto.getArg('terms')
    export_pst = demisto.getArg('exportPST')
    export_mbox = demisto.getArg('exportMBOX')
    org_unit = demisto.getArg('ou')

    validate_input_values([include_drafts, export_pst, export_mbox], ['true', 'false', ''])
    validate_input_values([data_scope], ['All Data', 'Held Data', 'Unprocessed Data'])
    validate_input_values([search_method], ['All Accounts', 'Specific Accounts(requires emails argument)',
                                            'Organizational Unit(requires ou argument)'])

    query = create_mail_export_query(export_name, emails, time_frame, start_time, end_time, terms, org_unit, export_pst,
                                     export_mbox, search_method, include_drafts, data_scope)
    try:
        response = create_export(service, matter_id, query)
    except Exception as ex:
        err_msg = str(ex)
        if 'Quota exceeded for quota metric' in err_msg:
            err_msg = 'Quota for Google Vault API exceeded'
            return_error(f'Unable to create export. Error: {err_msg}')
        else:
            raise ex

    create_time = response.get('createTime')
    export_id = response.get('id')

    title = 'A new export has been created successfully:\n'
    output_for_markdown = {  # This one is for tableToMarkdown to correctly map
        'Matter ID': matter_id,
        'Export ID': export_id,
        'Export Name': export_name,
        'Created Time': create_time
    }
    markdown = tableToMarkdown(title, output_for_markdown, ['Matter ID', 'Export ID', 'Export Name', 'Created Time'])

    new_export = {
        'MatterID': matter_id,
        'ExportID': export_id,
        'Name': export_name,
        'CreateTime': create_time
    }

    context_matter = get_current_matter_from_context(matter_id)
    new_matter = populate_matter_with_export(context_matter, new_export)

    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': response,
        'HumanReadable': markdown,
        'EntryContext': {
            f'GoogleVault.Matter(val.MatterID === "{matter_id}")': new_matter
        }
    })


def create_drive_export_command():
    service = connect()
    matter_id = demisto.getArg('matterID')
    export_name = demisto.getArg('exportName')
    data_scope = demisto.getArg('dataScope')
    search_method = demisto.getArg('searchMethod')
    emails = demisto.getArg('emails')
    org_unit = demisto.getArg('ou')
    team_drives = demisto.getArg('teamDrive')
    include_teamdrives = demisto.getArg('includeTeamDrives')
    time_frame = demisto.getArg('timeFrame')
    start_time = demisto.getArg('startTime')
    end_time = demisto.getArg('endTime')
    terms = demisto.getArg('terms')

    validate_input_values([include_teamdrives], ['true', 'false', ''])
    validate_input_values([data_scope], ['All Data', 'Held Data', 'Unprocessed Data'])
    validate_input_values([search_method], ['Team Drive', 'Specific Accounts(requires emails argument)',
                                            'Organizational Unit(requires ou argument)'])

    query = create_drive_export_query(export_name, emails, team_drives, time_frame, start_time, end_time, terms,
                                      org_unit, search_method, include_teamdrives, data_scope)
    try:
        response = create_export(service, matter_id, query)
    except Exception as ex:
        err_msg = str(ex)
        if 'Quota exceeded for quota metric' in err_msg:
            err_msg = 'Quota for Google Vault API exceeded'
            return_error(f'Unable to create export. Error: {err_msg}')
        else:
            raise ex

    create_time = response.get('createTime')
    export_id = response.get('id')

    new_export = {
        'MatterID': matter_id,
        'ExportID': export_id,
        'Name': export_name,
        'CreateTime': create_time
    }

    context_matter = get_current_matter_from_context(matter_id)
    new_matter = populate_matter_with_export(context_matter, new_export)

    title = 'A new export has been created successfully:\n'
    output_for_markdown = {  # This one is for tableToMarkdown to correctly map
        'Matter ID': matter_id,
        'Export ID': export_id,
        'Export Name': export_name,
        'Created Time': create_time
    }
    markdown = tableToMarkdown(title, output_for_markdown, ['Matter ID', 'Export ID', 'Export Name', 'Created Time'])
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': response,
        'HumanReadable': markdown,
        'EntryContext': {
            f'GoogleVault.Matter(val.MatterID === "{matter_id}")': new_matter
        }
    })


def create_groups_export_command():
    service = connect()
    matter_id = demisto.getArg('matterID')
    export_name = demisto.getArg('exportName')
    data_scope = demisto.getArg('dataScope')
    search_method = 'ACCOUNT'  # Hard-coded only for groups export
    emails = demisto.getArg('groups')
    start_time = demisto.getArg('startTime')
    end_time = demisto.getArg('endTime')
    time_frame = demisto.getArg('timeFrame')
    terms = demisto.getArg('terms')
    export_pst = demisto.getArg('exportPST')
    export_mbox = demisto.getArg('exportMBOX')

    validate_input_values([export_pst, export_mbox], ['true', 'false', ''])
    validate_input_values([data_scope], ['All Data', 'Held Data', 'Unprocessed Data'])

    query = create_groups_export_query(export_name, emails, time_frame, start_time, end_time, terms, search_method,
                                       export_pst, export_mbox, data_scope)
    try:
        response = create_export(service, matter_id, query)
    except Exception as ex:
        err_msg = str(ex)
        if 'Quota exceeded for quota metric' in err_msg:
            err_msg = 'Quota for Google Vault API exceeded'
            return_error(f'Unable to create export. Error: {err_msg}')
        else:
            raise ex

    create_time = response.get('createTime')
    export_id = response.get('id')

    new_export = {
        'MatterID': matter_id,
        'ExportID': export_id,
        'Name': export_name,
        'CreateTime': create_time
    }

    context_matter = get_current_matter_from_context(matter_id)
    new_matter = populate_matter_with_export(context_matter, new_export)

    title = 'A new export has been created successfully:\n'
    output_for_markdown = {  # This one is for tableToMarkdown to correctly map
        'Matter ID': matter_id,
        'Export ID': export_id,
        'Export Name': export_name,
        'Created Time': create_time
    }
    markdown = tableToMarkdown(title, output_for_markdown, ['Matter ID', 'Export ID', 'Export Name', 'Created Time'])
    demisto.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': response,
        'HumanReadable': markdown,
        'EntryContext': {
            f'GoogleVault.Matter(val.MatterID === "{matter_id}")': new_matter
        }
    })


def get_multiple_exports_command():
    export_IDs = argToList(demisto.getArg('exportIDS'))
    matter_id = demisto.getArg('matterId')
    id_concatenation = demisto.getArg('queryIDS')
    if id_concatenation:
        if '#' not in id_concatenation:
            return_error(
                'Should enter a concatenation of MatterID and ExportID with "#" delimeter such: <Matter_ID>#<ExportID>')

        matter_id, export_id = id_concatenation.split('#')
        export_IDs = [export_id]

    if not (matter_id and export_IDs):
        return_error('Missing parameter MetterID or ExportID')

    current_matter = get_current_matter_from_context(matter_id)

    for export_id in export_IDs:
        new_export = get_export_command(export_id, matter_id)
        current_matter = populate_matter_with_export(current_matter, new_export)

    demisto.results({
        'ContentsFormat': formats['text'],
        'Contents': '',
        'Type': entryTypes['note'],
        'EntryContext': {
            f'GoogleVault.Matter(val.MatterID === "{matter_id}")': current_matter
        }
    })


def get_export_command(export_id, matter_id):
    service = connect()

    try:
        response = get_export_by_id(service, matter_id, export_id)
        export_name = response.get('name')
        export_status = response.get('status')
        create_time = response.get('createTime')
        bucket_name = response.get('cloudStorageSink').get('files')[0].get(
            'bucketName') if export_status == 'COMPLETED' else ''
        zip_object_name = get_object_mame_by_type(response.get('cloudStorageSink').get('files'),
                                                  '.zip') if export_status == 'COMPLETED' else ''
        xml_object_name = get_object_mame_by_type(response.get('cloudStorageSink').get('files'),
                                                  '.xml') if export_status == 'COMPLETED' else ''

        title = 'You Export details:\n'
        output_for_markdown = {  # This one is for tableToMarkdown to correctly map
            'Matter ID': matter_id,
            'Export ID': export_id,
            'Export Name': export_name,
            'Status': export_status,
            'Created Time': create_time,
            'Bucket Name(for download)': bucket_name,
            'Download ID': zip_object_name,
            'View ID': xml_object_name
        }
        if (export_status == 'COMPLETED'):
            headers = ['Matter ID', 'Export ID', 'Export Name', 'Status', 'Created Time', 'Bucket Name(for download)',
                       'Download ID', 'View ID']
        else:
            headers = ['Matter ID', 'Export ID', 'Export Name', 'Status', 'Created Time']
        markdown = tableToMarkdown(title, output_for_markdown, headers)

        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['text'],
            'Contents': response,
            'HumanReadable': markdown,
        })

        export_status = {
            'MatterID': matter_id,
            'ExportID': export_id,
            'ExportName': export_name,
            'Status': export_status,
            'BucketName': bucket_name,
            'DownloadID': zip_object_name,
            'ViewID': xml_object_name
        }

        return export_status

    except Exception as ex:
        err_msg = str(ex)
        if 'Quota exceeded for quota metric' in err_msg:
            err_msg = 'Quota for Google Vault API exceeded'
            return_error(f'Unable to get export. Error: {err_msg}')
        else:
            raise ex


def download_export_command():
    out_file = None
    try:
        bucket_name = demisto.getArg('bucketName')
        download_ID = demisto.getArg('downloadID')
        out_file = download_storage_object(download_ID, bucket_name)
        demisto.results(fileResult(demisto.uniqueFile() + '.zip', out_file.getvalue()))
    except Exception as ex:
        err_msg = str(ex)
        if 'Quota exceeded for quota metric' in err_msg:
            err_msg = 'Quota for Google Vault API exceeded'
            return_error(f'Unable to download export. Error: {err_msg}')
        else:
            raise ex
    finally:
        if out_file:
            out_file.close()


def download_and_sanitize_export_results(object_ID, bucket_name, max_results):
    out_file = None
    try:
        out_file = download_storage_object(object_ID, bucket_name)
        out_file_json = json.loads(xml2json(out_file.getvalue()))

        if not out_file_json['Root']['Batch'].get('Documents'):
            demisto.results('The export given contains 0 documents')
            sys.exit(0)
        documents = out_file_json['Root']['Batch']['Documents']['Document']

        if type(documents) is dict:
            documents = [documents]

        if len(documents) > max_results:
            documents = documents[:max_results]

        dictList = build_dict_list(documents)
        return dictList

    finally:
        if out_file:
            out_file.close()


def get_drive_results_command():
    try:
        max_results = int(demisto.getArg('maxResult'))
        view_ID = demisto.getArg('viewID')
        bucket_name = demisto.getArg('bucketName')
        output = download_and_sanitize_export_results(view_ID, bucket_name, max_results)

        if not (output[0].get('Author') or output[0].get('Collaborators') or output[0].get('Title')):
            return_error(
                'Error displaying results: Corpus of the invoked command and the supplied ViewID does not match')

        markedown_output = [{
            'Title': document.get('Title'),
            'Author': document.get('Author'),
            'Collaborators': document.get('Collaborators'),
            'Others': document.get('Others'),
            'DateCreated': document.get('DateCreated'),
            'DateModified': document.get('DateModified'),
            'DocType': document.get('DocType'),
            'MD5': document.get('MD5'),
        } for document in output]

        title = 'Your DRIVE inquiry details\n'
        headers = ['Title', 'Author', 'Collaborators', 'Others', 'Labels', 'Viewers', 'DateCreated', 'DateModified',
                   'DocType', 'MD5']
        markdown = tableToMarkdown(title, markedown_output, headers)

        exportID = str(view_ID).split('/')[1]
        contextOutput = {'ExportID': exportID, 'Results': markedown_output}

        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': contextOutput,
            'HumanReadable': markdown,
            'EntryContext': {
                'GoogleVault.Matter.Export(val.ExportID === obj.ExportID)': contextOutput
            }
        })

    except Exception as ex:
        err_msg = str(ex)
        if 'Quota exceeded for quota metric' in err_msg:
            err_msg = 'Quota for Google Vault API exceeded'
            return_error(f'Unable to display export result. Error: {err_msg}')
        else:
            raise ex


def get_mail_and_groups_results_command(inquiryType):
    try:
        max_results = int(demisto.getArg('maxResult'))
        view_ID = demisto.getArg('viewID')
        bucket_name = demisto.getArg('bucketName')
        output = download_and_sanitize_export_results(view_ID, bucket_name, max_results)
        if not (output[0].get('From') or output[0].get('To') or output[0].get('Subject')):
            return_error(
                'Error displaying results: Corpus of the invoked command and the supplied ViewID does not match')

        markedown_output = [{
            'From': document.get('From'),
            'To': document.get('To'),
            'CC': document.get('CC'),
            'BCC': document.get('BCC'),
            'Subject': document.get('Subject'),
            'DateSent': document.get('DateSent'),
            'DateReceived': document.get('DateReceived'),
        } for document in output]

        title = f'Your {inquiryType} inquiry details\n'
        headers = ['Subject', 'From', 'To', 'CC', 'BCC', 'DateSent']
        markdown = tableToMarkdown(title, markedown_output, headers)

        exportID = str(view_ID).split('/')[1]
        contextOutput = {'ExportID': exportID, 'Results': markedown_output}

        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': contextOutput,
            'HumanReadable': markdown,
            'EntryContext': {
                'GoogleVault.Matter.Export(val.ExportID === obj.ExportID)': contextOutput
            }
        })

    except Exception as ex:
        err_msg = str(ex)
        if 'Quota exceeded for quota metric' in err_msg:
            err_msg = 'Quota for Google Vault API exceeded'
            return_error(f'Unable to display export result. Error: {err_msg}')
        else:
            raise ex


def test_module():
    """
    This is the call made when pressing the integration test button.
    """
    try:
        service = connect()
        get_matters_by_state(service, 'STATE_UNSPECIFIED', first_page_only=True)
        demisto.results('ok')
        sys.exit(0)
    except Exception as ex:
        if 'Quota exceeded for quota metric' in str(ex):
            return_error('Quota for Google Vault API exceeded')
        else:
            return_error(str(ex))


def main():
    """Main Execution Block"""

    try:
        handle_proxy()

        # @@@@@@@@ DEMISTO COMMANDS @@@@@@@@

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration test button.
            test_module()
        elif demisto.command() == 'gvault-list-matters':
            list_matters_command()
        elif demisto.command() == 'gvault-create-matter':
            create_matter_command()
        elif demisto.command() == 'gvault-matter-update-state':
            update_matter_state_command()
        elif demisto.command() == 'gvault-add-heldAccount':
            add_account_to_hold_command()
        elif demisto.command() == 'gvault-get-matter':
            search_matter_command()
        elif demisto.command() == 'gvault-remove-heldAccount':
            remove_account_from_hold_command()
        elif demisto.command() == 'gvault-delete-hold':
            delete_hold_command()
        elif demisto.command() == 'gvault-list-holds':
            list_holds_command()
        elif demisto.command() == 'gvault-create-hold':
            create_hold_command()
        elif demisto.command() == 'gvault-create-export-mail':
            create_mail_export_command()
        elif demisto.command() == 'gvault-create-export-drive':
            create_drive_export_command()
        elif demisto.command() == 'gvault-create-export-groups':
            create_groups_export_command()
        elif demisto.command() == 'gvault-export-status':
            get_multiple_exports_command()
        elif demisto.command() == 'gvault-download-results':
            download_export_command()
        elif demisto.command() == 'gvault-get-drive-results':
            get_drive_results_command()
        elif demisto.command() == 'gvault-get-mail-results':
            get_mail_and_groups_results_command('MAIL')
        elif demisto.command() == 'gvault-get-groups-results':
            get_mail_and_groups_results_command('GROUPS')
    except Exception as e:
        return_error(str(e))


# python2 uses __builtin__ python3 uses builtins
if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
