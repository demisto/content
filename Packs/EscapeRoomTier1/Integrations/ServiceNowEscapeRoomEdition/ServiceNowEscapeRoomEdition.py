import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


ACCEPTABLE_CREDS = {
    ('Anna', 'KristenBell'),
    ('Elsa', 'IdinaMenzel'),
}

WRONG_CREDS = {
    ('admin', 'admin'): 'Bad credentials, looks like you forgot your Credentials.',
    ('Olaf', 'JoshGad'): 'Sorry, access to this product is restricted to humans only.',
    ('Pabbie', 'CiarandHinds'): 'Sorry, access to this product is restricted to humans only.',
    ('Swen', 'FrankWelker'): 'Sorry, access to this product is restricted to humans only.',
    ('Hans', 'SantinoFontana'): "Access Denied!!! Don't ever try this again!",
}

AUTO_EXTRACT_DETAILS = (
    'The Auto Extract feature extracts indicators and enriches their reputations using commands and'
    ' scripts defined for the indicator type.\n'
    'Cortex XSOAR recommends that you turn off Auto Extract using the server configurations for the different'
    ' Auto Extract options and only turn it on for those specific scenarios where it is necessary.\n'
    '![autoextract](https://user-images.githubusercontent.com/30797606/159860634-a031b732-87d7-41c5-a165-c3a2c52c8f1d.png)'
)
# image is: Packs/EscapeRoomTier1/images/autoextract.png

DUPLICATE_INCIDENT = (
    'This is a duplicate of a previous incident. try fetching the original incident again.\n'
    '![Nothing to see](https://user-images.githubusercontent.com/30797606/159861060-41783cfb-ddcd-413a-bede-7a79bc60b87e.gif)'
)
# image is: Packs/EscapeRoomTier1/images/snowincident_NothingToSee.gif


def validate_credentials(credentials):
    demisto.debug(f'Using the following credentials:\n {credentials}')
    creds = credentials.get('identifier', 'admin'), credentials.get('password', 'admin')
    if creds in ACCEPTABLE_CREDS:
        return

    raise PermissionError(WRONG_CREDS.get(creds))


def test_module(credentials):
    validate_credentials(credentials)
    return 'ok'


def fetch_incident(credentials, last_run):
    validate_credentials(credentials)
    occurs = datetime.now().isoformat(timespec='seconds')

    if last_run:
        incident = {
            'name': 'ServiceNow Incident No. 1337',
            'details': DUPLICATE_INCIDENT,
            'CustomFields': {
                'servicenowdetails': DUPLICATE_INCIDENT,
            },
            'severity': 1,
            # 'attachment': file_names,  # TODO: add some attachments
            'occurs': occurs,
            'rawJSON': json.dumps({}),
        }
    else:
        incident = {
            'name': 'ServiceNow Incident No. 1337',
            'details': AUTO_EXTRACT_DETAILS,
            'CustomFields': {
                'servicenowdetails': AUTO_EXTRACT_DETAILS,
            },
            'severity': 3,
            # 'attachment': file_names,  # TODO: add some attachments
            'occurs': occurs,
            'rawJSON': json.dumps({}),
        }
        last_run.update({'time': occurs})

    return [incident], last_run


''' MAIN FUNCTION '''


def main() -> None:
    command = demisto.command()
    credentials = demisto.getParam('credentials')
    credentials = credentials if credentials else {}
    demisto.debug(f'Command being called is {command}')
    try:
        if demisto.command() == 'test-module':
            return_results(test_module(credentials))
        if command == 'fetch-incidents':
            last_run = demisto.getLastRun()
            incidents, last_run = fetch_incident(credentials, last_run)
            demisto.incidents(incidents)
            demisto.setLastRun(last_run)
        else:
            if command in [
                'servicenow-get-ticket', 'servicenow-create-ticket', 'servicenow-update-ticket',
                'servicenow-delete-ticket', 'servicenow-query-tickets', 'servicenow-add-link',
                'servicenow-add-comment', 'servicenow-upload-file', 'servicenow-get-record',
                'servicenow-query-table', 'servicenow-create-record', 'servicenow-update-record',
                'servicenow-delete-record', 'servicenow-list-table-fields', 'servicenow-query-computers',
                'servicenow-query-groups', 'servicenow-query-users', 'servicenow-get-table-name',
                'servicenow-get-ticket-notes', 'servicenow-add-tag', 'servicenow-query-items',
                'servicenow-get-item-details', 'servicenow-create-item-order', 'servicenow-document-route-to-queue',
                'get-mapping-fields', 'get-remote-data', 'servicenow-oauth-login', 'servicenow-oauth-test'
            ]:
                return_results('all good!')

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
