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

AUTO_EXTRACT_DETAILS = '''The Auto Extract feature extracts indicators and enriches their reputations using commands and scripts defined for the indicator type.
Cortex XSOAR recommends that you turn off Auto Extract using the server configurations for the different Auto Extract options and only turn it on for those specific scenarios where it is necessary.
![](https://memegenerator.net/img/instances/74773082.jpg)
'''


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
            'name': f"ServiceNow Incident No. 1337",
            'details': 'This is a duplicate of a previous incident. try fetching the original incident again.',
            'CustomFields': {
                'servicenowdetails': AUTO_EXTRACT_DETAILS,
            },
            'severity': 1,
            # 'attachment': file_names,  # TODO: add some attachments
            'occurs': occurs,
            'rawJSON': json.dumps({}),
        }
    else:
        incident = {
            'name': f"ServiceNow Incident No. 1337",
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
            return_results('all good!')

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
