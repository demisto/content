import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


''' IMPORTS '''
from typing import Dict, Tuple, Union, Optional, List, Any, AnyStr
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

"""GLOBALS/PARAMS
Attributes:
    INTEGRATION_NAME:
        Name of the integration as shown in the integration UI, for example: Microsoft Graph User.

    INTEGRATION_COMMAND_NAME:
        Command names should be written in all lower-case letters,
        and each word separated with a hyphen, for example: msgraph-user.

    INTEGRATION_CONTEXT_NAME:
        Context output names should be written in camel case, for example: MSGraphUser.
"""
INTEGRATION_NAME = 'PhishLabs IOC - EIR'
INTEGRATION_COMMAND_NAME = 'phishlabs-ioc-eir'
INTEGRATION_CONTEXT_NAME = 'PhishLabsIOC'


class Client(BaseClient):
    def test_module(self) -> Dict:
        """Performs basic GET request to check if the API is reachable and authentication is successful.

        Returns:
            Response json
        """
        return self.phishlabs_ioc_eir_get_incident_by_id(incident_id='INC0660932')

    def phishlabs_ioc_eir_get_incidents(self, limit=25, offset=0, **kwargs: dict) -> Dict:
        """Query the specified kwargs with default parameters if not defined

        Args:
            offset: pagination parameter offset from the beginning of the page
            limit: pagination parameter limit of incidents on a page 0..50
            kwargs: parameters for filtering incidents

        Returns:
            Response JSON as dictionary
        """
        suffix = "/incidents/EIR"
        return self._http_request('GET',
                                  url_suffix=suffix,
                                  params={**kwargs,
                                          'offset': offset,
                                          'limit': limit})

    def phishlabs_ioc_eir_get_incident_by_id(self, **kwargs) -> Dict:
        """Query incident by ID

        Args:
            kwargs: incident_id

        Returns:
            Response JSON as dictionary
        """
        suffix = f"/incidents/EIR/{kwargs.get('incident_id')}"
        return self._http_request('GET',
                                  url_suffix=suffix)


''' HELPER FUNCTIONS '''


@logger
def indicator_ec(indicator: Dict, type_ec: AnyStr) -> Dict:
    """indicator convert to ec format
    Get an indicator from raw response and concert to demisto entry context format

    Args:
        indicator: raw response dictionary
        type_ec: type of entry context

    Returns:
         indicator entry context
    """
    ec: Dict = {}
    if type_ec == 'url-phishlabs':
        ec = {
            'URL': indicator.get('url'),
            'Malicious': indicator.get('malicious'),
            'MaliciousDomain': indicator.get('maliciousDomain'),
        }
    elif type_ec == 'attach-phishlabs':
        ec = {
            'fileName': indicator.get('fileName'),
            'MimeType': indicator.get('mimeType'),
            'MD5': indicator.get('md5'),
            'SHA256': indicator.get('sha256'),
            'Malicious': indicator.get('malicious')
        }
    elif type_ec == 'email-ec':
        ec = {
            'To': indicator.get('emailReportedBy'),
            'From': indicator.get('sender'),
            'Body/HTML': indicator.get('emailBody'),
            'Attachments': {
                'EntryID': None  # TODO TBD
            }
        }

    return ec


@logger
def indicator_dbot_ec(indicator: Dict, type_ec: AnyStr) -> Tuple[Dict, Dict]:
    """Indicator convert to ec and dbotscore ec
    Get an indicator from raw response and concert to demisto entry context format and demisto dbotscore entry context
    format.

    Args:
        indicator: raw response dictionary
        type_ec: type of entry context

    Returns:
        dbotscore entry context, indicator entry context
    """
    dbotscore: Dict = {}
    ec: Dict = {}
    if type_ec == 'url-ec':
        ec = {
            'Data': indicator.get('url'),
            'Malicious': {
                'Vendor': INTEGRATION_NAME,
                'Description': indicator.get('malicious')
            }
        }
        dbotscore = {
            'Indicator': indicator.get('url'),
            'Type': 'URL',
            'Vendor': INTEGRATION_NAME,
            'Score': dbotscores.get('High') if indicator.get('malicious') == 'true' else dbotscores.get('Low')
        }
    elif type_ec == 'file-ec':
        ec = {
            'Name': indicator.get('fileName'),
            'EntryID': '',  # TODO define it
            'SHA256': indicator.get('sha256'),
            'MD5': indicator.get('md5'),
            'Malicious': {
                'Vendor': INTEGRATION_NAME,
                'Description': indicator.get('malicious')
            }
        }
        dbotscore = {
            'Indicator': indicator.get('fileName'),
            'Type': 'File',
            'Vendor': INTEGRATION_NAME,
            'Score': dbotscores.get('High') if indicator.get('malicious') == 'true' else dbotscores.get('Low')
        }

    return dbotscore, ec


@logger
def indicators_to_list_ec(indicators: List, type_ec: AnyStr) -> Union[Tuple[List, List], List]:
    """Unpack list of indicators to demisto ec format
    Convert list of indicators from raw response to demisto entry context format lists

    Args:
        indicators: lit of indicators from raw response
        type_ec: type of indicators
    Returns:
         List of indicators entry context and if not integration context also dbotscore
    """
    dbots: List = []
    ecs: List = []
    if type_ec in ['url-ec', 'file-ec']:
        for indicator in indicators:
            dbotscore, ec = indicator_dbot_ec(indicator, type_ec)
            ecs.append(ec)
            dbots.append(dbotscore)
        return ecs, dbots
    else:
        for indicator in indicators:
            ec = indicator_ec(indicator, type_ec)
            ecs.append(ec)
        return ecs


@logger
def raw_response_to_context(incidents: Union[List, Any]) -> Tuple[List, List, List, List, List]:
    """
    Convert incidents list from raw response to demisto entry context list format
    Args:
        incidents: Incidents list

    Returns:
        Entry contexts of phishLabs, emails, files, urls, dbotScores
    """
    phishlabs_ec: List = []
    email_ec: List = []
    file_ec: List = []
    url_ec: List = []
    dbots_ec: List = []
    for incident in incidents:
        sc_incident: Dict = incident.get('details', {})
        # Phishlabs entry context
        phishlabs: Dict = {
            'CaseType': sc_incident.get('caseType'),
            'Classification': sc_incident.get('classification'),
            'SubClassification': sc_incident.get('subClassification'),
            'Severity': sc_incident.get('severity'),
            'EmailReportedBy': sc_incident.get('emailReportedBy'),
            'SubmissionMethod': sc_incident.get('submissionMethod'),
            'FurtherReviewReason': sc_incident.get('furtherReviewReason'),
            'ID': incident.get('id'),
            'Title': incident.get('title'),
            'Description': incident.get('description'),
            'Status': incident.get('status'),
            'Created': incident.get('created'),
            'Modified': incident.get('modified'),
            'Closed': incident.get('closed'),
            'Duration': incident.get('duration'),
            'Email': {
                'EmailBody': sc_incident.get('emailBody'),
                'Sender': sc_incident.get('sender'),
                'URL': indicators_to_list_ec(sc_incident.get('urls', []), type_ec='url-phishlabs'),
                'Attachment': indicators_to_list_ec(sc_incident.get('attachments', []), type_ec='attach-phishlabs')
            }
        }
        phishlabs_ec.append(phishlabs)
        # Email entry context
        email = indicator_ec(sc_incident, type_ec='email-ec')
        email_ec.append(email)
        # Files + dbot entry context
        files, dbotscores_files = indicators_to_list_ec(sc_incident.get('attachments', []), type_ec='file-ec')
        file_ec += files
        dbots_ec += dbotscores_files
        # Urls + dbot entry context
        urls, dbotscores_urls = indicators_to_list_ec(sc_incident.get('urls', []), type_ec='url-ec')
        url_ec += urls
        dbots_ec += dbotscores_urls

    return phishlabs_ec, email_ec, file_ec, url_ec, dbots_ec


''' COMMANDS '''


@logger
def test_module_command(client: Client, *_) -> Tuple[None, None, str]:
    """Performs a basic GET request to check if the API is reachable and authentication is successful.

    Args:
        client: Client object with request
        *_: Usually demisto.args()

    Returns:
        'ok' if test successful.

    Raises:
        DemistoException: If test failed.
    """
    results = client.test_module()
    if 'incidents' in results:
        return None, None, 'ok'
    raise DemistoException(f'Test module failed, {results}')


@logger
def fetch_incidents_command(
        client: Client,
        fetch_time: str,
        last_run: Optional[str] = None) -> Tuple[List, str]:
    """Uses to fetch incidents into Demisto
    Documentation: https://github.com/demisto/content/tree/master/docs/fetching_incidents

    Args:
        client: Client object with request
        fetch_time: From when to fetch if first time, e.g. `3 days`
        last_run: Last fetch object occurs.

    Returns:
        incidents, new last_run
    """
    occurred_format = '%Y-%m-%dT%H:%M:%SZ'
    # Get incidents from API
    if not last_run:  # if first time running
        datetime_new_last_run, _ = parse_date_range(fetch_time, date_format=occurred_format)
    else:
        datetime_new_last_run = parse_date_string(last_run)
    new_last_run = datetime_new_last_run.strftime(occurred_format)
    kwargs = {
        'created_after': new_last_run,
    }
    raws: List = []
    incidents: List = []
    offset = 0
    raw_response = client.phishlabs_ioc_eir_get_incidents(**kwargs)
    while raw_response.get('metadata', {}).get('count'):
        raws.append(raw_response)
        incidents += raw_response.get('incidents', [])
        offset += 50
        raw_response = client.phishlabs_ioc_eir_get_incidents(offset=offset, **kwargs)
    if incidents:
        for incident in incidents:
            # Creates incident entry
            occurred = incident.get('created')
            datetime_occurred = parse_date_string(occurred)
            incidents.append({
                'name': f"{INTEGRATION_NAME}: {incident.get('id')}",
                'occurred': occurred,
                'rawJSON': json.dumps(incident)
            })
            if datetime_occurred > datetime_new_last_run:
                new_last_run = datetime_occurred.strftime(occurred_format)
    # Return results
    return incidents, new_last_run


@logger
def phishlabs_ioc_eir_get_incidents_command(client: Client, **kwargs: Dict) -> Tuple[object, dict, Union[List, Dict]]:
    """Lists all incidents and return outputs in Demisto's context entry

    Args:
        client: Client object with request
        kwargs: Usually demisto.args()

    Returns:
        human readable (markdown format), raw response and entry context
    """
    raw_response: Optional[Dict] = client.phishlabs_ioc_eir_get_incidents(**kwargs)
    if raw_response:
        title = f'{INTEGRATION_NAME} - incidents'
        phishlabs_ec, emails_ec, files_ec, urls_ec, dbots_ec = raw_response_to_context(raw_response.get('incidents'))
        context_entry: Dict = {
            outputPaths.get('dbotscore'): dbots_ec,
            outputPaths.get('file'): files_ec,
            outputPaths.get('url'): urls_ec,
            'Email(val.Address && val.Address == obj.Address)': emails_ec,
            f'{INTEGRATION_CONTEXT_NAME}(val.EIR.ID && val.EIR.ID === obj.EIR.ID && '
            f'val.EIR.Modified && val.EIR.Modified === obj.EIR.Modified)': {
                'EIR': phishlabs_ec
            }
        }
        human_readable = tableToMarkdown(name=title,
                                         t=phishlabs_ec,
                                         headers=['ID', 'Title', 'Status', 'Created', 'Classification',
                                                  'SubClassification', 'EmailReportedBy'],
                                         removeNull=True)

        return human_readable, context_entry, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


@logger
def phishlabs_ioc_eir_get_incident_by_id_command(client: Client, **kwargs: Dict) -> Tuple[object, Dict, Dict]:
    """Lists all events and return outputs in Demisto's context entry

    Args:
        client: Client object with request
        kwargs: Usually demisto.args()

    Returns:
        human readable (markdown format), raw response and entry context
    """
    raw_response: Optional[Dict] = client.phishlabs_ioc_eir_get_incident_by_id(**kwargs)
    if raw_response:
        title = f'{INTEGRATION_NAME} - incidents'
        phishlabs_ec, emails_ec, files_ec, urls_ec, dbots_ec = raw_response_to_context(raw_response.get('incidents'))
        context_entry: Dict = {
            outputPaths.get('dbotscore'): dbots_ec,
            outputPaths.get('file'): files_ec,
            outputPaths.get('url'): urls_ec,
            'Email(val.Address && val.Address == obj.Address)': emails_ec,
            f'{INTEGRATION_CONTEXT_NAME}(val.EIR.ID && val.EIR.ID === obj.EIR.ID && '
            f'val.EIR.Modified && val.EIR.Modified === obj.EIR.Modified)': {
                'EIR': phishlabs_ec
            }
        }
        human_readable = tableToMarkdown(name=title,
                                         t=phishlabs_ec,
                                         headers=['ID', 'Title', 'Status', 'Created', 'Classification',
                                                  'SubClassification', 'EmailReportedBy'],
                                         removeNull=True)

        return human_readable, context_entry, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    params = demisto.params()
    base_url = urljoin(params.get('url'), 'idapi/v1')
    verify_ssl = not params.get('insecure', False)
    proxy = params.get('proxy')
    client = Client(
        base_url=base_url,
        verify=verify_ssl,
        proxy=proxy,
        auth=(params.get('user'),
              params.get('password'))
    )
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    commands = {
        'test-module': test_module_command,
        f'{INTEGRATION_COMMAND_NAME}-get-incidents': phishlabs_ioc_eir_get_incidents_command,
        f'{INTEGRATION_COMMAND_NAME}-get-incident-by-id': phishlabs_ioc_eir_get_incident_by_id_command
    }
    try:
        if command == 'fetch-incidents' and params.get('is_fetch'):
            incidents, new_last_run = fetch_incidents_command(client,
                                                              fetch_time=params.get('fetch_time'),
                                                              last_run=demisto.getLastRun())
            demisto.incidents(incidents)
            demisto.setLastRun(new_last_run)
        else:
            readable_output, outputs, raw_response = commands[command](client=client, **demisto.args())
            return_outputs(readable_output, outputs, raw_response)
    # Log exceptions
    except Exception as e:
        err_msg = f'Error in {INTEGRATION_NAME} Integration [{e}]'
        return_error(err_msg, error=e)


if __name__ == 'builtins':
    main()
