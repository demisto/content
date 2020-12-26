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

    INTEGRATION_CONTEXT_NAME:
        Context output names should be written in camel case, for example: MSGraphUser.
"""
INTEGRATION_NAME = 'PhishLabs IOC - EIR'
INTEGRATION_CONTEXT_NAME = 'PhishLabsIOC'


class Client(BaseClient):
    def test_module(self) -> Dict:
        """Performs basic GET request to check if the API is reachable and authentication is successful.

        Returns:
            Response json
        """
        return self.get_incidents(limit=2)

    def get_incidents(self, status: Optional[str] = None, created_after: Optional[str] = None,
                      created_before: Optional[str] = None, closed_before: Optional[str] = None,
                      closed_after: Optional[str] = None, sort: Optional[str] = None, direction: Optional[str] = None,
                      limit: Union[str, int] = 25, offset: Union[str, int] = 0, period: str = None) -> Dict:
        """
        Query the specified kwargs with default parameters if not defined
        Args:
            status: open,closed
            created_after: Timestamp is in RFC3339 format
            created_before: Timestamp is in RFC3339 format
            closed_before: Timestamp is in RFC3339 format
            closed_after: Timestamp is in RFC3339 format
            sort: created_at,closed_at
            direction: asc,desc
            limit: Limit amounts of incidents (0-50, default 50)
            offset: Offset from last incident
            period: timestamp (<number> <time unit>, e.g., 12 hours, 7 days)

        Returns:
            Raw response json as dictionary
        """
        suffix = "/incidents/EIR"
        params: Dict[str, Any] = {}
        if period:
            created_after, created_before = parse_date_range(date_range=period,
                                                             date_format='%Y-%m-%dT%H:%M:%SZ')
            params = {
                'created_after': created_after,
                'created_before': created_before
            }
        else:
            params = {
                'created_after': created_after,
                'created_before': created_before,
                'closed_before': closed_before,
                'closed_after': closed_after
            }
        params.update({
            'status': status,
            'sort': sort,
            'direction': direction,
            'limit': limit,
            'offset': offset
        })
        return self._http_request('GET',
                                  url_suffix=suffix,
                                  params=assign_params(**params))

    def get_incident_by_id(self, incident_id: str) -> Dict:
        """Query incident by ID

        Args:
            incident_id: ID of incident

        Returns:
            Response JSON as dictionary
        """
        suffix = f"/incidents/EIR/{incident_id}"
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
            'Body/HTML': indicator.get('emailBody')
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
            'Score': Common.DBotScore.BAD if indicator.get('malicious') == 'true' else Common.DBotScore.GOOD
        }
    elif type_ec == 'file-ec':
        ec = {
            'Name': indicator.get('fileName'),
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
            'Score': Common.DBotScore.BAD if indicator.get('malicious') == 'true' else Common.DBotScore.GOOD
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
        limit: str,
        last_run: Optional[str] = None) -> Tuple[List[Dict[str, Any]], Dict]:
    """Uses to fetch incidents into Demisto
    Documentation: https://github.com/demisto/content/tree/master/docs/fetching_incidents

    Args:
        client: Client object with request
        fetch_time: From when to fetch if first time, e.g. `3 days`
        limit: limit of incidents in a fetch
        last_run: Last fetch object occurs.

    Returns:
        incidents, new last_run
    """
    # Init
    raws: List = []
    incidents_raw: List = []
    # Set last run time
    occurred_format = '%Y-%m-%dT%H:%M:%SZ'
    if not last_run:
        datetime_new_last_run, _ = parse_date_range(date_range=fetch_time,
                                                    date_format=occurred_format)
    else:
        datetime_new_last_run = last_run
    # Query incidents by limit and creation time
    total = 0
    offset = 50
    limit_incidents = int(limit)
    limit_page = min(50, limit_incidents)
    raw_response = client.get_incidents(created_after=datetime_new_last_run,
                                        offset=offset,
                                        limit=limit_page,
                                        sort='created_at',
                                        direction='asc')
    while raw_response.get('metadata', {}).get('count') and total < limit_incidents:
        raws.append(raw_response)
        incidents_raw += raw_response.get('incidents', [])
        total += int(raw_response.get('metadata', {}).get('count'))
        offset += int(raw_response.get('metadata', {}).get('count'))
        if total >= limit_incidents:
            break
        if limit_incidents - total < 50:
            limit_page = limit_incidents - total
        raw_response = client.get_incidents(offset=offset,
                                            created_after=datetime_new_last_run,
                                            limit=limit_page,
                                            sort='created_at',
                                            direction='asc')
    # Gather incidents by demisto format
    new_last_run: Optional[str] = None
    incidents_report = []
    if incidents_raw:
        for incident_raw in incidents_raw:
            # Creates incident entry
            occurred = incident_raw.get('created')
            incidents_report.append({
                'name': f"{INTEGRATION_NAME}: {incident_raw.get('id')}",
                'occurred': occurred,
                'rawJSON': json.dumps(incident_raw)
            })

        new_last_run = incidents_report[-1].get('occurred')
    # Return results
    return incidents_report, {'lastRun': new_last_run}


@logger
def get_incidents_command(client: Client, **kwargs: Dict) -> Tuple[object, dict, Union[List, Dict]]:
    """Lists all incidents and return outputs in Demisto's context entry

    Args:
        client: Client object with request
        kwargs: Usually demisto.args()

    Returns:
        human readable (markdown format), raw response and entry context
    """
    raw_response: Dict = client.get_incidents(**kwargs)  # type: ignore
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
def get_incident_by_id_command(client: Client, incident_id: str) -> Tuple[object, Dict, Dict]:
    """Lists all events and return outputs in Demisto's context entry

    Args:
        client: Client object with request
        incident_id: ID of Incident

    Returns:
        human readable (markdown format), raw response and entry context
    """
    raw_response: Dict = client.get_incident_by_id(incident_id)
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
        auth=(params.get('credentials', {}).get('identifier'),
              params.get('credentials', {}).get('password'))
    )
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    commands = {
        'test-module': test_module_command,
        'phishlabs-ioc-eir-get-incidents': get_incidents_command,
        'phishlabs-ioc-eir-get-incident-by-id': get_incident_by_id_command
    }
    try:
        if command == 'fetch-incidents':
            incidents, new_last_run = fetch_incidents_command(client,
                                                              fetch_time=params.get('fetchTime'),
                                                              last_run=demisto.getLastRun().get('lastRun'),
                                                              limit=params.get('fetchLimit'))
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
