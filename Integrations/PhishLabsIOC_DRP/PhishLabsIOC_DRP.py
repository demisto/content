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
INTEGRATION_NAME = 'PhishLabs IOC - DRP'
INTEGRATION_COMMAND_NAME = 'phishlabs-ioc-drp'
INTEGRATION_CONTEXT_NAME = 'PhishLabsIOC'


class Client(BaseClient):
    def test_module(self) -> Dict:
        """Performs basic GET request to check if the API is reachable and authentication is successful.

        Returns:
            Response json
        """
        return self.get_cases(max_records=2)

    def get_cases(self, status: Optional[str] = None, case_type: Optional[str] = None,
                  max_records: Union[str, int] = 25, offset: Union[str, int] = 0,
                  date_field: Optional[str] = None, begin_date: Optional[str] = None,
                  end_date: Optional[str] = None, query_type: str = '') -> Dict:
        """
        Query the specified kwargs with default parameters if not defined

        Args:
            status: Filter cases based on the case status
            case_type: Filter cases by case type
            max_records: Maximum number of cases to return, default is 20, maximum is 200
            offset: Paginate results used in conjunction with maxRecords
            date_field: Field to use to query using dateBegin and dateEnd parameters.
            begin_date: Date query beginning date
            end_date: Date query beginning date
            query_type: query type influence on suffix - all/open/closed

        Returns:
            Response JSON as dictionary
        """
        suffix: str = f'/cases/{query_type}' if query_type else '/cases'
        params = {
            'status': status,
            'type': case_type,
            'maxRecords': int(max_records),
            'offset': int(offset),
            'dateField': date_field,
            'dateBegin': begin_date,
            'dateEnd': end_date
        }
        return self._http_request('GET',
                                  url_suffix=suffix,
                                  params=assign_params(**params))

    def get_case_by_id(self, case_id: str) -> Dict:
        """Query incident by ID

        Args:
            case_id: ID of the case

        Returns:
            Response JSON as dictionary
        """
        suffix = f"/cases/{case_id}"
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
    if type_ec == 'AttackSources':
        ec = {
            'URL': indicator.get('url'),
            'UrlType': indicator.get('urlType'),
            'IP': indicator.get('ipAddress'),
            'ISP': indicator.get('isp'),
            'Country': indicator.get('country'),
            'TargetedBrands': indicator.get('targetedBrands'),
            'FQDN': indicator.get('fqdn'),
            'Domain': indicator.get('domain'),
            'IsMaliciousDomain': indicator.get('isMaliciousDomain'),
            'WhoIs': {
                'Registrant': indicator.get('whois', {}).get('registrant'),
                'Registration': {
                    'Created': indicator.get('whois', {}).get('registration', {}).get('created'),
                    'Expires': indicator.get('whois', {}).get('registration', {}).get('expires'),
                    'Updated': indicator.get('whois', {}).get('registration', {}).get('updated'),
                    'Registrar': indicator.get('whois', {}).get('registration', {}).get('registrar'),
                    'NameServers': indicator.get('whois', {}).get('name_servers')
                },
            }
        }
    elif type_ec == 'Attachments':
        ec = {
            'ID': indicator.get('id'),
            'Type': indicator.get('type'),
            'Description': indicator.get('description'),
            'DateAdded': indicator.get('dateAdded'),
            'FileName': indicator.get('fileName'),
            'FileURL': indicator.get('fileURL')
        }
    elif type_ec == 'AssociatedURLs':
        ec = {
            'URL': indicator.get('url'),
            'UrlType': indicator.get('urlType'),
            'TargetedBrands': indicator.get('targetedBrands'),
            'WhoIs': {
                'Registrant': indicator.get(''),
                'Registration': {
                    'Created': indicator.get('whois', {}).get('registration', {}).get('created'),
                    'Expires': indicator.get('whois', {}).get('registration', {}).get('expires'),
                    'Updated': indicator.get('whois', {}).get('registration', {}).get('updated'),
                    'Registrar': indicator.get('whois', {}).get('registration', {}).get('registrar'),
                    'NameServers': indicator.get('whois', {}).get('name_servers')
                }
            }
        }

    return assign_params(**ec)


@logger
def indicators_to_list_ec(indicators: List, type_ec: AnyStr) -> Union[Tuple[List, List], List]:
    """Unpack list of incidents to demisto ec format
    Convert list of incidents from raw response to demisto entry context format lists

    Args:
        indicators: lit of indicators from raw response
        type_ec: type of indicators
    Returns:
         List of indicators entry context
    """
    ecs: List = []
    for indicator in indicators:
        ec = indicator_ec(indicator, type_ec)
        ecs.append(ec)
    return ecs


@logger
def raw_response_to_context(cases: Union[List, Any]) -> List:
    """
    Convert incidents list from raw response to demisto entry context list format
    Args:
        cases: Incidents list

    Returns:
        Entry contexts of phishLabs, emails, files, urls, dbotScores
    """
    phishlabs_ec: List = []
    for case in cases:
        # PhishLabs entry context
        phishlabs: Dict = {
            'CaseID': case.get('caseId'),
            'Title': case.get('title'),
            'Description': case.get('description'),
            'CaseNumber': case.get('caseNumber'),
            'Resolution': case.get('resolution'),
            'ResolutionStatus': case.get('resolutionStatus'),
            'CreatedBy': {
                'ID': case.get('createdBy', {}).get('id'),
                'Name': case.get('createdBy', {}).get('name'),
                'DisplayName': case.get('createdBy', {}).get('displayName')
            },
            'Brand': case.get('brand'),
            'Email': case.get('emailAddress'),
            'CaseType': case.get('caseType'),
            'CaseStatus': case.get('caseStatus'),
            'DateCreated': case.get('dateCreated'),
            'DateClosed': case.get('dateClosed'),
            'DateModified': case.get('dateModified'),
            'Customer': case.get('customer'),
            'AttackSources': indicators_to_list_ec(indicators=case.get('attackSources', []), type_ec='AttackSources'),
            'Attachments': indicators_to_list_ec(indicators=case.get('attachments', []), type_ec='Attachments'),
            'ApplicationName': case.get('applicationName'),
            'Platform': case.get('platform'),
            'Severity': case.get('severity'),
            'Developer': case.get('developer'),
            'DeveloperWebsite': case.get('developerWebsite'),
            'ApplicationDescription': case.get('applicationDescripion'),
            'Language': case.get('language'),
            'Hardware': case.get('hardware'),
            'Phone': case.get('phoneNumber'),
            'AssociatedURLs': indicators_to_list_ec(indicators=case.get('associatedURLs', []), type_ec='AssociatedURLs')
        }
        phishlabs_ec.append(assign_params(**phishlabs))

    return phishlabs_ec


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
    if 'data' in results:
        return None, None, 'ok'
    raise DemistoException(f'Test module failed, {results}')


@logger
def fetch_incidents_command(
        client: Client,
        fetch_time: str,
        max_records: Union[str, int],
        last_run: Optional[str] = None) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Uses to fetch incidents into Demisto
    Documentation: https://github.com/demisto/content/tree/master/docs/fetching_incidents

    Args:
        client: Client object with request
        fetch_time: From when to fetch if first time, e.g. `3 days`
        max_records: limit of incidents in a fetch
        last_run: Last fetch object occurs.

    Returns:
        incidents, new last_run
    """
    # Init
    raws: List = []
    cases_raw: List = []
    # Set last run time
    occurred_format = '%Y-%m-%dT%H:%M:%SZ'
    if not last_run:
        datetime_new_last_run, _ = parse_date_range(date_range=fetch_time,
                                                    date_format=occurred_format)
    else:
        datetime_new_last_run = last_run
    # Query incidents by limit and creation time
    total = 0
    offset = 0
    max_records = int(max_records)
    max_records_page = 200
    if max_records <= 200:
        max_records_page = max_records
    raw_response = client.get_cases(begin_date=datetime_new_last_run,
                                    date_field='caseOpen',
                                    offset=offset,
                                    max_records=max_records_page)
    while raw_response.get('header', {}).get('returnResult') and total < max_records:
        raws.append(raw_response)
        cases_raw += raw_response.get('data', [])
        total += int(raw_response.get('header', {}).get('returnResult'))
        if total >= max_records:
            break
        if max_records - total < 200:
            max_records_page = max_records - total
        offset += max_records_page
        raw_response = client.get_cases(begin_date=datetime_new_last_run,
                                        date_field='caseOpen',
                                        offset=offset,
                                        max_records=max_records_page)
    # Gather incidents by demisto format
    new_last_run: Optional[str] = None
    cases_report = []
    if cases_raw:
        for case_raw in cases_raw:
            # Creates incident entry
            occurred = case_raw.get('dateCreated')
            cases_report.append({
                'name': f"{INTEGRATION_NAME}: {case_raw.get('caseId')}",
                'occurred': occurred,
                'rawJSON': json.dumps(case_raw)
            })

        new_last_run = cases_report[-1].get('occurred')
    # Return results
    return cases_report, new_last_run


@logger
def get_cases_command(client: Client, **kwargs: Dict) -> Tuple[object, dict, Union[List, Dict]]:
    """Get all case by filters and return outputs in Demisto's context entry

    Args:
        client: Client object with request
        kwargs: Usually demisto.args()

    Returns:
        human readable (markdown format), raw response and entry context
    """
    raw_response: Dict = client.get_cases(**kwargs)  # type: ignore
    if raw_response:
        title = f'{INTEGRATION_NAME} - cases'
        phishlabs_ec = raw_response_to_context(raw_response.get('data', []))
        context_entry: Dict = {
            f'{INTEGRATION_CONTEXT_NAME}(val.DRP.CaseID && val.EIR.CaseID === obj.DRP.CaseID && '
            f'val.DRP.DateModified && val.DRP.DateModified === obj.DRP.DateModified)': {
                'DRP': phishlabs_ec
            }
        }
        human_readable = tableToMarkdown(name=title,
                                         t=phishlabs_ec,
                                         headers=['CaseID', 'Title', 'CaseStatus', 'DateCreated', 'Resolution',
                                                  'ResolutionStatus', 'CreatedBy'],
                                         removeNull=True)

        return human_readable, context_entry, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


@logger
def get_case_by_id_command(client: Client, **kwargs: Dict) -> Tuple[object, dict, Union[List, Dict]]:
    """Get case by ID and return outputs in Demisto's context entry

    Args:
        client: Client object with request
        kwargs: Usually demisto.args()

    Returns:
        human readable (markdown format), raw response and entry context
    """
    raw_response: Dict = client.get_case_by_id(**kwargs)  # type: ignore
    if raw_response:
        title = f'{INTEGRATION_NAME} - case ID {kwargs.get("caseid")}'
        phishlabs_ec = raw_response_to_context(raw_response.get('data', []))
        context_entry: Dict = {
            f'{INTEGRATION_CONTEXT_NAME}(val.DRP.CaseID && val.EIR.CaseID === obj.DRP.CaseID && '
            f'val.DRP.DateModified && val.DRP.DateModified === obj.DRP.DateModified)': {
                'DRP': phishlabs_ec
            }
        }
        human_readable = tableToMarkdown(name=title,
                                         t=phishlabs_ec,
                                         headers=['CaseID', 'Title', 'CaseStatus', 'DateCreated', 'Resolution',
                                                  'ResolutionStatus', 'CreatedBy'],
                                         removeNull=True)

        return human_readable, context_entry, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


@logger
def get_open_cases_command(client: Client, **kwargs: Dict) -> Tuple[object, dict, Union[List, Dict]]:
    """Get all open case by filters and return outputs in Demisto's context entry

      Args:
          client: Client object with request
          kwargs: Usually demisto.args()

      Returns:
          human readable (markdown format), raw response and entry context
      """
    raw_response: Dict = client.get_cases(**kwargs, query_type='open')  # type: ignore
    if raw_response:
        title = f'{INTEGRATION_NAME} - open cases'
        phishlabs_ec = raw_response_to_context(raw_response.get('data', []))
        context_entry: Dict = {
            f'{INTEGRATION_CONTEXT_NAME}(val.DRP.CaseID && val.EIR.CaseID === obj.DRP.CaseID && '
            f'val.DRP.DateModified && val.DRP.DateModified === obj.DRP.DateModified)': {
                'DRP': phishlabs_ec
            }
        }
        human_readable = tableToMarkdown(name=title,
                                         t=phishlabs_ec,
                                         headers=['CaseID', 'Title', 'CaseStatus', 'DateCreated', 'Resolution',
                                                  'ResolutionStatus', 'CreatedBy'],
                                         removeNull=True)

        return human_readable, context_entry, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


@logger
def get_closed_cases_command(client: Client, **kwargs: Dict) -> Tuple[object, dict, Union[List, Dict]]:
    """Get all closed case by filters and return outputs in Demisto's context entry

      Args:
          client: Client object with request
          kwargs: Usually demisto.args()

      Returns:
          human readable (markdown format), raw response and entry context
      """
    raw_response: Dict = client.get_cases(**kwargs, query_type='closed')  # type: ignore
    if raw_response:
        title = f'{INTEGRATION_NAME} - closed cases'
        phishlabs_ec = raw_response_to_context(raw_response.get('data', []))
        context_entry: Dict = {
            f'{INTEGRATION_CONTEXT_NAME}(val.DRP.CaseID && val.EIR.CaseID === obj.DRP.CaseID && '
            f'val.DRP.DateModified && val.DRP.DateModified === obj.DRP.DateModified)': {
                'DRP': phishlabs_ec
            }
        }
        human_readable = tableToMarkdown(name=title,
                                         t=phishlabs_ec,
                                         headers=['CaseID', 'Title', 'CaseStatus', 'DateCreated', 'Resolution',
                                                  'ResolutionStatus', 'CreatedBy'],
                                         removeNull=True)

        return human_readable, context_entry, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    params = demisto.params()
    base_url = urljoin(params.get('url'), '/v1/data')
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
        f'{INTEGRATION_COMMAND_NAME}-get-cases': get_cases_command,
        f'{INTEGRATION_COMMAND_NAME}-get-case-by-id': get_case_by_id_command,
        f'{INTEGRATION_COMMAND_NAME}-get-open-cases': get_open_cases_command,
        f'{INTEGRATION_COMMAND_NAME}-get-closed-cases': get_closed_cases_command
    }
    try:
        if command == 'fetch-incidents':
            incidents, new_last_run = fetch_incidents_command(client,
                                                              fetch_time=params.get('fetchTime'),
                                                              last_run=demisto.getLastRun(),
                                                              max_records=params.get('fetchLimit'))
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
