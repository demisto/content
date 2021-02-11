import urllib3

from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''
MINIMUM_API_VERSION = 10.1
DEFAULT_RANGE_VALUE = '0-49'
''' CLIENT CLASS '''


class Client(BaseClient):

    def __init__(self, base_url: str, verify: bool, proxy: bool, api_version: str, credentials: Dict):
        username = credentials.get("identifier", "")
        password = credentials.get("password", "")
        super().__init__(base_url, verify=verify, proxy=proxy, auth=(username, password))
        self.password = password
        self.base_headers = {
            'Version': api_version,
        }

    def http_request(self, method: str, url_suffix: str, params: Optional[Dict] = None, data: Optional[Dict] = None,
                     additional_headers: Optional[Dict] = None):
        headers = {**additional_headers, **self.base_headers} if additional_headers else self.base_headers
        return self._http_request(
            method=method,
            url_suffix=url_suffix,
            params=params,
            data=data,
            headers=headers
        )

    def qradar_offences_list(self, offence_id: Optional[int], range_: str, filter_: Optional[str]):
        id_suffix = f'/{offence_id}' if offence_id else ''
        range_header = {'Range': f'items={range_}'}
        return self.http_request(
            method='GET',
            url_suffix=f'/siem/offenses{id_suffix}',
            params=assign_params(filter=filter_),
            additional_headers=range_header
        )

    def qradar_offence_update(self, offence_id: Optional[int], protected: Optional[bool], follow_up: Optional[bool],
                              status: Optional[str], closing_reason_id: Optional[int], assigned_to: Optional[str]):
        return self.http_request(
            method='POST',
            url_suffix=f'/siem/offenses/{offence_id}',
            params=assign_params(
                protected=protected,
                follow_up=follow_up,
                status=status,
                closing_reason_id=closing_reason_id,
                assigned_to=assigned_to
            )
        )

    def qradar_closing_reasons_list(self, closing_reason_id: Optional[int], range_: str,
                                    filter_: Optional[str]):
        id_suffix = f'/{closing_reason_id}' if closing_reason_id else ''
        range_header = {'Range': f'items={range_}'}
        return self.http_request(
            method='GET',
            url_suffix=f'/siem/offense_closing_reasons{id_suffix}',
            additional_headers=range_header,
            params=assign_params(filter=filter_)
        )

    def qradar_offence_notes_list(self, offence_id: Optional[int], note_id: Optional[int], range_: str,
                                  filter_: Optional[str]):
        note_id_suffix = f'/{note_id}' if note_id else ''
        range_header = {'Range': f'items={range_}'}
        return self.http_request(
            method='GET',
            url_suffix=f'/siem/offenses/{offence_id}/notes{note_id_suffix}',
            additional_headers=range_header,
            params=assign_params(filter=filter_)
        )

    def qradar_offence_notes_create(self, offence_id: Optional[int], note_text: Optional[str]):
        return self.http_request(
            method='POST',
            url_suffix=f'/siem/offenses/{offence_id}/notes',
            params=assign_params(note_text=note_text)
        )

    # figure how to use rule type
    # def qradar_rules_list(self, rule_id: Optional[int], rule_type:):

    def qradar_rule_groups_list(self, rule_group_id: Optional[int], range_: str, filter_: Optional[str]):
        id_suffix = f'/{rule_group_id}' if rule_group_id else ''
        range_header = {'Range': f'items={range_}'}
        return self.http_request(
            method='GET',
            url_suffix=f'/analytics/rule_groups{id_suffix}',
            additional_headers=range_header,
            params=assign_params(filter=filter_)
        )

    def qradar_assets_list(self, range_: str, filter_: Optional[str]):
        range_header = {'Range': f'items={range_}'}
        return self.http_request(
            method='GET',
            url_suffix='/asset_model/assets',
            additional_headers=range_header,
            params=assign_params(filter=filter_)
        )

    def qradar_saved_searches_list(self, rule_group_id: Optional[int], range_: str, filter_: Optional[str]):
        id_suffix = f'/{rule_group_id}' if rule_group_id else ''
        range_header = {'Range': f'items={range_}'}
        return self.http_request(
            method='GET',
            url_suffix=f'/ariel/saved_searches{id_suffix}',
            additional_headers=range_header,
            params=assign_params(filter=filter_)
        )

    def qradar_searches_list(self, range_: str, filter_: Optional[str]):
        range_header = {'Range': f'items={range_}'}
        return self.http_request(
            method='GET',
            url_suffix=f'/ariel/searches',
            additional_headers=range_header,
            params=assign_params(filter=filter_)
        )

    def qradar_search_create(self, query_expression: Optional[str], saved_search_id: Optional[str]):
        return self.http_request(
            method='POST',
            url_suffix='/ariel/searches',
            params=assign_params(
                query_expression=query_expression,
                saved_search_id=saved_search_id
            )
        )

    def qradar_search_status_get(self, search_id: Optional[str]):
        return self.http_request(
            method='GET',
            url_suffix=f'/ariel/searches/{search_id}',
        )

    # def qradar_search_results_get

    def qradar_reference_sets_list(self, ref_name: Optional[str], range_: str, filter_: Optional[str]):
        name_suffix = f'/{ref_name}' if ref_name else ''
        range_header = {'Range': f'items={range_}'}
        return self.http_request(
            method='GET',
            url_suffix=f'/reference_data/sets{name_suffix}',
            params=assign_params(filter=filter_),
            additional_headers=range_header
        )

    def qradar_reference_set_create(self, ref_name: Optional[str], element_type: Optional[str],
                                    timeout_type: Optional[str], time_to_live: Optional[str]):
        return self.http_request(
            method='POST',
            url_suffix='/reference_data/sets',
            params=assign_params(
                name=ref_name,
                element_type=element_type,
                timeout_type=timeout_type,
                time_to_live=time_to_live
            )
        )

    def qradar_reference_set_delete(self, ref_name: Optional[str]):
        return self.http_request(
            method='DELETE',
            url_suffix=f'/reference_data/sets/{ref_name}'
        )

    # unsure about the date value def qradar_reference_set_value_upsert(self, ref_name: Optional[str],
    # value: Optional[str], source: Optional[str], date_value: Optional[str]):

    def qradar_reference_set_value_delete(self, ref_name: Optional[str], value: Optional[str]):
        return self.http_request(
            method='DELETE',
            url_suffix=f'/reference_data/sets/{ref_name}/{value}'
        )

    def qradar_domains_list(self, domain_id: Optional[int], range_: str, filter_: Optional[str]):
        id_suffix = f'/{domain_id}' if domain_id else ''
        range_header = {'Range': f'items={range_}'}
        return self.http_request(
            method='GET',
            url_suffix=f'/config/domain_management/domains{id_suffix}',
            additional_headers=range_header,
            params=assign_params(filter=filter_)
        )

    # discuss with arseny
    # def qradar_indicators_upload

    def qradar_geolocations_for_ip_get(self, filter_: Optional[str]):
        return self.http_request(
            method='GET',
            url_suffix='/services/geolocations',
            params=assign_params(filter=filter_)
        )

    def qradar_log_sources_list(self, range_: str, filter_: Optional[str]):
        additional_headers = {
            'x-qrd-encryption-algorithm': 'AES256',
            'x-qrd-encryption-password': self.password
        }
        if range_:
            additional_headers['Range'] = range_
        return self.http_request(
            method='GET',
            url_suffix='/config/event_sources/log_source_management/log_sources',
            params=assign_params(filter=filter_),
            additional_headers=additional_headers
        )


''' HELPER FUNCTIONS '''


def qradar_error_handler(res: Any):
    """

    Args:
        res:

    Returns:

    """
    err_msg = 'Error in API call [{}] - {}' \
        .format(res.status_code, res.reason)
    try:
        # Try to parse json error response
        error_entry = res.json()
        message = error_entry.get('message', '')
        raise DemistoException(err_msg, res=message)
    except ValueError:
        err_msg += '\n{}'.format(res.text)
        raise DemistoException(err_msg, res=res)


''' COMMAND FUNCTIONS '''


def test_module_command(client: Client) -> str:
    """
    Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.
    Args:
        client (Client): Client to perform the API calls.

    Returns:
        - 'ok' if test passed
        - DemistoException if something had failed the test.
    """
    try:
        # TODO: ADD HERE some code to test connectivity and authentication to your service.
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def qradar_offences_list_command(client: Client, args: Dict):
    offence_id = args.get('offence_id')
    range_ = f'''items={args.get('range', DEFAULT_RANGE_VALUE)}'''
    filter_ = args.get('filter')

    response = client.qradar_offences_list(offence_id, range_, filter_)
    return CommandResults(
        # readable_output=human_readable,
        outputs_prefix='QRadar.Offence',
        outputs_key_field='id',
        # outputs=response,
        raw_response=response
    )


def qradar_offence_update_command(client: Client, args: Dict):
    offence_id = args.get('offence_id')
    protected = args.get('protected')
    follow_up = args.get('follow_up')
    status = args.get('status')
    closing_reason_id = args.get('closing_reason_id')
    assigned_to = args.get('assigned_to')

    response = client.qradar_offence_update(offence_id, protected, follow_up, status, closing_reason_id, assigned_to)

    return CommandResults(
        # readable_output=human_readable,
        outputs_prefix='QRadar.Offence',
        outputs_key_field='id',
        # outputs=response,
        raw_response=response
    )


def qradar_closing_reasons_list_command(client: Client, args: Dict):
    closing_reason_id = args.get('closing_reason_id')
    range_ = f'''items={args.get('range', DEFAULT_RANGE_VALUE)}'''
    filter_ = args.get('filter')

    response = client.qradar_closing_reasons_list(closing_reason_id, range_, filter_)

    return CommandResults(
        # readable_output=human_readable,
        outputs_prefix='QRadar.ClosingReason',
        outputs_key_field='id',
        # outputs=response,
        raw_response=response
    )


def qradar_offence_notes_list_command(client: Client, args: Dict):
    offence_id = args.get('offence_id')
    note_id = args.get('note_id')
    range_ = f'''items={args.get('range', DEFAULT_RANGE_VALUE)}'''
    filter_ = args.get('filter')

    response = client.qradar_offence_notes_list(offence_id, note_id, range_, filter_)

    return CommandResults(
        # readable_output=human_readable,
        outputs_prefix='QRadar.OffenceNote',
        outputs_key_field='id',
        # outputs=response,
        raw_response=response
    )


def qradar_offence_notes_create_command(client: Client, args: Dict):
    offence_id = args.get('offence_id')
    note_text = args.get('note_text')

    response = client.qradar_offence_notes_create(offence_id, note_text)

    return CommandResults(
        # readable_output=human_readable,
        outputs_prefix='QRadar.OffenceNote',
        outputs_key_field='id',
        # outputs=response,
        raw_response=response
    )


# figure how to use rule type
# def qradar_rules_list_command(self, rule_id: Optional[int], rule_type:):

def qradar_rule_groups_list_command(client: Client, args: Dict):
    rule_group_id = args.get('rule_group_id')
    range_ = f'''items={args.get('range', DEFAULT_RANGE_VALUE)}'''
    filter_ = args.get('filter')

    response = client.qradar_rule_groups_list(rule_group_id, range_, filter_)

    return CommandResults(
        # readable_output=human_readable,
        outputs_prefix='QRadar.RuleGroup',
        outputs_key_field='id',
        # outputs=response,
        raw_response=response
    )


def qradar_assets_list_command(client: Client, args: Dict):
    asset_id = args.get('asset_id')
    range_ = f'''items={args.get('range', DEFAULT_RANGE_VALUE)}'''
    filter_ = args.get('filter')

    # If asset ID was given, override filter if both were given
    if asset_id:
        filter_ = f'id={asset_id}'

    response = client.qradar_assets_list(range_, filter_)

    return CommandResults(
        # readable_output=human_readable,
        outputs_prefix='QRadar.Asset',
        outputs_key_field='id',
        # outputs=response,
        raw_response=response
    )


def qradar_saved_searches_list_command(client: Client, args: Dict):
    rule_group_id = args.get('rule_group_id')
    range_ = f'''items={args.get('range', DEFAULT_RANGE_VALUE)}'''
    filter_ = args.get('filter')

    response = client.qradar_saved_searches_list(rule_group_id, range_, filter_)

    return CommandResults(
        # readable_output=human_readable,
        outputs_prefix='QRadar.SavedSearch',
        outputs_key_field='id',
        # outputs=response,
        raw_response=response
    )


def qradar_searches_list_command(client: Client, args: Dict):
    range_ = f'''items={args.get('range', DEFAULT_RANGE_VALUE)}'''
    filter_ = args.get('filter')

    response = client.qradar_searches_list(range_, filter_)

    return CommandResults(
        # readable_output=human_readable,
        outputs_prefix='QRadar.Search',
        outputs_key_field='id',
        # outputs=response,
        raw_response=response
    )

def qradar_search_create_command(client: Client, args: Dict):
    query_expression = args.get('query_expression')
    saved_search_id = args.get('saved_search_id')

    response = client.qradar_search_create(query_expression, saved_search_id)
    # QRadar.Search

    return CommandResults(
        # readable_output=human_readable,
        outputs_prefix='QRadar.Search',
        outputs_key_field='search_id',
        # outputs=response,
        raw_response=response
    )


# def qradar_search_status_get_command
# def qradar_search_results_get_command

# waiting on value explanation
# def qradar_reference_sets_list_command

def qradar_reference_set_create_command(client: Client, args: Dict, ref_name: Optional[str],
                                        element_type: Optional[str],
                                        timeout_type: Optional[str], time_to_live: Optional[str]):
    ref_name = args.get('ref_name')
    element_type = args.get('element_type')
    timeout_type = args.get('timeout_type')
    time_to_live = args.get('time_to_live')

    response = client.qradar_reference_set_create(ref_name, element_type, timeout_type, time_to_live)
    # QRadar.ReferenceSet

    return CommandResults(
        # readable_output=human_readable,
        outputs_prefix='QRadar.ReferenceSet',
        outputs_key_field='name',
        # outputs=response,
        raw_response=response
    )


def qradar_reference_set_delete_command(client: Client, args: Dict):
    ref_name = args.get('ref_name')

    response = client.qradar_reference_set_delete(ref_name)
    # maybe add output for the task to be monitored
    raise NotImplementedError


# unsure about the date value def qradar_reference_set_value_upsert_command(self, ref_name: Optional[str],
# value: Optional[str], source: Optional[str], date_value: Optional[str]):

def qradar_reference_set_value_delete_command(client: Client, args: Dict):
    ref_name = args.get('ref_name')
    value = args.get('value')

    response = client.qradar_reference_set_value_delete(ref_name, value)
    human_readable = f'### value: {value} of reference: {ref_name} was deleted successfully'
    return CommandResults(
        readable_output=human_readable,
        raw_response=response
    )


def qradar_domains_list_command(client: Client, args: Dict):
    domain_id = args.get('domain_id')
    range_ = f'''items={args.get('range', DEFAULT_RANGE_VALUE)}'''
    filter_ = args.get('filter')

    response = client.qradar_domains_list(domain_id, range_, filter_)
    # QRadar.Domain

    return CommandResults(
        # readable_output=human_readable,
        outputs_prefix='QRadar.Domain',
        outputs_key_field='id',
        # outputs=response,
        raw_response=response
    )


# discuss with arseny
# def qradar_indicators_upload_command

def qradar_geolocations_for_ip_get_command(client: Client, args: Dict, ips: Optional[str]):
    ips = argToList(args.get('ips'))
    if not ips:
        raise DemistoException('''IPs list cannot be empty for command 'qradar-geolocations-for-ip-get'.''')
    filter_ = f'''ip_address IN ({','.join(ips)})'''

    response = client.qradar_geolocations_for_ip_get(filter_)
    # QRadar.GeoforIP

    return CommandResults(
        # readable_output=human_readable,
        outputs_prefix='QRadar.GeoForIP',
        outputs_key_field='ip_address',
        # outputs=response,
        raw_response=response
    )


def qradar_log_sources_list_command(client: Client, args: Dict):
    range_ = f'''items={args.get('range', DEFAULT_RANGE_VALUE)}'''
    filter_ = args.get('filter')

    response = client.qradar_log_sources_list(range_, filter_)
    raise NotImplementedError


''' MAIN FUNCTION '''
"""
for removed versions
"Version (3.0) from header parameter (Version) has been removed and is no longer valid. Please refer to documentation 
for list of valid versions."
for unvalid versions
"Version (322.0123) from header parameter (Version) is not a valid version. Please refer to documentation for list
of valid versions."

Range argument
pattern: items=x-y
invalid range (items = 3-0)
"message": "Range of pages specified in \"Range\" header is negative. Non-negative page range must be specified."
"message": "Failed to parse Range header. The syntax of the Range header must follow this pattern: items=x-y"
 (items=-3-2)
 {
    "http_response": {
        "code": 422,
        "message": "The request was well-formed but was unable to be followed due to semantic errors"
    },
    "code": 36,
    "description": "",
    "details": {},
    "message": "Failed to parse Range header. The syntax of the Range header must follow this pattern: items=x-y"
}
 
get offense by id
returns a dict (not a list) containing the offense details


update offense

closing offense without closing_reason_id
{
    "http_response": {
        "code": 422,
        "message": "The request was well-formed but was unable to be followed due to semantic errors"
    },
    "code": 1005,
    "description": "A request parameter is not valid.",
    "details": {},
    "message": "closing_reason_id must be provided when closing an offense."
}

unknown status
{
    "http_response": {
        "code": 422,
        "message": "The request was well-formed but was unable to be followed due to semantic errors"
    },
    "code": 11,
    "description": "",
    "details": {},
    "message": "Failed to transform user query parameter \"status\" with a content type of \"TEXT_PLAIN\""
}



qradar-closing-reasons-list + by id
id - returns a dict, list - returns list of dicts

notes + notes id

not found note id

create note

empty note_text
{
    "http_response": {
        "code": 422,
        "message": "The request was well-formed but was unable to be followed due to semantic errors"
    },
    "code": 8,
    "description": "",
    "details": {},
    "message": "Missing required parameter \"note_text\" from query parameters"
}
example result
{
    "note_text": "asd",
    "create_time": 1612962518474,
    "id": 2,
    "username": "API_user: demisto"
}


rules + rule by id
list returns list of dicts, id returns dict

rules group list + by id
list returns list of dicts, id returns dict

saved searches list + id

searches list + id

create search
exactly one argument should be provided
{
    "http_response": {
        "code": 422,
        "message": "The request was well-formed but was unable to be followed due to semantic errors"
    },
    "code": 1005,
    "description": "A request parameter is not valid.",
    "details": {},
    "message": "Exactly one parameter is required."
}

search results get not found search id

qradar reference set by name

create reference set
empty
{
    "http_response": {
        "code": 422,
        "message": "The request was well-formed but was unable to be followed due to semantic errors"
    },
    "code": 8,
    "description": "",
    "details": {},
    "message": "Missing required parameter \"name\" from query parameters"
}
name only
{
    "http_response": {
        "code": 422,
        "message": "The request was well-formed but was unable to be followed due to semantic errors"
    },
    "code": 8,
    "description": "",
    "details": {},
    "message": "Missing required parameter \"element_type\" from query parameters"
}
unknown element type
{
    "http_response": {
        "code": 422,
        "message": "The request was well-formed but was unable to be followed due to semantic errors"
    },
    "code": 11,
    "description": "",
    "details": {},
    "message": "Failed to transform user query parameter \"element_type\" with a content type of \"TEXT_PLAIN\""
}

unknown timeout type
{
    "http_response": {
        "code": 422,
        "message": "The request was well-formed but was unable to be followed due to semantic errors"
    },
    "code": 11,
    "description": "",
    "details": {},
    "message": "Failed to transform user query parameter \"timeout_type\" with a content type of \"TEXT_PLAIN\""
}

delete reference set
return on success
{
    "created_by": "demisto",
    "created": 1612971240237,
    "name": "Reference Data Deletion Task",
    "modified": 1612971240927,
    "started": null,
    "completed": null,
    "id": 71,
    "message": "Searching for items that depend on the Reference Data.",
    "status": "QUEUED"
}
Response Description
A status ID to retrieve the reference data set's deletion or purge status with at 
/api/system/task_management/tasks/{status_id}. You can also find the url in the Location header

add or update reference set
empty
{
    "http_response": {
        "code": 422,
        "message": "The request was well-formed but was unable to be followed due to semantic errors"
    },
    "code": 8,
    "description": "",
    "details": {},
    "message": "Missing required parameter \"value\" from query parameters"
}

upsert

value is in
    "data": [
        {
            "last_seen": 1612971683681,
            "first_seen": 1612971630849,
            "source": "reference data api",
            "value": "1.2.3.4",
            "domain_id": null
        }
    ],

unknown namepsace
{
    "http_response": {
        "code": 422,
        "message": "The request was well-formed but was unable to be followed due to semantic errors"
    },
    "code": 11,
    "description": "",
    "details": {},
    "message": "Failed to transform user query parameter \"namespace\" with a content type of \"TEXT_PLAIN\""
}
giving tenant
{
    "http_response": {
        "code": 422,
        "message": "The request was well-formed but was unable to be followed due to semantic errors"
    },
    "code": 1012,
    "description": "The namespace value of SHARED was expected",
    "details": {},
    "message": "Admin user can only access shared namespace"
}

config management domains

delete reference value

upload indicators
data not included
{
    "http_response": {
        "code": 422,
        "message": "The request was well-formed but was unable to be followed due to semantic errors"
    },
    "code": 10,
    "description": "",
    "details": {},
    "message": "Request body must be populated for body parameter \"data\""
}
{
    "http_response": {
        "code": 500,
        "message": "Unexpected internal server error"
    },
    "code": 1020,
    "description": "An error occurred during the attempt to add or update data in the reference map.",
    "details": {},
    "message": "Adding/updating data to Map test_aas failed"
}

geolocation
syntax
ip_address = "127.0.0.1"
ip_address IN ( "127.0.0.1", "127.0.0.2" )

log sources list
too strong
{
    "http_response": {
        "code": 422,
        "message": "The request was well-formed but was unable to be followed due to semantic errors"
    },
    "code": 1003,
    "description": "The specified encryption strength is not available. Consider installing \"Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy\" or using a weaker encryption.",
    "details": {},
    "message": "The specified encryption strength is not available. Consider installing \"Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy\" or using a weaker encryption."
}
"""


def main() -> None:
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    base_url = urljoin(params.get('base_url'),'/api')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    api_version = params.get('api_version')
    if float(api_version) < MINIMUM_API_VERSION:
        raise DemistoException('Minimum API version is {MINIMUM_API_VERSION}')
    credentials = params.get('credentials')

    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            api_version=api_version,
            credentials=credentials)

        if command == 'test-module':
            result = test_module_command(client)
            return_results(result)

        elif command == 'fetch-incidents':
            raise NotImplementedError

        elif command == 'qradar-offences-list':
            return_results(qradar_offences_list_command(client, args))

        elif command == 'qradar-offence-update':
            return_results(qradar_offence_update_command(client, args))

        elif command == 'qradar-closing-reasons':
            return_results(qradar_closing_reasons_list_command(client, args))

        elif command == 'qradar-offence-notes-list':
            return_results(qradar_offence_notes_list_command(client, args))

        elif command == 'qradar-offence-note-create':
            return_results(qradar_offence_notes_create_command(client, args))

        # elif command == 'qradar-rules-list':
        #     return_results(qradar_rules_list_command)
        # QRadar.Rule

        elif command == 'qradar-rule-groups-list':
            return_results(qradar_rule_groups_list_command(client, args))

        elif command == 'qradar-assets-list':
            return_results(qradar_assets_list_command(client, args))
        # QRadar.Asset

        elif command == 'qradar-saved-searches-list':
            return_results(qradar_saved_searches_list_command(client, args))

        # elif command == 'qradar-searches-list':
        #     return_results(qradar_searches_list_command(client, args))
        # QRadar.Search

        elif command == 'qradar-search-create':
            return_results(qradar_search_create_command(client, args))

        # might be united with searches list
        # elif command == 'qradar-search-status-get':
        #     return_results(qradar_search_status_get(client, args))
        # QRadar.SearchStatus

        # elif command == 'qradar-search-results-get':
        #     return_results(qradar_search_results_get_command(client, args))
        # QRadar.SearchResult

        # elif command == 'qradar-reference-sets-list':
        #     return_results(qradar_reference_sets_list_command(client, args))
        # QRadar.ReferenceSet

        elif command == 'qradar-reference-set-create':
            return_results(qradar_reference_set_create_command(client, args))

        elif command == 'qradar-reference-set-delete':
            return_results(qradar_reference_set_delete_command(client, args))

        # elif command == 'qradar-reference-set-value-upsert':
        #     return_results(qradar_reference_set_value_upsert(client, args))
        # QRadar.ReferenceSetValue

        elif command == 'qradar-reference-set-value-delete':
            return_results(qradar_reference_set_value_delete_command(client, args))

        elif command == 'qradar-domains-list':
            return_results(qradar_domains_list_command(client, args))

        # elif command == 'qradar-indicators-upload':
        #     return_results(qradar_indicators_upload_command(client, args))
        # QRadar.Indicator

        elif command == 'qradar-geolocations-for-ip-get':
            return_results(qradar_geolocations_for_ip_get_command(client, args))

        elif command == 'qradar-log-sources-list':
            return_results(qradar_log_sources_list_command(client, args))

        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
