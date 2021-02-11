from typing import Tuple

import urllib3

from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

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

    def qradar_offences_list(self, offence_id: Optional[int], range_: Optional[str], filter_: Optional[str]):
        id_suffix = f'/{offence_id}' if offence_id else ''
        range_header = {'Range': f'items={range_}'} if range_ else None
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

    def qradar_closing_reasons_list(self, closing_reason_id: Optional[int], range_: Optional[str],
                                    filter_: Optional[str]):
        id_suffix = f'/{closing_reason_id}' if closing_reason_id else ''
        range_header = {'Range': f'items={range_}'} if range_ else None
        return self.http_request(
            method='GET',
            url_suffix=f'/siem/offense_closing_reasons{id_suffix}',
            additional_headers=range_header,
            params=assign_params(filter=filter_)
        )

    def qradar_offence_notes_list(self, offence_id: Optional[int], note_id: Optional[int], range_: Optional[str],
                                  filter_: Optional[str]):
        note_id_suffix = f'/{note_id}' if note_id else ''
        range_header = {'Range': f'items={range_}'} if range_ else None
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

    def qradar_rule_groups_list(self, rule_group_id: Optional[int], range_: Optional[str], filter_: Optional[str]):
        id_suffix = f'/{rule_group_id}' if rule_group_id else ''
        range_header = {'Range': f'items={range_}'} if range_ else None
        return self.http_request(
            method='GET',
            url_suffix=f'/analytics/rule_groups{id_suffix}',
            additional_headers=range_header,
            params=assign_params(filter=filter_)
        )

    # waiting on asset ID API call
    # def qradar_assets_list(self, asset):

    def qradar_saved_searches_list(self, rule_group_id: Optional[int], range_: Optional[str], filter_: Optional[str]):
        id_suffix = f'/{rule_group_id}' if rule_group_id else ''
        range_header = {'Range': f'items={range_}'} if range_ else None
        return self.http_request(
            method='GET',
            url_suffix=f'/ariel/saved_searches{id_suffix}',
            additional_headers=range_header,
            params=assign_params(filter=filter_)
        )

    # waiting to see if range/filter should be added, and unite with status-get
    # def qradar_searches_list

    def qradar_search_create(self, query_expression: Optional[str], saved_search_id: Optional[str]):
        return self.http_request(
            method='POST',
            url_suffix='/ariel/searches',
            params=assign_params(
                query_expression=query_expression,
                saved_search_id=saved_search_id
            )
        )

    # def qradar_search_status_get
    # def qradar_search_results_get

    # waiting on value explanation
    # def qradar_reference_sets_list

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

    def qradar_set_delete(self, ref_name: Optional[str]):
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

    def qradar_domains_list(self, domain_id: Optional[int], range_: Optional[str], filter_: Optional[str]):
        id_suffix = f'/{domain_id}' if domain_id else ''
        range_header = {'Range': f'items={range_}'} if range_ else None
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

    def qradar_log_sources_list(self, range_: Optional[str], filter_: Optional[str]):
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


def qradar_error_handler(response: Dict):
    pass


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
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
 
 filter parameter
 good filter - {filter : events_count=5}
 each API Endpoint has FilterAble on the fields which can be used for filter
 if trying to filter on non filtered option
     "description": "The filter parameter is not valid.",
    "details": {},
    "message": "The filter parameter is not valid."
 wrong filter
 "message": "A filter parameter was invalid. Please make sure that the syntax is correct: Error Parsing filter"
 
 
get offense by id
returns a dict (not a list) containing the offense details
unknown id
{
    "http_response": {
        "code": 404,
        "message": "We could not find the resource you requested."
    },
    "code": 1002,
    "description": "No offense was found for the provided offense_id.",
    "details": {},
    "message": "No offense was found for the provided offense_id."
}

update offense

unknown offense id
{
    "http_response": {
        "code": 404,
        "message": "We could not find the resource you requested."
    },
    "code": 1002,
    "description": "No offense was found for the provided offense_id.",
    "details": {},
    "message": "Offense not found for offense_id: 32"
}

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

assigning to unknown user
{
    "http_response": {
        "code": 422,
        "message": "The request was well-formed but was unable to be followed due to semantic errors"
    },
    "code": 1005,
    "description": "A request parameter is not valid.",
    "details": {},
    "message": "assigned_to value griklin is not a valid user."
}


qradar-closing-reasons-list + by id
id - returns a dict, list - returns list of dicts
unfound id
{
    "http_response": {
        "code": 404,
        "message": "We could not find the resource you requested."
    },
    "code": 1002,
    "description": "No closing reason was found for the provided closing_reason_id.",
    "details": {},
    "message": "Closing Reason not found for closing_reason_id: 12"
}

notes + notes id
not found offense id
{
    "http_response": {
        "code": 404,
        "message": "We could not find the resource you requested."
    },
    "code": 1002,
    "description": "No offense was found for the provided offense_id.",
    "details": {},
    "message": "Offense not found for offense_id: 142"
}
not found note id
{
    "http_response": {
        "code": 404,
        "message": "We could not find the resource you requested."
    },
    "code": 1003,
    "description": "No note was found for the provided note_id.",
    "details": {},
    "message": "Note not found for note_id: 2"
}


create note
not found offense id
{
    "http_response": {
        "code": 404,
        "message": "We could not find the resource you requested."
    },
    "code": 1002,
    "description": "No offense was found for the provided offense_id.",
    "details": {},
    "message": "Offense not found for offense_id: 62"
}

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
not found id
{
    "http_response": {
        "code": 404,
        "message": "We could not find the resource you requested."
    },
    "code": 1002,
    "description": "The rule does not exist.",
    "details": {},
    "message": "No Custom Rule found with id: 1"
}
list returns list of dicts, id returns dict


rules group list + by id
list returns list of dicts, id returns dict
not found id
{
    "http_response": {
        "code": 404,
        "message": "We could not find the resource you requested."
    },
    "code": 1002,
    "description": "The rule group does not exist.",
    "details": {},
    "message": "No group found with id: 321"
}

saved searches list + id
not found id
{
    "http_response": {
        "code": 404,
        "message": "We could not find the resource you requested."
    },
    "code": 1002,
    "description": "The Ariel saved search does not exist.",
    "details": {},
    "message": "No Saved Search found with id: 277612"
}

searches list + id
not found id
{
    "http_response": {
        "code": 404,
        "message": "We could not find the resource you requested."
    },
    "code": 1002,
    "description": "The search does not exist.",
    "details": {},
    "message": "Query e5a70925-87f5-4a93-ab6a-05391540d7a6axz does not exist"
}

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
{
    "http_response": {
        "code": 404,
        "message": "We could not find the resource you requested."
    },
    "code": 1002,
    "description": "The search does not exist.",
    "details": {},
    "message": "Query 1fb92c78-23f8-46f2-a931-6c37228a0382d does not exist"
}

qradar reference set by name
not found name
{
    "http_response": {
        "code": 404,
        "message": "We could not find the resource you requested."
    },
    "code": 1002,
    "description": "The reference set does not exist.",
    "details": {},
    "message": "Mail Sesrvers does not exist"
}

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
name exists
{
    "http_response": {
        "code": 409,
        "message": "The request could not be completed due to a conflict with the current state of the resource"
    },
    "code": 1004,
    "description": "The reference set could not be created, the name provided is already in use. Please change the name and try again.",
    "details": {},
    "message": "The name test_a is already in use"
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
invalid time to live
{
    "http_response": {
        "code": 422,
        "message": "The request was well-formed but was unable to be followed due to semantic errors"
    },
    "code": 1005,
    "description": "A request parameter is not valid",
    "details": {},
    "message": "Invalid time to live interval 12xzd"
}

delete reference set
not found reference name
{
    "http_response": {
        "code": 404,
        "message": "We could not find the resource you requested."
    },
    "code": 1002,
    "description": "The reference set does not exist.",
    "details": {},
    "message": "Mail Sesrvers does not exist"
}
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
invalid value
{
    "http_response": {
        "code": 422,
        "message": "The request was well-formed but was unable to be followed due to semantic errors"
    },
    "code": 1005,
    "description": "A request parameter is not valid",
    "details": {},
    "message": "Invalid IP value: test"
}
upsert
element type date not matching
{
    "http_response": {
        "code": 422,
        "message": "The request was well-formed but was unable to be followed due to semantic errors"
    },
    "code": 1005,
    "description": "A request parameter is not valid",
    "details": {},
    "message": "Invalid DATE value: 1.2.3.4"
}

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
    
unknown reference name
{
    "http_response": {
        "code": 404,
        "message": "We could not find the resource you requested."
    },
    "code": 1002,
    "description": "The reference set does not exist",
    "details": {},
    "message": "Mail Serversa does not exist"
}
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
unknown domain ID
{
    "http_response": {
        "code": 404,
        "message": "We could not find the resource you requested."
    },
    "code": 1002,
    "description": "No domain was found for the provided domain id.",
    "details": {},
    "message": "Domain ID 1 does not exist"
}


delete reference value
not IP
{
    "http_response": {
        "code": 422,
        "message": "The request was well-formed but was unable to be followed due to semantic errors"
    },
    "code": 1005,
    "description": "A request parameter is not valid",
    "details": {},
    "message": "Invalid IP value: as"
}
ip not found in shared
    "http_response": {
        "code": 404,
        "message": "We could not find the resource you requested."
    },
    "code": 1003,
    "description": "The record does not exist in the reference set",
    "details": {},
    "message": "Set Mail Servers does not contain value 1.2.3.5 in shared"
}

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
"""


def main() -> None:
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    credentials = params.get('credentials')

    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        client = Client(
            base_url='TODO',
            verify=verify_certificate,
            proxy=proxy,
            credentials=credentials)

        if demisto.command() == 'test-module':
            result = test_module(client)
            return_results(result)

        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
