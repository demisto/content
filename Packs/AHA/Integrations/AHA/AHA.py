from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
from enum import Enum


# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]  # pylint: disable=no-member

''' CONSTANTS '''
REPLACE = 'replace'
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
URL_SUFFIX_PATTERN = f'/products/{REPLACE}/'
EDIT_FIELDS = ['id', 'reference_num', 'name', 'description', 'workflow_status', 'created_at']
DEFAULT_FIELDS = ['reference_num', 'name', 'id', 'created_at']
FEATURE_FIELDS = ['ideas', 'test']

''' AHA ENUM'''


class AHA_TYPE(Enum):
    IDEAS = 1
    FEATURES = 2

    def get_url_suffix(self) -> str:
        if (self == AHA_TYPE.IDEAS):
            return 'ideas/'
        else:
            return 'features/'

    def get_type_plural(self) -> str:
        if (self == AHA_TYPE.IDEAS):
            return 'ideas'
        else:
            return 'features'

    def get_type_singular(self) -> str:
        if (self == AHA_TYPE.IDEAS):
            return 'idea'
        else:
            return 'feature'

    def get_type_for_outputs(self) -> str:
        if (self == AHA_TYPE.IDEAS):
            return 'Idea'
        else:
            return 'Feature'


''' CLIENT CLASS '''


class Client(BaseClient):
    url = ''

    def __init__(self,
                 headers: dict,
                 base_url: str,
                 proxy: bool,
                 verify: bool,
                 url: str):
        super().__init__(base_url=base_url, proxy=proxy, verify=verify, headers=headers)
        self.url = url
        self._headers['Content-Type'] = 'application/json'

    def get(self,
            aha_type: AHA_TYPE,
            name: str,
            fields: str,
            from_date: str,
            page: str,
            per_page: str) -> dict:
        """
        Retrieves a list of features/ideas from AHA
        Args:
            aha_type: determine what to get ideas or features using AHA_TYPE Enum.
            name: str if given it will fetch the feature/idea specified. if not, it will fetch all features/ideas.
            fields: str optional feature/idea fields to retrieve from the service.
            from_date: str format: YYYY-MM-DD get features/ideas created after from_date.
            page: str pagination specify the number of the page.
            per_page: str pagination specify the maximum number of features/ideas per page.
        """
        headers = self._headers
        params = {
            'updated_since': from_date,
            'fields': fields,
            'page': page,
            'per_page': per_page,
        }
        return self._http_request(method='GET',
                                  url_suffix=f'{self.url}{aha_type.get_url_suffix()}{name}',
                                  headers=headers, params=params, resp_type='json')

    def edit(self, aha_object_name: str, aha_type: AHA_TYPE, fields: dict) -> dict:
        """
        Updates fields in a feature/idea from AHA
        Args:
            aha_object_name: str idea to update
            aha_type: determine what to edit ideas or features using AHA_TYPE Enum.
            fields: Dict fields to update
        """
        payload = build_edit_idea_req_payload() if aha_type == AHA_TYPE.IDEAS else build_edit_feature_req_payload(fields=fields)
        demisto.debug(f'Edit {aha_type.get_type_singular()} payload: {payload}')
        fields = ','.join(EDIT_FIELDS)
        url_suffix = f'{self.url}{aha_type.get_url_suffix()}{aha_object_name}?fields={fields}'
        return self._http_request(method='PUT', url_suffix=url_suffix, resp_type='json', json_data=payload)


''' HELPER FUNCTIONS'''


def build_edit_feature_req_payload(fields: dict):
    payload: dict = {'feature': {}}
    for field in fields:
        feature = payload.get('feature', {})
        if field == 'status':
            workflow_status = {'name': fields[field]}
            feature['workflow_status'] = workflow_status
        else:
            feature[field] = fields[field]
    return payload


def build_edit_idea_req_payload():
    payload: dict = {'idea': {}}
    idea = payload.get('idea', {})
    idea['workflow_status'] = "Shipped"
    return payload


def extract_ideas_from_feature(ideas: List) -> List:
    ret_list: list[str] = []
    for idea in ideas:
        ret_list.append(idea.get('reference_num'))
    return ret_list


def parse_multiple_objects(aha_objects: dict, fields: List) -> List:
    res_list = []
    for res in aha_objects:
        curr = parse_single_object(res, fields=fields)
        res_list.extend(curr)
    demisto.debug(f'Parsed response fields: {res_list}')
    return res_list


def parse_single_object(aha_object: dict, fields: List = DEFAULT_FIELDS) -> List:
    ret_dict = {}
    for curr in fields:
        if curr == 'description':
            ret_dict[curr] = aha_object.get(curr, {}).get('body')
        elif curr == 'workflow_status':
            ret_dict[curr] = aha_object.get(curr, {}).get('name')
        elif curr == 'ideas':
            ret_dict[curr] = extract_ideas_from_feature(aha_object.get(curr, {}))
        else:
            ret_dict[curr] = aha_object.get(curr, '')
    return [ret_dict]


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'"""

    message: str = ''
    try:
        result = client.get(AHA_TYPE.FEATURES, '', '', '2020-01-01', page='1', per_page='1')
        if result:
            message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = 'Authorization Error: make sure that the API Key is setup correctly.'
        else:
            raise e
    return message


def get_command(client: Client,
                aha_type: AHA_TYPE,
                from_date: str,
                aha_object_name: str = '',
                fields: str = '',
                page: str = '1',
                per_page: str = '30') -> CommandResults:
    message: List = []
    fields_list: List = DEFAULT_FIELDS + argToList(fields)
    if aha_type == AHA_TYPE.FEATURES:
        fields_list.extend(FEATURE_FIELDS)
    req_fields = ','.join(fields_list)
    response = client.get(aha_type=aha_type, name=aha_object_name, fields=req_fields,
                          from_date=from_date, page=page, per_page=per_page)
    if response:
        if aha_type.get_type_plural() in response:
            message = parse_multiple_objects(response[aha_type.get_type_plural()], fields_list)
        else:
            message = parse_single_object(response[aha_type.get_type_singular()], fields_list)
        human_readable = tableToMarkdown(f'Aha! get {aha_type.get_type_plural()}',
                                         message,
                                         removeNull=True)
    else:
        human_readable = ''
        demisto.debug(f"{response=} -> {human_readable=}")
    return CommandResults(
        outputs_prefix=f'AHA.{aha_type.get_type_for_outputs()}',
        outputs_key_field='id',
        outputs=message,
        raw_response=response,
        readable_output=human_readable
    )


def edit_command(client: Client,
                 aha_type: AHA_TYPE,
                 aha_object_name: str,
                 fields: str = '{}') -> CommandResults:
    message: List = []
    fieldsDict = json.loads(fields)
    response = client.edit(aha_object_name=aha_object_name, aha_type=aha_type, fields=fieldsDict)
    if response:
        message = parse_single_object(response[aha_type.get_type_singular()], fields=EDIT_FIELDS)
        human_readable = tableToMarkdown(f'Aha! edit {aha_type.get_type_singular()}',
                                         message,
                                         removeNull=True)
    else:
        human_readable = ''
        demisto.debug(f"{response=} -> {human_readable=}")
    return CommandResults(
        outputs_prefix=f'AHA.{aha_type.get_type_for_outputs()}',
        outputs_key_field='id',
        outputs=message,
        readable_output=human_readable,
        raw_response=response
    )


''' MAIN FUNCTION '''


def main() -> None:

    params = demisto.params()
    base_url = urljoin(params['url'], '/api/v1')
    project_name = params.get('project_name', {})
    url = URL_SUFFIX_PATTERN.replace(REPLACE, project_name)
    api_key = params.get('api_key', {}).get('password', {})
    proxy = params.get('proxy', False)
    verify = not params.get('insecure', False)
    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        headers: dict = {'Authorization': f'Bearer {api_key}'}
        client = Client(
            headers=headers,
            base_url=base_url,
            proxy=proxy,
            verify=verify,
            url=url)
        command = demisto.command()
        args = demisto.args()

        if command == 'test-module':
            result = test_module(client)
            return_results(result)
        elif command == 'aha-get-features':
            command_result = get_command(client, aha_type=AHA_TYPE.FEATURES,
                                         aha_object_name=args.pop('feature_name', ''), **args)
            return_results(command_result)
        elif command == 'aha-edit-feature':
            command_result = edit_command(client, aha_type=AHA_TYPE.FEATURES,
                                          aha_object_name=args.pop('feature_name', ''), **args)
            return_results(command_result)
        elif command == 'aha-get-ideas':
            command_result = get_command(client=client, aha_type=AHA_TYPE.IDEAS,
                                         aha_object_name=args.pop('idea_name', ''), **args)
            return_results(command_result)
        elif command == 'aha-edit-idea':
            command_result = edit_command(client, aha_type=AHA_TYPE.IDEAS,
                                          aha_object_name=args.pop('idea_name', ''), **args)
            return_results(command_result)
        else:
            raise NotImplementedError(f'{command} command is not implemented.')
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
