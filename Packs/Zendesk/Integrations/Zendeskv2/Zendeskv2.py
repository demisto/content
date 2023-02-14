import demistomock as demisto
from CommonServerPython import *
from copy import copy
from functools import lru_cache
from urllib.parse import urlencode
from urllib3 import disable_warnings
from requests.exceptions import HTTPError
from requests import Response
from typing import Callable, Iterable, Optional, List, Union, Iterator, Dict


STR_OR_STR_LIST = Union[str, List[str]]
MAX_PAGE_SIZE = 100
USER_CONTEXT_PATH = "Zendesk.User"
USERS_HEADERS = ['id', 'name', 'email', 'role', 'active', 'external_id', 'created_at', 'updated_at']
ORGANIZATIONS_HEADERS = ['id', 'name', 'domain_names', 'tags', 'external_id', 'created_at', 'updated_at']
TICKETS_HEADERS = ['id', 'subject', 'description', 'priority', 'status', 'assignee_id', 'created_at', 'updated_at', 'external_id']
COMMENTS_HEADERS = ['id', 'body', 'created_at', 'public', 'attachments']
ATTACHMENTS_HEADERS = ['id', 'file_name', 'content_url', 'size', 'content_type']
ARTICLES_HEADERS = ['body']
ROLES = ['end-user', 'admin', 'agent']
ROLE_TYPES = {
    'custom_agent': 0,
    'light_agent': 1,
    'chat_agent': 2,
    'chat_agent_contributor': 3,
    'admin': 4,
    'billing_admin': 5,
}
TICKET_FILTERS = ['assigned', 'requested', 'ccd', 'followed', 'recent']
CURSOR_SORTS = {
    'id_asc': 'id',
    'status_asc': 'status',
    'updated_at_asc': 'updated_at',
    'id_desc': '-id',
    'status_desc': '-status',
    'updated_at_desc': '-updated_at'
}
TICKET_TYPE = ['problem', 'incident', 'question', 'task']
TICKET_STATUS = ['open', 'pending', 'hold', 'solved', 'closed']
TICKET_PRIORITY = ['urgent', 'high', 'normal', 'low']
PRIORITY_MAP = {
    'urgent': IncidentSeverity.CRITICAL,
    'high': IncidentSeverity.HIGH,
    'normal': IncidentSeverity.MEDIUM,
    'low': IncidentSeverity.LOW
}
params = demisto.params()   # pylint: disable=W9016
MIRROR_USER_AGENT = 'XSOAR mirror'
MIRROR_DIRECTION = {
    'Incoming': 'In',
    'Outgoing': 'Out',
    'Incoming And Outgoing': 'Both'
}.get(params.get('mirror_direction'))
FIELDS_TO_REMOVE_FROM_MIROR_IN = ['url', 'id', 'created_at']
DEFAULT_UPLOAD_FILES_COMMENT = 'Uploaded from XSOAR.'
MIRROR_TAGS = params.get('mirror_tags') or []
CLOSE_INCIDENT = argToBoolean(params.get('close_incident', False))
INTEGRATION_INSTANCE = demisto.integrationInstance()
CACHE = None


class CacheManager:

    def __init__(self, zendesk_client):
        self._data = None
        self._zendesk_client: ZendeskClient = zendesk_client

    @staticmethod
    def zendesk_clear_cache(**kwargs):
        demisto.setIntegrationContext({})
        return 'Cache clear done.'

    def save(self):
        if self._data:
            demisto.setIntegrationContext(self._data)

    def replace_ids_change(self, data: Dict, organization_fields: List[str] = [], user_fields: List[str] = []):
        for fields, get_func in [(organization_fields, self.organization), (user_fields, self.user)]:
            for field in fields:
                obj_id = data.get(field)
                if obj_id:
                    field = field.replace('_id', '')
                    if isinstance(obj_id, List):
                        data[field] = list(map(get_func, obj_id))
                    else:
                        data[field] = get_func(obj_id)
        return data

    @property
    def data(self):
        if self._data is None:
            self._data = demisto.getIntegrationContext()
        return self._data

    @lru_cache
    def user(self, user_id: int) -> str:
        return self._generic_get_by_id('users', user_id, self._zendesk_client._get_user_by_id, 'email')

    @lru_cache
    def organization(self, organization_id: int) -> str:
        return self._generic_get_by_id('organizations', organization_id, self._zendesk_client._get_organization_by_id, 'name')

    @lru_cache
    def organization_name(self, organization_name: str) -> Union[int, Dict]:
        organizations = self._zendesk_client._get_organizations_by_name(organization_name)
        ids = ','.join(map(lambda x: str(x['id']), organizations))
        assert len(organizations) == 1, \
            f"found {len(organizations)} organizations with name {organization_name} and ids {ids}"

        return organizations[0]['id']

    def _generic_get_by_id(self, data_type: str, obj_id: int, data_get: Callable, val_field: str):
        self.data[data_type] = self.data.get(data_type, {})
        try:
            return self.data[data_type][obj_id]
        except KeyError:
            pass

        try:
            user_email = data_get(obj_id)[val_field] or obj_id
            self.data[data_type][obj_id] = user_email
            return user_email
        except:  # noqa # lgtm[py/]
            return obj_id


def datetime_to_iso(date: datetime) -> str:
    return date.strftime('%Y-%m-%dT%H:%M:%SZ')


def prepare_kwargs(kwargs: Dict[str, Any], ignore_args: STR_OR_STR_LIST = [],
                   str_args: STR_OR_STR_LIST = [],
                   list_args: STR_OR_STR_LIST = [],
                   bool_args: STR_OR_STR_LIST = [],
                   int_args: STR_OR_STR_LIST = [],
                   json_args: STR_OR_STR_LIST = []) -> Dict[str, Any]:
    return_kwargs = dict()

    for arg in ignore_args if isinstance(ignore_args, List) else [ignore_args]:
        if arg in kwargs:
            return_kwargs[arg] = kwargs[arg]

    for arg in str_args if isinstance(str_args, List) else [str_args]:
        if arg in kwargs:
            return_kwargs[arg] = str(kwargs[arg])

    for arg in list_args if isinstance(list_args, List) else [list_args]:
        if arg in kwargs:
            return_kwargs[arg] = argToList(kwargs[arg])

    for arg in bool_args if isinstance(bool_args, List) else [bool_args]:
        if arg in kwargs:
            return_kwargs[arg] = argToBoolean(kwargs[arg])

    for arg in int_args if isinstance(int_args, List) else [int_args]:
        if arg in kwargs:
            return_kwargs[arg] = int(kwargs[arg])

    for arg in json_args if isinstance(json_args, List) else [json_args]:
        if arg in kwargs:
            return_kwargs[arg] = kwargs[arg] if isinstance(kwargs[arg], Dict) else json.loads(kwargs[arg])

    return return_kwargs


def error_entry(error_msg: str) -> Dict[str, Any]:
    return {
        'Type': EntryType.ERROR,
        'ContentsFormat': EntryFormat.TEXT,
        'Contents': error_msg,
    }


def close_entry(reason: str) -> Dict[str, Any]:
    return {
        'Type': EntryType.NOTE,
        'Contents': {
            'dbotIncidentClose': True,
            'closeReason': reason
        },
        'ContentsFormat': EntryFormat.JSON
    }


class Validators:

    @staticmethod
    def _validate(val: Any, arg_name: str, allowed: Iterable[Any]):
        copy_value = argToList(val)
        for value in copy_value:
            assert value in allowed, f"'{val}' is not a valid {arg_name}.\nallowed {arg_name}s are '{','.join(allowed)}'"

    @staticmethod
    def validate_role(role: STR_OR_STR_LIST):
        Validators._validate(role, 'role', ROLES)

    @staticmethod
    def validate_role_type(role_type: str):
        Validators._validate(role_type, 'role type', ROLE_TYPES.keys())

    @staticmethod
    def validate_ticket_filter(ticket_filter: str):
        Validators._validate(ticket_filter, 'filter', TICKET_FILTERS)

    @staticmethod
    def validate_ticket_sort(ticket_sort: str):
        Validators._validate(ticket_sort, 'sort', CURSOR_SORTS.keys())

    @staticmethod
    def validate_ticket_type(ticket_type: str):
        Validators._validate(ticket_type, 'type', TICKET_TYPE)

    @staticmethod
    def validate_ticket_status(ticket_status: str):
        Validators._validate(ticket_status, 'status', TICKET_STATUS)

    @staticmethod
    def validate_ticket_priority(ticket_priority: str):
        Validators._validate(ticket_priority, 'priority', TICKET_PRIORITY)


class TicketEvents:

    def __init__(self, zendesk_client, after_cursor: str = None, tickets_list: List = []):
        self._client = zendesk_client
        self._demisto_params = demisto.params()  # pylint: disable=W9016
        self._tickets_list = tickets_list
        self._after_cursor = after_cursor
        self._last_fetch: Dict = {}

    def _get_all(self, **kwargs):
        return self._client._http_request('GET', url_suffix='incremental/tickets/cursor', params=kwargs)

    def next_run(self):
        next_run = {
            'after_cursor': self._last_fetch.get('after_cursor', self._after_cursor),
        }
        if self._tickets_list:
            next_run['tickets'] = self._tickets_list
        return next_run

    @abstractmethod
    def query_params(self):
        if after_cursor := self._last_fetch.get('after_cursor', self._after_cursor):
            return {'cursor': after_cursor}
        return {}

    def tickets(self, limit: int = 1000, params: Optional[Dict] = {}):
        yielded = 0
        if self._tickets_list:
            for _ in range(min(limit, len(self._tickets_list))):
                yield self._tickets_list.pop(0)
                yielded += 1
            if yielded >= limit:
                return

        res = self._get_all(**(self.query_params() | params))
        self._tickets_list = res.get('tickets', [])
        while True:
            self._after_cursor = res.get('after_cursor') or self._after_cursor
            for _ in range(min(limit - yielded, len(self._tickets_list))):
                yield self._tickets_list.pop(0)
                yielded += 1

            if res['end_of_stream']:
                return
            res = self._get_all(**(self.query_params() | params))


class UpdatedTickets(TicketEvents):

    def __init__(self, zendesk_client, last_update: int, last_run_data: Dict = {}):
        self._last_update = last_update
        super(UpdatedTickets, self).__init__(zendesk_client, last_run_data.get('after_cursor'))

    def query_params(self):
        params = super(UpdatedTickets, self).query_params()
        if not params:
            params['start_time'] = self._last_update
        return params

    def tickets(self):
        def filter_created_ticket(ticket: Dict):
            return ticket['created_at'] != ticket['updated_at']

        for ticket in filter(filter_created_ticket, super(UpdatedTickets, self).tickets()):
            yield ticket


class CreatedTickets(TicketEvents):

    def __init__(self, zendesk_client, last_run):
        after_cursor = last_run.get('after_cursor')
        self._latest_ticket_id = last_run.get('latest_ticket_id', 0)
        self._highest_ticket_id_in_current_run = 0
        super(CreatedTickets, self).__init__(zendesk_client, after_cursor, last_run.get('tickets', []))

    def next_run(self):
        next_run = super(CreatedTickets, self).next_run()
        next_run['latest_ticket_id'] = max(self._latest_ticket_id, self._highest_ticket_id_in_current_run)
        return next_run

    def query_params(self):

        params = super(CreatedTickets, self).query_params()
        if not params:
            params['start_time'] = int(dateparser.parse(        # type: ignore
                self._demisto_params.get('first_fetch', '3d')
            ).timestamp())

        params['exclude_deleted'] = True
        return params

    def tickets(self):
        limit = int(self._demisto_params.get('max_fetch', 50))
        ticket_types = self._demisto_params.get('ticket_types', [])
        ticket_types = None if 'all' in ticket_types else ticket_types

        def filter_updated_ticket(ticket: Dict):
            return ticket['id'] > self._latest_ticket_id and (not ticket_types or ticket.get('type') in ticket_types)

        for ticket in filter(filter_updated_ticket, super(CreatedTickets, self).tickets(limit=limit)):
            self._highest_ticket_id_in_current_run = max(ticket['id'], self._highest_ticket_id_in_current_run)
            yield ticket


class ZendeskClient(BaseClient):

    def __init__(self, base_url: str, username: Optional[str] = None, password: Optional[str] = None,
                 proxy: bool = False, verify: bool = True):
        base_url = urljoin(base_url, '/api/v2/')
        auth = headers = None
        if username and password:
            # auth = (f'{username}/token', password)
            auth = (username, password)
        elif password:
            headers = {'Authorization': f'Bearer {password}'}

        super(ZendeskClient, self).__init__(base_url, auth=auth, proxy=proxy, verify=verify, headers=headers)

    @staticmethod
    def error_handler(res: Response) -> None:
        res.raise_for_status()

    def _http_request(self, method: str, url_suffix: str = '', full_url: Optional[str] = None,  # type: ignore[override]
                      json_data: Optional[Dict] = None, params: Dict = None, data: Dict = None, content: bytes = None,
                      resp_type: str = 'json', return_empty_response: bool = False, **kwargs):

        if params:
            final_params_list = []
            for k, v in params.items():
                if isinstance(v, List):
                    for singel_v in v:
                        final_params_list.append(f'{k}[]={singel_v}')
                else:
                    final_params_list.append(f'{k}={v}')
            params_str = f'?{"&".join(final_params_list)}'
            if url_suffix:
                url_suffix = f'{url_suffix}{params_str}'
            if full_url:
                full_url = f'{full_url}{params_str}'

        return super(ZendeskClient, self)._http_request(method, url_suffix=url_suffix, full_url=full_url, json_data=json_data,
                                                        data=data or content, return_empty_response=return_empty_response,
                                                        resp_type=resp_type, error_handler=self.error_handler, **kwargs)

    def __cursor_pagination(self, url_suffix: str, data_field_name: str, params: Optional[Dict] = None,
                            limit: int = 50) -> Iterator[Dict]:
        # API docs here https://developer.zendesk.com/api-reference/ticketing/introduction/#using-cursor-pagination
        page_size = min(limit, MAX_PAGE_SIZE)
        next_link_section = 'next'
        count_data = 1
        paged_params = copy(params) if params is not None else {}
        paged_params['page[size]'] = page_size
        res = self._http_request('GET', url_suffix=url_suffix, params=paged_params)
        while True:
            for i in res[data_field_name]:
                yield i
                count_data += 1
                if count_data > limit:
                    return

            if not dict_safe_get(res, ['meta', 'has_more']):
                break

            res = self._http_request('GET', full_url=res['links'][next_link_section])

    def __get_spesific_page(self, url_suffix: str, data_field_name: str, page_size: int,
                            page_number: int, params: Optional[Dict] = None) -> Iterator[Dict]:
        # API docs here https://developer.zendesk.com/api-reference/ticketing/introduction/#using-offset-pagination
        page_size = min(page_size, MAX_PAGE_SIZE)
        paged_params = copy(params) if params is not None else {}
        paged_params['per_page'] = page_size
        paged_params['page'] = page_number
        for res in self._http_request('GET', url_suffix=url_suffix, params=paged_params)[data_field_name]:
            yield res

    def _paged_request(self, url_suffix: str, data_field_name: str, params: Optional[Dict] = None,
                       limit: int = 50, page_size: Optional[int] = None, page_number: Optional[int] = None) -> Iterator[Dict]:
        # validate parameters
        if page_size is not None and page_number is not None:
            return self.__get_spesific_page(url_suffix=url_suffix, data_field_name=data_field_name,
                                            params=params, page_size=int(page_size), page_number=int(page_number))
        elif page_size is not None or page_number is not None:
            raise AssertionError("you need to specify both 'page_size' and 'page_number'.")
        else:
            return self.__cursor_pagination(url_suffix=url_suffix, data_field_name=data_field_name,
                                            params=params, limit=int(limit))

    # ---- user releated functions ---- #

    @staticmethod
    def __command_results_zendesk_users(users: List[Dict]):
        role_types_reverse = {int_k: str_k for str_k, int_k in ROLE_TYPES.items()}

        def _iter_context(user: Dict):
            user = CACHE.replace_ids_change(user, ['organization_id'])  # type: ignore
            role_type = role_types_reverse.get(user.get('role_type'))  # type: ignore
            if role_type:
                user['role_type'] = role_type
            return user
        raw_results = copy(users)
        context = list(map(_iter_context, users))
        readable_outputs = tableToMarkdown(name='Zendek users:', t=context, headers=USERS_HEADERS,
                                           headerTransform=camelize_string)
        return CommandResults(outputs_prefix=USER_CONTEXT_PATH, outputs=context,
                              readable_output=readable_outputs, raw_response=raw_results)

    def _get_user_by_id(self, user_id: str):
        return self._http_request('GET', f'users/{user_id}')['user']

    def zendesk_user_list(self, user_id: Optional[STR_OR_STR_LIST] = None,
                          user_name: Optional[str] = None, role: Optional[Union[List[str], str]] = None,
                          **kwargs):
        users_field_name = 'users'
        results = []
        error_msgs = []

        if user_id is not None:
            users_list = []
            for single_user in argToList(user_id):
                try:
                    users_list.append(self._get_user_by_id(single_user))
                except Exception as e:
                    demisto.error(f'could not retrieve user: {single_user}\n{traceback.format_exc()}')
                    error_msgs.append(f'could not retrieve user: {single_user}\n{e}')
        elif user_name is not None:
            users_list = self._http_request('GET', 'users/autocomplete', params={'name': user_name})[users_field_name]
        else:
            params = prepare_kwargs(kwargs=kwargs, str_args='external_id')
            if role:
                role_list = argToList(role)
                Validators.validate_role(role_list)
                params['role'] = role_list[0] if len(role_list) == 1 else role_list
            users_list = list(self._paged_request('users', 'users', params=params, **kwargs))

        if users_list:
            results.append(self.__command_results_zendesk_users(users_list))

        if error_msgs:
            results.append(error_entry('\n'.join(error_msgs)))

        return results if results else 'No outputs.'

    @staticmethod
    def _handle_role_argument(role: Optional[str] = None, role_type: Optional[str] = None) -> Dict[str, Any]:
        role_params: Dict[str, Union[str, int]] = {}
        if role:
            Validators.validate_role(role)
            role_params['role'] = role
            if role_type is not None:
                assert role == 'agent', "You cannot use the 'role_type' argument if the selected role is not 'agent'"
                Validators.validate_role_type(role_type)
                role_params['role_type'] = ROLE_TYPES[role_type]
        return role_params

    def zendesk_user_create(self, name: str, email: str, role: Optional[str] = None, role_type: Optional[str] = None,
                            check_if_user_exists: bool = False, **kwargs):
        url_suffix = 'users/create' if argToBoolean(check_if_user_exists) else 'users/create_or_update'

        user_body = {
            'name': name,
            'email': email
        }

        if 'organization_name' in kwargs:
            assert 'organization_id' not in kwargs, "you can specify 'organization_id' or 'organization_name' not both."
            kwargs['organization_id'] = CACHE.organization_name(kwargs.pop('organization_name'))  # type: ignore

        user_body.update(prepare_kwargs(
            kwargs=kwargs,
            str_args=['phone', 'notes', 'details', 'external_id', 'locale', 'alias'],
            list_args='tags',
            int_args=['organization_id', 'default_group_id', 'custom_role_id'],
            bool_args='verified',
            json_args=['identities', 'user_fields']
        ))
        user_body.update(self._handle_role_argument(role=role, role_type=role_type))

        return self.__command_results_zendesk_users([
            self._http_request('POST', url_suffix=url_suffix, json_data={'user': user_body})['user']
        ])

    def zendesk_user_update(self, user_id: str, role: Optional[str] = None, role_type: Optional[str] = None, **kwargs):
        if 'organization_name' in kwargs:
            assert 'organization_id' not in kwargs, "you can specify 'organization_id' or 'organization_name' not both."
            kwargs['organization_id'] = CACHE.organization_name(kwargs.pop('organization_name'))  # type: ignore

        user_body = prepare_kwargs(
            kwargs=kwargs,
            str_args=['name', 'email', 'phone', 'notes', 'details', 'external_id', 'locale', 'alias'],
            list_args='tags',
            int_args=['organization_id', 'default_group_id', 'custom_role_id'],
            bool_args=['verified', 'suspended'],
            json_args=['identities', 'user_fields']
        )
        user_body.update(self._handle_role_argument(role=role or 'agent', role_type=role_type))

        return self.__command_results_zendesk_users([
            self._http_request('PUT', url_suffix=f'users/{user_id}', json_data={'user': user_body})['user']
        ])

    def zendesk_user_delete(self, user_id: str):    # pragma: no cover
        self._http_request('DELETE', url_suffix=f'users/{user_id}')
        return f'User deleted. (id: {user_id})'

    # ---- organization releated functions ---- #

    @staticmethod
    def __command_results_zendesk_organizations(organizations: List[Dict]):  # pragma: no cover
        readable_outputs = tableToMarkdown(name='Zendek organizations:', t=organizations, headers=ORGANIZATIONS_HEADERS,
                                           headerTransform=camelize_string)
        return CommandResults(outputs_prefix="Zendesk.Organization",
                              outputs=organizations, readable_output=readable_outputs)

    def _get_organization_by_id(self, organization_id: str) -> Dict[str, Any]:
        return self._http_request('GET', f'organizations/{organization_id}')['organization']

    def _get_organizations_by_name(self, organization_name: str) -> List[Dict[str, Any]]:
        return self._http_request('GET', 'organizations/autocomplete', params={'name': organization_name})['organizations']

    def zendesk_organization_list(self, organization_id: Optional[str] = None, **kwargs):

        if organization_id:
            organizations = [self._get_organization_by_id(organization_id)]
        else:
            organizations = list(self._paged_request(url_suffix='organizations', data_field_name='organizations', **kwargs))

        return self.__command_results_zendesk_organizations(organizations)

    # ---- ticket releated functions ---- #

    @staticmethod
    def __ticket_context(ticket: Dict[str, Any]):
        return CACHE.replace_ids_change(ticket, organization_fields=['organization_id'],    # type: ignore
                                        user_fields=['assignee_id', 'collaborator_ids',
                                        'email_cc_ids', 'follower_ids', 'requester_id', 'submitter_id'])

    @staticmethod
    def __command_results_zendesk_tickets(tickets: List[Dict]):
        raw = tickets
        context = list(map(ZendeskClient.__ticket_context, tickets))
        readable_outputs = tableToMarkdown(name='Zendek tickets:', t=context, headers=TICKETS_HEADERS,
                                           headerTransform=camelize_string)
        return CommandResults(outputs_prefix="Zendesk.Ticket",
                              outputs=tickets, readable_output=readable_outputs, raw_response=raw)

    def _get_ticket_by_id(self, ticket_id: str, **kwargs):
        return self._http_request('GET', f'tickets/{ticket_id}', **kwargs)['ticket']

    @staticmethod
    def __get_sort_params(sort: str, cursor_paging: bool = False):
        Validators.validate_ticket_sort(sort)
        if not cursor_paging:
            # using the offest paged request
            sort_list = sort.split('_')
            sort, order = '_'.join(sort_list[:-1]), sort_list[-1]
            return {
                'sort_by': sort,
                'sort_order': order
            }
            # using the cursor paged request
        return {'sort': CURSOR_SORTS[sort]}

    @staticmethod
    def __get_tickets_url_suffix(filter: str, user_id: Optional[Union[str, int]] = None) -> str:
        match filter:
            case None:
                return 'tickets'
            case 'recent':  # lgtm[py/unreachable-statement]
                return 'tickets/recent'
            case _:  # lgtm[py/unreachable-statement]
                assert user_id, f"user_id is required when using '{filter}' as filter."
                Validators.validate_ticket_filter(filter)
                return f'/users/{user_id}/tickets/{filter}'

    def zendesk_ticket_list(self, ticket_id: Optional[STR_OR_STR_LIST] = None, query: Optional[str] = None,
                            user_id: Optional[str] = None, sort: Optional[str] = None,
                            page_number: Optional[int] = None, **kwargs):
        filter_ = kwargs.pop('filter', None)
        error_msgs = []
        command_results = []
        if query is not None:
            assert ticket_id is None, "please provide either 'query' or 'ticket_id' not both."
            ticket_filter = 'type:ticket'
            query = query if query.startswith(ticket_filter) else f'{ticket_filter} {query}'
            ticket_id = list(map(
                lambda x: x['id'],
                filter(
                    lambda x: x['result_type'] == 'ticket',
                    self.__zebdesk_search_results(query=query, page_number=page_number, **kwargs)
                )
            ))
        if ticket_id is not None:
            tickets = []
            for single_ticket in argToList(ticket_id):
                try:
                    tickets.append(self._get_ticket_by_id(single_ticket))
                except Exception as e:
                    demisto.error(f'could not retrieve ticket: {single_ticket}\n{traceback.format_exc()}')
                    error_msgs.append(f'could not retrieve ticket: {single_ticket}\n{e}')
        else:
            can_use_cursor_paging = page_number is None
            sort_params = self.__get_sort_params(sort, can_use_cursor_paging) if sort else None
            url_suffix = self.__get_tickets_url_suffix(filter_, user_id)
            tickets = list(self._paged_request(url_suffix=url_suffix, data_field_name='tickets',
                                               params=sort_params, page_number=page_number, **kwargs))

        if tickets:
            command_results.append(self.__command_results_zendesk_tickets(tickets))
        if error_msgs:
            command_results.append(error_entry('\n'.join(error_msgs)))
        return command_results if command_results else 'No outputs.'

    class Ticket:

        def __init__(self, type: Optional[str] = None, collaborators: Optional[str] = None,
                     comment: Optional[str] = None, public: Optional[Union[str, bool]] = None,
                     email_ccs: Optional[str] = None, priority: Optional[str] = None,
                     followers: Optional[Union[List[str], str]] = None, status: Optional[str] = None,
                     **kwargs):

            self._data: Dict[str, Any] = dict()

            if type:
                Validators.validate_ticket_type(type)
                self._data['type'] = type
                if type != 'incident':
                    assert 'problem_id' not in kwargs, "you can't use 'problem_id' if the ticket type is not 'incident'"
            if priority:
                Validators.validate_ticket_priority(priority)
                self._data['priority'] = priority
            if comment:
                self._data['comment'] = {'body': comment}
                if public:
                    self._data['comment']['public'] = argToBoolean(public)
            if status:
                Validators.validate_ticket_status(status)
                self._data['status'] = status
            if collaborators:
                self._data['collaborators'] = list(map(self.try_int, argToList(collaborators)))
            if followers:
                self._data['followers'] = list(map(self.follower_and_email_cc_parse, argToList(followers)))
            if email_ccs:
                self._data['email_ccs'] = list(map(self.follower_and_email_cc_parse, argToList(followers)))

            self._data.update(prepare_kwargs(
                kwargs=kwargs,
                str_args=['subject', 'requester', 'assignee_email',
                          'recipient', 'priority', 'external_id', 'due_at', 'comment'],
                list_args='tags',
                int_args=['forum_topic_id', 'group_id', 'organization_id', 'via_followup_source_id', 'brand_id', 'problem_id'],
                json_args='custom_fields'
            ))

        def __iter__(self):
            for key, val in self._data.items():
                yield key, val

        @staticmethod
        def try_int(value: str) -> Union[int, str]:
            try:
                return int(value)
            except (ValueError, TypeError):
                return value

        @staticmethod
        def follower_and_email_cc_parse(user_and_action: str):
            follower_or_email_cc = {}
            splited_user_and_action = user_and_action.split(':')
            try:
                follower_or_email_cc['user_id'] = str(int(splited_user_and_action[0]))
            except ValueError:
                follower_or_email_cc['user_email'] = splited_user_and_action[0]

            if len(splited_user_and_action) == 2:   # action included
                follower_or_email_cc['action'] = splited_user_and_action[1]

            return follower_or_email_cc

    def zendesk_ticket_create(self, **kwargs):  # pragma: no cover
        for argument in ['subject', 'type', 'requester', 'description']:
            assert argument in kwargs, f"'{argument}' is a required argument."
        kwargs['comment'] = kwargs.pop('description')
        return self.__command_results_zendesk_tickets([
            self._http_request('POST', url_suffix='tickets', json_data={'ticket': dict(self.Ticket(**kwargs))})['ticket']
        ])

    def zendesk_ticket_update(self, ticket_id: str, results: Optional[bool] = True,  # pragma: no cover
                              is_mirror: bool = False, **kwargs):
        headers = {'user-agent': MIRROR_USER_AGENT} if is_mirror else {}
        res = self._http_request('PUT', url_suffix=f'tickets/{ticket_id}',
                                 json_data={'ticket': dict(self.Ticket(**kwargs))}, headers=headers)
        if results:
            return self.__command_results_zendesk_tickets([
                res['ticket']
            ])

    def zendesk_ticket_delete(self, ticket_id: str):  # pragma: no cover
        self._http_request('DELETE', url_suffix=f'tickets/{ticket_id}', return_empty_response=True)
        return f'ticket: {ticket_id} deleted.'

    @staticmethod
    def _map_comment_attachments(comment: Dict):
        if not comment.get('attachments'):
            return comment

        copy_comment = copy(comment)
        copy_comment['attachments'] = []
        for attachment in comment['attachments']:
            copy_comment['attachments'].append({
                'file name': attachment['file_name'],
                'content url': attachment['content_url'],
                'id': attachment['id'],
            })
        return copy_comment

    @staticmethod
    def __command_results_zendesk_ticket_comments(comments: List[Dict]):
        readable_pre_proces = list(map(ZendeskClient._map_comment_attachments, comments))
        readable_outputs = tableToMarkdown(name='Zendek comments:', t=readable_pre_proces, headers=COMMENTS_HEADERS,
                                           headerTransform=camelize_string, is_auto_json_transform=True)
        return CommandResults(outputs_prefix="Zendesk.Ticket.Comment",
                              outputs=comments, readable_output=readable_outputs)

    def _get_comments(self, ticket_id: str, **kwargs):
        for comment in self._paged_request(url_suffix=f'tickets/{ticket_id}/comments', data_field_name='comments', **kwargs):
            for attachment in comment.get('attachments', []):
                attachment.pop('thumbnails', None)
            yield CACHE.replace_ids_change(comment, user_fields=['author_id'])  # type: ignore

    def zendesk_ticket_comment_list(self, ticket_id: str, **kwargs):
        return self.__command_results_zendesk_ticket_comments(list(self._get_comments(ticket_id, **kwargs)))

    # ---- attachment releated functions ---- #

    def zendesk_ticket_attachment_add(self, file_id: STR_OR_STR_LIST, ticket_id: int, comment: str,
                                      file_name: Optional[STR_OR_STR_LIST] = None, is_mirror: bool = False):
        headers = {'Content-Type': 'application/binary'}
        if is_mirror:
            headers['user-agent'] = MIRROR_USER_AGENT
        file_id = argToList(file_id)
        file_name_list = argToList(file_name) if file_name else [None] * len(file_id)
        file_tokens = []
        uploaded_files = []
        for single_file_id, single_file_name in zip(file_id, file_name_list):
            single_file = demisto.getFilePath(single_file_id)
            display_name = single_file_name or single_file['name']
            with open(single_file['path'], 'rb') as file_to_upload:
                file_tokens.append(
                    self._http_request(
                        'POST', url_suffix='uploads',
                        params={'filename': display_name},
                        headers=headers,
                        content=file_to_upload.read(),
                    )['upload']['token'])
            uploaded_files.append(display_name)

        self._http_request('PUT', url_suffix=f'tickets/{ticket_id}',
                           json_data={'ticket': {'comment': {'uploads': file_tokens, 'body': comment}}})

        return f'file: {", ".join(uploaded_files)} attached to ticket: {ticket_id}'

    def zendesk_attachment_get(self, attachment_id: int):
        attachments = [
            self._http_request(
                'GET',
                url_suffix=f'attachments/{single_attachent_id}'
            )['attachment'] for single_attachent_id in argToList(attachment_id)
        ]

        def filter_thumbnails(attachment: Dict):
            attachment.pop('thumbnails')
            return attachment

        attachments = list(map(filter_thumbnails, attachments))
        readable_output = tableToMarkdown(name='Zendesk attachments', t=attachments,
                                          headers=ATTACHMENTS_HEADERS, headerTransform=camelize_string)
        results = [CommandResults(outputs_prefix='Zendesk.Attachment',
                                  outputs=attachments, readable_output=readable_output)]
        for attachment_link, attachment_name in map(lambda x: (x['content_url'], x['file_name']), attachments):
            res = self._http_request('GET', full_url=attachment_link, resp_type='response')
            res.raise_for_status()
            results.append(fileResult(filename=attachment_name, data=res.content, file_type=EntryType.ENTRY_INFO_FILE))

        return results

    # ---- search releated functions ---- #

    def __zebdesk_search_results(self, query: str, limit: int = 50, page_number: Optional[int] = None, page_size: int = 50):
        params = {'query': urlencode({'A': query})[2:]}
        results = []
        if page_number:
            results = list(self.__get_spesific_page(url_suffix='search.json', params=params,
                           data_field_name='results', page_number=int(page_number), page_size=int(page_size)))
        else:
            count = self._http_request('GET', url_suffix='search/count.json', params=params)['count']
            limit = min(int(limit), count)
            size = min(limit, MAX_PAGE_SIZE)
            current_page = 1
            while len(results) < limit:
                results.extend(self.__get_spesific_page(url_suffix='search.json', params=params,
                               data_field_name='results', page_number=current_page, page_size=size))
                current_page += 1
            results = results[:limit]

        return results

    def zendesk_search(self, query: str, limit: int = 50, page_number: Optional[int] = None, page_size: int = 50):
        return CommandResults(outputs_prefix="Zendesk.Search",
                              outputs=self.__zebdesk_search_results(
                                  query=query, limit=limit, page_number=page_number, page_size=page_size
                              ))

    # ---- articles releated functions ---- #

    def zendesk_article_list(self, locale: Optional[str] = '', article_id: Optional[int] = None, **kwargs):
        if locale:
            locale = f'{locale}/'
        if article_id:
            articles = [
                self._http_request('GET', url_suffix=f'help_center/{locale}articles/{article_id}')['article']
            ]
        else:
            articles = list(self._paged_request(
                url_suffix=f'help_center/{locale}articles', data_field_name='articles', **kwargs))

        readable_output = ["</h1>Zendesk articles</h1>"]
        for title, body in map(lambda x: (x['title'], x['body']), articles):
            readable_output.append(f'<h1>{title}</h1>\n{body}')

        return CommandResults(outputs_prefix='Zendesk.Article', outputs=articles,
                              readable_output='\n\n\n'.join(readable_output))

    # ---- demisto releated functions ---- #

    def test_module(self):  # pragma: no cover
        exception: Exception
        # If one of the endpoints work we will pass the test_module check.
        for data_type in ['tickets', 'users', 'organizations']:
            try:
                self._paged_request(url_suffix=data_type, data_field_name=data_type, limit=1)
                return 'ok'
            except Exception as e:
                exception = e

        raise exception from None

    @staticmethod
    def _ticket_to_incident(ticket: Dict):
        ticket |= {
            'severity': PRIORITY_MAP.get(ticket['priority']),
            'mirror_instance': INTEGRATION_INSTANCE,
            'mirror_id': str(ticket['id']),
            'mirror_direction': MIRROR_DIRECTION,
            'mirror_last_sync': datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ'),
            'mirror_tags': MIRROR_TAGS,
        }
        return {
            'rawJSON': json.dumps(ticket),
            'name': ticket['subject'],
            'occurred': ticket['created_at'],
        }

    def fetch_incidents(self, lastRun: Optional[str] = None):
        created_tickets = CreatedTickets(self, json.loads(lastRun or '{}') or demisto.getLastRun())

        tickets = list(map(
            self._ticket_to_incident,
            map(
                self.__ticket_context,
                created_tickets.tickets()
            )
        ))
        demisto.incidents(tickets)
        demisto.setLastRun(created_tickets.next_run())

    def get_modified_remote_data(self, lastUpdate: Optional[str] = None):
        try:
            timestamp = int(dateparser.parse(lastUpdate).timestamp())  # type: ignore
        except (TypeError, AttributeError):
            timestamp = 0
        last_run = get_last_mirror_run() or {}
        updated_tickets = UpdatedTickets(self, timestamp, last_run)
        tickets_ids = list(map(lambda x: str(x['id']), updated_tickets.tickets()))
        if tickets_ids:
            return_results(GetModifiedRemoteDataResponse(tickets_ids))
        try:
            set_last_mirror_run(updated_tickets.next_run())
        except json.decoder.JSONDecodeError as e:
            demisto.debug(f'{e}')

    @staticmethod
    def _create_entry_from_comment(comment: Dict):
        comment_body = comment.get('body')
        attachments = comment.get('attachments')
        if attachments:
            attachments_table = tableToMarkdown("attachments", attachments, [
                                                "file_name", "id"], headerTransform=camelize_string)
            comment_body = f'{comment_body}\n{attachments_table}'

        return {
            'Type': EntryType.NOTE,
            'Contents': comment_body,
            'ContentsFormat': EntryFormat.MARKDOWN,
            'Note': True
        }

    def get_remote_data(self, **kwargs):
        try:
            parsed_args = GetRemoteDataArgs(kwargs)
            last_update = datetime_to_iso(dateparser.parse(parsed_args.last_update, settings={'TIMEZONE': 'UTC'}))  # type: ignore
            try:
                ticket_data = self._get_ticket_by_id(parsed_args.remote_incident_id)
            except HTTPError as e:
                if e.response.status_code == 404 and CLOSE_INCIDENT:
                    return GetRemoteDataResponse(
                        close_entry(f'ticket {parsed_args.remote_incident_id} deleted.'),
                        [close_entry(f'ticket {parsed_args.remote_incident_id} deleted.')]
                    )
                raise e from None

            context = self.__ticket_context(ticket_data)
            context['severity'] = PRIORITY_MAP.get(ticket_data['priority'])
            context['incomming_mirror_error'] = ''
            for field_to_delete in FIELDS_TO_REMOVE_FROM_MIROR_IN:
                if field_to_delete in context:
                    del context[field_to_delete]

            def filter_comments(comment: Dict):
                return comment['created_at'] > last_update \
                    and dict_safe_get(comment, ['metadata', 'system', 'client']) != MIRROR_USER_AGENT

            ticket_entries = list(map(
                self._create_entry_from_comment,
                filter(filter_comments, self._get_comments(parsed_args.remote_incident_id, limit=200))
            ))
            if ticket_data.get('status') == 'closed' and CLOSE_INCIDENT:
                ticket_entries.append(close_entry(f'ticket {parsed_args.remote_incident_id} closed.'))

            return GetRemoteDataResponse(context, ticket_entries)
        except Exception as e:
            return GetRemoteDataResponse({
                'incomming_mirror_error': f'mirroring failed with error: {e}\n{traceback.format_exc()}'
            }, [])

    def update_remote_system(self, **kwargs):
        # TODO: finish outgoing mapper
        args = UpdateRemoteSystemArgs(kwargs)
        files = []
        args.delta = {key: val for key, val in args.delta.items() if val}

        if 'severity' in args.delta:
            severity = args.delta.pop('severity')
            severity = IncidentSeverity.LOW if severity < IncidentSeverity.LOW else severity
            for priority, severity_val in PRIORITY_MAP.items():
                if severity == severity_val:
                    args.delta['priority'] = priority
                    break

        if args.incident_changed and CLOSE_INCIDENT:
            if args.inc_status == IncidentStatus.DONE or (args.data.get('state') == 'closed'):
                args.delta['status'] = 'closed'

        def upload_files_and_reset_files_list(files: List):
            while files:
                comment = files[0].get('contents', DEFAULT_UPLOAD_FILES_COMMENT)
                files_to_upload = []
                while files and files[0].get('contents', DEFAULT_UPLOAD_FILES_COMMENT) == comment:
                    files_to_upload.append(files.pop(0)['id'])

                self.zendesk_ticket_attachment_add(
                    file_id=files_to_upload, ticket_id=args.remote_incident_id, comment=comment, is_mirror=True)

        try:
            for entry in args.entries or []:
                # Mirroring files as entries
                if entry['type'] in [EntryType.ENTRY_INFO_FILE, EntryType.FILE, EntryType.IMAGE]:
                    files.append(entry)
                else:
                    upload_files_and_reset_files_list(files)
                    # Mirroring comment and work notes as entries
                    self.zendesk_ticket_update(ticket_id=args.remote_incident_id,
                                               comment=entry['contents'], results=False, is_mirror=True)

            upload_files_and_reset_files_list(files)
            if args.delta:
                self.zendesk_ticket_update(ticket_id=args.remote_incident_id, results=False, **args.delta)

        except HTTPError as e:
            if e.response.status_code != 404 and CLOSE_INCIDENT:
                raise e from None
            demisto.debug(f'ticket {args.remote_incident_id} deleted.')

        return args.remote_incident_id

    def get_mapping_fields(self, **kwargs):  # pragma: no cover
        zendesk_ticket_scheme = SchemeTypeMapping('Zendesk Ticket')
        zendesk_ticket_scheme.add_field(
            name='type', description='The type of this ticket. Allowed values are "problem", "incident", "question", or "task".')
        zendesk_ticket_scheme.add_field(name='subject', description='The value of the subject field for this ticket.')
        zendesk_ticket_scheme.add_field(name='description', description='The ticket description.')
        zendesk_ticket_scheme.add_field(
            name='priority',
            description='The urgency with which the ticket should be addressed. '
            'Allowed values are "urgent", "high", "normal", or "low".'
        )
        zendesk_ticket_scheme.add_field(
            name='status',
            description='The state of the ticket. Allowed values are "new", "open", "pending", "hold", "solved", or "closed".'
        )
        zendesk_ticket_scheme.add_field(name='recipient', description='The original recipient e-mail address of the ticket.')
        zendesk_ticket_scheme.add_field(name='requester', description='The user who requested this ticket.')
        zendesk_ticket_scheme.add_field(name='assigne', description='The agent currently assigned to the ticket.')
        zendesk_ticket_scheme.add_field(name='organization', description='The organization of the requester.')
        zendesk_ticket_scheme.add_field(name='collaborators', description="The users currently CC'ed on the ticket.")
        zendesk_ticket_scheme.add_field(name='followers', description='The agents currently following the ticket.')
        zendesk_ticket_scheme.add_field(
            name='email_ccs', description="The agents or end users currently CC'ed on the ticket.")
        zendesk_ticket_scheme.add_field(name='tags', description='The array of tags applied to this ticket.')
        zendesk_ticket_scheme.add_field(
            name='custom_fields', description='Custom fields for the ticket (this is a json formatted argument see: https://developer.zendesk.com/documentation/ticketing/managing-tickets/creating-and-updating-tickets#setting-custom-field-values).')  # noqa: E501

        return GetMappingFieldsResponse([zendesk_ticket_scheme])


def main():  # pragma: no cover

    params = demisto.params()
    verify = not params.get('insecure', False)
    if not verify:
        disable_warnings()
    client = ZendeskClient(
        base_url=params['base_url'],
        username=params['credentials'].get('identifier'),
        password=params['credentials']['password'],
        proxy=params.get('proxy', False),
        verify=verify
    )
    global CACHE
    CACHE = CacheManager(client)
    try:
        command = demisto.command()
        args = demisto.args()
        commands: Dict[str, Callable] = {
            # demisto commands
            'test-module': client.test_module,
            'fetch-incidents': client.fetch_incidents,
            'get-modified-remote-data': client.get_modified_remote_data,
            'get-remote-data': client.get_remote_data,
            'update-remote-system': client.update_remote_system,
            'get-mapping-fields': client.get_mapping_fields,
            'zendesk-clear-cache': CacheManager.zendesk_clear_cache,

            # user commands
            'zendesk-user-list': client.zendesk_user_list,
            'zendesk-user-create': client.zendesk_user_create,
            'zendesk-user-update': client.zendesk_user_update,
            'zendesk-user-delete': client.zendesk_user_delete,

            # organization commands
            'zendesk-organization-list': client.zendesk_organization_list,

            # ticket commands
            'zendesk-ticket-list': client.zendesk_ticket_list,
            'zendesk-ticket-create': client.zendesk_ticket_create,
            'zendesk-ticket-update': client.zendesk_ticket_update,
            'zendesk-ticket-delete': client.zendesk_ticket_delete,
            'zendesk-ticket-comment-list': client.zendesk_ticket_comment_list,

            # attachment commands
            'zendesk-ticket-attachment-add': client.zendesk_ticket_attachment_add,
            'zendesk-attachment-get': client.zendesk_attachment_get,

            # search command
            'zendesk-search': client.zendesk_search,

            # articles command
            'zendesk-article-list': client.zendesk_article_list,
        }
        demisto.debug(f'command {command} called')

        if command in commands:
            if command_res := commands[command](**args):
                return_results(command_res)
        else:
            raise NotImplementedError(command)
    except Exception as e:
        return_error(f'An error occurred: {e}', error=e)
    finally:
        CACHE.save()


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
