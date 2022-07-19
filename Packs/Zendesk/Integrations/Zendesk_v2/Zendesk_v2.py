from copy import copy
from functools import lru_cache
from urllib.parse import urlencode
from urllib3 import disable_warnings
import demistomock as demisto
from CommonServerPython import *

from typing import Optional, List, Union, Iterator


MAX_PAGE_SIZE = 100
USER_CONTEXT_PATH = "Zendesk.User"
USERS_HEADERS = ['id', 'name', 'email', 'role', 'active', 'external_id', 'created_at', 'updated_at']
ORGANIZATIONS_HEADERS = ['id', 'name', 'domain_names', 'tags', 'external_id', 'created_at', 'updated_at']
TICKETS_HEADERS = ['id', 'subject', 'description', 'priority', 'status', 'assignee_id', 'created_at', 'updated_at', 'external_id']
COMMENTS_HEADERS = ['id', 'body', 'created_at', 'public', 'attachments']
ATTACHMENTS_HEADERS = ['id', 'file_name', 'content_url', 'size', 'content_type']
ARTICLES_HEADERS = ['body']
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
TICKET_STATUS = ['open', 'pending', 'hold', 'solved' 'closed']
TICKET_PRIORITY = ['urgent', 'high', 'normal', 'low']
PRIORITY_MAP = {
    'urgent': IncidentSeverity.CRITICAL,
    'high': IncidentSeverity.HIGH,
    'normal': IncidentSeverity.MEDIUM,
    'low': IncidentSeverity.LOW
}
MIRROR_DIRECTION = {
    'Incoming': 'In',
    'Outgoing': 'Out',
    'Incoming And Outgoing': 'Both'
}.get(demisto.params().get('mirror_direction'))
INTEGRATION_INSTANCE = demisto.integrationInstance()
CACHE = None


class CacheManager:

    def __init__(self, zendesk_client):
        self._data = None
        self._zendesk_client: ZendeskClient = zendesk_client

    def save(self):
        if self._data:
            demisto.setIntegrationContext(self._data)

    def replace_ids_change(self, obj, organization_fields: Optional[List[str]] = [], user_fields: Optional[List[str]] = []):
        for fields, get_func in [(organization_fields, self.organization), (user_fields, self.user)]:
            for field in fields:
                obj_id = obj.get(field)
                if obj_id:
                    field = field.replace('_id', '')
                    if isinstance(obj_id, List):
                        obj = list(map(get_func, obj_id))
                    else:
                        obj = get_func(obj_id)
                    obj[field] = obj
        return obj

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

    def organization_name(self, organization_name: str) -> Union[int, None]:
        organizations = self._zendesk_client._get_organizations_by_name(organization_name)

        if len(organizations) > 1:
            demisto.error(f"found more than one organization with name '{organization_name} ignoring.'")
        elif len(organizations) < 1:
            demisto.error(f"could not found organization with name '{organization_name}' ignoring.")
        else:
            return organizations[0]

    def _generic_get_by_id(self, data_type, obj_id, data_get, val_field):
        self.data[data_type] = self.data.get(data_type, {})
        try:
            return self.data[data_type][obj_id]
        except KeyError:
            pass

        try:
            user_email = data_get(obj_id)[val_field] or obj_id
            self.data[data_type][obj_id] = user_email
            return user_email
        except:  # noqa
            pass

        return obj_id


def datetime_to_iso(date: datetime) -> str:
    return date.strftime('%Y-%m-%dT%H:%M:%SZ')


def prepare_kwargs(kwargs: Dict[str, Any], ignore_args: Optional[Union[str, List[str]]] = [],
                   str_args: Optional[Union[str, List[str]]] = [],
                   list_args: Optional[Union[str, List[str]]] = [],
                   bool_args: Optional[Union[str, List[str]]] = [],
                   int_args: Optional[Union[str, List[str]]] = [],
                   json_args: Optional[Union[str, List[str]]] = []) -> Dict[str, Any]:
    return_kwargs = dict()

    for arg in ignore_args if isinstance(ignore_args, List) else [ignore_args]:
        if arg in kwargs:
            return_kwargs[arg] = kwargs[arg]

    for arg in str_args if isinstance(str_args, List) else [str_args]:
        if arg in kwargs:
            return_kwargs[arg] = kwargs[arg]

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
            return_kwargs[arg] = json.loads(kwargs[arg])

    return return_kwargs


class Validators:

    @staticmethod
    def _validate(val: Any, arg_name: str, aloowed: Iterator[Any]):
        copy_value = argToList(val)
        try:
            for value in copy_value:
                assert value in aloowed
        except AssertionError:
            return_error(f"'{val}' is not a valid {arg_name}.\naloowed {arg_name}s are '{','.join(aloowed)}'")

    @staticmethod
    def validate_role(role: str):
        aloowed_roles = ['end-user', 'admin', 'agent']
        Validators._validate(role, 'role', aloowed_roles)

    @staticmethod
    def validate_role_type(role_type: str):
        Validators._validate(role_type, 'role type', ROLE_TYPES.keys())

    def validate_ticket_filter(ticket_filter: str):
        Validators._validate(ticket_filter, 'filter', TICKET_FILTERS)

    def validate_ticket_sort(ticket_sort: str):
        Validators._validate(ticket_sort, 'sort', CURSOR_SORTS.keys())

    def validate_ticket_type(ticket_type: str):
        Validators._validate(ticket_type, 'type', TICKET_TYPE)

    def validate_ticket_status(ticket_status: str):
        Validators._validate(ticket_status, 'status', TICKET_STATUS)

    def validate_ticket_priority(ticket_priority: str):
        Validators._validate(ticket_priority, 'priority', TICKET_PRIORITY)


class ZendeskClient(BaseClient):

    def __init__(self, base_url: str, username: Optional[str] = None, password: Optional[str] = None, proxy: bool = False, verify: bool = True):
        base_url += '/api/v2/'
        auth = headers = None
        if username and password:
            auth = (f'{username}/token', password)
        elif password:
            headers = {'Authorization': f'Bearer {password}'}

        super(ZendeskClient, self).__init__(base_url, auth=auth, proxy=proxy, verify=verify, headers=headers)

    def _http_request(self, method, url_suffix='', full_url=None, json_data=None,
                      params=None, data=None, content=None, resp_type='json',
                      return_empty_response=False):
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

        return super()._http_request(method, url_suffix=url_suffix, full_url=full_url, json_data=json_data,
                                     data=data or content, return_empty_response=return_empty_response,
                                     resp_type=resp_type)

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

            if not res.get('meta', {}).get('has_more'):
                break

            res = self._http_request('GET', full_url=res['links'].get(next_link_section))

    def __get_spesific_page(self, url_suffix: str, data_field_name: str, page_size: int, page_number: int, params: Optional[Dict] = None) -> Iterator[Dict]:
        # API docs here https://developer.zendesk.com/api-reference/ticketing/introduction/#using-offset-pagination
        page_size = min(page_size, MAX_PAGE_SIZE)
        paged_params = copy(params) if params is not None else {}
        paged_params['per_page'] = page_size
        paged_params['page'] = page_number
        demisto.error(f'{url_suffix=}')
        demisto.error(f"{self._http_request('GET', url_suffix=url_suffix, params=paged_params)=}")
        for res in self._http_request('GET', url_suffix=url_suffix, params=paged_params)[data_field_name]:
            yield res

    def _paged_request(self, url_suffix: str, data_field_name: str, params: Optional[Dict] = None,
                       limit: int = 50, page_size: Optional[int] = None, page_number: Optional[int] = None, **_kwargs) -> Iterator[Dict]:
        # validate parameters
        if page_size is not None and page_number is not None:
            return self.__get_spesific_page(url_suffix=url_suffix, data_field_name=data_field_name,
                                            params=params, page_size=int(page_size), page_number=int(page_number))
        elif page_size is not None and page_number is not None:
            raise AssertionError("you need to specify both 'page_size' and 'page_number'.")
        else:
            return self.__cursor_pagination(url_suffix=url_suffix, data_field_name=data_field_name, params=params, limit=int(limit))

    # ---- user releated functions ---- #

    @staticmethod
    def _return_results_zendesk_users(users: List[Dict]):
        role_types_reverse = {int_k: str_k for str_k, int_k in ROLE_TYPES.items()}

        def _iter_context(user):
            user = CACHE.replace_ids_change(user, ['organization_id'])
            role_type = role_types_reverse.get(user.get('role_type'))
            if role_type:
                user['role_type'] = role_type
            return user
        raw_results = copy(users)
        context = list(map(_iter_context, users))
        readable_outputs = tableToMarkdown(name='Zendek users:', t=context, headers=USERS_HEADERS,
                                           headerTransform=lambda x: x.replace('_', ' '))
        return_results(CommandResults(outputs_prefix=USER_CONTEXT_PATH, outputs=context,
                       readable_output=readable_outputs, raw_response=raw_results))

    def _get_user_by_id(self, user_id: str):
        demisto.error(self._http_request('GET', f'users/{user_id}')['user'])
        return self._http_request('GET', f'users/{user_id}')['user']

    def zendesk_user_list(self, user_id: Optional[Union[str, List[str]]] = None,
                          user_name: Optional[str] = None, role: Optional[Union[List[str], str]] = None,
                          **kwargs):
        users_field_name = 'users'

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
                role = argToList(role)
                Validators.validate_role(role)
                role = role[0] if len(role) == 1 else role
                params['role'] = role
            users_list = list(self._paged_request('users', 'users', params=params, **kwargs))

        if users_list:
            self._return_results_zendesk_users(users_list)
        if error_msgs:
            return_error('\n'.join(error_msgs))

        if not users_list:
            return_results('No outputs.')

    @staticmethod
    def _handle_role_argument(role: Optional[str] = None, role_type: Optional[str] = None) -> Dict[str, Any]:
        role_params = {}
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
            kwargs['organization_id'] = CACHE.organization_name(kwargs.pop('organization_name', None))

        user_body.update(prepare_kwargs(
            kwargs=kwargs,
            str_args=['phone', 'notes', 'details', 'external_id', 'locale', 'alias'],
            list_args='tags',
            int_args=['organization_id', 'default_group_id', 'custom_role_id'],
            bool_args='verified',
            json_args=['identities', 'user_fields']
        ))
        user_body.update(self._handle_role_argument(role=role, role_type=role_type))

        self._return_results_zendesk_users([
            self._http_request('POST', url_suffix=url_suffix, json_data={'user': user_body})['user']
        ])

    def zendesk_user_update(self, user_id: str, role: Optional[str] = None, role_type: Optional[str] = None, **kwargs):
        if 'organization_name' in kwargs:
            assert 'organization_id' not in kwargs, "you can specify 'organization_id' or 'organization_name' not both."
            kwargs['organization_id'] = CACHE.organization_name(kwargs.pop('organization_name', None))

        user_body = prepare_kwargs(
            kwargs=kwargs,
            str_args=['name', 'email', 'phone', 'notes', 'details', 'external_id', 'locale', 'alias'],
            list_args='tags',
            int_args=['organization_id', 'default_group_id', 'custom_role_id'],
            bool_args=['verified', 'suspended'],
            json_args=['identities', 'user_fields']
        )
        user_body.update(self._handle_role_argument(role=role or 'agent', role_type=role_type))

        self._return_results_zendesk_users([
            self._http_request('PUT', url_suffix=f'users/{user_id}', json_data={'user': user_body})['user']
        ])

    def zendesk_user_delete(self, user_id: str):
        self._http_request('DELETE', url_suffix=f'users/{user_id}')
        return_results(f'User deleted. (id: {user_id})')

    # ---- organization releated functions ---- #

    @staticmethod
    def __return_results_zendesk_organizations(organizations: List[Dict]):
        readable_outputs = tableToMarkdown(name='Zendek organizations:', t=organizations, headers=ORGANIZATIONS_HEADERS,
                                           headerTransform=lambda x: x.replace('_', ' '))
        return_results(CommandResults(outputs_prefix="Zendesk.Organization",
                       outputs=organizations, readable_output=readable_outputs))

    def _get_organization_by_id(self, organization_id: str) -> Dict[str, Any]:
        return self._http_request('GET', f'organizations/{organization_id}')['organization']

    def _get_organizations_by_name(self, organization_name: str) -> List[Dict[str, Any]]:
        self._http_request('GET', f'organizations/autocomplete', params={'name': organization_name})['organizations']

    def zendesk_organization_list(self, organization_id: Optional[str] = None, **kwargs):

        if organization_id:
            organizations = [self._get_organization_by_id(organization_id)]
        else:
            organizations = list(self._paged_request(url_suffix='organizations', data_field_name='organizations', **kwargs))

        self.__return_results_zendesk_organizations(organizations)

    # ---- ticket releated functions ---- #

    @staticmethod
    def __ticket_context(ticket: Dict[str, Any]):
        return CACHE.replace_ids_change(ticket, organization_fields=['organization_id'],
                                        user_fields=['assignee_id', 'collaborator_ids', 'email_cc_ids', 'follower_ids', 'requester_id', 'submitter_id'])

    @staticmethod
    def __return_results_zendesk_tickets(tickets: List[Dict]):
        raw = tickets
        context = list(map(ZendeskClient.__ticket_context, tickets))
        readable_outputs = tableToMarkdown(name='Zendek tickets:', t=context, headers=TICKETS_HEADERS,
                                           headerTransform=lambda x: x.replace('_', ' '))
        return_results(CommandResults(outputs_prefix="Zendesk.Ticket",
                       outputs=tickets, readable_output=readable_outputs, raw_response=raw))

    def _get_ticket_by_id(self, ticket_id: str):
        return self._http_request('GET', f'tickets/{ticket_id}')['ticket']

    def zendesk_ticket_list(self, ticket_id: Optional[Union[str, List[str]]] = None,
                            filter: Optional[str] = None, user_id: Optional[str] = None,
                            sort: Optional[str] = None, page_number: Optional[int] = None, **kwargs):
        error_msgs = []
        if ticket_id is not None:
            tickets = []
            for single_ticket in argToList(ticket_id):
                try:
                    tickets.add(self._get_ticket_by_id(single_ticket))
                except Exception as e:
                    demisto.error(f'could not retrieve ticket: {single_ticket}\n{traceback.format_exc()}')
                    error_msgs.append(f'could not retrieve ticket: {single_ticket}\n{e}')

        else:
            match filter:
                case None:
                    url_suffix = 'tickets'
                case 'recent':
                    url_suffix = 'tickets/recent'
                case _:
                    assert user_id is not None, f"user_id is required when using '{filter}' as filter."
                    Validators.validate_ticket_filter(filter)
                    url_suffix = f'/users/{user_id}/tickets/{filter}'

            sort_params = None
            if sort:
                Validators.validate_ticket_sort(sort)
                if page_number:
                    # using the offest paged request
                    sort = sort.split('_')
                    sort, order = '_'.join(sort[:-1]), sort[-1]
                    sort_params = {
                        'sort_by': sort,
                        'sort_order': order
                    }
                else:
                    # using the cursor paged request
                    sort_params = {'sort': CURSOR_SORTS[sort]}

            tickets = list(self._paged_request(url_suffix=url_suffix, data_field_name='tickets',
                           parms=sort_params, page_number=page_number, **kwargs))

        if tickets:
            self.__return_results_zendesk_tickets(tickets)
        if error_msgs:
            return_error('\n'.join(error_msgs))

        if not tickets:
            return_results('No outputs.')

    class Ticket:

        def __init__(self, type: Optional[str] = None, collaborators: Optional[str] = None,
                     comment: Optional[str] = None, public: Optional[Union[str, bool]] = None,
                     email_ccs: Optional[str] = None, priority: Optional[str] = None,
                     followers: Optional[Union[List[str], str]] = None, status: Optional[str] = None,
                     **kwargs):

            self._data = dict()

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
            except ValueError:
                return value

        @staticmethod
        def follower_and_email_cc_parse(user_and_action):
            follower_or_email_cc = {}
            user_and_action = user_and_action.split(':')
            try:
                follower_or_email_cc['user_id'] = str(int(user_and_action[0]))
            except ValueError:
                follower_or_email_cc['user_email'] = user_and_action[0]

            if len(user_and_action) == 2:   # action included
                follower_or_email_cc['action'] = user_and_action[1]

            return follower_or_email_cc

    def zendesk_ticket_create(self, **kwargs):
        for argument in ['subject', 'type', 'requester', 'description']:
            assert argument in kwargs, f"'{argument}' is a required argument."
        kwargs['comment'] = kwargs.pop('description')
        self.__return_results_zendesk_tickets([
            self._http_request('POST', url_suffix='tickets', json_data={'ticket': dict(self.Ticket(**kwargs))})['ticket']
        ])

    def zendesk_ticket_update(self, ticket_id: str, results: Optional[bool] = True, **kwargs):
        res = self._http_request('PUT', url_suffix=f'tickets/{ticket_id}',
                                 json_data={'ticket': dict(self.Ticket(**kwargs))})
        if results:
            self.__return_results_zendesk_tickets([
                res['ticket']
            ])

    def zendesk_ticket_delete(self, ticket_id: str):
        self._http_request('DELETE', url_suffix=f'tickets/{ticket_id}', return_empty_response=True)
        return_results(f'ticket: {ticket_id} deleted.')

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
    def __return_results_zendesk_ticket_comments(comments: List[Dict]):
        readable_pre_proces = list(map(ZendeskClient._map_comment_attachments, comments))
        readable_outputs = tableToMarkdown(name='Zendek comments:', t=readable_pre_proces, headers=COMMENTS_HEADERS,
                                           headerTransform=lambda x: x.replace('_', ' '), is_auto_json_transform=True)
        return_results(CommandResults(outputs_prefix="Zendesk.Ticket.Comment",
                       outputs=comments, readable_output=readable_outputs))

    def _get_comments(self, ticket_id: str, **kwargs):
        for comment in self._paged_request(url_suffix=f'tickets/{ticket_id}/comments', data_field_name='comments', **kwargs):
            for attachment in comment.get('attachments', []):
                attachment.pop('thumbnails', None)
            yield CACHE.replace_ids_change(comment, user_fields=['author_id'])

    def zendesk_ticket_comment_list(self, ticket_id: str, **kwargs):
        self.__return_results_zendesk_ticket_comments(list(self._get_comments(ticket_id, **kwargs)))

     # ---- attachment releated functions ---- #

    def zendesk_ticket_attachment_add(self, file_id: Union[str, List[str]], ticket_id: int, comment: str, file_name: Optional[Union[str, List[str]]] = None):
        file_id = argToList(file_id)
        file_name = argToList(file_name) if file_name else [None] * len(file_id)
        file_tokens = []
        uploaded_files = []
        for single_file_id, single_file_name in zip(file_id, file_name):
            single_file = demisto.getFilePath(single_file_id)
            display_name = single_file_name or single_file['name']
            with open(single_file['path'], 'rb') as file_to_upload:
                file_tokens.append(
                    self._http_request(
                        'POST', url_suffix='uploads',
                        params={'filename': display_name},
                        content=file_to_upload.read()
                    )['upload']['token'])
            uploaded_files.append(display_name)

        self._http_request('PUT', url_suffix=f'tickets/{ticket_id}',
                           json_data={'ticket': {'comment': {'uploads': file_tokens, 'body': comment}}})

        return_results(f'file: {", ".join(uploaded_files)} attached to ticket: {ticket_id}')

    def zendesk_attachment_get(self, attachment_id: int):
        attachments = [
            self._http_request('GET', url_suffix=f'attachments/{single_attachent_id}')['attachment'] for single_attachent_id in argToList(attachment_id)
        ]

        def filter_thumbnails(attachment: Dict):
            attachment.pop('thumbnails')
            return attachment

        attachments = list(map(filter_thumbnails, attachments))
        readable_output = tableToMarkdown(name='Zendesk attachments', t=attachments,
                                          headers=ATTACHMENTS_HEADERS, headerTransform=lambda x: x.replace('_', ' '))
        return_results(CommandResults(outputs_prefix='Zendesk.Attachment', outputs=attachments, readable_output=readable_output))
        for attachment_link, attachment_name in map(lambda x: (x['content_url'], x['file_name']), attachments):
            res = self._http_request('GET', full_url=attachment_link, resp_type='response')
            res.raise_for_status()
            return_results(fileResult(filename=attachment_name, data=res.content, file_type=EntryType.ENTRY_INFO_FILE))

    # ---- search releated functions ---- #

    def zendesk_search(self, query: str, limit: Optional[int] = 50, page_number: Optional[int] = None, page_size: Optional[int] = 50):
        url_data = urlencode({'query': query})
        results = []
        if page_number:
            results = list(self.__get_spesific_page(url_suffix=f'search?{url_data}',
                           data_field_name='results', page_number=int(page_number), page_size=int(page_size)))
        else:
            limit = int(limit)
            count = self._http_request('GET', url_suffix=f'search/count?{url_data}')['count']
            size = min(limit, count)
            current_page = 1
            while len(results) < limit:
                results.extend(self.__get_spesific_page(url_suffix=f'search?{url_data}',
                               data_field_name='results', page_number=current_page, page_size=size))
                current_page += 1
            # results = results[:limit]

        return_results(CommandResults(outputs_prefix="Zendesk.Search",
                       outputs=results))

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

        return_results(CommandResults(outputs_prefix='Zendesk.Article',
                       outputs=articles, readable_output='\n\n\n'.join(readable_output)))

    # ---- demisto releated functions ---- #

    def test_module(self):
        for data_type in ['tickets', 'users', 'organizations']:
            self._paged_request(url_suffix=data_type, data_field_name=data_type, limit=1)
        return_results('ok')

    class TicketEvents:

        def __init__(self, zendesk_client, last_run):
            self._client = zendesk_client
            self._demisto_params = demisto.params()
            self._tickets_list = last_run.get('tickets', [])
            self._after_cursor = last_run.get('after_cursor')
            self._latest_ticket_id = last_run.get('latest_ticket_id', 0)
            self._highest_ticket_id_in_current_run = 0

        def _get_all(self, **kwargs):
            return self._client._http_request('GET', url_suffix='incremental/tickets/cursor', params=kwargs)

        @staticmethod
        def _get_first_time_last_run_template():
            return {
                'start_time': int(
                    dateparser.parse(demisto.params().get('first_fetch', '3d')).timestamp())
            }

        @property
        def next_run(self):
            next_run = {
                'after_cursor': self._after_cursor,
                'latest_ticket_id': max(self._latest_ticket_id, self._highest_ticket_id_in_current_run)
            }
            if self._tickets_list:
                next_run['tickets'] = self._tickets_list
            return next_run

        @property
        def query_params(self):
            if self._after_cursor:
                return {'cursor': self._after_cursor}
            return self._get_first_time_last_run_template()

        def _tickets(self, limit=1000, params: Optional[Dict] = {}):
            yielded = 0
            if self._tickets_list:
                for _ in range(min(limit, len(self._tickets_list))):
                    yield self._tickets_list.pop(0)
                    yielded += 1
                if yielded >= limit:
                    return

            res = self._get_all(**(self.query_params | params))
            self._tickets_list = res.get('tickets', [])
            while True:
                self._after_cursor = res.get('after_cursor') or self._after_cursor
                for _ in range(min(limit - yielded, len(self._tickets_list))):
                    yield self._tickets_list.pop(0)
                    yielded += 1

                if res['end_of_stream']:
                    return
                res = self._get_all(**(self.query_params | params))

        def new_tickets(self, ticket_types: Optional[List[str]] = None):
            limit = self._demisto_params.get('max_fetch', 50)

            def filter_updated_ticket(ticket):
                return ticket['id'] > self._latest_ticket_id and \
                    (ticket_types is None or ticket.get('type') in ticket_types)

            for ticket in filter(filter_updated_ticket, self._tickets(limit=limit, params={'exclude_deleted': True})):
                self._highest_ticket_id_in_current_run = max(ticket['id'], self._highest_ticket_id_in_current_run)
                yield ticket

        def updated_tickets(self):
            def filter_created_ticket(ticket):
                return ['created_at'] != ticket['updated_at']

            for ticket in filter(filter_created_ticket, self._tickets()):
                yield ticket

    @staticmethod
    def _ticket_to_incident(ticket: Dict):
        return {
            'rawJSON': json.dumps(ticket),
            'name': ticket['subject'],
            'details': ticket['description'],
            'severity': PRIORITY_MAP.get(ticket['priority']),
            'occurred': ticket['created_at'],
            # 'dbotMirrorLastSync': datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ'),
            # 'dbotMirrorInstance': INTEGRATION_INSTANCE,
            # 'dbotMirrorId': str(ticket['id']),
            # 'dbotMirrorDirection': MIRROR_DIRECTION
        }

    def fetch_incidents(self, lastRun: Optional[str] = None):
        ticket_events = self.TicketEvents(self, json.loads(lastRun or '{}') or demisto.getLastRun())
        demisto.incidents(list(map(
            self._ticket_to_incident,
            map(
                self.__ticket_context,
                ticket_events.new_tickets(demisto.params().get('ticket_types')))
        )
        ))
        demisto.setLastRun(ticket_events.next_run)

    # def get_modified_remote_data(self, lastUpdate: Optional[str] = None):
    #     ticket_events = self.TicketEvents(self, lastUpdate or demisto.getLastMirrorRun())
    #     tickets_ids = list(map(lambda x: str(x['id']), ticket_events.updated_tickets()))
    #     demisto.error(f'\n\nincident {tickets_ids} chaneges detected\n\n')
    #     return_results(GetModifiedRemoteDataResponse(tickets_ids))
    #     set_last_mirror_run(ticket_events.next_run)

    # @staticmethod
    # def _create_entry_from_comment(comment: Dict):
    #     comment_body = comment.get('body')
    #     return {
    #         'Type': EntryType.NOTE,
    #         'Contents': comment_body,
    #         'ContentsFormat': EntryFormat.TEXT,
    #         'Note': True
    #     }

    # def get_remote_data(self, **kwargs):
    #     parsed_args = GetRemoteDataArgs(kwargs)
    #     last_update = datetime_to_iso(datetime.fromtimestamp(int(parsed_args.last_update)))
    #     ticket_data = self._get_ticket_by_id(parsed_args.remote_incident_id)
    #     ticket_comments = list(map(
    #         self._create_entry_from_comment,
    #         filter(
    #             lambda x: x['created_at'] > last_update,
    #             self._get_comments(parsed_args.remote_incident_id, limit=200)
    #         )
    #     ))
    #     return_results(GetRemoteDataResponse(ticket_data, ticket_comments))

    # def update_remote_system(self, **kwargs):
    #     # TODO: finish outgoing mapper
    #     demisto.results(kwargs)
    #     pass

    #     # args = UpdateRemoteSystemArgs(kwargs)
    #     # if args.get('')
    #     # self.zendesk_ticket_update(ticket_id=args.remote_incident_id, results=False, **args.delta)

    # def get_mapping_fields(self, **kwargs):
    #     zendesk_ticket_scheme = SchemeTypeMapping('Zendesk Ticket')
    #     zendesk_ticket_scheme.add_field(name='external_id', description='the description for the field')
    #     zendesk_ticket_scheme.add_field(name='type', description='the description for the field')
    #     zendesk_ticket_scheme.add_field(name='subject', description='the description for the field')
    #     zendesk_ticket_scheme.add_field(name='description', description='the description for the field')
    #     zendesk_ticket_scheme.add_field(name='priority', description='the description for the field')
    #     zendesk_ticket_scheme.add_field(name='status', description='the description for the field')
    #     zendesk_ticket_scheme.add_field(name='recipient', description='the description for the field')
    #     zendesk_ticket_scheme.add_field(name='requester', description='the description for the field')
    #     zendesk_ticket_scheme.add_field(name='assigne', description='the description for the field')
    #     zendesk_ticket_scheme.add_field(name='organization', description='the description for the field')
    #     zendesk_ticket_scheme.add_field(name='collaborators', description='the description for the field')
    #     zendesk_ticket_scheme.add_field(name='followers', description='the description for the field')
    #     zendesk_ticket_scheme.add_field(name='email_ccs', description='the description for the field')
    #     zendesk_ticket_scheme.add_field(name='tags', description='the description for the field')
    #     zendesk_ticket_scheme.add_field(name='custom_fields', description='the description for the field')
    #     zendesk_ticket_scheme.add_field(name='followup_ids', description='the description for the field')

    #     return_results(GetMappingFieldsResponse([zendesk_ticket_scheme]))


def main():
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
    demisto.error(f'\n\n\n\n\n\n{demisto.command()=}\n{INTEGRATION_INSTANCE=}\n\n\n\n\n\n')
    commands = {
        # demisto commands
        'test-module': client.test_module,
        'fetch-incidents': client.fetch_incidents,
        # 'get-modified-remote-data': client.get_modified_remote_data,
        # 'get-remote-data': client.get_remote_data,
        # 'update-remote-system': client.update_remote_system,
        # 'get-mapping-fields': client.get_mapping_fields,

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
    command = demisto.command()
    demisto.debug(f'command {command} called')
    commands[command](**demisto.args())
    CACHE.save()


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
