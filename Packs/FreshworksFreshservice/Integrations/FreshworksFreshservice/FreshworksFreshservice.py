import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


from http import HTTPStatus
from collections import namedtuple
from typing import Any
from collections.abc import Callable
import requests
import base64

MIN_PAGE_NUM = 1
MAX_PAGE_SIZE = 50
MIN_PAGE_SIZE = 1
MAX_LIMIT = 50
MIN_LIMIT = 1
MAX_DEFAULT_ARGS_COUNT = 3
STRFTIME = "%Y-%m-%d"
TIME_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

TICKET_PROPERTIES_BY_TYPE = {
    'ticket': {
        'status': {
            'Open': 2,
            'Pending': 3,
            'Resolved': 4,
            'Closed': 5,
        },
        'priority': {
            'Low': 1,
            'Medium': 2,
            'High': 3,
            'Urgent': 4,
        },
        'source': {
            'Email': 1,
            'Portal': 2,
            'Phone': 3,
            'Chat': 4,
            'Feedback widget': 5,
            'Yammer': 6,
            'AWS Cloudwatch': 7,
            'Pagerduty': 8,
            'Walkup': 9,
            'Slack': 10,
        },
        'impact': {
            'Low': 1,
            'Medium': 2,
            'High': 3,
        },
        'urgency': {
            'Low': 1,
            'Medium': 2,
            'High': 3,
        },
    },
    'problem': {
        'status': {
            'Open': 1,
            'Change Requested': 2,
            'Closed': 3,
        },
        'priority': {
            'Low': 1,
            'Medium': 2,
            'High': 3,
            'Urgent': 4,
        },
        'impact': {
            'Low': 1,
            'Medium': 2,
            'High': 3,
        },
    },
    'change': {
        'status': {
            'Open': 1,
            'Planning': 2,
            'Approval': 3,
            'Pending Release': 4,
            'Pending Review': 5,
            'closed': 6,
        },
        'priority': {
            'Low': 1,
            'Medium': 2,
            'High': 3,
            'Urgent': 4,
        },
        'impact': {
            'Low': 1,
            'Medium': 2,
            'High': 3,
        },
        'risk': {
            'Low': 1,
            'Medium': 2,
            'High': 3,
            'Very High': 4
        },
        'change_type': {
            'Minor': 1,
            'Standard': 2,
            'Major': 3,
            'Emergency': 4
        },
    },
    'release': {
        'status': {
            'Open': 1,
            'On hold': 2,
            'In Progress': 3,
            'Incomplete': 4,
            'Completed': 5
        },
        'priority': {
            'Low': 1,
            'Medium': 2,
            'High': 3,
            'Urgent': 4,
        },
        'release_type': {
            'Minor': 1,
            'Standard': 2,
            'Major': 3,
            'Emergency': 4
        },
    },
}

READABLE_OUTPUT_HEADER_BY_ENTITY = {
    'ticket': [
        'id',
        'description_text',
        'requester_id',
        'type',
        'subject',
        'status',
        'source',
        'impact',
        'priority',
        'custom_fields',
        'category',
        'created_at',
        'updated_at',
        'due_by',
        'fr_due_by',
    ],
    'change': [
        'id',
        'description_text',
        'requester_id',
        'subject',
        'risk',
        'impact',
        'status',
        'priority',
        'change_type',
        'category',
        'created_at',
        'updated_at',
        'planned_start_date',
        'planned_end_date',
    ],
    'problem': [
        'id',
        'description_text',
        'requester_id',
        'subject',
        'impact',
        'status',
        'priority',
        'group_id',
        'known_error',
        'category',
        'created_at',
        'updated_at',
        'due_by',
    ],
    'release': [
        'id',
        'description_text',
        'subject',
        'release_type',
        'status',
        'priority',
        'group_id',
        'known_error',
        'category',
        'created_at',
        'updated_at',
        'planned_start_date',
        'planned_end_date',
    ],
    'task': [
        'id',
        'description',
        'title',
        'notify_before',
        'status',
        'deleted',
        'closed_at',
        'created_at',
        'updated_at',
        'due_date',
    ],
    'conversation': [
        'id',
        'user_id',
        'body_text',
        'to_emails',
        'incoming',
        'private',
        'source',
        'created_at',
        'updated_at',
    ],
    'reply': [
        'id',
        'user_id',
        'body_text',
        'to_emails',
        'from_email',
        'created_at',
        'updated_at',
    ],
    'agents': [
        'id',
        'first_name',
        'last_name',
        'email',
        'active',
        'created_at',
        'updated_at',
        'time_zone',
        'language',
        'can_see_all_tickets_from_associated_departments',
        'auto_assign_status_changed_at',
    ],
    'agent_groups': [
        'id',
        'name',
        'description',
        'members',
        'observers',
        'agent_ids',
        'created_at',
        'updated_at',
        'auto_ticket_assign',
    ],
    'assets': [
        'display_id',
        'name',
        'description',
        'asset_type_id',
        'impact',
        'author_type',
        'usage_type',
        'created_at',
        'updated_at',
        'end_of_life',
    ],
    'roles': [
        'id',
        'name',
        'description',
        'role_type',
        'default',
        'created_at',
        'updated_at',
    ],
    'requesters': [
        'id',
        'first_name',
        'last_name',
        'primary_email',
        'active',
        'created_at',
        'updated_at',
        'time_zone',
        'department_id',
        'department_name',
        'can_see_all_tickets_from_associated_departments',
        'can_see_all_changes_from_associated_departments',
    ],
    'vendors': [
        'id',
        'name',
        'contact_name',
        'description',
        'email',
        'created_at',
        'updated_at',
    ],
    'departments': [
        'id',
        'name',
        'description',
        'domains',
        'created_at',
        'updated_at',
    ],
    'softwares': [
        'id',
        'name',
        'description',
        'application_type',
        'status',
        'created_at',
        'updated_at',
        'managed_by_id',
        'publisher_id',
        'workspace_id',
        'user_count',
        'category',
        'installation_count',
    ],
    'purchase_orders': [
        'id',
        'name',
        'vendor_id',
        'po_number',
        'total_cost',
        'status',
        'created_at',
        'updated_at',
        'expected_delivery_date',
    ],
    'requester_fields': [
        'id',
        'name',
        'label',
        'position',
        'type',
        'label_for_requesters',
        'choices',
        'created_at',
        'updated_at',
    ],
}

TASK_STATUS_VALUES = {'status': {'Open': 1, 'In Progress': 2, 'Completed': 3}}
PURCHASE_ORDER_STATUS_VALUES = {
    'status': {
        'Open': 20,
        'Cancelled': 10,
        'Ordered': 25
    }
}

FETCH_TICKET_TYPE = {
    'Incident/Service Request': 'ticket',
    'Problem Request': 'problem',
    'Change Request': 'change',
    'Release Request': 'release',
}

MIRROR_DIRECTION_MAPPING = {
    "Incoming": "In",
    "Outgoing": "Out",
    "Incoming And Outgoing": "Both",
}

TICKET_TYPE_TO_INCIDENT_TYPE = {
    'ticket': "FreshService Ticket",
    'problem': "FreshService Problem Request",
    'change': "FreshService Change Request",
    'release': "FreshService Release Request",
}

MIRRORING_COMMON_FIELDS = [
    "category",
    "sub_category",
    "department_id",
    "group_id",
    "assets",
    "due_by",
    "description",
    "status",
    "priority",
]

TICKET_TYPE_TO_ADDITIONAL_MIRRORING_FIELDS = {
    'ticket': ['impact', 'urgency', 'requester_id', 'tags', 'custom_fields'],
    'problem': ['impact', 'requester_id', 'agent_id', 'custom_fields'],
    'change': [
        'impact', 'requester_id', 'agent_id', 'risk', 'change_type',
        'planned_start_date', 'planned_end_date'
    ],
    'release':
        ['agent_id', 'release_type', 'planned_start_date', 'planned_end_date'],
}

TICKET_ID_PREFIX = {
    'ticket': 'tic',
    'problem': 'pro',
    'change': 'cha',
    'release': 'rel',
}

CommandArgs = namedtuple('CommandArgs', [
    'page', 'page_size', 'pagination_message', 'updated_query',
    'updated_since', 'ticket_filter', 'include', 'order_type',
    'command_response_key'
])

TicketProperties = namedtuple('TicketProperties', [
    'urgency', 'status', 'source', 'priority', 'impact', 'risk', 'change_type',
    'release_type'
])


class Client(BaseClient):

    def __init__(
        self,
        server_url: str,
        api_token: str,
        verify: bool,
        proxy: bool,
    ):
        api_key = api_token + ':X'
        api_key_bytes = api_key.encode('utf-8')
        encoded_key = base64.b64encode(api_key_bytes).decode('utf-8')

        headers = {'Authorization': f'Basic {encoded_key}'}
        super().__init__(base_url=server_url,
                         verify=verify,
                         proxy=proxy,
                         headers=headers)

    def freshservice_ticket_list(
        self,
        page: int = None,
        page_size: int = None,
        ticket_id: int = None,
        updated_query: str = None,
        updated_since: str = None,
        ticket_filter: str = None,
        include: str = None,
        order_type: str = None,
        resp_type: str = "json",
        full_url: str = '',
    ) -> dict[str, Any]:
        """ Lists all the Tickets in a Freshservice account.

        Args:
            page (int): The number of items per page.
            page_size (int): Page number of paginated results.
            ticket_id (int, optional): Ticket ID. Defaults to None.
            updated_query (str, optional): Query to filter items. Defaults to None.
            updated_since (str, optional): Fetch ticket updated since. Defaults to None.
            filter (str, optional): Filter name. Defaults to None.
            include (str, optional): Fields to include. Defaults to None.
            order_type (str, optional): order type. Defaults to None.

        Returns:
            Dict[str, Any]: API response from Freshservice.
        """
        if full_url:
            return self._http_request('GET', full_url=full_url, resp_type=resp_type)

        params = remove_empty_elements({
            'page': page,
            'per_page': page_size,
            'query': updated_query,
            'updated_since': updated_since,
            'filter': ticket_filter,
            'include': include,
            'order_type': order_type,
        })

        url_suffix = get_url_suffix(ticket_id)
        url_suffix = '/filter' if updated_query else url_suffix
        return self._http_request('GET',
                                  f'api/v2/tickets{url_suffix}',
                                  params=params,
                                  resp_type=resp_type)

    def freshservice_ticket_create(self, **kwargs) -> dict[str, Any]:
        """ Create a new Ticket in a Freshservice account.

        Args:
            urgency (int, optional): Ticket urgency. Defaults to None.
            tags (List[str], optional): Tags that have been associated
                    with the ticket. Defaults to None.
            subject (str, optional): The subject of the ticket. Defaults to None.
            sub_category (str, optional): Ticket subcategory. Defaults to None.
            status (int, optional): Status of the Ticket. Defaults to None.
            source (int, optional): The channel through which the Ticket was
                    created. Defaults to None.
            responder_id (int, optional): The ID of the agent to whom the Ticket
                    has been assigned. Defaults to None.
            requester_id (int, optional): User ID of the requester. For existing
                    contacts, the 'requester_id' can be passed instead of the
                    requester's email. If 'requester_id' is not provided - 'email'
                    must be specified. Defaults to None.
            problem (int, optional): The problem that needs to be associated with
                    the Ticket (problem display id). Defaults to None.
            priority (int, optional): Priority of the Ticket. Defaults to None.
            phone (str, optional): Phone number of the requester. The 'phone' can
                    be passed instead of the requester's email. If no contact exists
                    with this phone number in Freshservice, it will be added as a
                    new contact. The name attribute is mandatory if the phone number
                    is set and the email address is not. Defaults to None.
            name (str, optional): Name of the requester. Defaults to None.
            impact (int, optional): Ticket impact. Defaults to None.
            group_id (int, optional): The ID of the group to which the Ticket has
                    been assigned. Defaults to None.
            fr_due_by (str, optional): The timestamp that denotes when the first
                    response is due. Defaults to None.
            email_config_id (int, optional): The ID of the email config which is used
                    for this ticket. Defaults to None.
            email (str, optional): Default identifier. If 'email' is not provided -
                    'requester_id' must be specified. Email address of the requester.
                    If no contact exists with this email address in Freshservice,
                    it will be added as a new contact. Defaults to None.
            due_by (str, optional): The timestamp that denotes when the Ticket is
                    due to be resolved. Defaults to None.
            description (str, optional): Ticket. Defaults to None.
            department_id (int, optional): Department ID of the requester.
                    Defaults to None.
            custom_fields (List[str], optional): Key value pairs containing the names
                    and values of custom fields. Defaults to None.
            change_initiating_ticket (int, optional): Change causing the Ticket that
                    needs to be associated with the Ticket (change display id).
                    Defaults to None.
            change_initiated_by_ticket (int, optional): Change needed for the Ticket
                    to be fixed that needs to be associated with the Ticket
                    (change display id). Defaults to None.
            cc_emails (List[str], optional): Email address added in the 'cc' field
                    of the incoming Ticket email. Defaults to None.
            category (str, optional): Ticket category. Defaults to None.
            attachments (List[Dict[str, Any]], optional): Ticket attachments.
                    Defaults to None.
            assets (int, optional): Assets that have to be associated with the ticket.
                    Defaults to None.

        Returns:
            Dict[str, Any]: API response from Freshservice.
        """
        kwargs = locals().pop('kwargs', None)
        data = remove_empty_elements(kwargs)

        return self._http_request(
            'POST',
            'api/v2/tickets',
            json_data=data,
        )

    def freshservice_ticket_update(
        self,
        ticket_id: int,
        attachments: list[tuple] = None,
        **kwargs,
    ) -> dict[str, Any]:
        """ Update a Ticket in a Freshservice account.

        Args:
            ticket_id (int): Ticket ID.
            urgency (int, optional): Ticket urgency. Defaults to None.
            tags (List[str], optional): Tags that have been associated
                    with the ticket. Defaults to None.
            subject (str, optional): The subject of the ticket. Defaults to None.
            sub_category (str, optional): Ticket subcategory. Defaults to None.
            status (int, optional): Status of the Ticket. Defaults to None.
            source (int, optional): The channel through which the Ticket was
                    created. Defaults to None.
            responder_id (int, optional): The ID of the agent to whom the Ticket
                    has been assigned. Defaults to None.
            requester_id (int, optional): User ID of the requester. For existing
                    contacts, the 'requester_id' can be passed instead of the
                    requester's email. If 'requester_id' is not provided - 'email'
                    must be specified. Defaults to None.
            problem (int, optional): The problem that needs to be associated with
                    the Ticket (problem display id). Defaults to None.
            priority (int, optional): Priority of the Ticket. Defaults to None.
            phone (str, optional): Phone number of the requester. The 'phone' can
                    be passed instead of the requester's email. If no contact exists
                    with this phone number in Freshservice, it will be added as a
                    new contact. The name attribute is mandatory if the phone number
                    is set and the email address is not. Defaults to None.
            name (str, optional): Name of the requester. Defaults to None.
            impact (int, optional): Ticket impact. Defaults to None.
            group_id (int, optional): The ID of the group to which the Ticket has
                    been assigned. Defaults to None.
            fr_due_by (str, optional): The timestamp that denotes when the first
                    response is due. Defaults to None.
            email_config_id (int, optional): The ID of the email config which is used
                    for this ticket. Defaults to None.
            email (str, optional): Default identifier. If 'email' is not provided -
                    'requester_id' must be specified. Email address of the requester.
                    If no contact exists with this email address in Freshservice,
                    it will be added as a new contact. Defaults to None.
            due_by (str, optional): The timestamp that denotes when the Ticket is
                    due to be resolved. Defaults to None.
            description (str, optional): Ticket. Defaults to None.
            department_id (int, optional): Department ID of the requester.
                    Defaults to None.
            custom_fields (List[str], optional): Key value pairs containing the names
                    and values of custom fields. Defaults to None.
            change_initiating_ticket (int, optional): Change causing the Ticket that
                    needs to be associated with the Ticket (change display id).
                    Defaults to None.
            change_initiated_by_ticket (int, optional): Change needed for the Ticket
                    to be fixed that needs to be associated with the Ticket
                    (change display id). Defaults to None.
            cc_emails (List[str], optional): Email address added in the 'cc' field
                    of the incoming Ticket email. Defaults to None.
            category (str, optional): Ticket category. Defaults to None.
            attachments (List[Dict[str, Any]], optional): Ticket attachments.
                    Defaults to None.
            assets (int, optional): Assets that have to be associated with the ticket.
                    Defaults to None.

        Returns:
            Dict[str, Any]: API response from Freshservice.
        """
        kwargs = locals().pop('kwargs', None)
        data = remove_empty_elements(kwargs)

        return self._http_request('PUT',
                                  f'api/v2/tickets/{ticket_id}',
                                  json_data=data,
                                  files=attachments)

    def freshservice_ticket_delete(self, ticket_id: int) -> requests.Response:
        """ Delete an existing Ticket in Freshservice.

        Args:
            ticket_id (int): Ticket ID.

        Returns:
            requests.Response: Information about the response from Freshservice.
        """

        return self._http_request('DELETE',
                                  f'api/v2/tickets/{ticket_id}',
                                  resp_type='response')

    def freshservice_ticket_task_list(
        self,
        ticket_id: int,
        page: int = None,
        page_size: int = None,
        task_id: int = None,
    ) -> dict[str, Any]:
        """ Retrieve tasks list (or a specific task) on a Ticket with
            the given ID from Freshservice.

        Args:
            page (int): The number of items per page.
            page_size (int): Page number of paginated results.
            ticket_id (int, optional): Ticket ID. Defaults to None.
            task_id (int, optional): Task ID. Defaults to None.

        Returns:
            Dict[str, Any]: API response from Freshservice.
        """
        params = remove_empty_elements({
            'page': page,
            'per_page': page_size,
        })

        return self._http_request(
            'GET',
            f'api/v2/tickets/{ticket_id}/tasks{get_url_suffix(task_id)}',
            params=params,
        )

    def freshservice_ticket_task_create(
        self,
        ticket_id: int,
        due_date: str,
        notify_before: int,
        title: str,
        description: str,
        status: int = None,
    ) -> dict[str, Any]:
        """ Create a new task on a Ticket request in Freshservice.

        Args:
            ticket_id (int): The Ticket ID to add a task for.
            due_date (str): Task due date.
            notify_before (int): Time in seconds before which notification is sent prior to due date.
            title (str): Task title.
            description (str): Task description.
            status (int, optional): Task status. Defaults to None.

        Returns:
            Dict[str, Any]: API response from Freshservice.
        """
        data = remove_empty_elements({
            "description": description,
            "due_date": due_date,
            "notify_before": notify_before,
            "title": title,
            "status": status
        })
        return self._http_request('POST',
                                  f'api/v2/tickets/{ticket_id}/tasks',
                                  json_data=data)

    def freshservice_ticket_task_update(
        self,
        ticket_id: int,
        task_id: int,
        due_date: str = None,
        notify_before: int = None,
        title: str = None,
        description: str = None,
        status: int = None,
    ) -> dict[str, Any]:
        """ Update a task on a Ticket request in Freshservice.

        Args:
            ticket_id (int): The Ticket ID to update a task for.
            task_id (int): The task ID.
            due_date (str): Task due date.
            notify_before (int): Time in seconds before which notification is sent prior to due date.
            title (str): Task title.
            description (str): Task description.
            status (int, optional): Task status. Defaults to None.

        Returns:
            Dict[str, Any]: API response from Freshservice.
        """
        data = remove_empty_elements({
            "description": description,
            "due_date": due_date,
            "notify_before": notify_before,
            "title": title,
            "status": status
        })

        return self._http_request(
            'PUT',
            f'api/v2/tickets/{ticket_id}/tasks/{task_id}',
            json_data=data)

    def freshservice_ticket_task_delete(
        self,
        ticket_id: int,
        task_id: int,
    ) -> requests.Response:
        """ Delete a task on a Ticket request in Freshservice.

        Args:
            ticket_id (int): The Ticket ID to update a task for.
            task_id (int): The task ID.

        Returns:
             requests.Response: Information about the response from Freshservice.
        """
        return self._http_request(
            'DELETE',
            f'api/v2/tickets/{ticket_id}/tasks/{task_id}',
            resp_type='response',
        )

    def freshservice_ticket_conversation_list(
        self,
        ticket_id: int,
        page: int = None,
        page_size: int = None,
    ) -> dict[str, Any]:
        """ Retrieve all Conversations of a Ticket.

        Args:
            page (int): The number of items per page.
            page_size (int): Page number of paginated results.
            ticket_id (int, optional): Ticket ID. Defaults to None.

        Returns:
            Dict[str, Any]: API response from Freshservice.
        """
        params = remove_empty_elements({
            'page': page,
            'per_page': page_size,
        })

        return self._http_request('GET',
                                  f'api/v2/tickets/{ticket_id}/conversations',
                                  params=params)

    def freshservice_ticket_conversation_reply_create(
        self,
        ticket_id: int,
        body: str,
        from_email: str = None,
        user_id: int = None,
        cc_emails: list[str] = None,
        bcc_emails: list[str] = None,
        files: list[tuple] = None,
    ) -> dict[str, Any]:
        """ Create a new reply for an existing Ticket Conversation.

        Args:
            ticket_id (int): Ticket ID.
            body (str): Reply description.
            from_email (str, optional): The email address from which the reply
                    is sent. By default, the global support email will be used.
                    Defaults to None.
            user_id (int, optional): The ID of the agent/user who is adding
                    the note. Defaults to None.
            cc_emails (List[str], optional): Email address added in the 'cc'
                    field of the outgoing Ticket email. Defaults to None.
            bcc_emails (List[str], optional): Email address added in the 'bcc'
                    field of the outgoing Ticket email. Defaults to None.
            files (List[Tuple], optional): Attachments. Defaults to None.

        Returns:
            Dict[str, Any]: API response from Freshservice.
        """
        data = remove_empty_elements({
            'body': body,
            'from_email': from_email,
            'user_id': user_id,
            'cc_emails[]': cc_emails,
            'bcc_emails[]': bcc_emails,
        })
        if not files:
            self._headers.update({'Content-Type': 'multipart/form-data'})

        return self._http_request('POST',
                                  f'api/v2/tickets/{ticket_id}/reply',
                                  data=data,
                                  files=files)

    def freshservice_ticket_conversation_note_create(
        self,
        ticket_id: int,
        body: str,
        incoming: str = None,
        user_id: int = None,
        notify_emails: list[str] = None,
        private: str = None,
        files: list[tuple] = None,
    ) -> dict[str, Any]:
        """ Create a new note for an existing Ticket Conversation.

        Args:
            ticket_id (int): Ticket ID.
            body (str): Content of the note.
            incoming (str, optional): If a particular note should appear as
                    being created from the outside. Defaults to None.
            user_id (int, optional): The ID of the agent/user who is adding
                    the note. Defaults to None.
            notify_emails (List[str], optional): Email addresses of
                    agents/users who need to be notified about this note.
                    Defaults to None.
            private (str, optional): True if the note is private.
                    Defaults to None.
            files (List[Tuple], optional): Attachments. Defaults to None.

        Returns:
            Dict[str, Any]: API response from Freshservice.
        """
        data = remove_empty_elements({
            'body': body,
            'notify_emails[]': notify_emails,
            'user_id': user_id,
            'incoming': incoming,
            'private': private,
        })

        if not files:
            self._headers.update({'Content-Type': 'multipart/form-data'})

        return self._http_request('POST',
                                  f'api/v2/tickets/{ticket_id}/notes',
                                  data=data,
                                  files=files)

    def freshservice_ticket_conversation_update(
        self,
        conversation_id: int,
        body: str,
        name: str = None,
        files: list[tuple] = None,
    ) -> dict[str, Any]:
        """ Update an existing Conversation on an existing Ticket
            in Freshservice.

        Args:
            conversation_id (int): The Conversation ID.
            body (str): Conversation content to update.
            name (str, optional): Conversation name. Defaults to None.
            files (List[Tuple], optional): Conversation attachments.
                    Defaults to None.

        Returns:
            Dict[str, Any]: API response from Freshservice
        """
        data = {
            'body': body,
            'name': name,
        }

        if not files:
            self._headers.update({'Content-Type': 'multipart/form-data'})

        return self._http_request('PUT',
                                  f'api/v2/conversations/{conversation_id}',
                                  data=data,
                                  files=files)

    def freshservice_ticket_conversation_delete(
        self,
        conversation_id: int,
    ) -> requests.Response:
        """ Delete the Conversation on a Ticket with the
            given ID from Freshservice.

        Args:
            conversation_id (int): The Conversation ID.

        Returns:
            requests.Response: Information about the response from Freshservice
        """
        return self._http_request(
            'DELETE',
            f'api/v2/conversations/{conversation_id}',
            resp_type='response',
        )

    def freshservice_problem_list(
        self,
        page: int = None,
        page_size: int = None,
        problem_id: int = None,
        updated_since: str = None,
        order_type: str = None,
        resp_type: str = "json",
        full_url: str = '',
    ) -> dict[str, Any]:
        """ Lists all the problems in a Freshservice account.

        Args:
            page (int): The number of items per page.
            page_size (int): Page number of paginated results.
            problem_id (int, optional): Problem ID. Defaults to None.
            updated_since (str, optional): Fetch ticket updated since. Defaults to None.
            order_type (str, optional): order type. Defaults to None.

        Returns:
            Dict[str, Any]: API response from Freshservice.
        """
        if full_url:
            return self._http_request('GET', full_url=full_url, resp_type=resp_type)

        params = remove_empty_elements({
            'page': page,
            'per_page': page_size,
            'updated_since': updated_since,
            'order_type': order_type,
        })

        return self._http_request(
            'GET',
            f'api/v2/problems{get_url_suffix(problem_id)}',
            params=params,
            resp_type=resp_type)

    def freshservice_problem_create(self, **kwargs) -> dict[str, Any]:
        """ Create a new problem request in Freshservice.

        Args:
            description (str): Problem request description.
            priority (int): Priority of the Problem.
            status (int): Status identifier of the Problem.
            subject (str): Problem request subject.
            sub_category (str, optional): The sub-category of the Problem.
                    Defaults to None.
            analysis_fields (int, optional): Key value pairs containing the
                    names and values of the Problem Cause, Problem Symptom,
                    and Problem Impact. Defaults to None.
            agent_id (int, optional): Unique identifier of the agent to whom
                    the Problem is assigned. Defaults to None.
            requester_id (int, optional): Requester ID. Defaults to None.
            group_id (int, optional): Unique identifier of the agent group to
                    which the Problem is assigned. Defaults to None.
            impact (int, optional): Impact of the Problem. Defaults to None.
            email (str, optional): Requester email. If not specified - must
                    provide 'requester_id'. Defaults to None.
            due_by (str, optional): Timestamp at which Problem due ends.
                    Defaults to None.
            department_id (int, optional): Unique ID of the department
                    initiating the Problem. Defaults to None.
            custom_fields (List[str], optional): Key value pairs containing
                    the names and values of custom fields. Defaults to None.
            category (str, optional): Category of the Problem.
                    Defaults to None.
            assets (int, optional): List of assets associated with the problem.
                    Defaults to None.

        Returns:
            Dict[str, Any]: API response from Freshservice.
        """
        kwargs = locals().pop('kwargs', None)
        data = remove_empty_elements(kwargs)

        return self._http_request(
            'POST',
            'api/v2/problems',
            json_data=data,
        )

    def freshservice_problem_update(self, ticket_id: int,
                                    **kwargs) -> dict[str, Any]:
        """ Update an existing Problem in Freshservice.

        Args:
            ticket_id (int): The problem ID.
            description (str): Problem request description.
            priority (int): Priority of the Problem.
            status (int): Status identifier of the Problem.
            subject (str): Problem request subject.
            sub_category (str, optional): The sub-category of the Problem.
                    Defaults to None.
            analysis_fields (int, optional): Key value pairs containing the
                    names and values of the Problem Cause, Problem Symptom,
                    and Problem Impact. Defaults to None.
            agent_id (int, optional): Unique identifier of the agent to whom
                    the Problem is assigned. Defaults to None.
            requester_id (int, optional): Requester ID. Defaults to None.
            group_id (int, optional): Unique identifier of the agent group to
                    which the Problem is assigned. Defaults to None.
            impact (int, optional): Impact of the Problem. Defaults to None.
            email (str, optional): Requester email. If not specified - must
                    provide 'requester_id'. Defaults to None.
            due_by (str, optional): Timestamp at which Problem due ends.
                    Defaults to None.
            department_id (int, optional): Unique ID of the department
                    initiating the Problem. Defaults to None.
            custom_fields (List[str], optional): Key value pairs containing
                    the names and values of custom fields. Defaults to None.
            category (str, optional): Category of the Problem.
                    Defaults to None.
            assets (int, optional): List of assets associated with the problem.
                    Defaults to None.

        Returns:
            Dict[str, Any]: API response from Freshservice.
        """
        kwargs = locals().pop('kwargs', None)
        data = remove_empty_elements(kwargs)
        return self._http_request(
            'PUT',
            f'api/v2/problems/{ticket_id}',
            json_data=data,
        )

    def freshservice_problem_delete(
        self,
        ticket_id: int,
    ) -> requests.Response:
        """ Delete the Problem with the given ID from Freshservice.

        Args:
            ticket_id (int): The problem ID to delete.

        Returns:
            requests.Response: Information about the response from Freshservice.
        """
        return self._http_request(
            'DELETE',
            f'api/v2/problems/{ticket_id}',
            resp_type='response',
        )

    def freshservice_problem_task_list(
        self,
        problem_id: int,
        page: int = None,
        page_size: int = None,
        task_id: int = None,
    ) -> dict[str, Any]:
        """ Lists all the problem tasks in a Freshservice account.

        Args:
            page (int): The number of items per page.
            page_size (int): Page number of paginated results.
            problem_id (int, optional): Problem ID. Defaults to None.
            task_id (int, optional): Task ID. Defaults to None.
        Returns:
            Dict[str, Any]: API response from Freshservice.
        """

        params = remove_empty_elements({
            'page': page,
            'per_page': page_size,
        })

        return self._http_request(
            'GET',
            f'api/v2/problems/{problem_id}/tasks{get_url_suffix(task_id)}',
            params=params,
        )

    def freshservice_problem_task_create(
        self,
        ticket_id: int,
        due_date: str,
        notify_before: int,
        title: str,
        description: str,
        status: int = None,
    ) -> dict[str, Any]:
        """ Create a new task on a Problem request in Freshservice.

        Args:
            ticket_id (int): The Problem ID to add a task for.
            due_date (str): Task due date.
            notify_before (int): Time in seconds before which notification is sent prior to due date.
            title (str): Task title.
            description (str): Task description.
            status (int, optional): Task status. Defaults to None.

        Returns:
            Dict[str, Any]: API response from Freshservice.
        """
        data = remove_empty_elements({
            "description": description,
            "due_date": due_date,
            "notify_before": notify_before,
            "title": title,
            "status": status
        })

        return self._http_request('POST',
                                  f'api/v2/problems/{ticket_id}/tasks',
                                  json_data=data)

    def freshservice_problem_task_update(
        self,
        ticket_id: int,
        task_id: int,
        due_date: str = None,
        notify_before: int = None,
        title: str = None,
        description: str = None,
        status: int = None,
    ) -> dict[str, Any]:
        """ Update a task on a problem request in Freshservice.

        Args:
            ticket_id (int): The problem ID to update a task for.
            task_id (int): The task ID.
            due_date (str): Task due date.
            notify_before (int): Time in seconds before which notification is sent prior to due date.
            title (str): Task title.
            description (str): Task description.
            status (int, optional): Task status. Defaults to None.

        Returns:
            Dict[str, Any]: API response from Freshservice.
        """
        data = remove_empty_elements({
            "description": description,
            "due_date": due_date,
            "notify_before": notify_before,
            "title": title,
            "status": status
        })

        return self._http_request(
            'PUT',
            f'api/v2/problems/{ticket_id}/tasks/{task_id}',
            json_data=data)

    def freshservice_problem_task_delete(
        self,
        problem_id: int,
        task_id: int,
    ) -> requests.Response:
        """ Delete a task on a problem request in Freshservice.

        Args:
            problem_id (int): The problem ID to update a task for.
            task_id (int): The task ID.

        Returns:
            requests.Response: Information about the response from Freshservice.
        """
        return self._http_request(
            'DELETE',
            f'api/v2/problems/{problem_id}/tasks/{task_id}',
            resp_type='response',
        )

    def freshservice_change_list(
        self,
        page: int = None,
        page_size: int = None,
        change_id: int = None,
        updated_since: str = None,
        order_type: str = None,
        resp_type: str = "json",
        full_url: str = '',
    ) -> dict[str, Any]:
        """ Lists all the changes in a Freshservice account.

        Args:
            page (int): The number of items per page.
            page_size (int): Page number of paginated results.
            change_id (int, optional): Change ID. Defaults to None.
            updated_since (str, optional): Fetch ticket updated since. Defaults to None.
            order_type (str, optional): order type. Defaults to None.

        Returns:
            Dict[str, Any]: API response from Freshservice.
        """
        if full_url:
            return self._http_request('GET', full_url=full_url, resp_type=resp_type)

        params = remove_empty_elements({
            'page': page,
            'per_page': page_size,
            'updated_since': updated_since,
            'order_type': order_type,
        })

        return self._http_request('GET',
                                  f'api/v2/changes{get_url_suffix(change_id)}',
                                  params=params,
                                  resp_type=resp_type)

    def freshservice_change_create(self, **kwargs) -> dict[str, Any]:
        """ Create a new change request in Freshservice.

        Args:
            description (str): change request description.
            priority (int): Priority of the change.
            status (int): Status identifier of the change.
            subject (str): change request subject.
            risk (int): change risk.
            change_type (int): change type.
            impact (int): change impact.
            planned_start_date (str): Timestamp at which change is starting.
            planned_end_date (str): Timestamp at which change is ending.
            email (str, optional): Requester email. Defaults to None.
            category (str, optional): Category of the Problem.
                    Defaults to None.
            sub_category (str, optional): The sub-category of the Problem.
                    Defaults to None.
            requester_id (int, optional): Requester ID. Defaults to None.
            department_id (int, optional): Unique ID of the department
                    initiating the change. Defaults to None.
            group_id (int, optional): Unique identifier of the agent group to
                    which the change is assigned. Defaults to None.
            agent_id (int, optional): Unique identifier of the agent to whom
                    the change is assigned. Defaults to None.

        Returns:
            Dict[str, Any]: API response from Freshservice.
        """
        kwargs = locals().pop('kwargs', None)
        data = remove_empty_elements(kwargs)

        return self._http_request('POST', 'api/v2/changes', json_data=data)

    def freshservice_change_update(
        self,
        ticket_id: int,
        **kwargs,
    ) -> dict[str, Any]:
        """ Update an existing change request in Freshservice.

        Args:
            ticket_id (int): change request ID.
            description (str): change request description.
            priority (int): Priority of the change.
            status (int): Status identifier of the change.
            subject (str): change request subject.
            risk (int): change risk.
            change_type (int): change type.
            impact (int): change impact.
            planned_start_date (str): Timestamp at which change is starting.
            planned_end_date (str): Timestamp at which change is ending.
            email (str, optional): Requester email. Defaults to None.
            category (str, optional): Category of the Problem.
                    Defaults to None.
            sub_category (str, optional): The sub-category of the Problem.
                    Defaults to None.
            requester_id (int, optional): Requester ID. Defaults to None.
            department_id (int, optional): Unique ID of the department
                    initiating the change. Defaults to None.
            group_id (int, optional): Unique identifier of the agent group to
                    which the change is assigned. Defaults to None.
            agent_id (int, optional): Unique identifier of the agent to whom
                    the change is assigned. Defaults to None.

        Returns:
            Dict[str, Any]: API response from Freshservice.
        """
        kwargs = locals().pop('kwargs', None)
        data = remove_empty_elements(kwargs)

        return self._http_request(
            'PUT',
            f'api/v2/changes/{ticket_id}',
            json_data=data,
        )

    def freshservice_change_delete(
        self,
        change_id: int,
    ) -> requests.Response:
        """ Delete a change request from Freshservice.

        Args:
            change_id (int): The change ID.

        Returns:
            requests.Response: Information about the response from Freshservice.
        """

        return self._http_request(
            'DELETE',
            f'api/v2/changes/{change_id}',
            resp_type='response',
        )

    def freshservice_change_task_list(
        self,
        change_id: int,
        page: int = None,
        page_size: int = None,
        task_id: int = None,
    ) -> dict[str, Any]:
        """ Lists all the change tasks in a Freshservice account.

        Args:
            page (int): The number of items per page.
            page_size (int): Page number of paginated results.
            change_id (int, optional): Change ID. Defaults to None.
            task_id (int, optional): Task ID. Defaults to None.
        Returns:
            Dict[str, Any]: API response from Freshservice.
        """

        params = remove_empty_elements({
            'page': page,
            'per_page': page_size,
        })

        return self._http_request(
            'GET',
            f'api/v2/changes/{change_id}/tasks{get_url_suffix(task_id)}',
            params=params,
        )

    def freshservice_change_task_create(
        self,
        ticket_id: int,
        due_date: str,
        notify_before: int,
        title: str,
        description: str,
        status: int = None,
    ) -> dict[str, Any]:
        """ Create a new task on a change request in Freshservice.

        Args:
            ticket_id (int): The change ID to add a task for.
            due_date (str): Task due date.
            notify_before (int): Time in seconds before which notification is sent prior to due date.
            title (str): Task title.
            description (str): Task description.
            status (int, optional): Task status. Defaults to None.

        Returns:
            Dict[str, Any]: API response from Freshservice.
        """
        data = remove_empty_elements({
            "description": description,
            "due_date": due_date,
            "notify_before": notify_before,
            "title": title,
            "status": status
        })

        return self._http_request('POST',
                                  f'api/v2/changes/{ticket_id}/tasks',
                                  json_data=data)

    def freshservice_change_task_update(
        self,
        ticket_id: int,
        task_id: int,
        due_date: str = None,
        notify_before: int = None,
        title: str = None,
        description: str = None,
        status: int = None,
    ) -> dict[str, Any]:
        """ Update a task on a change request in Freshservice.

        Args:
            ticket_id (int): The change ID to update a task for.
            task_id (int): The task ID.
            due_date (str): Task due date.
            notify_before (int): Time in seconds before which notification is sent prior to due date.
            title (str): Task title.
            description (str): Task description.
            status (int, optional): Task status. Defaults to None.

        Returns:
            Dict[str, Any]: API response from Freshservice.
        """
        data = remove_empty_elements({
            "description": description,
            "due_date": due_date,
            "notify_before": notify_before,
            "title": title,
            "status": status
        })

        return self._http_request(
            'PUT',
            f'api/v2/changes/{ticket_id}/tasks/{task_id}',
            json_data=data)

    def freshservice_change_task_delete(
        self,
        change_id: int,
        task_id: int,
    ) -> requests.Response:
        """ Delete a task on a change request in Freshservice.

        Args:
            change_id (int): The change ID to update a task for.
            task_id (int): The task ID.

        Returns:
            requests.Response: Information about the response from Freshservice.
        """
        return self._http_request(
            'DELETE',
            f'api/v2/changes/{change_id}/tasks/{task_id}',
            resp_type='response',
        )

    def freshservice_release_list(
        self,
        page: int = None,
        page_size: int = None,
        release_id: int = None,
        updated_query: str = None,
        updated_since: str = None,
        order_type: str = None,
        resp_type: str = "json",
        full_url: str = '',
    ) -> dict[str, Any]:
        """ Lists all the releases in a Freshservice account.

        Args:
            page (int): The number of items per page.
            page_size (int): Page number of paginated results.
            release_id (int, optional): release ID. Defaults to None.
            updated_since (str, optional): Fetch ticket updated since. Defaults to None.
            order_type (str, optional): order type. Defaults to None.
        Returns:
            Dict[str, Any]: API response from Freshservice.
        """
        if full_url:
            return self._http_request('GET', full_url=full_url, resp_type=resp_type)

        params = remove_empty_elements({
            'page': page,
            'per_page': page_size,
            'filter_name': updated_query,
            'updated_since': updated_since,
            'order_type': order_type,
        })

        return self._http_request(
            'GET',
            f'api/v2/releases{get_url_suffix(release_id)}',
            params=params,
            resp_type=resp_type)

    def freshservice_release_create(self, **kwargs) -> dict[str, Any]:
        """ Create a new release request in Freshservice.

        Args:
            ticket_id (int): release request ID.
            description (str): release request description.
            priority (int): Priority of the release.
            status (int): Status identifier of the release.
            subject (str): release request subject.
            risk (int): release risk.
            release_type (int): release type.
            impact (int): release impact.
            planned_start_date (str): Timestamp at which release is starting.
            planned_end_date (str): Timestamp at which release is ending.
            email (str, optional): Requester email. Defaults to None.
            category (str, optional): Category of the Problem.
                    Defaults to None.
            sub_category (str, optional): The sub-category of the Problem.
                    Defaults to None.
            requester_id (int, optional): Requester ID. Defaults to None.
            department_id (int, optional): Unique ID of the department
                    initiating the release. Defaults to None.
            group_id (int, optional): Unique identifier of the agent group to
                    which the release is assigned. Defaults to None.
            agent_id (int, optional): Unique identifier of the agent to whom
                    the release is assigned. Defaults to None.
            custom_fields (List[str], optional): Key value pairs containing
                    the names and values of custom fields. Defaults to None.

        Returns:
            Dict[str, Any]: API response from Freshservice.
        """
        kwargs = locals().pop('kwargs', None)
        data = remove_empty_elements(kwargs)

        return self._http_request('POST', 'api/v2/releases', json_data=data)

    def freshservice_release_update(
        self,
        ticket_id: int,
        **kwargs,
    ) -> dict[str, Any]:
        """ Update an existing release request in Freshservice.

        Args:
            ticket_id (int): release request ID.
            description (str): release request description.
            priority (int): Priority of the release.
            status (int): Status identifier of the release.
            subject (str): release request subject.
            risk (int): release risk.
            release_type (int): release type.
            impact (int): release impact.
            planned_start_date (str): Timestamp at which release is starting.
            planned_end_date (str): Timestamp at which release is ending.
            email (str, optional): Requester email. Defaults to None.
            category (str, optional): Category of the Problem.
                    Defaults to None.
            sub_category (str, optional): The sub-category of the Problem.
                    Defaults to None.
            requester_id (int, optional): Requester ID. Defaults to None.
            department_id (int, optional): Unique ID of the department
                    initiating the release. Defaults to None.
            group_id (int, optional): Unique identifier of the agent group to
                    which the release is assigned. Defaults to None.
            agent_id (int, optional): Unique identifier of the agent to whom
                    the release is assigned. Defaults to None.
            custom_fields (List[str], optional): Key value pairs containing
                    the names and values of custom fields. Defaults to None.

        Returns:
            Dict[str, Any]: API response from Freshservice.
        """
        kwargs = locals().pop('kwargs', None)
        data = remove_empty_elements(kwargs)

        return self._http_request(
            'PUT',
            f'api/v2/releases/{ticket_id}',
            json_data=data,
        )

    def freshservice_release_delete(
        self,
        release_id: int,
    ) -> requests.Response:
        """ Delete a release request from Freshservice.

        Args:
            release_id (int): The release ID.

        Returns:
            requests.Response: Information about the response from Freshservice.
        """

        return self._http_request(
            'DELETE',
            f'api/v2/releases/{release_id}',
            resp_type='response',
        )

    def freshservice_release_task_list(
        self,
        release_id: int,
        page: int = None,
        page_size: int = None,
        task_id: int = None,
    ) -> dict[str, Any]:
        """ Lists all the release tasks in a Freshservice account.

        Args:
            page (int): The number of items per page.
            page_size (int): Page number of paginated results.
            release_id (int, optional): Release ID. Defaults to None.
            task_id (int, optional): Task ID. Defaults to None.
        Returns:
            Dict[str, Any]: API response from Freshservice.
        """

        params = remove_empty_elements({
            'page': page,
            'per_page': page_size,
        })

        return self._http_request(
            'GET',
            f'api/v2/releases/{release_id}/tasks{get_url_suffix(task_id)}',
            params=params,
        )

    def freshservice_release_task_create(
        self,
        ticket_id: int,
        due_date: str,
        notify_before: int,
        title: str,
        description: str,
        status: int = None,
    ) -> dict[str, Any]:
        """ Create a new task on a release request in Freshservice.

        Args:
            ticket_id (int): The release ID to add a task for.
            due_date (str): Task due date.
            notify_before (int): Time in seconds before which notification is sent prior to due date.
            title (str): Task title.
            description (str): Task description.
            status (int, optional): Task status. Defaults to None.

        Returns:
            Dict[str, Any]: API response from Freshservice.
        """
        data = remove_empty_elements({
            "description": description,
            "due_date": due_date,
            "notify_before": notify_before,
            "title": title,
            "status": status
        })

        return self._http_request('POST',
                                  f'api/v2/releases/{ticket_id}/tasks',
                                  json_data=data)

    def freshservice_release_task_update(
        self,
        ticket_id: int,
        task_id: int,
        due_date: str = None,
        notify_before: int = None,
        title: str = None,
        description: str = None,
        status: int = None,
    ) -> dict[str, Any]:
        """ Update a task on a release request in Freshservice.

        Args:
            ticket_id (int): The release ID to update a task for.
            task_id (int): The task ID.
            due_date (str): Task due date.
            notify_before (int): Time in seconds before which notification is sent prior to due date.
            title (str): Task title.
            description (str): Task description.
            status (int, optional): Task status. Defaults to None.

        Returns:
            Dict[str, Any]: API response from Freshservice.
        """
        data = remove_empty_elements({
            "description": description,
            "due_date": due_date,
            "notify_before": notify_before,
            "title": title,
            "status": status
        })

        return self._http_request(
            'PUT',
            f'api/v2/releases/{ticket_id}/tasks/{task_id}',
            json_data=data)

    def freshservice_release_task_delete(
        self,
        release_id: int,
        task_id: int,
    ) -> requests.Response:
        """ Delete a task on a release request in Freshservice.

        Args:
            release_id (int): The release ID to update a task for.
            task_id (int): The task ID.

        Returns:
            requests.Response: Information about the response from Freshservice.
        """
        return self._http_request(
            'DELETE',
            f'api/v2/releases/{release_id}/tasks/{task_id}',
            resp_type='response',
        )

    def freshservice_requester_list(
        self,
        page: int = None,
        page_size: int = None,
        entity_id_value: int = None,
        updated_query: str = None,
    ) -> dict[str, Any]:
        """ Lists all the requesters in a Freshservice account.

        Args:
            page (int): The number of items per page.
            page_size (int): Page number of paginated results.
            entity_id_value (int, optional): requester ID. Defaults to None.
            updated_query (str, optional): Query to filter items. Defaults to None.

        Returns:
            Dict[str, Any]: API response from Freshservice.
        """
        params = remove_empty_elements({
            'page': page,
            'per_page': page_size,
            'query': updated_query,
        })

        return self._http_request(
            'GET',
            f'api/v2/requesters{get_url_suffix(entity_id_value)}',
            params=params)

    def freshservice_requester_field_list(
        self,
        page: int = None,
        page_size: int = None,
    ) -> dict[str, Any]:
        """ Lists all the requesters in a Freshservice account.

        Returns:
            Dict[str, Any]: API response from Freshservice.
        """
        params = remove_empty_elements({
            'page': page,
            'per_page': page_size,
        })
        return self._http_request(
            'GET',
            'api/v2/requester_fields',
            params=params,
        )

    def freshservice_agent_list(
        self,
        page: int = None,
        page_size: int = None,
        entity_id_value: int = None,
        updated_query: str = None,
    ) -> dict[str, Any]:
        """ Lists all the Agents in a Freshservice account.

        Args:
            page (int): The number of items per page.
            page_size (int): Page number of paginated results.
            entity_id_value (int, optional): Agent ID. Defaults to None.
            updated_query (str, optional): Query to filter items. Defaults to None.

        Returns:
            Dict[str, Any]: API response from Freshservice.
        """
        params = remove_empty_elements({
            'page': page,
            'per_page': page_size,
            'query': updated_query,
        })

        return self._http_request(
            'GET',
            f'api/v2/agents{get_url_suffix(entity_id_value)}',
            params=params)

    def freshservice_role_list(
        self,
        page: int = None,
        page_size: int = None,
        entity_id_value: int = None,
    ) -> dict[str, Any]:
        """ Lists all the Roles in a Freshservice account.

        Args:
            page (int): The number of items per page.
            page_size (int): Page number of paginated results.
            entity_id_value (int, optional): Role ID. Defaults to None.

        Returns:
            Dict[str, Any]: API response from Freshservice.
        """
        params = remove_empty_elements({'page': page, 'per_page': page_size})

        return self._http_request(
            'GET',
            f'api/v2/roles{get_url_suffix(entity_id_value)}',
            params=params)

    def freshservice_vendor_list(
        self,
        page: int = None,
        page_size: int = None,
        entity_id_value: int = None,
    ) -> dict[str, Any]:
        """ Lists all the Vendors in a Freshservice account.

        Args:
            page (int): The number of items per page.
            page_size (int): Page number of paginated results.
            entity_id_value (int, optional): Vendor ID. Defaults to None.

        Returns:
            Dict[str, Any]: API response from Freshservice.
        """
        params = remove_empty_elements({'page': page, 'per_page': page_size})

        return self._http_request(
            'GET',
            f'api/v2/vendors{get_url_suffix(entity_id_value)}',
            params=params)

    def freshservice_software_list(
        self,
        page: int = None,
        page_size: int = None,
        entity_id_value: int = None,
    ) -> dict[str, Any]:
        """ Lists all the Softwares in a Freshservice account.

        Args:
            page (int): The number of items per page.
            page_size (int): Page number of paginated results.
            entity_id_value (int, optional): Software ID. Defaults to None.

        Returns:
            Dict[str, Any]: API response from Freshservice.
        """

        params = remove_empty_elements({'page': page, 'per_page': page_size})

        return self._http_request(
            'GET',
            f'api/v2/applications{get_url_suffix(entity_id_value)}',
            params=params)

    def freshservice_asset_list(
        self,
        page: int = None,
        page_size: int = None,
        entity_id_value: int = None,
        updated_query: str = None,
    ) -> dict[str, Any]:
        """ Lists all the Assets in a Freshservice account.

        Args:
            page (int): The number of items per page.
            page_size (int): Page number of paginated results.
            entity_id_value (int, optional): Asset ID. Defaults to None.
            updated_query (str, optional): Query to filter items. Defaults to None.

        Returns:
            Dict[str, Any]: API response from Freshservice.
        """
        params = {
            'filter': updated_query
        } if updated_query else remove_empty_elements({
            'page': page,
            'per_page': page_size
        })

        return self._http_request(
            'GET',
            f'api/v2/assets{get_url_suffix(entity_id_value)}',
            params=params)

    def freshservice_purchase_order_list(
        self,
        page: int = None,
        page_size: int = None,
        entity_id_value: int = None,
    ) -> dict[str, Any]:
        """ Lists all the purchase orders in a Freshservice account.

        Args:
            page_size (int): The number of items per page.
            page (int): Page number of paginated results.
            entity_id_value (int, optional): Purchase order ID.

        Returns:
            Dict[str, Any]: API response from Freshservice.
        """
        params = remove_empty_elements({'page': page, 'per_page': page_size})

        return self._http_request(
            'GET',
            f'api/v2/purchase_orders{get_url_suffix(entity_id_value)}',
            params=params)

    def freshservice_agent_group_list(
        self,
        page: int = None,
        page_size: int = None,
        entity_id_value: int = None,
    ) -> dict[str, Any]:
        """ Lists all the agent groups in a Freshservice account.

        Args:
            page_size (int): The number of items per page.
            page (int): Page number of paginated results.
            entity_id_value (int, optional): Agent group ID.

        Returns:
            Dict[str, Any]: API response from Freshservice.
        """
        params = remove_empty_elements({'page': page, 'per_page': page_size})

        return self._http_request(
            'GET',
            f'api/v2/groups{get_url_suffix(entity_id_value)}',
            params=params)

    def freshservice_department_list(
        self,
        page: int = None,
        page_size: int = None,
        entity_id_value: int = None,
        updated_query: str = None,
    ) -> dict[str, Any]:
        """ Lists all the departments in a Freshservice account.

        Args:
            page_size (int): The number of items per page.
            page (int): Page number of paginated results.
            entity_id_value (int, optional): Department ID.

        Returns:
            Dict[str, Any]: API response from Freshservice.
        """
        params = remove_empty_elements({
            'page': page,
            'per_page': page_size,
            'query': updated_query,
        })

        return self._http_request(
            'GET',
            f'api/v2/departments{get_url_suffix(entity_id_value)}',
            params=params)


def list_freshservice_ticket_command(
    client: Client,
    args: dict[str, Any],
) -> CommandResults:
    """ Lists all the tickets/ problems/ changes/ releases in a Freshservice account.

    Args:
        client (Client): Freshservice API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    entity_id_value, entity_name, output_prefix, _ = get_args_by_command_name(
        args)

    command_args = get_command_list_args(args, entity_name, entity_id_value)
    freshservice_request = get_command_request(client, entity_name)

    command_args_dict = command_args._asdict()
    command_args_dict[f'{entity_name}_id'] = entity_id_value
    pagination_message = command_args_dict.pop('pagination_message', None)
    command_response_key = command_args_dict.pop('command_response_key', None)

    request_args = remove_empty_elements(command_args_dict)

    response = freshservice_request(**request_args)

    updated_response = convert_response_properties(
        response.get(command_response_key),
        TICKET_PROPERTIES_BY_TYPE[entity_name],
    )

    readable_output = tableToMarkdown(
        name=output_prefix,
        metadata=pagination_message,
        t=remove_empty_elements(updated_response),
        headers=READABLE_OUTPUT_HEADER_BY_ENTITY.get(entity_name),
        headerTransform=string_to_table_header,
    )

    return CommandResults(readable_output=readable_output,
                          outputs_prefix=f'Freshservice.{output_prefix}',
                          outputs_key_field='id',
                          outputs=updated_response,
                          raw_response=updated_response)


def create_update_freshservice_ticket_command(
    client: Client,
    args: dict[str, Any],
) -> CommandResults:
    """ Create a new or update an existing Ticket/ Problem/ Change/ Release in Freshservice.

    Args:
        client (Client): Freshservice API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    entity_id_value, entity_name, output_prefix, command_operator = get_args_by_command_name(
        args)

    args_for_request = get_request_arguments_per_ticket_type(
        entity_name,
        args,
        entity_id_value,
    )
    freshservice_request = get_command_request(
        client, f'{entity_name}_{command_operator}')

    response = freshservice_request(**args_for_request, )

    # Only 'ticket' supports the 'attachments' field.
    # In the API there is an issue while creating a ticket with 'attachments' and other fields.
    # If the ticket exists we:
    # 1. Create a ticket without the attachments.
    # 2. Update the ticket with the attachments.
    update_response = update_ticket_attachments(client, args_for_request,
                                                response, command_operator)
    response = update_response or response
    updated_response = convert_response_properties(
        response[entity_name],
        TICKET_PROPERTIES_BY_TYPE[entity_name],
    )

    readable_output = tableToMarkdown(
        name=output_prefix,
        metadata=f'{output_prefix} {command_operator}d successfully',
        t=remove_empty_elements(updated_response),
        headers=READABLE_OUTPUT_HEADER_BY_ENTITY.get(entity_name),
        headerTransform=string_to_table_header,
    )

    return CommandResults(readable_output=readable_output,
                          outputs_prefix=f'Freshservice.{output_prefix}',
                          outputs_key_field='id',
                          outputs=updated_response,
                          raw_response=updated_response)


def delete_freshservice_ticket_command(
    client: Client,
    args: dict[str, Any],
) -> CommandResults:
    """ Delete an existing Ticket/ Problem/ Change/ Release in Freshservice.

    Args:
        client (Client): Freshservice API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    entity_id_value, entity_name, output_prefix, _ = get_args_by_command_name(
        args, )
    freshservice_request = get_command_request(client, f'{entity_name}_delete')

    try:
        freshservice_request(entity_id_value)
        readable_output = f'{output_prefix} deleted successfully'
    except DemistoException as exc:
        if exc.res is not None and exc.res.status_code in [
            HTTPStatus.METHOD_NOT_ALLOWED, HTTPStatus.NOT_FOUND
        ]:
            readable_output = f'{output_prefix} {entity_id_value} does not exist'
        else:
            # if there's a different HTTP status code, it's not an expected behavior.
            raise Exception(f'Got the following error: {exc.message}')

    return CommandResults(readable_output=readable_output)


def list_freshservice_ticket_task_command(
    client: Client,
    args: dict[str, Any],
) -> CommandResults:
    """ Retrieve tasks list (or a specific task) on a Ticket/ Problem/ Change/
        Release with the given ID from Freshservice.

    Args:
        client (Client): Freshservice API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """

    task_id = args.get('task_id')
    entity_id_value, entity_name, output_prefix, _ = get_args_by_command_name(
        args)

    command_args = get_command_list_args(args, 'task', task_id)

    freshservice_request = get_command_request(client, f'{entity_name}_task')

    response = freshservice_request(entity_id_value, command_args.page,
                                    command_args.page_size, task_id)

    updated_response = convert_response_properties(
        response[command_args.command_response_key],
        TASK_STATUS_VALUES,
    )
    updated_output = {'id': entity_id_value, 'Task': updated_response}

    readable_output = tableToMarkdown(
        name=f'{output_prefix}',
        metadata=command_args.pagination_message,
        t=remove_empty_elements(updated_output['Task']),
        headers=READABLE_OUTPUT_HEADER_BY_ENTITY['task'],
        headerTransform=string_to_table_header,
    )

    return CommandResults(readable_output=readable_output,
                          outputs_prefix=f'Freshservice.{output_prefix}',
                          outputs_key_field='id',
                          outputs=updated_output,
                          raw_response=updated_output)


def create_update_freshservice_ticket_task_command(
    client: Client,
    args: dict[str, Any],
) -> CommandResults:
    """ Create or Update task of a Ticket/ Problem/ Change/
        Release with the given ID from Freshservice.

    Args:
        client (Client): Freshservice API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    entity_id_value, entity_name, output_prefix, command_operator = get_args_by_command_name(
        args)

    if notify_before := arg_to_datetime(args.get('notify_before')):
        notify_before_timestamp = int(notify_before.timestamp())
        notify_before_seconds = get_default_seconds(notify_before_timestamp)
    else:
        notify_before_seconds = None

    # Send only the relevant arguments to the request
    # (there are 8 different requests)
    request_args = remove_empty_elements(
        assign_params(ticket_id=entity_id_value,
                      task_id=args.get('task_id'),
                      due_date=args.get('due_date'),
                      notify_before=notify_before_seconds,
                      title=args.get('title'),
                      description=args.get('description'),
                      status=TASK_STATUS_VALUES['status'][args['status']]
                      if args.get('status') else None))

    freshservice_request = get_command_request(
        client, f'{entity_name}_task_{command_operator}')

    response = freshservice_request(**request_args)

    updated_response = convert_response_properties(
        response.get('task'),
        TASK_STATUS_VALUES,
    )
    updated_output = {'id': entity_id_value, 'Task': updated_response}

    readable_output = tableToMarkdown(
        name=f'{output_prefix}',
        metadata=f'{output_prefix} Task {command_operator}d successfully',
        t=remove_empty_elements(updated_output.get('Task')),
        headers=READABLE_OUTPUT_HEADER_BY_ENTITY.get('task'),
        headerTransform=string_to_table_header,
    )
    return CommandResults(readable_output=readable_output,
                          outputs_prefix=f'Freshservice.{output_prefix}',
                          outputs_key_field='id',
                          outputs=updated_output,
                          raw_response=updated_output)


def delete_freshservice_ticket_task_command(
    client: Client,
    args: dict[str, Any],
) -> CommandResults:
    """ Delete task from a Ticket/ Problem/ Change/
        Release with the given ID from Freshservice.

    Args:
        client (Client): Freshservice API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    entity_id_value, entity_name, output_prefix, command_operator = get_args_by_command_name(
        args)

    task_id = args['task_id']

    freshservice_request = get_command_request(
        client, f'{entity_name}_task_{command_operator}')
    try:
        freshservice_request(entity_id_value, task_id)
        readable_output = f'{output_prefix} Task deleted successfully'
    except DemistoException as exc:
        if exc.res is not None and exc.res.status_code in [
            HTTPStatus.METHOD_NOT_ALLOWED, HTTPStatus.NOT_FOUND
        ]:
            readable_output = f'Task {task_id} does not exist'
        else:
            # if there's a different HTTP status code, it's not an expected behavior.
            raise Exception(f'Got the following error: {exc.message}')

    return CommandResults(readable_output=readable_output)


def list_freshservice_ticket_conversation_command(
    client: Client,
    args: dict[str, Any],
) -> CommandResults:
    """ Retrieve all Conversations of a Ticket. Conversations consist of
        replies as well as public and private notes added to a ticket.

    Args:
        client (Client): Freshservice API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    entity_id_value, *_ = get_args_by_command_name(args)

    command_args = get_command_list_args(args, 'conversation')

    response = client.freshservice_ticket_conversation_list(
        ticket_id=entity_id_value,
        page=command_args.page,
        page_size=command_args.page_size,
    )

    updated_response = response.get('conversations')
    updated_output = {'id': entity_id_value, 'Conversation': updated_response}

    readable_output = tableToMarkdown(
        name='Ticket conversations',
        metadata=command_args.pagination_message,
        t=remove_empty_elements(updated_output.get('Conversation')),
        headers=READABLE_OUTPUT_HEADER_BY_ENTITY.get('conversation'),
        headerTransform=string_to_table_header,
    )
    return CommandResults(readable_output=readable_output,
                          outputs_prefix='Freshservice.Ticket',
                          outputs_key_field='id',
                          outputs=updated_output,
                          raw_response=updated_output)


def create_freshservice_ticket_conversation_reply_command(
    client: Client,
    args: dict[str, Any],
) -> CommandResults:
    """ Create a new reply for an existing Ticket Conversation.

    Args:
        client (Client): Freshservice API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """

    ticket_id = args['ticket_id']
    body = args['body']
    from_email = args.get('from_email')
    user_id = args.get('user_id')
    cc_emails = argToList(args.get('cc_emails'))
    bcc_emails = argToList(args.get('bcc_emails'))

    files = get_files_to_attach(args)

    response = client.freshservice_ticket_conversation_reply_create(
        ticket_id=ticket_id,
        body=body,
        from_email=from_email,
        user_id=user_id,
        cc_emails=cc_emails,
        bcc_emails=bcc_emails,
        files=files,
    )

    updated_output = {
        'id': ticket_id,
        'Conversation': response.get('conversation')
    }

    readable_output = tableToMarkdown(
        name='Ticket conversation reply created successfully',
        t=remove_empty_elements(updated_output.get('Conversation')),
        headers=READABLE_OUTPUT_HEADER_BY_ENTITY.get('reply'),
        headerTransform=string_to_table_header,
    )
    return CommandResults(readable_output=readable_output,
                          outputs_prefix='Freshservice.Ticket',
                          outputs_key_field='id',
                          outputs=updated_output,
                          raw_response=updated_output)


def create_freshservice_ticket_conversation_note_command(
    client: Client,
    args: dict[str, Any],
) -> CommandResults:
    """ Create a new note for an existing Ticket Conversation.

    Args:
        client (Client): Freshservice API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    ticket_id = args['ticket_id']
    body = args['body']
    incoming = args.get('incoming')
    notify_emails = args.get('notify_emails')
    private = args.get('private')
    user_id = args.get('user_id')
    files = get_files_to_attach(args)

    response = client.freshservice_ticket_conversation_note_create(
        ticket_id=ticket_id,
        body=body,
        incoming=incoming,
        user_id=user_id,
        notify_emails=notify_emails,
        private=private,
        files=files,
    )

    updated_output = {'id': ticket_id, 'Note': response.get('conversation')}

    readable_output = tableToMarkdown(
        name='Ticket conversation note created successfully',
        t=remove_empty_elements(updated_output.get('Note')),
        headers=READABLE_OUTPUT_HEADER_BY_ENTITY.get('conversation'),
        headerTransform=string_to_table_header,
    )
    return CommandResults(readable_output=readable_output,
                          outputs_prefix='Freshservice.Ticket',
                          outputs_key_field='id',
                          outputs=updated_output,
                          raw_response=updated_output)


def update_freshservice_ticket_conversation_command(
    client: Client,
    args: dict[str, Any],
) -> CommandResults:
    """ Update an existing Conversation on an existing Ticket in Freshservice.

    Args:
        client (Client): Freshservice API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """

    conversation_id = args['conversation_id']
    body = args['body']
    name = args.get('name')
    files = get_files_to_attach(args)

    response = client.freshservice_ticket_conversation_update(
        conversation_id=conversation_id,
        body=body,
        name=name,
        files=files,
    )

    updated_output = {
        'id': response['conversation'].get('ticket_id'),
        'Conversation': response.get('conversation'),
    }

    readable_output = tableToMarkdown(
        name='Ticket conversation updated successfully',
        t=remove_empty_elements(updated_output.get('Conversation')),
        headers=READABLE_OUTPUT_HEADER_BY_ENTITY.get('conversation'),
        headerTransform=string_to_table_header,
    )
    return CommandResults(readable_output=readable_output,
                          outputs_prefix='Freshservice.Ticket',
                          outputs_key_field='id',
                          outputs=updated_output,
                          raw_response=updated_output)


def delete_freshservice_ticket_conversation_command(
    client: Client,
    args: dict[str, Any],
) -> CommandResults:
    """ Delete the Conversation on a Ticket with the
        given ID from Freshservice.

    Args:
        client (Client): Freshservice API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    conversation_id = args['conversation_id']

    try:
        client.freshservice_ticket_conversation_delete(conversation_id)
        readable_output = 'Conversation deleted successfully'
    except DemistoException as exc:
        if exc.res is not None and exc.res.status_code in [
            HTTPStatus.METHOD_NOT_ALLOWED, HTTPStatus.NOT_FOUND
        ]:
            readable_output = 'Conversation does not exist'
        else:
            # if there's a different HTTP status code, it's not an expected behavior.
            raise Exception(f'Got the following error: {exc.message}')

    return CommandResults(readable_output=readable_output)


def list_freshservice_entities_command(
    client: Client,
    args: dict[str, Any],
) -> CommandResults:
    """ Lists all the requesters/ agents/ vendors/ softwares/ assets/
        agent groups/ roles/ purchase orders in a Freshservice account.

    Args:
        client (Client): Freshservice API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    entity_id_value, entity_name, output_prefix, _ = get_args_by_command_name(
        args)

    command_args = get_command_list_args(args, entity_name, entity_id_value)

    freshservice_request = get_command_request(client, entity_name)

    request_args = remove_empty_elements(
        assign_params(
            page=command_args.page,
            page_size=command_args.page_size,
            entity_id_value=entity_id_value,
            updated_query=command_args.updated_query,
        ))

    response = freshservice_request(**request_args)

    updated_response = response.get(command_args.command_response_key)
    if entity_name == 'purchase_order':
        updated_response = convert_response_properties(
            updated_response,
            PURCHASE_ORDER_STATUS_VALUES,
        )
        # to be align to rest entity response when get one entity and not list
        updated_response = updated_response[0] if len(
            updated_response) == 1 else updated_response

    readable_output = tableToMarkdown(
        name=output_prefix,
        metadata=command_args.pagination_message,
        t=remove_empty_elements(updated_response),
        headers=READABLE_OUTPUT_HEADER_BY_ENTITY.get(f'{entity_name}s'),
        headerTransform=string_to_table_header,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix=f'Freshservice.{output_prefix}',
        outputs_key_field='id',
        outputs=updated_response,
        raw_response=updated_response,
    )


def test_module(client: Client) -> str:
    try:
        client.freshservice_ticket_list(1, 20)
    except DemistoException as exc:
        if exc.res is not None and exc.res.status_code in [
            HTTPStatus.UNAUTHORIZED, HTTPStatus.NOT_FOUND,
            HTTPStatus.FORBIDDEN
        ]:
            return "Authorization Error: Unknown API key or Freshservice URL"

        return exc.message
    return "ok"


''' Helper Functions '''


def get_request_arguments_per_ticket_type(
    entity_name: str,
    args: dict[str, Any],
    entity_id_value: str = None,
) -> dict[str, Any]:
    """ Get the arguments for each ticket type when create or update ticket.

    Args:
        entity_name (str): The command entity name.
        args (Dict[str, Any]): command arguments from XSOAR.
        entity_id_value (str | None, optional): Ticket ID. Defaults to None.

    Returns:
        Dict[str, Any]: The updated arguments.
    """
    ticket_properties = convert_command_properties(
        args,
        entity_name,
    )

    # Prioritise a source_numeric command argument over a source command argument.
    if args.get('source_numeric'):
        source_value = args.get('source_numeric')
    else:
        source_value = ticket_properties.source

    validate_mandatory_ticket_requester_fields(
        entity_name,
        args,
        entity_id_value,
    )

    args_for_request = remove_empty_elements(
        assign_params(
            ticket_id=entity_id_value,
            description=args.get('description'),
            priority=ticket_properties.priority,
            status=ticket_properties.status,
            subject=args.get('subject'),
            urgency=ticket_properties.urgency,
            tags=argToList(args.get('tags')),
            sub_category=args.get('sub_category'),
            source=source_value,
            responder_id=arg_to_number(args.get('responder_id')),
            requester_id=arg_to_number(args.get('requester_id')),
            problem=get_arg_template(args.get('problem'), 'problem'),   # type: ignore[arg-type]
            phone=args.get('phone'),
            name=args.get('name'),
            impact=ticket_properties.impact,
            group_id=arg_to_number(args.get('group_id')),
            fr_due_by=args.get('fr_due_by'),
            email_config_id=args.get('email_config_id'),
            email=args.get('email'),
            due_by=args.get('due_by'),
            department_id=arg_to_number(args.get('department_id')),
            custom_fields=update_custom_fields(args),
            change_initiating_ticket=get_arg_template(args.get('change_initiating_ticket'),  # type: ignore[arg-type]
                                                      'change_initiating_ticket'),
            change_initiated_by_ticket=get_arg_template(args.get('change_initiated_by_ticket'),  # type: ignore[arg-type]
                                                        'change_initiated_by_ticket'),
            cc_emails=argToList(args.get('cc_emails')),
            category=args.get('category'),
            attachments=get_files_to_attach(args),
            assets=get_arg_template(argToList(args.get('assets')), 'assets'),
            analysis_fields=argToList(args.get('analysis_fields')),
            change_type=ticket_properties.change_type,
            risk=ticket_properties.risk,
            release_type=ticket_properties.release_type,
            planned_start_date=args.get('planned_start_date'),
            planned_end_date=args.get('planned_end_date'),
            resolution_notes=args.get('resolution_notes'),
        ))
    return args_for_request


def update_ticket_attachments(client: Client, args_for_request: dict[str, Any], create_response: dict[str, Any],
                              command_operator: str) -> dict[str, Any] | None:
    """ Update ticket with attachments when user create ticket with attachments.

    Args:
        client (Client): Freshservice client.
        args_for_request (Dict[str, Any]): Request arguments.
        create_response (Dict[str, Any]): Create ticket response.
        command_operator (str): The command operator.

    Returns:
        Union[Dict[str, Any], None]: Update ticket response.
    """
    response = None
    attachments = args_for_request.get('attachments')
    if attachments and command_operator == 'create':
        ticket_id = create_response['ticket']['id']
        response = client.freshservice_ticket_update(ticket_id,
                                                     attachments=attachments)

    return response


def get_arg_template(
    arg_values: list[dict[str, Any]],
    arg_name: str,
) -> dict[str, int | None] | list[dict[str, int | None]] | None:
    """ Get argument template {'display_id': some_id}.

    Args:
        arg_values (Optional[List[Dict[str, Any]]]): argument values (could be a list).
        arg_name (str): argument name.

    Returns:
        List[dict[str, int]] | None: updated argument according the template.
    """
    if not arg_values:
        return None
    arg_template = [{
        'display_id': arg_to_number(value)
    } for value in arg_values]

    if arg_name != 'assets':
        return arg_template[0]

    return arg_template


def update_custom_fields(args: dict[str, Any]) -> dict[Any, Any] | None:
    """ Update custom_fields argument to match Freshservice template.

    Args:
        args (Dict[str, Any]): command arguments from XSOAR.

    Returns:
        Optional[Dict[Any, Any]]: Updated field.
    """
    try:
        return {
            item.split("=")[0].strip(): item.split("=")[1].strip()
            for item in argToList(args.get('custom_fields'))
        } or None
    except IndexError:
        raise DemistoException("The custom_fields argument must be a comma-separated list of `key=value` items")


def validate_mandatory_ticket_requester_fields(
    entity_name: str,
    args: dict[str, Any],
    entity_id_value: str = None,
):
    """ Validate user specified one of the following:
        requester_id, phone, email
        when create any type of ticket.

    Args:
        entity_name (str): The command entity name.
        args (Dict[str, Any]): command arguments from XSOAR.
        entity_id_value (str | None, optional): Ticket ID. Defaults to None.

    Raises:
        ValueError: In case user don't specified the required fields.
    """
    if all([
        entity_name != 'release', not entity_id_value, not any([
            args.get('requester_id'),
            args.get('phone'),
            args.get('email')
        ])
    ]):
        raise ValueError(
            'One of the following is mandatory: requester_id, phone, email')


def get_files_to_attach(args: dict[str, Any], ) -> list[tuple]:
    """ Get array of files to attach in Freshservice.

    Args:
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        List[Tuple]: List of files.
    """
    return [get_file(file) for file in argToList(args.get('attachments'))]


def convert_response_properties(
    updated_response: list[dict] | dict[str, Any],
    predefined_values: dict[str, dict[str, int]],
) -> list[dict] | dict[str, Any]:
    """ Convert command properties from number to string for
        the XSOAR output.

    Args:
        updated_response (List[dict]): Freshservice response.
        predefined_values (Dict[str, Dict[str, int]]): Predefined values for Freshservice.

    Returns:
        List[dict]: Updated response.
    """
    if not updated_response:
        return updated_response

    if isinstance(updated_response, dict):
        updated_response = [updated_response]

    response_keys = updated_response[0].keys()

    for item in updated_response:
        for response_key in response_keys:
            if item.get(response_key) and response_key in predefined_values:
                property_values = reverse_dict(predefined_values[response_key])
                item[response_key] = property_values.get(item[response_key])

    return updated_response


def reverse_dict(dict_: dict[str, Any]) -> dict[str, Any]:
    """ Reverse dictionary.
    Args:
        dict_ (dict[str, Any]): Dictionary to reverse.
    Returns:
        dict[Any, str]: Reversed dictionary.
    """
    return {v: k for k, v in dict_.items()}


def get_args_by_command_name(args: dict[str, Any]) -> tuple:
    """ Return the default command args by the command name.

    Args:
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        Tuple: The arguments.
    """
    command_name = args['command_name'].split("-")
    command_operator = command_name[-1]
    entity_name = command_name[1]
    entity_id_key = f'{entity_name}_id'
    output_prefix = entity_name.capitalize()

    # checks if command entity consists of two words.
    if len(command_name) > MAX_DEFAULT_ARGS_COUNT and not {'task', 'conversation'}.intersection(command_name):
        entity_id_key = f'{entity_name}_{command_name[2]}_id'
        entity_name = f'{entity_name}_{command_name[2]}'
        output_prefix = f'{output_prefix}{command_name[2].capitalize()}'

    return args.get(
        entity_id_key), entity_name, output_prefix, command_operator


def get_default_seconds(time_in_seconds: int) -> int:
    """ Get the closest Freshservice predefined seconds to the specified seconds.

    Args:
        time_in_seconds (int): The specified seconds.

    Returns:
        int: The updated seconds.
    """
    return min([0, 900, 1800, 2700, 3600, 7200],
               key=lambda default_time: abs(default_time - time_in_seconds))


def get_file(file_id: str) -> tuple:
    """ Open file to send data to API.

    Args:
        file_id (str): The file ID.

    Returns:
        Dict[str, Any]: Dict with file data.
    """
    file_data = demisto.getFilePath(file_id)
    with open(file_data['path'], 'rb') as f:
        file = ('attachments[]', (file_data['name'], f.read(), 'image/png'))

    return file


def convert_command_properties(args: dict[str, Any],
                               ticket_type: str) -> TicketProperties:
    """ Convert command properties from string to number for
        the Freshservice request.

    Args:
        args (Dict[str, Any]): args (Dict[str, Any]): Command arguments from XSOAR.
        ticket_type (str): The ticket type.

    Returns:
        Tuple: The converted arguments.
    """
    ticket_property_keys = [
        'urgency',
        'status',
        'source',
        'priority',
        'impact',
        'risk',
        'change_type',
        'release_type',
    ]
    return TicketProperties(
        **{
            ticket_property_key: dict_safe_get(
                TICKET_PROPERTIES_BY_TYPE[ticket_type],
                [ticket_property_key,
                 args.get(ticket_property_key)])
            for ticket_property_key in ticket_property_keys
        })


def get_url_suffix(entity_id: int = None) -> str:
    """ Get the URL suffix.

    Args:
        entity_id (int, optional): The entity ID. Defaults to None.

    Returns:
        str: Updated URL suffix.
    """
    return f'/{entity_id}' if entity_id is not None else ''


def get_command_request(client: Client, command_entity: str) -> Callable:
    """ Get command request by entity name.

    Args:
        client (Client): Freshservice API client.
        command_entity (str): The command entity name.

    Returns:
        Callable: The request function.
    """

    entities_request_functions: dict[str, Callable] = {
        'vendor': client.freshservice_vendor_list,
        'department': client.freshservice_department_list,
        'asset': client.freshservice_asset_list,
        'agent': client.freshservice_agent_list,
        'agent_group': client.freshservice_agent_group_list,
        'software': client.freshservice_software_list,
        'role': client.freshservice_role_list,
        'requester': client.freshservice_requester_list,
        'requester_field': client.freshservice_requester_field_list,
        'purchase_order': client.freshservice_purchase_order_list,
        'ticket': client.freshservice_ticket_list,
        'problem': client.freshservice_problem_list,
        'change': client.freshservice_change_list,
        'release': client.freshservice_release_list,
        'ticket_create': client.freshservice_ticket_create,
        'problem_create': client.freshservice_problem_create,
        'change_create': client.freshservice_change_create,
        'release_create': client.freshservice_release_create,
        'ticket_update': client.freshservice_ticket_update,
        'problem_update': client.freshservice_problem_update,
        'change_update': client.freshservice_change_update,
        'release_update': client.freshservice_release_update,
        'ticket_delete': client.freshservice_ticket_delete,
        'problem_delete': client.freshservice_problem_delete,
        'change_delete': client.freshservice_change_delete,
        'release_delete': client.freshservice_release_delete,
        'ticket_task': client.freshservice_ticket_task_list,
        'problem_task': client.freshservice_problem_task_list,
        'change_task': client.freshservice_change_task_list,
        'release_task': client.freshservice_release_task_list,
        'ticket_task_create': client.freshservice_ticket_task_create,
        'problem_task_create': client.freshservice_problem_task_create,
        'change_task_create': client.freshservice_change_task_create,
        'release_task_create': client.freshservice_release_task_create,
        'ticket_task_update': client.freshservice_ticket_task_update,
        'problem_task_update': client.freshservice_problem_task_update,
        'change_task_update': client.freshservice_change_task_update,
        'release_task_update': client.freshservice_release_task_update,
        'ticket_task_delete': client.freshservice_ticket_task_delete,
        'problem_task_delete': client.freshservice_problem_task_delete,
        'change_task_delete': client.freshservice_change_task_delete,
        'release_task_delete': client.freshservice_release_task_delete,
    }
    return entities_request_functions[command_entity]


def get_command_list_args(args: dict[str, Any],
                          command_response_key: str,
                          command_arg_id: int = None) -> CommandArgs:
    """ Get command arguments according to the command mode: list or get.
        If command_arg_id is specified the command mode is get, otherwise is list.

    Args:
        args (Dict[str, Any]): Command arguments from XSOAR.
        command_arg_id (int, optional): Command argument ID. Defaults to None.

    Raises:
        ValueError: In case specified other arguments except command_arg_id.

    Returns:
        Tuple: The command argument according to the command mode.
    """

    if command_response_key == 'agent_group':
        command_response_key = 'group'
    elif command_response_key == 'software':
        command_response_key = 'application'

    page, page_size, pagination_message = pagination(args)

    # Check whether special arguments exist
    filter_name = args.get('filter_name')
    ticket_filter = args.get('filter')
    include = args.get('include')
    updated_since = args.get('updated_since')
    order_type = args.get('order_type')

    if not command_arg_id:
        # Check whether include, ticket_filter or updated_since exists,
        # if they do the other query arguments are irrelevant
        if any([updated_since, ticket_filter, include]):
            updated_since = updated_since and convert_date_time(updated_since)
            ticket_filter = 'new_and_my_open' if ticket_filter == 'open' else ticket_filter
            updated_query = None
        else:
            updated_query = filter_name or build_query(args,
                                                       command_response_key)

        command_response_key = f'{command_response_key}s'
    else:
        # The default arguments are limit & command_name.
        # This condition makes sure the user doesn't provide the
        # entity ID argument in addition to any filter arguments.
        if command_response_key not in [
            'task', 'conversation'
        ] and len(args.keys()) > MAX_DEFAULT_ARGS_COUNT:
            raise ValueError(
                'You can specify ID or any other filter arguments, not both')
        updated_query = None
        updated_since = None
        page = None
        page_size = None
        pagination_message = f'{command_response_key} ID - {command_arg_id}'

    return CommandArgs(page, page_size, pagination_message, updated_query,
                       updated_since, ticket_filter, include, order_type,
                       command_response_key)


def build_query(
    non_empty_args: dict[str, Any],
    entity_name: str,
) -> str:
    """ Create a query for Freshservice according their template.

    Args:
        args (Dict[str, Any]): Command arguments from XSOAR.

    Raises:
        ValueError: In case specified other arguments except query.

    Returns:
        str: The updated query.
    """
    updated_query = None

    for key, value in non_empty_args.items():
        if key == 'query':
            # check if args include only default arguments and query argument
            if len(non_empty_args.keys()) > 3:
                raise ValueError(
                    'You can specify query or any other filter arguments, not both'
                )

            updated_query = value

        # assign to updated_query only the filter arguments
        elif key not in [
            'command_name', 'limit', 'page', 'page_size', 'order_type'
        ]:
            if key in ['created_at', 'updated_at', 'due_by', 'fr_due_by']:
                value = convert_date_time(value)

            correct_value = int(value) if 'id' in key else f"'{value}'"

            # Convert str value to int in case it's a predefined values
            if entity_name in ['ticket', 'problem', 'change', 'release'] and \
                    (dict_key := TICKET_PROPERTIES_BY_TYPE[entity_name].get(key)):
                integer_value = dict_key.get(value)
                correct_value = integer_value if integer_value is not None else correct_value

            if updated_query:
                updated_query += f" AND {key}:{correct_value}"
            else:
                updated_query = f"{key}:{correct_value}"

    if updated_query:
        updated_query = f'"{updated_query}"'

    return updated_query


def convert_date_time(date_time: str) -> str | None:
    """ Convert str to datetime.

    Args:
        date_time (str): The datetime str.

    Returns:
        str: The updated datetime.
    """
    datetime_arg = arg_to_datetime(date_time)
    if isinstance(datetime_arg, datetime):
        updated_datetime_arg = datetime_arg.strftime(STRFTIME)
    else:
        updated_datetime_arg = date_time
        demisto.debug(f"{datetime_arg=} isn't of type datetime.")
    return updated_datetime_arg


def validate_pagination_arguments(
    page: int | None = None,
    page_size: int | None = None,
    limit: int | None = None,
):
    """ Validate pagination arguments according to their default.

    Args:
        page (int, optional): Page number of paginated results.
        page_size (int, optional): Number of items per page.
        limit (int, optional): The maximum number of records to retrieve.

    Raises:
        ValueError: Appropriate error message.
    """
    if page_size and (page_size < MIN_PAGE_SIZE or page_size > MAX_PAGE_SIZE):
        raise ValueError(
            f"page size argument must be greater than {MIN_PAGE_SIZE} and smaller than {MAX_PAGE_SIZE}."
        )
    if page is not None and page < MIN_PAGE_NUM:
        raise ValueError(
            f"page argument must be greater than {MIN_PAGE_NUM - 1}.")
    if limit is not None and limit <= MIN_LIMIT:
        raise ValueError(f"limit argument must be greater than {MIN_LIMIT}.")


def pagination(args: dict[str, Any]) -> tuple:
    """ Return the correct limit and offset for the API
        based on the user arguments page, page_size and limit.

    Args:
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        Tuple: new_limit, offset, pagination_message.
    """
    page = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size"))
    limit = arg_to_number(args.get("limit"))

    validate_pagination_arguments(page, page_size, limit)

    new_page = 1
    new_page_size = limit

    if page is not None and page_size:
        new_page_size = page_size
        new_page = page

    pagination_message = f"Showing page {new_page}. \n Current page size: {new_page_size}."

    return new_page, new_page_size, pagination_message


def date_to_epoch_for_fetch(date: datetime | None) -> int:
    """
    Converts datetime object to date in epoch timestamp (in seconds),
    for fetch command.

    Args:
        date (Optional[datetime]): The datetime to convert.

    Returns:
        int: date in epoch timestamp.
    """
    return date_to_timestamp(date) // 1000


def get_modified_remote_data(client: Client, args: dict[str, Any]) -> GetModifiedRemoteDataResponse:
    """
    Queries for incidents that were modified since the last update.

    Args:
        client: Freshservice API client.
        args (Dict[str, Any]): command arguments.

    Returns:
        GetModifiedRemoteDataResponse: modified tickets from Freshservice.
    """
    remote_args = GetModifiedRemoteDataArgs(args)
    last_update = remote_args.last_update

    modified_tickets = []
    for ticket_type in FETCH_TICKET_TYPE.values():
        request_args = {
            'updated_since': convert_date_time(last_update),
            'order_type': 'asc'
        }
        freshservice_request = get_command_request(client, ticket_type)
        response = freshservice_request(**request_args)
        modified_tickets_by_type = convert_response_properties(
            response[f'{ticket_type}s'],
            TICKET_PROPERTIES_BY_TYPE[ticket_type],
        )
        if not isinstance(modified_tickets_by_type, list):
            raise ValueError

        for ticket in modified_tickets_by_type:
            ticket_id = ticket["id"]
            ticket.update(
                {'id': f'{TICKET_ID_PREFIX[ticket_type]}: {ticket_id}'})
            modified_tickets.append(ticket_id)

    return GetModifiedRemoteDataResponse(modified_tickets)


def get_mapping_fields_command() -> GetMappingFieldsResponse:
    """
    Pulls the remote schema for the different incident types, and their associated incident fields, from the remote system.

    Returns:
    GetMappingFieldsResponse: Dictionary with keys as field names.
    """

    mapping_response = GetMappingFieldsResponse()
    for ticket_type, incident_type in TICKET_TYPE_TO_INCIDENT_TYPE.items():
        incident_type_scheme = SchemeTypeMapping(type_name=incident_type)
        outgoing_fields = MIRRORING_COMMON_FIELDS + TICKET_TYPE_TO_ADDITIONAL_MIRRORING_FIELDS[
            ticket_type]
        for field in outgoing_fields:
            incident_type_scheme.add_field(field)

        mapping_response.add_scheme_type(incident_type_scheme)

    return mapping_response


def update_remote_system(
    client: Client,
    args: dict[str, Any],
) -> str:
    """
    This command pushes local changes to the remote system.
    Args:
        client: XSOAR Client to use.
        args:
            args['data']: the data to send to the remote system.
            args['entries']: the entries to send to the remote system.
            args['incident_changed']: boolean telling us if the local incident indeed changed or not.
            args['remote_incident_id']: the remote incident id.
    Returns: The remote incident id - ticket_id
    """
    parsed_args = UpdateRemoteSystemArgs(args)

    incident_id = parsed_args.remote_incident_id
    ticket_type, ticket_id = get_ticket_type_by_alert_id(incident_id)

    demisto.debug(
        f"Got the following delta keys {str(list(parsed_args.delta.keys()))}"
        if parsed_args.delta else "There is no delta fields in Freshservice")

    try:
        demisto.debug(
            f"Sending incident with remote ID [{ticket_id} - {ticket_type}] to remote system\n"
        )

        if parsed_args.incident_changed:
            demisto.debug(f"Incident changed: {parsed_args.incident_changed}")

            update_args = parsed_args.delta

            demisto.debug(
                f"Sending incident with remote ID [{ticket_id} - {ticket_type}] to Freshservice\n"
            )
            updated_arguments = {}
            for key, value in update_args.items():
                if key in MIRRORING_COMMON_FIELDS + TICKET_TYPE_TO_ADDITIONAL_MIRRORING_FIELDS[ticket_type]:
                    update_value = dict_safe_get(TICKET_PROPERTIES_BY_TYPE,
                                                 [ticket_type, key, value],
                                                 value)
                    updated_arguments[key] = update_value

            updated_arguments.update({'ticket_id': ticket_id})

            demisto.debug(
                f"remote ID [{ticket_id} - {ticket_type}] to Freshservice. {updated_arguments=}|| {update_args=}"
            )
            freshservice_request = get_command_request(
                client, f'{ticket_type}_update')
            freshservice_request(**updated_arguments)

        demisto.info(f"remote data of {ticket_id}: {parsed_args.data}")
    except Exception as error:
        demisto.info(
            f"Error in Freshservice outgoing mirror for incident {ticket_id} - {ticket_type} \n"
            f"Error message: {error}")

    finally:
        return incident_id


def get_remote_data_command(client: Client, args: dict[str, Any], params: dict[str, Any]) -> GetRemoteDataResponse:
    """
    Gets new information about the incidents in the remote system
    and updates existing incidents in Cortex XSOAR.
    Args:
        client: Freshservice API client.
        params (dict): Integration parameters.
        args (Dict[str, Any]): command arguments.
    Returns:
        List[Dict[str, Any]]: first entry is the incident (which can be completely empty) and the new entries.
    """
    parsed_args = GetRemoteDataArgs(args)
    close_incident = params.get("close_incident")
    entries = []

    incident_id = parsed_args.remote_incident_id
    ticket_type, ticket_id = get_ticket_type_by_alert_id(incident_id)

    last_update = date_to_epoch_for_fetch(
        arg_to_datetime(parsed_args.last_update))

    freshservice_request = get_command_request(client, ticket_type)
    response = freshservice_request(**{f'{ticket_type}_id': ticket_id})
    response = convert_response_properties(
        response.get(ticket_type),
        TICKET_PROPERTIES_BY_TYPE[ticket_type],
    )
    mirrored_ticket = response[0] if isinstance(response, list) else response
    mirrored_ticket.update(
        {'id': f'{TICKET_ID_PREFIX[ticket_type]}: {mirrored_ticket["id"]}'})

    ticket_last_update = date_to_epoch_for_fetch(
        arg_to_datetime(mirrored_ticket.get('updated_at')))

    if last_update > ticket_last_update:
        mirrored_ticket = {}

    if mirrored_ticket.get("status") in ['Closed', 'closed', 'Completed'
                                         ] and close_incident:
        entries.append({
            "Type": EntryType.NOTE,
            "Contents": {
                "dbotIncidentClose": True,
                "closeReason": "Closed from Freshservice.",
            },
            "ContentsFormat": EntryFormat.JSON,
        })

    return GetRemoteDataResponse(mirrored_ticket, entries)


def convert_datetime_to_iso(created_at: str) -> datetime:
    """ Convert datetime to iso.

    Args:
        created_at (str): Created at argument.

    Returns:
        datetime: Updated argument.
    """
    alert_date = datetime.strptime(created_at, TIME_FORMAT)
    return FormatIso8601(alert_date) + 'Z'


def get_alert_properties(args: dict[str, Any]) -> tuple:
    """ Get alert properties.

    Args:
        args (Dict[str, Any]): XSOAR arguments.

    Returns:
        Tuple: Updated alert properties.
    """
    ticket_types = argToList(args.get('ticket_type'))
    if ticket_types == ['All']:
        ticket_types = FETCH_TICKET_TYPE.keys()

    ticket_prefix = 'ticket_'
    alert_properties = [(alert_property,
                         argToList(args.get(ticket_prefix + alert_property)))
                        for alert_property in
                        ['impact', 'status', 'risk', 'urgency', 'priority']]

    return ticket_types, alert_properties


def get_last_run(args: dict[str, Any], ticket_type: str) -> tuple:
    """ Get last run arguments.

    Args:
        args (Dict[str, Any]): XSOAR arguments.
        ticket_type (str): Ticket type.

    Returns:
        Tuple: Updated last run arguments.
    """
    last_run = demisto.getLastRun()
    demisto.debug(f'get_last_run {last_run=}')
    ticket_last_run = last_run.get(ticket_type)
    last_run_id = None

    if last_run and ticket_last_run:
        last_run_time = ticket_last_run.get('time')
        last_run_id = ticket_last_run.get('id')
    else:
        last_run_time = args.get('first_fetch', '3 Days')

    first_fetch = arg_to_datetime(arg=last_run_time,
                                  arg_name='First fetch time',
                                  required=True)

    first_fetch_timestamp = first_fetch and int(first_fetch.timestamp())

    assert isinstance(first_fetch_timestamp, int)

    # convert the last_run_time to Freshservice time format
    last_run_datetime = dateparser.parse(last_run_time)
    # use condition statement to avoid mypy error
    if last_run_datetime:
        last_run_datetime_str = last_run_datetime.strftime(TIME_FORMAT)
    else:
        last_run_datetime_str = ''
        demisto.debug(f"{last_run_datetime=} -> {last_run_datetime_str=}")
    last_run_datetime = dateparser.parse(last_run_datetime_str)

    return last_run_id, last_run_datetime, last_run_datetime_str


def get_ticket_type_by_alert_id(alert_id: str) -> tuple:
    """ Get ticket ID & type from the alert ID.

    Args:
        alert_id (str): Alert ID.

    Returns:
        Tuple: Ticket ID & type.
    """
    alert_data = alert_id.split(':')
    ticket_prefix_type = alert_data[0]
    ticket_type_by_prefix = reverse_dict(TICKET_ID_PREFIX)
    ticket_type = ticket_type_by_prefix[ticket_prefix_type]
    ticket_id = int(alert_data[1])
    return ticket_type, ticket_id


def fetch_relevant_tickets_by_ticket_type(
    client: Client,
    alert_list: list[dict],
    alert_properties: list[tuple],
    fetch_ticket_task: bool,
    ticket_type: str,
    last_run_id: str,
    last_run_datetime: datetime,
    max_fetch_per_ticket_type: int,
    mirror_direction: str | None,
) -> tuple:
    """ Fetch only relevant ticket by ticket defined properties.

    Args:
        client (Client): Freshservice client.
        alert_list (List[dict]): Ticket list from Freshservice.
        alert_properties (List[Tuple]): Alert defined properties.
        fetch_ticket_task (bool): Whether to fetch also ticket tasks.
        ticket_type (str): Ticket type.
        last_run_id (int): Last run ID.
        last_run_datetime (datetime): Last run datetime.
        max_fetch_per_ticket_type (int): Max fetch per ticket type.
        mirror_direction (str): The mirror direction.

    Returns:
        Tuple: Incidents for XSOAR and alert list.
    """
    alerts = []
    incidents = []

    for alert in alert_list:
        alert_time = dateparser.parse(alert['created_at'])
        alert_id = alert.get('id')

        # use condition statement to avoid mypy error for alert_time
        if alert_id != last_run_id and alert_time and last_run_datetime < alert_time:  # noqa: SIM102

            # check if alert properties is according to the defined properties.
            if all((alert_property := alert.get(key)) is None
                   or properties == ['All'] or alert_property in properties
                   for key, properties in alert_properties):
                # fetch task for each ticket if true
                if fetch_ticket_task:
                    freshservice_request = get_command_request(
                        client, f'{ticket_type}_task')
                    task_response = freshservice_request(alert_id)
                    alert |= task_response

                alert.update({'incident_id': alert_id})
                alert.update(
                    {'id': f'{TICKET_ID_PREFIX[ticket_type]}: {alert_id}'})

                alerts.append(alert)
                incidents.append(
                    parse_incident(alert, ticket_type, mirror_direction))
                # insert only limited number of tickets according max_fetch_per_ticket_type.
                if len(alerts) == max_fetch_per_ticket_type:
                    break
            else:
                demisto.debug(f'filtering out alert {alert_id} due to properties arent according to defined properties')
        else:
            demisto.debug(f'filtering out alert {alert_id} due to time')

    return alerts, incidents


def parse_incident(alert: dict, entity_name: str, mirror_direction: str | None) -> dict:
    """
    Parse alert to XSOAR Incident.

    Args:
        alert (dict): alert item.

    Returns:
        dict: XSOAR Incident.
    """

    alert_iso_time = convert_datetime_to_iso(alert['created_at'])

    alert['ticket_type'] = entity_name
    alert["mirror_direction"] = mirror_direction
    alert["mirror_instance"] = demisto.integrationInstance()

    return {
        'name': f"{entity_name} ID: {alert.get('id')}",
        'occurred': alert_iso_time,
        'rawJSON': json.dumps(alert)
    }


def get_next_link(response):
    link_header = response.headers.get("link", "") or response.headers.get("Link", "")
    demisto.debug(f"Link header: {link_header}")

    if not link_header:
        demisto.debug("No 'link' header found in response.")
        return ""

    match = re.search(r'<([^>]+)>;\s*rel="next"', link_header)
    if match:
        next_link = match.group(1)
        demisto.debug(f"Found next link: {next_link}")
        return next_link

    demisto.debug(f"No 'next' link found in the link header, link: {link_header=}")
    return ""


def fetch_incidents(client: Client, params: dict):
    """ This function retrieves new alerts from an API endpoint every interval (default is 1 minute).
        It is responsible for fetching incidents only once and ensuring that no incidents are missed.
        By default, this function is invoked by XSOAR every minute.
        It uses the last_run parameter to save the timestamp of the last alert it processed.
        If last_run is not provided, the function uses the integration parameter first_fetch
        to determine when to start fetching the first time.

    Args:
        client (Client): An API client object used to retrieve incidents.
        params (dict): Integration params.
        args (dict): A dictionary of parameters used to configure the function.
            The following keys are supported:
                - alert types (str): A comma-separated list of alert types to fetch.
                - alert severities (str): A comma-separated list of alert severities to fetch.
                - alert status (str): The status of alerts to fetch.
                - max fetch (int): The maximum number of incidents to fetch per ticket type.
                - first_fetch (str): The timestamp of the first alert to fetch.
                - mirror_direction (str):
                    The mirror direction to use when syncing incidents with another system.
                    Can be 'None' or one of the values defined in the MIRROR_DIRECTION_MAPPING dictionary.
                - fetch_ticket_task (str):
                    A boolean value indicating whether to fetch ticket tasks along with incidents.
    """
    # use condition statement to avoid mypy error
    mirror_direction = None if params["mirror_direction"] == 'None' else MIRROR_DIRECTION_MAPPING[params["mirror_direction"]]

    ticket_types, alert_properties = get_alert_properties(params)
    fetch_ticket_task = argToBoolean(params['fetch_ticket_task'])
    demisto.debug(f'Starting fetch_incidents {ticket_types=} {alert_properties=} {fetch_ticket_task=}')

    # use condition statement to avoid mypy error
    if (max_fetch := arg_to_number(params['max_fetch'])) is not None:
        max_fetch_per_ticket_type = max_fetch // len(ticket_types)
        demisto.debug(f'fetch-incidents {max_fetch_per_ticket_type=}')

    incidents = []
    last_run = {}

    for alert_type in ticket_types:
        demisto.debug(f'fetching {alert_type=}')
        ticket_type = FETCH_TICKET_TYPE[alert_type]

        last_run_id, last_run_datetime, last_run_datetime_str = get_last_run(
            params, ticket_type)
        demisto.debug(f'last run info {last_run_id=} {last_run_datetime_str=}')

        freshservice_request = get_command_request(client, ticket_type)
        request_args = {
            'updated_since': convert_datetime_to_iso(last_run_datetime_str),
            'order_type': 'asc',
            'page_size': 100
        }
        demisto.debug(f"Request arguments: {request_args}")
        tickets = []
        next_link = ''

        while True:
            response = freshservice_request(**request_args, full_url=next_link, resp_type='response')
            json_response = response.json()
            new_tickets = json_response.get(f'{ticket_type}s', [])
            tickets.extend(new_tickets)
            demisto.debug(f"Fetched additional: {len(new_tickets)}")

            if not (next_link := get_next_link(response)):
                break

        demisto.debug(f'Total fetched before filtering: {len(tickets)} for {ticket_type=}')
        alert_list = convert_response_properties(tickets, TICKET_PROPERTIES_BY_TYPE[ticket_type])
        if not isinstance(alert_list, list):
            alert_list = [alert_list]

        relevant_alerts, relevant_incidents = fetch_relevant_tickets_by_ticket_type(
            client=client,
            alert_list=alert_list,
            alert_properties=alert_properties,
            fetch_ticket_task=fetch_ticket_task,
            ticket_type=ticket_type,
            last_run_id=last_run_id,
            last_run_datetime=last_run_datetime,
            max_fetch_per_ticket_type=max_fetch_per_ticket_type,
            mirror_direction=mirror_direction,
        )

        demisto.debug(f'Total fetched after filtering: {len(relevant_incidents)} for {ticket_type=}')
        incidents += relevant_incidents

        if relevant_alerts:
            last_run_alert = max(relevant_alerts,
                                 key=lambda k: k["created_at"])

            last_run[ticket_type] = {
                'id': last_run_alert["id"],
                'time': last_run_alert["created_at"]
            }
        else:
            last_run[ticket_type] = {
                'id': last_run_id,
                'time': last_run_datetime_str
            }
    if incidents:
        demisto.debug(f'Added {len(incidents)=} new incidents.')
    else:
        demisto.debug('No new incidents fetched in this run.')
    demisto.debug(f'setting last run {last_run=}')
    demisto.setLastRun(last_run)
    demisto.debug(f'{len(incidents)=}')
    demisto.incidents(incidents)


def main():
    params: dict[str, Any] = demisto.params()
    args: dict[str, Any] = demisto.args()

    url = params['url']
    api_token = params.get('credentials', {}).get('password')

    verify_certificate: bool = not params.get('insecure', False)
    proxy: bool = params.get('proxy', False)

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    args['command_name'] = command

    try:
        client: Client = Client(url, api_token, verify_certificate, proxy)
        commands = {
            'freshservice-ticket-conversation-list':
                list_freshservice_ticket_conversation_command,
            'freshservice-ticket-conversation-reply-create':
                create_freshservice_ticket_conversation_reply_command,
            'freshservice-ticket-conversation-note-create':
                create_freshservice_ticket_conversation_note_command,
            'freshservice-ticket-conversation-update':
                update_freshservice_ticket_conversation_command,
            'freshservice-ticket-conversation-delete':
                delete_freshservice_ticket_conversation_command,
        }

        if command == 'test-module':
            return_results(test_module(client))
        elif command in [
            'freshservice-ticket-list',
            'freshservice-problem-list',
            'freshservice-change-list',
            'freshservice-release-list',
        ]:
            return_results(list_freshservice_ticket_command(client, args))
        elif command in [
            'freshservice-ticket-delete',
            'freshservice-problem-delete',
            'freshservice-change-delete',
            'freshservice-release-delete',
        ]:
            return_results(delete_freshservice_ticket_command(client, args))
        elif command in [
            'freshservice-ticket-update',
            'freshservice-problem-update',
            'freshservice-change-update',
            'freshservice-release-update',
            'freshservice-ticket-create',
            'freshservice-problem-create',
            'freshservice-change-create',
            'freshservice-release-create',
        ]:
            return_results(
                create_update_freshservice_ticket_command(client, args))
        elif command in [
            'freshservice-ticket-task-list',
            'freshservice-problem-task-list',
            'freshservice-change-task-list',
            'freshservice-release-task-list',
        ]:
            return_results(list_freshservice_ticket_task_command(client, args))
        elif command in [
            'freshservice-ticket-task-update',
            'freshservice-problem-task-update',
            'freshservice-change-task-update',
            'freshservice-release-task-update',
            'freshservice-ticket-task-create',
            'freshservice-problem-task-create',
            'freshservice-change-task-create',
            'freshservice-release-task-create',
        ]:
            return_results(
                create_update_freshservice_ticket_task_command(client, args))
        elif command in [
            'freshservice-ticket-task-delete',
            'freshservice-problem-task-delete',
            'freshservice-change-task-delete',
            'freshservice-release-task-delete',
        ]:
            return_results(
                delete_freshservice_ticket_task_command(client, args))
        elif command in [
            'freshservice-requester-list',
            'freshservice-requester-field-list',
            'freshservice-agent-list',
            'freshservice-role-list',
            'freshservice-vendor-list',
            'freshservice-software-list',
            'freshservice-asset-list',
            'freshservice-purchase-order-list',
            'freshservice-agent-group-list',
            'freshservice-department-list',
        ]:
            return_results(list_freshservice_entities_command(client, args))
        elif command == 'fetch-incidents':
            fetch_incidents(client, params)
        elif command == "get-remote-data":
            return_results(get_remote_data_command(client, args, params))
        elif command == "get-modified-remote-data":
            return_results(get_modified_remote_data(client, args))
        elif command == "update-remote-system":
            return_results(update_remote_system(client, args))
        elif command == "get-mapping-fields":
            return_results(get_mapping_fields_command())
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
