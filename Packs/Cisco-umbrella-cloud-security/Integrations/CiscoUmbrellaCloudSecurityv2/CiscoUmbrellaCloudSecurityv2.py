import enum
import http
from typing import Any, TypeVar
from collections.abc import Callable

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

BASE_URL = 'https://api.umbrella.com'

INTEGRATION_COMMAND_PREFIX = 'umbrella'
DESTINATION = 'destination'
DESTINATION_LIST = 'destination-list'
DOMAIN = 'domain'

INTEGRATION_OUTPUT_PREFIX = 'Umbrella'
DESTINATION_OUTPUT_PREFIX = 'Destinations'
DESTINATION_LIST_OUTPUT_PREFIX = 'DestinationLists'

ID_OUTPUTS_KEY_FIELD = 'id'

MAX_LIMIT = 100
DEFAULT_LIMIT = 50

DESTINATION_LIST_HEADERS = ['id', 'name', 'access', 'isGlobal', 'destinationCount']
DESTINATION_LIST_JSON_TRANSFORMER = JsonTransformer(keys=DESTINATION_LIST_HEADERS, is_nested=True)

OptionalDictOrList = TypeVar('OptionalDictOrList', None, dict[str, Any], list[dict[str, Any]])


class BundleType(int, enum.Enum):
    DNS = 1
    WEB = 2


class Access(str, enum.Enum):
    ALLOW = 'allow'
    BLOCK = 'block'


''' Client '''


class Client(BaseClient):
    """Client class to interact with the Umbrella API."""

    AUTH_SUFFIX = 'auth/v2/token'
    POLICIES_SUFFIX = 'policies/v2'

    DESTINATION_LIST_ENDPOINT = urljoin(POLICIES_SUFFIX, 'destinationlists')

    def __init__(
        self,
        base_url: str,
        api_key: str,
        api_secret: str,
        verify: bool = False,
        proxy: bool = False,
    ) -> None:
        """Initialize the Client class.

        Args:
            base_url (str): The base URL of the API.
            api_key (str): The API key to use.
            api_secret (str): The API secret to use.
            verify (bool, optional): Whether to verify the SSL certificate.
                Defaults to False.
            proxy (bool, optional): Whether to use a proxy.
                Defaults to False.
        """
        self.api_key = api_key
        self.api_secret = api_secret

        super().__init__(
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            headers={},
        )

    def login(self) -> None:
        """
        Log in to the API using the API key and API secret.
        The access token is stored in the headers of the request.
        """
        response = self._http_request(
            method='POST',
            url_suffix=Client.AUTH_SUFFIX,
            auth=(self.api_key, self.api_secret),
        )

        try:
            access_token = response['access_token']
            self._headers['Authorization'] = f'Bearer {access_token}'
        except Exception as e:
            raise DemistoException(f'Failed logging in: {response}') from e

    def _get_destination_payload(
        self,
        destinations: list[str] | None = None,
        destinations_comment: str | None = None,
    ) -> list[dict[str, Any]] | None:
        """Get the destination payload.

        Args:
            destinations (list[str] | None, optional): The list of destinations.
                Defaults to None.
            destinations_comment (str | None, optional): The comment of the destinations.
                Defaults to None.

        Returns:
            list[dict[str, Any]] | None: The destination payload or None incase destinations weren't given.
        """
        if not destinations:
            return None

        return [
            {
                'destination': destination,
                'comment': destinations_comment,
            }
            for destination in destinations
        ]

    def list_destinations(
        self,
        destination_list_id: str,
        page: int | None = None,
        limit: int = DEFAULT_LIMIT,
    ) -> dict[str, Any]:
        """Retrieve the list of destinations for a given destination list ID.

        Args:
            destination_list_id (str): The ID of the destination list.
            page (int, optional): The page number.
                Defaults to None.
            limit (int, optional): The number of items per page.
                Defaults to DEFAULT_LIMIT.

        Returns:
            dict[str, Any]: The list of destinations.
        """
        params = assign_params(
            page=page,
            limit=limit,
        )
        url_suffix = urljoin(Client.DESTINATION_LIST_ENDPOINT, f'{destination_list_id}/destinations')

        return self._http_request(
            method='GET',
            url_suffix=url_suffix,
            params=params,
        )

    def add_destination(
        self,
        destination_list_id: str,
        destinations: list[str],
        destinations_comment: str | None = None,
    ) -> dict[str, Any]:
        """Add a list of destinations to a given destination list ID.

        Args:
            destination_list_id (str): The ID of the destination list.
            destinations (list[str]): The list of destinations.
            destinations_comment (str, optional): The comment of the destination.
                Defaults to None.

        Returns:
            dict[str, Any]: The destination list that holds the added destinations.
        """
        payload = self._get_destination_payload(
            destinations=destinations,
            destinations_comment=destinations_comment,
        )
        url_suffix = urljoin(Client.DESTINATION_LIST_ENDPOINT, f'{destination_list_id}/destinations')

        return self._http_request(
            method='POST',
            url_suffix=url_suffix,
            json_data=payload,
        )

    def delete_destination(self, destination_list_id: str, destination_ids: list[int]) -> dict[str, Any]:
        """Delete a list of destinations from a given destination list ID.

        Args:
            destination_list_id (str): The ID of the destination list.
            destination_ids (list[int]): The list of destination IDs.

        Returns:
            dict[str, Any]: The destination list that holds the deleted destinations.
        """
        url_suffix = urljoin(Client.DESTINATION_LIST_ENDPOINT, f'{destination_list_id}/destinations/remove')
        return self._http_request(
            method='DELETE',
            url_suffix=url_suffix,
            json_data=destination_ids,
        )

    def list_destination_lists(
        self,
        page: int | None = None,
        limit: int = DEFAULT_LIMIT,
    ) -> dict[str, Any]:
        """Retrieve the list of destination lists.

        Args:
            destination_list_id (str): The ID of the destination list.

        Returns:
            dict[str, Any]: The destination list.
        """
        params = assign_params(
            page=page,
            limit=limit,
        )
        return self._http_request(
            method='GET',
            url_suffix=Client.DESTINATION_LIST_ENDPOINT,
            params=params,
        )

    def get_destination_list(self, destination_list_id: str) -> dict[str, Any]:
        """Retrieve a destination list.

        Args:
            destination_list_id (str): The ID of the destination list.

        Returns:
            dict[str, Any]: The destination list.
        """
        url_suffix = urljoin(Client.DESTINATION_LIST_ENDPOINT, destination_list_id)
        return self._http_request(method='GET', url_suffix=url_suffix)

    def create_destination_list(
        self,
        name: str,
        access: Access,
        is_global: bool,
        bundle_type: str | None = None,
        destinations: list[str] | None = None,
        destinations_comment: str | None = None,
    ) -> dict[str, Any]:
        """Create a destination list.

        Args:
            name (str): The name of the destination list.
            access (Access): The access of the destination list.
            is_global (bool): Whether the destination list is global.
            bundle_type (str | None, optional): The bundle type of the destination list.
                Defaults to None.
            destinations (list[str] | None, optional): The list of destinations.
                Defaults to None.
            destinations_comment (str | None, optional): The comment of the destinations.
                Defaults to None.

        Returns:
            dict[str, Any]: The destination list.
        """
        payload = remove_empty_elements(
            {
                'name': name,
                'access': access,
                'isGlobal': is_global,
                'bundleType': bundle_type and BundleType[bundle_type].value,
                'destinations': self._get_destination_payload(
                    destinations=destinations,
                    destinations_comment=destinations_comment,
                ),
            }
        )
        return self._http_request(
            method='POST',
            url_suffix=Client.DESTINATION_LIST_ENDPOINT,
            json_data=payload,
        )

    def update_destination_list(self, destination_list_id: str, name: str) -> dict[str, Any]:
        """Update a destination list.

        Args:
            destination_list_id (str): The ID of the destination list.
            name (str): The name of the destination list.

        Returns:
            dict[str, Any]: The destination list.
        """
        url_suffix = urljoin(Client.DESTINATION_LIST_ENDPOINT, destination_list_id)
        return self._http_request(
            method='PATCH',
            url_suffix=url_suffix,
            json_data={'name': name},
        )

    def delete_destination_list(self, destination_list_id: str) -> dict[str, Any]:
        """Delete a destination list.

        Args:
            destination_list_id (str): The ID of the destination list.

        Returns:
            dict[str, Any]: The destination list.
        """
        url_suffix = urljoin(Client.DESTINATION_LIST_ENDPOINT, destination_list_id)
        return self._http_request(
            method='DELETE',
            url_suffix=url_suffix,
        )


''' HELPER COMMANDS '''


@logger
def bridge_v1_to_v2(
    v2_command: Callable[[Client, dict[str, Any]], CommandResults],
    client: Client,
    args: dict[str, Any],
) -> CommandResults:
    """
    Bridge commands from the v1 pack (not API) to v2 commands.

    Args:
        v2_command (Callable[[Client, dict[str, Any]], CommandResults]): The v2 command.
        client (Client): Session to Cisco Umbrella to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.

    Returns:
        CommandResults: The result of v2 command.
    """
    args['destination_list_id'] = args.pop('destId', None)
    args['destinations'] = args.pop('domain', None) or args.pop('domains', None)
    args['destination_ids'] = args.pop('domainIds', None)
    args['limit'] = DEFAULT_LIMIT

    return v2_command(client, args)


@logger
def is_get_request_type(get_args: list, list_args: list) -> bool:
    """
    Determine whether the request arguments are for a GET or LIST request.

    Args:
        get_args (list): GET request arguments.
        list_args (list): LIST request arguments.

    Raises:
        ValueError: In case the user has entered both GET and LIST arguments, raise an error.

    Returns:
        bool: True if the arguments are for a GET request, False otherwise.
    """
    is_get_request = any(get_args)
    is_list_request = any(list_args)

    if is_get_request and is_list_request:
        raise ValueError('GET and LIST arguments can not be supported simultaneously.')

    return is_get_request


@logger
def get_json_table(obj: OptionalDictOrList, json_transformer: JsonTransformer) -> OptionalDictOrList:
    """Convert a dict or list to a table.

    Args:
        obj (OptionalDictOrList): The dict or list to convert.
        json_transformer (JsonTransformer): The json transformer to use.

    Returns:
        OptionalDictOrList: The converted dict or list, otherwise returns obj if nothing was inserted.
    """
    if not obj:
        return obj

    def transform_json_to_dict(data: dict[str, Any]) -> dict[str, Any]:
        """Use a JsonTransformer to extract the given keys from a dict and reconstruct it.

        Args:
            data (dict[str, Any]): The dict to transform.

        Returns:
            dict[str, Any]: The transformed dict.
        """
        return {
            transformed_data[1]: transformed_data[2]
            for transformed_data in json_transformer.json_to_path_generator(data)
        }

    if isinstance(obj, list):
        return [transform_json_to_dict(o) for o in obj]

    return transform_json_to_dict(obj)


def get_single_or_full_list(items: list) -> list | dict:
    """Get a single item or a full list of items.

    If the list contains only one item, return the item.
    If the list contains more than one item, return the full list.

    Args:
        items (list): The list of items.

    Returns:
        list | dict: The single item or the full list of items.
    """
    return items[0] if len(items) == 1 else items


@logger
def handle_pagination(
    list_command: Callable[..., dict[str, Any]],
    limit: int,
    *args,
    page_size: int | None = None,
    page: int | None = None,
    **kwargs,
) -> tuple[list[dict[str, Any]] | dict[str, Any], list[dict[str, Any]] | dict[str, Any]]:
    """Handles pagination for the given list_command.

    Args:
        list_command (Callable[..., dict[str, Any]]): Callable that returns data containing destinations.
        limit (int): The maximum number of items to return.
        page (int | None, optional): The page number to start from.
            Defaults to None.
        page_size (int | None, optional): The number of items to return per page.
            Defaults to None.
        *args: Arguments passed down by the CLI to configure the request.
        **kwargs: Keyword arguments passed down by the CLI to configure the request.

    Returns:
        tuple[list[dict[str, Any]] | dict[str, Any], list[dict[str, Any]] | dict[str, Any]]:
            A tuple containing the list of items and raw responses, or a single item and raw response if page is None.
    """
    if page:
        page_size = min(page_size or DEFAULT_LIMIT, MAX_LIMIT)
        demisto.debug(f'Calling list command with {args=}, {page=}, limit={page_size}')
        raw_response = list_command(*args, page=page, limit=page_size, **kwargs)
        return raw_response.get('data', []), raw_response

    page = 1

    outputs: list[dict[str, Any]] = []
    raw_responses: list[dict[str, Any]] = []

    # Keep calling the API until the required amount of items have been met.
    while limit > 0:
        demisto.debug(f'Calling list command with {args=}, {page=}, limit={MAX_LIMIT}')
        raw_response = list_command(*args, page=page, limit=MAX_LIMIT, **kwargs)

        # If the API returned no items, we're done.
        if not (output := raw_response.get('data')):
            demisto.debug(f'The API returned no items for {page=}, stopping')
            break

        received_items = len(output)

        # If the API returned more than the required amount of items, we need to trim the output.
        if limit < received_items:
            output = output[:limit]

        raw_responses.append(raw_response)
        outputs += output

        # If the API returned less than the required amount of items, we're done.
        if received_items < MAX_LIMIT:
            demisto.debug(f'These are the last items in the API {page=}, stopping')
            break

        limit -= received_items
        page += 1

    outputs_result = get_single_or_full_list(outputs)
    raw_response_result = get_single_or_full_list(raw_responses)

    return outputs_result, raw_response_result


@logger
def find_destinations(
    list_command: Callable[..., dict[str, Any]],
    destination_list_id: str,
    destinations: set[str] | None = None,
    destination_ids: set[str] | None = None,
) -> tuple[list[dict[str, Any]] | dict[str, Any], list[dict[str, Any]] | dict[str, Any]]:
    """Fetches and returns destinations and their associated data from a given list_command callable.

    Args:
        list_command (Callable[..., dict[str, Any]]): Callable that returns data containing destinations.
        destination_list_id (str): The destination list to search through.
        destinations (list[str] | None, optional): A set of destination names to look for.
            Defaults to None.
        destination_ids (list[str] | None, optional): A set of destination ids to look for.
            Defaults to None.

    Raises:
        ValueError: If both destinations and destination_ids weren't provided.

    Returns:
        tuple[list[dict[str, Any]] | dict[str, Any], list[dict[str, Any]] | dict[str, Any]]:
            A tuple containing two lists: one with the fetched data,
            and one with the raw responses from the list command.
    """
    if not any((destinations, destination_ids)):
        raise ValueError('At least one of the arguments "destinations" or "destination_ids" must be provided.')

    def filter_out_non_target_items(
        item: str,
        target_items: set[str] | None,
        other_item: str,
        other_target_items: set[str] | None,
    ) -> bool:
        """
        Checks if an item is in target_items.
        If so, removes the item and associated other_item from their respective sets.

        Args:
            item (str): Item to check for in target_items.
            target_items (set[str]): Set of items to search in.
            other_item (str): Associated item to remove from other_target_items if item is found in target_items.
            other_target_items (set[str]): Set of associated items.

        Returns:
            bool: True if the item was found and removed, False otherwise.
        """
        if not target_items:
            return False

        if item in (target_items or ()):
            target_items.discard(item)

            if other_target_items:
                other_target_items.discard(other_item)

            return True

        return False

    destinations = set(destinations) if destinations else None
    destination_ids = set(destination_ids) if destination_ids else None

    page = 1

    outputs: list[dict[str, Any]] = []
    raw_responses: list[dict[str, Any]] = []

    while destinations or destination_ids:
        demisto.debug(f'Calling list command with {destination_list_id=}, {page=}, limit={MAX_LIMIT}')
        raw_response = list_command(destination_list_id=destination_list_id, page=page, limit=MAX_LIMIT)
        items = raw_response.get('data', [])

        if not items:
            demisto.debug(f'The API returned no items for {page=}, stopping')
            break

        raw_responses.append(raw_response)

        for item in items:
            # Called twice to avoid duplicates if an item was given in ID and destination.
            if filter_out_non_target_items(
                item['id'],
                destination_ids,
                item['destination'],
                destinations,
            ) or filter_out_non_target_items(
                item['destination'],
                destinations,
                item['id'],
                destination_ids,
            ):
                outputs.append(item)

        if len(items) < MAX_LIMIT:
            demisto.debug(f'These are the last items in the API {page=}, stopping')
            break

    outputs_result = get_single_or_full_list(outputs)
    raw_response_result = get_single_or_full_list(raw_responses)

    return outputs_result, raw_response_result


@logger
def get_destination_list_command_results(raw_response: list | dict, outputs: list | dict) -> CommandResults:
    """Get the destination list command results.

    Args:
        raw_response (list | dict): The raw response from the API.
        outputs (list | dict): The destination list data.

    Returns:
        CommandResults: The destination list command results.
    """
    readable_output = tableToMarkdown(
        name='Destination List:',
        t=get_json_table(outputs, DESTINATION_LIST_JSON_TRANSFORMER),
        headers=DESTINATION_LIST_HEADERS,
        headerTransform=pascalToSpace,
    )
    return CommandResults(
        outputs_prefix='.'.join([INTEGRATION_OUTPUT_PREFIX, DESTINATION_LIST_OUTPUT_PREFIX]),
        outputs_key_field=ID_OUTPUTS_KEY_FIELD,
        outputs=outputs,
        readable_output=readable_output,
        raw_response=raw_response,
    )


''' COMMANDS '''


@logger
def list_destinations_command(client: Client, args: dict[str, Any]) -> CommandResults:
    destination_list_id = args['destination_list_id']
    # GET arguments
    destinations = argToList(args.get('destinations'))
    destination_ids = argToList(args.get('destination_ids'))
    # LIST arguments
    limit = arg_to_number(args.get('limit')) or DEFAULT_LIMIT
    page = arg_to_number(args.get('page'))
    page_size = arg_to_number(args.get('page_size'))

    if is_get_request_type(
        get_args=[destinations, destination_ids],
        list_args=[page, page_size],
    ):
        outputs, raw_response = find_destinations(
            list_command=client.list_destinations,
            destination_list_id=destination_list_id,
            destinations=destinations,
            destination_ids=destination_ids,
        )
    else:  # is_list_request
        outputs, raw_response = handle_pagination(
            list_command=client.list_destinations,
            limit=limit,
            page=page,
            page_size=page_size,
            destination_list_id=destination_list_id,
        )

    readable_output = tableToMarkdown(
        name='Destination(s):',
        t=outputs,
        headers=['id', 'destination', 'type', 'comment', 'createdAt'],
        headerTransform=pascalToSpace,
    )

    return CommandResults(
        outputs_prefix='.'.join([INTEGRATION_OUTPUT_PREFIX, DESTINATION_OUTPUT_PREFIX]),
        outputs_key_field=ID_OUTPUTS_KEY_FIELD,
        outputs=outputs,
        readable_output=readable_output,
        raw_response=raw_response,
    )


@logger
def add_destination_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Add destinations to a destination list.

    Args:
        client (Client): Session to Cisco Umbrella to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.
            destination_list_id (str): The ID of the destination list.
            destinations (list[str]): The list of destinations to add.
            comment (str, optional): The comment for the destinations.

    Returns:
        CommandResults: The result of the destination addition.
    """
    destination_list_id = args['destination_list_id']
    destinations = argToList(args['destinations'])
    destinations_comment = args.get('comment')

    raw_response = client.add_destination(
        destination_list_id=destination_list_id,
        destinations=destinations,
        destinations_comment=destinations_comment,
    )

    return CommandResults(
        readable_output=(
            f'The destination(s) "{destinations}" '
            f'were successfully added to the destination list "{destination_list_id}"'
        ),
        raw_response=raw_response,
    )


@logger
def delete_destination_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Delete destinations from a destination list.

    Args:
        client (Client): Session to Cisco Umbrella to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.
            destination_list_id (str): The ID of the destination list.
            destination_ids (list[int]): The IDs of the destinations to delete.

    Returns:
        CommandResults: The result of the destination deletion.
    """
    destination_list_id = args['destination_list_id']
    destination_ids = [
        number for arg in argToList(args['destination_ids']) if (number := arg_to_number(arg)) is not None
    ]

    raw_response = client.delete_destination(
        destination_list_id=destination_list_id,
        destination_ids=destination_ids,
    )

    return CommandResults(
        readable_output=(
            f'The destination(s) "{destination_ids}" '
            f'were successfully removed from the destination list "{destination_list_id}"'
        ),
        raw_response=raw_response,
    )


@logger
def list_destination_lists_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """List destination lists.

    Args:
        client (Client): Session to Cisco Umbrella to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.
            destination_list_id (str, optional): The ID of a specific destination list.
            limit (int, optional): The maximum number of records to retrieve.
            page (int, optional): Page number of paginated results.
            page_size (int, optional): The number of items per page.

    Returns:
        CommandResults: The requested destination lists.
    """
    # GET arguments
    destination_list_id = args.get('destination_list_id', '')
    # LIST arguments
    limit = arg_to_number(args.get('limit')) or DEFAULT_LIMIT
    page = arg_to_number(args.get('page'))
    page_size = arg_to_number(args.get('page_size'))

    if is_get_request_type(
        get_args=[destination_list_id],
        list_args=[page, page_size],
    ):
        outputs, raw_response = None, client.get_destination_list(destination_list_id)
    else:  # is_list_request
        outputs, raw_response = handle_pagination(
            list_command=client.list_destination_lists,
            limit=limit,
            page=page,
            page_size=page_size,
        )

    return get_destination_list_command_results(
        outputs=outputs or raw_response.get('data'),
        raw_response=raw_response,
    )


@logger
def create_destination_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Create a destination list.

    Args:
        client (Client): Session to Cisco Umbrella to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.
            name (str): The name of the destination list.
            access (str): The access level of the destination list.
            is_global (bool): Whether the destination list is global.
            bundle_type (str, optional): The type of bundle.
            destinations (list[str], optional): The list of destinations.
            destinations_comment (str, optional): The comment for the destinations.

    Returns:
        CommandResults: The created destination list.
    """
    raw_response = client.create_destination_list(
        name=args['name'],
        access=args['access'],
        is_global=argToBoolean(args['is_global']),
        bundle_type=args.get('bundle_type'),
        destinations=argToList(args.get('destinations')),
        destinations_comment=args.get('destinations_comment'),
    )
    return get_destination_list_command_results(
        outputs=raw_response,
        raw_response=raw_response,
    )


@logger
def update_destination_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Update a destination list.

    Args:
        client (Client): Session to Cisco Umbrella to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.
            destination_list_id (str): The ID of the destination list.
            name (str): The name of the destination list.

    Returns:
        CommandResults: The updated destination list.
    """
    raw_response = client.update_destination_list(
        destination_list_id=args['destination_list_id'],
        name=args['name'],
    )
    return get_destination_list_command_results(
        outputs=raw_response['data'],
        raw_response=raw_response,
    )


@logger
def delete_destination_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Delete a destination list.

    Args:
        client (Client): Session to Cisco Umbrella to run API requests.
        args (dict[str, Any]): Arguments passed down by the CLI to configure the request.
            destination_list_id (str): The ID of the destination list.

    Returns:
        CommandResults: The result of the destination list deletion.
    """
    destination_list_id = args['destination_list_id']
    raw_response = client.delete_destination_list(destination_list_id)

    return CommandResults(
        readable_output=f'The destination list "{destination_list_id}" was successfully deleted',
        raw_response=raw_response,
    )


@logger
def test_module(client: Client) -> str:
    """Tests API connectivity and authentication.

    Returning 'ok' indicates that the integration works like it is supposed to.
    Raises exceptions if something goes wrong.

    Args:
        client (Client): Session to Cisco Umbrella to run API requests.

    Raises:
        DemistoException: Incase there is an unknown error.

    Returns:
        str: : 'ok' if test passed, or an error message if the credentials are incorrect.
    """
    try:
        client.login()

    except DemistoException as exc:
        if exc.res is not None and exc.res.status_code == http.HTTPStatus.UNAUTHORIZED:
            return 'Authorization Error: invalid API key or secret'

        raise exc

    return 'ok'


def main() -> None:
    params: dict[str, Any] = demisto.params()
    args: dict[str, Any] = demisto.args()
    command: str = demisto.command()

    api_key: str = params['credentials']['identifier']
    api_secret: str = params['credentials']['password']
    verify_certificate: bool = not params.get('insecure', False)
    proxy: bool = params.get('proxy', False)

    demisto.debug(f'Command being called is {command}')

    commands_v2 = {
        f'{INTEGRATION_COMMAND_PREFIX}-{DESTINATION}s-list': list_destinations_command,
        f'{INTEGRATION_COMMAND_PREFIX}-{DESTINATION}-add': add_destination_command,
        f'{INTEGRATION_COMMAND_PREFIX}-{DESTINATION}-delete': delete_destination_command,
        f'{INTEGRATION_COMMAND_PREFIX}-{DESTINATION_LIST}s-list': list_destination_lists_command,
        f'{INTEGRATION_COMMAND_PREFIX}-{DESTINATION_LIST}-create': create_destination_list_command,
        f'{INTEGRATION_COMMAND_PREFIX}-{DESTINATION_LIST}-update': update_destination_list_command,
        f'{INTEGRATION_COMMAND_PREFIX}-{DESTINATION_LIST}-delete': delete_destination_list_command,
    }

    commands_v1 = {
        f'{INTEGRATION_COMMAND_PREFIX}-get-{DESTINATION}-{DOMAIN}': list_destinations_command,
        f'{INTEGRATION_COMMAND_PREFIX}-get-{DESTINATION}-{DOMAIN}s': list_destinations_command,
        f'{INTEGRATION_COMMAND_PREFIX}-search-{DESTINATION}-{DOMAIN}s': list_destinations_command,
        f'{INTEGRATION_COMMAND_PREFIX}-add-{DOMAIN}': add_destination_command,
        f'{INTEGRATION_COMMAND_PREFIX}-remove-{DOMAIN}': delete_destination_command,
        f'{INTEGRATION_COMMAND_PREFIX}-get-{DESTINATION}-lists': list_destination_lists_command,
    }

    try:
        client = Client(
            base_url=BASE_URL,
            api_key=api_key,
            api_secret=api_secret,
            verify=verify_certificate,
            proxy=proxy,
        )

        if command == 'test-module':
            results = test_module(client)
        elif command in commands_v2:
            client.login()
            results = commands_v2[command](client, args)
        elif command in commands_v1:
            client.login()
            results = bridge_v1_to_v2(v2_command=commands_v1[command], client=client, args=args)
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

        return_results(results)

    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
