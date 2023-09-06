import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import copy
from CommonServerUserPython import *
from typing import Any, Dict, Callable, Tuple

MIN_PAGE_SIZE = 5
MAX_PAGE_SIZE = 100


class Client(BaseClient):
    """Client class to interact with CloudFlare WAF API."""

    def __init__(self, credentials: str, account_id: str, proxy: bool, insecure: bool, base_url: str, zone_id: str = None):
        self.account_id = account_id
        self.zone_id = zone_id
        headers = {'Authorization': f'Bearer {credentials}', 'Content-Type': 'application/json'}
        super().__init__(base_url=base_url, headers=headers, proxy=proxy, verify=insecure)

    def cloudflare_waf_firewall_rule_create_request(self, action: str, zone_id: str, description: str = None,
                                                    products: List[str] = None, paused: bool = None, priority: int = None,
                                                    ref: str = None, filter_id: int = None,
                                                    filter_expression: str = None) -> Dict[str, Any]:
        """ Create a new Firewall rule in Cloudflare.

        Args:
            description (str, optional): A description of the rule to help identify it. Defaults to None.
            products (list, optional): List of products to bypass for a request when the bypass action is used.
                Defaults to None.
            action (str, optional): The rule action. Defaults to None.
            paused (bool, optional): Whether this firewall rule is currently paused. Defaults to None.
            priority (int, optional): The priority of the rule to allow control of processing order. A lower number indicates
                high priority. If not provided, any rules with a priority will be sequenced before those without.
                Defaults to None.
            ref (str, optional): Short reference tag to quickly select related rules. Defaults to None.
            filter_id (int, optional): Filter ID (if using existing filter). Required if filter_expression is unspecified.
                Defaults to None.
            filter_expression (str, optional): Filter expression (if creating new filter for the created rule).
                Required if filter_id is unspecified. Defaults to None.

        Returns:
            dict: API response from Cloudflare.
        """
        params = remove_empty_elements({
            'description': description,
            'products': products,
            'action': action,
            'paused': paused,
            'priority': priority,
            'ref': ref,
            'filter': {'id': filter_id, 'expression': filter_expression}
        })
        return self._http_request(
            method='POST',
            url_suffix=f'zones/{zone_id}/firewall/rules',
            json_data=[params])

    def cloudflare_waf_firewall_rule_update_request(self, rule_id: str, filter_id: str, zone_id: str, action: str,
                                                    description: str = None, products: List[str] = None, paused: bool = None,
                                                    priority: int = None, ref: str = None) -> Dict[str, Any]:
        """ Sets the Firewall rule for the specified rule id. Can update rule action, paused, description,
            priority, products and ref. Can not update or delete rule filter, ONLY add a new filter.

        Args:
            id(str): Firewall Rule identifier. Defaults to None.
            description(str, optional): A description of the rule to help identify it. Defaults to None.
            products(list, optional): List of products to bypass for a request when the bypass action is used. Defaults to None.
            action(str, optional): The rule action. Defaults to None.
            paused(bool, optional): Whether this firewall rule is currently paused. Defaults to None.
            priority(int, optional): The priority of the rule to allow control of processing order. A lower number indicates
                high priority. If not provided, any rules with a priority will be sequenced before those without.
                Defaults to None.
            ref(str, optional): Short reference tag to quickly select related rules. Defaults to None.
            filter_id(int, optional): Filter ID(for adding an existing filter). Defaults to None.

        Returns:
            dict: API response from Cloudflare.
        """
        params = remove_empty_elements({
            'id': rule_id,
            'description': description,
            'products': products,
            'action': action,
            'paused': paused,
            'priority': priority,
            'ref': ref,
            'filter': {'id': filter_id}
        })

        return self._http_request(
            method='PUT',
            url_suffix=f'zones/{zone_id}/firewall/rules',
            json_data=[params])

    def cloudflare_waf_firewall_rule_delete_request(self, rule_id: str, zone_id: str) -> Dict[str, Any]:
        """ Delete Firewall rule for the specified rule id.
        Args:
            id(str, optional): Firewall Rule identifier.

        Returns:
            dict: API response from Cloudflare.
        """
        return self._http_request(
            method='DELETE',
            url_suffix=f'zones/{zone_id}/firewall/rules',
            params={'id': rule_id})

    def cloudflare_waf_firewall_rule_list_request(self, args: dict, page: int = None, page_size: int = None) -> Dict[str, Any]:
        """ List of firewall rules or details of individual rule by ID.

        Args:
            id(str, optional): Firewall Rule identifier. Defaults to None.
            description(str, optional): A description of the rule to help identify it. Defaults to None.
            action(str, optional): The rule action. Defaults to None.
            paused(bool, optional): Whether this firewall rule is currently paused. Defaults to None.
            page(int, optional): Page number of paginated results. min value: 1.
            page_size(int, optional): Number of firewall rules per page. min value: 5, max value: 100.

        Returns:
            dict: API response from Cloudflare.
        """

        params = remove_empty_elements({
            'id': args.get('rule_id'),
            'description': args.get('description'),
            'action': args.get('action'),
            'paused': args.get('paused'),
            'page': page,
            'per_page': page_size
        })
        zone_id = args.get('zone_id')
        return self._http_request(
            method='GET',
            url_suffix=f'zones/{zone_id}/firewall/rules',
            params=params)

    def cloudflare_waf_zone_list_request(self, args: dict = None, page: int = None, page_size: int = None) -> Dict[str, Any]:
        """ List account's zones or details of individual zone by ID.

        Args:
            match(str, optional): Whether to match all search requirements or at least one(any). Defaults to None.
            name(str, optional): A domain name. Defaults to None.
            account_name(str, optional): Account name. Defaults to None.
            order(str, optional): Field to order zones by. Defaults to None.
            status(str, optional): Status of the zone. Defaults to None.
            account_id(str, optional): Account identifier tag. Defaults to None.
            direction(str, optional): Direction to order zones. Defaults to None.
            page(int, optional): Page number of paginated results. Defaults to 1.
            page_size(int, optional): Number of zones per page. Defaults to 50.

        Returns:
            dict: API response from Cloudflare.
        """
        if args is None:
            args = {}

        params = remove_empty_elements({
            'match': args.get('match'),
            'name': args.get('name'),
            'account_name': args.get('account_name'),
            'order': args.get('order'),
            'status': args.get('status'),
            'account_id': args.get('account_id'),
            'direction': args.get('direction'),
            'page': page,
            'per_page': page_size
        })
        return self._http_request(
            method='GET',
            url_suffix='zones',
            params=params)

    def cloudflare_waf_filter_create_request(self, expression: str, zone_id: str, ref: str = None, paused: bool = None,
                                             description: str = None) -> Dict[str, Any]:
        """ Create a new Filter in Cloudflare.
        Args:
            expression(str): The filter expression to be used. Defaults to None.
            ref(str, optional): Short reference tag to quickly select related rules. Defaults to None.
            paused(str, optional): Whether this filter is currently paused. Defaults to None.
            description(str, optional): A note that you can use to describe the purpose of the filter. Defaults to None.
            zone_id(str, optional): Zone identifier. Defaults to None.

        Returns:
            dict: API response from Cloudflare.
        """
        params = remove_empty_elements({
            'expression': expression,
            'ref': ref,
            'paused': paused,
            'description': description,
            'zone_id': zone_id
        })
        return self._http_request(
            method='POST',
            url_suffix=f'zones/{zone_id}/filters',
            json_data=[params])

    def cloudflare_waf_filter_update_request(self, filter_id: str, expression: str, zone_id: str, ref: str = None,
                                             paused: bool = None, description: str = None) -> Dict[str, Any]:
        """ Sets the Filter for the specified id.

        Args:
            id (str, optional): Filter identifier. Defaults to None.
            expression (str, optional): The filter expression to be used. Defaults to None.
            ref (str, optional): Short reference tag to quickly select related rules. Defaults to None.
            paused (str, optional): Whether this filter is currently paused. Defaults to None.
            description (str, optional): A note that you can use to describe the purpose of the filter. Defaults to None.
            zone_id (str, optional): Zone identifier. Defaults to None.

        Returns:
            dict: API response from Cloudflare.
        """
        params = remove_empty_elements({
            'id': filter_id,
            'expression': expression,
            'ref': ref,
            'paused': paused,
            'description': description,
            'zone_id': zone_id
        })
        return self._http_request(
            method='PUT',
            url_suffix=f'zones/{zone_id}/filters',
            json_data=[params])

    def cloudflare_waf_filter_delete_request(self, filter_id: str, zone_id: str) -> Dict[str, Any]:
        """ Delete filter by the specified id.

        Args:
            filter_id (str): Filter ID.
            zone_id (str): Zone ID.

        Returns:
            dict: API response from Cloudflare.

        """
        return self._http_request(
            method='DELETE',
            url_suffix=f'zones/{zone_id}/filters',
            params={'id': filter_id})

    def cloudflare_waf_filter_list_request(self, args: dict, page: int = None, page_size: int = None) -> Dict[str, Any]:
        """ List filters or details of individual filter by ID.

        Args:
            id (str, optional): Filter identifier. Defaults to None.
            expression (str, optional): Case-insensitive string to find in expression. Defaults to None.
            ref (str, optional): Exact match search on a ref. Defaults to None.
            paused (str, optional): Whether this filter is currently paused. Defaults to None.
            description (str, optional): Case-insensitive string to find in description. Defaults to None.
            zone_id (str, optional): ip-list identifier. Defaults to None.
            page (int, optional): Page number of paginated results. Defaults to 1.
            page_size (int, optional): Number of filter per page. Defaults to 50.

        Returns:
            dict: API response from Cloudflare.
        """
        params = remove_empty_elements({
            'id': args.get('filter_id'),
            'expression': args.get('expression'),
            'ref': args.get('ref'),
            'paused': args.get('paused'),
            'description': args.get('description'),
            'page': page,
            'per_page': page_size
        })
        zone_id = args.get('zone_id')
        return self._http_request(
            method='GET',
            url_suffix=f'zones/{zone_id}/filters',
            params=params)

    def cloudflare_waf_ip_lists_list_request(self, list_id: str = None, page: int = None,
                                             page_size: int = None) -> Dict[str, Any]:
        """ List ip-lists or details of individual list by ID.

        Args:
            id (str, optional): List-ip identifier. Defaults to None.
            page (int, optional): Page number of paginated results. Defaults to 1.
            page_size (int, optional): Number of ip-list per page. Defaults to 50.

        Returns:
            dict: API response from Cloudflare.
        """
        params = remove_empty_elements({
            'page': page,
            'per_page': page_size
        })

        ip_list = f'/{list_id}' if list_id else ''

        return self._http_request(
            method='GET',
            url_suffix=f'accounts/{self.account_id}/rules/lists{ip_list}',
            params=params)

    def cloudflare_waf_ip_list_create_request(self, name: str, description: str = None) -> Dict[str, Any]:
        """  Create a new ip-list.

        Args:
            name (str, optional): The name of the list (used in filter expressions). Defaults to None.
            kind (int, optional): The kind of values in the List. Defaults to 1.
            description (int, optional): A note that can be used to annotate the List. Defaults to 50.

        Returns:
            dict: API response from Cloudflare.
        """
        params = remove_empty_elements({
            'name': name,
            'kind': 'ip',
            'description': description
        })

        return self._http_request(
            method='POST',
            url_suffix=f'accounts/{self.account_id}/rules/lists',
            json_data=params)

    def cloudflare_waf_ip_list_delete_request(self, list_id: str) -> Dict[str, Any]:
        """ Delete ip-list for the specified list id.
        Args:
            id (str, optional): IP-list identifier.

        Returns:
            dict: API response from Cloudflare.
        """
        return self._http_request(
            method='DELETE',
            url_suffix=f'accounts/{self.account_id}/rules/lists/{list_id}')

    def cloudflare_waf_ip_list_item_create_request(self, list_id: str, items: list) -> Dict[str, Any]:
        """  Create a new ip-list items.

        Args:
            list_id (str, optional): The list ID.
            items (int, optional): The items to add to the list.

        Returns:
            dict: API response from Cloudflare.
        """
        return self._http_request(
            method='POST',
            url_suffix=f'accounts/{self.account_id}/rules/lists/{list_id}/items',
            json_data=items)

    def cloudflare_waf_ip_list_item_update_request(self, list_id: str, items: list) -> Dict[str, Any]:
        """  Replace ip-list items with a new items. Remove all current list items and append the given items to the List.

        Args:
            list_id (str, optional): The list ID.
            items (int, optional): The item to update.

        Returns:
            dict: API response from Cloudflare.
        """
        return self._http_request(
            method='PUT',
            url_suffix=f'accounts/{self.account_id}/rules/lists/{list_id}/items',
            json_data=items)

    def cloudflare_waf_ip_list_item_delete_request(self, list_id: str, items: list) -> Dict[str, Any]:
        """  Delete ip-list items.

        Args:
            list_id (str, optional): The list ID.
            items (int, optional): The item to delete.

        Returns:
            dict: API response from Cloudflare.
        """
        return self._http_request(
            method='DELETE',
            url_suffix=f'accounts/{self.account_id}/rules/lists/{list_id}/items',
            json_data={'items': items})

    def cloudflare_waf_ip_list_item_list_request(self, list_id: str, item: list = None, cursors: str = None) -> Dict[str, Any]:
        """  List ip-list items.

        Args:
            list_id (str, optional): The list ID.
            item (list, optional): The item ID to fetch.
            cursors (str, optional): The key to fetch the rest of the list.

        Returns:
            dict: API response from Cloudflare.
        """
        item_suffix = f'/{item}' if item else ''
        params = {'cursor': cursors} if cursors else {}

        return self._http_request(
            method='GET',
            params=params,
            url_suffix=f'accounts/{self.account_id}/rules/lists/{list_id}/items{item_suffix}')

    def cloudflare_waf_get_operation_request(self, operation_id: str) -> Dict[str, Any]:
        """ Get the current status of a Lists asynchronous operation.

        Args:
            operation_id (str): The obtained operation id.

        Returns:
            dict: API response from Cloudflare.
        """
        return self._http_request(
            method='GET',
            url_suffix=f'accounts/{self.account_id}/rules/lists/bulk_operations/{operation_id}')


def validate_pagination_arguments(page: int = None, page_size: int = None, limit: int = None):
    """ Validate pagination arguments according to their default.

    Args:
        page (int, optional): Page number of paginated results.
        page_size (int, optional): Number of ip-list per page.
        limit (int, optional): The maximum number of records to retrieve.

    Raises:
        ValueError: Appropriate error message.
    """
    if page_size and not MIN_PAGE_SIZE <= page_size <= MAX_PAGE_SIZE:
        raise ValueError(f'page size argument must be greater than {MIN_PAGE_SIZE} and smaller than {MAX_PAGE_SIZE}.')

    if page:
        if page < 1:
            raise ValueError('page argument must be greater than 0.')

    if limit:
        if limit < 5 or limit > 100:
            raise ValueError('limit argument must be greater than 5.')


def pagination(request_command: Callable, args: Dict[str, Any], pagination_args: Dict[str, Any]) -> Tuple:
    """ Executing Manual Pagination (using the page and page size arguments)
        or Automatic Pagination (display a number of total results).
    Args:
        request_command (Callable): The command to execute.
        args (Dict[str, Any]): The command arguments.
        pagination_args (dict): page, page_size and limit arguments.

    Returns:
        dict: response, output, pagination message for Command Results.
    """

    page = pagination_args.get('page')
    page_size = pagination_args.get('page_size')
    limit = pagination_args.get('limit', 50)
    output = []
    response = []

    if page and page_size:
        response = request_command(
            args, page=page, page_size=page_size)

        output = response['result']  # type: ignore
        total_num_item = dict_safe_get(response, ['result_info', 'count'])
        page_num = dict_safe_get(response, ['result_info', 'page'])
        total_pages = dict_safe_get(response, ['result_info', 'total_pages'])
        # type: ignore
        pagination_message = f'Showing page {page_num} out of {total_pages}. \n Current page size: {total_num_item}'
    else:
        while limit > 0:
            page_size = 100 if limit > 100 else limit
            response = request_command(args, page_size=page_size)
            total_count = dict_safe_get(response, ['result_info', 'total_count'])
            output.extend(response['result'])  # type: ignore
            limit -= 100

        pagination_message = f'Showing {len(output)} rows out of {total_count}.'

    return response, output, pagination_message


def ip_list_pagination(response: Union[list, dict], page: int = None, page_size: int = None, limit: int = None) -> Tuple:
    """ Executing Manual Pagination (using the page and page size arguments)
        or Automatic Pagination (display a number of total results) for the ip-list commands.

    Args:
        response (dict): API response.
        page (int, optional): Page number of paginated results.
        page_size (int, optional): Number of ip-list per page.
        limit (int, optional): The maximum number of records to retrieve.

    Returns:
        dict: output and pagination message for Command Results.
    """
    if isinstance(response, dict):
        response = [response]  # type: ignore

    output = response
    if page and page_size:
        if page_size < len(response):
            first_item = page_size * (page - 1)
            output = response[first_item:first_item + page_size]
        else:
            output = response[:page_size]
        pagination_message = f'Showing page {page} out of others that may exist. \n Current page size: {page_size}'
    else:
        output = response[:limit]
        pagination_message = f'Showing {len(output)} rows out of {len(response)}.'

    return output, pagination_message


def arg_to_boolean(arg: str) -> Optional[bool]:
    """ Retrieve arg boolean value if it's not none.

    Args:
        arg (str): Boolean argument.

    Returns:
        Optional[bool]: The argument boolean value.
    """
    return argToBoolean(arg) if arg else None


def cloudflare_waf_firewall_rule_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """ Create a new firewall rule by a new filter (if filter_expression is specified)
        or an already exist filter (if filter_id is specified).

    Args:
        client (Client): Cloudflare API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: readable outputs for XSOAR.
    """
    action = args['action']
    zone_id = args.get('zone_id', client.zone_id)
    filter_id = args.get('filter_id')
    filter_expression = args.get('filter_expression')
    products = argToList(args.get('products'))
    description = args.get('description')
    paused = arg_to_boolean(args.get('paused'))  # type: ignore
    priority = arg_to_number(args.get('priority'))
    ref = args.get('ref')

    response = client.cloudflare_waf_firewall_rule_create_request(
        action, zone_id,
        description=description, products=products, paused=paused, priority=priority, ref=ref,
        filter_id=filter_id, filter_expression=filter_expression)

    output = response['result']
    firewall_rule_output = output[0]

    firewall_rule = [{'id': dict_safe_get(firewall_rule_output, ['id']),
                      'action': dict_safe_get(firewall_rule_output, ['action']),
                      'paused': dict_safe_get(firewall_rule_output, ['paused']),
                      'description': dict_safe_get(firewall_rule_output, ['description']),
                      'filter_id': dict_safe_get(firewall_rule_output, ['filter', 'id']),
                      'filter_expression': dict_safe_get(firewall_rule_output, ['filter', 'expression']),
                      'products': dict_safe_get(firewall_rule_output, ['products']),
                      'ref': dict_safe_get(firewall_rule_output, ['ref']),
                      'priority': dict_safe_get(firewall_rule_output, ['priority']),
                      'zone_id': zone_id}]

    readable_output = tableToMarkdown(
        name='Firewall rule was successfully created.',
        t=firewall_rule,
        headers=['id', 'action', 'filter_id', 'filter_expression', 'products', 'priority', 'paused', 'description', 'ref'],
        headerTransform=string_to_table_header
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='CloudflareWAF.FirewallRule',
        outputs_key_field='id',
        outputs=output,
        raw_response=response
    )


def cloudflare_waf_firewall_rule_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """ Update firewall rule by the specified rule ID. Can update rule action, paused, description,
        priority, products and ref. Can not update or delete rule filter, ONLY add a new filter.

    Args:
        client (Client): Cloudflare API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: readable outputs for XSOAR.
    """
    rule_id = args['id']
    zone_id = args.get('zone_id', client.zone_id)
    action = args.get('action')
    filter_id = args.get('filter_id')
    products = args.get('products')
    description = args.get('description')
    paused = arg_to_boolean(args.get('paused'))  # type: ignore
    priority = arg_to_number(args.get('priority'))
    ref = args.get('ref')

    response = client.cloudflare_waf_firewall_rule_update_request(
        rule_id, filter_id, zone_id, action, description=description,  # type: ignore
        products=products, paused=paused, priority=priority, ref=ref)

    output = response['result']

    return CommandResults(
        readable_output=f'Firewall rule {rule_id} was successfully updated.',
        outputs_prefix='CloudflareWAF.FirewallRule',
        outputs_key_field='id',
        outputs=output,
        raw_response=response
    )


def cloudflare_waf_firewall_rule_delete_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """ Delete firewall rule by the specified rule ID.

    Args:
        client (Client): Cloudflare API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: readable outputs for XSOAR.
    """
    rule_id = args['id']
    zone_id = args.get('zone_id', client.zone_id)

    response = client.cloudflare_waf_firewall_rule_delete_request(rule_id, zone_id)

    return CommandResults(
        readable_output=f'Firewall rule {rule_id} was successfully deleted.',
        raw_response=response
    )


def cloudflare_waf_firewall_rule_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """ List of firewall rules under the specified firewall rules information includes the description, action and paused.
        Or retrieve details of individual firewall rule by specified the rule ID.

    Args:
        client (Client): Cloudflare API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    zone_id = args.get('zone_id', client.zone_id)
    rule_id = args.get('id')
    description = args.get('description')
    action = args.get('action')
    paused = arg_to_boolean(args.get('paused'))  # type: ignore
    page = arg_to_number(args.get('page'))
    page_size = arg_to_number(args.get('page_size'))
    limit = arg_to_number(args.get('limit'))

    validate_pagination_arguments(page, page_size, limit)

    firewall_rules = []

    command_args = {'zone_id': zone_id, 'rule_id': rule_id, 'description': description, 'action': action, 'paused': paused}
    pagination_args = {'limit': limit, 'page': page, 'page_size': page_size}
    response, output, pagination_message = pagination(
        client.cloudflare_waf_firewall_rule_list_request, command_args, pagination_args)

    for fr in output:
        firewall_rules.append({'id': fr['id'], 'action': fr['action'], 'paused': fr['paused'],
                               'description': dict_safe_get(fr, ['description']), 'filter_id': fr['filter']['id'],
                               'filter_expression': fr['filter']['expression']
                               })
        fr['zone_id'] = zone_id

    readable_output = tableToMarkdown(
        name='Firewall rule list',
        metadata=pagination_message,
        t=firewall_rules,
        headers=['id', 'action', 'paused', 'description', 'filter_id', 'filter_expression'],
        headerTransform=string_to_table_header
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='CloudflareWAF.FirewallRule',
        outputs_key_field='id',
        outputs=output,
        raw_response=response
    )


def cloudflare_waf_zone_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """ List of Zones under the specified zone information includes the name, account and status.
        Or retrieve details of individual zone by specified the zone ID.

    Args:
        client (Client): Cloudflare API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    match = args.get('match')
    name = args.get('name')
    account_name = args.get('account_name')
    order = args.get('order')
    status = args.get('status')
    account_id = args.get('account_id')
    direction = args.get('direction')
    page = arg_to_number(args.get('page'))
    page_size = arg_to_number(args.get('page_size'))
    limit = arg_to_number(args.get('limit'))

    validate_pagination_arguments(page, page_size, limit)

    command_args = {'match': match, 'name': name, 'account_name': account_name, 'order': order,
                    'status': status, 'account_id': account_id, 'direction': direction}
    pagination_args = {'limit': limit, 'page': page, 'page_size': page_size}
    response, output, pagination_message = pagination(
        client.cloudflare_waf_zone_list_request, command_args, pagination_args)

    readable_output = tableToMarkdown(
        name='Zone List',
        metadata=pagination_message,
        t=output,
        headers=['name', 'account name', 'status', 'account id', 'direction'],
        headerTransform=pascalToSpace
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='CloudflareWAF.Zone',
        outputs_key_field='id',
        outputs=output,
        raw_response=response
    )


def cloudflare_waf_filter_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """ Create a new filter for a firewall rule by a new filter expression.

    Args:
        client (Client): Cloudflare API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """

    expression = args['expression']
    zone_id = args.get('zone_id', client.zone_id)

    ref = args.get('ref')
    description = args.get('description')
    paused = arg_to_boolean(args.get('paused'))  # type: ignore

    response = client.cloudflare_waf_filter_create_request(
        expression, zone_id, description=description, paused=paused, ref=ref)

    cloned_response = copy.deepcopy(response)
    output = cloned_response['result']
    output.append({'zone_id': zone_id})

    readable_output = tableToMarkdown(
        name='Filter was successfully created.',
        t=output,
        headers=['id', 'expression', 'paused', 'description', 'ref'],
        headerTransform=pascalToSpace
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='CloudflareWAF.Filter',
        outputs_key_field='id',
        outputs=output,
        raw_response=response
    )


def cloudflare_waf_filter_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """ Update filter by the specified filter ID.

    Args:
        client (Client): Cloudflare API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """

    filter_id = args['id']
    expression = args.get('expression')
    zone_id = args.get('zone_id', client.zone_id)
    ref = args.get('ref')
    description = args.get('description')
    paused = arg_to_boolean(args.get('paused'))  # type: ignore

    response = client.cloudflare_waf_filter_update_request(
        filter_id, expression, zone_id, description=description,  # type: ignore
        paused=paused, ref=ref)

    output = response['result']

    return CommandResults(
        readable_output=f'Filter {filter_id} was successfully updated.',
        outputs_prefix='CloudflareWAF.Filter',
        outputs_key_field='id',
        outputs=output,
        raw_response=response
    )


def cloudflare_waf_filter_delete_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """ Delete filter by the specified filter ID.

    Args:
        client (Client): Cloudflare API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """

    filter_id = args['filter_id']
    zone_id = args.get('zone_id', client.zone_id)

    output = client.cloudflare_waf_filter_delete_request(filter_id, zone_id)
    return CommandResults(
        readable_output=f'Filter {filter_id} was successfully deleted.',
        raw_response=output
    )


def cloudflare_waf_filter_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """ List of filters under the specified filter information includes the paused, ref and description.
        Or retrieve details of individual filter by specified the ID.

    Args:
        client (Client): Cloudflare API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    zone_id = args.get('zone_id', client.zone_id)
    filter_id = args.get('id')
    expression = args.get('expression')
    ref = args.get('ref')
    description = args.get('description')
    paused = arg_to_boolean(args.get('paused'))  # type: ignore

    page = arg_to_number(args.get('page'))
    page_size = arg_to_number(args.get('page_size'))
    limit = arg_to_number(args.get('limit'))

    validate_pagination_arguments(page, page_size, limit)

    command_args = {'zone_id': zone_id, 'filter_id': filter_id,
                    'description': description, 'ref': ref, 'paused': paused, 'expression': expression}
    pagination_args = {'limit': limit, 'page': page, 'page_size': page_size}
    response, output, pagination_message = pagination(
        client.cloudflare_waf_filter_list_request, command_args, pagination_args)

    for filter in output:
        filter['zone_id'] = zone_id

    readable_output = tableToMarkdown(
        name='Filter list',
        metadata=pagination_message,
        t=output,
        headers=['id', 'expression', 'ref', 'description', 'paused'],
        headerTransform=pascalToSpace
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='CloudflareWAF.Filter',
        outputs_key_field='id',
        outputs=output,
        raw_response=response
    )


def cloudflare_waf_ip_lists_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """ List IP-lists under the specified list information includes the description, kind, number of items,
        number of referencing filters and dates.
        Or retrieve details of individual ip-list by specified the ID.

    Args:
        client (Client): Cloudflare API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """

    list_id = args.get('id')
    page = arg_to_number(args.get('page'))
    page_size = arg_to_number(args.get('page_size'))
    limit = arg_to_number(args.get('limit'))

    validate_pagination_arguments(page, page_size, limit)

    response = client.cloudflare_waf_ip_lists_list_request(
        list_id, page=page, page_size=page_size)
    response = response['result']

    # make sure response type is a list
    if isinstance(response, dict):
        response = [response]  # type: ignore

    output, pagination_message = ip_list_pagination(response, page, page_size, limit)

    readable_output = tableToMarkdown(
        name='IP lists list',
        metadata=pagination_message,
        t=output,
        headers=['id', 'name', 'kind', 'num_items', 'num_referencing_filters', 'created_on', 'modified_on'],
        headerTransform=string_to_table_header
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='CloudflareWAF.IpList',
        outputs_key_field='id',
        outputs=response,
        raw_response=response
    )


def cloudflare_waf_ip_list_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """ Create a new IP-list. An IP-list is a list that includes IP addresses and CIDR.
        IP-list is used in the filter expression.

    Args:
        client (Client): Cloudflare API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """

    name = args['name']
    description = args.get('description')

    response = client.cloudflare_waf_ip_list_create_request(
        name, description=description)

    output = response['result']
    readable_output = tableToMarkdown(
        name='IP list was successfully created.',
        t=output,
        headers=['id', 'name', 'description', 'kind', 'num_items', 'num_referencing_filters', 'created_on', 'modified_on'],
        headerTransform=string_to_table_header
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='CloudflareWAF.IpList',
        outputs_key_field='id',
        outputs=output,
        raw_response=response
    )


def cloudflare_waf_ip_list_delete_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """ Delete IP-list by the specified ID.

    Args:
        client (Client): Cloudflare API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """

    list_id = args['id']

    output = client.cloudflare_waf_ip_list_delete_request(list_id)

    return CommandResults(
        readable_output=f'IP list {list_id} was successfully deleted',
        raw_response=output
    )


def cloudflare_waf_ip_list_item_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """ Create a new ip-list items.

    Args:
        client (Client): Cloudflare API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """

    list_id = args['list_id']
    items = [{'ip': item} for item in argToList(args.get('items'))]

    response = client.cloudflare_waf_ip_list_item_create_request(list_id, items)
    output = response['result']

    return CommandResults(
        readable_output=f'Create items in the IP List {list_id} is executing',
        raw_response=output)


def cloudflare_waf_ip_list_item_update_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """ Replace exist ip-list items with a new items.

    Args:
        client (Client): Cloudflare API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """

    list_id = args['list_id']

    items = [{'ip': item} for item in argToList(args.get('items'))]

    response = client.cloudflare_waf_ip_list_item_update_request(list_id, items)
    output = response['result']

    return CommandResults(
        readable_output=f'Update items from ip-list {list_id} is executing',
        raw_response=output)


def cloudflare_waf_ip_list_item_delete_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """ Delete items from an ip-list.

    Args:
        client (Client): ClouDflare API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """

    list_id = args['list_id']
    items = [{'id': item} for item in argToList(args.get('items_id'))]

    response = client.cloudflare_waf_ip_list_item_delete_request(list_id, items)

    output = response['result']

    return CommandResults(
        readable_output=f'Delete items to the ip-list {list_id} is executing',
        raw_response=output)


def cloudflare_waf_ip_list_item_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """ List ip-list items. Can get by specified item ID or item IP.

    Args:
        client (Client): ClouDflare API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """

    list_id = args['list_id']
    item_id = args.get('item_id')
    item_ip = args.get('item_ip')

    if item_id and item_ip:
        raise ValueError('You specified both item_id and item_ip, only one can be specified.')

    page = arg_to_number(args.get('page'))
    page_size = arg_to_number(args.get('page_size'))
    limit = arg_to_number(args.get('limit'))

    validate_pagination_arguments(page, page_size, limit)

    ip_list = client.cloudflare_waf_ip_list_item_list_request(list_id, item=item_id)
    response = ip_list['result']

    # fetch all ip-list item, each call get 25 items
    while dict_safe_get(ip_list, ['result_info', 'cursors', 'after']):
        cursors = ip_list['result_info']['cursors']['after']
        ip_list = client.cloudflare_waf_ip_list_item_list_request(list_id, item=item_id, cursors=cursors)
        response += ip_list['result']

    output, pagination_message = ip_list_pagination(response, page, page_size, limit)

    # if user specified an item_IP and not item_ID - search in IP list the specified IP
    if item_ip:
        for item in response:
            if item['ip'] == item_ip:
                item_id = item['id']
                output = item
                pagination_message = 'Showing 1 rows out of 1.'
        if not item_id:
            raise ValueError(f"IP address {item_ip} it's not an item in IP list {list_id}")

    new_output = {'list_id': list_id, 'items': output}
    readable_output = tableToMarkdown(
        name=f'ip-list {list_id}',
        metadata=pagination_message,
        t=output,
        headers=['id', 'ip', 'created_on', 'modified_on'],
        headerTransform=string_to_table_header
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='CloudflareWAF.IpListItem',
        outputs_key_field='list_id',
        outputs=new_output,
        raw_response=new_output
    )


def cloudflare_waf_get_operation_command(client: Client, operation_id) -> CommandResults:
    """ Get operation command status.

    Args:
        client (Client): ClouDflare API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: status, outputs, readable outputs and raw response for XSOAR.
    """
    response = client.cloudflare_waf_get_operation_request(operation_id)
    output = response['result']

    readable_output = 'The command was executed successfully'
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='CloudflareWAF.Operation',
        outputs_key_field='id',
        outputs=output,
        raw_response=output
    )


def test_module(client: Client):
    try:
        client.cloudflare_waf_zone_list_request()
    except DemistoException as e:
        if 'Authorization' in str(e):
            return 'Authorization Error: make sure API Token is correctly set'
        else:
            raise e
    return 'ok'


def schedule_command(operation_id: str, interval: Optional[int], timeout: Optional[int], cmd: str,
                     args: Dict[str, Any]) -> ScheduledCommand:
    """ Build scheduled command if operation status is not completed.

    Args:
        operation_id (str): The command operation ID.
        cmd (Callable): The command name to execute.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        ScheduledCommand: Command, args, timeout and interval for CommandResults.
    """

    polling_args = {
        'operation_id': operation_id,
        'interval': interval,
        'polling': True,
        **args
    }

    scheduled_command = ScheduledCommand(
        command=cmd,
        next_run_in_seconds=interval,  # type: ignore
        args=polling_args,
        timeout_in_seconds=timeout)
    return scheduled_command


def run_polling_command(client: Client, cmd: str, command_function: Callable, args: Dict[str, Any]) -> CommandResults:
    """ Run a pipeline.

    Args:
        cmd (str): The command name.
        command (Callable): The command.
        client (Client): ClouDflare API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    ScheduledCommand.raise_error_if_not_supported()
    interval = arg_to_number(args.get('interval', 10))
    timeout = arg_to_number(args.get('timeout', 60))

    if 'operation_id' not in args:
        command_results = command_function(client, args)
        output = command_results.raw_response
        operation_id = output['operation_id']
        args['operation_id'] = operation_id
        scheduled_command = schedule_command(operation_id, interval, timeout, cmd, args)

        command_results.scheduled_command = scheduled_command
        return command_results

    operation_id = args.get('operation_id')
    command_results = cloudflare_waf_get_operation_command(client, operation_id)

    if command_results.outputs['status'] != 'completed':
        scheduled_command = schedule_command(operation_id, interval, timeout, cmd, args)
        command_results = CommandResults(scheduled_command=scheduled_command)
    return command_results


def main() -> None:
    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()

    credentials = params.get('credentials', {}).get('password')

    base_url = params.get('server')
    account_id = params.get('account_id')
    zone_id = params.get('zone_id')
    proxy = argToBoolean(params.get('proxy', False))
    insecure = argToBoolean(params.get('insecure', True))

    polling = args.get('polling')

    command = demisto.command()
    commands = {
        'cloudflare-waf-firewall-rule-create': cloudflare_waf_firewall_rule_create_command,
        'cloudflare-waf-firewall-rule-update': cloudflare_waf_firewall_rule_update_command,
        'cloudflare-waf-firewall-rule-delete': cloudflare_waf_firewall_rule_delete_command,
        'cloudflare-waf-firewall-rule-list': cloudflare_waf_firewall_rule_list_command,
        'cloudflare-waf-filter-create': cloudflare_waf_filter_create_command,
        'cloudflare-waf-filter-update': cloudflare_waf_filter_update_command,
        'cloudflare-waf-filter-delete': cloudflare_waf_filter_delete_command,
        'cloudflare-waf-filter-list': cloudflare_waf_filter_list_command,
        'cloudflare-waf-zone-list': cloudflare_waf_zone_list_command,
        'cloudflare-waf-ip-list-create': cloudflare_waf_ip_list_create_command,
        'cloudflare-waf-ip-list-delete': cloudflare_waf_ip_list_delete_command,
        'cloudflare-waf-ip-lists-list': cloudflare_waf_ip_lists_list_command,
        'cloudflare-waf-ip-list-item-create': cloudflare_waf_ip_list_item_create_command,
        'cloudflare-waf-ip-list-item-update': cloudflare_waf_ip_list_item_update_command,
        'cloudflare-waf-ip-list-item-delete': cloudflare_waf_ip_list_item_delete_command,
        'cloudflare-waf-ip-list-item-list': cloudflare_waf_ip_list_item_list_command
    }
    try:
        client: Client = Client(credentials, account_id, proxy, insecure, base_url, zone_id)  # type: ignore

        if command == 'test-module':
            return_results(test_module(client))
        if polling:
            return_results(run_polling_command(client, command, commands[command], args))
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(f'One or more of the specified fields are invalid. Please validate them. {e}')


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
