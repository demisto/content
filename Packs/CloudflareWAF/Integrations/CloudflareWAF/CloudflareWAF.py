# type: ignore
# pylint: disable=no-member
import demistomock as demisto  # noqa: F401
from CommonServerPython import *
from CommonServerUserPython import *
from typing import Any, Dict, Callable
from requests import Response


class Client(BaseClient):
    """Client class to interact with CloudFlare WAF API."""

    def __init__(self, credentials: str, account_id: str, zone_id: str = None):
        self.account_id = account_id
        self.zone_id = zone_id
        self.base_url = 'https://api.cloudflare.com/client/v4/'
        headers = {'Authorization': f'Bearer {credentials}', 'Content-Type': 'application/json'}
        super().__init__(base_url=self.base_url, headers=headers)

    def cloudflare_waf_firewall_rule_create_request(self, action: str, zone_id: str, description: str = None, products: list = None,
                                                    paused: bool = None, priority: int = None, ref: str = None,
                                                    filter_id: int = None, filter_expression: str = None) -> Dict[str, Any]:
        """ Create a new Firewall rule in Cloudflare.

        Args:
            description (str, optional): A description of the rule to help identify it. Defaults to None.
            products (list, optional): List of products to bypass for a request when the bypass action is used. Defaults to None.
            action (str, optional): The rule action. Defaults to None.
            paused (bool, optional): Whether this firewall rule is currently paused. Defaults to None.
            priority (int, optional): The priority of the rule to allow control of processing order. A lower number indicates
                high priority. If not provided, any rules with a priority will be sequenced before those without. Defaults to None.
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

    def cloudflare_waf_firewall_rule_update_request(self, rule_id: str, filter_id: str, zone_id: str, action: str, description: str = None,
                                                    products: list = None, paused: bool = None, priority: int = None,
                                                    ref: str = None) -> Dict[str, Any]:
        """ Sets the Firewall rule for the specified rule id.

        Args:
            id (str, optional): Firewall Rule identifier. Defaults to None.
            description (str, optional): A description of the rule to help identify it. Defaults to None.
            products (list, optional): List of products to bypass for a request when the bypass action is used. Defaults to None.
            action (str, optional): The rule action. Defaults to None.
            paused (bool, optional): Whether this firewall rule is currently paused. Defaults to None.
            priority (int, optional): The priority of the rule to allow control of processing order. A lower number indicates
                high priority. If not provided, any rules with a priority will be sequenced before those without. Defaults to None.
            ref (str, optional): Short reference tag to quickly select related rules. Defaults to None.
            filter_id (int, optional): Filter ID (for adding an existing filter). Defaults to None.

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
            id (str, optional): Firewall Rule identifier.

        Returns:
            dict: API response from Cloudflare.
        """
        return self._http_request(
            method='DELETE',
            url_suffix=f'zones/{zone_id}/firewall/rules',
            params={'id': rule_id})

    def cloudflare_waf_firewall_rule_list_request(self, zone_id: str, rule_id: str = None, description: str = None, action: str = None,
                                                  paused: bool = None, page: int = None, page_size: int = None) -> Dict[str, Any]:
        """ List of firewall rules or details of individual rule by ID.

        Args:
            id (str, optional): Firewall Rule identifier. Defaults to None.
            description (str, optional): A description of the rule to help identify it. Defaults to None.
            action (str, optional): The rule action. Defaults to None.
            paused (bool, optional): Whether this firewall rule is currently paused. Defaults to None.
            page (int, optional): Page number of paginated results. min value: 1.
            page_size (int, optional): Number of firewall rules per page. min value: 5, max value: 100.

        Returns:
            dict: API response from Cloudflare.
        """
        params = remove_empty_elements({
            'id': rule_id,
            'description': description,
            'action': action,
            'paused': paused,
            'page': page,
            'per_page': page_size
        })
        return self._http_request(
            method='GET',
            url_suffix=f'zones/{zone_id}/firewall/rules',
            params=params)

    def cloudflare_waf_zone_list_request(self, match: str = None, name: str = None, account_name: str = None, order: str = None,
                                         status: str = None, account_id: str = None, direction: str = None, page: int = None, page_size: int = None) -> Dict[str, Any]:
        """ List account's zones or details of individual zone by ID.

        Args:
            match (str, optional): Whether to match all search requirements or at least one (any). Defaults to None.
            name (str, optional):A domain name. Defaults to None.
            account_name (str, optional): Account name. Defaults to None.
            order (str, optional): Field to order zones by. Defaults to None.
            status (str, optional): Status of the zone. Defaults to None.
            account_id (str, optional): Account identifier tag. Defaults to None.
            direction (str, optional): Direction to order zones. Defaults to None.
            page (int, optional): Page number of paginated results. Defaults to 1.
            page_size (int, optional): Number of zones per page. Defaults to 50.

        Returns:
            dict: API response from Cloudflare.
        """
        params = remove_empty_elements({
            'match': match,
            'name': name,
            'account_name': account_name,
            'order': order,
            'status': status,
            'account_id': account_id,
            'direction': direction,
            'page': page,
            'per_page': page_size
        })
        return self._http_request(
            method='GET',
            url_suffix='zones',
            params=params)

    def cloudflare_waf_filter_create_request(self, expression: str, zone_id: str, ref: str = None, paused: bool = None, description: str = None) -> Dict[str, Any]:
        """ Create a new Filter in Cloudflare.
        Args:
            expression (str, optional): The filter expression to be used. Defaults to None.
            ref (str, optional): Short reference tag to quickly select related rules. Defaults to None.
            paused (str, optional): Whether this filter is currently paused. Defaults to None.
            description (str, optional): A note that you can use to describe the purpose of the filter. Defaults to None.
            zone_id (str, optional): Zone identifier. Defaults to None.

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

    def cloudflare_waf_filter_update_request(self, filter_id: str, expression: str, zone_id: str, ref: str = None, paused: bool = None,
                                             description: str = None) -> Dict[str, Any]:
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
        """_summary_

        Args:
            filter_id (str): _description_
            zone_id (str): _description_

        Returns:
            Dict[str, Any]: _description_
        """
        return self._http_request(
            method='DELETE',
            url_suffix=f'zones/{zone_id}/filters',
            params={'id': filter_id})

    def cloudflare_waf_filter_list_request(self, zone_id: str, filter_id: str = None, expression: str = None, ref: str = None, paused: bool = None,
                                           description: str = None, page: int = None, page_size: int = None) -> Dict[str, Any]:
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
            'id': filter_id,
            'expression': expression,
            'ref': ref,
            'paused': paused,
            'description': description,
            'zone_id': zone_id,
            'page': page,
            'per_page': page_size
        })
        return self._http_request(
            method='GET',
            url_suffix=f'zones/{zone_id}/filters',
            params=params)

    def cloudflare_waf_ip_lists_list_request(self, list_id: str = None, page: int = None, page_size: int = None) -> Dict[str, Any]:
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
            name (str, optional): The name of the list (used in filter expressions). Defaults to None.
            kind (int, optional): The kind of values in the List. Defaults to 1.
            description (int, optional): A note that can be used to annotate the List. Defaults to 50.

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
            name (str, optional): The name of the list (used in filter expressions). Defaults to None.
            kind (int, optional): The kind of values in the List. Defaults to 1.
            description (int, optional): A note that can be used to annotate the List. Defaults to 50.

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
            name (str, optional): The name of the list (used in filter expressions). Defaults to None.
            kind (int, optional): The kind of values in the List. Defaults to 1.
            description (int, optional): A note that can be used to annotate the List. Defaults to 50.

        Returns:
            dict: API response from Cloudflare.
        """
        return self._http_request(
            method='DELETE',
            url_suffix=f'accounts/{self.account_id}/rules/lists/{list_id}/items',
            json_data={'items': items})

    def cloudflare_waf_ip_list_item_list_request(self, list_id: str, item: list = None) -> Dict[str, Any]:
        """  List ip-list items.

        Args:
            name (str, optional): The name of the list (used in filter expressions). Defaults to None.
            kind (int, optional): The kind of values in the List. Defaults to 1.
            description (int, optional): A note that can be used to annotate the List. Defaults to 50.

        Returns:
            dict: API response from Cloudflare.
        """
        item_suffix = f'/{item}' if item else ''

        return self._http_request(
            method='GET',
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
    if page_size:
        if page_size < 5 or page_size > 100:
            raise ValueError('page size argument must be greater than 5 and smaller than 100.')

    if page:
        if page < 1:
            raise ValueError('page argument must be greater than 0.')

    if limit < 5 or limit > 100:
        raise ValueError('limit argument must be greater than 5.')


def cloudflare_waf_firewall_rule_create_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """ Create a new firewall rule by new filter (if filter_expression is specified)
        or an already exist filter (if filter_id is specified).

    Args:
        client (Client): Cloudflare API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: readable outputs for XSOAR.
    """
    products = argToList(args.get('products'))
    description = args.get('description')
    action = args['action']
    paused = args.get('paused')
    paused = argToBoolean(paused) if paused else None
    priority = arg_to_number(args.get('priority'))
    ref = args.get('ref')
    filter_id = args.get('filter_id')
    filter_expression = args.get('filter_expression')
    zone_id = args.get('zone_id', client.zone_id)

    firewall_rule_item = client.cloudflare_waf_firewall_rule_create_request(
        description=description, products=products, action=action, paused=paused, priority=priority, ref=ref,
        filter_id=filter_id, filter_expression=filter_expression, zone_id=zone_id)

    output = firewall_rule_item['result']
    firewall_rule_output = output[0]

    firewall_rule = [{'id': dict_safe_get(firewall_rule_output, ['id']),
                      'action': dict_safe_get(firewall_rule_output, ['action']),
                      'paused': dict_safe_get(firewall_rule_output, ['paused']),
                      'description': dict_safe_get(firewall_rule_output, ['description']),
                      'filter_id': dict_safe_get(firewall_rule_output, ['filter', 'id']),
                      'filter_expression': dict_safe_get(firewall_rule_output, ['filter', 'expression']),
                      'products': dict_safe_get(firewall_rule_output, ['products']),
                      'ref': dict_safe_get(firewall_rule_output, ['ref']),
                      'priority': dict_safe_get(firewall_rule_output, ['priority'])}]

    output['zone_id'] = zone_id

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
        raw_response=output
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
    products = args.get('products')
    description = args.get('description')
    action = args.get('action')
    paused = args.get('paused')
    paused = argToBoolean(paused) if paused else None
    priority = arg_to_number(args.get('priority'))
    ref = args.get('ref')
    filter_id = args.get('filter_id')
    zone_id = args.get('zone_id', client.zone_id)

    firewall_rule_item = client.cloudflare_waf_firewall_rule_update_request(
        rule_id=rule_id, description=description, products=products, action=action, paused=paused, priority=priority, ref=ref,
        filter_id=filter_id, zone_id=zone_id)

    output = firewall_rule_item['result']
    output['zone_id'] = zone_id

    return CommandResults(
        readable_output=f'Firewall rule {rule_id} was successfully updated.',
        outputs_prefix='CloudflareWAF.FirewallRule',
        outputs_key_field='id',
        outputs=output,
        raw_response=output
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

    client.cloudflare_waf_firewall_rule_delete_request(rule_id=rule_id, zone_id=zone_id)

    return CommandResults(
        readable_output=f'Firewall rule {rule_id} was successfully deleted.'
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
    rule_id = args.get('id')
    description = args.get('description')
    action = args.get('action')
    paused = args.get('paused')
    paused = argToBoolean(paused) if paused else None
    page = arg_to_number(args.get('page'))
    page_size = arg_to_number(args.get('page_size'))
    limit = arg_to_number(args.get('limit'))
    zone_id = args.get('zone_id', client.zone_id)

    validate_pagination_arguments(page=page, page_size=page_size, limit=limit)

    firewall_rule_lists = []

    if page and page_size:
        firewall_rule_list = client.cloudflare_waf_firewall_rule_list_request(
            rule_id=rule_id, description=description, action=action, paused=paused, page=page, page_size=page_size, zone_id=zone_id)

        firewall_rule_lists.extend(firewall_rule_list['result'])
        total_num_item = dict_safe_get(firewall_rule_list, ['result_info', 'count'])
        page_num = dict_safe_get(firewall_rule_list, ['result_info', 'page'])
        total_pages = dict_safe_get(firewall_rule_list, ['result_info', 'total_pages'])
        pagination_message = f'Showing page {page_num} out of {total_pages}. \n Current page size: {total_num_item}'
    else:
        while limit > 0:
            if limit > 100:
                page_size = 100
            else:
                page_size = limit
            firewall_rule_list = client.cloudflare_waf_firewall_rule_list_request(
                rule_id=rule_id, description=description, action=action, paused=paused, page=page, page_size=page_size, zone_id=zone_id)
            total_count = dict_safe_get(firewall_rule_list, ['result_info', 'total_count'])
            firewall_rule_lists.extend(firewall_rule_list['result'])
            limit = limit - 100
        pagination_message = f'Showing {len(firewall_rule_lists)} rows out of {total_count}.'

    output = firewall_rule_lists
    firewall_rules = []

    for fr in output:
        firewall_rules.append({'id': fr['id'], 'action': fr['action'], 'paused': fr['paused'],
                               'description': dict_safe_get(fr, ['description']), 'filter_id': fr['filter']['id'],
                               'filter_expression': fr['filter']['expression'], 'zone_id': zone_id
                               })

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
        outputs=firewall_rules,
        raw_response=output
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

    validate_pagination_arguments(page=page, page_size=page_size, limit=limit)

    zone_lists = []
    if page and page_size:
        zone_list = client.cloudflare_waf_zone_list_request(match=match, name=name, account_name=account_name, order=order,
                                                            status=status, account_id=account_id, direction=direction, page=page,
                                                            page_size=page_size)

        zone_lists.extend(zone_list['result'])
        total_num_item = dict_safe_get(zone_list, ['result_info', 'count'])
        page_num = dict_safe_get(zone_list, ['result_info', 'page'])
        total_pages = dict_safe_get(zone_list, ['result_info', 'total_pages'])
        pagination_message = f'Showing page {page_num} out of {total_pages}. \n Current page size: {total_num_item}'
    else:
        while limit > 0:
            if limit > 100:
                page_size = 100
            else:
                page_size = limit
            zone_list = client.cloudflare_waf_zone_list_request(match=match, name=name, account_name=account_name, order=order,
                                                                status=status, account_id=account_id, direction=direction, page=page,
                                                                page_size=page_size)
            total_count = dict_safe_get(zone_list, ['result_info', 'total_count'])
            zone_lists.extend(zone_list['result'])
            limit = limit - 100
        pagination_message = f'Showing {len(zone_lists)} rows out of {total_count}'

    output = zone_lists

    readable_output = tableToMarkdown(
        name='Zone list',
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
        raw_response=output
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
    ref = args.get('ref')
    description = args.get('description')
    paused = args.get('paused')
    paused = argToBoolean(paused) if paused else None
    zone_id = args.get('zone_id', client.zone_id)

    filter_item = client.cloudflare_waf_filter_create_request(description=description, paused=paused, ref=ref,
                                                              expression=expression, zone_id=zone_id)

    output = filter_item['result']
    output['zone_id'] = zone_id

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
        raw_response=output
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
    ref = args.get('ref')
    description = args.get('description')
    paused = args.get('paused')
    paused = argToBoolean(paused) if paused else None
    zone_id = args.get('zone_id', client.zone_id)

    filter_item = client.cloudflare_waf_filter_update_request(filter_id=filter_id, description=description, paused=paused, ref=ref,
                                                              expression=expression, zone_id=zone_id)

    output = filter_item['result']
    output['zone_id'] = zone_id

    return CommandResults(
        readable_output=f'Filter {filter_id} was successfully updated.',
        outputs_prefix='CloudflareWAF.Filter',
        outputs_key_field='id',
        outputs=output,
        raw_response=output
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

    l=client.cloudflare_waf_filter_delete_request(filter_id=filter_id, zone_id=zone_id)
    print(l)
    return CommandResults(
        readable_output=f'Filter {filter_id} was successfully deleted.',
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

    filter_id = args.get('id')
    expression = args.get('expression')
    ref = args.get('ref')
    description = args.get('description')
    paused = args.get('paused')
    paused = argToBoolean(paused) if paused else None
    zone_id = args.get('zone_id', client.zone_id)
    page = arg_to_number(args.get('page'))
    page_size = arg_to_number(args.get('page_size'))
    limit = arg_to_number(args.get('limit'))

    validate_pagination_arguments(page=page, page_size=page_size, limit=limit)

    filter_lists = []
    if page and page_size:
        filter_list = client.cloudflare_waf_filter_list_request(filter_id=filter_id, description=description, paused=paused, ref=ref,
                                                                expression=expression, zone_id=zone_id, page=page,
                                                                page_size=page_size)
        filter_lists.extend(filter_list['result'])
        total_num_item = dict_safe_get(filter_list, ['result_info', 'count'])
        page_num = dict_safe_get(filter_list, ['result_info', 'page'])
        total_pages = dict_safe_get(filter_list, ['result_info', 'total_pages'])
        pagination_message = f'Showing page {page_num} out of {total_pages}. \n  Current page size: {total_num_item}'
    else:
        while limit > 0:
            if limit > 100:
                page_size = 100
            else:
                page_size = limit
            filter_list = client.cloudflare_waf_filter_list_request(filter_id=filter_id, description=description, paused=paused, ref=ref,
                                                                    expression=expression, zone_id=zone_id, page=page,
                                                                    page_size=page_size)
            total_count = dict_safe_get(filter_list, ['result_info', 'total_count'])
            filter_lists.extend(filter_list['result'])
            limit = limit - 100

        pagination_message = f'Showing {len(filter_lists)} rows out of {total_count}.'

    for f in filter_lists:
        f['zone_id'] = zone_id

    output = filter_lists

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
        raw_response=output
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

    validate_pagination_arguments(page=page, page_size=page_size, limit=limit)
    ip_lists = client.cloudflare_waf_ip_lists_list_request(list_id=list_id, page=page, page_size=page_size)
    response = ip_lists['result']

    if isinstance(response, dict):
        response = [response]

    output = response

    if page and page_size:
        if page_size < len(response):
            first_item = page_size * (page - 1)
            output = response[first_item:]
            output = output[:page_size]
        else:
            output = response[:page_size]
        pagination_message = f'Showing page {page} out of others that may exist. \n Current page size: {page_size}'
    else:
        output = response[:limit]
        pagination_message = f'Showing {len(output)} rows out of {len(response)}.'

    ip_lists_lists = output

    output = ip_lists_lists

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

    new_list = client.cloudflare_waf_ip_list_create_request(name=name, description=description)

    output = new_list['result']
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
        raw_response=output
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

    client.cloudflare_waf_ip_list_delete_request(list_id=list_id)

    return CommandResults(
        readable_output=f'IP list {list_id} was successfully deleted'
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

    updated_list = client.cloudflare_waf_ip_list_item_create_request(list_id=list_id, items=items)

    output = updated_list['result']

    return CommandResults(
        readable_output=f'Adding items to the ip-list {list_id} is executing',
        outputs=output,
        raw_response=output
    )


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

    updated_list = client.cloudflare_waf_ip_list_item_update_request(list_id=list_id, items=items)

    output = updated_list['result']

    return CommandResults(
        readable_output=f'Replacing items in the IP List {list_id} is executing',
        outputs=output,
        raw_response=output
    )


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

    updated_list = client.cloudflare_waf_ip_list_item_delete_request(list_id=list_id, items=items)

    output = updated_list['result']

    return CommandResults(
        readable_output=f'Deleting items from ip-list {list_id} is executing',
        outputs=output,
        raw_response=output
    )


def cloudflare_waf_ip_list_item_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """ List ip-list items.

    Args:
        client (Client): ClouDflare API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """

    list_id = args['list_id']
    item = args.get('items')
    page = arg_to_number(args.get('page'))
    page_size = arg_to_number(args.get('page_size'))
    limit = arg_to_number(args.get('limit'))

    validate_pagination_arguments(page=page, page_size=page_size, limit=limit)

    updated_list = client.cloudflare_waf_ip_list_item_list_request(list_id=list_id, item=item)
    response = updated_list['result']
    output = response
    if page and page_size:
        if page_size < len(response):
            first_item = page_size * (page - 1)
            output = response[first_item:]
            output = output[:page_size]
        else:
            output = response[:page_size]
        pagination_message = f'Showing page {page} out of others that may exist. \n Current page size: {page_size}'
    else:
        output = response[:limit]
        pagination_message = f'Showing {len(output)} rows out of {len(response)}.'

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
        outputs_prefix='CloudflareWAF.IpListItems',
        outputs_key_field='list_id',
        outputs=new_output,
        raw_response=new_output
    )


def cloudflare_waf_get_operation_command(client: Client, operation_id) -> CommandResults:
    """_summary_

    Args:
        client (Client): _description_
        operation_id (_type_): _description_

    Returns:
        CommandResults: _description_
    """
    response = client.cloudflare_waf_get_operation_request(operation_id)
    output = response['result']
    status = output['status']

    readable_output = 'The command was executed successfully'
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='CloudflareWAF.Operation',
        outputs_key_field='id',
        outputs=output,
        raw_response=output
    ), status


def test_module(client: Client) -> None:
    try:
        client.cloudflare_waf_zone_list_request()
    except DemistoException as e:
        if 'Authorization' in str(e):
            return 'Authorization Error: make sure API Token is correctly set'
        else:
            raise e
    return 'ok'


def run_polling_command(client: Client, cmd: str, command: Callable, args: Dict[str, Any]) -> None:
    """_summary_

    Args:
        cmd (str): The command name.
        command (Callable): The command.
        client (Client): ClouDflare API client.
        args (Dict[str, Any]): Command arguments from XSOAR.

    Returns:
        _type_: _description_
    """
    ScheduledCommand.raise_error_if_not_supported()
    interval = arg_to_number(args.get('interval'), 30)
    timeout = arg_to_number(args.get('timeout'), 60)

    if 'operation_id' not in args:
        command_results: Dict[str, Any] = command(client, args)
        outputs = command_results.outputs
        operation_id = outputs.get('operation_id')
        if outputs.get('status') != 'completed':
            polling_args = {
                'operation_id': operation_id,
                'interval': interval,
                'polling': True,
                **args
            }
            scheduled_command = ScheduledCommand(
                command=cmd,
                next_run_in_seconds=interval,
                args=polling_args,
                timeout_in_seconds=timeout)
            command_results.scheduled_command = scheduled_command
            return command_results
        else:
            args['operation_id'] = operation_id
    operation_id = args.get('operation_id')
    command_results, status = cloudflare_waf_get_operation_command(client, operation_id)

    if status != 'completed':
        polling_args = {
            'operation_id': args.get('operation_id'),
            'interval': interval,
            'polling': True,
            **args
        }
        scheduled_command = ScheduledCommand(
            command=cmd,
            next_run_in_seconds=interval,
            args=polling_args,
            timeout_in_seconds=timeout)

        command_results = CommandResults(scheduled_command=scheduled_command)
    return command_results


def main() -> None:
    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()

    credentials = params.get('credentials', {}).get('identifier')
    account_id = params.get('account_id', {}).get('identifier')
    zone_id = params.get('zone_id', {}).get('identifier')

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
        client: Client = Client(credentials, account_id, zone_id)

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
