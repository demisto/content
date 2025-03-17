import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
from AWSApiModule import *  # noqa: E402
from typing import TYPE_CHECKING, Any
from collections.abc import Callable

# The following import are used only for type hints and autocomplete.
# It is not used at runtime, and not exist in the docker image.
if TYPE_CHECKING:
    from mypy_boto3_wafv2 import WAFV2Client
    from mypy_boto3_wafv2.type_defs import (
        RegexTypeDef,
        UpdateRuleGroupResponseTypeDef,
        RuleTypeDef,
        VisibilityConfigTypeDef
    )

''' CONSTANTS '''

SERVICE = 'wafv2'
OUTPUT_PREFIX = 'AWS.Waf'
DEFAULT_SCOPE = 'Regional'
REGEX_MATCH_STATEMENT = 'RegexPatternSetReferenceStatement'
BYTE_MATCH_STATEMENT = 'ByteMatchStatement'
TEXT_TRANSFORMATIONS = 'NONE | COMPRESS_WHITE_SPACE | HTML_ENTITY_DECODE | LOWERCASE | CMD_LINE | URL_DECODE | ' \
                       'BASE64_DECODE | HEX_DECODE | MD5 | REPLACE_COMMENTS | ESCAPE_SEQ_DECODE | SQL_HEX_DECODE | ' \
                       'CSS_DECODE | JS_DECODE | NORMALIZE_PATH | NORMALIZE_PATH_WIN | REMOVE_NULLS | ' \
                       'REPLACE_NULLS | BASE64_DECODE_EXT | URL_DECODE_UNI | UTF8_TO_UNICODE'

SCOPE_MAP = {'Regional': 'REGIONAL',
             'Global': 'CLOUDFRONT'}
OPERATOR_TO_STATEMENT_OPERATOR = {'And': 'AndStatement', 'Or': 'OrStatement', 'Not': 'NotStatement'}
MATCH_TYPE_TO_POSITIONAL_CONSTRAIN = {'Exactly Matches String': 'EXACTLY',
                                      'Starts With String': 'STARTS_WITH',
                                      'Ends With String': 'ENDS_WITH',
                                      'Contains String': 'CONTAINS',
                                      'Contains Words': 'CONTAINS_WORD',
                                      'all': 'EXACTLY | STARTS_WITH | ENDS_WITH | CONTAINS | CONTAINS_WORD'}
WEB_REQUEST_COMPONENT_MAP = {"Headers": "Headers",
                             "Cookies": "Cookies",
                             "Query Parameters": "AllQueryArguments",
                             "Uri Path": "UriPath",
                             "Query String": "QueryString",
                             "Body": "Body",
                             "HTTP Method": "Method"}

''' HELPER FUNCTIONS '''


def build_string_match_rule_object(args: dict) -> dict:  # pragma: no cover
    """
    Creates a string match rule statement object that can be added to a rule
    Args:
        args: The command arguments

    Returns:
        String match rule statement object
    """
    return {
        'Statement': build_string_match_statement(**args)
    }


def get_required_args_for_get_rule_group(args: dict) -> dict:  # pragma: no cover
    """
    Build the required arguments for a request of get_rule_group
    Args:
        args: The command arguments

    Returns:
       The required arguments for a request of get_rule_group
    """
    return {
        'Name': args.get('group_name', ''),
        'Scope': SCOPE_MAP[args.get('scope') or DEFAULT_SCOPE],
        'Id': args.get('group_id', '')
    }


def build_ip_statement(ip_set_arn: str) -> dict:  # pragma: no cover
    """
    Creates an ip statement that can be added to a statements list of a rule
    Args:
        ip_set_arn: The ip set ARN representation

    Returns:
        An ip statement object
    """
    return {'IPSetReferenceStatement': {'ARN': ip_set_arn}}


def build_country_statement(country_codes: list) -> dict:  # pragma: no cover
    """
    Creates a country statement that can be added to a statements list of a rule
    Args:
        country_codes: The country codes

    Returns:
        A country statement object
    """
    return {'GeoMatchStatement': {'CountryCodes': country_codes}}


def build_country_rule_object(args: dict) -> dict:  # pragma: no cover
    """
    Creates a country rule statement object that can be added to a rule
    Args:
        args: The command arguments

    Returns:
        Country rule statement object
    """
    country_codes = argToList(args.get('country_codes'))
    return {
        'Statement': build_country_statement(country_codes)
    }


def build_visibility_config_object(metric_name: str,
                                   cloud_watch_metrics_enabled: bool,
                                   sampled_requests_enabled: bool) -> dict:  # pragma: no cover
    """
    Creates a dictionary which represents visibility config
    Args:
        metric_name: The metric name
        cloud_watch_metrics_enabled: whether to enable cloud metrics
        sampled_requests_enabled: whether to enable sample requests

    Returns:
        Visibility config object
    """
    return {
        'CloudWatchMetricsEnabled': cloud_watch_metrics_enabled,
        'MetricName': metric_name,
        'SampledRequestsEnabled': sampled_requests_enabled
    }


def get_tags_dict_from_args(tag_keys: list, tag_values: list) -> list:
    """
    Creates a list of dictionaries containing the tag key, and its corresponding value
    Args:
        tag_keys: tag keys list
        tag_values: tag values list

    Returns:
        List of tags
    """
    if len(tag_keys) != len(tag_values):
        raise DemistoException('The tags_keys and tag_values arguments must be at the same length.')

    # keys and values are in the same length
    return [{'Key': k, 'Value': v} for k, v in zip(tag_keys, tag_values)]


def build_regex_pattern_object(regex_patterns: list) -> list["RegexTypeDef"]:
    """
    Creates a list of dictionaries which represent a regex set object
    Args:
        regex_patterns: regex patterns

    Returns:
        List of regex patterns objects
    """
    return [
        {'RegexString': regex_pattern} for regex_pattern in regex_patterns
    ]


def build_ip_rule_object(args: dict) -> dict:
    """
    Creates an ip rule statement object that can be added to a rule
    Args:
        args: The command arguments

    Returns:
        Ip rule statement object
    """
    ip_rule = {}
    ip_set_arns = argToList(args.get('ip_set_arn'))
    condition_operator = args.get('condition_operator', '')
    if len(ip_set_arns) > 1 and not condition_operator:
        raise DemistoException('The condition_operator argument must be specified when '
                               'ip_set_arn contains more than one value.')

    if len(ip_set_arns) == 1:
        ip_rule['Statement'] = build_ip_statement(ip_set_arns[0])
    elif len(ip_set_arns) > 1:
        statement_operator = OPERATOR_TO_STATEMENT_OPERATOR[condition_operator]
        ip_rule.setdefault('Statement', {})[statement_operator] = {
            'Statements': [build_ip_statement(ip_set_arn) for ip_set_arn in ip_set_arns]
        }
    return ip_rule


def build_string_match_statement(match_type: str = '',
                                 string_to_match: str = '',
                                 regex_set_arn: str = '',
                                 oversize_handling: str = '',
                                 text_transformation: str = 'NONE',
                                 web_request_component: str = '', **kwargs) -> dict:
    """
    Creates a byte/regex match statement that can be added to a statements list of a rule
    Args:
        match_type: Which match type should be performed
        string_to_match: string_to_match: The string to match to
        regex_set_arn: The regex set to match to
        oversize_handling: The oversize handling to be applied to web request contents
        text_transformation: The text transformation to perform on the component
        web_request_component: web_request_component: The web request component to inspect
        kwargs: Args that are not in use in this method but passed from the command arguments

    Returns:
        A byte/regex match statement object
    """
    match_statement = REGEX_MATCH_STATEMENT if match_type == 'Matches Regex Pattern Set' \
        else BYTE_MATCH_STATEMENT
    web_request_component = WEB_REQUEST_COMPONENT_MAP.get(web_request_component) or ''
    if match_statement == BYTE_MATCH_STATEMENT:
        if not string_to_match:
            raise DemistoException('string_to_match must be provided when using strings match_type')
        statement = build_byte_match_statement(web_request_component=web_request_component,
                                               oversize_handling=oversize_handling,
                                               text_transformation=text_transformation,
                                               string_to_match=string_to_match,
                                               match_type=match_type)

    else:  # match_statement == REGEX_MATCH_STATEMENT
        if not regex_set_arn:
            raise DemistoException('regex_set_arn must be provided when using Matches Regex Pattern Set match_type')
        statement = build_regex_match_statement(web_request_component=web_request_component,
                                                oversize_handling=oversize_handling,
                                                regex_set_arn=regex_set_arn,
                                                text_transformation=text_transformation)

    return {match_statement: statement}


def update_rule_with_statement(rule: dict, statements: list, condition_operator: str):
    """
    Updates an existing rule with a new statement
    Args:
        rule: The rule to update
        statements: The statement to update the rule with
        condition_operator: The condition to apply on the statements
    """
    old_rule_statement = rule.get('Statement', {})
    if 'AndStatement' in old_rule_statement or 'OrStatement' in old_rule_statement:
        demisto.info('ignoring condition_operator argument as the statement already contains an operator.')
        condition = list(old_rule_statement.keys())[0]
    elif condition_operator:
        condition = OPERATOR_TO_STATEMENT_OPERATOR[condition_operator]
        # override the statement key with the conditional statement
        rule['Statement'] = {condition: {'Statements': [old_rule_statement]}}

    else:
        raise DemistoException('Rule contains only one statement. Please provide condition operator.')
    rule['Statement'][condition]['Statements'].extend(statements)


def create_rules_list_with_new_rule_statement(args: dict, statements: list, rules: list) -> list:
    """
    Creates a rules list with the updated rule
    Args:
        args: The command arguments
        statements: The statements to add to a rule
        rules: The original rules

    Returns:
        Updated list of rules
    """
    new_rules = rules.copy()
    rule_name = args.get('rule_name', '')
    condition_operator = args.get('condition_operator', '')
    for rule in new_rules:
        if rule.get('Name') == rule_name:
            update_rule_with_statement(rule, statements, condition_operator)
            return rules
    raise DemistoException(f'Did not find any rule with name {rule_name}')


def build_web_component_match_object(web_request_component: str, oversize_handling: str) -> dict:
    """
    Creates web component object to send to the API
    Args:
        web_request_component: The web request component to inspect
        oversize_handling: The oversize handling to be applied to web request contents

    Returns:

    """
    web_request_component_object = {}
    if web_request_component in {'Headers', 'Cookies', 'Body'}:
        if not oversize_handling:
            raise DemistoException(
                'oversize_handling must be provided when using Headers, Cookies, Body in web_request_component')
        if web_request_component != 'Body':
            web_request_component_object = {'MatchPattern': {
                'All': {}
            },
                'MatchScope': 'ALL'
            }
        web_request_component_object['OversizeHandling'] = oversize_handling
    return web_request_component_object


def build_byte_match_statement(web_request_component: str,
                               oversize_handling: str,
                               text_transformation: str,
                               string_to_match: str,
                               match_type: str) -> dict:
    """
    Creates a byte match statement
    Args:
        web_request_component: The web request component to inspect
        oversize_handling: The oversize handling to be applied to web request contents
        that are bigger than what can be inspected by AWS WAF
        text_transformation: The text transformation to perform on the component
        string_to_match: The string to match to
        match_type: Which match type should be performed

    Returns:
        A byte match statement value
    """
    web_request_component_object = build_web_component_match_object(web_request_component, oversize_handling)
    return {
        'SearchString': string_to_match,
        'FieldToMatch': {
            web_request_component: web_request_component_object
        },
        'TextTransformations': [
            {'Priority': 0,
             'Type': text_transformation
             }
        ],
        'PositionalConstraint': MATCH_TYPE_TO_POSITIONAL_CONSTRAIN[match_type]}


def build_regex_match_statement(web_request_component: str,
                                oversize_handling: str,
                                text_transformation: str,
                                regex_set_arn: str) -> dict:
    """
    Creates a byte match statement
    Args:
        web_request_component: The web request component to inspect
        oversize_handling: The oversize handling to be applied to web request contents
        that are bigger than what can be inspected by AWS WAF
        text_transformation: The text transformation to perform on the component
        regex_set_arn: The regex set to match to

    Returns:
        A regex match statement value
    """
    web_request_component_object = build_web_component_match_object(web_request_component, oversize_handling)
    return {
        'ARN': regex_set_arn,
        'FieldToMatch': {
            web_request_component: web_request_component_object
        },
        'TextTransformations': [
            {'Priority': 0, 'Type': text_transformation
             }
        ]
    }


def build_new_rule_object(args: dict, rule_group_visibility_config: "VisibilityConfigTypeDef",
                          build_rule_func: Callable[[dict], dict]) -> dict:
    """
    Creates a country rule object that can be added to a rule group rules list
    Args:
        args: The command arguments
        rule_group_visibility_config: The rule visibility config
        build_rule_func: A generic function that builds the statement of the rule

    Returns:
        Entire rule object
    """
    name = args.get('rule_name', '')
    rule_visibility_config = build_visibility_config_object(
        metric_name=name,
        cloud_watch_metrics_enabled=rule_group_visibility_config.get('CloudWatchMetricsEnabled', True),
        sampled_requests_enabled=rule_group_visibility_config.get('SampledRequestsEnabled', True))

    rule = {
        'Name': name,
        'Priority': arg_to_number(args.get('priority', '')) or 0,
        'Action': {
            args.get('action'): {}
        },
        'VisibilityConfig': rule_visibility_config,

    }
    rule |= build_rule_func(args)

    return rule


def delete_rule(rule_name: str, rules: list) -> list:
    """
    Deletes a rule from a rules list
    Args:
        rule_name: The rule name to delete
        rules: The rules list of a rule group

    Returns:
        A new rules list without the rule to delete
    """
    updated_rules = rules.copy()
    for rule in rules:
        if rule.get('Name') == rule_name:
            updated_rules.remove(rule)
            break
    return updated_rules


def append_new_rule(rules: list, rule: dict) -> list:
    """
    Adds a rule from a rules list
    Args:
        rule: The rule object to add
        rules: The rules list of a rule group

    Returns:
        A new rules list with the rule to delete
    """
    updated_rules = rules.copy()
    updated_rules.append(rule)
    return updated_rules


def get_required_response_fields_from_rule_group(client: "WAFV2Client", kwargs: dict
                                                 ) -> tuple[list["RuleTypeDef"], "VisibilityConfigTypeDef", str]:
    """
    Gets all the fields from the response that are required for the update request
    Args:
        client: AWS WF client
        kwargs: args required for get rule group

    Returns:
        rules, visibility config object and lockToken associated to a rule group
    """
    response = client.get_rule_group(**kwargs)

    rule_group = response.get('RuleGroup', {})
    rules = rule_group.get('Rules', [])
    rule_group_visibility_config = rule_group.get('VisibilityConfig', {})
    lock_token = response.get('LockToken', '')

    return rules, rule_group_visibility_config, lock_token  # type: ignore[return-value]


'''CLIENT FUNCTIONS'''


def update_rule_group_rules(client: "WAFV2Client",
                            kwargs: dict,
                            lock_token: str,
                            updated_rules: list,
                            rule_group_visibility_config: "VisibilityConfigTypeDef"
                            ) -> "UpdateRuleGroupResponseTypeDef":  # pragma: no cover
    """ Updates rule group with new rules list"""
    kwargs |= {'LockToken': lock_token,
               'Rules': updated_rules,
               'VisibilityConfig': rule_group_visibility_config
               }

    return client.update_rule_group(**kwargs)


''' COMMAND FUNCTIONS '''


def connection_test(client: "WAFV2Client") -> str:  # pragma: no cover
    """ Command to test the connection to the API"""
    try:
        client.list_ip_sets(Scope=SCOPE_MAP[DEFAULT_SCOPE])  # type: ignore[arg-type]
    except Exception as e:
        raise DemistoException(f'Failed to execute test module. Error: {str(e)}')

    return 'ok'


def create_ip_set_command(client: "WAFV2Client", args: dict) -> CommandResults:
    """ Command to create an IP set"""
    tag_keys = argToList(args.get('tag_key')) or []
    tag_values = argToList(args.get('tag_value')) or []
    kwargs = {
        'Name': args.get('name', ''),
        'Scope': SCOPE_MAP[args.get('scope') or DEFAULT_SCOPE],
        'IPAddressVersion': args.get('ip_version', ''),
        'Addresses': argToList(args.get('addresses')) or [],
    }

    if description := args.get('description'):
        kwargs |= {'Description': description}
    if tags := get_tags_dict_from_args(tag_keys, tag_values):
        kwargs |= {'Tags': tags}

    response = client.create_ip_set(**kwargs)
    outputs = response.get('Summary', {})

    readable_output = f'AWS Waf ip set with id {outputs.get("Id", "")} was created successfully'

    return CommandResults(readable_output=readable_output,
                          outputs=outputs,
                          raw_response=response,
                          outputs_prefix=f'{OUTPUT_PREFIX}.IpSet',
                          outputs_key_field='Id')


def get_ip_set_command(client: "WAFV2Client", args: dict) -> CommandResults:
    """ Command to get a specific IP set"""
    kwargs = {
        'Name': args.get('name', ''),
        'Scope': SCOPE_MAP[args.get('scope') or DEFAULT_SCOPE],
        'Id': args.get('id', '')
    }

    response = client.get_ip_set(**kwargs)

    outputs = response.get('IPSet', {})

    readable_output = tableToMarkdown('IP Set', outputs)

    return CommandResults(readable_output=readable_output,
                          outputs=outputs,
                          raw_response=response,
                          outputs_prefix=f'{OUTPUT_PREFIX}.IpSet',
                          outputs_key_field='Id')


def update_ip_set_command(client: "WAFV2Client", args: dict) -> CommandResults:
    """ Command to update a specific IP set"""
    kwargs = {
        'Name': args.get('name', ''),
        'Scope': SCOPE_MAP[args.get('scope') or DEFAULT_SCOPE],
        'Id': args.get('id', '')
    }

    addresses_to_update = argToList(args.get('addresses')) or []
    overwrite = argToBoolean(args.get('is_overwrite')) or False

    get_response = client.get_ip_set(**kwargs)

    lock_token = get_response.get('LockToken', '')
    original_addresses = get_response.get('IPSet', {}).get('Addresses', [])
    if not overwrite:
        addresses_to_update.extend(original_addresses)

    kwargs |= {'LockToken': lock_token, 'Addresses': addresses_to_update}

    if description := args.get('description'):
        kwargs |= {'Description': description}

    response = client.update_ip_set(**kwargs)

    readable_output = f'AWS Waf ip set with id {args.get("id", "")} was updated successfully.'

    return CommandResults(readable_output=readable_output,
                          raw_response=response)


def list_ip_set_command(client: "WAFV2Client", args: dict) -> CommandResults:
    """ Command to get a list of all IP sets"""
    kwargs: dict[str, Any] = {
        'Scope': SCOPE_MAP[args.get('scope') or DEFAULT_SCOPE],
        'Limit': arg_to_number(args.get('limit')) or 50
    }

    if next_marker := args.get('next_token'):
        kwargs |= {'NextMarker': next_marker}

    response = client.list_ip_sets(**kwargs)
    ip_sets = response.get('IPSets', [])
    readable_output = tableToMarkdown('List IP Sets',
                                      ip_sets,
                                      headers=['Name', 'Id', 'ARN', 'Description'],
                                      is_auto_json_transform=True)
    outputs = {f'{OUTPUT_PREFIX}.IpSet(val.Id === obj.Id)': ip_sets,
               f'{OUTPUT_PREFIX}(true)': {'IpSetNextToken': response.get('NextMarker', '')}}

    return CommandResults(readable_output=readable_output,
                          outputs=outputs,
                          raw_response=response,
                          outputs_key_field='Id')


def delete_ip_set_command(client: "WAFV2Client", args: dict) -> CommandResults:
    """ Command to delete a specific IP set"""
    kwargs = {
        'Name': args.get('name', ''),
        'Scope': SCOPE_MAP[args.get('scope') or DEFAULT_SCOPE],
        'Id': args.get('id', '')
    }

    get_response = client.get_ip_set(**kwargs)

    kwargs |= {'LockToken': get_response.get('LockToken', '')}

    response = client.delete_ip_set(**kwargs)

    readable_output = f'AWS Waf ip set with id {args.get("id", "")} was deleted successfully'

    return CommandResults(readable_output=readable_output,
                          raw_response=response)


def create_regex_set_command(client: "WAFV2Client", args: dict) -> CommandResults:
    """ Command to create a regex set"""
    tag_keys = argToList(args.get('tag_key')) or []
    tag_values = argToList(args.get('tag_value')) or []
    regex_patterns = argToList(args.get('regex_pattern')) or []
    kwargs = {
        'Name': args.get('name', ''),
        'Scope': SCOPE_MAP[args.get('scope') or DEFAULT_SCOPE],
        'RegularExpressionList': build_regex_pattern_object(regex_patterns)
    }

    if description := args.get('description'):
        kwargs |= {'Description': description}
    if tags := get_tags_dict_from_args(tag_keys, tag_values):
        kwargs |= {'Tags': tags}

    response = client.create_regex_pattern_set(**kwargs)
    outputs = response.get('Summary', {})

    readable_output = f'AWS Waf regex set with id {outputs.get("Id", "")} was created successfully'

    return CommandResults(readable_output=readable_output,
                          outputs=outputs,
                          raw_response=response,
                          outputs_prefix=f'{OUTPUT_PREFIX}.RegexSet',
                          outputs_key_field='Id')


def get_regex_set_command(client: "WAFV2Client", args: dict) -> CommandResults:
    """ Command to get a specific regex set"""
    kwargs = {
        'Name': args.get('name', ''),
        'Scope': SCOPE_MAP[args.get('scope') or DEFAULT_SCOPE],
        'Id': args.get('id', '')
    }

    response = client.get_regex_pattern_set(**kwargs)

    outputs = response.get('RegexPatternSet', {})

    readable_output = tableToMarkdown('Regex Set', outputs)

    return CommandResults(readable_output=readable_output,
                          outputs=outputs,
                          raw_response=response,
                          outputs_prefix=f'{OUTPUT_PREFIX}.RegexSet',
                          outputs_key_field='Id')


def update_regex_set_command(client: "WAFV2Client", args: dict) -> CommandResults:
    """ Command to update a specific regex set"""
    kwargs = {
        'Name': args.get('name', ''),
        'Scope': SCOPE_MAP[args.get('scope') or DEFAULT_SCOPE],
        'Id': args.get('id', '')
    }

    patterns_to_update = build_regex_pattern_object(argToList(args.get('regex_pattern')))
    overwrite = argToBoolean(args.get('is_overwrite')) or False

    get_response = client.get_regex_pattern_set(**kwargs)

    lock_token = get_response.get('LockToken', '')
    original_patterns = get_response.get('RegexPatternSet', {}).get('RegularExpressionList', [])
    if not overwrite:
        patterns_to_update.extend(original_patterns)

    kwargs |= {'LockToken': lock_token, 'RegularExpressionList': patterns_to_update}

    if description := args.get('description'):
        kwargs |= {'Description': description}

    response = client.update_regex_pattern_set(**kwargs)

    readable_output = f'AWS Waf ip set with id {args.get("Id", "")} was updated successfully.'

    return CommandResults(readable_output=readable_output,
                          raw_response=response)


def list_regex_set_command(client: "WAFV2Client", args: dict) -> CommandResults:
    """ Command to get a list of all regex sets"""
    kwargs: dict[str, Any] = {
        'Scope': SCOPE_MAP[args.get('scope') or DEFAULT_SCOPE],
        'Limit': arg_to_number(args.get('limit')) or 50
    }

    if next_marker := args.get('next_token'):
        kwargs |= {'NextMarker': next_marker}

    response = client.list_regex_pattern_sets(**kwargs)
    regex_patterns = response.get('RegexPatternSets', [])
    readable_output = tableToMarkdown('List regex Sets',
                                      regex_patterns,
                                      headers=['Name', 'Id', 'ARN', 'Description'],
                                      is_auto_json_transform=True)
    outputs = {f'{OUTPUT_PREFIX}.RegexSet(val.Id === obj.Id)': regex_patterns,
               f'{OUTPUT_PREFIX}(true)': {'RegexSetNextToken': response.get('NextMarker', '')}}

    return CommandResults(readable_output=readable_output,
                          outputs=outputs,
                          raw_response=response,
                          outputs_key_field='Id')


def delete_regex_set_command(client: "WAFV2Client", args: dict) -> CommandResults:
    """ Command to delete a specific regex set"""
    kwargs = {
        'Name': args.get('name', ''),
        'Scope': SCOPE_MAP[args.get('scope') or DEFAULT_SCOPE],
        'Id': args.get('id', '')
    }

    get_response = client.get_regex_pattern_set(**kwargs)

    kwargs |= {'LockToken': get_response.get('LockToken', '')}

    response = client.delete_regex_pattern_set(**kwargs)

    readable_output = f'AWS Waf regex set with id {args.get("id", "")} was deleted successfully'

    return CommandResults(readable_output=readable_output,
                          raw_response=response)


def list_rule_group_command(client: "WAFV2Client", args: dict) -> CommandResults:
    """ Command to get a list of all rule groups"""
    kwargs: dict[str, Any] = {
        'Scope': SCOPE_MAP[args.get('scope') or DEFAULT_SCOPE],
        'Limit': arg_to_number(args.get('limit')) or 50
    }

    if next_marker := args.get('next_token'):
        kwargs |= {'NextMarker': next_marker}

    response = client.list_rule_groups(**kwargs)
    rule_groups = response.get('RuleGroups', [])
    outputs = {f'{OUTPUT_PREFIX}.RuleGroup(val.Id === obj.Id)': rule_groups,
               f'{OUTPUT_PREFIX}(true)': {'RuleGroupNextToken': response.get('NextMarker', '')}}
    readable_output = tableToMarkdown('List rule groups',
                                      rule_groups,
                                      headers=['Name', 'Id', 'ARN', 'Description'],
                                      is_auto_json_transform=True)

    return CommandResults(readable_output=readable_output,
                          outputs=outputs,
                          raw_response=response,
                          outputs_key_field='Id')


def get_rule_group_command(client: "WAFV2Client", args: dict) -> CommandResults:
    """ Command to get a specific rule group"""
    kwargs = {
        'Name': args.get('name', ''),
        'Scope': SCOPE_MAP[args.get('scope') or DEFAULT_SCOPE],
        'Id': args.get('id', '')
    }

    response = client.get_rule_group(**kwargs)
    response = convert_dict_values_bytes_to_str(response)
    outputs = response.get('RuleGroup', {})
    readable_output = tableToMarkdown('Rule group', outputs, headers=['Id', 'Name', 'Description'])

    return CommandResults(readable_output=readable_output,
                          outputs=outputs,
                          raw_response=response,
                          outputs_prefix=f'{OUTPUT_PREFIX}.RuleGroup',
                          outputs_key_field='Id')


def delete_rule_group_command(client: "WAFV2Client", args: dict) -> CommandResults:
    """ Command to delete a specific rule group"""
    kwargs = {
        'Name': args.get('name', ''),
        'Scope': SCOPE_MAP[args.get('scope') or DEFAULT_SCOPE],
        'Id': args.get('id', '')
    }

    get_response = client.get_rule_group(**kwargs)

    kwargs |= {'LockToken': get_response.get('LockToken', '')}

    response = client.delete_rule_group(**kwargs)

    readable_output = f'AWS Waf rule group with id {args.get("id", "")} was deleted successfully'

    return CommandResults(readable_output=readable_output,
                          raw_response=response)


def create_rule_group_command(client: "WAFV2Client", args: dict) -> CommandResults:
    """ Command to create a rule group"""
    tag_keys = argToList(args.get('tag_key')) or []
    tag_values = argToList(args.get('tag_value')) or []
    name = args.get('name', '')
    cloud_watch_metrics_enabled = argToBoolean(args.get('cloud_watch_metrics_enabled', '')) or True
    metric_name = args.get('metric_name', '') or name
    sampled_requests_enabled = argToBoolean(args.get('sampled_requests_enabled', '')) or True

    kwargs = {
        'Name': name,
        'Scope': SCOPE_MAP[args.get('scope') or DEFAULT_SCOPE],
        'Capacity': arg_to_number(args.get('capacity', '')),
        'VisibilityConfig': build_visibility_config_object(cloud_watch_metrics_enabled=cloud_watch_metrics_enabled,
                                                           metric_name=metric_name,
                                                           sampled_requests_enabled=sampled_requests_enabled)
    }

    if description := args.get('description'):
        kwargs |= {'Description': description}
    if tags := get_tags_dict_from_args(tag_keys, tag_values):
        kwargs |= {'Tags': tags}

    response = client.create_rule_group(**kwargs)
    outputs = response.get('Summary', {})

    readable_output = f'AWS Waf rule group with id {outputs.get("Id", "")} was created successfully'

    return CommandResults(readable_output=readable_output,
                          outputs=outputs,
                          raw_response=response,
                          outputs_prefix=f'{OUTPUT_PREFIX}.RuleGroup',
                          outputs_key_field='Id')


def create_ip_rule_command(client: "WAFV2Client", args: dict) -> CommandResults:
    """ Command to create an ip rule"""
    kwargs = get_required_args_for_get_rule_group(args)

    rules, rule_group_visibility_config, lock_token = get_required_response_fields_from_rule_group(client, kwargs)

    rule = build_new_rule_object(args, rule_group_visibility_config, build_ip_rule_object)
    updated_rules = append_new_rule(rules, rule)

    response = update_rule_group_rules(client=client,
                                       kwargs=kwargs,
                                       lock_token=lock_token,
                                       updated_rules=updated_rules,
                                       rule_group_visibility_config=rule_group_visibility_config)

    readable_output = f'AWS Waf ip rule with name {args.get("rule_name", "")} was created successfully.'

    return CommandResults(readable_output=readable_output,
                          raw_response=response)


def create_country_rule_command(client: "WAFV2Client", args: dict) -> CommandResults:
    """ Command to create a country rule"""
    kwargs = get_required_args_for_get_rule_group(args)

    rules, rule_group_visibility_config, lock_token = get_required_response_fields_from_rule_group(client, kwargs)

    rule = build_new_rule_object(args, rule_group_visibility_config, build_country_rule_object)
    updated_rules = append_new_rule(rules, rule)

    response = update_rule_group_rules(client=client,
                                       kwargs=kwargs,
                                       lock_token=lock_token,
                                       updated_rules=updated_rules,
                                       rule_group_visibility_config=rule_group_visibility_config)

    readable_output = f'AWS Waf country rule with name {args.get("rule_name", "")} was created successfully.'

    return CommandResults(readable_output=readable_output,
                          raw_response=response)


def create_string_match_rule_command(client: "WAFV2Client", args: dict) -> CommandResults:
    """ Command to create a string match rule"""
    kwargs = get_required_args_for_get_rule_group(args)

    rules, rule_group_visibility_config, lock_token = get_required_response_fields_from_rule_group(client, kwargs)

    rule = build_new_rule_object(args, rule_group_visibility_config, build_string_match_rule_object)
    updated_rules = append_new_rule(rules, rule)

    response = update_rule_group_rules(client=client,
                                       kwargs=kwargs,
                                       lock_token=lock_token,
                                       updated_rules=updated_rules,
                                       rule_group_visibility_config=rule_group_visibility_config)

    readable_output = f'AWS Waf string match rule with name {args.get("rule_name", "")} was created successfully.'

    return CommandResults(readable_output=readable_output,
                          raw_response=response)


def delete_rule_command(client: "WAFV2Client", args: dict) -> CommandResults:
    """ Command to delete a specific rule"""
    kwargs = get_required_args_for_get_rule_group(args)

    rules, rule_group_visibility_config, lock_token = get_required_response_fields_from_rule_group(client, kwargs)
    rule_name = args.get('rule_name', '')
    updated_rules = delete_rule(rule_name, rules)

    response = update_rule_group_rules(client=client,
                                       kwargs=kwargs,
                                       lock_token=lock_token,
                                       updated_rules=updated_rules,
                                       rule_group_visibility_config=rule_group_visibility_config)

    readable_output = f'AWS Waf rule with id {args.get("Id", "")} was deleted successfully.'

    return CommandResults(readable_output=readable_output,
                          raw_response=response)


def add_ip_statement_command(client: "WAFV2Client", args: dict) -> CommandResults:
    """ Command to add an ip statement to a rule"""
    kwargs = get_required_args_for_get_rule_group(args)
    rules, rule_group_visibility_config, lock_token = get_required_response_fields_from_rule_group(client, kwargs)
    ip_set_arns = argToList(args.get('ip_set_arn'))
    statements = [build_ip_statement(ip_set_arn) for ip_set_arn in ip_set_arns]
    updated_rules = create_rules_list_with_new_rule_statement(args, statements, rules)

    response = update_rule_group_rules(client=client,
                                       kwargs=kwargs,
                                       lock_token=lock_token,
                                       updated_rules=updated_rules,
                                       rule_group_visibility_config=rule_group_visibility_config)

    readable_output = f'AWS Waf ip statement was added to rule with name {args.get("rule_name", "")} successfully.'

    return CommandResults(readable_output=readable_output,
                          raw_response=response)


def add_country_statement_command(client: "WAFV2Client", args: dict) -> CommandResults:
    """ Command to add a country statement to a rule"""
    kwargs = get_required_args_for_get_rule_group(args)

    rules, rule_group_visibility_config, lock_token = get_required_response_fields_from_rule_group(client, kwargs)
    country_codes = argToList(args.get('country_codes')) or []
    statement = [build_country_statement(country_codes)]
    updated_rules = create_rules_list_with_new_rule_statement(args, statement, rules)

    response = update_rule_group_rules(client=client,
                                       kwargs=kwargs,
                                       lock_token=lock_token,
                                       updated_rules=updated_rules,
                                       rule_group_visibility_config=rule_group_visibility_config)

    readable_output = f'AWS Waf country statement was added to rule with name {args.get("rule_name", "")} ' \
                      f'successfully.'

    return CommandResults(readable_output=readable_output,
                          raw_response=response)


def add_string_match_statement_command(client: "WAFV2Client", args: dict) -> CommandResults:
    """ Command to add a string match statement to a rule"""
    kwargs = get_required_args_for_get_rule_group(args)

    rules, rule_group_visibility_config, lock_token = get_required_response_fields_from_rule_group(client, kwargs)

    statement = [build_string_match_statement(**args)]
    updated_rules = create_rules_list_with_new_rule_statement(args, statement, rules)

    response = update_rule_group_rules(client=client,
                                       kwargs=kwargs,
                                       lock_token=lock_token,
                                       updated_rules=updated_rules,
                                       rule_group_visibility_config=rule_group_visibility_config)

    readable_output = f'AWS Waf string match statement was added to rule with name {args.get("rule_name", "")} ' \
                      f'successfully.'

    return CommandResults(readable_output=readable_output,
                          raw_response=response)


def add_json_statement_command(client: "WAFV2Client", args: dict) -> CommandResults:
    """ Command to add a json object represents a statement to a rule"""
    kwargs = get_required_args_for_get_rule_group(args)

    rules, rule_group_visibility_config, lock_token = get_required_response_fields_from_rule_group(client, kwargs)

    statement = json.loads(args.get('statement_json') or '{}')
    updated_rules = create_rules_list_with_new_rule_statement(args, statement, rules)

    response = update_rule_group_rules(client=client,
                                       kwargs=kwargs,
                                       lock_token=lock_token,
                                       updated_rules=updated_rules,
                                       rule_group_visibility_config=rule_group_visibility_config)

    readable_output = f'AWS Waf json statement was added to rule with name {args.get("rule_name", "")} successfully.'

    return CommandResults(readable_output=readable_output,
                          raw_response=response)


def template_json_command(args: dict) -> CommandResults:  # pragma: no cover
    """ Command to get a json template represents a statement"""
    statement_type = args.get('statement_type', '')
    web_request_component = args.get('web_request_component', '')
    if statement_type == 'Ip Set':
        readable_output = json.dumps(build_ip_statement(ip_set_arn='The Ip Set ARN'))

    elif statement_type == 'Country':
        readable_output = json.dumps(build_country_statement(country_codes=['country code1, country code2...']))

    else:
        if not web_request_component:
            raise DemistoException('Please provide web_request_component for string match and regex match ')
        web_request_component = WEB_REQUEST_COMPONENT_MAP[web_request_component]
        if statement_type == 'String Match':
            output = build_byte_match_statement(web_request_component=web_request_component,
                                                oversize_handling='CONTINUE | MATCH | NO_MATCH',
                                                text_transformation=TEXT_TRANSFORMATIONS,
                                                string_to_match='The string to match',
                                                match_type='all')
            match_statement = BYTE_MATCH_STATEMENT

        else:  # statement_type == 'Regex Pattern':
            output = build_regex_match_statement(web_request_component=web_request_component,
                                                 oversize_handling='CONTINUE | MATCH | NO_MATCH',
                                                 text_transformation=TEXT_TRANSFORMATIONS,
                                                 regex_set_arn="The regex set ARN")
            match_statement = REGEX_MATCH_STATEMENT

        statement = {match_statement: output}
        readable_output = json.dumps(statement)

    return CommandResults(readable_output=readable_output)


''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover
    params = demisto.params()
    aws_default_region = params.get('defaultRegion')
    aws_role_arn = params.get('roleArn')
    aws_role_session_name = params.get('roleSessionName')
    aws_role_session_duration = params.get('sessionDuration')
    aws_access_key_id = params.get('access_key', {}).get('password') or params.get('access_key')
    aws_secret_access_key = params.get('secret_key', {}).get('password') or params.get('secret_key')
    verify_certificate = not params.get('insecure', True)
    timeout = params.get('timeout') or 1
    retries = params.get('retries') or 5

    try:
        validate_params(aws_default_region, aws_role_arn, aws_role_session_name, aws_access_key_id,
                        aws_secret_access_key)

        aws_client = AWSClient(aws_default_region=aws_default_region,
                               aws_role_arn=aws_role_arn,
                               aws_role_session_name=aws_role_session_name,
                               aws_role_policy=None,
                               aws_role_session_duration=aws_role_session_duration,
                               aws_access_key_id=aws_access_key_id,
                               aws_secret_access_key=aws_secret_access_key,
                               verify_certificate=verify_certificate,
                               timeout=timeout,
                               retries=retries)
        args = demisto.args()
        command = demisto.command()
        client: WAFV2Client = aws_client.aws_session(service=SERVICE, region=args.get('region'))
        result = CommandResults()

        if command == 'test-module':
            # This is the call made when pressing the integration test button.
            return_results(connection_test(client))

        elif command == 'aws-waf-ip-set-create':
            result = create_ip_set_command(client, args)
        elif command == 'aws-waf-ip-set-get':
            result = get_ip_set_command(client, args)
        elif command == 'aws-waf-ip-set-update':
            result = update_ip_set_command(client, args)
        elif command == 'aws-waf-ip-set-list':
            result = list_ip_set_command(client, args)
        elif command == 'aws-waf-ip-set-delete':
            result = delete_ip_set_command(client, args)

        elif command == 'aws-waf-regex-set-create':
            result = create_regex_set_command(client, args)
        elif command == 'aws-waf-regex-set-get':
            result = get_regex_set_command(client, args)
        elif command == 'aws-waf-regex-set-update':
            result = update_regex_set_command(client, args)
        elif command == 'aws-waf-regex-set-list':
            result = list_regex_set_command(client, args)
        elif command == 'aws-waf-regex-set-delete':
            result = delete_regex_set_command(client, args)

        elif command == 'aws-waf-rule-group-list':
            result = list_rule_group_command(client, args)
        elif command == 'aws-waf-rule-group-get':
            result = get_rule_group_command(client, args)
        elif command == 'aws-waf-rule-group-delete':
            result = delete_rule_group_command(client, args)
        elif command == 'aws-waf-rule-group-create':
            result = create_rule_group_command(client, args)

        elif command == 'aws-waf-ip-rule-create':
            result = create_ip_rule_command(client, args)
        elif command == 'aws-waf-country-rule-create':
            result = create_country_rule_command(client, args)
        elif command == 'aws-waf-string-match-rule-create':
            result = create_string_match_rule_command(client, args)
        elif command == 'aws-waf-rule-delete':
            result = delete_rule_command(client, args)

        elif command == 'aws-waf-ip-statement-add':
            result = add_ip_statement_command(client, args)
        elif command == 'aws-waf-country-statement-add':
            result = add_country_statement_command(client, args)
        elif command == 'aws-waf-string-match-statement-add':
            result = add_string_match_statement_command(client, args)
        elif command == 'aws-waf-statement-json-add':
            result = add_json_statement_command(client, args)

        elif command == 'aws-waf-statement-json-template-get':
            result = template_json_command(args)

        else:
            raise NotImplementedError(f'Command {command} is not implemented in AWS WAF integration.')

        return_results(result)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
