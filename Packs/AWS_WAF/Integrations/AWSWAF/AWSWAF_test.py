import json
import io
from CommonServerPython import *
import pytest
from AWSWAF import OPERATOR_TO_STATEMENT_OPERATOR, REGEX_MATCH_STATEMENT, BYTE_MATCH_STATEMENT

IP_ARN_LIST = ['ip_arn', 'ip_arn1']
AND_CONDITION_OPERATOR = 'And'
OR_CONDITION_OPERATOR = 'Or'


class MockedBoto3Client:
    """Mocked AWSClient session for easier expectation settings."""

    def create_ip_set(self, **kwargs):
        pass

    def get_ip_set(self, **kwargs):
        pass

    def update_ip_set(self, **kwargs):
        pass

    def list_ip_sets(self, **kwargs):
        pass

    def delete_ip_set(self, **kwargs):
        pass

    def create_regex_pattern_set(self, **kwargs):
        pass

    def get_regex_pattern_set(self, **kwargs):
        pass

    def update_regex_pattern_set(self, **kwargs):
        pass

    def list_regex_pattern_sets(self, **kwargs):
        pass

    def delete_regex_pattern_set(self, **kwargs):
        pass

    def create_rule_group(self, **kwargs):
        pass

    def get_rule_group(self, **kwargs):
        pass

    def list_rule_groups(self, **kwargs):
        pass

    def delete_rule_group(self, **kwargs):
        pass


def util_load_json(path):
    with io.open(f'test_data/{path}.json', mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_get_tags_dict_from_args():
    """
    Given:
        tags keys and tags values lists of same length

    When:
        Creating tags for create commands

    Then:
        assert tags list has same length as the tags and values lists
    """
    from AWSWAF import get_tags_dict_from_args
    tag_keys = ['tag1', 'tag2']
    tag_values = ['value1', 'value2']
    result = get_tags_dict_from_args(tag_keys=tag_keys, tag_values=tag_values)
    assert len(result) == 2


def test_get_tags_dict_from_args_raise_exception():
    """
    Given:
        tags keys and tags values lists  of different lengths

    When:
        Creating tags for create commands

    Then:
        assert exception wis raised
    """
    from AWSWAF import get_tags_dict_from_args
    tag_keys = ['tag1']
    tag_values = ['value1', 'value2']
    with pytest.raises(DemistoException):
        get_tags_dict_from_args(tag_keys=tag_keys, tag_values=tag_values)


def test_build_regex_pattern_object():
    """
    Given:
        Regex patterns list

    When:
        Creating regex pattern object

    Then:
        assert object was being created correctly
    """
    from AWSWAF import build_regex_pattern_object
    regex_patterns = ["pattern1", "pattern2"]
    result = build_regex_pattern_object(regex_patterns=regex_patterns)
    assert len(result) == 2


@pytest.mark.parametrize('args, expected_result',
                         [({'ip_set_arn': IP_ARN_LIST[:1]},
                           'IPSetReferenceStatement'),
                          ({'ip_set_arn': IP_ARN_LIST, 'condition_operator': AND_CONDITION_OPERATOR},
                           OPERATOR_TO_STATEMENT_OPERATOR[AND_CONDITION_OPERATOR])])
def test_build_ip_rule_object(args, expected_result):
    """
    Given:
        IP sets arns

    When:
        Creating a new rule object

    Then:
        assert object['Statement'] contains one statement object
        assert object['Statement'] contains statement operator
    """
    from AWSWAF import build_ip_rule_object
    ip_rule = build_ip_rule_object(args=args)
    assert expected_result in ip_rule['Statement']


@pytest.mark.parametrize('rule_file, statement_condition, statements',
                         [('rule_one_statement',
                           OPERATOR_TO_STATEMENT_OPERATOR[AND_CONDITION_OPERATOR],
                           [{"IPSetReferenceStatement": {
                               "ARN": "ip_arn"
                           }}]),
                          ('rule_two_statements',
                           OPERATOR_TO_STATEMENT_OPERATOR[OR_CONDITION_OPERATOR],
                           [{"IPSetReferenceStatement": {
                               "ARN": "ip_arn"
                           }}, {"IPSetReferenceStatement": {
                               "ARN": "ip_arn1"
                           }}])])
def test_update_rule_with_statement(rule_file, statement_condition, statements):
    """
    Given:
        Rule statements

    When:
        Updating an existing rule with a statement

    Then:
        assert object['Statement'] contains the given condition operator
        assert object['Statement'] contains the existing condition operator
    """
    from AWSWAF import update_rule_with_statement
    rule = util_load_json(rule_file)
    update_rule_with_statement(rule=rule, statements=statements, condition_operator=AND_CONDITION_OPERATOR)
    assert statement_condition in rule['Statement']


def test_create_rules_list_with_new_rule_statement(mocker):
    """
    Given:
        Rule name to update

    When:
        Updating an existing rule with a statement

    Then:
        assert updating happens to the correct rule
    """
    from AWSWAF import create_rules_list_with_new_rule_statement
    rules = util_load_json('rule_group').get('RuleGroup').get('Rules')
    args = {'rule_name': 'test_1'}
    res = mocker.patch('AWSWAF.update_rule_with_statement')
    create_rules_list_with_new_rule_statement(args=args, statements=[{}], rules=rules)
    assert res.call_count == 1


@pytest.mark.parametrize('match_type, regex_set_arn, string_to_match, expected_exception',
                         [('Exactly Matches String', 'regex_arn', None, 'string_to_match must be provided'),
                          ('Matches Regex Pattern Set', None, 'str_to_match', 'regex_set_arn must be provided')])
def test_build_string_match_statement_raise_exception(match_type, regex_set_arn, string_to_match, expected_exception):
    """
    Given:
        String match statement related parameters

    When:
        Creating a string match statement

    Then:
        assert exception is raised when wrong parameters are provided
    """
    from AWSWAF import build_string_match_statement
    with pytest.raises(DemistoException) as e:
        build_string_match_statement(match_type=match_type)
        assert expected_exception in str(e)


@pytest.mark.parametrize('match_type, string_to_match, regex_set_arn, oversize_handling, '
                         'text_transformation, web_request_component, expected_result, match_statement',
                         [('Exactly Matches String', 'str_to_match', None, 'CONTINUE', 'NONE', 'Body',
                           'SearchString', BYTE_MATCH_STATEMENT),
                          ('Matches Regex Pattern Set', None, 'regex_arn', None, None, 'UriPath',
                           'ARN', REGEX_MATCH_STATEMENT)])
def test_build_string_match_statement(match_type,
                                      string_to_match,
                                      regex_set_arn,
                                      oversize_handling,
                                      text_transformation,
                                      web_request_component,
                                      expected_result,
                                      match_statement):
    """
    Given:
        String match statement related parameters

    When:
        Creating a string match statement

    Then:
        assert the created object matches the match type
    """
    from AWSWAF import build_string_match_statement
    statement = build_string_match_statement(match_type,
                                             string_to_match,
                                             regex_set_arn,
                                             oversize_handling,
                                             text_transformation,
                                             web_request_component)
    assert expected_result in statement[match_statement]


@pytest.mark.parametrize('web_request_component, oversize_handling, expected_result',
                         [('Cookies', 'CONTINUE',
                           {'MatchPattern': {'All': {}}, 'MatchScope': 'ALL', 'OversizeHandling': 'CONTINUE'}),
                          ('UriPath', None,
                           {}),
                          ('Body', 'CONTINUE', {'OversizeHandling': 'CONTINUE'})])
def test_build_web_component_match_object(web_request_component, oversize_handling, expected_result):
    """
    Given:
        web_request_component, oversize_handling

    When:
        Creating a web component object

    Then:
        assert that oversize_handling exists for the relevant web components
        assert that match pattern exists for the relevant web components
    """
    from AWSWAF import build_web_component_match_object
    web_request_component_object = build_web_component_match_object(web_request_component, oversize_handling)
    assert web_request_component_object == expected_result


def test_delete_rule():
    """
    Given:
        Rules list and rule to delete

    When:
        Deleting a rule

    Then:
        assert rule has been deleted
    """
    from AWSWAF import delete_rule
    original_rules = util_load_json('rule_group').get('RuleGroup').get('Rules')
    deleted_rules = delete_rule(rule_name='test_1', rules=original_rules)
    assert len(original_rules) == len(deleted_rules) + 1


def test_append_new_rule():
    """
    Given:
        Rules list and rule to add

    When:
        Creating a rule

    Then:
        assert rule has been created and appended
    """
    from AWSWAF import append_new_rule
    original_rules = util_load_json('rule_group').get('RuleGroup').get('Rules')
    rule = util_load_json('rule_one_statement')
    updated_rules = append_new_rule(rule=rule, rules=original_rules)
    assert len(original_rules) == len(updated_rules) - 1


'''COMMANDS TESTS'''


def test_create_ip_set_command(mocker):
    """
    Given:
        Command arguments

    When:
        Creating ip set

    Then:
        assert api request was called with the required parameters
    """
    from AWSWAF import create_ip_set_command
    client = MockedBoto3Client()
    create_ip_set_args = {'name': 'name', 'scope': 'Regional', 'ip_version': 'IPV4', 'addresses': []}
    create_ip_set_mock = mocker.patch.object(client, 'create_ip_set')
    create_ip_set_command(client=client, args=create_ip_set_args)
    create_ip_set_mock.assert_called_with(Name='name', Scope='REGIONAL', IPAddressVersion='IPV4', Addresses=[])


def test_get_ip_set_command(mocker):
    """
    Given:
        Command arguments

    When:
        Getting ip set

    Then:
        assert api request was called with the required parameters
    """
    from AWSWAF import get_ip_set_command
    client = MockedBoto3Client()
    get_ip_set_args = {'name': 'name', 'scope': 'Regional', 'id': 'id'}
    get_ip_set_mock = mocker.patch.object(client, 'get_ip_set')
    get_ip_set_command(client=client, args=get_ip_set_args)
    get_ip_set_mock.assert_called_with(Name='name', Scope='REGIONAL', Id='id')


@pytest.mark.parametrize('is_overwrite, updated_addresses',
                         [(True, ['1.1.1.2/32']), (False, ['1.1.1.2/32', '1.1.2.2/32'])])
def test_update_ip_set_command(mocker, is_overwrite, updated_addresses):
    """
    Given:
        Command arguments

    When:
        Updating ip set

    Then:
        assert api request was called with the required parameters
        assert the addresses list is updated according to overwrite argument
    """
    from AWSWAF import update_ip_set_command
    client = MockedBoto3Client()
    update_ip_set_args = {'name': 'name', 'scope': 'Regional', 'ip_version': 'IPV4',
                          'addresses': '1.1.1.2/32', 'is_overwrite': is_overwrite, 'id': 'id'}
    get_ip_set_response = util_load_json('get_ip_set_response')
    mocker.patch.object(client, 'get_ip_set', return_value=get_ip_set_response)
    update_ip_set_mock = mocker.patch.object(client, 'update_ip_set')
    update_ip_set_command(client=client, args=update_ip_set_args)
    update_ip_set_mock.assert_called_with(Name='name',
                                          Id='id',
                                          Scope='REGIONAL',
                                          LockToken='lockToken',
                                          Addresses=updated_addresses)


def test_list_ip_set_command(mocker):
    """
    Given:
        Command arguments

    When:
        Listing ip sets

    Then:
        assert api request was called with the required parameters
    """
    from AWSWAF import list_ip_set_command
    client = MockedBoto3Client()
    list_ip_set_args = {'scope': 'Regional'}
    list_ip_sets_mock = mocker.patch.object(client, 'list_ip_sets')
    list_ip_set_command(client=client, args=list_ip_set_args)
    list_ip_sets_mock.assert_called_with(Scope='REGIONAL', Limit=50)


def test_delete_ip_set_command(mocker):
    """
    Given:
        Command arguments

    When:
        Deleting ip set

    Then:
        assert api request was called with the required parameters
    """
    from AWSWAF import delete_ip_set_command
    client = MockedBoto3Client()
    delete_ip_set_args = {'name': 'name', 'scope': 'Regional', 'id': 'id'}
    get_ip_set_response = util_load_json('get_ip_set_response')
    mocker.patch.object(client, 'get_ip_set', return_value=get_ip_set_response)
    delete_ip_set_mock = mocker.patch.object(client, 'delete_ip_set')
    delete_ip_set_command(client=client, args=delete_ip_set_args)
    delete_ip_set_mock.assert_called_with(Name='name',
                                          Id='id',
                                          Scope='REGIONAL',
                                          LockToken='lockToken')


def test_create_regex_set_command(mocker):
    """
    Given:
        Command arguments

    When:
        Creating regex patterns set

    Then:
        assert api request was called with the required parameters
    """
    from AWSWAF import create_regex_set_command
    client = MockedBoto3Client()
    create_regex_set_args = {'name': 'name', 'scope': 'Regional', 'regex_pattern': 'regex_pattern'}
    create_regex_set_mock = mocker.patch.object(client, 'create_regex_pattern_set')
    create_regex_set_command(client=client, args=create_regex_set_args)
    create_regex_set_mock.assert_called_with(Name='name',
                                             Scope='REGIONAL',
                                             RegularExpressionList=[{'RegexString': 'regex_pattern'}])


def test_get_regex_set_command(mocker):
    """
    Given:
        Command arguments

    When:
        Getting regex patterns set

    Then:
        assert api request was called with the required parameters
    """
    from AWSWAF import get_regex_set_command
    client = MockedBoto3Client()
    get_regex_set_args = {'name': 'name', 'scope': 'Regional', 'id': 'id'}
    get_regex_set_mock = mocker.patch.object(client, 'get_regex_pattern_set')
    get_regex_set_command(client=client, args=get_regex_set_args)
    get_regex_set_mock.assert_called_with(Name='name', Scope='REGIONAL', Id='id')


@pytest.mark.parametrize('is_overwrite, updated_regex_list',
                         [(True, [{"RegexString": "regex_pattern1"}]),
                          (False, [{"RegexString": "regex_pattern1"}, {"RegexString": "regex_pattern"}])])
def test_update_regex_set_command(mocker, is_overwrite, updated_regex_list):
    """
    Given:
        Command arguments

    When:
        Updating regex patterns set

    Then:
        assert api request was called with the required parameters
        assert regex patterns list was updated according to the overwrite parameter
    """
    from AWSWAF import update_regex_set_command
    client = MockedBoto3Client()
    update_regex_set_args = {'name': 'name', 'scope': 'Regional', 'regex_pattern': 'regex_pattern1',
                             'is_overwrite': is_overwrite, 'id': 'id'}
    get_regex_set_response = util_load_json('get_regex_set_response')
    mocker.patch.object(client, 'get_regex_pattern_set', return_value=get_regex_set_response)
    update_regex_set_mock = mocker.patch.object(client, 'update_regex_pattern_set')
    update_regex_set_command(client=client, args=update_regex_set_args)
    update_regex_set_mock.assert_called_with(Name='name',
                                             Id='id',
                                             Scope='REGIONAL',
                                             LockToken='lockToken',
                                             RegularExpressionList=updated_regex_list)


def test_list_regex_set_command(mocker):
    """
    Given:
        Command arguments

    When:
        Listing regex patterns set

    Then:
        assert api request was called with the required parameters
    """
    from AWSWAF import list_regex_set_command
    client = MockedBoto3Client()
    list_regex_set_args = {'scope': 'Regional'}
    list_regex_sets_mock = mocker.patch.object(client, 'list_regex_pattern_sets')
    list_regex_set_command(client=client, args=list_regex_set_args)
    list_regex_sets_mock.assert_called_with(Scope='REGIONAL', Limit=50)


def test_delete_regex_set_command(mocker):
    """
    Given:
        Command arguments

    When:
        Deleting regex patterns set

    Then:
        assert api request was called with the required parameters
    """
    from AWSWAF import delete_regex_set_command
    client = MockedBoto3Client()
    delete_regex_set_args = {'name': 'name', 'scope': 'Regional', 'id': 'id'}
    get_regex_set_response = util_load_json('get_regex_set_response')
    mocker.patch.object(client, 'get_regex_pattern_set', return_value=get_regex_set_response)
    delete_regex_set_mock = mocker.patch.object(client, 'delete_regex_pattern_set')
    delete_regex_set_command(client=client, args=delete_regex_set_args)
    delete_regex_set_mock.assert_called_with(Name='name',
                                             Id='id',
                                             Scope='REGIONAL',
                                             LockToken='lockToken')


def test_list_rule_group_command(mocker):
    """
    Given:
        Command arguments

    When:
        Listing rule group

    Then:
        assert api request was called with the required parameters
    """
    from AWSWAF import list_rule_group_command
    client = MockedBoto3Client()
    list_rule_group_args = {'scope': 'Regional'}
    list_rule_group_mock = mocker.patch.object(client, 'list_rule_groups')
    list_rule_group_command(client=client, args=list_rule_group_args)
    list_rule_group_mock.assert_called_with(Scope='REGIONAL', Limit=50)


def test_get_rule_group_command(mocker):
    """
    Given:
        Command arguments

    When:
        Getting rule group

    Then:
        assert api request was called with the required parameters
    """
    from AWSWAF import get_rule_group_command
    client = MockedBoto3Client()
    get_rule_group_args = {'name': 'name', 'scope': 'Regional', 'id': 'id'}
    get_rule_group_mock = mocker.patch.object(client, 'get_rule_group')
    get_rule_group_command(client=client, args=get_rule_group_args)
    get_rule_group_mock.assert_called_with(Name='name', Scope='REGIONAL', Id='id')


def test_create_rule_group_command(mocker):
    """
    Given:
        Command arguments

    When:
        Creating rule group

    Then:
        assert api request was called with the required parameters
    """
    from AWSWAF import create_rule_group_command
    client = MockedBoto3Client()
    create_rule_group_args = {'name': 'name',
                              'scope': 'Regional',
                              'capacity': 100,
                              'cloud_watch_metrics_enabled': True,
                              'sampled_requests_enabled': True}
    expected_visibility_config = {
        'CloudWatchMetricsEnabled': True,
        'MetricName': 'name',
        'SampledRequestsEnabled': True
    }
    create_rule_group_mock = mocker.patch.object(client, 'create_rule_group')
    create_rule_group_command(client=client, args=create_rule_group_args)
    create_rule_group_mock.assert_called_with(Name='name',
                                              Scope='REGIONAL',
                                              Capacity=100,
                                              VisibilityConfig=expected_visibility_config)


def test_delete_rule_group_command(mocker):
    """
    Given:
        Command arguments

    When:
        Deleting rule group

    Then:
        assert api request was called with the required parameters
    """
    from AWSWAF import delete_rule_group_command
    client = MockedBoto3Client()
    delete_rule_group_args = {'name': 'name', 'scope': 'Regional', 'id': 'id'}
    get_rule_group_response = util_load_json('rule_group')
    mocker.patch.object(client, 'get_rule_group', return_value=get_rule_group_response)
    delete_rule_group_mock = mocker.patch.object(client, 'delete_rule_group')
    delete_rule_group_command(client=client, args=delete_rule_group_args)
    delete_rule_group_mock.assert_called_with(Name='name',
                                              Id='id',
                                              Scope='REGIONAL',
                                              LockToken='lockToken')
