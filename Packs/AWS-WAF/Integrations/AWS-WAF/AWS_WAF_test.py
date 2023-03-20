import json
import io
from CommonServerPython import *
import pytest
from AWS_WAF import OPERATOR_TO_STATEMENT_OPERATOR


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


def util_load_json(path):
    with io.open(f'test_data/{path}.json', mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_get_tags_dict_from_args():
    from AWS_WAF import get_tags_dict_from_args
    tag_keys = ['tag1', 'tag2']
    tag_values = ['value1', 'value2']
    result = get_tags_dict_from_args(tag_keys=tag_keys, tag_values=tag_values)
    assert len(result) == 2


def test_get_tags_dict_from_args_raise_exception():
    from AWS_WAF import get_tags_dict_from_args
    tag_keys = ['tag1']
    tag_values = ['value1', 'value2']
    with pytest.raises(DemistoException):
        get_tags_dict_from_args(tag_keys=tag_keys, tag_values=tag_values)


def test_build_regex_pattern_object():
    from AWS_WAF import build_regex_pattern_object
    regex_patterns = ["pattern1", "pattern2"]
    result = build_regex_pattern_object(regex_patterns=regex_patterns)
    assert len(result) == 2


IP_ARN_LIST = ['pi_arn', 'ip_arn']
AND_CONDITION_OPERATOR = 'And'
OR_CONDITION_OPERATOR = 'Or'


@pytest.mark.parametrize('args, expected_result',
                         [({'ip_set_arn': IP_ARN_LIST[:1]},
                           'IPSetReferenceStatement'),
                          ({'ip_set_arn': IP_ARN_LIST, 'condition_operator': AND_CONDITION_OPERATOR},
                           OPERATOR_TO_STATEMENT_OPERATOR[AND_CONDITION_OPERATOR])])
def test_build_ip_rule_object(args, expected_result):
    from AWS_WAF import build_ip_rule_object
    ip_rule = build_ip_rule_object(args=args)
    assert expected_result in ip_rule['Statement']


@pytest.mark.parametrize('ip_set_arn, expected_type',
                         [(IP_ARN_LIST[:1], dict),
                          (IP_ARN_LIST, list)])
def test_build_ip_statement(ip_set_arn, expected_type):
    from AWS_WAF import build_ip_statement
    statement = build_ip_statement(ip_set_arn=ip_set_arn)
    assert type(statement) == expected_type


@pytest.mark.parametrize('rule_file, statement_condition',
                         [('rule_one_statement', OPERATOR_TO_STATEMENT_OPERATOR[AND_CONDITION_OPERATOR]),
                          ('rule_two_statements', OPERATOR_TO_STATEMENT_OPERATOR[OR_CONDITION_OPERATOR])])
def test_update_rule_with_statement(rule_file, statement_condition):
    from AWS_WAF import update_rule_with_statement
    rule = util_load_json(rule_file)
    statement = {"IPSetReferenceStatement": {
        "ARN": "ip_arn"
    }}
    update_rule_with_statement(rule=rule, statement=statement, condition_operator=AND_CONDITION_OPERATOR)
    assert statement_condition in rule['Statement']


def test_add_statement_to_rule(mocker):
    from AWS_WAF import add_statement_to_rule
    rules = util_load_json('rule_group').get('RuleGroup').get('Rules')
    args = {'rule_name': 'test_1'}
    res = mocker.patch('AWS_WAF.update_rule_with_statement')
    add_statement_to_rule(args=args, statement={}, rules=rules)
    assert res.call_count == 1


@pytest.mark.parametrize('web_request_component, oversize_handling, expected_result',
                         [('Cookies', 'CONTINUE',
                           {'MatchPattern': {'All': {}}, 'MatchScope': 'ALL', 'OversizeHandling': 'CONTINUE'}),
                          ('UriPath', None,
                           {}),
                          ('Body', 'CONTINUE', {'OversizeHandling': 'CONTINUE'})])
def test_build_web_component_match_object(web_request_component, oversize_handling, expected_result):
    from AWS_WAF import build_web_component_match_object
    web_request_component_object = build_web_component_match_object(web_request_component, oversize_handling)
    assert web_request_component_object == expected_result


def test_delete_rule():
    from AWS_WAF import delete_rule
    original_rules = util_load_json('rule_group').get('RuleGroup').get('Rules')
    deleted_rules = delete_rule(rule_name='test_1', rules=original_rules)
    assert len(original_rules) == len(deleted_rules) + 1


def test_append_new_rule():
    from AWS_WAF import append_new_rule
    original_rules = util_load_json('rule_group').get('RuleGroup').get('Rules')
    rule = util_load_json('rule_one_statement')
    updated_rules = append_new_rule(rule=rule, rules=original_rules)
    assert len(original_rules) == len(updated_rules) - 1


'''COMMANDS TESTS'''


def test_create_ip_set_command(mocker):
    from AWS_WAF import create_ip_set_command
    client = MockedBoto3Client()
    create_ip_set_args = {'name': 'name', 'scope': 'Regional', 'ip_version': 'IPV4', 'addresses': []}
    create_ip_set_mock = mocker.patch.object(client, 'create_ip_set')
    create_ip_set_command(client=client, args=create_ip_set_args)
    create_ip_set_mock.assert_called_with(Name='name', Scope='REGIONAL', IPAddressVersion='IPV4', Addresses=[])


def test_get_ip_set_command(mocker):
    from AWS_WAF import get_ip_set_command
    client = MockedBoto3Client()
    get_ip_set_args = {'name': 'name', 'scope': 'Regional', 'id': 'id'}
    get_ip_set_mock = mocker.patch.object(client, 'get_ip_set')
    get_ip_set_command(client=client, args=get_ip_set_args)
    get_ip_set_mock.assert_called_with(Name='name', Scope='REGIONAL', Id='id')


@pytest.mark.parametrize('is_overwrite, updated_addresses',
                         [(True, ['1.1.1.2/32']), (False, ['1.1.1.2/32', '1.1.2.2/32'])])
def test_update_ip_set_command(mocker, is_overwrite, updated_addresses):
    from AWS_WAF import update_ip_set_command
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
    from AWS_WAF import list_ip_set_command
    client = MockedBoto3Client()
    list_ip_set_args = {'scope': 'Regional'}
    list_ip_sets_mock = mocker.patch.object(client, 'list_ip_sets')
    list_ip_set_command(client=client, args=list_ip_set_args)
    list_ip_sets_mock.assert_called_with(Scope='REGIONAL', Limit=50)


def test_delete_ip_set_command(mocker):
    from AWS_WAF import delete_ip_set_command
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
    from AWS_WAF import create_regex_set_command
    client = MockedBoto3Client()
    create_regex_set_args = {'name': 'name', 'scope': 'Regional', 'regex_pattern': 'regex_pattern'}
    create_regex_set_mock = mocker.patch.object(client, 'create_regex_pattern_set')
    create_regex_set_command(client=client, args=create_regex_set_args)
    create_regex_set_mock.assert_called_with(Name='name',
                                             Scope='REGIONAL',
                                             RegularExpressionList=[{'RegexString': 'regex_pattern'}])


def test_get_regex_set_command(mocker):
    from AWS_WAF import get_regex_set_command
    client = MockedBoto3Client()
    get_regex_set_args = {'name': 'name', 'scope': 'Regional', 'id': 'id'}
    get_regex_set_mock = mocker.patch.object(client, 'get_regex_pattern_set')
    get_regex_set_command(client=client, args=get_regex_set_args)
    get_regex_set_mock.assert_called_with(Name='name', Scope='REGIONAL', Id='id')


@pytest.mark.parametrize('is_overwrite, updated_regex_list',
                         [(True, [{"RegexString": "regex_pattern1"}]),
                          (False, [{"RegexString": "regex_pattern1"}, {"RegexString": "regex_pattern"}])])
def test_update_regex_set_command(mocker, is_overwrite, updated_regex_list):
    from AWS_WAF import update_regex_set_command
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
    from AWS_WAF import list_regex_set_command
    client = MockedBoto3Client()
    list_regex_set_args = {'scope': 'Regional'}
    list_regex_sets_mock = mocker.patch.object(client, 'list_regex_pattern_sets')
    list_regex_set_command(client=client, args=list_regex_set_args)
    list_regex_sets_mock.assert_called_with(Scope='REGIONAL', Limit=50)


def test_delete_regex_set_command(mocker):
    from AWS_WAF import delete_regex_set_command
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
