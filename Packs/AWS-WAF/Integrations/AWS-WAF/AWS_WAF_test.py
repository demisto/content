import json
import io
from CommonServerPython import *
import pytest
from AWS_WAF import OPERATOR_TO_STATEMENT_OPERATOR


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
