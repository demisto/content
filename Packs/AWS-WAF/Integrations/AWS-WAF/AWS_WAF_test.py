import json
import io
from CommonServerPython import *
import pytest


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
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
CONDITION_OPERATOR = 'And'


@pytest.mark.parametrize('args, expected_result',
                         [({'ip_set_arn': IP_ARN_LIST[:1]}, 'IPSetReferenceStatement'),
                          ({'ip_set_arn': IP_ARN_LIST, 'condition_operator': CONDITION_OPERATOR}, 'AndStatement')])
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




