import json
import io
import pytest
import demistomock as demisto
from CommonServerPython import DemistoException


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.mark.parametrize('args, indicators_types, expected_result', [
    ({"domain_indicator_type": 'spam_domain',
      "domain_values": 'my.domain1.com',
      "email_indicator_type": 'spam_email',
      "email_values": 'test@test.com',
      "ip_indicator_type": 'actor_ip',
      "ip_values": '1.1.1.1',
      "md5_indicator_type": 'phish_md5',
      "md5_values": '00000000000000000000000000000000',
      "url_indicator_type": 'parked_url',
      "url_values": 'https://test.com'},
     {'email': 'spam_email', 'md5': 'phish_md5', 'ip': 'actor_ip', 'url': 'parked_url', 'domain': 'spam_domain'},
     [{'value': 'test@test.com', 'itype': 'spam_email'},
      {'value': '00000000000000000000000000000000', 'itype': 'phish_md5'},
      {'value': '1.1.1.1', 'itype': 'actor_ip'},
      {'value': 'https://test.com', 'itype': 'parked_url'},
      {'value': 'my.domain1.com', 'itype': 'spam_domain'}]),
    ({"domain_values": 'my.domain1.com',
      "email_values": 'test@test.com',
      "ip_values": '1.1.1.1',
      "md5_values": '00000000000000000000000000000000',
      "url_values": 'https://test.com'},
     {'email': 'mal_email', 'md5': 'mal_md5', 'ip': 'mal_ip', 'url': 'mal_url', 'domain': 'mal_domain'},
     [{'value': 'test@test.com', 'itype': 'mal_email'},
      {'value': '00000000000000000000000000000000', 'itype': 'mal_md5'},
      {'value': '1.1.1.1', 'itype': 'mal_ip'},
      {'value': 'https://test.com', 'itype': 'mal_url'},
      {'value': 'my.domain1.com', 'itype': 'mal_domain'}])
])
def test_get_indicators_from_user(args, indicators_types, expected_result):
    """Tests get_indicators_from_user function.

    Checks the output of the command function with the expected output.
    """
    from ThreatstreamBuildIocImportJson import get_indicators_from_user
    response = get_indicators_from_user(args, indicators_types)
    assert response == expected_result


@pytest.mark.parametrize('email_list, md5_list, ip_list, url_list, domain_list, expected_result', [
    (['email'], [], [], [], [], 'Invalid indicators values: email'),
    ([], ['111'], [], [], [], 'Invalid indicators values: 111'),
    ([], [], ['1.1'], [], [], 'Invalid indicators values: 1.1'),
    ([], [], [], ['url'], [], 'Invalid indicators values: url'),
    ([], [], [], [], ['domain'], 'Invalid indicators values: domain'),
])
def test_validate_indicators(email_list, md5_list, ip_list, url_list, domain_list, expected_result):
    """Tests validate_indicators function.

    Checks that an error message raised.
    """
    from ThreatstreamBuildIocImportJson import validate_indicators
    with pytest.raises(DemistoException) as de:
        validate_indicators(email_list, md5_list, ip_list, url_list, domain_list)

    assert de.value.message == expected_result


@pytest.mark.parametrize('query, indicators_types, return_value, expected_result', [
    ('type:(IP Domain)', {'email': 'mal_email', 'md5': 'mal_md5', 'ip': 'mal_ip', 'url': 'mal_url', 'domain': 'mal_domain'},
     [{'ModuleName': 'name', 'Brand': 'Scripts', 'Category': 'automation', 'ID': '', 'Version': 0, 'Type': 3,
       'Contents': [{'id': '1', 'indicator_type': 'IP', 'value': '1.2.4.5'},
                    {'id': '2', 'indicator_type': 'Domain', 'value': 'my.domain1.com'}]}],
     [{'value': '1.2.4.5', 'itype': 'mal_ip'}, {'value': 'my.domain1.com', 'itype': 'mal_domain'}]),
])
def test_execute_get_indicators_by_query(mocker, query, indicators_types, return_value, expected_result):
    """Tests execute_get_indicators_by_query function.

    Checks the output of the command function with the expected output.
    """
    from ThreatstreamBuildIocImportJson import execute_get_indicators_by_query
    mocker.patch.object(demisto, 'executeCommand', return_value=return_value)
    response = execute_get_indicators_by_query(query, indicators_types)
    assert response == expected_result


@pytest.mark.parametrize('args, return_value, expected_outputs, expected_readable', [
    ({'indicator_query': 'type:(IP Domain)'},
     [{'ModuleName': 'name', 'Brand': 'Scripts', 'Category': 'automation', 'ID': '', 'Version': 0, 'Type': 3,
       'Contents': [{'id': '1', 'indicator_type': 'IP', 'value': '1.2.4.5'},
                    {'id': '2', 'indicator_type': 'Domain', 'value': 'my.domain1.com'}]}],
     {'ThreatstreamBuildIocImportJson': "{'objects': [{'value': '1.2.4.5', 'itype': 'mal_ip'}, "
      "{'value': 'my.domain1.com', 'itype': 'mal_domain'}]}"},
     "{'objects': [{'value': '1.2.4.5', 'itype': 'mal_ip'}, {'value': 'my.domain1.com', 'itype': 'mal_domain'}]}"),
    ({"domain_indicator_type": 'spam_domain',
      "domain_values": 'my.domain1.com',
      "email_indicator_type": 'spam_email',
      "email_values": 'test@test.com',
      "ip_indicator_type": 'actor_ip',
      "ip_values": '1.1.1.1',
      "md5_indicator_type": 'phish_md5',
      "md5_values": '00000000000000000000000000000000',
      "url_indicator_type": 'parked_url',
      "url_values": 'https://test.com'},
     None,
     {'ThreatstreamBuildIocImportJson': "{'objects': [{'value': 'test@test.com', 'itype': 'spam_email'}, "
      "{'value': '00000000000000000000000000000000', 'itype': 'phish_md5'}, "
      "{'value': '1.1.1.1', 'itype': 'actor_ip'}, {'value': 'https://test.com', 'itype': 'parked_url'}, "
      "{'value': 'my.domain1.com', 'itype': 'spam_domain'}]}"},
     "{'objects': [{'value': 'test@test.com', 'itype': 'spam_email'}, "
     "{'value': '00000000000000000000000000000000', 'itype': 'phish_md5'}, "
     "{'value': '1.1.1.1', 'itype': 'actor_ip'}, {'value': 'https://test.com', 'itype': 'parked_url'}, "
     "{'value': 'my.domain1.com', 'itype': 'spam_domain'}]}")
])
def test_get_indicators_and_build_json(mocker, args, return_value, expected_outputs, expected_readable):
    """Tests get_indicators_and_build_json function.

    Checks the output of the command function with the expected output.
    """
    from ThreatstreamBuildIocImportJson import get_indicators_and_build_json
    mocker.patch.object(demisto, 'executeCommand', return_value=return_value)
    response = get_indicators_and_build_json(args)
    assert response.outputs == expected_outputs
    assert response.readable_output == expected_readable
