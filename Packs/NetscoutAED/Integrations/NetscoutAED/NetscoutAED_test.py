import json
import io
import pytest
import requests_mock
from NetscoutAED import Client
from CommonServerPython import DemistoException

MOCK_URL = "http://base_url_mock"
client = Client(
    base_url=MOCK_URL,
    verify=False,
    api_token="api_token",
    proxy=False)

inbound_blacklisted = {'direction': 'inbound', 'list_color': 'blacklist'}
inbound_whitelisted = {'direction': 'inbound', 'list_color': 'whitelist'}
outbound_blacklisted = {'direction': 'outbound', 'list_color': 'blacklist'}
outbound_whitelisted = {'direction': 'outbound', 'list_color': 'whitelist'}


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_objects_time_to_readable_time():
    """

        Given:
            - A list of objects with same time key and a valid key name

        When:
            - When the api returns list of objects with timestamps (seconds)

        Then:
            - The time value of each object is replaced with a date string (ISO 8601 format)

    """
    from NetscoutAED import objects_time_to_readable_time
    list_of_objects = [{'countryName': 'country', 'createdTime': 1615888547},
                       {'countryName': 'country', 'createdTime': 1615838546}]
    time_key = "createdTime"
    objects_time_to_readable_time(list_of_objects, time_key)
    expected_output = [{'country_name': 'country', 'created_time': '2021-03-16T09:55:47.000Z'},
                       {'country_name': 'country', 'created_time': '2021-03-15T20:02:26.000Z'}]
    assert len(list_of_objects) == len(expected_output)
    assert all([x == y for x, y in zip(list_of_objects, expected_output)])


def test_objects_time_to_readable_time_key_mismatch():
    """

        Given:
            - A key that does not match the keys in the list of objects

        When:
            - When the api returns list of objects with timestamps (seconds)

        Then:
            - An exception is raised by the function

    """
    from NetscoutAED import objects_time_to_readable_time
    with pytest.raises(DemistoException, match="argument is not valid"):
        objects_time_to_readable_time([{'createdTime': 1615888547}, {'createdTime': 1615444547}], "TimeKey")


def test_serialize_protection_groups():
    """

        Given:
            - A valid object

        When:
            - When the api expects a different format

        Then:
            - Returns the expected format

    """
    from NetscoutAED import serialize_protection_groups

    protection_groups_list = [{'active': True, 'protectionLevel': "low"},
                              {'active': False, 'protectionLevel': "medium"},
                              {'active': False, 'protectionLevel': "high"}]
    expected_output = [{'active': 1, 'protectionLevel': 1},
                       {'active': 0, 'protectionLevel': 2},
                       {'active': 0, 'protectionLevel': 3}
                       ]
    for i, protection_group in enumerate(protection_groups_list):
        serialize_protection_groups(protection_group)
        assert protection_groups_list[i] == expected_output[i]


def test_deserialize_protection_groups():
    """

        Given:
            - A valid list of objects

        When:
            - When the human readable expects a different format

        Then:
            - Returns the expected format

    """
    from NetscoutAED import deserialize_protection_groups

    protection_groups_list = [
        {'active': 1, 'protectionLevel': 1},
        {'active': 0, 'protectionLevel': 2},
        {'active': 0, 'protectionLevel': 3},
    ]
    expected_output = [
        {'active': True, 'protectionLevel': "low"},
        {'active': False, 'protectionLevel': "medium"},
        {'active': False, 'protectionLevel': "high"},
    ]
    deserialize_protection_groups(protection_groups_list)
    assert len(protection_groups_list) == len(expected_output)
    assert all([x == y for x, y in zip(protection_groups_list, expected_output)])


def test_country_code_list_command(mocker):
    """

        Given:
            - A valid args input

        When:
            - Running country code list command.

        Then:
            - Ensure expected human readable response is returned and output is correct

    """
    from NetscoutAED import country_code_list_command

    countries_code_raw_response = util_load_json('test_data/countries_codes/countries_code_raw.json')
    mocker.patch.object(client, "country_code_list_command", return_value=countries_code_raw_response)
    result = country_code_list_command(client, {})
    assert "Anguilla" in result.readable_output
    assert "| Algeria | DZ |" in result.readable_output
    assert {'country_name': 'Afghanistan', 'iso_code': 'AF'} in result.outputs


country_list_params = [(outbound_blacklisted, "outbound_blacklisted_country_list_command",
                        'outbound_blacklisted_countries_raw.json',
                        {'annotation': 'Test', 'country': 'BD', 'update_time': '2021-03-16T16:57:16.000Z'}),
                       (inbound_blacklisted, "inbound_blacklisted_country_list_command",
                        'inbound_blacklisted_countries_raw.json',
                        {'annotation': ['Test2'], 'cid': [-1], 'country': 'BF', 'pgid': [-1],
                         'update_time': '2021-03-15T10:17:32.000Z'})
                       ]


@pytest.mark.parametrize("direction_color, func_mock, raw_respond, expected_output", country_list_params)
def test_handle_country_list_commands(mocker, direction_color, func_mock, raw_respond, expected_output):
    """

        Given:
            - A valid args input

        When:
            - Running blacklisted country list command

        Then:
            - Ensure expected human readable response is returned and output is correct

    """
    from NetscoutAED import handle_country_list_commands

    outbound_blacklisted_countries_raw_response = util_load_json(f'test_data/countries/{raw_respond}')
    mocker.patch.object(client, func_mock,
                        return_value=outbound_blacklisted_countries_raw_response)
    result = handle_country_list_commands(client, {}, direction_color)
    assert "Test" in result.readable_output
    assert "| AI | 2021-03-16T16:57:09.000Z |" in result.readable_output
    assert expected_output in result.outputs


country_addition_params = [('BS', outbound_blacklisted, "outbound_blacklisted_country_add_command",
                            'added_outbound_blacklisted_countries_raw.json',
                            [{'annotation': 'Test', 'country': 'BS', 'update_time': '2021-03-14T12:18:05.000Z'}]),
                           ('BS,AU', outbound_blacklisted, "outbound_blacklisted_country_add_command",
                            'added_outbound_blacklisted_countries_raw.json',
                            [{'annotation': 'Test', 'country': 'AU', 'update_time': '2021-03-16T17:54:38.000Z'},
                             {'annotation': None, 'country': 'BS', 'update_time': '2021-03-14T12:18:05.000Z'}]),
                           ('BS', inbound_blacklisted, "inbound_blacklisted_country_add_command",
                            'added_inbound_blacklisted_countries_raw.json',
                            [{'annotation': 'Test', 'country': 'BS', 'update_time': '2021-03-14T12:18:05.000Z'}]),
                           ('BS,AU', inbound_blacklisted, "inbound_blacklisted_country_add_command",
                            'added_inbound_blacklisted_countries_raw.json',
                            [{'annotation': 'Test', 'country': 'AU', 'update_time': '2021-03-16T17:54:38.000Z'},
                             {'annotation': None, 'country': 'BS', 'update_time': '2021-03-14T12:18:05.000Z'}]),
                           ]


@pytest.mark.parametrize("country, direction_color, func_mock, raw_respond, expected_output", country_addition_params)
def test_handle_country_addition_commands(mocker, country, func_mock, raw_respond, direction_color, expected_output):
    """

        Given:
            - (case1) A valid args and a single country to add input
            - (case2) A valid args and multiple countries to add input (comma seperated)

        When:
            - Running outbound/inbound blacklisted country add command

        Then:
            - Ensure expected human readable response is returned and output is correct

    """
    from NetscoutAED import handle_country_addition_commands

    blacklisted_countries_raw = util_load_json('test_data/countries/' + raw_respond)
    if country == 'BS':
        blacklisted_countries_raw = blacklisted_countries_raw["single_country_output"]
    elif country == 'BS,AU':
        blacklisted_countries_raw = blacklisted_countries_raw["multiple_country_output"]

    mocker.patch.object(client, func_mock, return_value=blacklisted_countries_raw)
    result = handle_country_addition_commands(client, {"country": country}, direction_color)
    assert "Test" in result.readable_output
    assert "| BS | 2021-03-14T12:18:05.000Z |" in result.readable_output
    assert all([x == y for x, y in zip(expected_output, result.outputs)])


def test_handle_country_addition_commands_no_country_given():
    """

        Given:
            - An invalid country input

        When:
            - Running outbound/inbound blacklisted country add command

        Then:
            - An exception is raised by the function

    """
    from NetscoutAED import handle_country_addition_commands
    with pytest.raises(DemistoException, match="A country code must be provided in order to add"):
        handle_country_addition_commands(client, {}, outbound_blacklisted)


@pytest.mark.parametrize("country, func_mock, url_suffix, direction_color", [
    ('BS', "outbound_blacklisted_country_delete_command", "/otf/blacklisted-countries/", outbound_blacklisted),
    ('BS,AU', "outbound_blacklisted_country_delete_command", "/otf/blacklisted-countries/", outbound_blacklisted),
    ('BS', "inbound_blacklisted_country_delete_command", "/protection-groups/blacklisted-countries/",
     inbound_blacklisted),
    ('BS,AU', "inbound_blacklisted_country_delete_command", "/protection-groups/blacklisted-countries/",
     inbound_blacklisted),
])
def test_handle_country_deletion_commands(country, func_mock, url_suffix, direction_color):
    """

        Given:
            - (case1) A valid args and a single country to remove input
            - (case2) A valid args and multiple countries to remove input (comma seperated)

        When:
            - Running outbound/inbound blacklisted country remove command

        Then:
            - Ensure expected response is returned

    """
    from NetscoutAED import handle_country_deletion_commands
    with requests_mock.Mocker() as m:
        m.delete(f"{MOCK_URL}{url_suffix}", status_code=204)
        result = handle_country_deletion_commands(client, {"country": country}, direction_color)
    assert "Countries were successfully removed" in result


def test_handle_country_deletion_commands_no_country_given():
    """

        Given:
            - An invalid country input

        When:
            - Running outbound/inbound blacklisted country delete command

        Then:
            - An exception is raised by the function

    """
    from NetscoutAED import handle_country_deletion_commands
    with pytest.raises(DemistoException, match="A country code must be provided in order to add"):
        handle_country_deletion_commands(client, {}, outbound_blacklisted)


hosts_list_params = [(outbound_blacklisted, "outbound_blacklisted_host_list_command",
                      'outbound_blacklisted_hosts_list_raw.json',
                      [{"annotation": "blacklisted outbound", "host_address": "6.6.6.6",
                        "update_time": "2021-03-15T13:16:11.000Z"}]),
                     (inbound_blacklisted, "inbound_blacklisted_host_list_command",
                      'inbound_blacklisted_hosts_list_raw.json',
                      [{"annotation": ["blacklisted inbound"], "cid": [-1], "host_address": "1.1.1.1", "pgid": [-1],
                        "update_time": "2021-03-15T13:16:11.000Z"}]),
                     (outbound_whitelisted, "outbound_whitelisted_host_list_command",
                      'outbound_whitelisted_hosts_list_raw.json',
                      [{"annotation": "whitelisted outbound", "host_address": "12.1.1.1",
                        "update_time": "2021-03-15T13:16:11.000Z"}]),
                     (inbound_whitelisted, "inbound_whitelisted_host_list_command",
                      'inbound_whitelisted_hosts_list_raw.json', [
                          {"annotation": ["whitelisted inbound"], "cid": [-1], "host_address": "6.6.6.6", "pgid": [-1],
                           "update_time": "2021-03-15T13:16:11.000Z"}])]


@pytest.mark.parametrize("direction_color, func_mock, raw_respond, expected_output", hosts_list_params)
def test_handle_host_list_commands(mocker, direction_color, func_mock, raw_respond, expected_output):
    """

        Given:
            - A valid args input

        When:
            - Running hosts list command

        Then:
            - Ensure expected human readable response is returned and output is correct

    """
    from NetscoutAED import handle_host_list_commands

    outbound_blacklisted_hosts_raw_response = util_load_json(f'test_data/hosts/{raw_respond}')
    mocker.patch.object(client, func_mock,
                        return_value=outbound_blacklisted_hosts_raw_response)
    result = handle_host_list_commands(client, {}, direction_color)
    assert direction_color['direction'] and direction_color['list_color'] in result.readable_output
    assert "2021-03-15T13:16:11.000Z" in result.readable_output
    assert expected_output[0] == result.outputs[0]


host_addition_params = [('1.1.1.1', outbound_blacklisted, "outbound_blacklisted_host_add_update_command",
                         'added_or_updated_outbound_blacklisted_hosts_raw.json',
                         [{'annotation': 'Test blacklisted outbound', 'host_address': '1.1.1.1',
                           'update_time': '2021-03-18T10:38:56.000Z'}]),
                        ('2.2.2.2,3.3.3.3', outbound_blacklisted, "outbound_blacklisted_host_add_update_command",
                         'added_or_updated_outbound_blacklisted_hosts_raw.json',
                         [{'annotation': 'Test blacklisted outbound', 'host_address': '2.2.2.2',
                           'update_time': '2021-03-18T10:41:27.000Z'},
                          {'annotation': 'Test blacklisted outbound', 'host_address': '3.3.3.3',
                           'update_time': '2021-03-18T10:41:27.000Z'}]),

                        ('1.1.1.1', inbound_blacklisted, "inbound_blacklisted_host_add_update_command",
                         'added_or_updated_inbound_blacklisted_hosts_raw.json',
                         [{'annotation': ['Test blacklisted inbound'], 'cid': [-1], 'host_address': '1.1.1.1',
                           'pgid': [-1], 'update_time': '2021-03-18T10:48:37.000Z'}]),
                        ('2.2.2.2,3.3.3.3', inbound_blacklisted, "inbound_blacklisted_host_add_update_command",
                         'added_or_updated_inbound_blacklisted_hosts_raw.json',
                         [{'annotation': ['Test blacklisted inbound'], 'cid': [-1], 'host_address': '2.2.2.2',
                           'pgid': [-1], 'update_time': '2021-03-18T10:53:00.000Z'},
                          {'annotation': ['Test blacklisted inbound'], 'cid': [-1], 'host_address': '3.3.3.3',
                           'pgid': [-1], 'update_time': '2021-03-18T10:53:00.000Z'}]),

                        ('1.1.1.1', outbound_whitelisted, "outbound_whitelisted_host_add_update_command",
                         'added_or_updated_outbound_whitelisted_hosts_raw.json',
                         [{'annotation': 'Test whitelisted outbound', 'host_address': '1.1.1.1',
                           'update_time': '2021-03-18T10:44:09.000Z'}]),
                        ('2.2.2.2,3.3.3.3', outbound_whitelisted, "outbound_whitelisted_host_add_update_command",
                         'added_or_updated_outbound_whitelisted_hosts_raw.json',
                         [{'annotation': 'Test whitelisted outbound', 'host_address': '2.2.2.2',
                           'update_time': '2021-03-18T10:45:18.000Z'},
                          {'annotation': 'Test whitelisted outbound', 'host_address': '3.3.3.3',
                           'update_time': '2021-03-18T10:45:18.000Z'}]),

                        ('1.1.1.1', inbound_whitelisted, "inbound_whitelisted_host_add_update_command",
                         'added_or_updated_inbound_whitelisted_hosts_raw.json',
                         [{'annotation': ['Test whitelisted inbound'], 'cid': [-1], 'host_address': '1.1.1.1',
                           'pgid': [-1], 'update_time': '2021-03-18T10:48:37.000Z'}]),
                        ('2.2.2.2,3.3.3.3', inbound_whitelisted, "inbound_whitelisted_host_add_update_command",
                         'added_or_updated_inbound_whitelisted_hosts_raw.json',
                         [{'annotation': ['Test whitelisted inbound'], 'cid': [-1], 'host_address': '2.2.2.2',
                           'pgid': [-1], 'update_time': '2021-03-18T10:50:36.000Z'},
                          {'annotation': ['Test whitelisted inbound'], 'cid': [-1], 'host_address': '3.3.3.3',
                           'pgid': [-1], 'update_time': '2021-03-18T10:50:36.000Z'}]),
                        ]


@pytest.mark.parametrize("host, direction_color, func_mock, raw_respond, expected_output", host_addition_params)
def test_handle_host_addition_commands(mocker, host, func_mock, raw_respond, direction_color, expected_output):
    """

        Given:
            - (case1) A valid args and a single host to add/update input
            - (case2) A valid args and multiple host to add/update input (comma seperated)

        When:
            - Running host addition/update command

        Then:
            - Ensure expected human readable response is returned and output is correct

    """
    from NetscoutAED import handle_host_addition_and_replacement_commands

    hosts_raw = util_load_json('test_data/hosts/' + raw_respond)
    if host == '1.1.1.1':
        hosts_raw = hosts_raw["single_host_output"]
    elif host == '2.2.2.2,3.3.3.3':
        hosts_raw = hosts_raw["multiple_hosts_output"]

    mocker.patch.object(client, func_mock, return_value=hosts_raw)
    result = handle_host_addition_and_replacement_commands(client, {"host_address": host}, direction_color)
    assert "Hosts were successfully" in result.readable_output
    assert all([x == y for x, y in zip(expected_output, result.outputs)])


def test_handle_host_addition_commands_no_host_given():
    """

        Given:
            - An invalid host input

        When:
            - Running host addition command

        Then:
            - An exception is raised by the function

    """
    from NetscoutAED import handle_host_addition_and_replacement_commands
    with pytest.raises(DemistoException, match="A host address must be provided in order to add/update"):
        handle_host_addition_and_replacement_commands(client, {}, outbound_blacklisted)


host_deletion_params = [
    ('1.1.1.1', outbound_blacklisted, "outbound_blacklisted_host_remove_command", "/otf/blacklisted-hosts/"),
    ('2.2.2.2,3.3.3.3', outbound_blacklisted, "outbound_blacklisted_host_remove_command", "/otf/blacklisted-hosts/"),

    (
        '1.1.1.1', inbound_blacklisted, "inbound_blacklisted_host_remove_command",
        "/protection-groups/blacklisted-hosts/"),
    ('2.2.2.2,3.3.3.3', inbound_blacklisted, "inbound_blacklisted_host_remove_command",
     "/protection-groups/blacklisted-hosts/"),

    ('1.1.1.1', outbound_whitelisted, "outbound_whitelisted_host_remove_command", "/otf/whitelisted-hosts/"),
    ('2.2.2.2,3.3.3.3', outbound_whitelisted, "outbound_whitelisted_host_remove_command", "/otf/whitelisted-hosts/"),

    (
        '1.1.1.1', inbound_whitelisted, "inbound_whitelisted_host_remove_command",
        "/protection-groups/whitelisted-hosts/"),
    ('2.2.2.2,3.3.3.3', inbound_whitelisted, "inbound_whitelisted_host_remove_command",
     "/protection-groups/whitelisted-hosts/")]


@pytest.mark.parametrize("host, direction_color, func_mock, url_suffix", host_deletion_params)
def test_handle_host_deletion_commands(host, func_mock, direction_color, url_suffix):
    """

        Given:
            - (case1) A valid args and a single host to remove input
            - (case2) A valid args and multiple hosts to remove input (comma seperated)

        When:
            - Running host deletion command

        Then:
            - Ensure expected response is returned

    """
    from NetscoutAED import handle_host_deletion_commands
    with requests_mock.Mocker() as m:
        m.delete(f"{MOCK_URL}{url_suffix}", status_code=204)
        result = handle_host_deletion_commands(client, {"host_address": host}, direction_color)
    assert "Hosts were successfully removed" in result


def test_handle_host_deletion_commands_no_host_given():
    """

        Given:
            - An invalid host input

        When:
            - Running host deletion command

        Then:
            - An exception is raised by the function

    """
    from NetscoutAED import handle_host_deletion_commands
    with pytest.raises(DemistoException, match="A host address must be provided in order to remove"):
        handle_host_deletion_commands(client, {}, outbound_blacklisted)


def test_handle_protection_groups_list_commands(mocker):
    """

        Given:
            - A valid args input

        When:
            - Running protection groups list command

        Then:
            - Ensure expected human readable response is returned and output is correct

    """
    from NetscoutAED import handle_protection_groups_list_commands

    protection_groups_raw_response = util_load_json('test_data/protection_groups/protection_groups_list_raw.json')
    mocker.patch.object(client, 'protection_group_list_command',
                        return_value=protection_groups_raw_response)
    expected_output = {
        "active": False,
        "bps_dropped": 0,
        "bps_passed": 0,
        "bytes_dropped": 0,
        "bytes_passed": 0,
        "cid": None,
        "description": "The default protection group on 0.0.0.0/0",
        "name": "Default Protection Group",
        "packets_dropped": 0,
        "packets_passed": 0,
        "pgid": 7,
        "pps_dropped": 0,
        "pps_passed": 0,
        "prefixes": [
            "0.0.0.0/0"
        ],
        "profiling": False,
        "profiling_duration": 0,
        "profiling_start": 0,
        "protection_level": 'low',
        "server_name": "Generic Server",
        "server_type": 0,
        "time_created": '2021-01-17T13:54:13.000Z'
    }
    result = handle_protection_groups_list_commands(client, {})
    assert "Default Protection Group" in result.readable_output
    assert "Generic Server" in result.readable_output
    assert "42" in result.readable_output
    assert expected_output == result.outputs[0]


def test_handle_protection_groups_update_commands(mocker):
    """

        Given:
            - A valid args input

        When:
            - Running protection groups update command

        Then:
            - Ensure expected human readable response is returned and output is correct

    """
    from NetscoutAED import handle_protection_groups_update_commands

    protection_groups_update_raw_response = util_load_json(
        'test_data/protection_groups/protection_groups_update_raw.json')
    mocker.patch.object(client, 'protection_group_patch_command',
                        return_value=protection_groups_update_raw_response)
    expected_output = {
        "active": False,
        "bps_dropped": 0,
        "bps_passed": 0,
        "bytes_dropped": 0,
        "bytes_passed": 0,
        "description": "The default protection group on 0.0.0.0/0",
        "name": "Default Protection Group",
        "packets_dropped": 0,
        "packets_passed": 0,
        "pgid": 7,
        "pps_dropped": 0,
        "pps_passed": 0,
        "prefixes": [
            "0.0.0.0/0"
        ],
        "profiling": False,
        "profiling_duration": 0,
        "profiling_start": 0,
        "protection_level": 'low',
        "server_name": "Generic Server",
        "server_type": 0,
        "time_created": '2021-01-17T13:54:13.000Z'
    }
    result = handle_protection_groups_update_commands(client, {'pgid': 7})
    assert "Successfully updated the protection group object with protection group id: 7" in result.readable_output
    assert "Default Protection Group" in result.readable_output
    assert expected_output == result.outputs[0]


def test_handle_protection_groups_update_commands_no_pgid_given(mocker):
    """

        Given:
            - An invalid pgid input

        When:
            - Running protection group update command

        Then:
            - An exception is raised by the function

    """
    from NetscoutAED import handle_protection_groups_update_commands
    with pytest.raises(DemistoException, match="A pgid must be provided in order to update"):
        handle_protection_groups_update_commands(client, {})


def test_handle_domain_list_commands(mocker):
    """

            Given:
                - A valid args input

            When:
                - Running inbound blacklisted domain list command

            Then:
                - Ensure expected human readable response is returned and output is correct

    """
    from NetscoutAED import handle_domain_list_commands

    inbound_blacklisted_domains_raw_response = util_load_json('test_data/domains/inbound_blacklisted_domains_raw.json')
    mocker.patch.object(client, 'inbound_blacklisted_domain_list_command',
                        return_value=inbound_blacklisted_domains_raw_response)
    result = handle_domain_list_commands(client, {})
    assert "google.com" in result.readable_output
    assert "2021-03-18T16:49:50.000Z" in result.readable_output
    assert {'annotation': [], 'cid': [-1], 'domain': 'google.com', 'pgid': [-1],
            'update_time': '2021-03-18T16:49:26.000Z'} == result.outputs[0]


domain_addition_params = [('google.com',
                           [{'annotation': [], 'cid': [-1], 'domain': 'google.com', 'pgid': [-1],
                             'update_time': '2021-03-18T16:49:26.000Z'}]),
                          ('google.com,sport.com',
                           [{'annotation': [], 'cid': [-1], 'domain': 'google.com', 'pgid': [-1],
                             'update_time': '2021-03-18T16:49:26.000Z'},
                            {'annotation': [], 'cid': [-1], 'domain': 'sport.com', 'pgid': [-1],
                             'update_time': '2021-03-18T17:25:26.000Z'}])]


@pytest.mark.parametrize("domain, expected_output", domain_addition_params)
def test_handle_domain_addition_commands(mocker, domain, expected_output):
    """

        Given:
            - (case1) A valid args and a single domain to add input
            - (case2) A valid args and multiple domains to add input (comma seperated)

        When:
            - Running domain addition command

        Then:
            - Ensure expected human readable response is returned and output is correct

    """
    from NetscoutAED import handle_domain_addition_commands

    domains_raw = util_load_json('test_data/domains/added_inbound_blacklisted_domains_raw.json')
    if domain == 'google.com':
        domains_raw = domains_raw["single_domain_output"]
    elif domain == 'google.com,sport.com':
        domains_raw = domains_raw["multiple_domains_output"]

    mocker.patch.object(client, "inbound_blacklisted_domain_add_command", return_value=domains_raw)
    result = handle_domain_addition_commands(client, {"domain": domain})
    assert "Domains were successfully added to the inbound blacklisted list" in result.readable_output
    assert "google.com" in result.readable_output
    assert all([x == y for x, y in zip(expected_output, result.outputs)])


def test_handle_domain_addition_commands_no_domain_given():
    """

        Given:
            - An invalid domain input

        When:
            - Running domain addition command

        Then:
            - An exception is raised by the function

    """
    from NetscoutAED import handle_domain_addition_commands
    with pytest.raises(DemistoException, match="A domain must be provided in order to add"):
        handle_domain_addition_commands(client, {})


@pytest.mark.parametrize("domain", [('google.com'), ('google.com,sport.com')])
def test_handle_domain_deletion_commands(mocker, domain):
    """

        Given:
            - (case1) A valid args and a single domain to remove input
            - (case2) A valid args and multiple domains to remove input (comma seperated)

        When:
            - Running domain deletion command

        Then:
            - Ensure expected human readable response is returned and output is correct

    """
    from NetscoutAED import handle_domain_deletion_commands

    with requests_mock.Mocker() as m:
        m.delete(f"{MOCK_URL}/protection-groups/blacklisted-domains/", status_code=204)
        result = handle_domain_deletion_commands(client, {"domain": domain})
    assert "Domains were successfully removed" in result


def test_handle_domain_deletion_commands_no_domain_given():
    """

        Given:
            - An invalid domain input

        When:
            - Running domain deletion command

        Then:
            - An exception is raised by the function

    """
    from NetscoutAED import handle_domain_deletion_commands

    with pytest.raises(DemistoException, match="A domain must be provided in order to remove"):
        handle_domain_deletion_commands(client, {})


def test_handle_url_list_commands(mocker):
    """

            Given:
                - A valid args input

            When:
                - Running inbound blacklisted url list command

            Then:
                - Ensure expected human readable response is returned and output is correct

    """
    from NetscoutAED import handle_url_list_commands

    inbound_blacklisted_urls_raw_response = util_load_json('test_data/urls/inbound_blacklisted_urls_raw.json')
    mocker.patch.object(client, 'inbound_blacklisted_url_list_command',
                        return_value=inbound_blacklisted_urls_raw_response)
    result = handle_url_list_commands(client, {})
    assert "google.com" in result.readable_output
    assert "2021-03-18T16:52:26.000Z" in result.readable_output
    assert {'annotation': [], 'cid': [-1], 'pgid': [-1], 'url': 'google.com',
            'update_time': '2021-03-18T16:52:26.000Z'} == result.outputs[0]


url_addition_params = [('maps.google.com',
                        [{'annotation': ['Google Maps'], 'cid': [-1], 'pgid': [-1], 'url': 'maps.google.com',
                          'update_time': '2021-03-18T18:08:39.000Z'}]),
                       ('maps.google.com,sport.com',
                        [{'annotation': ['Google Maps'], 'cid': [-1], 'pgid': [-1], 'url': 'maps.google.com',
                          'update_time': '2021-03-18T18:08:39.000Z'},
                         {'annotation': ['Google Maps'], 'cid': [-1], 'pgid': [-1], 'url': 'sport.com',
                          'update_time': '2021-03-18T18:08:39.000Z'}])]


@pytest.mark.parametrize("url, expected_output", url_addition_params)
def test_handle_url_addition_commands(mocker, url, expected_output):
    """

        Given:
            - (case1) A valid args and a single url to add input
            - (case2) A valid args and multiple urls to add input (comma seperated)

        When:
            - Running domain addition command

        Then:
            - Ensure expected human readable response is returned and output is correct

    """
    from NetscoutAED import handle_url_addition_commands

    urls_raw = util_load_json('test_data/urls/added_inbound_blacklisted_urls_raw.json')
    if url == 'maps.google.com':
        urls_raw = urls_raw["single_url_output"]
    elif url == 'maps.google.com,sport.com':
        urls_raw = urls_raw["multiple_urls_output"]

    mocker.patch.object(client, "inbound_blacklisted_url_add_command", return_value=urls_raw)
    result = handle_url_addition_commands(client, {"url": url})
    assert "Urls were successfully added to the inbound blacklisted list" in result.readable_output
    assert "maps.google.com" in result.readable_output
    assert all([x == y for x, y in zip(expected_output, result.outputs)])


def test_handle_url_addition_commands_no_url_given():
    """

       Given:
           - An invalid url input

       When:
           - Running url addition command

       Then:
           - An exception is raised by the function

   """
    from NetscoutAED import handle_url_addition_commands
    with pytest.raises(DemistoException, match="A URL must be provided in order to add"):
        handle_url_addition_commands(client, {})


@pytest.mark.parametrize("url", [('google.com'), ('google.com,sport.com')])
def test_handle_url_deletion_commands(url):
    """

        Given:
            - (case1) A valid args and a single url to remove input
            - (case2) A valid args and multiple urls to remove input (comma seperated)

        When:
            - Running url deletion command

        Then:
            - Ensure expected human readable response is returned and output is correct

    """
    from NetscoutAED import handle_url_deletion_commands

    with requests_mock.Mocker() as m:
        m.delete(f"{MOCK_URL}/protection-groups/blacklisted-urls/", status_code=204)
        result = handle_url_deletion_commands(client, {"url": url})
    assert "URLs were successfully removed" in result


def test_handle_url_deletion_commands_no_url_given():
    """

        Given:
            - An invalid url input

        When:
            - Running url deletion command

        Then:
            - An exception is raised by the function

    """
    from NetscoutAED import handle_url_deletion_commands

    with pytest.raises(DemistoException, match="A URL must be provided in order to remove"):
        handle_url_deletion_commands(client, {})
