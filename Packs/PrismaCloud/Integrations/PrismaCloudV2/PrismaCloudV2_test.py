import pytest
from CommonServerPython import *  # noqa: F401


@pytest.mark.parametrize('url_to_format, formatted_url', [('https://api.prismacloud.io', 'https://api.prismacloud.io/'),
                                                          ('https://app.prismacloud.io/', 'https://api.prismacloud.io/'),
                                                          ('https://other.prismacloud.io/', 'https://other.prismacloud.io/'),
                                                          ('https://app.prismacloud.io/app', 'https://api.prismacloud.io/app/')])
def test_format_url(url_to_format, formatted_url):
    from PrismaCloudV2 import format_url

    assert format_url(url_to_format) == formatted_url


def test_extract_nested_values():
    from PrismaCloudV2 import extract_nested_values

    readable_response = {'id': 'P-1234567', 'status': 'open', 'reason': 'NEW_ALERT', 'firstSeen': 1660654610830,
                         'lastSeen': 1660654610830, 'alertTime': 1660654610830, 'eventOccurred': 1660654610256,
                         'resource': {'id': '-123456712345679737', 'name': 'AssumeRole', 'account': 'MyAccount',
                                      'accountId': '123456797356',
                                      'regionId': 'us-east-1', 'resourceType': 'EVENT', 'data': {'country': 'USA'},
                                      'resourceDetailsAvailable': False}, 'triggeredBy': '188612342792',
                         'policy': {'remediable': False}}
    nested_headers = {'resource.name': 'Resource Name', 'resource.id': 'Resource ID', 'resource.account': 'Account',
                      'resource.accountId': 'Account ID', 'resource.resourceType': 'Resource Type',
                      'resource.data.country': 'Country', 'policy.remediable': 'Is Remediable', 'id': 'Alert ID'}

    extract_nested_values(readable_response, nested_headers)
    assert set(nested_headers.values()).issubset(set(readable_response.keys()))

    assert readable_response['Resource Name'] == 'AssumeRole'
    assert readable_response['Resource ID'] == '-123456712345679737'
    assert readable_response['Account'] == 'MyAccount'
    assert readable_response['Account ID'] == '123456797356'
    assert readable_response['Resource Type'] == 'EVENT'
    assert readable_response['Country'] == 'USA'
    assert readable_response['Is Remediable'] is False
    assert readable_response['Alert ID'] == 'P-1234567'


def test_extract_nested_values_nonexistent_key():
    from PrismaCloudV2 import extract_nested_values

    readable_response = {'id': 'P-1234567', 'status': 'open', 'reason': 'NEW_ALERT', 'firstSeen': 1660654610830,
                         'lastSeen': 1660654610830, 'alertTime': 1660654610830, 'eventOccurred': 1660654610256,
                         'resource': {'id': '-123456712345679737', 'name': 'AssumeRole', 'account': 'MyAccount',
                                      'accountId': '123456797356',
                                      'regionId': 'us-east-1', 'resourceType': 'EVENT', 'data': {'country': 'USA'},
                                      'resourceDetailsAvailable': False}, 'triggeredBy': '188612342792'}
    nested_headers = {'resource.othername': 'Resource Other Name', 'nonexistent.b': 'b'}

    extract_nested_values(readable_response, nested_headers)
    assert readable_response.get('Resource Other Name') is None


def test_remove_empty_values_from_dict():
    from PrismaCloudV2 import remove_empty_values_from_dict

    dict_input = {'empty1': [],
                  'empty2': None,
                  'empty3': False,
                  'empty4': {},
                  'empty5': '',
                  'empty6': {'v1': None, 'v2': [], 'v3': {}},
                  'empty7': {'v1': {'empty': {'nested_empty': None}}},
                  'empty8': [{'v1': None}, {'v2': ''}],
                  'with_value1': 'text',
                  'with_value2': ['v1', 'v2'],
                  'with_value3': {'v1', 'v2'},
                  'with_value4': {'v1': None, 'v2': 'v3'},
                  'with_value5': {'timeRange': {'type': 'to_now', 'value': 'epoch'},
                                  'filters': [{"name": "string1", "operator": "=", "value": "string1"},
                                              {"name": "string2", "operator": "=", "value": "string2"}],
                                  },
                  'with_value6': 'false',
                  }
    dict_expected_output = {'with_value1': 'text',
                            'with_value2': ['v1', 'v2'],
                            'with_value3': {'v1', 'v2'},
                            'with_value4': {'v2': 'v3'},
                            'with_value5': {
                                'timeRange': {'type': 'to_now', 'value': 'epoch'},
                                'filters': [{"name": "string1", "operator": "=", "value": "string1"},
                                            {"name": "string2", "operator": "=", "value": "string2"}]},
                            'with_value6': 'false',
                            }

    assert remove_empty_values_from_dict(dict_input) == dict_expected_output


def test_handle_filters():
    from PrismaCloudV2 import handle_filters

    filters = argToList('alert.status=open,alert.status=resolved, policy.remediable=true ')
    parsed_filters = handle_filters(filters)
    assert parsed_filters == [{'name': 'alert.status', 'operator': '=', 'value': 'open'},
                              {'name': 'alert.status', 'operator': '=', 'value': 'resolved'},
                              {'name': 'policy.remediable', 'operator': '=', 'value': 'true'}]


@pytest.mark.parametrize('filter_name', ('no_equal_sign', 'too=many=equal_signs', ' ', 'no_value= ', '=no_name'))
def test_handle_filters_error(filter_name):
    from PrismaCloudV2 import handle_filters

    filters = argToList(filter_name)
    with pytest.raises(DemistoException) as de:
        handle_filters(filters)
    assert de.value.message == f'Filters should be in the format of "filtername1=filtervalue1,filtername2=filtervalue2". ' \
                               f'The filter "{filters[0]}" doesn\'t meet this requirement.'
