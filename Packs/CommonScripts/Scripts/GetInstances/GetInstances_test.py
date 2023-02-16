import pytest
from GetInstances import *


ARGS_SYSTEM_FILTER = {'instance_status': 'both'}
ARGS_BRAND_FILTER = {'brand': 'EWS v2, splunk', 'instance_status': 'both'}
ARGS_IS_ENABLED_FILTER = {'instance_status': 'active'}
ARGS_ALL_FILTERS = {'brand': 'EWS v2, splunk', 'instance_status': 'active'}
PREPARED_ARGS_ALL_FILTERS = {
    'instance_status': ARGS_ALL_FILTERS['instance_status'],
    'filter_brand': list(map(lambda x: x.strip(), ARGS_ALL_FILTERS['brand'].split(',')))
}


def load_json_file(path):
    with open(path, 'r') as json_file:
        json_string = json_file.read()
    return json.loads(json_string)


data_test_prepare_args = [
    (ARGS_SYSTEM_FILTER, ARGS_SYSTEM_FILTER),
    (ARGS_IS_ENABLED_FILTER, ARGS_IS_ENABLED_FILTER),
    (ARGS_ALL_FILTERS, PREPARED_ARGS_ALL_FILTERS)
]


@pytest.mark.parametrize('input_args, expected_output', data_test_prepare_args)
def test_prepare_args(input_args, expected_output):
    output = prepare_args(input_args)
    assert output == expected_output


data_test_prepare_args_with_invalid_value = [{}, {'instance_status': 'test'}]


@pytest.mark.parametrize('input_args', data_test_prepare_args_with_invalid_value)
def test_prepare_args_with_invalid_value(input_args):
    try:
        prepare_args(input_args)
    except ValueError as error:
        assert str(error) == "instance_status should be one of the following 'active', 'both', 'disabled'"


def test_without_any_filter():
    assert filter_config({'brand': 'EWS v2'}, instance_status='both')
    assert not filter_config({'brand': 'Scripts'}, instance_status='both')
    assert not filter_config({'brand': 'Builtin'}, instance_status='both')
    assert not filter_config({'brand': 'testmodule'}, instance_status='both')


def test_with_enabled_filter():
    assert filter_config({'state': 'active'}, instance_status='active')
    assert not filter_config({'state': 'disabled'}, instance_status='active')


data_test_filter_instances = [
    (ARGS_SYSTEM_FILTER, 'system_filter'),
    (ARGS_BRAND_FILTER, 'brand_filter'),
    (ARGS_IS_ENABLED_FILTER, 'is_enabled_filter'),
    (ARGS_ALL_FILTERS, 'all_filters')
]


@pytest.mark.parametrize('filter_args, filter_type', data_test_filter_instances)
def test_filter_instances(filter_args, filter_type):
    modules = load_json_file('test_data/raw_modules.json')
    args = prepare_args(filter_args)
    output_instances = list(filter_instances(modules, **args))
    assert load_json_file(f'test_data/modules_with_{filter_type}.json') == output_instances
