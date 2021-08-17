import json
import io
from ReversingLabsA1000v2 import a1000_report_output, list_extracted_files_output, get_classification_output
import demistomock as demisto
import pytest

INTEGRATION_NAME = 'ReversingLabs A1000'


@pytest.fixture(autouse=True)
def handle_calling_context(mocker):
    mocker.patch.object(demisto, 'callingContext', {'context': {'IntegrationBrand': INTEGRATION_NAME}})


def test_a1000_report_output():
    test_response = util_load_json('TestData/a1000_response.json')
    test_context = util_load_json('TestData/a1000_context.json')

    result = a1000_report_output(test_response)

    assert result.to_context() == test_context


def test_a1000_list_extracted_output():
    test_response = util_load_json('TestData/a1000_list_extracted_response.json')
    test_context = util_load_json('TestData/a1000_list_extracted_context.json')

    result = list_extracted_files_output(test_response)

    assert result.to_context() == test_context


def test_a1000_get_classification_output():
    test_response = util_load_json('TestData/a1000_get_classification_response.json')
    test_context = util_load_json('TestData/a1000_get_classification_context.json')

    result = get_classification_output(test_response)

    assert result.to_context() == test_context


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())
