import json
from .ReversingLabs_A1000_v2 import (a1000_report_output,
                                     list_extracted_files_output,
                                     get_classification_output)


def test_a1000_report_output():
    test_response = json.load(open('ReversingLabs_A1000_v2/TestData/a1000_response.json'))
    test_context = json.load(open('ReversingLabs_A1000_v2/TestData/a1000_context.json'))

    result = a1000_report_output(test_response)

    assert result.to_context() == test_context


def test_a1000_list_extracted_output():
    test_response = json.load(open('ReversingLabs_A1000_v2/TestData/a1000_list_extracted_response.json'))
    test_context = json.load(open('ReversingLabs_A1000_v2/TestData/a1000_list_extracted_context.json'))

    result = list_extracted_files_output(test_response)

    assert result.to_context() == test_context


def test_a1000_get_classification_output():
    test_response = json.load(open('ReversingLabs_A1000_v2/TestData/a1000_get_classification_response.json'))
    test_context = json.load(open('ReversingLabs_A1000_v2/TestData/a1000_get_classification_context.json'))

    result = get_classification_output(test_response)

    assert result.to_context() == test_context
