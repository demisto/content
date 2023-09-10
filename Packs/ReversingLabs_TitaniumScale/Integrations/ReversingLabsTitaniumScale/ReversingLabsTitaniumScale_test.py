import json
import io
from ReversingLabsTitaniumScale import parse_report_and_return_results, parse_upload_report_and_return_results, format_proxy


def test_parse_report_and_return_results():
    test_response = util_load_json('test_data/tiscale_response.json')
    test_context = util_load_json('test_data/tiscale_context.json')

    result = parse_report_and_return_results(title='## ReversingLabs TitaniumScale get results\n',
                                             response_json=test_response)

    assert result.to_context() == test_context


def test_parse_upload_report_and_return_results():
    test_response = util_load_json('test_data/tiscale_upload_response.json')
    test_context = util_load_json('test_data/tiscale_upload_context.json')

    result = parse_upload_report_and_return_results(response_json=test_response)

    assert result.to_context() == test_context


def test_format_proxy():
    formatted_correctly = format_proxy(
        addr="https://proxy-address.com",
        username="user1",
        password="pass1"
    )

    correct_expected = "https://user1:pass1@proxy-address.com"

    assert formatted_correctly == correct_expected


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())
