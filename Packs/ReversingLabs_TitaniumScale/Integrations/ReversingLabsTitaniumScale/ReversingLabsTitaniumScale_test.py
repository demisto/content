import json
from ReversingLabsTitaniumScale import parse_report_and_return_results, parse_upload_report_and_return_results, format_proxy, \
    classification_to_score, get_status_from_classification, list_processing_tasks_output, get_yara_id_output


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

    formatted_http = format_proxy(
        addr="http://proxy-address.com",
        username="user1",
        password="pass1"
    )

    correct_expected = "https://user1:pass1@proxy-address.com"

    assert formatted_correctly == correct_expected
    assert formatted_http != correct_expected


def test_classification_to_score():
    assert classification_to_score("MALICIOUS") == 3
    assert classification_to_score("SUSPICIOUS") == 2


def test_get_status_from_classification():
    assert get_status_from_classification(3) == "malicious"
    assert get_status_from_classification(2) == "suspicious"


def test_list_processing_tasks_output():
    test_response = util_load_json("test_data/tiscale_list_processing_response.json")
    result = list_processing_tasks_output(resp_json=test_response)

    assert result.to_context().get("Contents").get("list_processing_tasks")[0].get("task_id") == 43


def test_get_yara_id_output():
    test_response = {"id": "f0a151ce303ae9b9e46b236492ac9196f3f72490"}
    result = get_yara_id_output(resp_json=test_response)

    assert result.to_context().get("Contents").get("yara_id").get("id") == "f0a151ce303ae9b9e46b236492ac9196f3f72490"


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())
