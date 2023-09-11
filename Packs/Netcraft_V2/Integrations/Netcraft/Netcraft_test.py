import pytest
from CommonServerPython import *
import json
import yaml
from unittest import mock
from Netcraft import Client

# import io
# from Netcraft import Client, attack_report_command, takedown_list_command, takedown_update_command, takedown_escalate_command, takedown_note_create_command, takedown_note_list_command, attack_type_list_command, submission_list_command, file_report_submit_command, submission_file_list_command, file_screenshot_get_command, email_report_submit_command, submission_mail_get_command, mail_screenshot_get_command, url_report_submit_command, submission_url_list_command, url_screenshot_get_command
# SERVER_URL = 'https://test_url.com'


def load_yaml(filename):
    with open(f'test_data/{filename}.yml') as f:
        return yaml.safe_load(f.read())

def add_to_yaml(filename, obj):
    with open(f'test_data/{filename}.yml', 'a') as f:
        return f.read(yaml.dump(obj))

@pytest.mark.parametrize(
    'command',
    [
        'netcraft-attack-report',
        'netcraft-takedown-list',
        'netcraft-takedown-update',
        'netcraft-takedown-escalate',
        'netcraft-takedown-note-create',
        'netcraft-takedown-note-list',
        'netcraft-attack-type-list',
        'netcraft-submission-list',
        'netcraft-file-report-submit',
        'netcraft-submission-file-list',
        # 'netcraft-file-screenshot-get',
        'netcraft-email-report-submit',
        'netcraft-submission-mail-get',
        # 'netcraft-mail-screenshot-get',
        'netcraft-url-report-submit',
        'netcraft-submission-url-list',
        # 'netcraft-url-screenshot-get'
    ]
)
def test_generate(mocker, command):
    _command_ = command.removeprefix('netcraft-').replace('-', '_')
    data = load_yaml(_command_)
    req = mocker.patch.object(Client, '_http_request', return_value=data['api_response'])
    cr: CommandResults = getattr(__import__('Netcraft'), f'{_command_}_command')(data['args'], Client(True, False, ok_codes=(200,), headers={}))
    # my_mock.call_args_list[0].args
    cr_dict = {
        'outputs': cr.outputs,
        'outputs_key_field': cr.outputs_key_field,
        'outputs_prefix': cr.outputs_prefix,
        'raw_response': cr.raw_response,
        'readable_output': cr.readable_output,
    }
    add_to_yaml(
        _command_,
        {
            'http_func_args': {
                'args': list(req.call_args.args),
                'kwargs': req.call_args.kwargs
            },
            'outputs': cr_dict
        },
    )
    

# @pytest.fixture()
# def client():
#     return Client(verify=None, proxy=None, ok_codes=None, headers=None)


# def test_attack_report_command(client, requests_mock):
#     """
#         When:
#         Given:
#         Then:
#         """
#     args = {}
#     mock_response_attack_report = load_json(
#         './test_data/outputs/attack_report.json')
#     mock_results = load_json(
#         './test_data/outputs/attack_report_command.json')
#     requests_mock.post(SERVER_URL, json=mock_response_attack_report)
#     results = attack_report_command(client=client)
#     assert results.outputs_prefix == 'Netcraft.Takedown'
#     assert results.outputs_key_field == 'id'
#     assert results.raw_response == mock_response_attack_report


# def test_takedown_list_command(client, requests_mock):
#     """
#         When:
#         Given:
#         Then:
#         """
#     args = {}
#     mock_response_get_takedowns = load_json(
#         './test_data/outputs/get_takedowns.json')
#     mock_results = load_json(
#         './test_data/outputs/takedown_list_command.json')
#     requests_mock.post(SERVER_URL, json=mock_response_get_takedowns)
#     results = takedown_list_command(client=client)
#     assert results.readable_output == mock_results.get('readable_output')
#     assert results.outputs_prefix == 'Netcraft.Takedown'
#     assert results.outputs_key_field == 'id'
#     assert results.outputs == mock_results.get('outputs')


# def test_takedown_update_command(client, requests_mock):
#     """
#     When:
#     Given:
#     Then:
#     """
#     args = {}
#     mock_response_takedown_update = load_json('./test_data/outputs/takedown_update.json')
#     mock_results = load_json(
#         './test_data/outputs/takedown_update_command.json')
#     requests_mock.post(SERVER_URL, json=mock_response_takedown_update)
#     results = takedown_update_command(client=client)
#     assert results.readable_output == mock_results.get('readable_output')


# def test_takedown_escalate_command(client, requests_mock):
#     """
#         When:
#         Given:
#         Then:
#         """
#     args = {}
#     mock_response_takedown_escalate = load_json(
#         './test_data/outputs/takedown_escalate.json')
#     mock_results = load_json(
#         './test_data/outputs/takedown_escalate_command.json')
#     requests_mock.post(SERVER_URL, json=mock_response_takedown_escalate)
#     results = takedown_escalate_command(client=client)
#     assert results.readable_output == mock_results.get('readable_output')


# def test_takedown_note_create_command(client, requests_mock):
#     """
#         When:
#         Given:
#         Then:
#         """
#     args = {}
#     mock_response_takedown_note_create = load_json(
#         './test_data/outputs/takedown_note_create.json')
#     mock_results = load_json(
#         './test_data/outputs/takedown_note_create_command.json')
#     requests_mock.post(SERVER_URL, json=mock_response_takedown_note_create)
#     results = takedown_note_create_command(client=client)
#     assert results.outputs_prefix == 'Netcraft.TakedownNote'
#     assert results.outputs == mock_results.get('outputs')
#     assert results.outputs_key_field == 'note_id'
#     assert results.readable_output == mock_results.get('readable_output')


# def test_takedown_note_list_command(client, requests_mock):
#     """
#         When:
#         Given:
#         Then:
#         """
#     args = {}
#     mock_response_takedown_note_list = load_json(
#         './test_data/outputs/takedown_note_list.json')
#     mock_results = load_json(
#         './test_data/outputs/takedown_note_list_command.json')
#     requests_mock.post(SERVER_URL, json=mock_response_takedown_note_list)
#     results = takedown_note_list_command(client=client)
#     assert results.outputs_prefix == 'Netcraft.TakedownNote'
#     assert results.outputs == mock_results.get('outputs')
#     assert results.outputs_key_field == 'note_id'
#     assert results.readable_output == mock_results.get('readable_output')


# def test_attack_type_list_command(client, requests_mock):
#     """
#         When:
#         Given:
#         Then:
#         """
#     args = {}
#     mock_response_attack_type_list = load_json(
#         './test_data/outputs/attack_type_list.json')
#     mock_results = load_json(
#         './test_data/outputs/attack_type_list_command.json')
#     requests_mock.post(SERVER_URL, json=mock_response_attack_type_list)
#     results = attack_type_list_command(client=client)
#     assert results.outputs_prefix == 'Netcraft.AttackType'
#     assert results.outputs == mock_results.get('outputs')
#     assert results.readable_output == mock_results.get('readable_output')


# def test_submission_list_command(client, requests_mock):
#     """
#         When:
#         Given:
#         Then:
#         """
#     args = {}
#     results = submission_list_command(client=client)


# def test_file_report_submit_command(client, requests_mock):
#     """
#         When:
#         Given:
#         Then:
#         """
#     args = {}
#     mock_response_file_report_submit = load_json(
#         './test_data/outputs/file_report_submit.json')
#     mock_results = load_json(
#         './test_data/outputs/file_report_submit_command.json')
#     requests_mock.post(SERVER_URL, json=mock_response_file_report_submit)
#     results = file_report_submit_command(client=client)


# def test_submission_file_list_command(client, requests_mock):
#     """
#         When:
#         Given:
#         Then:
#         """
#     args = {}
#     results = submission_file_list_command(client=client)
#     assert results.readable_output == mock_results.get('readable_output')
#     assert results.outputs == mock_results.get('outputs')
#     assert results.outputs_prefix == 'Netcraft.SubmissionFile'
#     assert results.outputs_key_field == 'hash'


# def test_file_screenshot_get_command(client, requests_mock):
#     """
#         When:
#         Given:
#         Then:
#         """
#     args = {}
#     mock_response_file_screenshot_get = load_json(
#         './test_data/outputs/file_screenshot_get.json')
#     mock_results = load_json(
#         './test_data/outputs/file_screenshot_get_command.json')
#     requests_mock.post(SERVER_URL, json=mock_response_file_screenshot_get)
#     results = file_screenshot_get_command(client=client)


# def test_email_report_submit_command(client, requests_mock):
#     """
#         When:
#         Given:
#         Then:
#         """
#     args = {}
#     mock_response_email_report_submit = load_json(
#         './test_data/outputs/email_report_submit.json')
#     mock_results = load_json(
#         './test_data/outputs/email_report_submit_command.json')
#     requests_mock.post(SERVER_URL, json=mock_response_email_report_submit)
#     results = email_report_submit_command(client=client)


# def test_submission_mail_get_command(client, requests_mock):
#     """
#         When:
#         Given:
#         Then:
#         """
#     args = {}
#     mock_response_submission_mail_get = load_json(
#         './test_data/outputs/submission_mail_get.json')
#     mock_results = load_json(
#         './test_data/outputs/submission_mail_get_command.json')
#     requests_mock.post(SERVER_URL, json=mock_response_submission_mail_get)
#     results = submission_mail_get_command(client=client)
#     assert results.outputs == mock_results.get('outputs')
#     assert results.outputs_prefix == 'Netcraft.SubmissionMail'
#     assert results.outputs_key_field == 'hash'
#     assert results.readable_output == mock_results.get('readable_output')


# def test_mail_screenshot_get_command(client, requests_mock):
#     """
#         When:
#         Given:
#         Then:
#         """
#     args = {}
#     mock_response_mail_screenshot_get = load_json(
#         './test_data/outputs/mail_screenshot_get.json')
#     mock_results = load_json(
#         './test_data/outputs/mail_screenshot_get_command.json')
#     requests_mock.post(SERVER_URL, json=mock_response_mail_screenshot_get)
#     results = mail_screenshot_get_command(client=client)


# def test_url_report_submit_command(client, requests_mock):
#     """
#         When:
#         Given:
#         Then:
#         """
#     args = {}
#     mock_response_url_report_submit = load_json(
#         './test_data/outputs/url_report_submit.json')
#     mock_results = load_json(
#         './test_data/outputs/url_report_submit_command.json')
#     requests_mock.post(SERVER_URL, json=mock_response_url_report_submit)
#     results = url_report_submit_command(client=client)


# def test_submission_url_list_command(client, requests_mock):
#     """
#         When:
#         Given:
#         Then:
#         """
#     args = {}
#     results = submission_url_list_command(client=client)
#     assert results.outputs == mock_results.get('outputs')
#     assert results.outputs_key_field == 'uuid'
#     assert results.outputs_prefix == 'Netcraft.SubmissionURL'
#     assert results.readable_output == mock_results.get('readable_output')


# def test_url_screenshot_get_command(client, requests_mock):
#     """
#         When:
#         Given:
#         Then:
#         """
#     args = {}
#     mock_response_url_screenshot_get = load_json(
#         './test_data/outputs/url_screenshot_get.json')
#     mock_results = load_json(
#         './test_data/outputs/url_screenshot_get_command.json')
#     requests_mock.post(SERVER_URL, json=mock_response_url_screenshot_get)
#     results = url_screenshot_get_command(client=client)
