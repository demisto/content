import pytest
from test_data.test_data import *
from Netcraft import Client
# import CommonServerPython
# import json
# import yaml
# from unittest import mock
# import Netcraft
# import requests

MOCK_CLIENT = Client(
    verify=True,
    proxy=True,
    ok_codes=(200,),
    headers={}
)


def test_attack_report_command(mocker):
    '''
    Given:
        - TODO.

    When:
        - Running the "netcraft-attack-report" command.

    Then:
        - Report a new attack or authorise an existing attack in the Takedown service.
    '''
    from Netcraft import attack_report_command

    request = mocker.patch.object(Client, '_http_request', return_value=attack_report.api_response)

    result = attack_report_command(attack_report.args, MOCK_CLIENT)

    assert attack_report.outputs.outputs == result.outputs
    assert attack_report.outputs.outputs_key_field == result.outputs_key_field
    assert attack_report.outputs.outputs_prefix == result.outputs_prefix
    assert attack_report.outputs.raw_response == result.raw_response
    assert attack_report.outputs.readable_output == result.readable_output

    request.assert_called_with(
        *attack_report.http_func_args['args'],
        **attack_report.http_func_args['kwargs']
    )


def test_takedown_list_command(mocker):
    '''
    Given:
        - TODO.

    When:
        - Running the "netcraft-takedown-list" command.

    Then:
        - Get a list of takedown objects.
    '''
    from Netcraft import takedown_list_command

    request = mocker.patch.object(Client, '_http_request', return_value=takedown_list.api_response)

    result = takedown_list_command(takedown_list.args, MOCK_CLIENT)

    assert takedown_list.outputs.outputs == result.outputs
    assert takedown_list.outputs.outputs_key_field == result.outputs_key_field
    assert takedown_list.outputs.outputs_prefix == result.outputs_prefix
    assert takedown_list.outputs.raw_response == result.raw_response
    assert takedown_list.outputs.readable_output == result.readable_output

    request.assert_called_with(
        *takedown_list.http_func_args['args'],
        **takedown_list.http_func_args['kwargs']
    )


def test_takedown_update_command(mocker):
    '''
    Given:
        - TODO.

    When:
        - Running the "netcraft-takedown-update" command.

    Then:
        - Update one or more fields related to a takedown.
    '''
    from Netcraft import takedown_update_command

    request = mocker.patch.object(Client, '_http_request', return_value=takedown_update.api_response)

    result = takedown_update_command(takedown_update.args, MOCK_CLIENT)

    assert takedown_update.outputs.outputs == result.outputs
    assert takedown_update.outputs.outputs_key_field == result.outputs_key_field
    assert takedown_update.outputs.outputs_prefix == result.outputs_prefix
    assert takedown_update.outputs.raw_response == result.raw_response
    assert takedown_update.outputs.readable_output == result.readable_output

    request.assert_called_with(
        *takedown_update.http_func_args['args'],
        **takedown_update.http_func_args['kwargs']
    )


def test_takedown_escalate_command(mocker):
    '''
    Given:
        - TODO.

    When:
        - Running the "netcraft-takedown-escalate" command.

    Then:
        - Escalate an automated takedown to a managed takedown.
    '''
    from Netcraft import takedown_escalate_command

    request = mocker.patch.object(Client, '_http_request', return_value=takedown_escalate.api_response)

    result = takedown_escalate_command(takedown_escalate.args, MOCK_CLIENT)

    assert takedown_escalate.outputs.outputs == result.outputs
    assert takedown_escalate.outputs.outputs_key_field == result.outputs_key_field
    assert takedown_escalate.outputs.outputs_prefix == result.outputs_prefix
    assert takedown_escalate.outputs.raw_response == result.raw_response
    assert takedown_escalate.outputs.readable_output == result.readable_output

    request.assert_called_with(
        *takedown_escalate.http_func_args['args'],
        **takedown_escalate.http_func_args['kwargs']
    )


def test_takedown_note_create_command(mocker):
    '''
    Given:
        - TODO.

    When:
        - Running the "netcraft-takedown-note-create" command.

    Then:
        - Add a new note to an existing takedown.
    '''
    from Netcraft import takedown_note_create_command

    request = mocker.patch.object(Client, '_http_request', return_value=takedown_note_create.api_response)

    result = takedown_note_create_command(takedown_note_create.args, MOCK_CLIENT)

    assert takedown_note_create.outputs.outputs == result.outputs
    assert takedown_note_create.outputs.outputs_key_field == result.outputs_key_field
    assert takedown_note_create.outputs.outputs_prefix == result.outputs_prefix
    assert takedown_note_create.outputs.raw_response == result.raw_response
    assert takedown_note_create.outputs.readable_output == result.readable_output

    request.assert_called_with(
        *takedown_note_create.http_func_args['args'],
        **takedown_note_create.http_func_args['kwargs']
    )


def test_takedown_note_list_command(mocker):
    '''
    Given:
        - TODO.

    When:
        - Running the "netcraft-takedown-note-list" command.

    Then:
        - Retrieve details of notes that have been added to takedowns.
    '''
    from Netcraft import takedown_note_list_command

    request = mocker.patch.object(Client, '_http_request', return_value=takedown_note_list.api_response)

    result = takedown_note_list_command(takedown_note_list.args, MOCK_CLIENT)

    assert takedown_note_list.outputs.outputs == result.outputs
    assert takedown_note_list.outputs.outputs_key_field == result.outputs_key_field
    assert takedown_note_list.outputs.outputs_prefix == result.outputs_prefix
    assert takedown_note_list.outputs.raw_response == result.raw_response
    assert takedown_note_list.outputs.readable_output == result.readable_output

    request.assert_called_with(
        *takedown_note_list.http_func_args['args'],
        **takedown_note_list.http_func_args['kwargs']
    )


def test_attack_type_list_command(mocker):
    '''
    Given:
        - TODO.

    When:
        - Running the "netcraft-attack-type-list" command.

    Then:
        - Get information on the attack types that are available under a given region.
    '''
    from Netcraft import attack_type_list_command

    request = mocker.patch.object(Client, '_http_request', return_value=attack_type_list.api_response)

    result = attack_type_list_command(attack_type_list.args, MOCK_CLIENT)

    assert attack_type_list.outputs.outputs == result.outputs
    assert attack_type_list.outputs.outputs_key_field == result.outputs_key_field
    assert attack_type_list.outputs.outputs_prefix == result.outputs_prefix
    assert attack_type_list.outputs.raw_response == result.raw_response
    assert attack_type_list.outputs.readable_output == result.readable_output

    request.assert_called_with(
        *attack_type_list.http_func_args['args'],
        **attack_type_list.http_func_args['kwargs']
    )


def test_submission_list_command(mocker):
    '''
    Given:
        - TODO.

    When:
        - Running the "netcraft-submission-list" command.

    Then:
        - Get basic information about a submissions.
    '''
    from Netcraft import submission_list_command

    request = mocker.patch.object(Client, '_http_request', return_value=submission_list.api_response)

    result = submission_list_command(submission_list.args, MOCK_CLIENT)

    assert submission_list.outputs.outputs == result.outputs
    assert submission_list.outputs.outputs_key_field == result.outputs_key_field
    assert submission_list.outputs.outputs_prefix == result.outputs_prefix
    assert submission_list.outputs.raw_response == result.raw_response
    assert submission_list.outputs.readable_output == result.readable_output

    request.assert_called_with(
        *submission_list.http_func_args['args'],
        **submission_list.http_func_args['kwargs']
    )


def test_file_report_submit_command(mocker):
    '''
    Given:
        - TODO.

    When:
        - Running the "netcraft-file-report-submit" command.

    Then:
        - Report files to Netcraft for analysis.
    '''
    from Netcraft import file_report_submit_command

    request = mocker.patch.object(Client, '_http_request', return_value=file_report_submit.api_response)

    result = file_report_submit_command(file_report_submit.args, MOCK_CLIENT)

    assert file_report_submit.outputs.outputs == result.outputs
    assert file_report_submit.outputs.outputs_key_field == result.outputs_key_field
    assert file_report_submit.outputs.outputs_prefix == result.outputs_prefix
    assert file_report_submit.outputs.raw_response == result.raw_response
    assert file_report_submit.outputs.readable_output == result.readable_output

    request.assert_called_with(
        *file_report_submit.http_func_args['args'],
        **file_report_submit.http_func_args['kwargs']
    )


def test_submission_file_list_command(mocker):
    '''
    Given:
        - TODO.

    When:
        - Running the "netcraft-submission-file-list" command.

    Then:
        - Get basic information about a submission's files.
    '''
    from Netcraft import submission_file_list_command

    request = mocker.patch.object(Client, '_http_request', return_value=submission_file_list.api_response)

    result = submission_file_list_command(submission_file_list.args, MOCK_CLIENT)

    assert submission_file_list.outputs.outputs == result.outputs
    assert submission_file_list.outputs.outputs_key_field == result.outputs_key_field
    assert submission_file_list.outputs.outputs_prefix == result.outputs_prefix
    assert submission_file_list.outputs.raw_response == result.raw_response
    assert submission_file_list.outputs.readable_output == result.readable_output

    request.assert_called_with(
        *submission_file_list.http_func_args['args'],
        **submission_file_list.http_func_args['kwargs']
    )


def test_email_report_submit_command(mocker):
    '''
    Given:
        - TODO.

    When:
        - Running the "netcraft-email-report-submit" command.

    Then:
        - Report email messages to Netcraft for analysis.
    '''
    from Netcraft import email_report_submit_command

    request = mocker.patch.object(Client, '_http_request', return_value=email_report_submit.api_response)

    result = email_report_submit_command(email_report_submit.args, MOCK_CLIENT)

    assert email_report_submit.outputs.outputs == result.outputs
    assert email_report_submit.outputs.outputs_key_field == result.outputs_key_field
    assert email_report_submit.outputs.outputs_prefix == result.outputs_prefix
    assert email_report_submit.outputs.raw_response == result.raw_response
    assert email_report_submit.outputs.readable_output == result.readable_output

    request.assert_called_with(
        *email_report_submit.http_func_args['args'],
        **email_report_submit.http_func_args['kwargs']
    )


def test_submission_mail_get_command(mocker):
    '''
    Given:
        - TODO.

    When:
        - Running the "netcraft-submission-mail-get" command.

    Then:
        - Get basic information about a submission's mail.
    '''
    from Netcraft import submission_mail_get_command

    request = mocker.patch.object(Client, '_http_request', return_value=submission_mail_get.api_response)

    result = submission_mail_get_command(submission_mail_get.args, MOCK_CLIENT)

    assert submission_mail_get.outputs.outputs == result.outputs
    assert submission_mail_get.outputs.outputs_key_field == result.outputs_key_field
    assert submission_mail_get.outputs.outputs_prefix == result.outputs_prefix
    assert submission_mail_get.outputs.raw_response == result.raw_response
    assert submission_mail_get.outputs.readable_output == result.readable_output

    request.assert_called_with(
        *submission_mail_get.http_func_args['args'],
        **submission_mail_get.http_func_args['kwargs']
    )


def test_url_report_submit_command(mocker):
    '''
    Given:
        - TODO.

    When:
        - Running the "netcraft-url-report-submit" command.

    Then:
        - Report URLs to Netcraft for analysis.
    '''
    from Netcraft import url_report_submit_command

    request = mocker.patch.object(Client, '_http_request', return_value=url_report_submit.api_response)

    result = url_report_submit_command(url_report_submit.args, MOCK_CLIENT)

    assert url_report_submit.outputs.outputs == result.outputs
    assert url_report_submit.outputs.outputs_key_field == result.outputs_key_field
    assert url_report_submit.outputs.outputs_prefix == result.outputs_prefix
    assert url_report_submit.outputs.raw_response == result.raw_response
    assert url_report_submit.outputs.readable_output == result.readable_output

    request.assert_called_with(
        *url_report_submit.http_func_args['args'],
        **url_report_submit.http_func_args['kwargs']
    )


def test_submission_url_list_command(mocker):
    '''
    Given:
        - TODO.

    When:
        - Running the "netcraft-submission-url-list" command.

    Then:
        - Get basic information about a submission's URLs.
    '''
    from Netcraft import submission_url_list_command

    request = mocker.patch.object(Client, '_http_request', return_value=submission_url_list.api_response)

    result = submission_url_list_command(submission_url_list.args, MOCK_CLIENT)

    assert submission_url_list.outputs.outputs == result.outputs
    assert submission_url_list.outputs.outputs_key_field == result.outputs_key_field
    assert submission_url_list.outputs.outputs_prefix == result.outputs_prefix
    assert submission_url_list.outputs.raw_response == result.raw_response
    assert submission_url_list.outputs.readable_output == result.readable_output

    request.assert_called_with(
        *submission_url_list.http_func_args['args'],
        **submission_url_list.http_func_args['kwargs']
    )


def test_file_screenshot_get_command(mocker):
    '''
    Given:
        - TODO.

    When:
        - Running the "netcraft-file-screenshot-get" command.

    Then:
        - Get a screenshot for a file associated with a submission.
    '''
    from Netcraft import file_screenshot_get_command

    request = mocker.patch.object(Client, '_http_request', return_value=file_screenshot_get.api_response)

    result = file_screenshot_get_command(file_screenshot_get.args, MOCK_CLIENT)

    assert file_screenshot_get.outputs == result['File']

    request.assert_called_with(
        *file_screenshot_get.http_func_args['args'],
        **file_screenshot_get.http_func_args['kwargs']
    )


def test_mail_screenshot_get_command(mocker):
    '''
    Given:
        - TODO.

    When:
        - Running the "netcraft-mail-screenshot-get" command.

    Then:
        - Get a screenshot for the mail associated with a submission.
    '''
    from Netcraft import mail_screenshot_get_command

    request = mocker.patch.object(Client, '_http_request', return_value=mail_screenshot_get.api_response)

    result = mail_screenshot_get_command(mail_screenshot_get.args, MOCK_CLIENT)

    assert mail_screenshot_get.outputs == result['File']

    request.assert_called_with(
        *mail_screenshot_get.http_func_args['args'],
        **mail_screenshot_get.http_func_args['kwargs']
    )


def test_url_screenshot_get_command(mocker):
    '''
    Given:
        - TODO.

    When:
        - Running the "netcraft-url-screenshot-get" command.

    Then:
        - Download associated screenshots for a specified URL.
    '''
    from Netcraft import url_screenshot_get_command

    request = mocker.patch.object(Client, '_http_request', return_value=url_screenshot_get.api_response)

    result = url_screenshot_get_command(url_screenshot_get.args, MOCK_CLIENT)

    assert url_screenshot_get.outputs == result['File']

    request.assert_called_with(
        *url_screenshot_get.http_func_args['args'],
        **url_screenshot_get.http_func_args['kwargs']
    )
