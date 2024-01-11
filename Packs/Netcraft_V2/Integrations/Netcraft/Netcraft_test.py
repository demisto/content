import pytest
from test_data.data import *  # nopycln: import
from Netcraft import Client
import demistomock as demisto
from CommonServerPython import ScheduledCommand, DemistoException


MOCK_CLIENT = Client(
    {
        'takedown_url': 'https://takedown.netcraft.com/',
        'submission_url': 'https://report.netcraft.com/',
    },
    verify=True,
    proxy=True,
    ok_codes=(200,),
    headers={}
)


def mock_demisto(mocker):
    mocker.patch.object(demisto, 'params')
    mocker.patch.object(demisto, 'args')
    mocker.patch.object(demisto, 'incidents')
    mocker.patch.object(demisto, 'debug')


@pytest.mark.parametrize("input_dict,keys,expected", [
    ({'a': 1, 'b': 0}, ['a'], {'a': True, 'b': 0}),
    ({'a': '1', 'b': '0'}, ['a', 'b'], {'a': True, 'b': False}),
    ({'x': 'yes', 'y': 'no'}, ['x'], {'x': 'yes', 'y': 'no'}),
    ({'x': 'yes', 'y': 'no'}, [], {'x': 'yes', 'y': 'no'}),
    ({'x': True, 'y': 'no'}, ['x'], {'x': True, 'y': 'no'}),
])
def test_convert_binary_keys_to_bool(input_dict, keys, expected):
    from Netcraft import convert_binary_keys_to_bool
    convert_binary_keys_to_bool(input_dict, *keys)
    assert input_dict == expected


def mock_client_func_for_paginate_with_page_num_and_size(args, pagination_args):
    page = pagination_args['page']
    count = pagination_args['count']
    assert args == 'args'
    return {
        "results": list(range((page - 1) * count, page * count))
    }


@pytest.mark.parametrize('page, page_size, limit, expected', [
    (2, 10, None, list(range(10, 20))),
    (None, 100, 50, list(range(50))),
    (None, None, 45, list(range(45))),
    (None, None, 2, list(range(2)))
])
def test_paginate_with_page_num_and_size(page, page_size, limit, expected):

    from Netcraft import paginate_with_page_num_and_size

    result = paginate_with_page_num_and_size(
        mock_client_func_for_paginate_with_page_num_and_size,
        'args',
        page=page,
        page_size=page_size,
        limit=limit,
        pages_key_path=['results'],
        api_limit=10
    )

    assert result == expected


def mock_client_func_for_paginate_with_token(args):
    marker = args['marker'] or 0
    page_size = args['page_size']
    assert args['params'] == 'any'
    return {
        "results": list(range(marker, marker + page_size)),
        "marker": marker + page_size
    }


@pytest.mark.parametrize('token, page_size, limit, expected', [
    (1, 3, 10, ([1, 2, 3], 4)),
    (None, 3, 10, ([0, 1, 2, 3, 4, 5, 6, 7, 8, 9], 10)),
    (None, None, 13, ([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12], 13)),
])
def test_paginate_with_token(token, page_size, limit, expected):

    from Netcraft import paginate_with_token

    result = paginate_with_token(
        mock_client_func_for_paginate_with_token,
        api_params={'params': 'any'},
        next_token=token,
        page_size=page_size,
        limit=limit,
        pages_key_path=['results'],
        api_limit=5
    )

    assert result == expected


@pytest.mark.parametrize(
    'data',
    [
        fetch_incidents,
        fetch_incidents_first_run,
    ]
)
def test_fetch_incidents(mocker, data):
    '''
    Given:
        - A server call to fetch incidents.

    When:
        - Fetching incidents.

    Then:
        - Fetch Netcraft takedowns as incidents.
    '''
    import Netcraft

    Netcraft.PARAMS = data.params
    mocker.patch.object(demisto, 'getLastRun', return_value=data.last_run)
    setLastRun = mocker.patch.object(demisto, 'setLastRun')
    request = mocker.patch.object(Client, '_http_request', return_value=data.api_response)

    incidents = Netcraft.fetch_incidents(MOCK_CLIENT)
    setLastRun.assert_called_with(data.set_last_run)
    request.assert_called_with(
        *data.http_func_args['args'],
        **data.http_func_args['kwargs']
    )
    assert incidents == data.outputs


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

    getFilePath = mocker.patch.object(
        demisto, 'getFilePath', return_value={'name': 'file name', 'path': 'test_data/mock_file.txt'})
    request = mocker.patch.object(Client, '_http_request', return_value=attack_report.api_response)

    result = attack_report_command(attack_report.args, MOCK_CLIENT)

    assert attack_report.outputs.outputs == result.outputs
    assert attack_report.outputs.outputs_key_field == result.outputs_key_field
    assert attack_report.outputs.outputs_prefix == result.outputs_prefix
    assert attack_report.outputs.raw_response == result.raw_response
    assert attack_report.outputs.readable_output == result.readable_output
    assert str(request.call_args.kwargs.pop('files')['evidence']) == "<_io.BufferedReader name='test_data/mock_file.txt'>"

    getFilePath.assert_called_with(attack_report.args.get('entry_id'))
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
    assert submission_list.outputs.readable_output == result.readable_output

    request.assert_called_with(
        *submission_list.http_func_args['args'],
        **submission_list.http_func_args['kwargs']
    )


def test_submission_list_command_with_uuid(mocker):
    '''
    Given:
        - TODO.

    When:
        - Running the "netcraft-submission-list" command.

    Then:
        - Get basic information about a submissions.
    '''
    from Netcraft import submission_list_command

    request = mocker.patch.object(Client, '_http_request', return_value=submission_list_with_uuid.api_response)

    result = submission_list_command(submission_list_with_uuid.args, MOCK_CLIENT)

    assert submission_list_with_uuid.outputs.outputs == result.outputs
    assert submission_list_with_uuid.outputs.outputs_key_field == result.outputs_key_field
    assert submission_list_with_uuid.outputs.outputs_prefix == result.outputs_prefix
    assert submission_list_with_uuid.outputs.readable_output == result.readable_output

    request.assert_called_with(
        *submission_list_with_uuid.http_func_args['args'],
        **submission_list_with_uuid.http_func_args['kwargs']
    )


@pytest.mark.parametrize(
    'data',
    [
        file_report_submit_with_entry_id,
        file_report_submit_with_file_name_and_content
    ]
)
def test_file_report_submit_command(mocker, data):
    '''
    Given:
        - TODO.

    When:
        - Running the "netcraft-file-report-submit" command.

    Then:
        - Report files to Netcraft for analysis.
    '''
    import Netcraft

    mocker.patch.object(ScheduledCommand, 'raise_error_if_not_supported')
    getFilePath = mocker.patch.object(
        demisto, 'getFilePath', return_value={'name': 'file name', 'path': 'test_data/mock_file.txt'})
    request = mocker.patch.object(Client, '_http_request', return_value=data.api_response)
    get_submission = mocker.patch.object(Netcraft, 'get_submission')

    Netcraft.file_report_submit_command(data.args, MOCK_CLIENT)

    get_submission.assert_called_with(*data.get_submission_call_args, MOCK_CLIENT)
    assert str(getFilePath.call_args_list) == data.getFilePath_call_args
    request.assert_called_with(
        *data.http_func_args['args'],
        **data.http_func_args['kwargs']
    )


def test_file_report_submit_command_error():
    '''
    Given:
        - Args without file_content and file_name or entry_id.

    When:
        - Running the "netcraft-file-report-submit" command.

    Then:
        - Raise an error.
    '''
    from Netcraft import file_report_submit_command

    with pytest.raises(DemistoException, match='A file must be provided. Use file_content and file_name OR entry_id'):
        file_report_submit_command({}, MOCK_CLIENT)


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
    import Netcraft

    mocker.patch.object(ScheduledCommand, 'raise_error_if_not_supported')
    request = mocker.patch.object(Client, '_http_request', return_value=email_report_submit.api_response)
    get_submission = mocker.patch.object(Netcraft, 'get_submission')

    Netcraft.email_report_submit_command(email_report_submit.args, MOCK_CLIENT)

    get_submission.assert_called_with(*email_report_submit.get_submission_call_args, MOCK_CLIENT)

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
    import Netcraft

    mocker.patch.object(ScheduledCommand, 'raise_error_if_not_supported')
    request = mocker.patch.object(Client, '_http_request', return_value=url_report_submit.api_response)
    get_submission = mocker.patch.object(Netcraft, 'get_submission')

    Netcraft.url_report_submit_command(url_report_submit.args, MOCK_CLIENT)

    get_submission.assert_called_with(*url_report_submit.get_submission_call_args, MOCK_CLIENT)

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
    fileResult = mocker.patch('Netcraft.fileResult')

    file_screenshot_get_command(file_screenshot_get.args, MOCK_CLIENT)

    fileResult.assert_called_with(file_screenshot_get.outputs, None, 9)

    request.assert_called_with(
        *file_screenshot_get.http_func_args['args'],
        **file_screenshot_get.http_func_args['kwargs']
    )


def test_file_screenshot_get_with_404(mocker):
    '''
    Given:
        - A request to get the screenshot of a given file which has no screenshot.

    When:
        - Running the "netcraft-file-screenshot-get" command.

    Then:
        - Return the message that the scan is not available.
    '''
    from Netcraft import file_screenshot_get_command

    request = mocker.patch.object(Client, '_http_request', return_value=file_screenshot_get_404.api_response)

    result = file_screenshot_get_command(file_screenshot_get_404.args, MOCK_CLIENT)

    assert file_screenshot_get_404.outputs == result.readable_output

    request.assert_called_with(
        *file_screenshot_get_404.http_func_args['args'],
        **file_screenshot_get_404.http_func_args['kwargs']
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
    fileResult = mocker.patch('Netcraft.fileResult')

    mail_screenshot_get_command(mail_screenshot_get.args, MOCK_CLIENT)

    fileResult.assert_called_with(mail_screenshot_get.outputs, None, 9)

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

    fileResult = mocker.patch('Netcraft.fileResult')
    request = mocker.patch.object(Client, '_http_request', return_value=url_screenshot_get.api_response)

    url_screenshot_get_command(url_screenshot_get.args, MOCK_CLIENT)

    fileResult.assert_called_with(url_screenshot_get.outputs, None, 9)

    request.assert_called_with(
        *url_screenshot_get.http_func_args['args'],
        **url_screenshot_get.http_func_args['kwargs']
    )
