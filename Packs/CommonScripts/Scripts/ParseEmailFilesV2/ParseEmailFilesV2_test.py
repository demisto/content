import pytest

import demistomock as demisto
from CommonServerPython import *
from ParseEmailFilesV2 import main, data_to_md, parse_nesting_level


def exec_command_for_file(
        file_path,
        info="RFC 822 mail text, with CRLF line terminators",
        file_name=None,
        file_type="",
):
    """
    Return a executeCommand function which will return the passed path as an entry to the call 'getFilePath'

    Arguments:
        file_path {string} -- file name of file residing in test_data dir

    Raises:
        ValueError: if call with differed name from getFilePath or getEntry

    Returns:
        [function] -- function to be used for mocking
    """
    if not file_name:
        file_name = file_path
    path = 'test_data/' + file_path

    def executeCommand(name, args=None):
        if name == 'getFilePath':
            return [
                {
                    'Type': entryTypes['note'],
                    'Contents': {
                        'path': path,
                        'name': file_name
                    }
                }
            ]
        elif name == 'getEntry':
            return [
                {
                    'Type': entryTypes['file'],
                    'FileMetadata': {
                        'info': info,
                        'type': file_type
                    }
                }
            ]
        else:
            raise ValueError('Unimplemented command called: {}'.format(name))

    return executeCommand


def test_eml_type(mocker):
    """
    Given:
        - A eml file
    When:
        - run the ParseEmailFilesV2 script
    Then:
        - Ensure its was parsed successfully
    """
    def executeCommand(name, args=None):
        if name == 'getFilePath':
            return [
                {
                    'Type': entryTypes['note'],
                    'Contents': {
                        'path': 'test_data/smtp_email_type.eml',
                        'name': 'smtp_email_type.eml'
                    }
                }
            ]
        elif name == 'getEntry':
            return [
                {
                    'Type': entryTypes['file'],
                    'FileMetadata': {
                        'info': 'SMTP mail, UTF-8 Unicode text, with CRLF terminators'
                    }
                }
            ]
        else:
            raise ValueError('Unimplemented command called: {}'.format(name))

    mocker.patch.object(demisto, 'args', return_value={'entryid': 'test'})
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    mocker.patch.object(demisto, 'context')
    mocker.patch.object(demisto, 'dt', return_value=['SMTP mail, UTF-8 Unicode text, with CRLF terminators'])
    mocker.patch.object(demisto, 'results')
    # validate our mocks are good
    assert demisto.args()['entryid'] == 'test'
    # assert demisto.executeCommand('getFilePath', {})[0]['Type'] == entryTypes['note']
    main()
    assert demisto.results.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0]['Type'] == entryTypes['note']
    assert results[0]['EntryContext']['Email']['Subject'] == 'Test Smtp Email'


def test_eml_contains_eml(mocker):
    """
    Given:
        - A eml file contains eml
    When:
        - run the ParseEmailFilesV2 script
    Then:
        - Ensure the was parsed successfully
        - Ensure both files was parsed
        - Ensure the attachments was returned
    """
    def executeCommand(name, args=None):
        if name == 'getFilePath':
            return [
                {
                    'Type': entryTypes['note'],
                    'Contents': {
                        'path': 'test_data/Fwd_test-inner_attachment_eml.eml',
                        'name': 'Fwd_test-inner_attachment_eml.eml'
                    }
                }
            ]
        elif name == 'getEntry':
            return [
                {
                    'Type': entryTypes['file'],
                    'FileMetadata': {
                        'info': 'news or mail text, ASCII text'
                    }
                }
            ]
        else:
            raise ValueError('Unimplemented command called: {}'.format(name))

    mocker.patch.object(demisto, 'args', return_value={'entryid': 'test'})
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    mocker.patch.object(demisto, 'context')
    mocker.patch.object(demisto, 'dt', return_value=['news or mail text, ASCII text'])
    mocker.patch.object(demisto, 'results')
    # validate our mocks are good
    assert demisto.args()['entryid'] == 'test'

    main()
    assert demisto.results.call_count == 4
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args_list

    assert len(results) == 4

    assert results[0].args[0]['File'] == 'ArcSight_ESM_fixes.yml'

    assert results[1].args[0]['File'] == 'test - inner attachment eml.eml'

    assert results[2].args[0]['EntryContext']['Email']['Subject'] == 'Fwd: test - inner attachment eml'
    assert 'ArcSight_ESM_fixes.yml' in results[2].args[0]['EntryContext']['Email']['Attachments']
    assert 'ArcSight_ESM_fixes.yml' in results[2].args[0]['EntryContext']['Email']['AttachmentsData'][0]['Name']
    assert 'test - inner attachment eml.eml' in results[2].args[0]['EntryContext']['Email']['Attachments']
    assert 'test - inner attachment eml.eml' in results[2].args[0]['EntryContext']['Email']['AttachmentsData'][1]['Name']
    assert results[2].args[0]['EntryContext']['Email']['Depth'] == 0

    assert results[3].args[0]['EntryContext']['Email']["Subject"] == 'test - inner attachment eml'
    assert results[3].args[0]['EntryContext']['Email']['Depth'] == 1


def test_eml_contains_msg(mocker):
    """
    Given:
        - A eml file contains msg
    When:
        - run the ParseEmailFilesV2 script
    Then:
        - Ensure the was parsed successfully
        - Ensure both files was parsed
        - Ensure the attachments was returned
    """
    def executeCommand(name, args=None):
        if name == 'getFilePath':
            return [
                {
                    'Type': entryTypes['note'],
                    'Contents': {
                        'path': 'test_data/DONT_OPEN-MALICIOUS.eml',
                        'name': 'DONT_OPEN-MALICIOUS.eml'
                    }
                }
            ]
        elif name == 'getEntry':
            return [
                {
                    'Type': entryTypes['file'],
                    'FileMetadata': {
                        'info': 'news or mail text, ASCII text'
                    }
                }
            ]
        else:
            raise ValueError('Unimplemented command called: {}'.format(name))

    mocker.patch.object(demisto, 'args', return_value={'entryid': 'test'})
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    mocker.patch.object(demisto, 'context')
    mocker.patch.object(demisto, 'dt', return_value=['news or mail text, ASCII text'])
    mocker.patch.object(demisto, 'results')
    # validate our mocks are good
    assert demisto.args()['entryid'] == 'test'

    main()
    results = demisto.results.call_args_list

    assert demisto.results.call_count == 3

    assert len(results) == 3

    assert results[0].args[0]['File'] == 'Attacker+email+.msg'

    assert results[1].args[0]['EntryContext']['Email']['Subject'] == 'DONT OPEN - MALICIOS'
    assert 'Attacker+email+.msg' in results[1].args[0]['EntryContext']['Email']['Attachments']
    assert 'Attacker+email+.msg' in results[1].args[0]['EntryContext']['Email']['AttachmentsData'][0]['Name']
    assert results[1].args[0]['EntryContext']['Email']['Depth'] == 0

    assert results[2].args[0]['EntryContext']['Email']["Subject"] == 'Attacker email'
    assert results[2].args[0]['EntryContext']['Email']['Depth'] == 1


def test_eml_contains_eml_depth(mocker):
    """
    Given:
        - A eml file contains eml
        - depth = 1
    When:
        - run the ParseEmailFilesV2 script
    Then:
        - Ensure only the first mail is parsed
        - Ensure the attachments of the first mail was returned
    """
    def executeCommand(name, args=None):
        if name == 'getFilePath':
            return [
                {
                    'Type': entryTypes['note'],
                    'Contents': {
                        'path': 'test_data/Fwd_test-inner_attachment_eml.eml',
                        'name': 'Fwd_test-inner_attachment_eml.eml'
                    }
                }
            ]
        elif name == 'getEntry':
            return [
                {
                    'Type': entryTypes['file'],
                    'FileMetadata': {
                        'info': 'news or mail text, ASCII text'
                    }
                }
            ]
        else:
            raise ValueError('Unimplemented command called: {}'.format(name))

    mocker.patch.object(demisto, 'args', return_value={'entryid': 'test', 'max_depth': '1'})
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    mocker.patch.object(demisto, 'context')
    mocker.patch.object(demisto, 'dt', return_value=['news or mail text, ASCII text'])
    mocker.patch.object(demisto, 'results')
    # validate our mocks are good
    assert demisto.args()['entryid'] == 'test'

    main()
    assert demisto.results.call_count == 3
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args_list

    assert len(results) == 3

    assert results[0].args[0]['File'] == 'ArcSight_ESM_fixes.yml'

    assert results[1].args[0]['File'] == 'test - inner attachment eml.eml'

    assert results[2].args[0]['EntryContext']['Email']['Depth'] == 0
    assert 'ArcSight_ESM_fixes.yml' in results[2].args[0]['EntryContext']['Email']['Attachments']
    assert 'ArcSight_ESM_fixes.yml' in results[2].args[0]['EntryContext']['Email']['AttachmentsData'][0]['Name']
    assert 'test - inner attachment eml.eml' in results[2].args[0]['EntryContext']['Email']['Attachments']
    assert 'test - inner attachment eml.eml' in results[2].args[0]['EntryContext']['Email']['AttachmentsData'][1]['Name']


def test_msg(mocker):
    """
    Given:
        - A msg file
    When:
        - run the ParseEmailFilesV2 script
    Then:
        - Ensure its was parsed successfully
    """
    info = 'CDFV2 Microsoft Outlook Message'
    mocker.patch.object(demisto, 'args', return_value={'entryid': 'test'})
    mocker.patch.object(demisto, 'executeCommand', side_effect=exec_command_for_file('smime-p7s.msg', info=info))
    mocker.patch.object(demisto, 'context')
    mocker.patch.object(demisto, 'dt', return_value=['CDFV2 Microsoft Outlook Message'])
    mocker.patch.object(demisto, 'results')
    # validate our mocks are good
    assert demisto.args()['entryid'] == 'test'
    main()
    # assert demisto.results.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0]['Type'] == entryTypes['note']
    assert results[0]['EntryContext']['Email']['Subject'] == 'test'


def test_no_content_type_file(mocker):
    """
    Given:
        - A eml with no_content_type
    When:
        - run the ParseEmailFilesV2 script
    Then:
        - Ensure its was parsed successfully
    """
    mocker.patch.object(demisto, 'args', return_value={'entryid': 'test'})
    mocker.patch.object(demisto, 'executeCommand',
                        side_effect=exec_command_for_file('no_content_type.eml', info="ascii text"))
    mocker.patch.object(demisto, 'context')
    mocker.patch.object(demisto, 'dt', return_value=['ascii text'])
    mocker.patch.object(demisto, 'results')
    main()
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0]['Type'] == entryTypes['note']
    assert results[0]['EntryContext']['Email']['Subject'] == 'No content type'


def test_no_content_file(mocker):
    """
    Given:
        - A eml without content
    When:
        - run the ParseEmailFilesV2 script
    Then:
        - Ensure a error is returned
    """
    mocker.patch.object(demisto, 'args', return_value={'entryid': 'test'})
    mocker.patch.object(demisto, 'executeCommand',
                        side_effect=exec_command_for_file('no_content.eml', info="ascii text"))
    mocker.patch.object(demisto, 'context')
    mocker.patch.object(demisto, 'dt', return_value=['ascii text'])
    mocker.patch.object(demisto, 'results')
    try:
        main()
    except SystemExit:
        gotexception = True
    assert gotexception
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert 'Could not extract email from file' in results[0]['Contents']


def test_md_output_empty_body_text():
    """
    Given:
     - The input email_data where the value of the 'Text' field is None.

    When:
     - Running the data_to_md command on this email_data.

    Then:
     - Validate that output the md doesn't contain a row for the 'Text' field.
    """
    email_data = {
        'To': 'email1@paloaltonetworks.com',
        'From': 'email2@paloaltonetworks.com',
        'Text': None
    }
    expected = u'### Results:\n' \
               u'* From:\temail2@paloaltonetworks.com\n' \
               u'* To:\temail1@paloaltonetworks.com\n' \
               u'* CC:\t\n' \
               u'* Subject:\t\n' \
               u'* Attachments:\t\n\n\n' \
               u'### HeadersMap\n' \
               u'**No entries.**\n'

    md = data_to_md(email_data)
    assert expected == md

    email_data = {
        'To': 'email1@paloaltonetworks.com',
        'From': 'email2@paloaltonetworks.com',
    }
    expected = u'### Results:\n' \
               u'* From:\temail2@paloaltonetworks.com\n' \
               u'* To:\temail1@paloaltonetworks.com\n' \
               u'* CC:\t\n' \
               u'* Subject:\t\n' \
               u'* Attachments:\t\n\n\n' \
               u'### HeadersMap\n' \
               u'**No entries.**\n'

    md = data_to_md(email_data)
    assert expected == md


def test_md_output_with_body_text():
    """
    Given:
     - The input email_data with a value in the 'Text' field.

    When:
     - Running the data_to_md command on this email_data.

    Then:
     - Validate that the output md contains a row for the 'Text' field.
    """
    email_data = {
        'To': 'email1@paloaltonetworks.com',
        'From': 'email2@paloaltonetworks.com',
        'Text': '<email text>'
    }
    expected = u'### Results:\n' \
               u'* From:\temail2@paloaltonetworks.com\n' \
               u'* To:\temail1@paloaltonetworks.com\n' \
               u'* CC:\t\n' \
               u'* Subject:\t\n' \
               u'* Body/Text:\t[email text]\n' \
               u'* Attachments:\t\n\n\n' \
               u'### HeadersMap\n' \
               u'**No entries.**\n'

    md = data_to_md(email_data)
    assert expected == md


@pytest.mark.parametrize('nesting_level_to_return, output, res', [('All files', ['output1', 'output2', 'output3'],
                                                                   ['output1', 'output2', 'output3']),
                                                                  ('Outer file', ['output1', 'output2', 'output3'],
                                                                   ['output1']),
                                                                  ('Inner file', ['output1', 'output2', 'output3'],
                                                                   ['output3'])])
def test_parse_nesting_level(nesting_level_to_return, output, res):
    """
    Given:
    - parsed email output, nesting_level_to_return param - All files.
    - parsed email output, nesting_level_to_return param - Outer file.
    - parsed email output, nesting_level_to_return param - Inner file.

    When:
    calling the parse_nesting_level function.

    Then:
    - Validating the that all outputs are returned.
    - Validating the that only output1 is returned.
    - Validating the that only output3 is returned.
    """
    assert parse_nesting_level(nesting_level_to_return, output) == res


@pytest.mark.parametrize('nesting_level_to_return, results_len, depth, results_index', [('All files', 4, 0, 2),
                                                                                        ('Outer file', 3, 0, 2),
                                                                                        ('Inner file', 1, 1, 0)])
def test_eml_contains_eml_nesting_level(mocker, nesting_level_to_return, results_len, depth, results_index):

    """
    Given:
    - A eml file contains eml, nesting_level_to_return param - All files.
    - A eml file contains eml, nesting_level_to_return param - Outer file.
    - A eml file contains eml, nesting_level_to_return param - Inner file.

    When: parsing the eml file.

    Then:
    - Validating the that call_args_list length is 4 (2 parsed eml files and 2 attachments).
    - Validating the that call_args_list length is 3 (the outer parsed eml file and is 2 attachments).
    - Validating the that call_args_list length is 1 ( the Inner parsed eml file).
    """

    def executeCommand(name, args=None):
        if name == 'getFilePath':
            return [
                {
                    'Type': entryTypes['note'],
                    'Contents': {
                        'path': 'test_data/Fwd_test-inner_attachment_eml.eml',
                        'name': 'Fwd_test-inner_attachment_eml.eml'
                    }
                }
            ]
        elif name == 'getEntry':
            return [
                {
                    'Type': entryTypes['file'],
                    'FileMetadata': {
                        'info': 'news or mail text, ASCII text'
                    }
                }
            ]
        else:
            raise ValueError('Unimplemented command called: {}'.format(name))

    mocker.patch.object(demisto, 'args', return_value={'entryid': 'test',
                                                       'nesting_level_to_return': nesting_level_to_return})
    mocker.patch.object(demisto, 'context')
    mocker.patch.object(demisto, 'dt', return_value=['news or mail text, ASCII text'])
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    mocker.patch.object(demisto, 'results')
    main()
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args_list

    assert len(results) == results_len
    assert results[results_index].args[0]['EntryContext']['Email']['Depth'] == depth


def test_eml_contains_empty_htm_not_containing_file_data(mocker):
    """
        Given: An email containing both an empty text file and a base64 encoded htm file.
        When: Parsing a valid email file with default parameters.
        Then: FileData is not one of the attachments' data attributes returned.
        """
    mocker.patch.object(demisto, 'args', return_value={'entryid': 'test'})
    mocker.patch.object(demisto, 'executeCommand',
                        side_effect=exec_command_for_file('eml_contains_emptytxt_htm_file.eml'))
    mocker.patch.object(demisto, 'results')

    assert demisto.args()['entryid'] == 'test'
    main()

    results = demisto.results.call_args[0]

    assert results[0]['EntryContext']['Email']['AttachmentsData'][0]['FileData'] is None
