from __future__ import print_function
from ParseEmailFiles import MsOxMessage, main, convert_to_unicode, unfold, handle_msg
from CommonServerPython import entryTypes
import demistomock as demisto
import pytest


def exec_command_for_file(file_path, info="RFC 822 mail text, with CRLF line terminators", file_name=None):
    """
    Return a executeCommand function which will return the passed path as an entry to the call 'getFilePath'

    Arguments:
        file_paht {string} -- file name of file residing in test_data dir

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
                        'info': info
                    }
                }
            ]
        else:
            raise ValueError('Unimplemented command called: {}'.format(name))

    return executeCommand


def test_msg_html_with_attachments():
    msg = MsOxMessage('test_data/html_attachment.msg')
    assert msg is not None
    msg_dict = msg.as_dict(max_depth=2)
    assert 'This is an html email' in msg_dict['Text']
    attachments_list = msg.get_all_attachments()
    assert len(attachments_list) == 1
    attach = attachments_list[0]
    assert attach.AttachFilename == 'dummy-attachment.txt'
    assert attach.AttachMimeTag == 'text/plain'
    assert attach.data == 'This is a text attachment'


def test_msg_utf_encoded_subject():
    msg = MsOxMessage('test_data/utf_subject.msg')
    assert msg is not None
    msg_dict = msg.as_dict(max_depth=2)
    # we test that subject which has utf-8 encoding (in the middle) is actually decoded
    assert '?utf-8' in msg_dict['HeadersMap']['Subject']
    subj = msg_dict['Subject']
    assert 'TESTING' in subj and '?utf-8' not in subj


def test_eml_smtp_type(mocker):
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
    mocker.patch.object(demisto, 'results')
    # validate our mocks are good
    assert demisto.args()['entryid'] == 'test'

    main()
    assert demisto.results.call_count == 5
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0]['Type'] == entryTypes['note']
    assert results[0]['EntryContext']['Email'][0]['Subject'] == 'Fwd: test - inner attachment eml'
    assert 'ArcSight_ESM_fixes.yml' in results[0]['EntryContext']['Email'][0]['Attachments']
    assert 'test - inner attachment eml.eml' in results[0]['EntryContext']['Email'][0]['Attachments']
    assert results[0]['EntryContext']['Email'][0]['Depth'] == 0
    assert results[0]['EntryContext']['Email'][1]["Subject"] == 'test - inner attachment eml'
    assert 'CS Training 2019 - EWS.pptx' in results[0]['EntryContext']['Email'][1]["Attachments"]
    assert results[0]['EntryContext']['Email'][1]['Depth'] == 1


def test_eml_contains_msg(mocker):
    def executeCommand(name, args=None):
        if name == 'getFilePath':
            return [
                {
                    'Type': entryTypes['note'],
                    'Contents': {
                        'path': 'test_data/DONT_OPEN-MALICIOS.eml',
                        'name': 'DONT_OPEN-MALICIOS.eml'
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
    mocker.patch.object(demisto, 'results')
    # validate our mocks are good
    assert demisto.args()['entryid'] == 'test'

    main()
    assert demisto.results.call_count == 3
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0]['Type'] == entryTypes['note']
    assert results[0]['EntryContext']['Email'][0]['Subject'] == 'DONT OPEN - MALICIOS'
    assert results[0]['EntryContext']['Email'][0]['Depth'] == 0

    assert 'Attacker+email+.msg' in results[0]['EntryContext']['Email'][0]['Attachments']
    assert results[0]['EntryContext']['Email'][1]["Subject"] == 'Attacker email'
    assert results[0]['EntryContext']['Email'][1]['Depth'] == 1


def test_eml_contains_eml_depth(mocker):
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
    mocker.patch.object(demisto, 'results')
    # validate our mocks are good
    assert demisto.args()['entryid'] == 'test'

    main()
    assert demisto.results.call_count == 3
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0]['Type'] == entryTypes['note']
    assert results[0]['EntryContext']['Email']['Subject'] == 'Fwd: test - inner attachment eml'
    assert 'ArcSight_ESM_fixes.yml' in results[0]['EntryContext']['Email']['Attachments']
    assert 'test - inner attachment eml.eml' in results[0]['EntryContext']['Email']['Attachments']
    assert isinstance(results[0]['EntryContext']['Email'], dict)
    assert results[0]['EntryContext']['Email']['Depth'] == 0


def test_eml_utf_text(mocker):
    def executeCommand(name, args=None):
        if name == 'getFilePath':
            return [
                {
                    'Type': entryTypes['note'],
                    'Contents': {
                        'path': 'test_data/utf_8_email.eml',
                        'name': 'utf_8_email.eml'
                    }
                }
            ]
        elif name == 'getEntry':
            return [
                {
                    'Type': entryTypes['file'],
                    'FileMetadata': {
                        'info': 'UTF-8 Unicode text, with very long lines, with CRLF line terminators'
                    }
                }
            ]
        else:
            raise ValueError('Unimplemented command called: {}'.format(name))

    mocker.patch.object(demisto, 'args', return_value={'entryid': 'test'})
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    mocker.patch.object(demisto, 'results')
    # validate our mocks are good
    assert demisto.args()['entryid'] == 'test'
    main()
    assert demisto.results.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0]['Type'] == entryTypes['note']
    assert results[0]['EntryContext']['Email']['Subject'] == 'Test UTF Email'


def test_email_with_special_character(mocker):
    def executeCommand(name, args=None):
        if name == 'getFilePath':
            return [
                {
                    'Type': entryTypes['note'],
                    'Contents': {
                        'path': 'test_data/email_with_special_char_bytes.eml',
                        'name': 'email_with_special_char_bytes.eml'
                    }
                }
            ]
        elif name == 'getEntry':
            return [
                {
                    'Type': entryTypes['file'],
                    'FileMetadata': {
                        'info': 'RFC 822 mail text, ISO-8859 text, with very long lines, with CRLF line terminators'
                    }
                }
            ]
        else:
            raise ValueError('Unimplemented command called: {}'.format(name))

    mocker.patch.object(demisto, 'args', return_value={'entryid': 'test', 'max_depth': '1'})
    mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)
    mocker.patch.object(demisto, 'results')
    # validate our mocks are good
    assert demisto.args()['entryid'] == 'test'

    main()
    assert demisto.results.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0]['Type'] == entryTypes['note']
    assert results[0]['EntryContext']['Email']['Subject'] == 'Hello dear friend'


def test_utf_subject_convert():
    subject = ('[TESTING] =?utf-8?q?=F0=9F=94=92_=E2=9C=94_Votre_colis_est_disponible_chez_votre_co?='
               ' =?utf-8?q?mmer=C3=A7ant_Pickup_!?=')
    decoded = convert_to_unicode(subject)
    assert '[TESTING]' in decoded
    assert 'utf-8' not in decoded
    assert 'Votre' in decoded
    assert 'chez' in decoded


def test_unfold():
    assert unfold('test\n\tthis') == 'test this'
    assert unfold('test\r\n\tthis') == 'test this'
    assert unfold('test   \r\n this') == 'test this'


def test_email_raw_headers(mocker):
    mocker.patch.object(demisto, 'args', return_value={'entryid': 'test', 'max_depth': '1'})
    mocker.patch.object(demisto, 'executeCommand', side_effect=exec_command_for_file('multiple_to_cc.eml'))
    mocker.patch.object(demisto, 'results')
    # validate our mocks are good
    assert demisto.args()['entryid'] == 'test'

    main()
    assert demisto.results.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0]['Type'] == entryTypes['note']
    assert results[0]['EntryContext']['Email']['From'] == 'test@test.com'
    assert results[0]['EntryContext']['Email']['To'] == 'test@test.com, example1@example.com'
    assert results[0]['EntryContext']['Email']['CC'] == 'test@test.com, example1@example.com'
    assert results[0]['EntryContext']['Email']['HeadersMap']['From'] == 'Guy Test <test@test.com>'
    assert results[0]['EntryContext']['Email']['HeadersMap']['To'] == 'Guy Test <test@test.com>' \
                                                                      ', Guy Test1 <example1@example.com>'
    assert results[0]['EntryContext']['Email']['HeadersMap']['CC'] == 'Guy Test <test@test.com>, ' \
                                                                      'Guy Test1 <example1@example.com>'


def test_eml_contains_eml_with_status(mocker):
    subject = '=?iso-8859-7?B?Rlc6IEZPT0RMSU5LINDLx9HZzMc=?='  # disable-secrets-detection
    decoded = convert_to_unicode(subject)
    subject_attach = decoded.decode('utf-8')
    mocker.patch.object(demisto, 'args', return_value={'entryid': 'test'})
    mocker.patch.object(demisto, 'executeCommand', side_effect=exec_command_for_file('ParseEmailFiles-test-emls.eml'))
    mocker.patch.object(demisto, 'results')
    # validate our mocks are good
    assert demisto.args()['entryid'] == 'test'
    main()
    # assert demisto.results.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0]['Type'] == entryTypes['note']
    assert results[0]['EntryContext']['Email'][1]['Subject'] == subject_attach


@pytest.mark.parametrize('email_file', ['eml_contains_base64_eml.eml', 'eml_contains_base64_eml2.eml'])
def test_eml_contains_base64_encoded_eml(mocker, email_file):
    mocker.patch.object(demisto, 'args', return_value={'entryid': 'test'})
    mocker.patch.object(demisto, 'executeCommand', side_effect=exec_command_for_file(email_file))
    mocker.patch.object(demisto, 'results')
    # validate our mocks are good
    assert demisto.args()['entryid'] == 'test'

    main()
    assert demisto.results.call_count == 3
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0]['Type'] == entryTypes['note']
    assert results[0]['EntryContext']['Email'][0]['Subject'] == 'Fwd: test - inner attachment eml (base64)'
    assert 'message.eml' in results[0]['EntryContext']['Email'][0]['Attachments']
    assert results[0]['EntryContext']['Email'][0]['Depth'] == 0

    assert results[0]['EntryContext']['Email'][1]["Subject"] == 'test - inner attachment eml'
    assert results[0]['EntryContext']['Email'][1]['Depth'] == 1


# check that we parse an email with "data" type and eml extension
@pytest.mark.parametrize('file_info', ['data', 'data\n'])
def test_eml_data_type(mocker, file_info):
    mocker.patch.object(demisto, 'args', return_value={'entryid': 'test'})
    mocker.patch.object(demisto, 'executeCommand',
                        side_effect=exec_command_for_file('smtp_email_type.eml', info=file_info))
    mocker.patch.object(demisto, 'results')
    # validate our mocks are good
    assert demisto.args()['entryid'] == 'test'
    main()
    assert demisto.results.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0]['Type'] == entryTypes['note']
    assert results[0]['EntryContext']['Email']['Subject'] == 'Test Smtp Email'


def test_smime(mocker):
    multipart_sigened = 'multipart/signed; protocol="application/pkcs7-signature";, ASCII text, with CRLF line terminators'
    mocker.patch.object(demisto, 'args', return_value={'entryid': 'test'})
    mocker.patch.object(demisto, 'executeCommand',
                        side_effect=exec_command_for_file('smime.p7m', info=multipart_sigened))
    mocker.patch.object(demisto, 'results')
    # validate our mocks are good
    assert demisto.args()['entryid'] == 'test'
    main()
    # assert demisto.results.call_count == 1
    # call_args is tuple (args list, kwargs). we only need the first one
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0]['Type'] == entryTypes['note']
    assert results[0]['EntryContext']['Email']['Subject'] == 'Testing Email Attachment'


def test_smime_msg(mocker):
    info = 'CDFV2 Microsoft Outlook Message'
    mocker.patch.object(demisto, 'args', return_value={'entryid': 'test'})
    mocker.patch.object(demisto, 'executeCommand', side_effect=exec_command_for_file('smime-p7s.msg', info=info))
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


def test_msg_headers_map():
    email_data, ignore = handle_msg('test_data/utf_subject.msg', 'utf_subject.msg')
    assert '?utf-8' not in email_data['Subject']
    assert 'TESTING' in email_data['Subject']
    assert 'This is a test email.' in email_data['Text']
    assert 'mobi777@gmail.com' in email_data['From']
    assert 47 == len(email_data['HeadersMap'])
    assert isinstance(email_data['HeadersMap']['Received'], list)
    assert 8 == len(email_data['HeadersMap']['Received'])
    assert '1; DM6PR11MB2810; 31:tCNnPn/K8BROQtLwu3Qs1Fz2TjDW+b7RiyfdRvmvCG+dGRQ08+3CN4i8QpLn2o4' \
           in email_data['HeadersMap']['X-Microsoft-Exchange-Diagnostics'][2]
    assert '2eWTrUmQCI=; 20:7yMOvCHfrNUNaJIus4SbwkpcSids8EscckQZzX/oGEwux6FJcH42uCQd9tNH8gmDkvPw' \
           in email_data['HeadersMap']['X-Microsoft-Exchange-Diagnostics'][2]
    assert 'text/plain' in email_data['Format']


def test_unknown_file_type(mocker):
    mocker.patch.object(demisto, 'args', return_value={'entryid': 'test'})
    mocker.patch.object(demisto, 'executeCommand', side_effect=exec_command_for_file('smtp_email_type.eml', info="bad"))
    mocker.patch.object(demisto, 'results')
    try:
        main()
    except SystemExit:
        gotexception = True
    assert gotexception
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert 'Unknown file format:' in results[0]['Contents']
    assert 'smtp_email_type.eml' in results[0]['Contents']
