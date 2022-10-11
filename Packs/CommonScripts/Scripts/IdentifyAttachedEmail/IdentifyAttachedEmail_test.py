from IdentifyAttachedEmail import *
import IdentifyAttachedEmail


def execute_command(command, args):
    if command == 'getEntry':
        return [
            {
                'Type': entryTypes['file'],
                'FileMetadata': {
                    'info': 'news or mail text, ASCII text'
                }
            }
        ]
    if command == "getEntries":
        return {}


def test_is_email():
    assert is_email('news or mail text, ASCII text', 'test.txt')
    assert is_email('CDFV2 Microsoft Outlook Message', 'msg.test')
    assert is_email('ASCII text, with CRLF line terminators', 'msg.eml')
    assert is_email('data', 'test.eml')
    assert not is_email('data', 'test.bin')
    assert not is_email('composite document file v2 document', 'cv.doc')
    assert is_email('RFC 822 mail text, ISO-8859 text, with very long lines, with CRLF line terminator', 'test.bin')
    assert is_email('CDFV2 Microsoft Outlook Message', 'test.bin')
    assert is_email('multipart/signed; protocol="application/pkcs7-signature";, ASCII text, with CRLF line terminators',
                    'test.bin')
    assert is_email('UTF-8 Unicode text, with very long lines, with CRLF line terminators', 'test.eml')


def test_is_entry_email(mocker):
    mocker.patch.object(IdentifyAttachedEmail, 'is_email', return_value=True)
    assert not is_entry_email('')


def test_identify_attached_mail(mocker):
    entry_ids = """[\"23@2\",\"24@2\"]"""
    from CommonServerPython import demisto
    mocker.patch.object(demisto, 'get', return_value=entry_ids)
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    mocker.patch.object(IdentifyAttachedEmail, 'is_entry_email', return_value=True)
    results = identify_attached_mail({})
    assert results == ('yes', {'reportedemailentryid': True})


def test_identify_attached_mail_no_email_attached(mocker):
    entry_ids = """[\"23@2\",\"24@2\"]"""
    from CommonServerPython import demisto
    mocker.patch.object(demisto, 'get', return_value=entry_ids)
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    mocker.patch.object(IdentifyAttachedEmail, 'is_entry_email', return_value=False)
    results = identify_attached_mail({})
    assert results == ('no', None)
