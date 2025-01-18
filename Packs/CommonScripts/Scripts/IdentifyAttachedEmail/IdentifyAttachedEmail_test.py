from IdentifyAttachedEmail import *
import IdentifyAttachedEmail
import pytest


def execute_command(command, args):
    if command == 'getEntry':
        if args['id'] == '23@2':
            return [
                {
                    'Type': entryTypes['note'],
                    'FileMetadata': {
                        'info': 'koko'
                    },
                    'ID': '23@2'
                }
            ]
        elif args['id'] == '24@2':
            return [
                {
                    'Type': entryTypes['file'],
                    'FileMetadata': {
                        'info': 'news or mail text, ASCII text'
                    },
                    'ID': '24@2'
                }
            ]
    if command == "getEntries":
        return {}
    return None


def test_is_email():
    assert is_email({'type': 'eml}'}, 'test.txt')
    assert is_email({'type': 'eml'}, 'test.txt')
    assert is_email({'type': 'message/rfc822'}, 'test.txt')
    assert not is_email({'type': 'other'}, 'test.txt')
    assert is_email({'info': 'news or mail text, ASCII text'}, 'test.txt')
    assert is_email({'info': 'CDFV2 Microsoft Outlook Message'}, 'msg.test')
    assert is_email({'info': 'ASCII text, with CRLF line terminators'}, 'msg.eml')
    assert is_email({'info': 'data'}, 'test.eml')
    assert not is_email({'info': 'data'}, 'test.bin')
    assert not is_email({'info': 'composite document file v2 document'}, 'cv.doc')
    assert is_email({'info': 'RFC 822 mail text, ISO-8859 text, with very long lines, with CRLF line terminator'}, 'test.bin')
    assert is_email({'info': 'CDFV2 Microsoft Outlook Message'}, 'test.bin')
    assert is_email({'info': 'multipart/signed; protocol="application/pkcs7-signature";, ASCII text, with CRLF line terminators'},
                    'test.bin')
    assert is_email({'info': 'UTF-8 Unicode text, with very long lines, with CRLF line terminators'}, 'test.eml')


def test_get_email_entry_id(mocker):
    mocker.patch.object(IdentifyAttachedEmail, 'is_email', return_value=True)
    assert not get_email_entry_id('')


def test_identify_attached_mail(mocker):
    entry_ids = '[\"23@2\",\"24@2\"]'
    from CommonServerPython import demisto
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)
    args = {
        'entryid': entry_ids
    }
    results = identify_attached_mail(args)
    assert results == ('yes', {'reportedemailentryid': ['24@2']})


def test_identify_attached_mail_no_email_attached(mocker):
    entry_ids = """[\"23@2\"]"""
    from CommonServerPython import demisto
    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)

    args = {
        'entryid': entry_ids
    }
    results = identify_attached_mail(args)
    assert results == ('no', None)


def test_identify_attached_mail_in_xsoar_saas_list_of_entries_passed(mocker):
    """
    Given
    - two entries with ids 23@2 24@2
    - the platform is xsoar saas

    When
    - running the script to get the entries

    Then
    - expect the getEntriesByIDs to be called

    """
    entry_ids = """[\"23@2\",\"24@2\"]"""
    import CommonServerPython
    mocker.patch.object(CommonServerPython, 'get_demisto_version', return_value={
        'version': '8.2.0',
        'buildNumber': '12345'
    })

    def execute_command(command, args):
        if command == 'getEntriesByIDs' and args.get('entryIDs') == '23@2,24@2':
            return [
                {
                    'File': 'msg.eml',
                    'FileMetadata': {
                        'info': 'ASCII text, with CRLF line terminators'
                    },
                    'ID': '23@2'
                },
                {
                    'File': 'foo.txt',
                    'FileMetadata': {
                        'info': 'ASCII text, with CRLF line terminators'
                    },
                    'ID': '24@2'
                }
            ]
        else:
            pytest.fail()

    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)

    args = {
        'entryid': entry_ids
    }
    results = identify_attached_mail(args)
    assert results == ('yes', {'reportedemailentryid': ['23@2']})


def test_identify_attached_mail_no_entries_passed(mocker):
    """
    Given
    - no entries passed
    - the platform is xsoar saas

    When
    - running the script to get the entries

    Then
    - expect the getEntries to be called with filters

    """
    import CommonServerPython
    mocker.patch.object(CommonServerPython, 'get_demisto_version', return_value={
        'version': '8.2.0',
        'buildNumber': '12345'
    })

    def execute_command(command, args):
        if command == 'getEntries' and args == {"filter": {"categories": ["attachments"]}}:
            return [
                {
                    'File': 'msg.eml',
                    'FileMetadata': {
                        'info': 'ASCII text, with CRLF line terminators'
                    },
                    'ID': '23@2'
                },
                {
                    'File': 'foo.txt',
                    'FileMetadata': {
                        'info': 'ASCII text, with CRLF line terminators'
                    },
                    'ID': '24@2'
                }
            ]
        else:
            pytest.fail()

    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)

    results = identify_attached_mail({})
    assert results == ('yes', {'reportedemailentryid': ['23@2']})


def test_identify_attached_mail_no_email_found(mocker):
    """
    Given
    - no email entries in the warroom
    - the platform is xsoar saas

    When
    - running the script to get the entries

    Then
    - no entries to be found

    """
    import CommonServerPython
    mocker.patch.object(CommonServerPython, 'get_demisto_version', return_value={
        'version': '8.2.0',
        'buildNumber': '12345'
    })

    def execute_command(command, args):
        if command == 'getEntries' and args == {"filter": {"categories": ["attachments"]}}:
            return
        else:
            pytest.fail()

    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)

    results = identify_attached_mail({})
    assert results == ('no', None)


def test_list_of_entries_passed_in_xsoar_saas_but_no_file_entries(mocker):
    """
    Given
    - two entries with ids 23@2 24@2 which are not file entries
    - the platform is xsoar saas

    When
    - running the script to get the entries

    Then
    - expect the getEntriesByIDs to be called
    - expect no email entries to be found

    """
    entry_ids = """[\"23@2\",\"24@2\"]"""
    import CommonServerPython
    mocker.patch.object(CommonServerPython, 'get_demisto_version', return_value={
        'version': '8.2.0',
        'buildNumber': '12345'
    })

    def execute_command(command, args):
        if command == 'getEntriesByIDs' and args.get('entryIDs') == '23@2,24@2':
            return [
                {
                    'File': 'msg.txt',
                    'FileMetadata': {
                        'info': 'ASCII text, with CRLF line terminators'
                    },
                    'ID': '23@2'
                },
                {
                    'File': 'foo.txt',
                    'FileMetadata': {
                        'info': 'ASCII text, with CRLF line terminators'
                    },
                    'ID': '24@2'
                }
            ]
        else:
            pytest.fail()

    mocker.patch.object(demisto, 'executeCommand', side_effect=execute_command)

    args = {
        'entryid': entry_ids
    }
    results = identify_attached_mail(args)
    assert results == ('no', None)
