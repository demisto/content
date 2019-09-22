from IdentifyAttachedEmail import is_email


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
