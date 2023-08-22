import demistomock as demisto
import os

import pytest
from ReadPDFFileV2 import PdfInvalidCredentialsException, PdfPermissionsException

CWD = os.getcwd() if os.getcwd().endswith('test_data') else f'{os.getcwd()}/test_data'


def open_html_file(file):
    with open(file, encoding='utf-8') as f:
        return f.read()


def test_urls_are_found_correctly(mocker):
    """
    Given
        - a pdf html content.
    When
        - trying extract the urls from that html.
    Then
        - the correct url is extracted from the html content.
    """
    from ReadPDFFileV2 import get_urls_and_emails_from_pdf_html_content
    mocker.patch('ReadPDFFileV2.get_pdf_htmls_content', return_value=open_html_file(f'{CWD}/pdf-html-content.html'))
    urls, _ = get_urls_and_emails_from_pdf_html_content('', '')
    assert urls == {'http://www.w3.org/1999/xhtml'}


def test_incorrect_authentication():
    """
    Given
        - An encrypted pdf file and an incorrect password.
    When
        - Trying to decrypt the file(using the password) to extract data.
    Then
        - The program will catch this error and raise the appropriate exception.
    """
    from ReadPDFFileV2 import get_pdf_metadata, handling_pdf_credentials
    file_path = f'{CWD}/encrypted.pdf'
    dec_file_path = f'{CWD}/decrypted.pdf'

    with pytest.raises(PdfInvalidCredentialsException) as e:
        get_pdf_metadata(file_path=file_path, user_password='12')
    assert 'Incorrect password' in str(e)

    with pytest.raises(PdfInvalidCredentialsException) as e:
        handling_pdf_credentials(cpy_file_path=file_path, dec_file_path=dec_file_path, encrypted='yes',
                                 user_password='12')
    assert 'Incorrect password' in str(e)


def test_get_files_names_in_path():
    from ReadPDFFileV2 import get_files_names_in_path
    pdf_file_names = get_files_names_in_path('test_data', '*.pdf')
    assert 'scanned.pdf' in pdf_file_names

    pdf_file_names = get_files_names_in_path('test_data', '*.pdf', full_path=True)
    assert 'test_data/text-only.pdf' in pdf_file_names


def test_get_images_paths_in_path():
    from ReadPDFFileV2 import get_images_paths_in_path
    img_file_paths = get_images_paths_in_path('test_data')
    assert 'test_data/test1.png' in img_file_paths
    assert 'test_data/scanned.pdf' not in img_file_paths


ENC_PDF_META_DATA_CASES = [
    ((b'Title:          sample1.pdf\nKeywords:       \nCreator:        Preview\n'
      b'Producer:       macOS Version 10.14.4 (Build 18E226) Quartz PDFContext\nCreationDate:   Wed May 15 08:18:48 2019\n'
      b'ModDate:        Wed May 15 08:18:48 2019\nTagged:         no\nForm:           none\nPages:          2\n'
      b'Encrypted:      AES 128-bit\nPermissions:    print:yes copy:yes change:yes addNotes:yes\n'
      b'Page size:      595 x 842 pts (A4) (rotated 0 degrees)\nFile size:      71085 bytes\nOptimized:      no\n'
      b'PDF version:    1.6\n'),
     {'Title': 'sample1.pdf', 'Keywords': '', 'Creator': 'Preview',
      'Producer': 'macOS Version 10.14.4 (Build 18E226) Quartz PDFContext', 'CreationDate': 'Wed May 15 08:18:48 2019',
      'ModDate': 'Wed May 15 08:18:48 2019', 'Tagged': 'no',
      'Form': 'none', 'Pages': '2', 'Encrypted': 'AES 128-bit', 'Permissions': 'print:yes copy:yes change:yes addNotes:yes',
      'PageSize': '595 x 842 pts (A4) (rotated 0 degrees)', 'FileSize': '71085 bytes', 'Optimized': 'no', 'PDFVersion': '1.6'})
]


@pytest.mark.parametrize('raw_result, expected_result', ENC_PDF_META_DATA_CASES)
def test_get_pdf_metadata_with_encrypted(mocker, raw_result, expected_result):
    from ReadPDFFileV2 import get_pdf_metadata
    file_path = f'{CWD}/encrypted.pdf'
    mocker.patch('ReadPDFFileV2.run_shell_command', return_value=raw_result)
    metadata = get_pdf_metadata(file_path, user_password='1234')
    assert metadata == expected_result


PDF_META_DATA_CASES = [
    ((b'Title:          Microsoft Word - Document1\nKeywords:       \nCreator:        Word\n'
      b'Producer:       macOS Version 10.14.4 (Build 18E226) Quartz PDFContext\nCreationDate:   Wed May 15 11:47:28 2019\n'
      b'ModDate:        Wed May 15 11:47:28 2019\nTagged:         no\nForm:           none\nPages:          1\n'
      b'Encrypted:      no\nPage size:      595 x 842 pts (A4) (rotated 0 degrees)\nFile size:      18920 bytes\n'
      b'Optimized:      no\nPDF version:    1.3\n'),
     {'Title': 'Microsoft Word - Document1', 'Keywords': '', 'Creator': 'Word',
      'Producer': 'macOS Version 10.14.4 (Build 18E226) Quartz PDFContext', 'CreationDate': 'Wed May 15 11:47:28 2019',
      'ModDate': 'Wed May 15 11:47:28 2019', 'Tagged': 'no', 'Form': 'none', 'Pages': '1', 'Encrypted': 'no',
      'PageSize': '595 x 842 pts (A4) (rotated 0 degrees)', 'FileSize': '18920 bytes', 'Optimized': 'no', 'PDFVersion': '1.3'})
]


@pytest.mark.parametrize('raw_result, expected_result', PDF_META_DATA_CASES)
def test_get_metadata_without_encrypted(mocker, raw_result, expected_result):
    from ReadPDFFileV2 import get_pdf_metadata
    try:
        get_pdf_metadata(f'{CWD}/encrypted.pdf')
        raise Exception("Incorrect password exception should've been thrown")
    except PdfPermissionsException as e:
        assert 'Incorrect password' in str(e)

    mocker.patch('ReadPDFFileV2.run_shell_command', return_value=raw_result)
    metadata = get_pdf_metadata(f'{CWD}/text-only.pdf')
    assert metadata == expected_result


def test_get_pdf_text_with_encrypted(tmp_path):
    from ReadPDFFileV2 import get_pdf_text, handling_pdf_credentials
    file_path = f'{CWD}/encrypted.pdf'
    dec_file_path = f'{CWD}/decrypted.pdf'
    dec_file_path = handling_pdf_credentials(cpy_file_path=file_path, user_password='1234',
                                             dec_file_path=dec_file_path, encrypted='yes')
    text = get_pdf_text(dec_file_path, f'{tmp_path}/encrypted.txt')
    expected = "XSL FO Sample Copyright © 2002-2005 Antenna House, Inc. All rights reserved.\n\n" \
               "Links in PDF\nPDF link is classified into two parts, link to the specified position in the PDF " \
               "document, and link to the external document.\n" \
               "The internal-destination property of fo:basic-link indicates to link to the position in the same" \
               " document. The externaldestination property indicates to link to external document. " \
               "Below shows the example.\n\nExample of a link to internal destination\nRefer to Purchasing " \
               "Assistance to get more information.\nExample of a link to external destination\nRefer to Purchasing " \
               "Assistance to get more information."

    if os.path.exists(dec_file_path):
        os.remove(dec_file_path)

    assert text.startswith(expected)


def test_get_pdf_text_without_encrypted(tmp_path):
    from ReadPDFFileV2 import get_pdf_text
    # assert error raised
    try:
        get_pdf_text(f'{CWD}/encrypted.pdf', f'{tmp_path}/encrypted.txt')
        raise Exception("Incorrect password exception should've been thrown")
    except PdfInvalidCredentialsException as e:
        assert 'Incorrect password' in str(e)

    # assert not warnings are raised
    text = get_pdf_text(f'{CWD}/warning_trigger.pdf', f'{tmp_path}/warning_trigger.txt')
    assert 'Riu Plaza Berlin' in text

    # assert extract file correctly
    text = get_pdf_text(f'{CWD}/text-only.pdf', f'{tmp_path}/text-only.txt')
    expected = "עברית"
    assert expected in text
    assert text.startswith('This is a pdf document with a text line within it.')

    text = get_pdf_text(f'{CWD}/text-with-images.pdf', f'{tmp_path}/text-with-images.txt')
    expected = 'Create an ETD Using Adobe Acrobat'
    assert text.startswith(expected)

    text = get_pdf_text(f'{CWD}/scanned.pdf', f'{tmp_path}/scanned.txt')
    expected = '\x0c'
    assert expected == text


def test_get_pdf_htmls_content_with_encrypted(mocker, tmp_path):
    mocker.patch.object(demisto, 'args', return_value={'userPassword': '1234'})
    from ReadPDFFileV2 import get_pdf_htmls_content, get_images_paths_in_path, handling_pdf_credentials
    file_path = f'{CWD}/encrypted.pdf'
    dec_file_path = f'{CWD}/decrypted.pdf'
    dec_file_path = handling_pdf_credentials(cpy_file_path=file_path, user_password='1234',
                                             dec_file_path=dec_file_path, encrypted='yes')
    # to_html_output_folder = f'{tmp_path}/PDF_html'
    html_text = get_pdf_htmls_content(dec_file_path, tmp_path)
    expected = 'If you are end user who wishes to use XSL Formatter yourself, you may purchase ' \
               'from our Reseller or direct from Antenna<br/>House.<br/>'

    if os.path.exists(dec_file_path):
        os.remove(dec_file_path)

    assert len(get_images_paths_in_path(tmp_path)) != 0, 'Failed to get images from html'
    assert expected in html_text


def test_get_pdf_htmls_content_without_encrypted(tmp_path):
    from ReadPDFFileV2 import get_pdf_htmls_content, get_images_paths_in_path
    try:
        get_pdf_htmls_content(f'{CWD}/encrypted.pdf', tmp_path)
        raise Exception("Incorrect password exception should've been thrown")
    except PdfPermissionsException as e:
        assert 'Incorrect password' in str(e)
    # to_html_output_folder = f'{tmp_path}/PDF_html'
    html_text = get_pdf_htmls_content(f'{CWD}/hyperlinks.pdf', tmp_path)
    assert 'http://www.example.com/' in html_text
    assert len(get_images_paths_in_path(tmp_path)) != 0, 'Failed to get images from html'


def test_get_urls_from_binary_file():
    from ReadPDFFileV2 import get_urls_from_binary_file
    urls = get_urls_from_binary_file(f'{CWD}/text-with-images.pdf')
    assert len(urls) == 10


def test_build_readpdf_entry_object_empty_extract(mocker):
    from ReadPDFFileV2 import build_readpdf_entry_object, DEFAULT_NUM_IMAGES
    mocker.patch.object(demisto, 'executeCommand', return_value=[{'Contents': ''}])
    res = build_readpdf_entry_object('test', {}, '', [], [], [], DEFAULT_NUM_IMAGES)
    assert res[0]['HumanReadable'] == '### Metadata\n\n### URLs\n\n### Text\n'


@pytest.mark.parametrize('file_path', [
    'URLs_Extraction_Test_PDF_Encoding_Google_Docs_Renderer_protected.pdf',
    'URLs_Extraction_Test_PDF_Encoding_Quartz_PDFContext_protected.pdf'
])
def test_get_urls_and_emails_from_pdf_annots_with_encrypt(file_path):
    """
    This test verifies URL and Emails extraction from an encrypted PDF file.

        Given:
        A path to an encrypted PDF file with a certain encoding:
            1. A pdf created with google docs.
            2. A pdf created with mac os Notes.

        Both PDFs include URLs and Email addresses from different kinds that should be extracted:

            * 'https://test1.com/' - A text url ended with a slash /.
            * 'https://test2.com' - A text url ended without a slash /.
            * 'www.test3.net' - A text url without the http prefix.
            * 'user@test4.com' - A text email address.
            * 'https://test5.com.co/ed/trn/update?email=user@test6.net' - A text url with an https prefix, and an email
               address in it.
            * 'http://www.test7.com' - A text hyperlink of a url.
            * 'https://test8.com/' - An embedded url (a url that is hyperlinked to an image).

        When:
            Running 'get_urls_and_emails_from_pdf_annots' function on the PDF file.

        Then:
            Verify that the URLs Emails was extracted successfully.

    """
    from ReadPDFFileV2 import get_urls_and_emails_from_pdf_annots, handling_pdf_credentials

    expected_urls = {'https://test1.com', 'https://test2.com', 'http://www.test3.net',
                     'https://test5.com.co/ed/trn/update?email=user@test6.net', 'http://www.test7.com',
                     'https://test8.com'}

    expected_emails = {'user@test4.com', 'user@test6.net'}

    # Decrypt the PDF:
    dec_file_path = f'{CWD}/decrypted.pdf'
    file_path = f'{CWD}/{file_path}'
    dec_file_path = handling_pdf_credentials(cpy_file_path=file_path,
                                             user_password='123456',
                                             dec_file_path=dec_file_path,
                                             encrypted='')
    # decrypt_pdf_file(file_path, '1234', dec_file_path)

    # Extract URLs and Emails:
    urls, emails = get_urls_and_emails_from_pdf_annots(dec_file_path)

    # Delete Decrypted file:
    if os.path.exists(dec_file_path):
        os.remove(dec_file_path)

    assert urls == expected_urls
    assert emails == expected_emails


@pytest.mark.parametrize('file_path', [
    'URLs_Extraction_Test_PDF_Encoding_Google_Docs_Renderer.pdf',
    'URLs_Extraction_Test_PDF_Encoding_Quartz_PDFContext.pdf'
])
def test_get_urls_and_emails_from_pdf_annots_without_encrypt(file_path):
    """
    This test verifies URL and Emails extraction from a non-encrypted PDF file.

        Given:
        A path to a PDF file with a certain encoding:
            1. A pdf created with google docs.
            2. A pdf created with mac os Notes.

        Both PDFs include URLs and Email addresses from different kinds that should be extracted:

            * 'https://test1.com/' - A text url ended with a slash /.
            * 'https://test2.com' - A text url ended without a slash /.
            * 'www.test3.net' - A text url without the http prefix.
            * 'user@test4.com' - A text email address.
            * 'https://test5.com.co/ed/trn/update?email=user@test6.net' - A text url with an https prefix, and an email
               address in it.
            * 'http://www.test7.com' - A text hyperlink of a url.
            * 'https://test8.com/' - An embedded url (a url that is hyperlinked to an image).

        When:
            Running 'get_urls_and_emails_from_pdf_annots' function on the PDF file.

        Then:
            Verify that the URLs Emails was extracted successfully.

    """
    from ReadPDFFileV2 import get_urls_and_emails_from_pdf_annots

    expected_urls = {'https://test1.com', 'https://test2.com', 'http://www.test3.net',
                     'https://test5.com.co/ed/trn/update?email=user@test6.net', 'http://www.test7.com',
                     'https://test8.com'}

    expected_emails = {'user@test4.com', 'user@test6.net'}

    file_path = f'{CWD}/{file_path}'

    # Extract URLs and Emails:
    urls, emails = get_urls_and_emails_from_pdf_annots(file_path)

    assert urls == expected_urls
    assert emails == expected_emails


def test_get_urls_and_emails_from_pdf_file_with_encrypt(tmp_path):
    """
    This test verifies URL and Emails extraction from an encrypted PDF file.

        Given:
        A path to an encrypted PDF file with a certain encoding (Libreoffice Encoding).

        When:
            Running 'extract_urls_and_emails_from_pdf_file' function on the PDF file.

        Then:
            Verify that the URLs Emails was extracted successfully.

    """
    from ReadPDFFileV2 import extract_urls_and_emails_from_pdf_file, handling_pdf_credentials

    expected_urls = {'www.hiddenvirusaddress.cn', 'www.msn.com', 'http://www.docxtesturl.com', 'www.google.com',
                     'www.docxtesturl.com', 'http://www.msn.com'}
    expected_emails = {'Userthatdoesnotexist3@demis', 'userthatdoesnotexist@demisto.com',
                       'userthatdoesnotexist4@demis', 'Userthatdoesnotexist2@demisto.com'}

    # Decrypt the PDF:
    file_path = f'{CWD}/URLs_Extraction_Test_PDF_Encoding_LibreOffice_protected.pdf'
    dec_file_path = f'{CWD}/decrypted.pdf'
    dec_file_path = handling_pdf_credentials(cpy_file_path=file_path, user_password='123456',
                                             dec_file_path=dec_file_path, encrypted='')
    # decrypt_pdf_file(file_path, '123456', dec_file_path)

    # Extract URLs and Emails:
    urls, emails = extract_urls_and_emails_from_pdf_file(dec_file_path, tmp_path)

    # Delete Decrypted file:
    if os.path.exists(dec_file_path):
        os.remove(dec_file_path)

    assert {url_data['Data'] for url_data in urls} == expected_urls
    assert set(emails) == expected_emails


def test_get_urls_and_emails_from_pdf_file_without_encrypt(tmp_path):
    """
    This test verifies URL and Emails extraction from a non-encrypted PDF file.

        Given:
        A path to a PDF file with a certain encoding (Libreoffice Encoding).

        When:
            Running 'extract_urls_and_emails_from_pdf_file' function on the PDF file.

        Then:
            Verify that the URLs Emails was extracted successfully.

    """
    from ReadPDFFileV2 import extract_urls_and_emails_from_pdf_file

    expected_urls = {'www.hiddenvirusaddress.cn', 'www.msn.com', 'http://www.docxtesturl.com',
                     'www.google.com', 'www.docxtesturl.com', 'http://www.msn.com'}
    expected_emails = {'Userthatdoesnotexist3@demis', 'userthatdoesnotexist@demisto.com',
                       'userthatdoesnotexist4@demis', 'Userthatdoesnotexist2@demisto.com'}

    file_path = f'{CWD}/URLs_Extraction_Test_PDF_Encoding_LibreOffice.pdf'

    # Extract URLs and Emails:
    urls, emails = extract_urls_and_emails_from_pdf_file(file_path, tmp_path)

    assert set(emails) == expected_emails
    assert {url_data['Data'] for url_data in urls} == expected_urls


def test_handle_error_read_only(mocker):
    from ReadPDFFileV2 import handle_error_read_only

    mocker.patch('ReadPDFFileV2.os.access', return_value=False)

    def fun(path):
        return path
    change_permition = mocker.patch('ReadPDFFileV2.os.chmod')
    handle_error_read_only(
        fun,
        f'{CWD}/test_for_read_only_file.txt',
        'The error is not due to a problem with write permissions to the file'
    )
    assert change_permition.call_count == 1


def test_handle_error_read_only_failed(mocker):
    from ReadPDFFileV2 import handle_error_read_only

    mocker.patch('ReadPDFFileV2.os.access', return_value=True)

    def fun(path):
        return path
    with pytest.raises(Exception) as e:
        handle_error_read_only(
            fun,
            f'{CWD}/test_for_read_only_file.txt',
            'The error is not due to a problem with write permissions to the file'
        )
    assert str(e.value) == 'The error is not due to a problem with write permissions to the file'
