import demistomock as demisto
import os

import pytest
from ReadPDFFileV2 import ShellException

CWD = os.getcwd() if os.getcwd().endswith('test_data') else f'{os.getcwd()}/test_data'


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


def test_get_pdf_metadata_with_encrypted():
    from ReadPDFFileV2 import get_pdf_metadata, decrypt_pdf_file
    file_path = f'{CWD}/encrypted.pdf'
    dec_file_path = f'{CWD}/decrypted.pdf'
    decrypt_pdf_file(file_path, '1234', dec_file_path)
    metadata = get_pdf_metadata(dec_file_path)
    expected = {
        'Title': 'sample1.pdf',
        'Keywords': '',
        'Creator': 'Preview',
        'Producer': 'macOS Version 10.14.4 (Build 18E226) Quartz PDFContext',
        'Tagged': 'no',
        'UserProperties': 'no',
        'Suspects': 'no', 'Form': 'none',
        'JavaScript': 'no',
        'Pages': '2',
        'Encrypted': 'yes (print:yes copy:yes change:yes addNotes:yes algorithm:AES)',
        'PageSize': '595 x 842 pts (A4)',
        'PageRot': '0',
        'FileSize': '71085 bytes',
        'Optimized': 'no',
        'PDFVersion': '1.6'
    }
    if os.path.exists(dec_file_path):
        os.remove(dec_file_path)
    assert expected.items() <= metadata.items()


def test_get_metadata_without_encrypted(tmp_path):
    from ReadPDFFileV2 import get_pdf_metadata
    try:
        get_pdf_metadata(f'{CWD}/encrypted.pdf')
        raise Exception("Incorrect password exception should've been thrown")
    except ShellException as e:
        assert 'Incorrect password' in str(e)
        assert 'error code: 1' in str(e)

    metadata = get_pdf_metadata(f'{CWD}/text-only.pdf')
    expected = {
        'Title': 'Microsoft Word - Document1',
        'Keywords': '',
        'Creator': 'Word',
        'Producer': 'macOS Version 10.14.4 (Build 18E226) Quartz PDFContext',
        'Tagged': 'no',
        'UserProperties': 'no',
        'Suspects': 'no',
        'Form': 'none',
        'JavaScript': 'no',
        'Pages': '1',
        'Encrypted': 'no',
        'PageSize': '595 x 842 pts (A4)',
        'PageRot': '0',
        'FileSize': '18920 bytes',
        'Optimized': 'no',
        'PDFVersion': '1.3'
    }

    assert expected.items() <= metadata.items()


def test_get_pdf_text_with_encrypted(tmp_path):
    from ReadPDFFileV2 import get_pdf_text, decrypt_pdf_file
    file_path = f'{CWD}/encrypted.pdf'
    dec_file_path = f'{CWD}/decrypted.pdf'
    decrypt_pdf_file(file_path, '1234', dec_file_path)
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
    except ShellException as e:
        assert 'Incorrect password' in str(e)
        assert 'error code: 1' in str(e)

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


def test_build_readpdf_entry_object_empty_extract(mocker):
    from ReadPDFFileV2 import build_readpdf_entry_object
    mocker.patch.object(demisto, 'executeCommand', return_value=[{u'Contents': ''}])
    pdf_file = {'Text': 'test'}
    res = build_readpdf_entry_object(pdf_file, {}, '', '', '', '')
    assert res[0]['HumanReadable'] == '### Metadata\n\n### URLs\n\n### Text\n'


@pytest.mark.parametrize('pdf_encoding_type, expected_output', [
    (1, 'https://test1.com/'),
    (1, 'https://test2.com'),
    (1, 'http://www.test3.net'),
    (1, 'mailto:user@test4.com'),
    (1, 'https://test5.com.co/ed/trn/update?email=user@test6.net'),
    (1, 'http://www.test7.com'),
    (1, 'https://test8.com/'),
    (2, 'https://test1.com/'),
    (2, 'https://test2.com'),
    (2, 'http://www.test3.net'),
    (2, 'mailto:user@test4.com'),
    (2, 'https://test5.com.co/ed/trn/update?email=user@test6.net'),
    (2, 'http://www.test7.com'),
    (2, 'https://test8.com/')
])
def test_get_urls_and_emails_from_pdf_file_with_encrypt(pdf_encoding_type, expected_output):
    """
    This test verifies URL and Emails extraction from an encrypted PDF file.

        Given:
        A number representing a type of a pdf encoding and an expected output - URL or Email address:
        (the pdf is encrypted)

            1. A PDF encoded with the first encoding, a text url ended with a slash /.

            2. A PDF encoded with the first encoding, a text url ended without a slash /.

            3. A PDF encoded with the first encoding, a text url without the http prefix.

            4. A PDF encoded with the first encoding, a text email address.

            5. A PDF encoded with the first encoding, a text url with an https prefix, and an email address in it.

            6. A PDF encoded with the first encoding, a text hyperlink of a url.

            7. A PDF encoded with the first encoding, aa embedded url (a url the is hyperlinked to an image).

            8. A PDF encoded with the second encoding, a text url ended with a slash /.

            9. A PDF encoded with the second encoding, a text url ended without a slash /.

            10. A PDF encoded with the second encoding, a text url without the http prefix.

            11. A PDF encoded with the second encoding, a text email address.

            12. A PDF encoded with the second encoding, a text url with an https prefix, and an email address in it.

            13. A PDF encoded with the second encoding, a text hyperlink of a url.

            14. A PDF encoded with the second encoding, aa embedded url (a url the is hyperlinked to an image).

        When:
            Running 'get_urls_and_emails_from_pdf_file' function on the PDF file.

        Then:
            Verify that the expected amount of URLs and Email addresses was extracted from the PDF.
            Verify that the specific URL or Email was extracted successfully.

    """
    from ReadPDFFileV2 import get_urls_and_emails_from_pdf_file, decrypt_pdf_file

    # Select the PDF encoding:
    if pdf_encoding_type == 1:  # first encoding type (a pdf created with google docs)
        file_path = f'{CWD}/URLs_Extraction_Test_PDF_Encoding_Google_Docs_Renderer_protected.pdf'
    else:  # second encoding type (a pdf created with mac os notes)
        file_path = f'{CWD}/URLs_Extraction_Test_PDF_Encoding_Quartz_PDFContext_protected.pdf'

    # Decrypt the PDF:
    dec_file_path = f'{CWD}/decrypted.pdf'
    decrypt_pdf_file(file_path, '123456', dec_file_path)

    # Extract URLs and Emails:
    urls = get_urls_and_emails_from_pdf_file(dec_file_path)

    # Delete Decrypted file:
    if os.path.exists(dec_file_path):
        os.remove(dec_file_path)

    assert len(urls) == 7
    assert expected_output in urls


@pytest.mark.parametrize('pdf_encoding_type, expected_output', [
    (1, 'https://test1.com/'),
    (1, 'https://test2.com'),
    (1, 'http://www.test3.net'),
    (1, 'mailto:user@test4.com'),
    (1, 'https://test5.com.co/ed/trn/update?email=user@test6.net'),
    (1, 'http://www.test7.com'),
    (1, 'https://test8.com/'),
    (2, 'https://test1.com/'),
    (2, 'https://test2.com'),
    (2, 'http://www.test3.net'),
    (2, 'mailto:user@test4.com'),
    (2, 'https://test5.com.co/ed/trn/update?email=user@test6.net'),
    (2, 'http://www.test7.com'),
    (2, 'https://test8.com/')
])
def test_get_urls_and_emails_from_pdf_file_without_encrypt(pdf_encoding_type, expected_output):
    """
    This test verifies URL and Emails extraction from a non-encrypted PDF file.

        Given:
        A number representing a type of a pdf encoding and an expected output - URL or Email address:

            1. A PDF encoded with the first encoding, a text url ended with a slash /.

            2. A PDF encoded with the first encoding, a text url ended without a slash /.

            3. A PDF encoded with the first encoding, a text url without the http prefix.

            4. A PDF encoded with the first encoding, a text email address.

            5. A PDF encoded with the first encoding, a text url with an https prefix, and an email address in it.

            6. A PDF encoded with the first encoding, a text hyperlink of a url.

            7. A PDF encoded with the first encoding, aa embedded url (a url the is hyperlinked to an image).

            8. A PDF encoded with the second encoding, a text url ended with a slash /.

            9. A PDF encoded with the second encoding, a text url ended without a slash /.

            10. A PDF encoded with the second encoding, a text url without the http prefix.

            11. A PDF encoded with the second encoding, a text email address.

            12. A PDF encoded with the second encoding, a text url with an https prefix, and an email address in it.

            13. A PDF encoded with the second encoding, a text hyperlink of a url.

            14. A PDF encoded with the second encoding, aa embedded url (a url the is hyperlinked to an image).

        When:
            Running 'get_urls_and_emails_from_pdf_file' function on the PDF file.

        Then:
            Verify that the expected amount of URLs and Email addresses was extracted from the PDF.
            Verify that the specific URL or Email was extracted successfully.

    """
    from ReadPDFFileV2 import get_urls_and_emails_from_pdf_file

    # Select the PDF encoding:
    if pdf_encoding_type == 1:  # first encoding type (a pdf created with google docs)
        file_path = f'{CWD}/URLs_Extraction_Test_PDF_Encoding_Google_Docs_Renderer.pdf'
    else:  # second encoding type (a pdf created with mac os notes)
        file_path = f'{CWD}/URLs_Extraction_Test_PDF_Encoding_Quartz_PDFContext.pdf'

    # Extract URLs and Emails:
    urls = get_urls_and_emails_from_pdf_file(file_path)

    assert len(urls) == 7
    assert expected_output in urls


def test_separate_urls_and_emails():
    """
        Given:
        A set including urls and emails that were extracted from a PDF file.

        When:
            Running 'separate_urls_and_emails' function on the given set.

        Then:
            Verify the expected amount of URLs identified.
            Verify the expected amount of Emails identified.
            Verify that each url was classified as a url, ans email address was classified as an email.
            Verify that the 'special url' that included both url and email was classified as a url, and the inner email
            was classified as an email.
    """
    from ReadPDFFileV2 import separate_urls_and_emails

    urls_and_emails_input_set = {'https://test.com/', 'www.test.net',
                                 'https://test.com.co/ed/trn/update?email=user@test.net',
                                 'mailto:user@testtest.com', 'user@testing.com'}

    # Define the expected outputs:
    expected_urls = ['https://test.com/', 'www.test.net', 'https://test.com.co/ed/trn/update?email=user@test.net']
    expected_emails = ['user@testing.com', 'user@testtest.com', 'user@test.net']

    # Separate URLs from Emails:
    urls_ec, emails_ec = separate_urls_and_emails(urls_and_emails_input_set)
    urls_ec = [item.get('Data') for item in urls_ec]
    urls_ec_set = set(urls_ec)
    emails_ec_set = set(emails_ec)

    assert len(urls_ec) == 3
    assert len(emails_ec) == 3
    for url in expected_urls:
        assert url in urls_ec_set
    for email in expected_emails:
        assert email in emails_ec_set
