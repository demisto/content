import demistomock as demisto
import os
from ReadPDFFileV2 import ShellException

CWD = os.getcwd() if os.getcwd().endswith('test_data') else f'{os.getcwd()}/test_data'


def open_html_file(file):
    with open(file, "r", encoding='utf-8') as f:
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


def test_get_pdf_metadata_with_encrypted(mocker):
    mocker.patch.object(demisto, 'args', return_value={'userPassword': '1234'})
    from ReadPDFFileV2 import get_pdf_metadata
    metadata = get_pdf_metadata(f'{CWD}/encrypted.pdf')
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


def test_get_pdf_text_with_encrypted(mocker, tmp_path):
    mocker.patch.object(demisto, 'args', return_value={'userPassword': '1234'})
    from ReadPDFFileV2 import get_pdf_text
    text = get_pdf_text(f'{CWD}/encrypted.pdf', f'{tmp_path}/encrypted.txt')
    expected = "XSL FO Sample Copyright © 2002-2005 Antenna House, Inc. All rights reserved.\n\n" \
               "Links in PDF\nPDF link is classified into two parts, link to the specified position in the PDF " \
               "document, and link to the external document.\n" \
               "The internal-destination property of fo:basic-link indicates to link to the position in the same" \
               " document. The externaldestination property indicates to link to external document. " \
               "Below shows the example.\n\nExample of a link to internal destination\nRefer to Purchasing " \
               "Assistance to get more information.\nExample of a link to external destination\nRefer to Purchasing " \
               "Assistance to get more information."
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


def test_get_pdf_htmls_content_with_encrypted(mocker, tmp_path):
    mocker.patch.object(demisto, 'args', return_value={'userPassword': '1234'})
    from ReadPDFFileV2 import get_pdf_htmls_content
    from ReadPDFFileV2 import get_images_paths_in_path
    html_text = get_pdf_htmls_content(f'{CWD}/encrypted.pdf', tmp_path)
    expected = 'If you are end user who wishes to use XSL Formatter yourself, you may purchase ' \
               'from our Reseller or direct from Antenna<br/>House.<br/>'
    assert len(get_images_paths_in_path(tmp_path)) != 0, 'Failed to get images from html'
    assert expected in html_text


def test_get_pdf_htmls_content_without_encrypted(tmp_path):
    from ReadPDFFileV2 import get_pdf_htmls_content
    from ReadPDFFileV2 import get_images_paths_in_path
    try:
        get_pdf_htmls_content(f'{CWD}/encrypted.pdf', tmp_path)
        raise Exception("Incorrect password exception should've been thrown")
    except ShellException as e:
        assert 'Incorrect password' in str(e)
        assert 'error code: 1' in str(e)

    html_text = get_pdf_htmls_content(f'{CWD}/hyperlinks.pdf', tmp_path)
    assert 'http://www.antennahouse.com/purchase.htm' in html_text
    assert len(get_images_paths_in_path(tmp_path)) != 0, 'Failed to get images from html'


def test_build_readpdf_entry_object_empty_extract(mocker):
    from ReadPDFFileV2 import build_readpdf_entry_object
    mocker.patch.object(demisto, 'executeCommand', return_value=[{u'Contents': ''}])
    pdf_file = {'Text': 'test'}
    res = build_readpdf_entry_object(pdf_file, {}, '', '', '', '')
    assert res[0]['HumanReadable'] == '### Metadata\n\n### URLs\n\n### Text\n'


def test_get_urls_from_binary_file():
    from ReadPDFFileV2 import get_urls_from_binary_file
    urls = get_urls_from_binary_file(f'{CWD}/text-with-images.pdf')
    assert len(urls) == 10
