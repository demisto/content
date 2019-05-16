import demistomock as demisto
# import PyPDF2
# import shutil

def test_get_files_names_in_path():
    from ReadPDFFile import get_files_names_in_path
    pdf_file_names = get_files_names_in_path('test_data', '*.pdf')
    assert 'scanned.pdf' in pdf_file_names

    pdf_file_names = get_files_names_in_path('test_data', '*.pdf', full_path=True)
    assert 'test_data/text-only.pdf' in pdf_file_names


def test_get_images_paths_in_path():
    from ReadPDFFile import get_images_paths_in_path
    img_file_paths = get_images_paths_in_path('test_data')
    assert 'test_data/test1.png' in img_file_paths
    assert 'test_data/test2.jpg' in img_file_paths
    assert 'test_data/scanned.pdf' not in img_file_paths


def test_get_pdf_metadata_with_encrypted(mocker):
    mocker.patch.object(demisto, 'args', return_value={'userPassword': '1234'})
    from ReadPDFFile import get_pdf_metadata
    from ReadPDFFile import USER_PASSWORD
    print(f'User password: {USER_PASSWORD}')
    metadata = get_pdf_metadata('encrypted.pdf')
    expected = {
        'Title': 'sample1.pdf',
        'Keywords': '',
        'Creator': 'Preview',
        'Producer': 'macOS Version 10.14.4 (Build 18E226) Quartz PDFContext',
        'CreationDate': 'Wed May 15 11:18:48 2019 IDT',
        'ModDate': 'Wed May 15 11:18:48 2019 IDT',
        'Tagged': 'no',
        'UserProperties': 'no',
        'Suspects': 'no', 'Form': 'none',
        'JavaScript': 'no',
        'Pages': '2',
        'Encrypted': 'yes (print:yes copy:yes change:yes addNotes:yes algorithm:AES)',
        'Page size': '595 x 842 pts (A4)',
        'Page rot': '0',
        'File size': '71085 bytes',
        'Optimized': 'no',
        'PDF version': '1.6'
    }
    assert expected == metadata


# def encrypt_pdf(filename: str, password: str) -> str:
#     """
#     Encrypts a file and returns the filename of the encrypted file.
#     Precondition: File is not encrypted
#     """
#     with open(filename, 'rb') as pdf_file:
#         pdf_reader = PyPDF2.PdfFileReader(pdf_file)
#         pdf_writer = PyPDF2.PdfFileWriter()
#
#         for page_number in range(pdf_reader.numPages):
#             pdf_writer.addPage(pdf_reader.getPage(page_number))
#         pdf_writer.encrypt(password)
#
#         filename_encrypted = filename.rstrip('.pdf') + "_encrypted.pdf"
#
#         with open(filename_encrypted, 'wb') as pdf_file_encrypted:
#             pdf_writer.write(pdf_file_encrypted)
#     return filename_encrypted


def test_get_metadata_without_encrypted(tmp_path):
    from ReadPDFFile import get_pdf_metadata
    # encryp
    # shutil.copyfile('test_data/encrypted.pdf', f'{tmp_path}/encrypted.pdf')
    # encrypted_path = encrypt_pdf('test_data/encrypted.pdf', '1234')
    try:
        get_pdf_metadata('encrypted.pdf')
        raise Exception("Incorrect password exception should've been thrown")
    except TypeError as e:
        assert 'Command Line Error: Incorrect password\n' == str(e)

    metadata = get_pdf_metadata('text-only.pdf')
    print(metadata)
    expected = {
        'Title': 'Microsoft Word - Document1',
        'Keywords': '',
        'Creator': 'Word',
        'Producer': 'macOS Version 10.14.4 (Build 18E226) Quartz PDFContext',
        'CreationDate': 'Wed May 15 11:47:28 2019 UTC',
        'ModDate': 'Wed May 15 11:47:28 2019 UTC',
        'Tagged': 'no',
        'UserProperties': 'no',
        'Suspects': 'no',
        'Form': 'none',
        'JavaScript': 'no',
        'Pages': '1',
        'Encrypted': 'no',
        'Page size': '595 x 842 pts (A4)',
        'Page rot': '0',
        'File size': '18920 bytes',
        'Optimized': 'no',
        'PDF version': '1.3'
    }

    assert expected == metadata


def test_get_pdf_text_with_encrypted(mocker, tmp_path):
    mocker.patch.object(demisto, 'args', return_value={'userPassword': '1234'})
    from ReadPDFFile import get_pdf_text
    text = get_pdf_text('encrypted.pdf', f'{tmp_path}/encrypted.txt')
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
    from ReadPDFFile import get_pdf_text
    try:
        get_pdf_text('encrypted.pdf', f'{tmp_path}/encrypted.txt')
        raise Exception("Incorrect password exception should've been thrown")
    except TypeError as e:
        assert 'Command Line Error: Incorrect password\n' == str(e)

    text = get_pdf_text('text-only.pdf', f'{tmp_path}/text-only.txt')
    expected = "עברית"
    assert expected in text
    assert text.startswith('This is a pdf document with a text line within it.')

    text = get_pdf_text('text-with-images.pdf', f'{tmp_path}/text-with-images.txt')
    expected = 'Create an ETD Using Adobe Acrobat'
    assert text.startswith(expected)

    text = get_pdf_text('scanned.pdf', f'{tmp_path}/scanned.txt')
    expected = '\x0c'
    assert expected == text


def test_get_pdf_htmls_content_with_encrypted(mocker, tmp_path):
    mocker.patch.object(demisto, 'args', return_value={'userPassword': '1234'})
    from ReadPDFFile import get_pdf_htmls_content
    from ReadPDFFile import get_images_paths_in_path
    html_text = get_pdf_htmls_content('encrypted.pdf', tmp_path)
    expected = 'If you are end user who wishes to use XSL Formatter yourself, you may purchase ' \
               'from our Reseller or direct from Antenna<br/>House.<br/>'
    assert len(get_images_paths_in_path(tmp_path)) != 0, 'Failed to get images from html'
    assert expected in html_text


def test_get_pdf_htmls_content_without_encrypted(tmp_path):
    from ReadPDFFile import get_pdf_htmls_content
    from ReadPDFFile import get_images_paths_in_path
    try:
        get_pdf_htmls_content('encrypted.pdf', tmp_path)
        raise Exception("Incorrect password exception should've been thrown")
    except TypeError as e:
        assert 'Command Line Error: Incorrect password\n' == str(e)

    html_text = get_pdf_htmls_content('hyperlinks.pdf', tmp_path)
    assert 'http://www.antennahouse.com/purchase.htm' in html_text
    assert len(get_images_paths_in_path(tmp_path)) != 0, 'Failed to get images from html'
