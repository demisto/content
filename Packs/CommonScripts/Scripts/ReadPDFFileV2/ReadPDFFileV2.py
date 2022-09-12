import demistomock as demisto
from CommonServerPython import *

import PyPDF2
import subprocess
import glob
import os
import stat
import re
import errno
import shutil
import json
from typing import List, Set
from pikepdf import Pdf

URL_EXTRACTION_REGEX = r'(?:(?:https?|ftp|hxxps?):\/\/|www\[?\.\]?|ftp\[?\.\]?)(?:[-\w\d]+\[?\.\]?)+' \
                       r'[-\w\d]+(?::\d+)?(?:(?:\/|\?)[-\w\d+&@#\/%=~_$?!\-:,.\(\);]*[\w\d+&@#\/%=~_$\(\);])?'


# error class for shell errors
class ShellException(Exception):
    pass


try:
    ROOT_PATH = os.getcwd()
    MAX_IMAGES = int(demisto.args().get('maxImages', 20))
except OSError:
    return_error("The script failed to access the current working directory. This might happen if your docker isn't "
                 "set up correctly. Please contact customer support")
except ValueError:
    return_error("Value provided for maxImages is of the wrong type. Please provide an integer for maxImages")

EMAIL_REGXEX = "[a-zA-Z0-9-_.]+@[a-zA-Z0-9-_.]+"
# Documentation claims png is enough for pdftohtml, but through testing we found jpg can be generated as well
IMG_FORMATS = ['jpg', 'jpeg', 'png', 'gif']


def handle_error_read_only(fun, path, exp):
    """
    Handling errors that can be encountered in `shutil.rmtree()` execution.
    """
    demisto.debug(exp)

    # Checking if the file is Read-Only
    if not os.access(path, os.W_OK):
        demisto.debug(f'The {path} file is read-only')
        # Change the file permission to the writting
        try:
            os.chmod(path, stat.S_IWUSR)
            fun(path)
        except Exception as e:
            raise ValueError(str(e))
    else:
        raise ValueError(str(exp))


def mark_suspicious(suspicious_reason, entry_id):
    """Missing EOF, file may be corrupted or suspicious file"""

    dbot = {
        "DBotScore":
            {
                "Indicator": entry_id,
                "Type": "file",
                "Vendor": "PDFx",
                "Score": 2
            }
    }
    human_readable = f"{suspicious_reason}\nFile marked as suspicious for entry id: {entry_id}"
    LOG(suspicious_reason)
    return_outputs(human_readable, dbot, {})


def return_error_without_exit(message):
    """Same as return_error, without the sys.exit"""
    LOG(message)
    LOG.print_log()
    demisto.results({
        'Type': entryTypes['error'],
        'ContentsFormat': formats['text'],
        'Contents': str(message)
    })


def run_shell_command(command, *args):
    """Runs shell command and returns the result if not encountered an error"""
    cmd = [command] + list(args)
    completed_process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if completed_process.returncode != 0:
        raise ShellException(f'Failed with the following error code: {completed_process.returncode}.'
                             f' Error: {completed_process.stderr.decode("utf8")}')
    elif completed_process.stderr:
        demisto.debug(f'ReadPDFFilev2: exec of [{cmd}] completed with warnings: '
                      f'{completed_process.stderr.decode("utf8")}')
    return completed_process.stdout


def get_files_names_in_path(path, name_of_file, full_path=False):
    """Returns a list[str] of file names in path, will return full path if given full_path=True"""
    os.chdir(ROOT_PATH)
    os.chdir(path)
    res = []
    for file_path in glob.glob(name_of_file):
        if full_path:
            file_path = f'{path}/{file_path}'
        res.append(file_path)
    return res


def get_images_paths_in_path(path):
    """Gets images paths from path"""
    res: List[str] = []
    for img_type in IMG_FORMATS:
        img_format = f'*.{img_type}'
        res.extend(get_files_names_in_path(path, img_format, True))
    return res


def get_pdf_metadata(file_path, user_password=None):
    """Gets the metadata from the pdf as a dictionary"""
    if user_password:
        metadata_txt = run_shell_command('pdfinfo', '-upw', user_password, file_path)
    else:
        metadata_txt = run_shell_command('pdfinfo', '-enc', 'UTF-8', file_path)
    metadata = {}
    metadata_str = metadata_txt.decode('utf8', 'replace')
    for line in metadata_str.split('\n'):
        # split to [key, value...]
        line_arr = line.split(':')
        if len(line_arr) > 1:
            key = line_arr[0]
            # camelize key
            if ' ' in key:
                if 'PDF' in key:
                    key = key.title().replace('Pdf', 'PDF').replace(' ', '')

                else:
                    key = key.title().replace(' ', '')

            # handle values with and without ':'
            value = ''
            for i in range(1, len(line_arr)):
                value += line_arr[i].strip() + ':'
            # remove redundant ':'
            value = value[:-1]
            metadata[key] = value
    return metadata


def get_pdf_text(file_path, pdf_text_output_path):
    """Creates a txt file from the pdf in the pdf_text_output_path and returns the content of the txt file"""
    run_shell_command('pdftotext', file_path, pdf_text_output_path)
    text = ''
    with open(pdf_text_output_path, 'rb') as f:
        for line in f:
            text += line.decode('utf-8')
    return text


def get_pdf_htmls_content(pdf_path, output_folder):
    """Creates an html file and images from the pdf in output_folder and returns the text content of the html files"""
    pdf_html_output_path = f'{output_folder}/PDF.html'
    run_shell_command('pdftohtml', pdf_path, pdf_html_output_path)
    html_file_names = get_files_names_in_path(output_folder, '*.html')
    html_content = ''
    for file_name in html_file_names:
        with open(file_name, 'rb') as f:
            for line in f:
                html_content += str(line)
    return html_content


def build_readpdf_entry_object(pdf_file, metadata, text, urls, emails, images):
    """Builds an entry object for the main script flow"""
    # Add Text to file entity
    pdf_file["Text"] = text

    # Add Metadata to file entity
    for k in metadata.keys():
        pdf_file[k] = metadata[k]

    md = "### Metadata\n"
    md += "* " if metadata else ""
    md += "\n* ".join([f"{k}: {v}" for k, v in metadata.items()])

    md += "\n### URLs\n"
    md += "* " if urls else ""
    md += "\n* ".join([f'{str(k["Data"])}' for k in urls])

    md += "\n### Text"
    md += f"\n{text}"
    results = [{"Type": entryTypes["note"],
                "ContentsFormat": formats["markdown"],
                "Contents": md,
                "HumanReadable": md,
                "EntryContext": {"File(val.EntryID == obj.EntryID)": pdf_file, "URL": urls}
                }]
    if images:
        results[0]['HumanReadable'] = f"{results[0]['HumanReadable']}\n### Images"
        os.chdir(ROOT_PATH)
        for i, img in enumerate(images):
            if i >= MAX_IMAGES:
                break
            file = file_result_existing_file(img)
            results.append(file)
    all_pdf_data = ""
    if metadata:
        for k, v in metadata.items():
            all_pdf_data += str(v)
    if text:
        all_pdf_data += text
    if urls:
        for u in urls:
            u = u["Data"] + " "
            all_pdf_data += u

    # Extract indicators (omitting context output, letting auto-extract work)
    try:
        indicators_map = demisto.executeCommand("extractIndicators", {"text": all_pdf_data})[0][u"Contents"]
        indicators_map = json.loads(indicators_map)
        if emails:
            indicators_map["Email"] = emails
    except json.JSONDecodeError:
        pass
    ec = build_readpdf_entry_context(indicators_map)
    results.append({
        "Type": entryTypes["note"],
        "ContentsFormat": formats["json"],
        "Contents": indicators_map,
        "HumanReadable": indicators_map,
        "EntryContext": ec
    })
    return results


def build_readpdf_entry_context(indicators_map):
    ec = {}
    if isinstance(indicators_map, dict):
        if 'URL' in indicators_map:
            ec_url = []
            for url in indicators_map['URL']:
                ec_url.append({'Data': url})
            ec['URL'] = ec_url
        if 'Email' in indicators_map:
            ec_email = []
            for email in indicators_map['Email']:
                ec_email.append({'Email': email})
            ec['Account'] = ec_email
    return ec


def get_urls_from_binary_file(file_path):
    """Reading from the binary pdf in the pdf_text_output_path and returns a list of the urls in the file"""
    with open(file_path, 'rb') as file:
        # the urls usually appear in the form: '/URI (url)'
        urls = re.findall(r'/URI ?\((.*?)\)', str(file.read()))
    binary_file_urls = set()
    # make sure the urls match the url regex
    for url in urls:
        mached_url = re.findall(URL_EXTRACTION_REGEX, url)
        if len(mached_url) != 0:
            binary_file_urls.add(mached_url[0])
    return binary_file_urls


def get_urls_and_emails_from_pdf_html_content(cpy_file_path, output_folder):
    """
    Extract the URLs and emails from the pdf html content.

    Args:
        cpy_file_path (str): the path of the PDF file.
        output_folder (str): the folder output to get the HTML files from.
    Returns:
        tuple[set, set]: The URLs and emails that were found.
    """
    pdf_html_content = get_pdf_htmls_content(cpy_file_path, output_folder)
    return set(re.findall(URL_EXTRACTION_REGEX, pdf_html_content)), set(re.findall(EMAIL_REGXEX, pdf_html_content))


def decrypt_pdf_file(file_path, user_password, path_to_decrypted_file):
    """
    Gets a path to an encrypted PDF file and its password, and decrypts the file using pikepdf package.
    Args:
        file_path (str): A path to the encrypted PDF file.
        user_password (str): The password to the encrypted PDF file.
        path_to_decrypted_file (str): A path to save the decrypted PDF file to.

    Returns: None.

    """
    pdf_file = Pdf.open(file_path, password=user_password)
    pdf_file.save(path_to_decrypted_file)


def extract_url_from_annot_object(annot_object):
    """
    Extracts the URLs from the Annot object (under key: '/A').

    Args:
        annot_object (PyPDF2.generic.DictionaryObject): An object contains annotations of a PDF.

    Returns:
         (PyPDF2.generic.TextStringObject): The extracted url if exists, else - None.

    """

    # Extracts the URLs from the Annot object (under key: '/A'):
    if a := annot_object.get('/A'):
        if isinstance(a, PyPDF2.generic.IndirectObject):
            a = a.get_object()

        if url := a.get('/URI'):
            if isinstance(url, PyPDF2.generic.IndirectObject):
                url = url.get_object()
            return url


def extract_url(extracted_object):
    """
    Extracts URL (if exists) from the extracted object, according to the URL_EXTRACTION_REGEX.

    Args:
        extracted_object (PyPDF2.generic.TextStringObject): A TextStringObject object contains a url or an email.

    Returns:
         (str): The extracted url.
    """
    match = ''
    matched_url = re.findall(URL_EXTRACTION_REGEX, extracted_object)
    if len(matched_url) != 0:
        match = matched_url[0]

    return match


def extract_email(extracted_object):
    """
    Extracts Email (if exists) from the extracted object, according to the EMAIL_REGXEX.

    Args:
        extracted_object (PyPDF2.generic.TextStringObject): A TextStringObject object contains a url or an email.

    Returns:
         (str): The extracted email.
    """
    match = ''
    matched_email = re.findall(EMAIL_REGXEX, extracted_object)
    if len(matched_email) != 0:
        match = matched_email[0]

    return match


def extract_urls_and_emails_from_annot_objects(annot_objects):
    """
    Extracts URLs and Emails from the Annot objects, and separate them into two different sets.

    Args:
        annot_objects (List): A list of objects that contain annotations of a PDF.

    Returns:
         Tuple[set, set]: A set includes the extracted urls, A set includes the extracted emails.

    """

    urls = set()
    emails = set()

    for annot_object in annot_objects:
        if isinstance(annot_object, PyPDF2.generic.IndirectObject):
            try:
                annot_object = annot_object.get_object()
            except Exception as e:
                if "Could not find object" in str(e):
                    demisto.error(f'annot.get_object() encountered an error: {e}.\n Skipping without failure.')
                    continue
                else:
                    demisto.error(f'annot.get_object() encountered an error: {e}.')

        extracted_object = extract_url_from_annot_object(annot_object)
        # Separates URLs and Emails:
        if extracted_object:
            if url := extract_url(extracted_object):
                urls.add(url)
            if email := extract_email(extracted_object):
                emails.add(email)

    return urls, emails


def get_urls_and_emails_from_pdf_annots(file_path):
    """
    Extracts the URLs and Emails from the pdf's Annots (Annotations and Commenting) using PyPDF2 package.
    Args:
        file_path (str): The path of the PDF file.

    Returns:
        Tuple[set, set]: A set includes the URLs that were found, A set includes the Emails that were found.

    """
    all_urls: Set[str] = set()
    all_emails: Set[str] = set()

    with open(file_path, 'rb') as pdf_file:
        pdf = PyPDF2.PdfFileReader(pdf_file, strict=False)
        pages_len = len(pdf.pages)

        # Goes over the PDF, page by page, and extracts urls and emails:
        for page in range(pages_len):
            page_sliced = pdf.pages[page]
            page_object = page_sliced.get_object()

            # Extracts the PDF's Annots (Annotations and Commenting):
            if annots := page_object.get('/Annots'):
                if not isinstance(annots, PyPDF2.generic.ArrayObject):
                    annots = [annots]

                for annot in annots:
                    annot_objects = annot.get_object()
                    if not isinstance(annot_objects, PyPDF2.generic.ArrayObject):
                        annot_objects = [annot_objects]

                    # Extracts URLs and Emails:
                    urls_set, emails_set = extract_urls_and_emails_from_annot_objects(annot_objects)
                    all_urls = all_urls.union(urls_set)
                    all_emails = all_emails.union(emails_set)

    # Logging:
    if len(all_urls) == 0:
        demisto.debug('No URLs were extracted from the PDF.')
    if len(all_emails) == 0:
        demisto.debug('No Emails were extracted from the PDF.')

    return all_urls, all_emails


def extract_urls_and_emails_from_pdf_file(file_path, output_folder):
    """
    Extract URLs and Emails from the PDF file.

    Args:
        file_path (str): The path of the PDF file.
        output_folder (str): The output folder for html files.
    Returns:
        tuple[set, set]: A set including the URLs and emails that were found, A set including only emails that were
         extracted from the html content.
    """

    # Get urls from the binary file:
    binary_file_urls = get_urls_from_binary_file(file_path)

    # Get URLS + emails:
    annots_urls, annots_emails = get_urls_and_emails_from_pdf_annots(file_path)
    html_urls, html_emails = get_urls_and_emails_from_pdf_html_content(file_path, output_folder)

    # This url is always generated with the pdf html file, and that's why we remove it
    html_urls.remove('http://www.w3.org/1999/xhtml')

    # Unify urls:
    urls_set = annots_urls.union(html_urls, binary_file_urls)
    emails_set = annots_emails.union(html_emails)

    return urls_set, emails_set


def main():
    entry_id = demisto.args()["entryID"]
    user_password = str(demisto.args().get('userPassword', ''))
    # File entity
    pdf_file = {
        "EntryID": entry_id
    }

    # URLS
    urls_ec = []
    emails_ec = []
    folders_to_remove = []

    try:
        path = demisto.getFilePath(entry_id).get('path')
        if path:
            try:
                output_folder = "ReadPDF"
                os.makedirs(output_folder)
            except OSError as e:
                if e.errno != errno.EEXIST:
                    raise e
            try:
                folders_to_remove.append(output_folder)
                cpy_file_path = f'{output_folder}/ReadPDF.pdf'
                shutil.copy(path, cpy_file_path)

                # Get metadata:
                metadata = get_pdf_metadata(cpy_file_path, user_password)

                if user_password:  # The PDF is encrypted
                    dec_file_path = f'{output_folder}/DecryptedPDF.pdf'
                    decrypt_pdf_file(cpy_file_path, user_password, dec_file_path)
                    cpy_file_path = dec_file_path

                # Get text:
                pdf_text_output_path = f'{output_folder}/PDFText.txt'
                text = get_pdf_text(cpy_file_path, pdf_text_output_path)

                # Get URLS + emails:
                urls_set, emails_set = extract_urls_and_emails_from_pdf_file(cpy_file_path, output_folder)

                for url in urls_set:
                    urls_ec.append({"Data": url})
                for email in emails_set:
                    emails_ec.append(email)

                # Get images:
                images = get_images_paths_in_path(output_folder)

            except Exception as e:
                demisto.results({
                    "Type": entryTypes["error"],
                    "ContentsFormat": formats["text"],
                    "Contents": f"Could not load pdf file in EntryID {entry_id}\nError: {str(e)}"
                })
                raise e
            readpdf_entry_object = build_readpdf_entry_object(pdf_file, metadata, text, urls_ec, emails_ec, images)
            demisto.results(readpdf_entry_object)
        else:
            demisto.results({
                "Type": entryTypes["error"],
                "ContentsFormat": formats["text"],
                "Contents": f"EntryID {entry_id} path could not be found"
            })
    except ShellException as e:
        mark_suspicious(f'The script failed read PDF file due to an error: {str(e)}', entry_id)
    except Exception as e:
        return_error_without_exit(f'The script failed read PDF file due to an error: {str(e)}')
    finally:
        os.chdir(ROOT_PATH)
        for folder in folders_to_remove:
            shutil.rmtree(folder, onerror=handle_error_read_only)


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
