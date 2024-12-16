import demistomock as demisto
from CommonServerPython import *

import PyPDF2
import subprocess
import glob
import os
import stat
import re
import shutil
import json
from pikepdf import Pdf, PasswordError
import contextlib
import io
import html

URL_EXTRACTION_REGEX = (
    r"(?:(?:https?|ftp|hxxps?):\/\/|www\[?\.\]?|ftp\[?\.\]?)(?:[-\w\d]+\[?\.\]?)+"
    r"[-\w\d]+(?::\d+)?(?:(?:\/|\?)[-\w\d+&@#\/%=~_$?!\-:,.\(\);]*[\w\d+&@#\/%=~_$\(\);])?"
)
INTEGRATION_NAME = 'ReadPDFFileV2'
DEFAULT_NUM_IMAGES = 20


class PdfPermissionsException(Exception):
    """
    Every exception class that is in charge of catching errors that occur when trying to
    extract data from the PDF must inherit this class
    """


class PdfCopyingProtectedException(PdfPermissionsException):
    """
    This class is in charge of catching errors that occur when we try to extract data from
    a `copy-protected` file (Copy-protected files are files that prevent us from copy its content)
    This is relevant since we run a command that copies the content of the pdf file into a text file.
    """


class PdfInvalidCredentialsException(PdfPermissionsException):
    """
    This class is in charge of catching errors that occur when we try to decrypt an encrypted
    pdf file with the wrong password.
    """


# Error class for shell errors
class ShellException(Exception):
    pass


try:
    ROOT_PATH = os.getcwd()
except OSError:
    return_error(
        "The script failed to access the current working directory. This might happen if your docker isn't "
        "set up correctly. Please contact customer support"
    )

EMAIL_REGXEX = "[a-zA-Z0-9-_.]+@[a-zA-Z0-9-_.]+"
# Documentation claims png is enough for pdftohtml, but through testing we found jpg can be generated as well
IMG_FORMATS = ["jpg", "jpeg", "png", "gif"]


def handle_error_read_only(fun, path, exp) -> None:
    """
    Handling errors that can be encountered in `shutil.rmtree()` execution.
    """
    demisto.debug(exp)

    # Checking if the file is Read-Only
    if not os.access(path, os.W_OK):
        demisto.debug(f"The {path} file is read-only")
        # Change the file permission to the writing
        try:
            os.chmod(path, stat.S_IWUSR)
            fun(path)
        except Exception as e:
            raise ValueError(str(e))
    else:
        raise ValueError(str(exp))


def create_file_instance(entry_id: str, path: str, file_name: str, score: int | None) -> Common.File:
    dbot_score = Common.DBotScore(
        indicator=entry_id,
        indicator_type=DBotScoreType.FILE,
        integration_name='PDFx',
        score=score,
    )
    file = Common.File(
        dbot_score=dbot_score,
        extension="pdf",
        entry_id=entry_id,
        name=file_name,
        path=path,
    )
    return file


def mark_suspicious(suspicious_reason: str, entry_id: str, path: str, file_name: str) -> None:
    """Missing EOF, file may be corrupted or suspicious file"""

    human_readable = (
        f'{suspicious_reason}\nFile marked as suspicious for entry id: {entry_id}'
    )
    file_instance = create_file_instance(
        entry_id=entry_id,
        path=path,
        file_name=file_name,
        score=Common.DBotScore.SUSPICIOUS,
    )
    return_warning(message=human_readable, outputs=file_instance.to_context())


def run_shell_command(command: str, *args) -> bytes:
    """Runs shell command and returns the result if not encountered an error"""
    cmd = [command] + list(args)
    demisto.debug(f'Running the shell command {cmd=}')
    completed_process = subprocess.run(  # noqa: UP022
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    exit_codes = completed_process.returncode
    error_string = completed_process.stderr.decode('utf-8')
    demisto.debug(f'Got the following error: {exit_codes=},  {error_string=}')
    if exit_codes != 0:
        if 'PDF file is damaged' in error_string or 'Couldn\'t read xref table' in error_string:
            raise ShellException('PDf file is damaged/corrupted.')
        elif "Incorrect password" in error_string:
            raise PdfInvalidCredentialsException(
                'Incorrect password. Please provide the correct password.')
        elif 'Copying of text from this document is not allowed' in error_string:
            raise PdfCopyingProtectedException(
                'Copying is not permitted')
        raise ShellException(
            f'Failed with the following error code: {exit_codes}.\n'
            f' Error: {error_string}'
        )
    elif error_string:
        demisto.debug(
            f"ReadPDFFilev2: exec of [{cmd}] completed with warnings: "
            f'{error_string}'
        )
    return completed_process.stdout


def get_files_names_in_path(path: str, name_of_file: str, full_path: bool = False) -> list:
    """Returns a list[str] of file names in path, will return full path if given full_path=True"""
    os.chdir(ROOT_PATH)
    os.chdir(path)
    res = []
    for file_path in glob.glob(name_of_file):
        if full_path:
            file_path = f"{path}/{file_path}"
        res.append(file_path)
    return res


def get_images_paths_in_path(path: str) -> list[str]:
    """Gets images paths from path"""
    res: list[str] = []
    for img_type in IMG_FORMATS:
        img_format = f"*.{img_type}"
        res.extend(get_files_names_in_path(path, img_format, True))
    return res


def get_pdf_metadata(file_path: str, user_or_owner_password: str | None = None) -> dict:
    """Gets the metadata from the pdf as a dictionary"""
    if user_or_owner_password:
        try:
            demisto.debug('Trying password as user password, using the [upw] flag')
            metadata_txt = run_shell_command(
                "pdfinfo", "-upw", user_or_owner_password, file_path
            )
        except PdfInvalidCredentialsException:
            demisto.debug('Trying password as owner password, using the [opw] flag')
            metadata_txt = run_shell_command(
                "pdfinfo", "-opw", user_or_owner_password, file_path
            )
        demisto.debug('PDF file has been successfully opened. Metadata has been retrieved.')
    else:
        metadata_txt = run_shell_command("pdfinfo", "-enc", "UTF-8", file_path)
    metadata = {}
    metadata_str = metadata_txt.decode("utf8", "replace")
    for line in metadata_str.split("\n"):
        # split to [key, value...]
        line_arr = line.split(":")
        if len(line_arr) > 1:
            key = line_arr[0]
            # camelize key
            if " " in key:
                if "PDF" in key:
                    key = key.title().replace("Pdf", "PDF").replace(" ", "")

                else:
                    key = key.title().replace(" ", "")

            # Handle values with and without ':'
            value = ""
            for i in range(1, len(line_arr)):
                value += line_arr[i].strip() + ":"
            # remove redundant ':'
            value = value[:-1]
            metadata[key] = value
    return metadata


def bypass_copy_protected_limitations(pdf_file: str) -> None:
    """
    This function is in charge of handling the situation when a pdf is `copy-protected`.
    Copy protected files prevent us from extracting content from the file, therefore we need a way to bypass this limitation.
    """
    with Pdf.open(pdf_file, allow_overwriting_input=True) as pdf:
        pdf.save(pdf_file)


def get_pdf_text(file_path: str, pdf_text_output_path: str) -> str:
    """Creates a txt file from the pdf in the pdf_text_output_path and returns the content of the txt file"""
    try:
        run_shell_command("pdftotext", file_path, pdf_text_output_path)
    except PdfCopyingProtectedException:
        bypass_copy_protected_limitations(pdf_file=file_path)
        run_shell_command("pdftotext", file_path, pdf_text_output_path)
    text = ""
    with open(pdf_text_output_path, "rb") as f:
        for line in f:
            text += line.decode("utf-8")
    return text


def get_pdf_htmls_content(pdf_path: str, output_folder: str, unescape_url: bool = True) -> str:
    """Creates an html file and images from the pdf in output_folder and returns the text content of the html files"""
    pdf_html_output_path = f'{output_folder}/PDF_html'
    try:
        run_shell_command("pdftohtml", pdf_path, pdf_html_output_path)
    except PdfCopyingProtectedException:
        bypass_copy_protected_limitations(pdf_file=pdf_path)
        run_shell_command("pdftohtml", pdf_path, pdf_html_output_path)
    html_file_names = get_files_names_in_path(output_folder, "*.html")
    html_content = ""
    for file_name in html_file_names:
        with open(file_name, "rb") as f:
            for line in f:
                html_content += html.unescape(str(line)) if unescape_url else str(line)
    return html_content


def build_readpdf_entry_object(entry_id: str, metadata: dict, text: str, urls: list, emails: list, images: list[str],
                               max_images: int,
                               hash_contexts: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """Builds an entry object for the main script flow"""
    pdf_file = {"EntryID": entry_id}
    # Add Text to file entity
    pdf_file["Text"] = text

    # Add Metadata to file entity
    for k in metadata:
        pdf_file[k] = metadata[k]

    md = "### Metadata\n"
    md += "* " if metadata else ""
    md += "\n* ".join([f"{k}: {v}" for k, v in metadata.items()])

    md += "\n### URLs\n"
    md += "* " if urls else ""
    md += "\n* ".join([f'{str(k["Data"])}' for k in urls])

    md += "\n### Text"
    md += f"\n{text}"
    results = [
        {
            "Type": entryTypes["note"],
            "ContentsFormat": formats["markdown"],
            "Contents": md,
            "HumanReadable": md,
            "EntryContext": {"File(val.EntryID == obj.EntryID)": pdf_file, "URL": urls},
        }
    ]
    if images:
        results[0]["HumanReadable"] = f"{results[0]['HumanReadable']}\n### Images"
        os.chdir(ROOT_PATH)
        for i, img in enumerate(images):
            if i >= max_images:
                break
            file = file_result_existing_file(img)
            results.append(file)
    all_pdf_data = ""
    if metadata:
        for _, v in metadata.items():
            all_pdf_data += str(v)
    if text:
        all_pdf_data += text
    if urls:
        for u in urls:
            u = u["Data"] + " "
            all_pdf_data += u

    # Extract indicators (omitting context output, letting auto-extract work)
    try:
        indicators_map = demisto.executeCommand(
            "extractIndicators", {"text": all_pdf_data}
        )[0]["Contents"]
        indicators_map = json.loads(indicators_map)
        if emails:
            indicators_map["Email"] = emails
        if hash_contexts:
            indicators_map['Hashes'] = hash_contexts
    except json.JSONDecodeError:
        pass
    ec = build_readpdf_entry_context(indicators_map)
    results.append(
        {
            "Type": entryTypes["note"],
            "ContentsFormat": formats["json"],
            "Contents": indicators_map,
            "HumanReadable": indicators_map,
            "EntryContext": ec,
        }
    )
    return results


def build_readpdf_entry_context(indicators_map: Any) -> dict:
    ec = {}
    if isinstance(indicators_map, dict):
        if "URL" in indicators_map:
            ec_url = []
            for url in indicators_map["URL"]:
                ec_url.append({"Data": url})
            ec["URL"] = ec_url
        if "Email" in indicators_map:
            ec_email = []
            for email in indicators_map["Email"]:
                ec_email.append({"Email": email})
            ec["Account"] = ec_email
        if 'Hashes' in indicators_map:
            ec['Hashes'] = indicators_map['Hashes']
    return ec


def get_urls_from_binary_file(file_path: str) -> set:
    """Reading from the binary pdf in the pdf_text_output_path and returns a list of the urls in the file"""
    with open(file_path, "rb") as file:
        # the urls usually appear in the form: '/URI (url)'
        urls = re.findall(r"/URI ?\((.*?)\)", str(file.read()))
    binary_file_urls = set()
    # make sure the urls match the url regex
    for url in urls:
        mached_url = re.findall(URL_EXTRACTION_REGEX, url)
        if len(mached_url) != 0:
            binary_file_urls.add(mached_url[0])
    return binary_file_urls


def get_urls_and_emails_from_pdf_html_content(cpy_file_path: str, output_folder: str,
                                              unescape_url: bool = True) -> tuple[set, set]:
    """
    Extract the URLs and emails from the pdf html content.

    Args:
        cpy_file_path (str): the path of the PDF file.
        output_folder (str): the folder output to get the HTML files from.
    Returns:
        tuple[set, set]: The URLs and emails that were found.
    """
    pdf_html_content = get_pdf_htmls_content(cpy_file_path, output_folder, unescape_url)
    return set(re.findall(URL_EXTRACTION_REGEX, pdf_html_content)), set(re.findall(EMAIL_REGXEX, pdf_html_content))


def extract_url_from_annot_object(annot_object: Any):
    """
    Extracts the URLs from the Annot object (under key: '/A').

    Args:
        annot_object (PyPDF2.generic.DictionaryObject): An object contains annotations of a PDF.

    Returns:
         (PyPDF2.generic.TextStringObject): The extracted url if exists, else - None.

    """

    # Extracts the URLs from the Annot object (under key: '/A'):
    if a := annot_object.get("/A"):
        if isinstance(a, PyPDF2.generic.IndirectObject):
            a = a.get_object()

        if url := a.get("/URI"):
            if isinstance(url, PyPDF2.generic.IndirectObject):
                url = url.get_object()
            return url
        return None
    return None


def extract_url(extracted_object: Any):
    """
    Extracts URL (if exists) from the extracted object, according to the URL_EXTRACTION_REGEX.

    Args:
        extracted_object (PyPDF2.generic.TextStringObject): A TextStringObject object contains a url or an email.

    Returns:
         (str): The extracted url.
    """
    match = ""
    matched_url = re.findall(URL_EXTRACTION_REGEX, extracted_object)
    if len(matched_url) != 0:
        match = matched_url[0]

    return match


def extract_email(extracted_object: Any):
    """
    Extracts Email (if exists) from the extracted object, according to the EMAIL_REGXEX.

    Args:
        extracted_object (PyPDF2.generic.TextStringObject): A TextStringObject object contains a url or an email.

    Returns:
         (str): The extracted email.
    """
    match = ""
    matched_email = re.findall(EMAIL_REGXEX, extracted_object)
    if len(matched_email) != 0:
        match = matched_email[0]

    return match


def extract_urls_and_emails_from_annot_objects(annot_objects: list | Any):
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
                if 'Could not find object' in str(e):
                    demisto.error(f'annot.get_object() encountered an error: {e}.\n Skipping without failure.')
                    continue
                else:
                    demisto.error(f'annot.get_object() encountered an error: {e}.')

        extracted_object = extract_url_from_annot_object(annot_object)
        # Separates URLs and Emails:
        if extracted_object:
            if isinstance(extracted_object, bytes):
                extracted_object = extracted_object.decode()
            if url := extract_url(extracted_object):
                urls.add(url)
            if email := extract_email(extracted_object):
                emails.add(email)

    return urls, emails


def get_urls_and_emails_from_pdf_annots(file_path: str) -> tuple[set, set]:
    """
    Extracts the URLs and Emails from the pdf's Annots (Annotations and Commenting) using PyPDF2 package.
    Args:
        file_path (str): The path of the PDF file.
    Returns:
        Tuple[set, set]: A set includes the URLs that were found, A set includes the Emails that were found.
    """
    all_urls: set[str] = set()
    all_emails: set[str] = set()
    output_capture = io.StringIO()
    with open(file_path, 'rb') as pdf_file:
        # The following context manager was added so we could redirect error messages to the server logs since
        # PyPDF2 would sometimes return warnings on some files (warnings and not errors because strict=False), and these warnings
        # would be flushed to stderr, and therefore they would be returned as an error message to the user instead of being
        # flushed to the server logs.
        with contextlib.redirect_stderr(output_capture):
            pdf = PyPDF2.PdfReader(pdf_file, strict=False)
            pages_len = len(pdf.pages)

            # Goes over the PDF, page by page, and extracts urls and emails:
            for page in range(pages_len):
                page_sliced = pdf.pages[page]
                page_object = page_sliced.get_object()

                # Extracts the PDF's Annots (Annotations and Commenting):
                if annots := page_object.get('/Annots'):  # type: ignore[union-attr]
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
        demisto.debug(output_capture.getvalue())
    # Logging:
    if len(all_urls) == 0:
        demisto.debug('No URLs were extracted from the PDF.')
    if len(all_emails) == 0:
        demisto.debug('No Emails were extracted from the PDF.')

    return all_urls, all_emails


def extract_urls_and_emails_from_pdf_file(file_path: str, output_folder: str,
                                          unescape_url: bool = True) -> tuple[list, list]:
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
    html_urls, html_emails = get_urls_and_emails_from_pdf_html_content(file_path, output_folder, unescape_url)

    # This url might be generated with the pdf html file, if so, we remove it
    html_urls.discard('http://www.w3.org/1999/xhtml')

    # Unify urls:
    urls_set = annots_urls.union(html_urls, binary_file_urls)
    emails_set = annots_emails.union(html_emails)

    urls_ec = []
    emails_ec = []
    for url in urls_set:
        urls_ec.append({"Data": url})
    for email in emails_set:
        emails_ec.append(email)

    return urls_ec, emails_ec


def extract_hash_contexts_from_pdf_file(file_text: str) -> list[dict[str, Any]]:
    """Extracts the hashes from the file's text, and converts them to hash contexts.

    Args:
        file_text (str): The text extracted from the PDF.

    Returns:
        list[dict[str, Any]]: A list of hash contexts.
    """
    hash_contexts: list[dict[str, Any]] = []
    hashes_in_file = get_hashes_from_file(file_text)
    for hash_type, hashes in hashes_in_file.items():
        if hashes:
            hash_contexts.extend(convert_hash_to_context(hash_type, hashes))
    return hash_contexts


def convert_hash_to_context(hash_type: str, hashes: set[Any]) -> list[dict[str, Any]]:
    """Converts the given hashes to hash contexts

    Args:
        hash_type (str): The hash type of the given hashes.
        hashes (set[Any]): The set of hashes.

    Returns:
        list[dict[str, Any]]: A list of hash contexts that have the same hash type.
    """
    hash_context: list[dict[str, Any]] = [{'type': hash_type, 'value': hash} for hash in hashes]
    return hash_context


def get_hashes_from_file(file_text: str) -> dict[str, set[Any]]:
    """Extracts all the hashes found in the file's text.

    Args:
        file_text (str): The file's text.

    Returns:
        dict[str, set[Any]]: A dictionary that holds the hash types as keys, and each key
        holds the set of hashes corresponding to that hash type.
    """
    demisto.debug('Extracting hashes from file')
    hashes: dict[str, set[Any]] = {}
    hashes['SHA1'] = set(re.findall(sha1Regex, file_text))
    hashes['SHA256'] = set(re.findall(sha256Regex, file_text))
    hashes['SHA512'] = set(re.findall(sha512Regex, file_text))
    hashes['MD5'] = set(re.findall(md5Regex, file_text))

    return hashes


def handling_pdf_credentials(cpy_file_path: str, dec_file_path: str, encrypted: str = '',
                             user_password: str = '') -> str:
    """
    This function decrypts the pdf if needed.
    """
    try:
        if user_password or 'yes' in encrypted:
            with Pdf.open(cpy_file_path, allow_overwriting_input=True, password=user_password) as pdf:
                pdf.save(dec_file_path)
                return dec_file_path
    except PasswordError:
        raise PdfInvalidCredentialsException('Incorrect password. Please provide the correct password.')
    return cpy_file_path


def extract_data_from_pdf(path: str, user_password: str, entry_id: str, max_images: int | None, working_dir: str,
                          unescape_url: bool = True) -> None:
    max_images = max_images if max_images else DEFAULT_NUM_IMAGES
    if path:
        cpy_file_path = f'{working_dir}/WorkingReadPDF.pdf'
        shutil.copy(path, cpy_file_path)
        metadata = get_pdf_metadata(path, user_password)
        encrypted = metadata.get('Encrypted', '')

        cpy_file_path = handling_pdf_credentials(cpy_file_path=cpy_file_path,
                                                 dec_file_path=f'{working_dir}/DecWorkingReadPDF.pdf',
                                                 encrypted=encrypted,
                                                 user_password=user_password)

        # Get text:
        pdf_text_output_path = f"{working_dir}/PDFText.txt"
        text = get_pdf_text(cpy_file_path, pdf_text_output_path)

        # Get hash contexts
        hash_contexts = extract_hash_contexts_from_pdf_file(text)

        # Get URLS + emails:
        urls_ec, emails_ec = extract_urls_and_emails_from_pdf_file(cpy_file_path, working_dir, unescape_url)

        # Get images:
        images = get_images_paths_in_path(working_dir)
        readpdf_entry_object = build_readpdf_entry_object(entry_id,
                                                          metadata,
                                                          text,
                                                          urls_ec,
                                                          emails_ec,
                                                          images,
                                                          max_images=max_images,
                                                          hash_contexts=hash_contexts)

        return_results(readpdf_entry_object)
    else:
        raise Exception(f"EntryID {entry_id} path could not be found")


def main():  # pragma: no cover
    args = demisto.args()
    unescape_url: bool = argToBoolean(args.get("unescape_url", "true"))
    working_dir = 'ReadPDFTemp'
    try:
        if not os.path.exists(working_dir):
            """ Check if the working directory does not exist and create it """
            os.makedirs(working_dir)
        entry_id = args.get('entryID')
        user_password = str(args.get('userPassword', ''))
        max_images = arg_to_number(args.get('maxImages', None))
        path = demisto.getFilePath(entry_id).get('path')

        extract_data_from_pdf(path=path, user_password=user_password, entry_id=entry_id, max_images=max_images,
                              working_dir=working_dir, unescape_url=unescape_url)
    except PdfPermissionsException as e:
        return_warning(str(e))
    except ShellException as e:
        file_name = demisto.getFilePath(entry_id).get('name')
        mark_suspicious(
            suspicious_reason=f'The script {INTEGRATION_NAME} failed due to an error\n{str(e)}',
            entry_id=entry_id,
            path=path,
            file_name=file_name,
        )
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(str(e))
    finally:
        os.chdir(ROOT_PATH)
        shutil.rmtree(working_dir, onerror=handle_error_read_only)


if __name__ in ["__main__", "__builtin__", "builtins"]:
    main()
