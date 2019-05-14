import demistomock as demisto
from CommonServerPython import *

import subprocess
import glob, os
import re
import errno
import shutil

ROOT_PATH = os.getcwd()


def mark_suspicious(suspicious_reason):
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

    human_readable = "{}, file marked as suspicious for entry id: {}".format(suspicious_reason, entry_id)

    return_outputs(human_readable, dbot, {})


def run_shell_command(command, arg1, *args):
    cmd = [command, arg1] + list(args)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    o, e = proc.communicate()
    return o.decode('utf8'), e.decode('utf8')


def get_files_names_in_path(path, name_of_file):
    # os.chdir(ROOT_PATH)
    os.chdir(path)
    res = []
    for file_path in glob.glob(name_of_file):
        res.append(file_path)
    return res


def get_images_names_in_path(path):
    # os.chdir(ROOT_PATH)
    os.chdir(path)
    res = []
    res.extend(get_files_names_in_path(path, "*.ppm"))
    res.extend(get_files_names_in_path(path, "*.bpm"))
    res.extend(get_files_names_in_path(path, "*.jpg"))
    res.extend(get_files_names_in_path(path, "*.png"))
    return res


def get_pdf_metadata(file_path):
    metadata_txt, e = run_shell_command('pdfinfo', file_path)
    metadata = {}
    for line in metadata_txt.split('\n'):
        # split to [key, value...]
        line_arr = line.split(':')
        if len(line_arr) > 1:
            key = line_arr[0]
            # handle values with and without ':'
            value = ''
            for i in range(1, len(line_arr)):
                value += line_arr[i].strip() + ':'
            # remove redundant ':'
            value = value[:-1]
            metadata[key] = value
    return metadata


def get_pdf_text(file_path):
    run_shell_command('pdftotext', cpy_file_path, pdf_text_output_path)
    text = ''
    with open(pdf_text_output_path, 'rb') as f:
        for line in f:
            text += line.decode('utf-8')
    return text


def get_pdf_htmls_content(pdf_path, output_folder):
    pdf_html_output_path = f'{output_folder}/PDFHtml.html'
    run_shell_command('pdftohtml', pdf_path, pdf_html_output_path)
    html_file_names = get_files_names_in_path(output_folder, '*.html')
    html_content = ''
    for file_name in html_file_names:
        with open(file_name, 'rb') as f:
            for line in f:
                html_content += line.decode('utf-8')
    return html_content


entry_id = demisto.args()["entryID"]
# File entity
pdf_file = {
    "EntryID": entry_id
}

# URLS
URLs = []
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
            pass
        try:
            folders_to_remove.append(output_folder)
            cpy_file_path = f'{output_folder}/ReadPDF.pdf'
            shutil.copy(path, cpy_file_path)

            # Get metadata:
            metadata = get_pdf_metadata(cpy_file_path)

            # Get text:
            pdf_text_output_path = f'{output_folder}/PDFText.txt'
            text = get_pdf_text(pdf_text_output_path)

            # Get URLS + Images:
            pdf_html_content = get_pdf_htmls_content(cpy_file_path, output_folder)
            urls = re.findall(urlRegex, pdf_html_content)
            urls = set(urls)
            for url in urls:
                URLs.append({"Data": url})
            images = get_images_names_in_path(output_folder)

        except Exception as e:
            demisto.results({
                "Type": entryTypes["error"],
                "ContentsFormat": formats["text"],
                "Contents" : "Could not load pdf file in EntryID {0}\nError: {1}".format(entry_id, str(e))
            })
            raise e

        # Add Text to file entity
        pdf_file["Text"] = text

        # Add Metadata to file entity
        for k in metadata.keys():
            pdf_file[k] = metadata[k]

        md = "### Metadata\n"
        md += "* " if metadata else ""
        md += "\n* ".join(["{0}: {1}".format(k,v) for k,v in metadata.items()])

        md += "\n### URLs\n"
        md += "* " if URLs else ""
        md += "\n* ".join(["{0}".format(str(k["Data"])) for k in URLs])

        md += "\n### Text"
        md += "\n{0}".format(text)

        demisto.results({"Type" : entryTypes["note"],
                         "ContentsFormat" : formats["markdown"],
                         "Contents" : md,
                         "HumanReadable": md,
                         "EntryContext": {"File(val.EntryID == obj.EntryID)": pdf_file, "URL": URLs}
                         })

        all_pdf_data = ""
        if metadata:
            for k,v in metadata.items():
                all_pdf_data += str(v)
        if text:
            all_pdf_data += text
        if URLs:
            for u in URLs:
                u = u["Data"] + " "
                all_pdf_data += u

        # Extract indicators (omitting context output, letting auto-extract work)
        indicators_hr = demisto.executeCommand("extractIndicators", {
            "text": all_pdf_data})[0][u"Contents"]
        demisto.results({
            "Type": entryTypes["note"],
            "ContentsFormat": formats["json"],
            "Contents": indicators_hr,
            "HumanReadable": indicators_hr
        })
        # if images:
        #     demisto.results({
        #         "Type": entryTypes["note"],
        #         "ContentsFormat": formats["text"],
        #         "Contents": '',
        #         "HumanReadable": '### Images'
        #     })
        #     for img in images:
        #         with open(img, 'rb') as f:
        #             data = b''
        #             for line in f:
        #                 data += line
        #             stored_img = fileResult(img, data)
        #             demisto.results({
        #                 'Type': entryTypes['image'],
        #                 'ContentsFormat': formats['text'],
        #                 'File': stored_img,
        #                 'Contents': ''
        #             })
    else:
        demisto.results({
            "Type" : entryTypes["error"],
            "ContentsFormat" : formats["text"],
            "Contents": "EntryID {0} path could not be found".format(entry_id)
        })
finally:
    os.chdir(ROOT_PATH)
    for folder in folders_to_remove:
        shutil.rmtree(folder)
