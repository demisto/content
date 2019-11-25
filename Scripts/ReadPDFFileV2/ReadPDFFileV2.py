import demistomock as demisto
from CommonServerPython import *

import subprocess
import glob
import os
import re
import errno
import shutil
from typing import List


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
    completed_process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if completed_process.returncode != 0:
        raise ShellException(f'Failed with the following error code: {completed_process.returncode}.'
                             f' Error: {completed_process.stderr}')
    elif completed_process.stderr:
        # raise only if stderr contains non warning messages
        lines = completed_process.stderr.splitlines()
        for l in lines:
            if 'warning:' not in l.lower():
                raise ShellException(f'{completed_process.stderr}Error code: {completed_process.returncode}')
        demisto.debug(f'ReadPDFFilev2: exec of [{cmd}] completed with warnings: {completed_process.stderr}')
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


def get_pdf_metadata(file_path):
    """Gets the metadata from the pdf as a dictionary"""
    user_password = demisto.args().get('userPassword')
    if user_password:
        metadata_txt = run_shell_command('pdfinfo', '-upw', user_password, file_path)
    else:
        metadata_txt = run_shell_command('pdfinfo', file_path)
    metadata = {}
    for line in metadata_txt.split('\n'):
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
    user_password = demisto.args().get('userPassword')
    if user_password:
        run_shell_command('pdftotext', '-upw', user_password, file_path, pdf_text_output_path)
    else:
        run_shell_command('pdftotext', file_path, pdf_text_output_path)
    text = ''
    with open(pdf_text_output_path, 'rb') as f:
        for line in f:
            text += line.decode('utf-8')
    return text


def get_pdf_htmls_content(pdf_path, output_folder):
    """Creates an html file and images from the pdf in output_folder and returns the text content of the html files"""
    pdf_html_output_path = f'{output_folder}/PDF.html'
    user_password = demisto.args().get('userPassword')
    if user_password:
        run_shell_command('pdftohtml', '-upw', user_password, pdf_path, pdf_html_output_path)
    else:
        run_shell_command('pdftohtml', pdf_path, pdf_html_output_path)
    html_file_names = get_files_names_in_path(output_folder, '*.html')
    html_content = ''
    for file_name in html_file_names:
        with open(file_name, 'rb') as f:
            for line in f:
                html_content += line.decode('utf-8')
    return html_content


def build_readpdf_entry_object(pdf_file, metadata, text, urls, images):
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
    indicators_hr = demisto.executeCommand("extractIndicators", {
        "text": all_pdf_data})[0][u"Contents"]
    results.append({
        "Type": entryTypes["note"],
        "ContentsFormat": formats["json"],
        "Contents": indicators_hr,
        "HumanReadable": indicators_hr
    })
    return results


def main():
    entry_id = demisto.args()["entryID"]
    # File entity
    pdf_file = {
        "EntryID": entry_id
    }

    # URLS
    urls_ec = []
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
                text = get_pdf_text(cpy_file_path, pdf_text_output_path)
                # Get URLS + emails:
                pdf_html_content = get_pdf_htmls_content(cpy_file_path, output_folder)
                urls = re.findall(urlRegex, pdf_html_content)
                urls_set = set(urls)
                emails = re.findall(EMAIL_REGXEX, pdf_html_content)
                urls_set = urls_set.union(set(emails))
                # this url is always generated with the pdf html file, and that's why we remove it
                urls_set.remove('http://www.w3.org/1999/xhtml')
                for url in urls_set:
                    urls_ec.append({"Data": url})
                # Get images:
                images = get_images_paths_in_path(output_folder)
            except Exception as e:
                demisto.results({
                    "Type": entryTypes["error"],
                    "ContentsFormat": formats["text"],
                    "Contents": f"Could not load pdf file in EntryID {entry_id}\nError: {str(e)}"
                })
                raise e
            readpdf_entry_object = build_readpdf_entry_object(pdf_file, metadata, text, urls_ec, images)
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
            shutil.rmtree(folder)


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()






  import pdfx
  from pdfminer.psparser import PSEOF
  from pdfminer.pdfdocument import PDFEncryptionError
  import traceback
  import sys
  reload(sys)
  sys.setdefaultencoding("utf-8")

  entry_id = demisto.args()["entryID"]

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


  #File entity
  pdf_file = {
      "EntryID" : entry_id
  }

  #URLS
  URLs = []

  maxFileSize = demisto.get(demisto.args(), "maxFileSize")
  if maxFileSize:
      maxFileSize = int(maxFileSize)
  else:
      maxFileSize = 1024**2
  res = demisto.executeCommand("getFilePath", {"id": entry_id})
  if isError(res[0]):
      demisto.results(res)
  else:
      path = demisto.get(res[0],"Contents.path")
      if path:
          try:
              pdf = pdfx.PDFx(path)
          except PSEOF:
              mark_suspicious('Missing EOF')
              sys.exit(0)
          except PDFEncryptionError:
              mark_suspicious('Possibly encrypted file')
              sys.exit(0)
          except TypeError:
              tb = traceback.format_exc()
              if 'pdf = pdfx.PDFx(args.pdf)' in tb and "out_str = in_str.decode(enc['encoding'])" in tb:
                  mark_suspicious("The script failed to read the PDF file. This might happen if your PDF file contains only an image")
              else:
                  mark_suspicious("The script failed read PDF file due to an unknown issue")
              sys.exit(0)

          if not pdf:
              demisto.results({
                  "Type": entryTypes["error"],
                  "ContentsFormat": formats["text"],
                  "Contents" : "Could not load pdf file in EntryID {0}".format(entry_id)
              })
              sys.exit(0)


          # Get metadata:
          metadata = pdf.get_metadata()

          # Get text:
          text = pdf.get_text()

          # Get URLs:
          references_dict = pdf.get_references_as_dict()
          if "url" in references_dict.keys():
              for url in references_dict["url"]:
                  URLs.append({"Data":url})

          #Add Text to file entity
          pdf_file["Text"] = text

          #Add Metadata to file entity
          for k in metadata.keys():
              pdf_file[k] = metadata[k]

          md = "### Metadata\n"
          md += "* " if metadata else ""
          md += "\n* ".join(["{0}: {1}".format(k,v) for k,v in metadata.iteritems()])

          md += "\n### URLs\n"
          md += "* " if URLs else ""
          md += "\n* ".join(["{0}".format(str(k["Data"])) for k in URLs])

          md += "\n### Text"
          md += "\n{0}".format(text)

          demisto.results({"Type" : entryTypes["note"],
                          "ContentsFormat" : formats["markdown"],
                          "Contents" : md,
                          "HumanReadable": md,
                          "EntryContext": {"File(val.EntryID == obj.EntryID)" : pdf_file, "URL" : URLs}
                          })

          all_pdf_data = ""
          if metadata:
              for k,v in metadata.iteritems():
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

      else:
          demisto.results({
              "Type" : entryTypes["error"],
              "ContentsFormat" : formats["text"],
              "Contents" : "EntryID {0} path could not be found".format(entry_id)
               })