import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import re


# Scipt result
res = False
# Mandatory arguments
file_entry_ids = demisto.args()["ForensicFileEntry"]
forensic_files = file_entry_ids if isinstance(file_entry_ids, list) else file_entry_ids.split(",")

try:
    for entry in forensic_files:
        files_info = demisto.getFilePath(id=entry)
        with open(files_info["path"], "r") as file_handle:
            file_content = file_handle.read()

            result = re.findall('hm rеvеnuе & custоms', file_content, re.IGNORECASE)
            if len(result):
                res = True

            result = re.findall('GOV.UK', file_content)
            if len(result):
                res = True

            result1 = re.findall('hmrc', file_content, re.IGNORECASE)
            result2 = re.findall('gov.uk', file_content, re.IGNORECASE)
            if len(result1) and len(result2):
                res = True

            result1 = re.findall('tax refund', file_content, re.IGNORECASE)
            result2 = re.findall('gov.uk', file_content, re.IGNORECASE)
            if len(result1) and len(result2):
                res = True

            ec = {
                "SlashNext.PhishingBrand": "HMRC" if res else "Unknown"
            }

            ioc_cont = {
                "PhishingBrand": "HMRC" if res else "Unknown"
            }

            md = tableToMarkdown(
                "HMRC Targeted Phishing Detection",
                ioc_cont,
                ['PhishingBrand']
            )

            return_outputs(md, ec, ioc_cont)

except Exception as ex:
    return_error("Exception Occurred, {}".format(str(ex)))
