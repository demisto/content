import requests

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

NON_SSL_PREFIX = "http"
SSL_PREFIX = "https"
VENDOR = "URL SSL Verification"
SUSPICIOUS_SCORE = 2
URL_REGEX_PATTERN = r',(?=https?://)'

url_arg = demisto.get(demisto.args(), "url")
# urls = re.split(URL_REGEX_PATTERN, url_arg)
urls = argToList(url_arg)

url_list = []

ec = {
    'URL': [],
    'DBotScore': []
}

for url in urls:
    url_obj = {
        "Data": url
    }
    malicious = None

    # Check if url is non SSL
    if not SSL_PREFIX in url.lower():
        malicious = {
            "Vendor": VENDOR,
            "Description": "The URL is not secure under SSL"
        }
    # Check SSL signature
    else:
        try:
            requests.get(url)
        except requests.exceptions.SSLError as e:
            malicious = {
                "Vendor": VENDOR,
                "Description": "SSL Certificate verification failed"
            }
        except requests.exceptions.RequestException as e:
            malicious = {
                "Vendor": VENDOR,
                "Description": "Failed to establish a new connection with the URL"
            }

    if malicious:
        ec["DBotScore"].append({
            "Indicator": url,
            "Type": "url",
            "Vendor": VENDOR,
            "Score": SUSPICIOUS_SCORE
        })

        url_obj["Verified"] = False
        url_obj["Malicious"] = malicious
    else:
        url_obj["Verified"] = True

    url_list.append(url_obj)


ec["URL(val.Data && val.Data === obj.Data)"] = url_list

preview_list = [{"URL": url["Data"], "Verified": url["Verified"], "Description": demisto.get(
    url, "Malicious.Description") or "SSL certificate is verified"} for url in url_list]

md = tableToMarkdown("URL SSL Verification", preview_list, ["URL", "Verified", "Description"])

demisto.results({
    "Type": entryTypes["note"],
    "Contents": url_list,
    "ContentsFormat": formats["json"],
    "HumanReadable": md,
    "EntryContext": ec
})
