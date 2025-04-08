import demistomock as demisto  # noqa: F401
import requests
from CommonServerPython import *  # noqa: F401

NON_SSL_PREFIX = "http"
SSL_PREFIX = "https"
VENDOR = "URL SSL Verification"
SUSPICIOUS_SCORE = 2
URL_REGEX_PATTERN = r",(?=https?://)"


def arg_to_list_with_regex(arg):
    """
    Converts a string representation of args to a python list

    :type arg: ``str`` or ``list``
    :param arg: Args to be converted (required)

    :return: A python list of args
    :rtype: ``list``
    """
    if not arg:
        return []
    if isinstance(arg, list):
        return arg
    if isinstance(arg, STRING_TYPES):
        if arg[0] == "[" and arg[-1] == "]":
            return json.loads(arg)
        return re.split(URL_REGEX_PATTERN, arg)  # type: ignore[arg-type]
    return arg


    
def verify_ssl_certificate(url):
    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        redirect_chain = response.history + [response]
    except requests.exceptions.SSLError:
        return {"Vendor": VENDOR, "Description": "SSL Certificate verification failed"}
    except requests.exceptions.RequestException as e:
        demisto.debug(f"Request failed: {e}")
        return {"Vendor": VENDOR, "Description": "Failed to establish a new connection with the URL"}
    
    is_all_http = True
    for response in redirect_chain:
        redirected_url = response.url
        demisto.debug(f"URL address:{redirected_url}")
        if SSL_PREFIX not in url.lower():
            continue
        is_all_http = False
        try:
            requests.get(redirected_url, timeout=10, verify=True)
        except requests.exceptions.SSLError:
            return {"Vendor": VENDOR, "Description": "SSL Certificate verification failed"}
        except requests.exceptions.RequestException:
            return {"Vendor": VENDOR, "Description": "Failed to establish a new connection with the URL"}
    if is_all_http:
        return {"Vendor": VENDOR, "Description": "The URL is not secure under SSL"}

    return None
    
def mark_http_as_suspicious(set_http_as_suspicious):
    # Could be None in previous playbooks that using this automation.
    return set_http_as_suspicious != "false"


def main():  # pragma: no cover
    url_arg = demisto.get(demisto.args(), "url")
    urls = arg_to_list_with_regex(url_arg)

    set_http_as_suspicious = demisto.args().get("set_http_as_suspicious")

    url_list = []

    ec = {"URL": [], "DBotScore": []}  # type: dict

    for url in urls:
        url_obj = {"Data": url}
        malicious = verify_ssl_certificate(url)

        if malicious:
            url_obj["Verified"] = False
            url_obj["Malicious"] = malicious
        else:
            url_obj["Verified"] = True

        if mark_http_as_suspicious(set_http_as_suspicious):
            if SSL_PREFIX not in url.lower():
                ec["DBotScore"].append({"Indicator": url, "Type": "url", "Vendor": VENDOR, "Score": SUSPICIOUS_SCORE})
            else:
                ec["DBotScore"].append("Unknown")
        else:
            if malicious:
                ec["DBotScore"].append({"Indicator": url, "Type": "url", "Vendor": VENDOR, "Score": SUSPICIOUS_SCORE})
            else:
                ec["DBotScore"].append("Unknown")
                
        url_list.append(url_obj)

    ec["URL(val.Data && val.Data === obj.Data)"] = url_list

    preview_list = [
        {
            "URL": url["Data"],
            "Verified": url["Verified"],
            "Description": demisto.get(url, "Malicious.Description") or "SSL certificate is verified",
        }
        for url in url_list
    ]

    md = tableToMarkdown("URL SSL Verification", preview_list, ["URL", "Verified", "Description"])

    demisto.results(
        {
            "Type": entryTypes["note"],
            "Contents": url_list,
            "ContentsFormat": formats["json"],
            "HumanReadable": md,
            "EntryContext": ec,
        }
    )


if __name__ in ["__main__", "__builtin__", "builtins"]:
    main()
